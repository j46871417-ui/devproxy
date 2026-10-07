"""Exercise actual persistent bridges, including pre-2.3.4 profiles."""
from contextlib import ExitStack
import socket
from unittest import mock
from test_fixes_233 import IsolatedState
from test_regressions import FakeProxy
from devproxy_pkg.core.background import BackgroundManager
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.transport import read_headers, recv_exact
from devproxy_pkg.core.oauth_browser import check_local_callback, check_login_tunnel, launch_login_browser, latest_login_url
from devproxy_pkg.core.user_errors import UserInputError
import os
import ssl


class LegacyBridgeTests(IsolatedState):
    def enable_fixture(self, manager, name, startup_error=False):
        executable = self.directory / 'Antigravity.exe'
        executable.write_bytes(b'fixture')
        record = dict(id='antigravity',name='fixture',executable=str(executable),electron=True)
        with ExitStack() as stack:
            stack.enter_context(mock.patch('devproxy_pkg.core.background.inspect_shortcuts',return_value=[]))
            stack.enter_context(mock.patch('devproxy_pkg.core.background.write_shortcut'))
            stack.enter_context(mock.patch('devproxy_pkg.core.background.broker_shortcut',side_effect=lambda link,app: dict(link)))
            stack.enter_context(mock.patch('devproxy_pkg.core.background.LoginStartup.read',return_value=None))
            stack.enter_context(mock.patch('devproxy_pkg.core.background.LoginStartup.expected',return_value={'value':'fixture','kind':1}))
            stack.enter_context(mock.patch('devproxy_pkg.core.background.LoginStartup.write',
                side_effect=OSError('fixture') if startup_error else None))
            manager.enable([record],name)

    def test_enabling_legacy_profile_keeps_identity_and_opens_real_bridge(self):
        with FakeProxy() as upstream:
            StateManager.save_profile(ProxyProfile('legacy','http','127.0.0.1',upstream.port).to_dict())
            manager = BackgroundManager()
            self.addCleanup(manager.close)
            self.enable_fixture(manager,'legacy')
            session = manager.sessions['legacy']
            identity = session.tunnel.profile_provider.profile_id
            self.assertEqual(StateManager.get_profile('legacy')['profile_id'],identity)
            with socket.create_connection(('127.0.0.1',session.tunnel.allocated_port),timeout=3) as client:
                client.sendall(b'CONNECT accounts.google.com:443 HTTP/1.1\r\nHost: accounts.google.com:443\r\n\r\n')
                self.assertIn(b'200',read_headers(client)[0])
                client.sendall(b'fixture-flow')
                self.assertEqual(recv_exact(client,12),b'fixture-flow')

    def test_enabling_second_legacy_profile_keeps_both_live_identities(self):
        with FakeProxy() as upstream:
            for name in ['first','second']:
                StateManager.save_profile(ProxyProfile(name,'http','127.0.0.1',upstream.port).to_dict())
            manager = BackgroundManager()
            self.addCleanup(manager.close)
            for name in ['first','second']:
                self.enable_fixture(manager,name)
            for name in ['first','second']:
                provider = manager.sessions[name].tunnel.profile_provider
                self.assertEqual(provider().name,name)
                self.assertEqual(StateManager.get_profile(name)['profile_id'],provider.profile_id)
            self.assertNotEqual(StateManager.get_profile('first')['profile_id'],StateManager.get_profile('second')['profile_id'])

    def test_failed_enable_rolls_back_and_closes_new_bridge(self):
        StateManager.save_profile(ProxyProfile('legacy','http','localhost',8000).to_dict())
        previous = StateManager.load_state()
        manager = BackgroundManager()
        self.addCleanup(manager.close)
        with self.assertRaises(OSError):
            self.enable_fixture(manager,'legacy',startup_error=True)
        self.assertEqual(StateManager.load_state(),previous)
        self.assertEqual(manager.sessions,{})


class OAuthPreflightTests(IsolatedState):
    def test_broken_provider_does_not_open_or_pin_browser(self):
        session = mock.Mock()
        session.tunnel.profile_provider.side_effect = ValueError('fixture')
        with self.assertRaisesRegex(UserInputError,'привязку'):
            launch_login_browser(session,'https://accounts.google.com/o/oauth2/auth?state=fixture','C:/browser/brave.exe')
        session.launch.assert_not_called()
        session.tunnel.profile_provider.pin.assert_not_called()

    def test_preflight_requires_google_tls_certificate_and_sends_no_oauth_data(self):
        session = mock.Mock()
        session.tunnel.bind_host='127.0.0.1'
        session.tunnel.allocated_port=18787
        client, tls = mock.MagicMock(), mock.MagicMock()
        client.__enter__.return_value=client
        tls.__enter__.return_value=tls
        context=mock.Mock()
        context.wrap_socket.return_value=tls
        with mock.patch('devproxy_pkg.core.oauth_browser.socket.create_connection',return_value=client) as dial, \
             mock.patch('devproxy_pkg.core.oauth_browser.ssl.create_default_context',return_value=context), \
             mock.patch('devproxy_pkg.core.oauth_browser.read_headers',side_effect=[(b'HTTP/1.1 200 OK\r\n\r\n',b''),(b'HTTP/1.1 302 Found\r\n\r\n',b'')]):
            check_login_tunnel(session)
            self.assertEqual(dial.call_args.args[0],('127.0.0.1',18787))
        context.wrap_socket.assert_called_once_with(client,server_hostname='accounts.google.com')
        self.assertIn(b'HEAD / HTTP/1.1',tls.sendall.call_args.args[0])
        self.assertNotIn(b'state=',tls.sendall.call_args.args[0])

    def test_certificate_failure_never_launches_browser(self):
        session=mock.Mock()
        with mock.patch('devproxy_pkg.core.oauth_browser.check_login_tunnel',side_effect=UserInputError('сертификат')):
            with self.assertRaisesRegex(UserInputError,'сертификат'):
                launch_login_browser(session,'https://accounts.google.com/o/oauth2/auth','C:/browser/brave.exe')
        session.launch.assert_not_called()
        session.tunnel.profile_provider.pin.assert_not_called()

    def test_failed_connect_surfaces_current_bridge_reason(self):
        session=mock.Mock()
        session.tunnel.bind_host='127.0.0.1'
        session.tunnel.allocated_port=18787
        session.tunnel.diagnostics.return_value={'failures':[{'host':'accounts.google.com','message':'fixture 407'}]}
        client=mock.MagicMock()
        client.__enter__.return_value=client
        with mock.patch('devproxy_pkg.core.oauth_browser.socket.create_connection',return_value=client), \
             mock.patch('devproxy_pkg.core.oauth_browser.read_headers',return_value=(b'HTTP/1.1 502 Bad Gateway\r\n\r\n',b'')), \
             mock.patch('devproxy_pkg.core.oauth_browser.ssl.create_default_context') as tls:
            with self.assertRaisesRegex(UserInputError,'fixture 407'):
                check_login_tunnel(session)
        tls.assert_not_called()

    def test_dead_loopback_callback_rejects_old_link_without_printing_it(self):
        url='https://accounts.google.com/v3/signin/accountchooser?state=SECRET_STATE&redirect_uri=http%3A%2F%2Flocalhost%3A53709%2Fauth%2Fcallback'
        with mock.patch('devproxy_pkg.core.oauth_browser.socket.create_connection',side_effect=ConnectionRefusedError):
            with self.assertRaisesRegex(UserInputError,'устарела') as error:
                check_local_callback(url)
        self.assertNotIn('SECRET_STATE',str(error.exception))
        self.assertNotIn('53709',str(error.exception))

    def test_live_loopback_callback_probe_sends_no_auth_code(self):
        url='https://accounts.google.com/o/oauth2/auth?redirect_uri=http%3A%2F%2Flocalhost%3A53709%2Fauth%2Fcallback'
        connection=mock.MagicMock()
        with mock.patch('devproxy_pkg.core.oauth_browser.socket.create_connection',return_value=connection) as dial:
            check_local_callback(url)
        self.assertEqual(dial.call_args.args[0],('localhost',53709))
        connection.sendall.assert_not_called()

    def test_recent_v3_google_link_can_be_read_from_bounded_log(self):
        folder=self.directory/'antigravity'/'logs'
        folder.mkdir(parents=True)
        url='https://accounts.google.com/v3/signin/accountchooser?state=fixture'
        (folder/'language_server.log').write_text('fixture '+url,encoding='utf8')
        with mock.patch.dict(os.environ,APPDATA=str(self.directory)):
            self.assertEqual(latest_login_url(),url)
