"""Failures found by the independent review; local fixtures only."""
import socket
import ssl
import threading
from unittest import mock
from test_fixes_233 import IsolatedState
from test_regressions import FakeProxy
from devproxy_pkg.cli import SavedProfileProvider, resolve_saved_profile, main
from devproxy_pkg.core.background import BackgroundManager
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager, state_lock
from devproxy_pkg.core.transport import read_headers, recv_exact
from devproxy_pkg.core.tunnel import LocalTunnel
from devproxy_pkg.core.profiles import set_route_backups
from devproxy_pkg.core.oauth_browser import validate_login_url, launch_login_browser, latest_login_url
from devproxy_pkg.core.transport import ProxyError
from devproxy_pkg.core.transport import open_proxy
from pathlib import Path
import os


class CompletionTests(IsolatedState):
    def test_https_limits_handshake_burst_but_releases_gate_for_next_connection(self):
        profile = ProxyProfile('fixture', 'https', 'handshake-fixture.invalid', 8443)
        active, peak, completed = [0], [0], []
        lock, first_pair, release = threading.Lock(), threading.Event(), threading.Event()
        def handshake(*args):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                if active[0] == 2:
                    first_pair.set()
            if not release.wait(3):
                raise AssertionError('handshake stalled')
            with lock:
                active[0] -= 1
            return mock.Mock()
        def worker():
            try:
                open_proxy(profile, timeout=4).close()
                completed.append(True)
            except Exception:
                completed.append(False)
        with mock.patch('devproxy_pkg.core.transport.socket.create_connection', return_value=mock.Mock()), \
             mock.patch('devproxy_pkg.core.transport._tls_handshake', side_effect=handshake):
            workers = [threading.Thread(target=worker) for _ in range(5)]
            for thread in workers:
                thread.start()
            self.assertTrue(first_pair.wait(2))
            self.assertLessEqual(peak[0], 2)
            release.set()
            for thread in workers:
                thread.join(4)
        self.assertEqual(completed, [True] * 5)
        self.assertLessEqual(peak[0], 2)

    def test_single_exit_handshakes_run_in_parallel(self):
        self.save(ProxyProfile('primary', 'http', 'localhost', 8000))
        provider = SavedProfileProvider('primary')
        ready = threading.Barrier(2)
        errors = []
        def connect(*args):
            ready.wait(timeout=2)
            return mock.Mock(), b''
        def worker():
            try:
                provider.open_connection('fixture.invalid', 443, 3, None)
            except Exception as error:
                errors.append(type(error).__name__)
        with mock.patch('devproxy_pkg.core.transport.connect_upstream', side_effect=connect):
            workers = [threading.Thread(target=worker) for _ in range(2)]
            for thread in workers:
                thread.start()
            for thread in workers:
                thread.join(3)
        self.assertEqual(errors, [])
        self.assertTrue(all(not thread.is_alive() for thread in workers))

    def test_transport_failure_selects_backup_and_keeps_session_exit(self):
        with FakeProxy() as healthy, FakeProxy() as failing:
            dead_port = failing.port
            failing.close()
            self.save(ProxyProfile('primary', 'http', '127.0.0.1', dead_port))
            self.save(ProxyProfile('backup', 'http', '127.0.0.1', healthy.port))
            set_route_backups('primary', ['backup'])
            provider = SavedProfileProvider('primary')
            with LocalTunnel(resolve_saved_profile('primary'), profile_provider=provider) as tunnel:
                with self.connect(tunnel) as client:
                    self.assertIn(b'200', read_headers(client)[0])
                    client.sendall(b'opaque')
                    self.assertEqual(recv_exact(client, 6), b'opaque')
                self.assertEqual(provider.route_status()['selected'], 'backup')
                with mock.patch('devproxy_pkg.core.transport.socket.create_connection', wraps=socket.create_connection) as dial:
                    with self.connect(tunnel) as client:
                        self.assertIn(b'200', read_headers(client)[0])
                    upstream_calls = [call for call in dial.call_args_list if call.args[0][1] != tunnel.allocated_port]
                    self.assertEqual([call.args[0][1] for call in upstream_calls], [healthy.port])

    def test_proxy_auth_or_destination_rejection_never_selects_backup(self):
        with FakeProxy(reject=True) as rejected, FakeProxy() as backup:
            self.save(ProxyProfile('primary', 'http', '127.0.0.1', rejected.port))
            self.save(ProxyProfile('backup', 'http', '127.0.0.1', backup.port))
            set_route_backups('primary', ['backup'])
            provider = SavedProfileProvider('primary')
            with self.assertRaises(ProxyError):
                provider.open_connection('google.invalid', 443, 3, None)
            self.assertEqual(backup.requests, [])
            self.assertEqual(provider.route_status()['selected'], 'primary')

    def test_certificate_and_whitelist_failures_never_use_other_exit(self):
        self.save(ProxyProfile('primary', 'https', 'localhost', 8000))
        self.save(ProxyProfile('backup', 'http', 'localhost', 8001))
        set_route_backups('primary', ['backup'])
        for error in [ssl.SSLCertVerificationError(1, 'fixture'), ProxyError('fixture', 'http_rejected', 403)]:
            error.devproxy_phase = 'proxy_tls' if isinstance(error, ssl.SSLError) else 'proxy_connect'
            provider = SavedProfileProvider('primary')
            with mock.patch('devproxy_pkg.core.transport.connect_upstream', side_effect=error) as connect:
                with self.assertRaises(OSError):
                    provider.open_connection('google.invalid', 443, 3, None)
                self.assertEqual(connect.call_count, 1)
                self.assertEqual(provider.route_status()['selected'], 'primary')

    def test_oauth_pinned_route_cannot_switch(self):
        with FakeProxy() as backup, FakeProxy() as primary:
            self.save(ProxyProfile('primary', 'http', '127.0.0.1', primary.port))
            self.save(ProxyProfile('backup', 'http', '127.0.0.1', backup.port))
            set_route_backups('primary', ['backup'])
            provider = SavedProfileProvider('primary')
            provider.pin()
            primary.close()
            with self.assertRaises(OSError):
                provider.open_connection('google.invalid', 443, 3, None)
            self.assertEqual(backup.requests, [])

    def test_login_browser_uses_same_bridge_and_separate_profile(self):
        session = mock.Mock()
        session.tunnel.session_id = 'fixture'
        session.tunnel.profile_provider = mock.Mock(profile_id='fixture-identity')
        url = 'https://accounts.google.com/o/oauth2/auth?state=fixture'
        with mock.patch('devproxy_pkg.core.oauth_browser.check_login_tunnel') as check:
            launch_login_browser(session, url, r'C:\browser\msedge.exe')
            check.assert_called_once_with(session)
        flags = session.launch.call_args.kwargs['flags']
        self.assertIn('--proxy-server={PROXY_URL}', flags)
        self.assertIn(url, flags)
        self.assertTrue(any(flag.startswith('--user-data-dir=') for flag in flags))
        session.tunnel.profile_provider.pin.assert_called_once()

    def test_login_link_rejects_untrusted_hosts_credentials_and_plaintext(self):
        for url in ['http://accounts.google.com/', 'https://accounts.google.com.evil.invalid/',
                    'https://user:pass@accounts.google.com/', 'https://accounts.google.com:444/']:
            with self.assertRaises(ValueError):
                validate_login_url(url)

    def test_oauth_log_is_bounded_and_link_is_not_persisted(self):
        folder = self.directory / 'antigravity' / 'logs'
        folder.mkdir(parents=True)
        path = folder / 'language_server.log'
        expected = 'https://accounts.google.com/o/oauth2/auth?state=fixture'
        path.write_text('old\n' * 50000 + expected, encoding='utf8')
        with mock.patch.dict(os.environ, APPDATA=str(self.directory)):
            self.assertEqual(latest_login_url(), expected)
        self.assertFalse((self.directory / 'state.json').exists())

    def test_live_rename_preserves_port_and_open_stream(self):
        with FakeProxy() as proxy:
            self.save(ProxyProfile('old', 'http', '127.0.0.1', proxy.port, 'alice', 'fixture'))
            manager = BackgroundManager()
            self.addCleanup(manager.close)
            session = manager._session('old', 0)
            port = session.tunnel.allocated_port
            with self.connect(session.tunnel) as old_stream:
                self.assertIn(b'200', read_headers(old_stream)[0])
                self.save(ProxyProfile('new', 'http', '127.0.0.1', proxy.port, 'alice'), 'old', True)
                self.assertIs(manager._session('new', port), session)
                self.assertNotIn('old', manager.sessions)
                old_stream.sendall(b'still-open')
                self.assertEqual(recv_exact(old_stream, 10), b'still-open')
                with self.connect(session.tunnel) as new_stream:
                    self.assertIn(b'200', read_headers(new_stream)[0])
            self.assertEqual(session.tunnel.allocated_port, port)

    def test_deleted_profile_name_reuse_does_not_retarget_provider(self):
        self.save(ProxyProfile('old', 'http', 'localhost', 8000))
        provider = SavedProfileProvider('old')
        StateManager.delete_profile('old')
        self.save(ProxyProfile('old', 'http', 'localhost', 8001))
        with self.assertRaises(ValueError):
            provider()

    def test_nested_state_lock_does_not_wait_on_itself(self):
        self.save(ProxyProfile('legacy', 'http', 'localhost', 8000))
        with state_lock():
            provider = SavedProfileProvider('legacy')
            self.assertEqual(provider().port, 8000)

    def test_cli_run_installs_live_provider_but_adhoc_does_not(self):
        self.save(ProxyProfile('saved', 'http', 'localhost', 8000))
        adapter = mock.Mock(app_id='fixture', electron=False)
        adapter.detect_executable.return_value = 'fixture.exe'
        for arguments, live in [(['run', 'fixture', '--profile', 'saved'], True),
                                (['run', 'fixture', '--proxy', 'http://localhost:8001'], False)]:
            with mock.patch('devproxy_pkg.cli.choose_adapter', return_value=adapter), \
                 mock.patch('devproxy_pkg.cli.ApplicationSession') as session:
                session.return_value.__enter__.return_value.wait.return_value = 0
                self.assertEqual(main(arguments), 0)
                self.assertEqual(isinstance(session.call_args.kwargs['profile_provider'], SavedProfileProvider), live)

    def test_recv_want_write_selects_writability_and_write_want_read_avoids_spin(self):
        class Peer:
            def setblocking(self, _): pass
            def shutdown(self, _): pass
            def recv(self, _): raise ssl.SSLWantWriteError()
        client, upstream = Peer(), Peer()
        tunnel = LocalTunnel(ProxyProfile('fixture', 'http', 'localhost', 1))
        interests = []
        def select(readers, writers, errors, timeout):
            interests.append((readers, writers))
            if len(interests) == 1:
                return [upstream], [], []
            tunnel._stop.set()
            return [], [], []
        with mock.patch('devproxy_pkg.core.tunnel.select.select', side_effect=select):
            tunnel._pipe_duplex(client, upstream)
        self.assertIn(upstream, interests[1][1])
        self.assertNotIn(upstream, interests[1][0])

    def test_select_reset_is_not_silently_swallowed(self):
        peers = [mock.Mock(), mock.Mock()]
        for peer in peers:
            peer.pending.return_value = 0
        tunnel = LocalTunnel(ProxyProfile('fixture', 'http', 'localhost', 1))
        with mock.patch('devproxy_pkg.core.tunnel.select.select', side_effect=ConnectionResetError):
            with self.assertRaises(ConnectionResetError):
                tunnel._pipe_duplex(*peers)

    def test_relay_error_reaches_destination_diagnostics(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile()) as tunnel:
            with mock.patch.object(tunnel, '_pipe_duplex', side_effect=ConnectionResetError):
                with self.connect(tunnel) as client:
                    self.assertIn(b'200', read_headers(client)[0])
                    client.recv(1)
                entry = tunnel.diagnostics()['failures'][0]
                self.assertEqual(entry['phase'], 'relay')
                self.assertEqual(entry['type'], 'ConnectionResetError')
