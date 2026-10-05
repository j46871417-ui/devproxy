"""Independent acceptance checks for the audited snapshot; real configs are untouched."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from devproxy_pkg.core.config_editor import ConfigEditor, strip_json_comments
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.secrets import SecretStore, EphemeralStore
from devproxy_pkg.core.launcher import Launcher
from devproxy_pkg.core.tunnel import LocalTunnel
from devproxy_pkg.core.validator import ProxyValidator
from devproxy_pkg.adapters.vscode_family import VSCodeAdapter
from devproxy_pkg import cli


class Review(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base/'settings.json'
        self.state = self.base/'state.json'
        self.adapter = VSCodeAdapter()
        self.patches = [
            patch('devproxy_pkg.core.recovery.get_devproxy_state_path', return_value=str(self.state)),
            patch.object(self.adapter, 'detect_config_files', return_value=[str(self.config)]),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        EphemeralStore._cache.clear()
        self.addCleanup(EphemeralStore._cache.clear)
        self.profile = ProxyProfile.parse('http://localhost:8080')
        env = patch.dict(os.environ, {'DEVPROXY_SECRET_BACKEND':'memory', 'DEVPROXY_STATE_DIR':str(self.base)})
        env.start()
        self.addCleanup(env.stop)

    def write(self, text):
        self.config.write_text(text, encoding='utf-8')

    def read(self):
        return ConfigEditor.load_jsonc(str(self.config))[0]

    def test_malformed_existing_file_stays_unchanged(self):
        raw = '{ "broken": '
        self.write(raw)
        ok, _ = self.adapter.apply_persistent(self.profile)
        self.assertFalse(ok)
        self.assertEqual(self.config.read_text(), raw)

    def test_bom_and_url_preserved(self):
        self.write('\ufeff{"url":"https://example.test", "editor.fontSize":14}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertEqual(self.read()['url'], 'https://example.test')
        self.assertEqual(self.read()['editor.fontSize'], 14)

    def test_trailing_comma_cleanup_does_not_change_string(self):
        self.write('{"text":"keep,} and,]",}')
        self.assertEqual(self.read()['text'], 'keep,} and,]')

    def test_nested_proxy_does_not_replace_root(self):
        self.write('{"custom":{"http.proxy":"http://nested:80"}}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertEqual(self.read()['http.proxy'], self.profile.to_url())
        self.assertEqual(self.read()['custom']['http.proxy'], 'http://nested:80')

    def test_commented_out_key_does_not_hide_real_key(self):
        self.write('{\n// "http.proxy":"http://comment:80"\n"editor.fontSize":14\n}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertEqual(self.read()['http.proxy'], self.profile.to_url())

    def test_insertion_after_line_comment_produces_valid_jsonc(self):
        self.write('{\n"editor.fontSize":14 // preserve me\n}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertIsNotNone(self.read(), self.config.read_text())

    def test_null_is_not_treated_as_missing_on_restore(self):
        self.write('{"http.proxy":null}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertTrue(self.adapter.restore_persistent()[0])
        self.assertIn('http.proxy', self.read())
        self.assertIsNone(self.read()['http.proxy'])

    def test_apply_apply_restore_recovers_original(self):
        self.write('{"http.proxy":"http://original:80","editor.fontSize":14}')
        self.assertTrue(self.adapter.apply_persistent(self.profile)[0])
        self.assertTrue(self.adapter.apply_persistent(ProxyProfile.parse('http://second:9090'))[0])
        self.assertTrue(self.adapter.restore_persistent()[0])
        self.assertEqual(self.read()['http.proxy'], 'http://original:80')

    def test_restore_does_not_overwrite_user_changes(self):
        self.write('{"http.proxy":"http://original:80"}')
        self.adapter.apply_persistent(self.profile)
        self.write('{"http.proxy":"http://manual:90","editor.fontSize":18}')
        self.adapter.restore_persistent()
        self.assertEqual(self.read()['http.proxy'], 'http://manual:90')
        self.assertEqual(self.read()['editor.fontSize'], 18)

    def test_restore_failure_keeps_recovery_record(self):
        self.write('{"editor.fontSize":14}')
        self.adapter.apply_persistent(self.profile)
        self.write('broken')
        ok, _ = self.adapter.restore_persistent()
        self.assertFalse(ok)
        self.assertIsNotNone(StateManager.get_applied_record('vscode'))

    def test_state_write_failure_is_reported(self):
        with patch('devproxy_pkg.core.recovery.os.replace', side_effect=PermissionError('mock denied')):
            with self.assertRaises(Exception):
                StateManager.save_profile(self.profile.to_dict())

    def test_backup_failure_prevents_configuration_write(self):
        self.write('{"editor.fontSize":14}')
        before = self.config.read_bytes()
        with patch('devproxy_pkg.core.config_editor.shutil.copy2', side_effect=PermissionError('mock denied')):
            ok, _ = self.adapter.apply_persistent(self.profile)
        self.assertFalse(ok)
        self.assertEqual(self.config.read_bytes(), before)

    def test_authenticated_persistent_is_not_masked_password(self):
        self.write('{}')
        p = ProxyProfile.parse('http://user:real-password@localhost:8080')
        ok, _ = self.adapter.apply_persistent(p)
        if ok:
            url = self.read()['http.proxy']
            self.assertNotIn(':***@', url, 'Masking is for display, not actual authentication')
            self.assertNotIn('real-password', url, 'Must use secure bridge/credential integration')

    def test_explicit_missing_profile_does_not_fall_back(self):
        StateManager.save_profile(self.profile.to_dict())
        with patch.object(SecretStore, 'get_password', return_value=None):
            self.assertIsNone(cli.resolve_profile('misspelled'))

    def test_profile_update_without_password_clears_old_secret(self):
        EphemeralStore.set('office', 'obsolete-secret')
        args = argparse.Namespace(proxy='http://localhost:8080', name='office')
        with contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_profile_add(args)
        with patch.object(SecretStore, 'get_password', side_effect=EphemeralStore.get):
            p = cli.resolve_profile('office')
        self.assertFalse(p.has_auth, 'Previous password must not be sent to a new proxy')

    def test_profile_port_zero_rejected(self):
        with self.assertRaises(ValueError):
            ProxyProfile.parse('http://localhost:0')

    def test_profile_query_and_fragment_rejected(self):
        for url in ['http://localhost:8080/path', 'http://localhost:8080/?token=x', 'http://localhost:8080/#x']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                ProxyProfile.parse(url)

    def test_decoded_host_control_characters_rejected(self):
        with self.assertRaises(ValueError):
            ProxyProfile.parse('bad\r\nhost:8080')

    def test_invalid_input_does_not_print_password(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            cli.cmd_profile_add(argparse.Namespace(proxy='user:TOPSECRET@localhost', name='bad'))
        self.assertNotIn('TOPSECRET', captured.getvalue())

    def test_launch_stops_tunnel_after_child_exit(self):
        fake_tunnel = Mock()
        fake_tunnel.start.return_value = 12345
        with patch('devproxy_pkg.core.launcher.LocalTunnel', return_value=fake_tunnel), patch.object(Launcher, 'launch', return_value=Mock()):
            Launcher.launch_with_tunnel('mock', self.profile, wait=True)
        fake_tunnel.stop.assert_called_once()

    def test_launch_failure_stops_tunnel(self):
        fake_tunnel = Mock()
        fake_tunnel.start.return_value = 12345
        with patch('devproxy_pkg.core.launcher.LocalTunnel', return_value=fake_tunnel), patch.object(Launcher, 'launch', side_effect=OSError('mock failure')):
            with self.assertRaises(OSError):
                Launcher.launch_with_tunnel('mock', self.profile)
        fake_tunnel.stop.assert_called_once()

    def test_fragmented_client_connect_is_read_completely(self):
        client = Mock()
        client.recv.side_effect = [b'CON', b'NECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n']
        upstream = Mock()
        upstream.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n'
        t = LocalTunnel(self.profile)
        with patch('devproxy_pkg.core.tunnel.socket.create_connection', return_value=upstream) as connect, patch.object(t, '_pipe_duplex'):
            t._handle_client(client)
        connect.assert_called_once()

    def test_https_proxy_is_tls_wrapped(self):
        from devproxy_pkg.core.transport import connect_upstream
        raw, context = Mock(), Mock()
        profile = ProxyProfile.parse('https://localhost:8443')
        with patch('devproxy_pkg.core.transport.socket.create_connection', return_value=raw), patch('devproxy_pkg.core.transport.ssl.create_default_context', return_value=context):
            wrapped = connect_upstream(profile)
        context.wrap_socket.assert_called_once_with(raw, server_hostname='localhost')
        self.assertIs(wrapped, context.wrap_socket.return_value)
        self.assertFalse(raw.sendall.called)

    def test_proxy_failure_header_cannot_fake_connect_success(self):
        client = Mock()
        client.recv.return_value = b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n'
        upstream = Mock()
        upstream.recv.return_value = b'HTTP/1.1 407 Authentication Required\r\nX-Note: 200 cached\r\n\r\n'
        t = LocalTunnel(self.profile)
        with patch('devproxy_pkg.core.tunnel.socket.create_connection', return_value=upstream), patch.object(t, '_pipe_duplex'):
            t._handle_client(client)
        response = b''.join(call.args[0] for call in client.sendall.call_args_list)
        self.assertNotIn(b'200 Connection established', response)

    def test_socks_origin_does_not_receive_proxy_credentials(self):
        client = Mock()
        client.recv.return_value = b'GET http://example.test/path HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic TESTSECRET\r\n\r\n'
        upstream = Mock()
        upstream.recv.side_effect = [b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', b'']
        t = LocalTunnel(ProxyProfile.parse('socks5://localhost:1080'))
        with patch('devproxy_pkg.core.tunnel.socket.create_connection', return_value=upstream), patch.object(t, '_socks5_connect_upstream', return_value=True), patch.object(t, '_pipe_duplex'):
            t._handle_client(client)
        forwarded = b''.join(call.args[0] for call in upstream.sendall.call_args_list)
        self.assertNotIn(b'Proxy-Authorization', forwarded)
        self.assertTrue(forwarded.startswith(b'GET /path HTTP/1.1'))

    def test_ipv6_destination_connect_accepted(self):
        client = Mock()
        client.recv.return_value = b'CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n'
        upstream = Mock()
        upstream.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n'
        t = LocalTunnel(self.profile)
        with patch('devproxy_pkg.core.tunnel.socket.create_connection', return_value=upstream) as connect, patch.object(t, '_pipe_duplex'):
            t._handle_client(client)
        connect.assert_called_once()

    def test_invalid_profile_cli_has_nonzero_exit(self):
        res = subprocess.run([sys.executable, str(ROOT/'devproxy.py'), 'profile', 'add', 'garbage'], capture_output=True)
        self.assertNotEqual(res.returncode, 0)

    def test_old_status_alias_still_works(self):
        res = subprocess.run([sys.executable, str(ROOT/'devproxy.py'), '--status'], capture_output=True)
        self.assertEqual(res.returncode, 0, res.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
