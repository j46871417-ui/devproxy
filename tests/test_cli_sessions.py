import argparse
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch
from devproxy_pkg import cli
from devproxy_pkg.core.secrets import WindowsCredentialStore
from devproxy_pkg.core.launcher import Launcher


class CliSessions(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        env = patch.dict(os.environ, {'DEVPROXY_STATE_DIR':str(self.base), 'DEVPROXY_SECRET_BACKEND':'memory'})
        env.start()
        self.addCleanup(env.stop)

    def test_dry_run_does_not_store_credentials_or_start_network(self):
        with patch.object(cli.SecretStore, 'store_password') as store, patch.object(cli.Launcher, 'launch_with_tunnel') as launch, contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['exec', '--proxy', 'https://u:fixture-secret@localhost:443', '--dry-run', '--', sys.executable, '-V'])
        self.assertEqual(code, 0)
        store.assert_not_called()
        launch.assert_not_called()
        self.assertFalse((self.base/'state.json').exists())

    def test_exec_returns_child_exit_code_and_environment_only_in_child(self):
        original = os.environ.get('HTTPS_PROXY')
        args = ['exec', '--proxy', 'https://u:fixture-secret@localhost:443', '--', sys.executable, '-c',
                'import os,sys; assert os.environ["HTTPS_PROXY"].startswith("http://127.0.0.1:"); assert "fixture-secret" not in repr(os.environ); sys.exit(7)']
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(args), 7)
        self.assertEqual(os.environ.get('HTTPS_PROXY'), original)

    def test_unknown_targets_preflight_all_before_write(self):
        config = self.base/'settings.json'
        config.write_text('{}')
        with contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(['apply', '--app', 'vscode,unknown', '--config-path', str(config), '--proxy','http://localhost:80'])
        self.assertEqual(code, 1)
        self.assertEqual(config.read_text(), '{}')

    def test_persistent_unsupported_adapters_do_not_create_fake_settings(self):
        for app in ('codex', 'opencode', 'claude'):
            with self.subTest(app=app), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['apply', '--app', app, '--proxy', 'http://localhost:80']), 1)
        self.assertFalse((self.base/'state.json').exists())

    def test_missing_vault_does_not_claim_saved_profile(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(['profile','add','https://u:fixture-secret@localhost:443'])
        self.assertEqual(code, 1)
        self.assertFalse((self.base/'state.json').exists())

    def test_stdin_proxy_does_not_enter_argv_or_state(self):
        with patch('sys.stdin', io.StringIO('https://u:fixture-secret@localhost:443\n')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['exec','--proxy-stdin','--dry-run','--',sys.executable,'-V']),0)
        self.assertFalse((self.base/'state.json').exists())

    def test_child_launch_failure_releases_active_listener(self):
        from devproxy_pkg.core.profile import ProxyProfile
        with self.assertRaises(FileNotFoundError):
            Launcher.launch_with_tunnel('missing-executable-fixture', ProxyProfile.parse('http://localhost:80'))

    def test_gui_session_lock_rejects_reuse_and_is_released_on_failure(self):
        from devproxy_pkg.core.profile import ProxyProfile
        directory = self.base/'gui'
        directory.mkdir()
        lock = directory/'.devproxy-session.lock'
        lock.write_text('existing-session')
        with self.assertRaisesRegex(ValueError, 'already has a proxy session'):
            Launcher.launch_with_tunnel(sys.executable, ProxyProfile.parse('http://localhost:80'), user_data_dir=str(directory))
        self.assertEqual(lock.read_text(), 'existing-session')
        lock.unlink()
        with self.assertRaises(FileNotFoundError):
            Launcher.launch_with_tunnel('missing-executable-fixture', ProxyProfile.parse('http://localhost:80'), user_data_dir=str(directory))
        self.assertFalse(lock.exists())

    def test_failed_profile_rotation_preserves_old_credentials(self):
        from devproxy_pkg.core.recovery import StateManager
        from devproxy_pkg.core.secrets import EphemeralStore
        previous = {'name':'office','protocol':'https','host':'localhost','port':443,'username':'u',
                    'requires_password':True,'secret_key':'old-revision','secret_backend':'os_keychain'}
        StateManager.save_profile(previous)
        EphemeralStore.set('old-revision', 'old-password')
        args = argparse.Namespace(proxy='https://u:new-password@localhost:443', name='office')
        def store(key, username, password):
            EphemeralStore.set(key, password)
            return 'os_keychain'
        with patch.object(cli.SecretStore, 'store_password', side_effect=store), patch.object(StateManager, 'save_profile', side_effect=OSError('fixture')), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_profile_add(args), 1)
        self.assertEqual(StateManager.get_profile('office')['secret_key'], 'old-revision')
        self.assertEqual(EphemeralStore.get('old-revision'), 'old-password')
        self.assertFalse(any(value == 'new-password' for value in EphemeralStore._cache.values()))
        EphemeralStore.delete('old-revision')

    def test_bound_primary_vault_does_not_revive_fallback_password(self):
        from devproxy_pkg.core.secrets import SecretStore
        with patch('devproxy_pkg.core.secrets.sys.platform', 'win32'), patch.dict(os.environ, {'DEVPROXY_SECRET_BACKEND':''}), patch('devproxy_pkg.core.secrets.WindowsCredentialStore.get_password', return_value=None), patch('devproxy_pkg.core.secrets.WindowsDPAPIStore.get_password', return_value='stale-password') as fallback:
            self.assertIsNone(SecretStore.get_password('fixture', backend='os_keychain'))
            fallback.assert_not_called()

    @unittest.skipUnless(sys.platform == 'win32' and os.environ.get('DEVPROXY_NATIVE_SECRET_TEST') == '1', 'Opt-in native Windows vault check')
    def test_native_windows_vault_roundtrip(self):
        key = 'test-' + str(uuid.uuid4())
        try:
            stored = WindowsCredentialStore.set_password(key, 'test-user', ' spaces-ключ-$1 ')
            if not stored and getattr(WindowsCredentialStore, 'last_error', None) == 1312:
                self.skipTest('This execution token has no Windows credential-vault logon session.')
            self.assertTrue(stored)
            self.assertEqual(WindowsCredentialStore.get_password(key), ' spaces-ключ-$1 ')
        finally:
            self.assertTrue(WindowsCredentialStore.delete_password(key))
        self.assertIsNone(WindowsCredentialStore.get_password(key))

    @unittest.skipUnless(sys.platform == 'win32' and os.environ.get('DEVPROXY_NATIVE_SECRET_TEST') == '1', 'Opt-in native DPAPI check')
    def test_dpapi_roundtrip_ciphertext_and_endpoint_binding(self):
        from devproxy_pkg.core.dpapi import WindowsDPAPIStore as Store
        key = 'test-' + str(uuid.uuid4())
        self.assertTrue(Store.set_password(key, ' spaces-ключ-$1 '))
        self.assertEqual(Store.get_password(key), ' spaces-ключ-$1 ')
        self.assertNotIn(b'spaces-', Store._path(key).read_bytes())
        with self.assertRaises(OSError):
            Store._transform(Store._path(key).read_bytes(), 'different-endpoint', False)
        self.assertTrue(Store.delete_password(key))
        self.assertIsNone(Store.get_password(key))
