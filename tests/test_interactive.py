"""User flows: numeric selection, recoverable failures and no hidden exit."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from devproxy_pkg import cli
from devproxy_pkg.adapters.cli_tools import CliToolAdapter
from devproxy_pkg.core.launcher import command_for
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.interactive import InteractiveMenu, choose


class InteractiveFlows(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        env = patch.dict(os.environ, {'DEVPROXY_STATE_DIR': str(self.base), 'DEVPROXY_SECRET_BACKEND': 'memory'})
        env.start()
        self.addCleanup(env.stop)
        self.output = io.StringIO()
        for stream in (contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output)):
            stream.__enter__()
            self.addCleanup(stream.__exit__, None, None, None)

    def run_menu(self, inputs, proxy='http://localhost:8080'):
        with patch('builtins.input', side_effect=inputs):
            return InteractiveMenu(proxy).run()

    def test_bad_numbers_repeat_without_exit(self):
        with patch('builtins.input', side_effect=['cursor', '-1', '3', '9' * 5000, '2']):
            self.assertEqual(choose('Apps', ['Cursor', 'Codex']), 2)
        self.assertEqual(self.output.getvalue().count('Введите число'), 4)

    def test_app_number_maps_to_adapter_not_typed_id(self):
        adapter = CliToolAdapter('claude', 'Claude Code')
        with patch('devproxy_pkg.interactive.list_adapters', return_value=[adapter]), patch.object(adapter, 'detect_executable', return_value=sys.executable), patch.object(cli.Launcher, 'launch_with_tunnel', return_value=(Mock(returncode=0), Mock())) as launch:
            self.assertEqual(self.run_menu(['1', '1', '1', '', '0']), 0)
        self.assertEqual(launch.call_args.args[0], sys.executable)
        self.assertIn('Claude Code [найдено]', self.output.getvalue())
        self.assertNotIn('Application ID', self.output.getvalue())

    def test_failed_launch_shows_error_and_returns_to_menu(self):
        adapter = CliToolAdapter('codex', 'Codex CLI')
        with patch('devproxy_pkg.interactive.list_adapters', return_value=[adapter]), patch.object(adapter, 'detect_executable', return_value=sys.executable), patch.object(cli.Launcher, 'launch_with_tunnel', side_effect=OSError('fixture launch failed')):
            self.assertEqual(self.run_menu(['1', '1', '1', '', '0']), 0)
        text = self.output.getvalue()
        self.assertIn('fixture launch failed', text)
        self.assertGreaterEqual(text.count('Главное меню'), 2)

    def test_missing_app_can_be_selected_by_explicit_path(self):
        adapter = CliToolAdapter('codex', 'Codex CLI')
        with patch('devproxy_pkg.interactive.list_adapters', return_value=[adapter]), patch.object(adapter, 'detect_executable', return_value=None), patch.object(cli.Launcher, 'launch_with_tunnel', return_value=(Mock(returncode=0), Mock())) as launch:
            self.assertEqual(self.run_menu(['1', '1', 'missing-fixture.exe', '"' + sys.executable + '"', '1', '', '0']), 0)
        self.assertEqual(launch.call_args.args[0], sys.executable)
        self.assertIn('Файл не найден', self.output.getvalue())

    def test_bad_proxy_retries_and_is_reused_without_plaintext_storage(self):
        menu = InteractiveMenu()
        with patch('getpass.getpass', side_effect=['garbage', 'https://fixture-user:fixture-password@localhost:443']), patch('builtins.input', side_effect=['3', '1', '', '0']):
            self.assertEqual(menu.run(), 0)
        self.assertEqual(menu.proxy_args, ['--proxy', 'https://fixture-user:fixture-password@localhost:443'])
        self.assertNotIn('fixture-password', self.output.getvalue())
        self.assertFalse((self.base / 'state.json').exists())

    def test_saved_profile_is_selected_by_number(self):
        StateManager.save_profile(ProxyProfile.parse('http://localhost:1234', name='work').to_dict())
        menu = InteractiveMenu()
        with patch('builtins.input', side_effect=['3', '2', '', '0']):
            self.assertEqual(menu.run(), 0)
        self.assertEqual(menu.proxy_args, ['--profile', 'work'])

    def test_vault_unavailable_does_not_lose_current_session_proxy(self):
        menu = InteractiveMenu('https://user:fixture-password@localhost:443')
        with patch('builtins.input', side_effect=['4', 'work', '', '0']):
            self.assertEqual(menu.run(), 0)
        self.assertIn('Текущий прокси остаётся доступен', self.output.getvalue())
        self.assertEqual(menu.proxy_args[0], '--proxy')
        self.assertFalse((self.base / 'state.json').exists())

    def test_unexpected_action_failure_stays_visible_and_redacts_secret(self):
        with patch.object(InteractiveMenu, 'launch', side_effect=TypeError('fixture-password error')):
            self.assertEqual(self.run_menu(['1', '', '0'], 'https://user:fixture-password@localhost:443'), 0)
        self.assertIn('Ошибка (TypeError)', self.output.getvalue())
        self.assertNotIn('fixture-password', self.output.getvalue())
        self.assertGreaterEqual(self.output.getvalue().count('Главное меню'), 2)

    def test_ctrl_c_in_action_returns_to_menu(self):
        with patch.object(InteractiveMenu, 'launch', side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_menu(['1', '', '0']), 0)
        self.assertIn('Действие отменено', self.output.getvalue())

    def test_eof_quits_without_traceback(self):
        self.assertEqual(self.run_menu([EOFError()]), 0)

    def test_corrupted_state_does_not_close_the_menu(self):
        (self.base / 'state.json').write_text('{broken', encoding='utf-8')
        self.assertEqual(self.run_menu(['5', '', '0']), 0)
        self.assertIn('Cannot read DevProxy state', self.output.getvalue())
        self.assertGreaterEqual(self.output.getvalue().count('Главное меню'), 2)

    def test_corrupted_state_still_allows_session_proxy(self):
        (self.base / 'state.json').write_text('{broken', encoding='utf-8')
        menu = InteractiveMenu()
        with patch('getpass.getpass', return_value='http://localhost:1234'), patch('builtins.input', side_effect=['3', '1', '', '0']):
            self.assertEqual(menu.run(), 0)
        self.assertEqual(menu.proxy_args, ['--proxy', 'http://localhost:1234'])
        self.assertEqual((self.base / 'state.json').read_text(), '{broken')

    def test_network_errors_in_test_and_serve_do_not_exit_menu(self):
        for selection, handler in [('2', 'cmd_test'), ('8', 'cmd_serve')]:
            with self.subTest(selection=selection), patch.object(cli, handler, side_effect=OSError('fixture connection refused')):
                self.assertEqual(self.run_menu([selection, '', '0']), 0)
        self.assertIn('fixture connection refused', self.output.getvalue())

    def test_detection_error_does_not_hide_other_applications(self):
        broken, good = CliToolAdapter('codex', 'Codex CLI'), CliToolAdapter('claude', 'Claude Code')
        with patch('devproxy_pkg.interactive.list_adapters', return_value=[broken, good]), patch.object(broken, 'detect_executable', side_effect=OSError('fixture detection failed')), patch.object(good, 'detect_executable', return_value=sys.executable):
            self.assertEqual(self.run_menu(['6', '', '0']), 0)
        self.assertIn('fixture detection failed', self.output.getvalue())
        self.assertIn('Claude Code [найдено]', self.output.getvalue())

    def test_restore_selects_record_by_number_and_retains_menu_on_error(self):
        StateManager.save_state({'profiles': {}, 'applied': {'vscode': {'fixture': {}}}})
        with patch.object(cli, 'cmd_restore', side_effect=ValueError('fixture restore conflict')) as restore:
            self.assertEqual(self.run_menu(['7', '2', '', '0']), 0)
        self.assertEqual(restore.call_args.args[0].app, 'vscode')
        self.assertIn('fixture restore conflict', self.output.getvalue())

    def test_source_entrypoint_accepts_numeric_exit(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, str(root / 'devproxy.py')], input='wrong\n0\n', capture_output=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Главное меню', result.stdout)
        self.assertIn('Введите число', result.stdout)
        self.assertNotIn('Traceback', result.stderr)


@unittest.skipUnless(os.name == 'nt', 'Windows launcher wrappers')
class WindowsWrappers(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name) / 'folder with spaces'
        self.base.mkdir()

    def test_path_cmd_is_resolved_before_reading(self):
        shim = self.base / 'fixture.cmd'
        script = self.base / 'entry.cjs'
        script.write_text('fixture')
        shim.write_text('@"%~dp0entry.cjs" %*')
        (self.base / 'node.exe').touch()
        with patch.dict(os.environ, {'PATH': str(self.base)}):
            command = command_for('fixture.cmd', ['literal&argument'])
        self.assertEqual(command, [str(self.base / 'node.exe'), str(script), 'literal&argument'])

    def test_npm_dp0_mjs_shim_does_not_invoke_cmd(self):
        shim = self.base / 'fixture.cmd'
        script = self.base / 'entry.mjs'
        script.write_text('fixture')
        shim.write_text('@"%dp0%\\entry.mjs" %*')
        (self.base / 'node.exe').touch()
        self.assertEqual(command_for(str(shim), ['$(literal)'])[1:], [str(script), '$(literal)'])

    def test_gui_bin_wrapper_uses_native_executable(self):
        folder = self.base / 'bin'
        folder.mkdir()
        native = self.base / 'Cursor.exe'
        native.touch()
        shim = folder / 'cursor.cmd'
        shim.write_text('@echo off')
        self.assertEqual(command_for(str(shim), ['--new-window']), [str(native), '--new-window'])

    def test_unknown_batch_wrapper_reports_actionable_error(self):
        shim = self.base / 'fixture.cmd'
        shim.write_text('@echo fixture')
        with self.assertRaisesRegex(ValueError, 'native executable'):
            command_for(str(shim), [])
