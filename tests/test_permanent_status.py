"""Saved launch rules must never be confused with a healthy network path."""
import os
from pathlib import Path
import tempfile
import tkinter as tk
import unittest
from unittest import mock
from devproxy_pkg.core.background import BackgroundManager
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.ui import DevProxyWindow


class PermanentStatusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patch = mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=temporary.name)
        patch.start()
        self.addCleanup(patch.stop)
        self.manager = BackgroundManager()
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        self.window = DevProxyWindow(self.root, auto_discover=False, background=self.manager)

    def rule(self):
        state = StateManager.load_state()
        state['background'] = {'applications': {'antigravity': {
            'profile': 'Рабочий', 'record': {'name': 'Antigravity'}}},
            'startup': {'applied': {'value': 'fixture'}}, 'ports': {'Рабочий': 18787}}
        StateManager.save_state(state)
        self.manager.refresh()

    def test_loaded_empty_rules_are_off_but_manual_session_does_not_enable_them(self):
        self.manager.refresh()
        self.window.session = mock.Mock()
        self.window.update_permanent_status()
        self.assertIn('ВЫКЛЮЧЕН', self.window.permanent_status.get())
        self.assertEqual(str(self.window.disable_button['state']), 'disabled')
        self.window.session = None

    def test_saved_rules_stay_on_when_bridge_is_down(self):
        self.rule()
        self.window.update_permanent_status()
        self.assertIn('ВКЛЮЧЁН', self.window.permanent_status.get())
        self.assertIn('Antigravity → Рабочий', self.window.permanent_details.get())
        self.assertIn('не запущен', self.window.permanent_health.get())
        self.assertIn('автозапуск настроен', self.window.permanent_health.get())

    def test_live_bridge_with_errors_is_not_reported_as_healthy(self):
        self.rule()
        with self.manager._cache_lock:
            self.manager._cache.update(sessions=[{'profile': 'Рабочий', 'running': True}],
                                       error='Ошибка TLS к api.invalid')
        self.window.update_permanent_status()
        self.assertIn('ВКЛЮЧЁН', self.window.permanent_status.get())
        self.assertIn('мост запущен', self.window.permanent_health.get())
        self.assertIn('Есть ошибки', self.window.permanent_health.get())
        self.window.profile.set('Другой')
        self.window.update_permanent_status()
        self.assertIn('Рабочий', self.window.permanent_details.get())

    def test_read_failure_retains_rules_and_reports_unknown_then_recovers(self):
        self.rule()
        with mock.patch.object(StateManager, 'load_state', side_effect=OSError('fixture')):
            self.manager.refresh()
        self.assertEqual(self.manager.snapshot()['applications'], ['antigravity'])
        self.window.update_permanent_status()
        self.assertIn('СТАТУС НЕДОСТУПЕН', self.window.permanent_status.get())
        self.manager.refresh()
        self.window.update_permanent_status()
        self.assertIn('ВКЛЮЧЁН', self.window.permanent_status.get())
        self.assertIsNone(self.manager.snapshot()['error'])

    def test_cache_and_ipc_expose_copy_of_rules_without_credentials(self):
        self.rule()
        snapshot = self.manager.snapshot()
        snapshot['policies'][0]['profile'] = 'mutated'
        self.assertEqual(self.manager.snapshot()['policies'][0]['profile'], 'Рабочий')
        status = self.window.status_snapshot()
        self.assertEqual(status['policies'][0]['name'], 'Antigravity')
        self.assertTrue(status['startup'])
        self.assertTrue(status['rules_loaded'])
        self.assertNotIn('record', repr(status['policies']))


if __name__ == '__main__':
    unittest.main()
