import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from devproxy_pkg.core.config_editor import ConfigEditor, parse_jsonc
from devproxy_pkg.core.recovery import StateManager, apply_json_batch, restore_json_batch


class Transactions(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        env = patch.dict(os.environ, {'DEVPROXY_STATE_DIR':str(self.base), 'DEVPROXY_SECRET_BACKEND':'memory'})
        env.start()
        self.addCleanup(env.stop)

    def test_multitarget_preflight_changes_nothing_on_invalid_second_file(self):
        first, second = self.base / 'a.json', self.base / 'b.json'
        first.write_text('{}')
        second.write_text('broken')
        with self.assertRaises(ValueError):
            apply_json_batch([('a', str(first), {'http.proxy':'http://a:80'}), ('b', str(second), {'http.proxy':'http://b:80'})])
        self.assertEqual(first.read_text(), '{}')
        self.assertFalse((self.base / 'state.json').exists())

    def test_multitarget_write_failure_rolls_back_first_and_journal(self):
        first, second = self.base / 'a.json', self.base / 'b.json'
        first.write_text('{"editor.fontSize":14}')
        second.write_text('{}')
        before = first.read_bytes()
        write = ConfigEditor.atomic_write

        def fail(path, content, **kwargs):
            if str(path) == str(second):
                raise PermissionError('fixture failure')
            return write(path, content, **kwargs)

        with patch.object(ConfigEditor, 'atomic_write', side_effect=fail), self.assertRaises(PermissionError):
            apply_json_batch([('a', str(first), {'http.proxy':'http://a:80'}), ('b', str(second), {'http.proxy':'http://b:80'})])
        self.assertEqual(first.read_bytes(), before)
        self.assertEqual(StateManager.load_state()['applied'], {})

    def test_dry_run_never_creates_configs_or_state(self):
        path = self.base / 'new.json'
        plans = apply_json_batch([('new', str(path), {'http.proxy':'http://a:80'})], dry_run=True)
        self.assertIn('http.proxy', parse_jsonc(plans[0][1]))
        self.assertFalse(path.exists())
        self.assertFalse((self.base / 'state.json').exists())

    def test_corrupt_state_is_not_silently_replaced(self):
        path = self.base / 'state.json'
        path.write_text('broken')
        with self.assertRaises(RuntimeError):
            StateManager.save_profile({'name':'a'})
        self.assertEqual(path.read_text(), 'broken')

    def test_backup_is_the_first_snapshot(self):
        path = self.base / 'a.json'
        path.write_text('{"http.proxy":null}')
        before = path.read_bytes()
        apply_json_batch([('a', str(path), {'http.proxy':'http://a:80'})])
        apply_json_batch([('a', str(path), {'http.proxy':'http://b:80'})])
        restore_json_batch(['a'])
        self.assertEqual(Path(str(path)+'.bak').read_bytes(), before)
        self.assertIsNone(parse_jsonc(path.read_text())['http.proxy'])

    def test_root_type_duplicate_keys_and_empty_existing_file_refused(self):
        for source in ('[]', 'null', '{"a":1,"a":2}', '', '{/* unterminated'):
            with self.subTest(source=source):
                path = self.base / 'a.json'
                path.write_text(source)
                self.assertIsNone(ConfigEditor.load_jsonc(str(path))[0])
                with self.assertRaises(ValueError):
                    apply_json_batch([('a', str(path), {'http.proxy':'http://a:80'})])
                self.assertEqual(path.read_text(), source)

    def test_existing_credentials_are_not_copied_into_state(self):
        path = self.base / 'a.json'
        path.write_text('{"http.proxy":"http://u:fixture-secret@host:80"}')
        with self.assertRaises(ValueError):
            apply_json_batch([('a', str(path), {'http.proxy':'http://a:80'})])
        self.assertFalse((self.base / 'state.json').exists())

    def test_restore_failure_keeps_record_and_file(self):
        path = self.base / 'a.json'
        path.write_text('{}')
        apply_json_batch([('a', str(path), {'http.proxy':'http://a:80'})])
        before, state = path.read_bytes(), StateManager.load_state()
        write = ConfigEditor.atomic_write

        def fail(target, content, **kwargs):
            if str(target) == str(path):
                raise PermissionError('fixture failure')
            return write(target, content, **kwargs)

        with patch.object(ConfigEditor, 'atomic_write', side_effect=fail), self.assertRaises(PermissionError):
            restore_json_batch(['a'])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(StateManager.load_state(), state)
