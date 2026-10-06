"""Exercise the real Tk clipboard, selection and layout-independent shortcuts."""
import sys
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest import mock

from devproxy_pkg.ui_editing import editable_entry, _control_key


class TextEditingTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.geometry("300x100+30000+30000")
        self.addCleanup(self.root.destroy)
        try:
            self.previous_clipboard = self.root.clipboard_get()
        except tk.TclError:
            self.previous_clipboard = None
        self.addCleanup(self.restore_clipboard)
        self.entry = editable_entry(self.root)
        self.entry.pack()
        self.root.update()
        self.entry.focus_force()
        self.root.update()

    def restore_clipboard(self):
        self.root.clipboard_clear()
        if self.previous_clipboard is not None:
            self.root.clipboard_append(self.previous_clipboard)
        self.root.update()

    def clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def test_ctrl_v_replaces_selection_once(self):
        self.entry.insert(0, "old")
        self.entry.selection_range(0, "end")
        self.clipboard("proxy.example.com")
        self.entry.event_generate("<Control-KeyPress>", keycode=86) if sys.platform == "win32" else self.entry.event_generate("<Control-v>")
        self.root.update()
        self.assertEqual(self.entry.get(), "proxy.example.com")

    def test_shift_insert_pastes_unicode(self):
        self.clipboard("Прокси для IDE")
        self.entry.event_generate("<Shift-Insert>")
        self.root.update()
        self.assertEqual(self.entry.get(), "Прокси для IDE")

    @unittest.skipUnless(sys.platform == "win32", "Windows physical keycodes")
    def test_russian_ctrl_shortcuts_edit_real_clipboard(self):
        self.entry.insert(0, "старый")
        _control_key(self.entry, SimpleNamespace(state=4, keycode=65, keysym="Cyrillic_ef"))
        self.assertTrue(self.entry.selection_present())
        self.clipboard("новый")
        result = _control_key(self.entry, SimpleNamespace(state=4, keycode=86, keysym="Cyrillic_em"))
        self.assertEqual(result, "break")
        self.assertEqual(self.entry.get(), "новый")
        _control_key(self.entry, SimpleNamespace(state=4, keycode=65, keysym="Cyrillic_ef"))
        _control_key(self.entry, SimpleNamespace(state=4, keycode=67, keysym="Cyrillic_es"))
        self.assertEqual(self.root.clipboard_get(), "новый")
        _control_key(self.entry, SimpleNamespace(state=4, keycode=88, keysym="Cyrillic_che"))
        self.assertEqual(self.entry.get(), "")
        self.assertEqual(self.root.clipboard_get(), "новый")

    def test_right_click_menu_pastes_over_selection(self):
        self.entry.insert(0, "before")
        self.entry.selection_range(0, "end")
        self.clipboard("after")
        menu = self.entry.edit_menu
        with mock.patch.object(menu, "tk_popup") as popup:
            self.entry.event_generate("<Button-3>", x=5, y=5)
        popup.assert_called_once()
        self.assertEqual(menu.entrycget(2, "label"), "Вставить")
        menu.invoke(2)
        self.assertEqual(self.entry.get(), "after")

    def test_disabled_and_readonly_fields_reject_paste(self):
        self.clipboard("new")
        self.entry.insert(0, "original")
        for state in ("disabled", "readonly"):
            self.entry.configure(state=state)
            self.entry.edit_menu.invoke(2)
            self.assertEqual(self.entry.get(), "original")
        self.entry.configure(state="normal")

    def test_password_field_pastes_and_stays_masked(self):
        self.entry.configure(show="•")
        self.clipboard("пароль:secret")
        self.entry.event_generate("<Control-KeyPress>", keycode=86) if sys.platform == "win32" else self.entry.event_generate("<Control-v>")
        self.root.update()
        self.assertEqual(self.entry.get(), "пароль:secret")
        self.assertEqual(self.entry.cget("show"), "•")
        self.entry.selection_range(0, "end")
        self.entry.edit_menu.invoke(1)
        self.assertNotIn("secret", self.root.clipboard_get())

    def test_altgr_does_not_trigger_paste(self):
        self.clipboard("unexpected")
        result = _control_key(self.entry, SimpleNamespace(state=4 | 0x20000, keycode=86, keysym="v"))
        self.assertIsNone(result)
        self.assertEqual(self.entry.get(), "")


if __name__ == "__main__":
    unittest.main()
