"""Native text editing with Windows shortcuts independent of keyboard layout."""
import sys
import tkinter as tk
from tkinter import ttk


_EDIT_EVENTS = {"a": "<<SelectAll>>", "c": "<<Copy>>", "v": "<<Paste>>", "x": "<<Cut>>"}
_WINDOWS_KEYS = {65: "a", 67: "c", 86: "v", 88: "x"}


def _edit(entry, action):
    entry.event_generate(action)
    return "break"


def _control_key(entry, event):
    # AltGr uses Ctrl+Alt; do not consume characters entered with it.
    if event.state & (0x8 | 0x20000):
        return None
    key = _WINDOWS_KEYS.get(event.keycode) if sys.platform == "win32" else None
    key = key or event.keysym.lower()
    action = _EDIT_EVENTS.get(key)
    return _edit(entry, action) if action else None


def editable_entry(parent, **options):
    """Create an Entry with native paste, select-all and a Russian edit menu."""
    entry = ttk.Entry(parent, **options)
    entry.bind("<Control-KeyPress>", lambda event: _control_key(entry, event))
    for sequence, action in (("<Shift-Insert>", "<<Paste>>"),
                             ("<Control-Insert>", "<<Copy>>"),
                             ("<Shift-Delete>", "<<Cut>>")):
        entry.bind(sequence, lambda event, action=action: _edit(entry, action))

    menu = tk.Menu(entry, tearoff=False)
    for label, action, accelerator in (("Вырезать", "<<Cut>>", "Ctrl+X"),
                                      ("Копировать", "<<Copy>>", "Ctrl+C"),
                                      ("Вставить", "<<Paste>>", "Ctrl+V")):
        menu.add_command(label=label, accelerator=accelerator,
                         command=lambda action=action: _edit(entry, action))
    menu.add_separator()
    menu.add_command(label="Выделить всё", accelerator="Ctrl+A",
                     command=lambda: _edit(entry, "<<SelectAll>>"))
    entry.edit_menu = menu

    def popup(event):
        entry.focus_set()
        editable = not entry.instate(("disabled",)) and not entry.instate(("readonly",))
        selected = entry.selection_present() and not entry.instate(("disabled",))
        menu.entryconfigure(0, state="normal" if editable and selected else "disabled")
        menu.entryconfigure(1, state="normal" if selected else "disabled")
        menu.entryconfigure(2, state="normal" if editable else "disabled")
        menu.entryconfigure(4, state="normal" if not entry.instate(("disabled",)) else "disabled")
        if event.type == tk.EventType.ButtonPress:
            x, y = event.x_root, event.y_root
        else:
            x, y = entry.winfo_rootx(), entry.winfo_rooty() + entry.winfo_height()
        try:
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()
        return "break"

    entry.bind("<Button-3>", popup)
    entry.bind("<Shift-F10>", popup)
    entry.bind("<KeyPress-Menu>", popup)
    return entry
