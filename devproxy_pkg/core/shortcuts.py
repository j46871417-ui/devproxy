"""Conflict-aware shortcut edits and per-user login startup."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys


def app_command():
    if getattr(sys, "frozen", False):
        gui = Path(sys.executable).with_name("devproxy-gui.exe")
        return [str(gui if gui.exists() else Path(sys.executable))]
    built = Path(__file__).resolve().parents[2] / "dist" / "devproxy-gui.exe"
    if built.exists():
        return [str(built)]
    python = Path(sys.executable).with_name("pythonw.exe")
    return [str(python if python.exists() else Path(sys.executable)),
            str(Path(__file__).resolve().parents[2] / "devproxy_gui.py")]


def split_arguments(arguments):
    if not arguments:
        return []
    from ctypes import wintypes
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel = ctypes.WinDLL("kernel32")
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    count = ctypes.c_int()
    pointer = shell.CommandLineToArgvW('app.exe ' + arguments, ctypes.byref(count))
    if not pointer:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [pointer[i] for i in range(1, count.value)]
    finally:
        kernel.LocalFree(pointer)


def shortcut_call(payload):
    script = Path(__file__).resolve().parents[1] / "resources" / "shortcuts.ps1"
    process = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)],
                             input=json.dumps(payload, ensure_ascii=False), encoding="utf-8",
                             capture_output=True, errors="replace", timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        result = json.loads(process.stdout.lstrip("\ufeff"))
    except (ValueError, UnicodeError):
        raise RuntimeError("Не удалось прочитать ярлыки Windows.") from None
    if process.returncode or not result.get("ok"):
        raise RuntimeError(result.get("error", "Не удалось изменить ярлыки Windows."))
    return result


def inspect_shortcuts(executable):
    return shortcut_call({"action": "inspect", "executable": os.path.abspath(executable)})["links"]


def broker_shortcut(original, app_id):
    command = app_command()
    arguments = split_arguments(original.get("arguments", ""))
    return dict(path=original["path"], target=command[0],
                arguments=subprocess.list2cmdline(command[1:] + ["--launch-app", app_id, "--"] + arguments),
                icon=original.get("icon") or original["target"] + ",0",
                directory=original.get("directory", ""))


def write_shortcut(path, expected, value):
    shortcut_call({"action": "write", "edits": [dict(path=path, expected=expected, value=value)]})


class LoginStartup:
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    NAME = "DevProxy"

    @classmethod
    def read(cls):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.KEY) as key:
                value, kind = winreg.QueryValueEx(key, cls.NAME)
            return {"value": value, "kind": kind}
        except FileNotFoundError:
            return None

    @classmethod
    def expected(cls):
        import winreg
        return {"value": subprocess.list2cmdline(app_command() + ["--background"]), "kind": winreg.REG_SZ}

    @classmethod
    def write(cls, expected, value):
        import winreg
        if cls.read() != expected:
            raise RuntimeError("Запись автозапуска изменена другой программой; она сохранена.")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cls.KEY) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, cls.NAME)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, cls.NAME, 0, value["kind"], value["value"])
