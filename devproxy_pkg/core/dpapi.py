"""Current-user DPAPI fallback when the Windows credential vault is unavailable."""
import ctypes
import hashlib
import os
import sys
from pathlib import Path
from .config_editor import ConfigEditor
from .recovery import get_devproxy_state_path


class WindowsDPAPIStore:
    @staticmethod
    def _path(key):
        directory = Path(get_devproxy_state_path()).parent / 'vault'
        return directory / (hashlib.sha256(key.encode('utf-8')).hexdigest() + '.dpapi')

    @staticmethod
    def _transform(value, key, protect):
        from ctypes import wintypes as w

        class Blob(ctypes.Structure):
            _fields_ = [('size', w.DWORD), ('data', ctypes.c_void_p)]

        crypt = ctypes.WinDLL('crypt32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
        crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), w.LPCWSTR, ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(Blob)]
        crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(Blob)]
        crypt.CryptProtectData.restype = crypt.CryptUnprotectData.restype = w.BOOL
        source_buffer = ctypes.create_string_buffer(value)
        entropy_buffer = ctypes.create_string_buffer(('devproxy:' + key).encode('utf-8'))
        source = Blob(len(value), ctypes.cast(source_buffer, ctypes.c_void_p))
        entropy = Blob(len(entropy_buffer.value), ctypes.cast(entropy_buffer, ctypes.c_void_p))
        output = Blob()
        function = crypt.CryptProtectData if protect else crypt.CryptUnprotectData
        ok = function(ctypes.byref(source), 'DevProxy password' if protect else None, ctypes.byref(entropy), None, None, 1, ctypes.byref(output))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(output.data, output.size)
        finally:
            kernel.LocalFree(output.data)

    @classmethod
    def set_password(cls, key, password):
        if sys.platform != 'win32':
            return False
        try:
            encrypted = cls._transform(password.encode('utf-8'), key, True)
            path = cls._path(key)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            ConfigEditor.atomic_write(str(path), encrypted, backup=False)
            os.chmod(path, 0o600)
            return True
        except OSError:
            return False

    @classmethod
    def get_password(cls, key):
        if sys.platform != 'win32':
            return None
        try:
            return cls._transform(cls._path(key).read_bytes(), key, False).decode('utf-8')
        except (OSError, UnicodeError):
            return None

    @classmethod
    def delete_password(cls, key):
        if sys.platform != 'win32':
            return False
        try:
            cls._path(key).unlink(missing_ok=True)
            return True
        except OSError:
            return False
