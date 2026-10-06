"""Credential Manager on Windows. Persistent saves never fall back silently."""
import ctypes
import os
import sys
from ctypes import wintypes

SERVICE_NAME = "devproxy-auth"


class EphemeralStore:
    _cache = {}

    @classmethod
    def set(cls, key, value):
        cls._cache[key] = value

    @classmethod
    def get(cls, key):
        return cls._cache.get(key)

    @classmethod
    def delete(cls, key):
        cls._cache.pop(key, None)


class WindowsCredentialStore:
    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.c_void_p), ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    @classmethod
    def _api(cls):
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        api.CredWriteW.argtypes = [ctypes.POINTER(cls.CREDENTIAL), wintypes.DWORD]
        api.CredWriteW.restype = wintypes.BOOL
        api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.POINTER(cls.CREDENTIAL))]
        api.CredReadW.restype = wintypes.BOOL
        api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        api.CredDeleteW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
        return api

    @classmethod
    def is_available(cls):
        return os.name == "nt"

    @classmethod
    def set_password(cls, profile_name, username, password):
        if not cls.is_available():
            return False
        blob = password.encode("utf-16le")
        if len(blob) > 2560:
            raise ValueError("Credential exceeds Windows storage limit")
        buffer = ctypes.create_string_buffer(blob)
        credential = cls.CREDENTIAL()
        credential.Type = 1
        credential.TargetName = f"{SERVICE_NAME}:{profile_name}"
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(buffer, ctypes.c_void_p)
        credential.Persist = 2
        credential.UserName = username or "proxy-user"
        return bool(cls._api().CredWriteW(ctypes.byref(credential), 0))

    @classmethod
    def get_password(cls, profile_name):
        if not cls.is_available():
            return None
        api = cls._api()
        pointer = ctypes.POINTER(cls.CREDENTIAL)()
        if not api.CredReadW(f"{SERVICE_NAME}:{profile_name}", 1, 0, ctypes.byref(pointer)):
            return None
        try:
            credential = pointer.contents
            return ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize).decode("utf-16le")
        finally:
            api.CredFree(pointer)

    @classmethod
    def delete_password(cls, profile_name):
        if not cls.is_available():
            return False
        return bool(cls._api().CredDeleteW(f"{SERVICE_NAME}:{profile_name}", 1, 0))


class SecretStore:
    @classmethod
    def store_password(cls, profile_name, username, password, require_persistent=False):
        if password is None:
            return "none"
        if WindowsCredentialStore.is_available() and WindowsCredentialStore.set_password(profile_name, username, password):
            EphemeralStore.delete(profile_name)
            return "os_keychain"
        if require_persistent:
            raise OSError("Windows Credential Manager unavailable; profile was not saved")
        EphemeralStore.set(profile_name, password)
        return "session_memory"

    @classmethod
    def get_password(cls, profile_name):
        memory = EphemeralStore.get(profile_name)
        return memory if memory is not None else WindowsCredentialStore.get_password(profile_name)

    @classmethod
    def delete_password(cls, profile_name):
        EphemeralStore.delete(profile_name)
        return WindowsCredentialStore.delete_password(profile_name)
