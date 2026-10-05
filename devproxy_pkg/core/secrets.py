"""
SecretStore: Secure, OS-native storage for proxy passwords.
- Windows: Windows Credential Manager / DPAPI (CryptProtectData via ctypes).
- macOS: Keychain via security tool.
- Linux: Secret Service via secret-tool or DBus.
- Fallback: Ephemeral in-memory storage (never saves unencrypted secrets to disk).
"""

import sys
import os
import ctypes
from typing import Optional
import hashlib
import json
from .dpapi import WindowsDPAPIStore


SERVICE_NAME = "devproxy-auth"


class EphemeralStore:
    """In-memory fallback for current process session only."""
    _cache = {}

    @classmethod
    def set(cls, key: str, value: str):
        cls._cache[key] = value

    @classmethod
    def get(cls, key: str) -> Optional[str]:
        return cls._cache.get(key)

    @classmethod
    def delete(cls, key: str):
        cls._cache.pop(key, None)


class WindowsCredentialStore:
    """
    Windows Credential Manager integration via Advapi32 CredWriteW / CredReadW / CredDeleteW.
    Standard, robust and non-destructive.
    """
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
            ("TargetName", ctypes.c_wchar_p),
            ("Comment", ctypes.c_wchar_p),
            ("LastWritten", ctypes.c_ulonglong),
            ("CredentialBlobSize", ctypes.c_ulong),
            ("CredentialBlob", ctypes.c_void_p),
            ("Persist", ctypes.c_ulong),
            ("AttributeCount", ctypes.c_ulong),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", ctypes.c_wchar_p),
            ("UserName", ctypes.c_wchar_p),
        ]

    @classmethod
    def _api(cls):
        from ctypes import wintypes
        api = ctypes.WinDLL('advapi32', use_last_error=True)
        api.CredWriteW.argtypes = [ctypes.POINTER(cls.CREDENTIAL), wintypes.DWORD]
        api.CredWriteW.restype = wintypes.BOOL
        api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(cls.CREDENTIAL))]
        api.CredReadW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
        api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        api.CredDeleteW.restype = wintypes.BOOL
        return api

    @classmethod
    def is_available(cls) -> bool:
        return sys.platform == "win32"

    @classmethod
    def set_password(cls, profile_name: str, username: str, password: str) -> bool:
        if not cls.is_available():
            return False
        try:
            advapi32 = cls._api()
            target_name = f"{SERVICE_NAME}:{profile_name}"
            blob = password.encode("utf-16le")
            
            cred = cls.CREDENTIAL()
            cred.Flags = 0
            cred.Type = cls.CRED_TYPE_GENERIC
            cred.TargetName = target_name
            cred.Comment = "DevProxy secure credentials"
            cred.CredentialBlobSize = len(blob)
            cred.CredentialBlob = ctypes.cast(ctypes.c_char_p(blob), ctypes.c_void_p)
            cred.Persist = cls.CRED_PERSIST_LOCAL_MACHINE
            cred.AttributeCount = 0
            cred.Attributes = None
            cred.TargetAlias = None
            cred.UserName = username or "proxy-user"

            res = advapi32.CredWriteW(ctypes.byref(cred), 0)
            cls.last_error = 0 if res else ctypes.get_last_error()
            return bool(res)
        except Exception:
            return False

    @classmethod
    def get_password(cls, profile_name: str) -> Optional[str]:
        if not cls.is_available():
            return None
        try:
            advapi32 = cls._api()
            target_name = f"{SERVICE_NAME}:{profile_name}"
            p_cred = ctypes.POINTER(cls.CREDENTIAL)()
            
            res = advapi32.CredReadW(target_name, cls.CRED_TYPE_GENERIC, 0, ctypes.byref(p_cred))
            if not res or not p_cred:
                return None
            
            cred = p_cred.contents
            blob_size = cred.CredentialBlobSize
            blob_ptr = cred.CredentialBlob
            
            if blob_ptr and blob_size > 0:
                raw_bytes = ctypes.string_at(blob_ptr, blob_size)
                advapi32.CredFree(p_cred)
                return raw_bytes.decode("utf-16le", errors="ignore")
            
            advapi32.CredFree(p_cred)
            return None
        except Exception:
            return None

    @classmethod
    def delete_password(cls, profile_name: str) -> bool:
        if not cls.is_available():
            return False
        try:
            advapi32 = cls._api()
            target_name = f"{SERVICE_NAME}:{profile_name}"
            res = advapi32.CredDeleteW(target_name, cls.CRED_TYPE_GENERIC, 0)
            return bool(res) or ctypes.get_last_error() in (1168, 1312)
        except Exception:
            return False


class MacOSKeychainStore:
    """Security.framework API: password bytes never enter a process argument."""
    @classmethod
    def is_available(cls):
        return sys.platform == 'darwin'

    @classmethod
    def _api(cls):
        api = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        u32, ptr = ctypes.c_uint32, ctypes.c_void_p
        api.SecKeychainFindGenericPassword.argtypes = [ptr, u32, ctypes.c_char_p, u32, ctypes.c_char_p, ctypes.POINTER(u32), ctypes.POINTER(ptr), ctypes.POINTER(ptr)]
        api.SecKeychainAddGenericPassword.argtypes = [ptr, u32, ctypes.c_char_p, u32, ctypes.c_char_p, u32, ctypes.c_char_p, ctypes.POINTER(ptr)]
        api.SecKeychainItemModifyAttributesAndData.argtypes = [ptr, ptr, u32, ctypes.c_char_p]
        api.SecKeychainItemDelete.argtypes = [ptr]
        api.SecKeychainItemFreeContent.argtypes = [ptr, ptr]
        for name in ('SecKeychainFindGenericPassword', 'SecKeychainAddGenericPassword', 'SecKeychainItemModifyAttributesAndData', 'SecKeychainItemDelete', 'SecKeychainItemFreeContent'):
            getattr(api, name).restype = ctypes.c_int32
        return api

    @classmethod
    def _find(cls, profile_name):
        api = cls._api()
        service, account = SERVICE_NAME.encode(), profile_name.encode('utf-8')
        size, data, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
        status = api.SecKeychainFindGenericPassword(None, len(service), service, len(account), account, ctypes.byref(size), ctypes.byref(data), ctypes.byref(item))
        password = None
        if status == 0:
            try:
                password = ctypes.string_at(data, size.value).decode('utf-8')
            finally:
                api.SecKeychainItemFreeContent(None, data)
        return api, status, item, password

    @classmethod
    def _release(cls, item):
        if item:
            core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            core.CFRelease.argtypes = [ctypes.c_void_p]
            core.CFRelease.restype = None
            core.CFRelease(item)

    @classmethod
    def set_password(cls, profile_name, username, password):
        if not cls.is_available():
            return False
        api, status, item, _ = cls._find(profile_name)
        service, account, value = SERVICE_NAME.encode(), profile_name.encode('utf-8'), password.encode('utf-8')
        try:
            if status == 0:
                return api.SecKeychainItemModifyAttributesAndData(item, None, len(value), value) == 0
            if status != -25300:
                return False
            return api.SecKeychainAddGenericPassword(None, len(service), service, len(account), account, len(value), value, None) == 0
        finally:
            cls._release(item)

    @classmethod
    def get_password(cls, profile_name):
        if not cls.is_available():
            return None
        _, _, item, password = cls._find(profile_name)
        cls._release(item)
        return password

    @classmethod
    def delete_password(cls, profile_name):
        if not cls.is_available():
            return False
        api, status, item, _ = cls._find(profile_name)
        try:
            return status == -25300 or (status == 0 and api.SecKeychainItemDelete(item) == 0)
        finally:
            cls._release(item)


class LinuxSecretStore:
    """Linux Secret Service via `secret-tool`."""
    @classmethod
    def is_available(cls) -> bool:
        if sys.platform != "linux":
            return False
        import shutil
        return shutil.which("secret-tool") is not None

    @classmethod
    def set_password(cls, profile_name: str, username: str, password: str) -> bool:
        if not cls.is_available():
            return False
        import subprocess
        cmd = [
            "secret-tool", "store",
            "--label", f"DevProxy {profile_name}",
            "service", SERVICE_NAME,
            "profile", profile_name
        ]
        p = subprocess.run(cmd, input=password.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.returncode == 0

    @classmethod
    def get_password(cls, profile_name: str) -> Optional[str]:
        if not cls.is_available():
            return None
        import subprocess
        cmd = [
            "secret-tool", "lookup",
            "service", SERVICE_NAME,
            "profile", profile_name
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode == 0:
            val = res.stdout.removesuffix('\n')
            return val if val else None
        return None

    @classmethod
    def delete_password(cls, profile_name: str) -> bool:
        if not cls.is_available():
            return False
        import subprocess
        cmd = [
            "secret-tool", "clear",
            "service", SERVICE_NAME,
            "profile", profile_name
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0


class SecretStore:
    """
    Unified SecretStore facade for secure credential storage.
    Delegates to platform native store, with safe ephemeral session memory fallback.
    Never prints secrets or writes them unencrypted to files.
    """
    @classmethod
    def store_password(cls, profile_name: str, username: str, password: str) -> str:
        """Stores password securely. Returns backend used: 'os_keychain' or 'session_memory'."""
        if not password:
            return "none"

        if os.environ.get("DEVPROXY_SECRET_BACKEND") == "memory":
            EphemeralStore.set(profile_name, password)
            return "session_memory"

        stored = False
        if sys.platform == "win32":
            stored = WindowsCredentialStore.set_password(profile_name, username, password)
            if not stored and WindowsDPAPIStore.set_password(profile_name, password):
                return 'os_dpapi'
        elif sys.platform == "darwin":
            stored = MacOSKeychainStore.set_password(profile_name, username, password)
        elif sys.platform.startswith("linux"):
            stored = LinuxSecretStore.set_password(profile_name, username, password)

        if stored:
            return "os_keychain"
        
        # Ephemeral in-memory fallback
        EphemeralStore.set(profile_name, password)
        return "session_memory"

    @classmethod
    def get_password(cls, profile_name: str, backend=None) -> Optional[str]:
        """Retrieves password from OS vault or ephemeral memory."""
        # Saved profiles bind to the store that accepted this exact revision.
        # Never revive an older fallback password when the primary vault fails.
        if backend == 'os_dpapi':
            return WindowsDPAPIStore.get_password(profile_name) if sys.platform == 'win32' else None
        if backend not in (None, 'os_keychain', 'session_memory'):
            return None
        # 1. Ephemeral cache first (if set during this run)
        mem_val = EphemeralStore.get(profile_name)
        if mem_val:
            return mem_val

        if os.environ.get("DEVPROXY_SECRET_BACKEND") == "memory":
            return None

        # 2. OS Keychain
        if sys.platform == "win32":
            native = WindowsCredentialStore.get_password(profile_name)
            return native if backend == 'os_keychain' else native or WindowsDPAPIStore.get_password(profile_name)
        elif sys.platform == "darwin":
            return MacOSKeychainStore.get_password(profile_name)
        elif sys.platform.startswith("linux"):
            return LinuxSecretStore.get_password(profile_name)
        return None

    @classmethod
    def delete_password(cls, profile_name: str) -> bool:
        """Deletes password from OS vault and memory."""
        EphemeralStore.delete(profile_name)
        if os.environ.get("DEVPROXY_SECRET_BACKEND") == "memory":
            return True
        if sys.platform == "win32":
            native = WindowsCredentialStore.delete_password(profile_name)
            fallback = WindowsDPAPIStore.delete_password(profile_name)
            return native and fallback
        elif sys.platform == "darwin":
            return MacOSKeychainStore.delete_password(profile_name)
        elif sys.platform.startswith("linux"):
            return LinuxSecretStore.delete_password(profile_name)
        return True


def credential_key(profile):
    identity = [profile.name, profile.protocol, profile.host, profile.port, profile.username]
    return 'endpoint-' + hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
