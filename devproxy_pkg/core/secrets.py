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
    def is_available(cls) -> bool:
        return sys.platform == "win32"

    @classmethod
    def set_password(cls, profile_name: str, username: str, password: str) -> bool:
        if not cls.is_available():
            return False
        try:
            advapi32 = ctypes.windll.advapi32
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
            return bool(res)
        except Exception:
            return False

    @classmethod
    def get_password(cls, profile_name: str) -> Optional[str]:
        if not cls.is_available():
            return None
        try:
            advapi32 = ctypes.windll.advapi32
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
            advapi32 = ctypes.windll.advapi32
            target_name = f"{SERVICE_NAME}:{profile_name}"
            res = advapi32.CredDeleteW(target_name, cls.CRED_TYPE_GENERIC, 0)
            return bool(res)
        except Exception:
            return False


class MacOSKeychainStore:
    """macOS Keychain access using `/usr/bin/security`."""
    @classmethod
    def is_available(cls) -> bool:
        return sys.platform == "darwin" and os.path.exists("/usr/bin/security")

    @classmethod
    def set_password(cls, profile_name: str, username: str, password: str) -> bool:
        if not cls.is_available():
            return False
        import subprocess
        target = f"{SERVICE_NAME}:{profile_name}"
        # -U updates if existing
        cmd = [
            "/usr/bin/security", "add-generic-password",
            "-U", "-s", target, "-a", username or "proxy-user",
            "-w", password
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0

    @classmethod
    def get_password(cls, profile_name: str) -> Optional[str]:
        if not cls.is_available():
            return None
        import subprocess
        target = f"{SERVICE_NAME}:{profile_name}"
        cmd = ["/usr/bin/security", "find-generic-password", "-s", target, "-w"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
        return None

    @classmethod
    def delete_password(cls, profile_name: str) -> bool:
        if not cls.is_available():
            return False
        import subprocess
        target = f"{SERVICE_NAME}:{profile_name}"
        cmd = ["/usr/bin/security", "delete-generic-password", "-s", target]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0


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
            val = res.stdout.strip()
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

        stored = False
        if sys.platform == "win32":
            stored = WindowsCredentialStore.set_password(profile_name, username, password)
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
    def get_password(cls, profile_name: str) -> Optional[str]:
        """Retrieves password from OS vault or ephemeral memory."""
        # 1. Ephemeral cache first (if set during this run)
        mem_val = EphemeralStore.get(profile_name)
        if mem_val:
            return mem_val

        # 2. OS Keychain
        if sys.platform == "win32":
            return WindowsCredentialStore.get_password(profile_name)
        elif sys.platform == "darwin":
            return MacOSKeychainStore.get_password(profile_name)
        elif sys.platform.startswith("linux"):
            return LinuxSecretStore.get_password(profile_name)
        return None

    @classmethod
    def delete_password(cls, profile_name: str) -> bool:
        """Deletes password from OS vault and memory."""
        EphemeralStore.delete(profile_name)
        if sys.platform == "win32":
            return WindowsCredentialStore.delete_password(profile_name)
        elif sys.platform == "darwin":
            return MacOSKeychainStore.delete_password(profile_name)
        elif sys.platform.startswith("linux"):
            return LinuxSecretStore.delete_password(profile_name)
        return True
