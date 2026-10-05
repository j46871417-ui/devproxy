"""
Generic VS Code Family Adapter for:
- Visual Studio Code
- Cursor
- Windsurf
- VSCodium
"""

import os
import sys
import shutil
from typing import List, Optional, Tuple
from .base import ApplicationAdapter
from ..core.profile import ProxyProfile
from ..core.config_editor import ConfigEditor
from ..core.recovery import StateManager


class VSCodeFamilyAdapter(ApplicationAdapter):
    def __init__(self, app_id: str, display_name: str, folder_name: str, bin_names: List[str]):
        self._app_id = app_id
        self._display_name = display_name
        self._folder_name = folder_name
        self._bin_names = bin_names

    @property
    def app_id(self) -> str:
        return self._app_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def supported_os(self) -> List[str]:
        return ["win32", "darwin", "linux"]

    def detect_executable(self) -> Optional[str]:
        if sys.platform == 'win32':
            executable = {'vscode': 'Code.exe', 'cursor': 'Cursor.exe', 'windsurf': 'Windsurf.exe',
                          'vscodium': 'VSCodium.exe', 'antigravity': 'Antigravity.exe'}.get(self.app_id, self._bin_names[-1] + '.exe')
            folders = [self._folder_name, self._display_name]
            if self.app_id == 'vscode':
                folders.insert(0, 'Microsoft VS Code')
            for base in (os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs'),
                         os.environ.get('ProgramFiles', r'C:\Program Files')):
                for folder in folders:
                    candidate = os.path.join(base, folder, executable)
                    if os.path.isfile(candidate):
                        return candidate
        if sys.platform == 'darwin':
            for binary in ('Electron', self._folder_name):
                candidate = f'/Applications/{self._display_name}.app/Contents/MacOS/{binary}'
                if os.path.isfile(candidate):
                    return candidate
        # Check PATH first
        for b in self._bin_names:
            p = shutil.which(b)
            if p:
                return p

        # Check standard installation folders
        candidates = []
        if sys.platform == "win32":
            local = os.environ.get("LOCALAPPDATA", "")
            prog = os.environ.get("ProgramFiles", "C:\\Program Files")
            for b in self._bin_names:
                exe = f"{b}.exe" if not b.endswith(".exe") else b
                candidates.extend([
                    os.path.join(local, "Programs", self._folder_name, exe),
                    os.path.join(local, "Programs", self._display_name, exe),
                    os.path.join(prog, self._folder_name, exe),
                    os.path.join(prog, self._display_name, exe),
                ])
        elif sys.platform == "darwin":
            app_name = f"{self._display_name}.app"
            candidates.extend([
                f"/Applications/{app_name}/Contents/Resources/app/bin/{self._bin_names[0]}",
                f"/Applications/{app_name}/Contents/MacOS/Electron",
                os.path.expanduser(f"~/Applications/{app_name}/Contents/MacOS/Electron")
            ])
        else:
            for b in self._bin_names:
                candidates.extend([
                    f"/usr/bin/{b}",
                    f"/usr/local/bin/{b}",
                    os.path.expanduser(f"~/.local/bin/{b}")
                ])

        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def detect_config_files(self) -> List[str]:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA", "")
            return [os.path.join(appdata, self._folder_name, "User", "settings.json")]
        elif sys.platform == "darwin":
            home = os.path.expanduser("~")
            return [os.path.join(home, "Library", "Application Support", self._folder_name, "User", "settings.json")]
        else:
            home = os.path.expanduser("~")
            return [
                os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config")), self._folder_name, "User", "settings.json"),
                # Flatpak path
                os.path.expanduser(f"~/.var/app/{self.flatpak_id()}/config/{self._folder_name}/User/settings.json")
            ]

    def flatpak_id(self):
        return {"vscode": "com.visualstudio.code", "vscodium": "com.vscodium.codium"}.get(self.app_id, self.app_id)

    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        return ["--proxy-server={PROXY_URL}", "--disable-quic", "--new-window"]

    session_gui = True

    def persistent_plan(self, profile, config_path=None):
        if profile.has_auth or profile.is_socks:
            raise ValueError("Authenticated and SOCKS proxies require session mode; use devproxy run.")
        candidates = list(dict.fromkeys(os.path.abspath(p) for p in self.detect_config_files()))
        existing = [p for p in candidates if os.path.exists(p)]
        if config_path:
            target = os.path.abspath(os.path.expanduser(config_path))
        elif len(existing) == 1:
            target = existing[0]
        elif len(existing) > 1:
            raise ValueError("Multiple settings files found; select --config-path explicitly.")
        else:
            raise ValueError("No settings file found; select --config-path explicitly to create one.")
        return self.app_id, target, {"http.proxy": profile.to_url(False), "http.proxySupport": "on"}

    def apply_persistent(self, profile):
        from ..core.recovery import apply_json_batch
        try:
            plan = self.persistent_plan(profile)
            apply_json_batch([plan])
            return True, "Configured " + plan[1]
        except (OSError, ValueError, RuntimeError) as error:
            return False, str(error)

    def restore_persistent(self):
        from ..core.recovery import restore_json_batch
        try:
            restore_json_batch([self.app_id])
            return True, "Original settings restored."
        except (OSError, ValueError, RuntimeError) as error:
            return False, str(error)

    def get_limitations(self) -> List[str]:
        return [
            f"{self.display_name} extensionHost runs out-of-process and requires env vars HTTP_PROXY/HTTPS_PROXY.",
            "Integrated terminal sessions inherit shell environment variables.",
            "Some 3rd-party extensions ignore 'http.proxy' and only respect process env vars."
        ]


# Specific subclasses
class VSCodeAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("vscode", "Visual Studio Code", "Code", ["code", "Code"])


class CursorAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("cursor", "Cursor", "Cursor", ["cursor", "Cursor"])

    def get_limitations(self) -> List[str]:
        lim = super().get_limitations()
        lim.append("Cursor AI chat and indexing communicate with api2.cursor.sh using HTTP/2; SOCKS5 / transparent tunnel recommended.")
        return lim


class WindsurfAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("windsurf", "Windsurf", "Windsurf", ["windsurf", "Windsurf"])

    def get_limitations(self) -> List[str]:
        lim = super().get_limitations()
        lim.append("Windsurf utilizes Codeium language server daemon; background daemons may retain an older environment; restart them for the session.")
        return lim


class VSCodiumAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("vscodium", "VSCodium", "VSCodium", ["codium", "VSCodium"])
