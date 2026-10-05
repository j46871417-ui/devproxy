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
                os.path.join(home, ".config", self._folder_name, "User", "settings.json"),
                # Flatpak path
                os.path.expanduser(f"~/.var/app/com.visualstudio.{self._bin_names[0]}/config/{self._folder_name}/User/settings.json")
            ]

    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        return ["--proxy-server={PROXY_URL}"]

    def apply_persistent(self, profile: ProxyProfile) -> Tuple[bool, str]:
        configs = self.detect_config_files()
        target_path = configs[0]
        parsed, raw = ConfigEditor.load_jsonc(target_path)
        if parsed is None:
            return False, f"Failed to parse JSONC in {target_path}. File may contain syntax errors."

        proxy_url = profile.to_safe_url() if profile.has_auth else profile.to_url()
        orig_proxy = parsed.get("http.proxy")
        orig_support = parsed.get("http.proxySupport")

        updates = {
            "http.proxy": proxy_url,
            "http.proxySupport": "on"
            # Strict SSL remains unmodified (never disabled)
        }

        StateManager.record_applied_change(
            self.app_id,
            target_path,
            updates,
            {"http.proxy": orig_proxy, "http.proxySupport": orig_support}
        )

        new_content = ConfigEditor.update_json_fields_preserving(raw, updates)
        try:
            ConfigEditor.atomic_write(target_path, new_content)
            return True, f"Configured {target_path}"
        except Exception as e:
            return False, str(e)

    def restore_persistent(self) -> Tuple[bool, str]:
        record = StateManager.get_applied_record(self.app_id)
        if not record:
            return False, f"No persistent changes recorded for {self.display_name}"

        messages = []
        for file_path, data in record.items():
            if not os.path.exists(file_path):
                continue
            parsed, raw = ConfigEditor.load_jsonc(file_path)
            if parsed is None:
                continue

            orig_values = data.get("original_values", {})
            keys_to_remove = []
            updates = {}
            for k, v in orig_values.items():
                if v is None:
                    keys_to_remove.append(k)
                else:
                    updates[k] = v

            content = raw
            if keys_to_remove:
                content = ConfigEditor.remove_json_fields_preserving(content, keys_to_remove)
            if updates:
                content = ConfigEditor.update_json_fields_preserving(content, updates)

            try:
                ConfigEditor.atomic_write(file_path, content)
                messages.append(f"Restored {file_path}")
            except Exception as e:
                messages.append(f"Error {file_path}: {e}")

        StateManager.clear_applied_record(self.app_id)
        return True, "; ".join(messages)

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
        lim.append("Windsurf utilizes Codeium language server daemon; session launch ensures daemon inherits tunnel.")
        return lim


class VSCodiumAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("vscodium", "VSCodium", "VSCodium", ["codium", "VSCodium"])
