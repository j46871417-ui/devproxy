"""
OpenCode Application Adapter.
Supports:
- CLI mode (`opencode`)
- Web/Desktop GUI if launched
- Node.js network runtime environment (fetch, undici, node-fetch)
"""

import os
import sys
import shutil
from typing import List, Optional, Tuple
from .base import ApplicationAdapter
from ..core.profile import ProxyProfile
from ..core.config_editor import ConfigEditor
from ..core.recovery import StateManager


class OpenCodeAdapter(ApplicationAdapter):
    @property
    def app_id(self) -> str:
        return "opencode"

    @property
    def display_name(self) -> str:
        return "OpenCode"

    @property
    def supported_os(self) -> List[str]:
        return ["win32", "darwin", "linux"]

    def detect_executable(self) -> Optional[str]:
        p = shutil.which("opencode") or shutil.which("OpenCode")
        if p:
            return p

        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, ".opencode", "bin", "opencode"),
            os.path.join(home, ".opencode", "bin", "opencode.exe"),
            os.path.join(home, "AppData", "Roaming", "npm", "opencode.cmd"),
            os.path.join(home, "AppData", "Local", "Programs", "OpenCode", "OpenCode.exe")
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def detect_config_files(self) -> List[str]:
        home = os.path.expanduser("~")
        return [
            os.path.join(home, ".opencode", "config.json"),
            os.path.join(home, ".config", "opencode", "config.json")
        ]

    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        return []

    def apply_persistent(self, profile: ProxyProfile) -> Tuple[bool, str]:
        configs = self.detect_config_files()
        target_path = configs[0]
        parsed, raw = ConfigEditor.load_jsonc(target_path)
        if parsed is None:
            return False, f"Failed to parse config in {target_path}"

        proxy_url = profile.to_safe_url() if profile.has_auth else profile.to_url()
        orig_proxy = parsed.get("proxy")

        updates = {"proxy": proxy_url}
        StateManager.record_applied_change(
            self.app_id,
            target_path,
            updates,
            {"proxy": orig_proxy}
        )

        new_content = ConfigEditor.update_json_fields_preserving(raw, updates)
        try:
            ConfigEditor.atomic_write(target_path, new_content)
            return True, f"Updated {target_path}"
        except Exception as e:
            return False, str(e)

    def restore_persistent(self) -> Tuple[bool, str]:
        record = StateManager.get_applied_record(self.app_id)
        if not record:
            return False, "No persistent changes recorded for OpenCode"

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
            "OpenCode runs in Node.js runtime; uses HTTP_PROXY / HTTPS_PROXY environment variables.",
            "Child tool executions inherit session environment variables.",
            "Streaming responses use HTTP chunked transfer / SSE."
        ]
