"""
Codex Application Adapters:
1. CodexCliAdapter: CLI binary (`codex.exe` or `codex`), `.codex/config.toml`, sandbox processes.
2. CodexGuiAdapter: Codex Desktop GUI application (packaged MSIX/WindowsApps or Electron desktop binary).
"""

import os
import sys
import shutil
import re
from typing import List, Optional, Tuple
from .base import ApplicationAdapter
from ..core.profile import ProxyProfile
from ..core.config_editor import ConfigEditor
from ..core.recovery import StateManager


class CodexCliAdapter(ApplicationAdapter):
    @property
    def app_id(self) -> str:
        return "codex"

    @property
    def display_name(self) -> str:
        return "Codex CLI"

    @property
    def supported_os(self) -> List[str]:
        return ["win32", "darwin", "linux"]

    def detect_executable(self) -> Optional[str]:
        # 1. Check PATH
        p = shutil.which("codex") or shutil.which("codex.exe")
        if p:
            return p

        # 2. Check OpenAI Codex standard installed path
        if sys.platform == "win32":
            local = os.environ.get("LOCALAPPDATA", "")
            base = os.path.join(local, "OpenAI", "Codex", "bin")
            if os.path.exists(base):
                for entry in os.listdir(base):
                    sub = os.path.join(base, entry, "codex.exe")
                    if os.path.exists(sub):
                        return sub

        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, ".codex", "bin", "codex"),
            os.path.join(home, ".local", "bin", "codex"),
            "/usr/local/bin/codex"
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def detect_config_files(self) -> List[str]:
        home = os.path.expanduser("~")
        return [
            os.path.join(home, ".codex", "config.toml")
        ]

    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        return []

    def apply_persistent(self, profile: ProxyProfile) -> Tuple[bool, str]:
        configs = self.detect_config_files()
        target_path = configs[0]
        if not os.path.exists(target_path):
            return False, f"Codex config not found at {target_path}"

        proxy_url = profile.to_safe_url() if profile.has_auth else profile.to_url()
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            return False, f"Failed to read {target_path}: {e}"

        # Match proxy = "..." in config.toml
        orig_proxy = None
        m = re.search(r'^\s*proxy\s*=\s*"([^"]*)"', content, re.MULTILINE)
        if m:
            orig_proxy = m.group(1)

        StateManager.record_applied_change(
            self.app_id,
            target_path,
            {"proxy": proxy_url},
            {"proxy": orig_proxy}
        )

        if m:
            new_content = re.sub(r'^\s*proxy\s*=\s*"[^"]*"', f'proxy = "{proxy_url}"', content, flags=re.MULTILINE)
        else:
            new_content = f'proxy = "{proxy_url}"\n' + content

        try:
            ConfigEditor.atomic_write(target_path, new_content)
            return True, f"Updated {target_path} (proxy = \"{proxy_url}\")"
        except Exception as e:
            return False, str(e)

    def restore_persistent(self) -> Tuple[bool, str]:
        record = StateManager.get_applied_record(self.app_id)
        if not record:
            return False, "No persistent changes recorded for Codex CLI"

        messages = []
        for file_path, data in record.items():
            if not os.path.exists(file_path):
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                continue

            orig_proxy = data.get("original_values", {}).get("proxy")
            if orig_proxy:
                content = re.sub(r'^\s*proxy\s*=\s*"[^"]*"', f'proxy = "{orig_proxy}"', content, flags=re.MULTILINE)
            else:
                content = re.sub(r'^\s*proxy\s*=\s*"[^"]*"\n?', '', content, flags=re.MULTILINE)

            try:
                ConfigEditor.atomic_write(file_path, content)
                messages.append(f"Restored {file_path}")
            except Exception as e:
                messages.append(f"Error {file_path}: {e}")

        StateManager.clear_applied_record(self.app_id)
        return True, "; ".join(messages)

    def get_limitations(self) -> List[str]:
        return [
            "Codex CLI spawns sandbox subprocesses (cmd, node_repl, powershell).",
            "Session launch injects HTTP_PROXY and HTTPS_PROXY which propagate to spawned sandboxes.",
            "Streaming responses use HTTP SSE; TCP tunnel ensures no mid-stream reset."
        ]


class CodexGuiAdapter(ApplicationAdapter):
    """
    Adapter for Codex Desktop GUI (packaged app / desktop window).
    """
    @property
    def app_id(self) -> str:
        return "codex-gui"

    @property
    def display_name(self) -> str:
        return "Codex Desktop (GUI)"

    @property
    def supported_os(self) -> List[str]:
        return ["win32", "darwin"]

    def detect_executable(self) -> Optional[str]:
        # On Windows, Codex Desktop can be launched via standard URI protocol or WindowsApps
        if sys.platform == "win32":
            # Check Start menu shortcut or WindowsApps package
            winapps = "C:\\Program Files\\WindowsApps"
            if os.path.exists(winapps):
                try:
                    for entry in os.listdir(winapps):
                        if "OpenAI.Codex" in entry:
                            exe = os.path.join(winapps, entry, "app", "Codex.exe")
                            if os.path.exists(exe):
                                return exe
                except Exception:
                    pass

            local = os.environ.get("LOCALAPPDATA", "")
            candidates = [
                os.path.join(local, "Programs", "Codex", "Codex.exe"),
                os.path.join(local, "Programs", "OpenAI Codex", "Codex.exe")
            ]
            for c in candidates:
                if os.path.exists(c):
                    return c

        elif sys.platform == "darwin":
            candidates = [
                "/Applications/Codex.app/Contents/MacOS/Codex",
                os.path.expanduser("~/Applications/Codex.app/Contents/MacOS/Codex")
            ]
            for c in candidates:
                if os.path.exists(c):
                    return c

        return None

    def detect_config_files(self) -> List[str]:
        home = os.path.expanduser("~")
        return [
            os.path.join(home, ".codex", "config.toml")
        ]

    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        return ["--proxy-server={PROXY_URL}"]

    def apply_persistent(self, profile: ProxyProfile) -> Tuple[bool, str]:
        # Shares the underlying config.toml with Codex CLI
        cli = CodexCliAdapter()
        return cli.apply_persistent(profile)

    def restore_persistent(self) -> Tuple[bool, str]:
        cli = CodexCliAdapter()
        return cli.restore_persistent()

    def get_limitations(self) -> List[str]:
        return [
            "Codex Desktop GUI coordinates with background stdio core worker (codex.exe).",
            "Session launch with LocalTunnel routes both the GUI Electron frontend and the internal core worker.",
            "Packaged Windows Store MSIX versions may require launching via protocol handler if executable permissions are locked by OS."
        ]
