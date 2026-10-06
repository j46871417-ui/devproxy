"""Explicit executable selection; no recursive disk scanning or shell wrappers."""
import os
from .base import ApplicationAdapter


class GenericApplicationAdapter(ApplicationAdapter):
    def __init__(self, executable):
        executable = os.path.realpath(executable)
        if not os.path.isfile(executable) or (os.name == "nt" and not executable.lower().endswith(".exe")):
            raise ValueError("Select an existing executable (.exe on Windows)")
        self.executable = executable
        name = os.path.basename(executable)
        electron = name.lower() in ("code.exe", "cursor.exe", "windsurf.exe", "vscodium.exe", "antigravity.exe", "codex.exe")
        # Codex CLI and GUI share a name, so require an explicit known GUI adapter.
        if name.lower() == "codex.exe":
            electron = False
        super().__init__("generic", name, electron=electron)

    def get_executable_paths(self):
        return [self.executable]
