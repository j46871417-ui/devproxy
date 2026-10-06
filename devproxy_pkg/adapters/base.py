"""Application identity and launch capabilities, independent of routing transport."""
import os
import shutil
import sys
from ..core.recovery import StateManager


class ApplicationAdapter:
    supports_native_proxy_configuration = False
    supports_environment_proxy = True
    supports_routing_redirect = False
    electron = False
    discover_on_path = True

    def __init__(self, app_id, display_name, names=(), folders=(), electron=False, config_folder=None):
        self.app_id, self.display_name = app_id, display_name
        self.names, self.folders = list(names), list(folders)
        self.electron = electron
        self.supports_native_proxy_configuration = electron
        self.config_folder = config_folder

    @property
    def supported_os(self):
        return ["win32"]

    def get_executable_paths(self):
        candidates = []
        if sys.platform == "win32":
            roots = [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
                     os.environ.get("LOCALAPPDATA", ""),
                     os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
            for root in filter(None, roots):
                for folder in self.folders:
                    for name in self.names:
                        candidates.append(os.path.join(root, folder, name if name.lower().endswith(".exe") else name + ".exe"))
        for name in self.names:
            if not self.discover_on_path:
                continue
            path = shutil.which(name)
            if path and (sys.platform != "win32" or path.lower().endswith(".exe")):
                candidates.append(path)
            # Electron PATH often points to bin/code.cmd. Resolve the actual EXE.
            wrapper = shutil.which(name + ".cmd") if sys.platform == "win32" else None
            if wrapper:
                root = os.path.dirname(os.path.dirname(wrapper))
                candidates.extend(os.path.join(root, n if n.lower().endswith(".exe") else n + ".exe") for n in self.names)
        result = []
        for path in candidates:
            if os.path.isfile(path):
                absolute = os.path.realpath(path)
                if absolute not in result:
                    result.append(absolute)
        return result

    def detect_executable(self):
        paths = self.get_executable_paths()
        return paths[0] if paths else None

    def matches_executable(self, executable):
        identity = os.path.normcase(os.path.realpath(executable))
        return any(identity == os.path.normcase(os.path.realpath(p)) for p in self.get_executable_paths())

    def detect_config_files(self):
        if not self.config_folder:
            return []
        return [os.path.join(os.environ.get("APPDATA", ""), self.config_folder, "User", "settings.json")]

    def get_cli_launch_flags(self, profile):
        return ["--proxy-server={PROXY_URL}"] if self.electron else []

    def apply_persistent(self, profile):
        return False, "Persistent config patching is disabled. Use an owned application session; credentials stay in DevProxy."

    def restore_persistent(self):
        return StateManager.restore_app(self.app_id)

    def get_limitations(self):
        return ["Native/environment proxy configuration is advisory.",
                "Arbitrary child executables, DNS, UDP and applications ignoring proxy settings can bypass it.",
                "Strict per-application routing requires a WFP backend, unavailable in this build."]
