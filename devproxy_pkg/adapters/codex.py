import os
import sys
from .cli_tools import CliToolAdapter


class CodexCliAdapter(CliToolAdapter):
    def __init__(self):
        super().__init__('codex', 'Codex CLI', ['~/.codex/config.toml'])


class CodexGuiAdapter(CliToolAdapter):
    session_gui = True

    def __init__(self):
        super().__init__('codex-gui', 'Codex Desktop', ['~/.codex/config.toml'])

    @property
    def supported_os(self):
        return ['win32', 'darwin']

    def detect_executable(self):
        paths = []
        if sys.platform == 'win32':
            local = os.environ.get('LOCALAPPDATA', '')
            paths += [os.path.join(local, 'Programs', 'Codex', 'Codex.exe'),
                      os.path.join(local, 'Programs', 'OpenAI Codex', 'Codex.exe')]
            try:
                for folder in os.scandir(r'C:\Program Files\WindowsApps'):
                    if folder.name.startswith('OpenAI.Codex'):
                        paths.append(os.path.join(folder.path, 'app', 'Codex.exe'))
            except OSError:
                pass
        elif sys.platform == 'darwin':
            paths += ['/Applications/Codex.app/Contents/MacOS/Codex']
        return next((p for p in paths if os.path.isfile(p)), None)

    def get_cli_launch_flags(self, profile):
        return ['--proxy-server={PROXY_URL}', '--disable-quic']

    def get_limitations(self):
        return super().get_limitations() + ['Packaged GUI launch and its background workers require application-specific validation. Use codex CLI if direct GUI launch is unavailable.']
