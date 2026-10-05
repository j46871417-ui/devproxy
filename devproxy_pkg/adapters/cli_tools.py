"""Tools with documented process-environment proxy support."""
import os
import shutil
from .base import ApplicationAdapter


class CliToolAdapter(ApplicationAdapter):
    def __init__(self, app_id, display_name, config_files=()):
        self._id, self._name, self._configs = app_id, display_name, config_files

    @property
    def app_id(self):
        return self._id

    @property
    def display_name(self):
        return self._name

    @property
    def supported_os(self):
        return ['win32', 'darwin', 'linux']

    def detect_executable(self):
        found = shutil.which(self.app_id) or shutil.which(self.app_id + '.exe')
        if found:
            return found
        home = os.path.expanduser('~')
        for directory in (os.path.join(home, '.local', 'bin'), os.path.join(home, '.' + self.app_id, 'bin'),
                          os.path.join(home, 'AppData', 'Roaming', 'npm')):
            for suffix in ('', '.exe', '.cmd'):
                candidate = os.path.join(directory, self.app_id + suffix)
                if os.path.isfile(candidate):
                    return candidate
        return None

    def detect_config_files(self):
        return [os.path.expanduser(p) for p in self._configs]

    def get_cli_launch_flags(self, profile):
        return []

    def apply_persistent(self, profile):
        return False, 'No supported persistent proxy field; use devproxy run or exec.'

    def restore_persistent(self):
        return False, 'No persistent proxy changes are made by this adapter. Legacy records are retained for manual inspection.'

    def get_limitations(self):
        return ['Proxy environment applies to this process and children that honor it.',
                'Existing/background workers and external OAuth browsers may retain a different environment.']


class ClaudeAdapter(CliToolAdapter):
    def __init__(self):
        super().__init__('claude', 'Claude Code', ['~/.claude/settings.json'])

    def get_limitations(self):
        return super().get_limitations() + ['Claude Desktop managed sessions and background supervisors have separate configuration scope.']


class GitAdapter(CliToolAdapter):
    def __init__(self):
        super().__init__('git', 'Git', ['~/.gitconfig'])

    def get_cli_launch_flags(self, profile):
        return ['-c', 'http.proxy={PROXY_URL}', '-c', 'http.sslVerify=true']

    def get_limitations(self):
        return ['Only Git HTTP/HTTPS transports use these flags. SSH transport has independent proxy configuration.']
