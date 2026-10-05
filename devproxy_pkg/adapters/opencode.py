import os
from .cli_tools import CliToolAdapter


class OpenCodeAdapter(CliToolAdapter):
    def __init__(self):
        super().__init__('opencode', 'OpenCode')

    def detect_config_files(self):
        home = os.path.expanduser('~')
        base = os.environ.get('XDG_CONFIG_HOME', os.path.join(home, '.config'))
        return [os.path.join(base, 'opencode', 'opencode.json'), os.path.join(base, 'opencode', 'opencode.jsonc')]
