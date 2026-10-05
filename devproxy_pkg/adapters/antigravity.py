from .vscode_family import VSCodeFamilyAdapter


class AntigravityAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__('antigravity', 'Antigravity', 'Antigravity', ['antigravity', 'Antigravity'])

    def get_limitations(self):
        return super().get_limitations() + [
            'Separate language servers must inherit the session environment; existing servers may need restarting.',
            'External browser OAuth traffic follows the browser configuration, not this tunnel.']
