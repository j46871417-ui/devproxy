from .base import ApplicationAdapter


class AntigravityAdapter(ApplicationAdapter):
    def __init__(self):
        super().__init__("antigravity", "Google Antigravity", ["Antigravity", "antigravity"],
                         ["Antigravity", "antigravity"], electron=True, config_folder="Antigravity")
