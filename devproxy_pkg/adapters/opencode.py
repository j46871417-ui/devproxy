from .base import ApplicationAdapter


class OpenCodeAdapter(ApplicationAdapter):
    def __init__(self):
        super().__init__("opencode", "OpenCode", ["opencode", "OpenCode"], ["OpenCode"])
