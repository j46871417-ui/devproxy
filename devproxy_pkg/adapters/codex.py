from .base import ApplicationAdapter


class CodexCliAdapter(ApplicationAdapter):
    def __init__(self):
        super().__init__("codex", "Codex CLI", ["codex"], ["OpenAI/Codex/bin"])


class CodexGuiAdapter(ApplicationAdapter):
    discover_on_path = False  # Never mistake the same-name CLI worker for the GUI.
    def __init__(self):
        super().__init__("codex-gui", "Codex Desktop", ["Codex"], ["Codex", "OpenAI Codex"], electron=True)
