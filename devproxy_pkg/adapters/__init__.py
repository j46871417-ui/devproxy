"""
Adapters registry for all supported development tools.
"""

from typing import Dict, List, Optional
from .base import ApplicationAdapter
from .antigravity import AntigravityAdapter
from .vscode_family import VSCodeAdapter, CursorAdapter, WindsurfAdapter, VSCodiumAdapter
from .opencode import OpenCodeAdapter
from .codex import CodexCliAdapter, CodexGuiAdapter
from .catalog import extra_adapters


ALL_ADAPTERS: List[ApplicationAdapter] = [
    AntigravityAdapter(),
    VSCodeAdapter(),
    CursorAdapter(),
    WindsurfAdapter(),
    VSCodiumAdapter(),
    OpenCodeAdapter(),
    CodexCliAdapter(),
    CodexGuiAdapter(),
]
ALL_ADAPTERS.extend(extra_adapters())


def get_adapter(app_id: str) -> Optional[ApplicationAdapter]:
    app_id = app_id.lower().strip()
    for adapter in ALL_ADAPTERS:
        if adapter.app_id.lower() == app_id:
            return adapter
    return None


def list_adapters() -> List[ApplicationAdapter]:
    return ALL_ADAPTERS
