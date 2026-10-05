"""
ApplicationAdapter: Base abstract class for IDE and tool integrations.
Each adapter provides:
- app_id: Unique string identifier
- display_name: Human-friendly name
- detect(): Finds installed executables and config paths
- get_cli_launch_flags(): Recommended process arguments (e.g. --proxy-server=...)
- apply_persistent(): Safely applies proxy to config files
- restore_persistent(): Rolls back changes made specifically by devproxy
- limitations(): Known restrictions (e.g. extension host quirks, UDP/QUIC)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from ..core.profile import ProxyProfile


class ApplicationAdapter(ABC):
    session_gui = False

    def persistent_plan(self, profile, config_path=None):
        raise ValueError('Persistent proxy settings are unsupported for this application; use run or exec.')

    @property
    @abstractmethod
    def app_id(self) -> str:
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        pass

    @property
    @abstractmethod
    def supported_os(self) -> List[str]:
        """List of 'win32', 'darwin', 'linux'"""
        pass

    @abstractmethod
    def detect_executable(self) -> Optional[str]:
        """Returns path to binary if installed, else None."""
        pass

    @abstractmethod
    def detect_config_files(self) -> List[str]:
        """Returns list of existing or expected config file paths."""
        pass

    @abstractmethod
    def get_cli_launch_flags(self, profile: ProxyProfile) -> List[str]:
        """Returns CLI flags for process launching, e.g. ['--proxy-server={PROXY_URL}']"""
        pass

    @abstractmethod
    def apply_persistent(self, profile: ProxyProfile) -> Tuple[bool, str]:
        """Applies persistent configuration with rollback recording."""
        pass

    @abstractmethod
    def restore_persistent(self) -> Tuple[bool, str]:
        """Rolls back changes made by devproxy."""
        pass

    @abstractmethod
    def get_limitations(self) -> List[str]:
        """Returns verified limitations and requirements."""
        pass
