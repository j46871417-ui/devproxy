"""
Recovery: State management and atomic rollback for persistent changes.
Tracks exact keys and values modified by devproxy in ~/.devproxy/state.json.
When restoring, reverts ONLY keys modified by devproxy without wiping manual changes made later.
"""

import os
import json
import tempfile
from typing import Dict, Any, Optional
from .config_editor import ConfigEditor


def get_devproxy_state_path() -> str:
    home = os.path.expanduser("~")
    state_dir = os.path.join(home, ".devproxy")
    os.makedirs(state_dir, exist_ok=True)
    return os.path.join(state_dir, "state.json")


class StateManager:
    @staticmethod
    def load_state() -> dict:
        path = get_devproxy_state_path()
        if not os.path.exists(path):
            return {"profiles": {}, "applied": {}}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"profiles": {}, "applied": {}}

    @staticmethod
    def save_state(state: dict):
        path = get_devproxy_state_path()
        dir_name = os.path.dirname(path)
        os.makedirs(dir_name, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="state_")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except Exception: pass

    @classmethod
    def record_applied_change(cls, app_id: str, file_path: str, modified_keys: Dict[str, Any], original_values: Dict[str, Any]):
        """Records modification made to a specific application file."""
        state = cls.load_state()
        applied = state.setdefault("applied", {})
        app_record = applied.setdefault(app_id, {})
        app_record[file_path] = {
            "modified_keys": list(modified_keys.keys()),
            "original_values": original_values
        }
        cls.save_state(state)

    @classmethod
    def get_applied_record(cls, app_id: str) -> Optional[dict]:
        state = cls.load_state()
        return state.get("applied", {}).get(app_id)

    @classmethod
    def clear_applied_record(cls, app_id: str):
        state = cls.load_state()
        if "applied" in state and app_id in state["applied"]:
            del state["applied"][app_id]
            cls.save_state(state)

    @classmethod
    def save_profile(cls, profile_dict: dict):
        state = cls.load_state()
        profiles = state.setdefault("profiles", {})
        profiles[profile_dict["name"]] = profile_dict
        cls.save_state(state)

    @classmethod
    def get_profile(cls, name: str) -> Optional[dict]:
        state = cls.load_state()
        return state.get("profiles", {}).get(name)

    @classmethod
    def list_profiles(cls) -> Dict[str, dict]:
        state = cls.load_state()
        return state.get("profiles", {})

    @classmethod
    def delete_profile(cls, name: str) -> bool:
        state = cls.load_state()
        if "profiles" in state and name in state["profiles"]:
            del state["profiles"][name]
            cls.save_state(state)
            return True
        return False
