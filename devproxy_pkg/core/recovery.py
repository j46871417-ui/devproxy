"""Atomic profile store and conflict-aware recovery ledger."""
from contextlib import contextmanager
import json
import os
import tempfile
import threading
import time
from .config_editor import ConfigEditor, parse_jsonc

_LOCK = threading.RLock()
_LOCK_CONTEXT = threading.local()


def get_devproxy_state_path():
    directory = os.environ.get("DEVPROXY_STATE_DIR") or os.path.join(os.path.expanduser("~"), ".devproxy")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "state.json")


@contextmanager
def state_lock():
    with _LOCK:
        if getattr(_LOCK_CONTEXT, "held", False):
            yield
            return
        with _file_state_lock():
            _LOCK_CONTEXT.held = True
            try:
                yield
            finally:
                _LOCK_CONTEXT.held = False


@contextmanager
def _file_state_lock():
    with _LOCK:
        path = get_devproxy_state_path() + ".lock"
        with open(path, "a+b") as file:
            file.seek(0, os.SEEK_END)
            if not file.tell():
                file.write(b"0")
                file.flush()
            if os.name == "nt":
                import msvcrt
                deadline = time.monotonic() + 5
                while True:
                    file.seek(0)
                    try:
                        msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise OSError("Profile store is busy")
                        time.sleep(0.05)
                try:
                    yield
                finally:
                    file.seek(0)
                    msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(file, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(file, fcntl.LOCK_UN)


class StateManager:
    @classmethod
    def list_applications(cls):
        records = cls.load_state().get("applications", [])
        if not isinstance(records, list):
            raise ValueError("Invalid saved application list")
        return records

    @classmethod
    def save_applications(cls, records, discovery_completed=False, profile_name=None):
        with state_lock():
            state = cls.load_state()
            state["applications"] = records
            if profile_name:
                state["selected_profile"] = profile_name
            if discovery_completed:
                state["discovery_completed"] = True
            cls.save_state(state)

    @staticmethod
    def load_state():
        path = get_devproxy_state_path()
        try:
            with open(path, encoding="utf-8") as file:
                state = json.load(file)
        except FileNotFoundError:
            return {"profiles": {}, "applied": {}}
        except (ValueError, UnicodeError):
            raise ValueError("Profile store is corrupt; refusing to overwrite it") from None
        if not isinstance(state, dict) or any(not isinstance(state.get(k, {}), dict) for k in ("profiles", "applied")):
            raise ValueError("Invalid profile store")
        return state

    @staticmethod
    def save_state(state):
        path = get_devproxy_state_path()
        fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path), prefix="state_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(state, file, indent=2, ensure_ascii=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    @classmethod
    def record_applied_change(cls, app_id, file_path, modified_keys, original_values):
        with state_lock():
            state = cls.load_state()
            records = state.setdefault("applied", {}).setdefault(app_id, {})
            old = records.get(file_path)
            records[file_path] = {"modified_keys": list(modified_keys),
                                 "applied_values": modified_keys,
                                 "original_values": old["original_values"] if old else original_values}
            cls.save_state(state)

    @classmethod
    def get_applied_record(cls, app_id):
        return cls.load_state().get("applied", {}).get(app_id)

    @classmethod
    def clear_applied_record(cls, app_id):
        with state_lock():
            state = cls.load_state()
            state.get("applied", {}).pop(app_id, None)
            cls.save_state(state)

    @classmethod
    def save_profile(cls, profile_dict):
        from .profile import ProxyProfile
        ProxyProfile.from_dict(profile_dict)
        with state_lock():
            state = cls.load_state()
            state.setdefault("profiles", {})[profile_dict["name"]] = profile_dict
            cls.save_state(state)

    @classmethod
    def get_profile(cls, name):
        return cls.load_state().get("profiles", {}).get(name)

    @classmethod
    def list_profiles(cls):
        return cls.load_state().get("profiles", {})

    @classmethod
    def delete_profile(cls, name):
        with state_lock():
            state = cls.load_state()
            if name not in state.get("profiles", {}):
                return False
            del state["profiles"][name]
            cls.save_state(state)
            return True

    @classmethod
    def restore_app(cls, app_id):
        with state_lock():
            state = cls.load_state()
            records = state.get("applied", {}).get(app_id, {})
            if not records:
                return False, "No changes recorded"
            messages = []
            for path, record in list(records.items()):
                current, raw = ConfigEditor.load_jsonc(path)
                expected = record.get("applied_values")
                if current is None or not raw or expected is None:
                    messages.append("Recovery needs a valid JSONC file and a verified ledger; record retained")
                    continue
                if any(current.get(k) != v for k, v in expected.items()):
                    messages.append("Settings changed since apply; record retained")
                    continue
                updates = {}
                remove = []
                for key, value in record["original_values"].items():
                    if value == {"$devproxy_missing": True}:
                        remove.append(key)
                    else:
                        updates[key] = value
                content = ConfigEditor.remove_json_fields_preserving(raw, remove)
                content = ConfigEditor.update_json_fields_preserving(content, updates)
                ConfigEditor.atomic_write(path, content)
                del records[path]
                messages.append("Settings restored")
            if not records:
                state.get("applied", {}).pop(app_id, None)
            cls.save_state(state)
            return not records, "; ".join(messages)
