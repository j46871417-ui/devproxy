"""Locked, journaled configuration changes and conflict-aware restore."""
import copy
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from .config_editor import ConfigEditor, parse_jsonc


def get_devproxy_state_path():
    directory = os.environ.get('DEVPROXY_STATE_DIR') or os.path.join(os.path.expanduser('~'), '.devproxy')
    return os.path.join(directory, 'state.json')


@contextmanager
def state_lock(timeout=3):
    path = get_devproxy_state_path() + '.lock'
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise RuntimeError('State is locked by another operation. A stale lock must be inspected before removal.')
            time.sleep(0.05)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(str(os.getpid()))
        yield
    finally:
        os.unlink(path)


class StateManager:
    @staticmethod
    def load_state():
        try:
            with open(get_devproxy_state_path(), encoding='utf-8') as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return {'schema_version': 2, 'profiles': {}, 'applied': {}}
        except (OSError, ValueError, UnicodeError):
            raise RuntimeError('Cannot read DevProxy state; existing state was not overwritten.') from None
        if not isinstance(state, dict) or not all(isinstance(state.get(k, {}), dict) for k in ('profiles', 'applied')):
            raise RuntimeError('Invalid DevProxy state structure.')
        if state.get('schema_version', 1) not in (1, 2):
            raise RuntimeError('Unsupported state version.')
        return state

    @staticmethod
    def save_state(state):
        ConfigEditor.atomic_write(get_devproxy_state_path(), json.dumps(state, indent=2, ensure_ascii=False), backup=False)
        os.chmod(get_devproxy_state_path(), 0o600)

    @classmethod
    def get_applied_record(cls, app_id):
        return cls.load_state().get('applied', {}).get(app_id)

    @classmethod
    def clear_applied_record(cls, app_id):
        with state_lock():
            state = cls.load_state()
            state.setdefault('applied', {}).pop(app_id, None)
            cls.save_state(state)

    @classmethod
    def record_applied_change(cls, app_id, file_path, modified_keys, original_values):
        # Retained for callers; new adapters use apply_json_batch instead.
        with state_lock():
            state = cls.load_state()
            records = state.setdefault('applied', {}).setdefault(app_id, {})
            prior = records.get(file_path)
            records[file_path] = prior or {'original_values': original_values, 'original_present': list(original_values)}
            records[file_path].update(applied_values=modified_keys, modified_keys=list(modified_keys), phase='applied')
            cls.save_state(state)

    @classmethod
    def save_profile(cls, profile_dict):
        if 'password' in profile_dict:
            raise ValueError('Plaintext passwords must not be persisted in state.')
        with state_lock():
            state = cls.load_state()
            state.setdefault('profiles', {})[profile_dict['name']] = profile_dict
            cls.save_state(state)

    @classmethod
    def get_profile(cls, name):
        return cls.load_state().get('profiles', {}).get(name)

    @classmethod
    def list_profiles(cls):
        return cls.load_state().get('profiles', {})

    @classmethod
    def delete_profile(cls, name):
        with state_lock():
            state = cls.load_state()
            if name not in state.setdefault('profiles', {}):
                return False
            del state['profiles'][name]
            cls.save_state(state)
            return True


def _same(current, key, values, present):
    return (key in current) == (key in present) and (key not in present or current[key] == values[key])


def _rollback(written, old_state):
    failures = []
    for path, before in reversed(written):
        try:
            if before is None:
                os.unlink(path)
            else:
                ConfigEditor.atomic_write(path, before, backup=False)
        except OSError:
            failures.append(path)
    if not failures:
        try:
            StateManager.save_state(old_state)
        except OSError:
            failures.append('state journal')
    if failures:
        raise RuntimeError('Rollback incomplete; recovery journal retained for: ' + ', '.join(failures))


def apply_json_batch(changes, dry_run=False):
    """Preflight all targets, save recovery intent, write, then commit the journal."""
    with state_lock():
        old = StateManager.load_state()
        state = copy.deepcopy(old)
        plans, paths = [], set()
        for app_id, path, updates in changes:
            path = os.path.abspath(path)
            if path in paths:
                raise ValueError('The same config file was selected more than once.')
            paths.add(path)
            parsed, raw = ConfigEditor.load_jsonc(path)
            if parsed is None:
                raise ValueError('Cannot read a valid JSONC object: ' + path)
            if any(isinstance(parsed.get(k), str) and '@' in parsed[k] for k in updates if k.endswith('proxy')):
                raise ValueError('Existing authenticated proxy must be removed manually before persistent editing; credentials will not be copied into the journal.')
            records = state.setdefault('applied', {}).setdefault(app_id, {})
            record = records.get(path)
            if record:
                if 'applied_values' not in record or 'original_present' not in record:
                    raise ValueError('Legacy recovery record cannot be safely replaced; inspect the original .bak first.')
                for key in record['applied_values']:
                    applied = _same(parsed, key, record['applied_values'], record['applied_values'])
                    original = _same(parsed, key, record['original_values'], record['original_present'])
                    if not applied and not (record.get('phase') == 'prepared' and original):
                        raise ValueError('Manual configuration change conflicts with apply: ' + key)
            else:
                record = {'original_values': {k: parsed[k] for k in updates if k in parsed},
                          'original_present': [k for k in updates if k in parsed],
                          'file_existed': os.path.exists(path)}
                records[path] = record
            for key in updates:
                if key not in record.get('modified_keys', []) and key not in record['original_values']:
                    if key in parsed:
                        record['original_values'][key] = parsed[key]
                        if key not in record['original_present']:
                            record['original_present'].append(key)
            record.update(applied_values=updates, modified_keys=list(updates), phase='prepared')
            content = ConfigEditor.update_json_fields_preserving(raw, updates)
            before = Path(path).read_bytes() if os.path.exists(path) else None
            plans.append((path, before, content, record))
        if dry_run:
            return [(path, content) for path, _, content, _ in plans]
        StateManager.save_state(state)
        written = []
        try:
            for path, before, content, record in plans:
                now = Path(path).read_bytes() if os.path.exists(path) else None
                if now != before:
                    raise RuntimeError('Configuration changed during apply; operation cancelled.')
                ConfigEditor.atomic_write(path, content)
                written.append((path, before))
                record['phase'] = 'applied'
            state['schema_version'] = 2
            StateManager.save_state(state)
        except Exception:
            _rollback(written, old)
            raise
        return [(path, content) for path, _, content, _ in plans]


def restore_json_batch(app_ids, dry_run=False):
    with state_lock():
        old = StateManager.load_state()
        state, plans = copy.deepcopy(old), []
        for app_id in app_ids:
            records = state.get('applied', {}).get(app_id)
            if not records:
                raise ValueError('No recorded changes for ' + app_id)
            for path, record in records.items():
                if 'applied_values' not in record or 'original_present' not in record:
                    raise ValueError('Legacy recovery record lacks conflict metadata; inspect its .bak manually.')
                parsed, raw = ConfigEditor.load_jsonc(path)
                if parsed is None or not os.path.exists(path):
                    raise ValueError('Cannot restore unreadable/missing config; journal retained: ' + path)
                for key in record['applied_values']:
                    applied = _same(parsed, key, record['applied_values'], record['applied_values'])
                    original = _same(parsed, key, record['original_values'], record['original_present'])
                    if not applied and not original:
                        raise ValueError('Manual change conflicts with restore; journal retained: ' + key)
                content = ConfigEditor.remove_json_fields_preserving(raw, [k for k in record['applied_values'] if k not in record['original_present']])
                content = ConfigEditor.update_json_fields_preserving(content, record['original_values'])
                plans.append((path, Path(path).read_bytes(), content))
            del state['applied'][app_id]
        if dry_run:
            return [(p, c) for p, _, c in plans]
        written = []
        try:
            for path, before, content in plans:
                if Path(path).read_bytes() != before:
                    raise RuntimeError('Configuration changed during restore; operation cancelled.')
                ConfigEditor.atomic_write(path, content)
                written.append((path, before))
            StateManager.save_state(state)
        except Exception:
            _rollback(written, old)
            raise
        return [(p, c) for p, _, c in plans]
