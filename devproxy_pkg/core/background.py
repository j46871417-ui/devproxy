"""Persistent shortcut policies, fixed loopback bridges and their recovery ledger."""
import copy
import os
from pathlib import Path
import threading
from functools import partial
from .launcher import ApplicationSession
from .recovery import StateManager, state_lock
from .shortcuts import inspect_shortcuts, broker_shortcut, write_shortcut, LoginStartup


class BackgroundManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()
        self.last_error = None
        # Cache for the GUI/IPC status path. ``lock`` is held across the file
        # operations of enable/disable, so a blocking read from a Tk callback
        # could freeze the window; this cache is refreshed after every real
        # mutation and read without touching that lock.
        self._cache = {"applications": [], "policies": [], "startup": False, "loaded": False,
                       "ports": {}, "sessions": [], "error": None, "revision": 0}
        self._cache_lock = threading.Lock()

    def policies(self):
        return StateManager.load_state().get("background", {}).get("applications", {})

    def _session(self, profile_name, port):
        self._sync_profile_names()
        existing = self.sessions.get(profile_name)
        if existing and not existing.closed:
            if existing.tunnel.allocated_port != port:
                raise RuntimeError("Локальный порт профиля изменён; перезапустите фоновый агент.")
            return existing
        from ..cli import resolve_profile, SavedProfileProvider
        session = ApplicationSession(resolve_profile(profile_name), bind_port=port,
                                     profile_provider=SavedProfileProvider(profile_name)).start()
        self.sessions[profile_name] = session
        return session

    def _sync_profile_names(self):
        """Rekey live bridges by the stable profile identity after a rename."""
        profiles = StateManager.list_profiles()
        for old_name, session in list(self.sessions.items()):
            identity = getattr(session.tunnel.profile_provider, "profile_id", None)
            if not isinstance(identity, str):
                continue
            names = [name for name, data in profiles.items() if data.get("profile_id") == identity]
            if len(names) == 1 and names[0] != old_name:
                new_name = names[0]
                if new_name in self.sessions and self.sessions[new_name] is not session:
                    raise RuntimeError("Профиль уже связан с другим действующим мостом.")
                self.sessions[new_name] = self.sessions.pop(old_name)
                with session.tunnel._lock:
                    session.tunnel.profile.name = new_name

    def snapshot(self):
        """Non-blocking status view for the GUI and IPC; never takes ``lock``."""
        with self._cache_lock:
            cached = self._cache
            return {"applications": list(cached["applications"]), "ports": dict(cached["ports"]),
                    "policies": [dict(item) for item in cached["policies"]], "startup": cached["startup"],
                    "loaded": cached["loaded"],
                    "sessions": [dict(item) for item in cached["sessions"]],
                    "error": cached["error"], "revision": cached["revision"]}

    def refresh(self):
        """Rebuild the status cache. Call from a worker, never from a Tk callback."""
        if not self.lock.acquire(blocking=False):
            return
        try:
            self._refresh_locked()
        finally:
            self.lock.release()

    def _refresh_locked(self):
        try:
            self._sync_profile_names()
            background = StateManager.load_state().get("background", {})
            rules = background.get("applications", {})
            applications = sorted(rules)
            policies = [dict(id=app_id, name=rules[app_id].get("record", {}).get("name", app_id),
                            profile=rules[app_id]["profile"]) for app_id in applications]
            startup = bool(background.get("startup"))
        except Exception:
            # Preserve the last known rules; a read failure does not mean OFF.
            self.last_error = "Не удалось прочитать правила постоянного режима."
            with self._cache_lock:
                self._cache = dict(self._cache, error=self.last_error, loaded=False,
                                   revision=self._cache["revision"] + 1)
            return
        if self.last_error == "Не удалось прочитать правила постоянного режима.":
            self.last_error = None
        sessions = []
        ports = {}
        for name, session in list(self.sessions.items()):
            try:
                ports[name] = session.tunnel.allocated_port
                sessions.append(dict(session.tunnel.diagnostics(), mode="persistent", profile=name))
            except Exception:
                continue
        failures = [entry for item in sessions for entry in item.get("failures", [])]
        error = self.last_error
        if failures:
            error = max(failures, key=lambda entry: entry.get("time", 0))["message"]
        with self._cache_lock:
            self._cache = {"applications": applications, "ports": ports, "sessions": sessions,
                           "policies": policies, "startup": startup, "loaded": True,
                           "error": error, "revision": self._cache["revision"] + 1}

    def resume(self):
        errors = []
        with self.lock:
            state = StateManager.load_state().get("background", {})
            for name in {p["profile"] for p in state.get("applications", {}).values()}:
                try:
                    self._session(name, state["ports"][name])
                except Exception:
                    errors.append(name)
            if errors:
                self.last_error = "Не удалось запустить фоновый прокси: " + ", ".join(errors) + ". Проверьте профиль, пароль и занятость локального порта."
        self.refresh()
        return errors

    def enable(self, records, profile_name):
        if os.name != "nt":
            raise RuntimeError("Постоянный режим доступен только в Windows.")
        if not records:
            raise ValueError("Отметьте приложения для постоянного режима.")
        with self.lock, state_lock():
            previous_sessions = set(self.sessions.values())
            previous = StateManager.load_state()
            if profile_name not in previous.get("profiles", {}):
                raise ValueError("Выберите сохранённый профиль прокси.")
            state = copy.deepcopy(previous)
            state["selected_profile"] = profile_name
            background = state.setdefault("background", {})
            ports = background.setdefault("ports", {})
            if profile_name not in ports:
                used = set(ports.values())
                for port in range(18787, 18887):
                    if port in used:
                        continue
                    try:
                        self._session(profile_name, port)
                        ports[profile_name] = port
                        break
                    except OSError:
                        continue
                else:
                    raise OSError("Нет свободного локального порта для фонового прокси.")
            else:
                self._session(profile_name, ports[profile_name])
            # _session migrates legacy profiles by persisting their stable ID.
            # Do not overwrite that migration with the pre-session snapshot.
            # The state lock excludes concurrent profile edits here.
            state["profiles"] = copy.deepcopy(StateManager.load_state()["profiles"])
            policies = background.setdefault("applications", {})
            ledger = background.setdefault("shortcuts", {})
            edits = []
            for record in records:
                if not os.path.isfile(record["executable"]) or not record["executable"].lower().endswith(".exe"):
                    raise ValueError("Приложение должно указывать на существующий EXE.")
                app_id = record["id"]
                policies[app_id] = {"profile": profile_name, "record": copy.deepcopy(record)}
                links = inspect_shortcuts(record["executable"])
                tracked = any(item["app_id"] == app_id for item in ledger.values())
                if not links and not tracked:
                    safe_name = "".join(c for c in record["name"] if c not in '<>:"/\\|?*').strip() or "Приложение"
                    path = str(Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/DevProxy" / (safe_name + ".lnk"))
                    links = [dict(path=path, target=record["executable"], arguments="", icon=record["executable"] + ",0", directory="", created=True)]
                for original in links:
                    path = original["path"]
                    applied = broker_shortcut(original, app_id)
                    old = ledger.get(path)
                    baseline = old["original"] if old else (None if original.get("created") else original)
                    ledger[path] = dict(app_id=app_id, original=baseline, applied=applied)
                    edits.append((path, None if original.get("created") else original, applied))
            startup = background.get("startup")
            if startup is None:
                startup = {"original": LoginStartup.read(), "applied": LoginStartup.expected()}
                background["startup"] = startup
            # Journal is durable before external writes. A partial operation remains recoverable.
            StateManager.save_state(state)
            completed = []
            try:
                for path, original, applied in edits:
                    write_shortcut(path, original, applied)
                    completed.append((path, original, applied))
                current_startup = LoginStartup.read()
                if current_startup != startup["applied"]:
                    LoginStartup.write(startup["original"], startup["applied"])
            except Exception:
                rollback_ok = True
                for path, original, applied in reversed(completed):
                    try:
                        write_shortcut(path, applied, original)
                    except Exception:
                        rollback_ok = False
                if rollback_ok:
                    StateManager.save_state(previous)
                    # A rollback may remove the identity created for a legacy
                    # profile. Retaining its new bridge would leave a provider
                    # permanently referring to a profile that no longer exists.
                    for name, session in list(self.sessions.items()):
                        if session not in previous_sessions:
                            self.sessions.pop(name).stop()
                else:
                    self.last_error = "Часть ярлыков требует восстановления. Запись изменений сохранена."
                raise
            self.last_error = None
        self.refresh()
        return len(records)

    def disable(self, app_ids=None):
        with self.lock, state_lock():
            state = StateManager.load_state()
            background = state.get("background", {})
            policies = background.get("applications", {})
            targets = set(policies) if app_ids is None else set(app_ids)
            errors = []
            for path, item in list(background.get("shortcuts", {}).items()):
                if item["app_id"] not in targets:
                    continue
                try:
                    # If a crash happened before applying the intent, an original link is already restored.
                    write_shortcut(path, item["applied"], item["original"])
                except Exception:
                    if item["original"] is None and not os.path.exists(path):
                        del background["shortcuts"][path]
                        continue
                    if item["original"] is not None:
                        try:
                            write_shortcut(path, item["original"], item["original"])
                        except Exception:
                            errors.append(item["app_id"])
                            continue
                    else:
                        errors.append(item["app_id"])
                        continue
                del background["shortcuts"][path]
            for app_id in targets - set(errors):
                policies.pop(app_id, None)
            if not policies and background.get("startup"):
                startup = background["startup"]
                try:
                    current = LoginStartup.read()
                    if current == startup["applied"]:
                        LoginStartup.write(startup["applied"], startup["original"])
                    elif current != startup["original"]:
                        raise RuntimeError("Autostart conflict")
                    background.pop("startup", None)
                except Exception:
                    errors.append("автозапуск")
            StateManager.save_state(state)
            active_profiles = {p["profile"] for p in policies.values()}
            self._sync_profile_names()
            for name in list(self.sessions):
                if name not in active_profiles:
                    self.sessions.pop(name).stop()
            if errors:
                raise RuntimeError("Не восстановлены изменённые другой программой ярлыки/автозапуск: " + ", ".join(sorted(set(errors))))
            self.last_error = None
        self.refresh()

    def launch(self, app_id, arguments=None):
        with self.lock:
            state = StateManager.load_state().get("background", {})
            policy = state.get("applications", {}).get(app_id)
            if not policy:
                raise ValueError("Для этого приложения постоянный режим не включён.")
            record = policy["record"]
            session = self._session(policy["profile"], state["ports"][policy["profile"]])
            electron = bool(record.get("electron"))
            flags = ["--proxy-server={PROXY_URL}"] if electron else []
            return session.launch(record["executable"], flags=flags,
                                  extra_args=list(record.get("arguments", [])) + list(arguments or []),
                                  electron=electron, preserve_profile=True,
                                  console=app_id in ("codex", "opencode", "claude", "git"))

    def close(self):
        with self.lock:
            for session in self.sessions.values():
                session.stop()
            self.sessions.clear()
        self.refresh()
