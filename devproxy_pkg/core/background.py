"""Persistent shortcut policies, fixed loopback bridges and their recovery ledger."""
import copy
import os
from pathlib import Path
import threading
from .launcher import ApplicationSession
from .recovery import StateManager, state_lock
from .shortcuts import inspect_shortcuts, broker_shortcut, write_shortcut, LoginStartup


class BackgroundManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()
        self.last_error = None

    def policies(self):
        return StateManager.load_state().get("background", {}).get("applications", {})

    def _session(self, profile_name, port):
        existing = self.sessions.get(profile_name)
        if existing and not existing.closed:
            if existing.tunnel.allocated_port != port:
                raise RuntimeError("Локальный порт профиля изменён; перезапустите фоновый агент.")
            return existing
        from ..cli import resolve_profile
        session = ApplicationSession(resolve_profile(profile_name), bind_port=port).start()
        self.sessions[profile_name] = session
        return session

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
        return errors

    def enable(self, records, profile_name):
        if os.name != "nt":
            raise RuntimeError("Постоянный режим доступен только в Windows.")
        if not records:
            raise ValueError("Отметьте приложения для постоянного режима.")
        with self.lock, state_lock():
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
                else:
                    self.last_error = "Часть ярлыков требует восстановления. Запись изменений сохранена."
                raise
            self.last_error = None
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
            for name in list(self.sessions):
                if name not in active_profiles:
                    self.sessions.pop(name).stop()
            if errors:
                raise RuntimeError("Не восстановлены изменённые другой программой ярлыки/автозапуск: " + ", ".join(sorted(set(errors))))
            self.last_error = None

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
