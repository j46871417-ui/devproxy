"""Profile editing service. UI never retrieves saved passwords."""
from .profile import ProxyProfile
from .recovery import StateManager, state_lock
from .secrets import SecretStore
from .user_errors import UserInputError
import uuid


def _migrate_background(state, old_name, new_name):
    """Repoint persistent rules and their reserved port at the renamed profile."""
    background = state.get("background")
    if not isinstance(background, dict):
        return
    for policy in background.get("applications", {}).values():
        if isinstance(policy, dict) and policy.get("profile") == old_name:
            policy["profile"] = new_name
    ports = background.get("ports")
    if isinstance(ports, dict) and old_name in ports:
        # A port already reserved for the new name wins; otherwise carry it over
        # so the running bridge keeps its address instead of being orphaned.
        if new_name not in ports:
            ports[new_name] = ports[old_name]
        del ports[old_name]
    if state.get("selected_profile") == old_name:
        state["selected_profile"] = new_name


def persist_profile(profile, original_name=None, keep_password=False):
    profile.__post_init__()
    with state_lock():
        state = StateManager.load_state()
        profiles = state.setdefault("profiles", {})
        old_name = original_name or profile.name
        old = profiles.get(old_name)
        if not original_name and old is not None:
            raise UserInputError("Профиль с таким названием уже есть. Нажмите «Изменить» или задайте другое название.")
        if original_name and old is None:
            raise UserInputError("Профиль уже удалён. Закройте окно и создайте новый.")
        if profile.name != old_name and profile.name in profiles:
            raise UserInputError("Профиль с таким названием уже существует.")
        if profile.name != old_name:
            ports = state.get("background", {}).get("ports", {})
            if old_name in ports and profile.name in ports and ports[old_name] != ports[profile.name]:
                raise UserInputError("Это имя уже связано с другим локальным портом. Сначала отключите его постоянный режим.")
        profile.profile_id = (old or {}).get("profile_id") or uuid.uuid4().hex
        old_key = (old.get("secret_reference") or old_name) if old else None
        key = profile.name
        previous_password = SecretStore.get_password(key) if profiles.get(key, {}).get("secret_reference") else None
        wrote_secret = False
        try:
            if profile.has_auth:
                if keep_password:
                    profile.password = SecretStore.get_password(old_key) if old_key else None
                if profile.password is None:
                    raise UserInputError("Введите пароль прокси. Сохранённый пароль недоступен.")
                SecretStore.store_password(key, profile.username or "", profile.password, require_persistent=True)
                profile.secret_reference = key
                wrote_secret = True
            else:
                profile.secret_reference = None
            profiles[profile.name] = profile.to_dict()
            if profile.name != old_name:
                profiles.pop(old_name, None)
                # Background rules and their running bridges are keyed by profile
                # name. Migrating them here keeps a rename from leaving a policy
                # or an already-open port pointing at a name that no longer exists.
                _migrate_background(state, old_name, profile.name)
            StateManager.save_state(state)
        except BaseException:
            if wrote_secret:
                if previous_password is None:
                    SecretStore.delete_password(key)
                else:
                    SecretStore.store_password(key, (old or {}).get("username") or "", previous_password, require_persistent=True)
            raise
        finally:
            profile.password = None
        if old_key and (old_key != key or not profile.has_auth):
            SecretStore.delete_password(old_key)


def profile_from_fields(name, protocol, host, port, username="", password=None, auth=False):
    try:
        number = int(port)
    except (ValueError, TypeError):
        raise UserInputError("Порт должен быть числом от 1 до 65535.") from None
    if not 1 <= number <= 65535:
        raise UserInputError("Порт должен быть числом от 1 до 65535.")
    host = host.strip().removeprefix("[").removesuffix("]")
    if not name.strip():
        raise UserInputError("Введите название профиля, например «Рабочий прокси».")
    if not host:
        raise UserInputError("Введите адрес сервера, например 127.0.0.1 или proxy.example.com.")
    if "://" in host:
        raise UserInputError("В поле «Адрес сервера» нужен только адрес. Ссылку целиком вставьте через «Вставить ссылку».")
    if auth and not username:
        raise UserInputError("Включена авторизация: введите логин.")
    return ProxyProfile(name.strip(), protocol, host, number, username if auth else None, password if auth else None)


def set_route_backups(primary_name, backup_names):
    """Optional ordered failover group. No server or secret is invented."""
    if len(backup_names) > 4 or len(set(backup_names)) != len(backup_names) or primary_name in backup_names:
        raise UserInputError("Выберите до четырёх различных резервных профилей.")
    from ..cli import SavedProfileProvider
    with state_lock():
        providers = [SavedProfileProvider(name) for name in [primary_name] + list(backup_names)]
        state = StateManager.load_state()
        state.setdefault("route_groups", {})[providers[0].profile_id] = [p.profile_id for p in providers[1:]]
        StateManager.save_state(state)
