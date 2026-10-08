"""Windows-first CLI. Secrets enter via getpass, never process arguments."""
import argparse
import getpass
import logging
import os
import sys
import uuid
from .adapters import get_adapter, list_adapters
from .adapters.generic import GenericApplicationAdapter
from .core.profile import ProxyProfile
from .core.secrets import SecretStore
from .core.recovery import StateManager, state_lock
from .core.launcher import ApplicationSession
from .core.validator import ProxyValidator
from . import __version__


def resolve_profile(profile_name=None, proxy_str=None):
    if proxy_str:
        profile = ProxyProfile.parse(proxy_str, profile_name or "adhoc")
        if profile.has_auth:
            raise ValueError("Credentials in command arguments are prohibited; save a profile using the password prompt")
        return profile
    name = profile_name or "default"
    data = StateManager.get_profile(name)
    if not data and profile_name is None:
        profiles = StateManager.list_profiles()
        if len(profiles) == 1:
            data = next(iter(profiles.values()))
    if not data:
        raise ValueError("Proxy profile not found")
    password = SecretStore.get_password(data.get("secret_reference") or data["name"]) if data.get("secret_reference") or data.get("username") is not None else None
    if (data.get("secret_reference") or data.get("username") is not None) and password is None:
        raise ValueError("Saved proxy credential unavailable; re-save the profile")
    return ProxyProfile.from_dict(data, password)


def save_profile(profile):
    from .core.profiles import persist_profile
    persist_profile(profile)


def resolve_saved_profile(name):
    """Read metadata and its secret as one atomic snapshot for a new connection.

    Metadata and credential are read under the same state lock, so a concurrent
    save can never yield a new host/port paired with a stale password. A missing
    profile or a removed secret raises; it never silently degrades to a
    credential-free or direct connection.
    """
    with state_lock():
        return resolve_profile(name)


class SavedProfileProvider:
    """A stable identity survives rename; deletion cannot reuse stale secrets."""
    def __init__(self, name):
        import threading
        self._route_lock = threading.RLock()
        self._retry_at = {}
        self._failures = {}
        self._pinned = False
        self._selected_name = name
        with state_lock():
            state = StateManager.load_state()
            data = state.get("profiles", {}).get(name)
            if data is None:
                raise ValueError("Proxy profile not found")
            if not data.get("profile_id"):
                data["profile_id"] = uuid.uuid4().hex
                StateManager.save_state(state)
            self.profile_id = data["profile_id"]
            self._selected_id = self.profile_id

    def __call__(self):
        with self._route_lock:
            return self._resolve(self._selected_id)

    def _resolve(self, identity):
        with state_lock():
            profiles = StateManager.load_state().get("profiles", {})
            names = [name for name, data in profiles.items()
                     if data.get("profile_id") == identity]
            if len(names) != 1:
                raise ValueError("Proxy profile not found")
            profile = resolve_profile(names[0])
            if identity == self._selected_id:
                self._selected_name = profile.name
            return profile

    def pin(self):
        """Keep OAuth and the IDE on the same exit until this session closes."""
        with self._route_lock:
            self._pinned = True

    def route_status(self):
        # Status never waits for a network handshake or accesses the keychain.
        return {"selected": self._selected_name, "pinned": self._pinned}

    def open_connection(self, host, port, timeout, on_socket, forward_http=False):
        from .core.transport import open_proxy, connect_upstream
        with self._route_lock:
            with state_lock():
                backups = StateManager.load_state().get("route_groups", {}).get(self.profile_id, [])
            parallel = self._pinned or not backups
            profile = self._resolve(self._selected_id) if parallel else None
        if parallel:
            # A fixed exit needs no network-wide mutex: independent streams
            # negotiate in parallel, including the browser and language server.
            if forward_http:
                return open_proxy(profile, timeout, on_socket), b"", profile
            sock, tail = connect_upstream(profile, host, port, timeout, on_socket)
            return sock, tail, profile
        return self._open_routed(host, port, timeout, on_socket, forward_http)

    def _open_routed(self, host, port, timeout, on_socket, forward_http=False):
        import ssl
        import time
        from .core.transport import open_proxy, connect_upstream, ProxyError
        with self._route_lock:
            with state_lock():
                state = StateManager.load_state()
                backups = state.get("route_groups", {}).get(self.profile_id, [])
            candidates = [self._selected_id]
            if not self._pinned:
                candidates += [identity for identity in [self.profile_id] + backups if identity not in candidates]
            deadline = time.monotonic() + timeout
            last_error = None
            for identity in candidates:
                if self._retry_at.get(identity, 0) > time.monotonic():
                    continue
                budget = min(deadline - time.monotonic(), max(1, timeout / len(candidates)))
                if budget <= 0:
                    break
                # Missing metadata/credentials are configuration errors. Do not
                # hide them by silently selecting a different server.
                profile = self._resolve(identity)
                try:
                    if forward_http:
                        sock, tail = open_proxy(profile, budget, on_socket), b""
                    else:
                        sock, tail = connect_upstream(profile, host, port, budget, on_socket)
                except OSError as error:
                    phase = getattr(error, "devproxy_phase", None)
                    if phase not in ("proxy_tcp", "proxy_tls") or isinstance(error, ssl.SSLCertVerificationError):
                        raise
                    if isinstance(error, ssl.SSLError) and not isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
                        raise
                    last_error = error
                    count = min(self._failures.get(identity, 0) + 1, 5)
                    self._failures[identity] = count
                    self._retry_at[identity] = time.monotonic() + min(300, 15 * 2 ** (count - 1))
                    continue
                self._selected_id = identity
                self._selected_name = profile.name
                self._retry_at.pop(identity, None)
                self._failures.pop(identity, None)
                return sock, tail, profile
            if last_error is not None:
                raise last_error
            raise ProxyError("All configured routes are unavailable", "routes_unavailable")


def rename_affected_policies(old_name, new_name):
    """Return background app ids that still point at a profile name."""
    state = StateManager.load_state().get("background", {})
    return sorted(app_id for app_id, policy in state.get("applications", {}).items()
                  if policy.get("profile") == old_name)


def choose_adapter(name):
    return get_adapter(name) or GenericApplicationAdapter(name)


def main(argv=None):
    parser = argparse.ArgumentParser(description="DevProxy Windows application proxy sessions (Phase 1)")
    parser.add_argument("--version", action="version", version="DevProxy " + __version__)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test-ui", action="store_true", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command")
    profiles = sub.add_parser("profile").add_subparsers(dest="action")
    add = profiles.add_parser("add")
    add.add_argument("proxy", nargs="?", help="Credential-free scheme://host:port")
    add.add_argument("--name", default="default")
    add.add_argument("--username")
    delete = profiles.add_parser("remove")
    delete.add_argument("name")
    profiles.add_parser("list")
    sub.add_parser("gui")
    sub.add_parser("status")
    repair = sub.add_parser("antigravity-recovery", help="Восстановление загрузки локального интерфейса Antigravity")
    repair.add_argument("executable", help="Полный путь к Antigravity.exe")
    repair.add_argument("--restore", action="store_true", help="Вернуть исходный архив клиента")
    apps = sub.add_parser("apps").add_subparsers(dest="action")
    apps.add_parser("list")
    for name in ("doctor", "test"):
        doctor = sub.add_parser(name)
        doctor.add_argument("--profile", "-p")
        doctor.add_argument("--proxy")
        doctor.add_argument("--target", default="github.com")
        doctor.add_argument("--port", type=int, default=443)
        doctor.add_argument("--echo", action="store_true")
    run = sub.add_parser("run")
    run.add_argument("app", help="Known application ID or absolute EXE path")
    run.add_argument("--profile", "-p")
    run.add_argument("--proxy")
    run.add_argument("--require-fail-closed", action="store_true")
    run.add_argument("--dry-run", action="store_true")
    restore = sub.add_parser("restore")
    restore.add_argument("--app", required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--app", required=True)
    apply.add_argument("--profile")
    raw = list(sys.argv[1:] if argv is None else argv)
    extra = []
    if "--" in raw:
        index = raw.index("--")
        raw, extra = raw[:index], raw[index + 1:]
    args = parser.parse_args(raw)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.ERROR,
                        format="%(levelname)s %(name)s %(message)s")
    try:
        if args.self_test_ui:
            from .ui import smoke_test
            smoke_test()
            print("UI smoke PASS")
            return 0
        if args.command in (None, "gui"):
            from .ui import main as gui
            gui()
            return 0
        if args.command == "profile":
            if args.action == "add":
                profile = ProxyProfile.parse(args.proxy or input("Proxy address (without credentials): "), args.name)
                if profile.has_auth:
                    raise ValueError("Credentials in URLs are prohibited; use --username and the password prompt")
                if args.username is not None:
                    profile.username = args.username
                    profile.password = getpass.getpass("Proxy password: ")
                    profile.__post_init__()
                save_profile(profile)
                print("Profile saved:", profile.name, profile.to_safe_url())
            elif args.action == "list":
                for name, data in StateManager.list_profiles().items():
                    print(name, ProxyProfile.from_dict(data).to_safe_url(), "(authentication)" if data.get("secret_reference") else "")
            elif args.action == "remove":
                if not StateManager.delete_profile(args.name):
                    raise ValueError("Profile not found")
                SecretStore.delete_password(args.name)
            return 0
        if args.command == "apps":
            for adapter in list_adapters():
                print(adapter.app_id, adapter.detect_executable() or "(not detected; select an EXE)")
            return 0
        if args.command == "status":
            print("Backend: native/environment; WFP redirector: unavailable")
            print("Profiles:", len(StateManager.list_profiles()))
            print("Legacy recovery records:", len(StateManager.load_state().get("applied", {})))
            return 0
        if args.command == "antigravity-recovery":
            from .core.antigravity_recovery import prepare
            print(prepare(args.executable, restore=args.restore))
            return 0
        if args.command in ("doctor", "test"):
            profile = resolve_profile(args.profile, args.proxy)
            result = ProxyValidator.validate(profile, [("Target TLS", args.target, args.port)])
            print(("PASS" if result.tcp_reachable else "FAIL"), "upstream TCP")
            print(("PASS" if result.auth_success else "FAIL"), "proxy handshake/authentication")
            print(("PASS" if result.tls_strict_verified else "FAIL"), "target TLS through local listener")
            print("WARN per-app enforcement, process-tree route, DNS/IPv6 leak protection: not verified; WFP unavailable")
            for error in result.errors:
                print("FAIL", error)
            if args.echo:
                from .core.diagnostics import test_ip_echo
                echo = test_ip_echo(profile)
                print(("PASS " + echo["egress_ip"]) if echo["success"] else "FAIL external IP query")
            return 0 if result.overall_success else 1
        if args.command == "run":
            profile = resolve_profile(args.profile, args.proxy)
            adapter = choose_adapter(args.app)
            executable = adapter.detect_executable()
            if not executable:
                raise ValueError("Application not detected; select its EXE path")
            if args.dry_run:
                print("EXE:", executable)
                print("Backend: native/environment; no enforced per-app fail-closed guarantee")
                return 0
            print("WARN native/environment mode: applications or children ignoring proxy settings can connect directly.")
            provider = SavedProfileProvider(profile.name) if not args.proxy else None
            with ApplicationSession(profile, profile_provider=provider) as session:
                if args.require_fail_closed:
                    session.start(require_fail_closed=True)
                session.launch(executable, adapter.get_cli_launch_flags(profile), extra, adapter.electron,
                               preserve_profile=adapter.app_id == "antigravity")
                return session.wait()
        if args.command == "apply":
            raise ValueError("Use the GUI button «Включить постоянно» to configure persistent launch shortcuts.")
        if args.command == "restore":
            success = True
            for app in args.app.split(","):
                ok, message = StateManager.restore_app(app.strip())
                print("PASS" if ok else "WARN", message)
                success &= ok
            return 0 if success else 1
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print("FAIL", str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("FAIL", type(exc).__name__, "(no secrets logged)", file=sys.stderr)
        return 1
    return 0
