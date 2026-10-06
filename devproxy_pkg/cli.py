"""Windows-first CLI. Secrets enter via getpass, never process arguments."""
import argparse
import getpass
import logging
import os
import sys
from .adapters import get_adapter, list_adapters
from .adapters.generic import GenericApplicationAdapter
from .core.profile import ProxyProfile
from .core.secrets import SecretStore
from .core.recovery import StateManager
from .core.launcher import ApplicationSession
from .core.validator import ProxyValidator


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


def choose_adapter(name):
    return get_adapter(name) or GenericApplicationAdapter(name)


def main(argv=None):
    parser = argparse.ArgumentParser(description="DevProxy Windows application proxy sessions (Phase 1)")
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
            with ApplicationSession(profile) as session:
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
