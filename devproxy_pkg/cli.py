"""DevProxy command line. All commands return meaningful exit codes."""
import argparse
import difflib
import getpass
import hashlib
import json
import os
import re
import sys
import uuid
from . import __version__
from .core.profile import ProxyProfile
from .core.secrets import SecretStore, EphemeralStore, credential_key
from .core.recovery import StateManager, apply_json_batch, restore_json_batch, get_devproxy_state_path
from .core.launcher import Launcher
from .core.validator import ProxyValidator
from .core.config_editor import ConfigEditor
from .core.diagnostics import get_environment_diagnostics, test_ip_echo
from .adapters import get_adapter, list_adapters
from .detector import LocalProxyDetector

if sys.platform == 'win32':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')


def resolve_profile(profile_name=None, proxy_str=None):
    if proxy_str:
        return ProxyProfile.parse(proxy_str, name=profile_name or 'adhoc')
    name = profile_name or 'default'
    data = StateManager.get_profile(name)
    if not data and profile_name is None:
        profiles = StateManager.list_profiles()
        if len(profiles) == 1:
            data = next(iter(profiles.values()))
    if not data:
        return None
    password = None
    if data.get('requires_password', bool(data.get('username'))):
        if not data.get('secret_key'):
            raise ValueError('Re-add this legacy authenticated profile to bind its secret to the correct endpoint.')
        password = SecretStore.get_password(data['secret_key'], backend=data.get('secret_backend'))
        if password is None:
            raise ValueError('Profile secret unavailable. Re-add it with a working OS vault or use --proxy-stdin for this session.')
    return ProxyProfile.from_dict(data, password=password)


def _raw_proxy(args):
    if getattr(args, 'proxy_stdin', False):
        if getattr(args, 'proxy', None):
            raise ValueError('Choose --proxy or --proxy-stdin, not both.')
        return sys.stdin.readline().rstrip('\r\n')
    return getattr(args, 'proxy', None)


def _profile(args):
    profile = resolve_profile(getattr(args, 'profile', None), _raw_proxy(args))
    if profile is None:
        raise ValueError('Proxy profile not found. Use --profile, --proxy or --proxy-stdin.')
    if getattr(args, 'ca_file', None):
        profile.ca_file = os.path.abspath(os.path.expanduser(args.ca_file))
    return profile


def cmd_profile_add(args):
    try:
        raw = _raw_proxy(args)
        if raw is None:
            raw = getpass.getpass('Proxy URL (hidden): ')
        profile = ProxyProfile.parse(raw, name=args.name or 'default')
        previous = StateManager.get_profile(profile.name)
        # Each profile revision gets its own vault entry: failed state writes
        # cannot replace credentials referenced by the previous valid profile.
        key = credential_key(profile) + '-' + uuid.uuid4().hex
        requires_password = bool(profile.password)
        backend = None
        if requires_password:
            backend = SecretStore.store_password(key, profile.username or '', profile.password)
            if backend not in ('os_keychain', 'os_dpapi'):
                EphemeralStore.delete(key)
                raise RuntimeError('OS credential storage unavailable; profile was not saved. Use --proxy-stdin with run/serve for a session.')
        data = profile.to_dict()
        data.update(requires_password=requires_password, secret_key=key if requires_password else None, secret_backend=backend)
        try:
            StateManager.save_profile(data)
        except Exception:
            if requires_password:
                SecretStore.delete_password(key)
            raise
        old_key = previous.get('secret_key') if previous else None
        if old_key and old_key != data['secret_key']:
            if not SecretStore.delete_password(old_key):
                print('Profile saved, but obsolete vault entry could not be removed.', file=sys.stderr)
                return 1
        # Retire the old name-only namespace; resolve never uses it again.
        SecretStore.delete_password(profile.name)
        print('Profile saved:', profile.name, profile.to_safe_url())
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print('Cannot save profile:', str(error), file=sys.stderr)
        return 1


def cmd_profile_list(args):
    for name, data in StateManager.list_profiles().items():
        profile = ProxyProfile.from_dict(data)
        print(name, profile.to_safe_url(), '(vault required)' if data.get('requires_password') else '')
    return 0


def cmd_profile_remove(args):
    data = StateManager.get_profile(args.name)
    if data is None:
        raise ValueError('Profile not found.')
    if data.get('secret_key') and not SecretStore.delete_password(data['secret_key']):
        raise RuntimeError('Vault entry could not be deleted; profile retained.')
    SecretStore.delete_password(args.name)
    StateManager.delete_profile(args.name)
    print('Profile removed:', args.name)
    return 0


def cmd_apps_list(args):
    for adapter in list_adapters():
        if sys.platform not in adapter.supported_os:
            continue
        print(adapter.app_id, ':', adapter.display_name, adapter.detect_executable() or '(not found)')
    return 0


def cmd_test(args):
    profile = _profile(args)
    targets = None
    if args.targets:
        targets = []
        for endpoint in args.targets.split(','):
            from .core.transport import parse_authority
            host, port = parse_authority(endpoint)
            targets.append((host, host, port))
    result = ProxyValidator.validate(profile, targets)
    if getattr(args, 'json', False):
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print('Proxy:', profile.to_safe_url())
        for entry in result.target_checks:
            print('OK' if entry['success'] else 'FAIL', entry['name'], entry['error'] or 'strict TLS verified')
        for error in result.errors:
            print(error, file=sys.stderr)
        print('All selected endpoints passed.' if result.overall_success else 'One or more selected endpoints failed.')
        print('This checks network/TLS access, not account authorization or application internals.')
    if args.echo:
        echo = test_ip_echo(profile)
        print(json.dumps(echo, ensure_ascii=False))
        return 0 if result.overall_success and echo['success'] else 1
    return 0 if result.overall_success else 1


def cmd_run(args):
    adapter = get_adapter(args.app)
    if adapter is None or sys.platform not in adapter.supported_os:
        raise ValueError('Unknown or unsupported application for this OS.')
    executable = args.executable or adapter.detect_executable()
    if not executable:
        raise ValueError('Application executable not found; select --executable.')
    profile = _profile(args)
    directory = None
    if adapter.session_gui:
        identity = hashlib.sha256((profile.name + profile.to_url(False)).encode()).hexdigest()[:16]
        directory = args.user_data_dir or os.path.join(os.path.dirname(get_devproxy_state_path()), 'sessions', adapter.app_id, identity)
        directory = os.path.abspath(os.path.expanduser(directory))
    flags = adapter.get_cli_launch_flags(profile)
    if args.dry_run:
        print('Executable:', executable)
        print('Arguments:', [f.replace('{PROXY_URL}', 'http://127.0.0.1:<allocated-port>') for f in flags] + args.extra_args)
        print('Proxy:', profile.to_safe_url(), 'User data:', directory or '(not applicable)')
        return 0
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    print('Session proxy:', profile.to_safe_url())
    if adapter.session_gui:
        print('A separate IDE profile is used. Keep this terminal open; Ctrl+C ends the proxy session.')
    for limitation in adapter.get_limitations():
        print('Scope:', limitation)
    process, _ = Launcher.launch_with_tunnel(executable, profile, flags, args.extra_args, wait=True,
                                            keep_alive=adapter.session_gui, user_data_dir=directory, no_proxy=args.no_proxy)
    return process.returncode


def cmd_exec(args):
    if not args.command:
        raise ValueError('Use exec -- COMMAND ARGUMENTS.')
    profile = _profile(args)
    if args.dry_run:
        print('Command:', args.command, 'Proxy:', profile.to_safe_url())
        return 0
    process, _ = Launcher.launch_with_tunnel(args.command[0], profile, extra_args=args.command[1:], no_proxy=args.no_proxy)
    return process.returncode


def cmd_serve(args):
    from .core.tunnel import LocalTunnel
    profile = _profile(args)
    tunnel = LocalTunnel(profile, bind_port=args.port)
    try:
        port = tunnel.start()
        print(f'Proxy bridge: http://127.0.0.1:{port}', flush=True)
        print('Set HTTP_PROXY and HTTPS_PROXY to this address before launching applications. Ctrl+C stops the bridge.', flush=True)
        import time
        while True:
            time.sleep(0.25)
    finally:
        tunnel.stop()


def _targets(args):
    names = [s.strip() for s in args.app.split(',') if s.strip()]
    if not names or len(names) != len(set(names)):
        raise ValueError('Select distinct application IDs.')
    adapters = [get_adapter(s) for s in names]
    if any(a is None or sys.platform not in a.supported_os for a in adapters):
        raise ValueError('Unknown or unsupported application for this OS.')
    return adapters


def _show_diff(plans):
    for path, after in plans:
        from .core.config_editor import parse_jsonc
        before, _ = ConfigEditor.load_jsonc(path)
        current = parse_jsonc(after)
        print('Planned changes:', path)
        for key in sorted(set(before or {}) | set(current)):
            if (key in (before or {})) == (key in current) and (before or {}).get(key) == current.get(key):
                continue
            def display(data):
                if key not in data:
                    return '<missing>'
                value = data[key]
                if isinstance(value, str) and '@' in value:
                    try:
                        value = ProxyProfile.parse(value).to_safe_url()
                    except ValueError:
                        value = '<credentials hidden>'
                return json.dumps(value, ensure_ascii=False)
            print(key, ':', display(before or {}), '->', display(current))


def cmd_apply(args):
    adapters, profile = _targets(args), _profile(args)
    if args.config_path and len(adapters) != 1:
        raise ValueError('--config-path selects exactly one application.')
    plans = [a.persistent_plan(profile, args.config_path) for a in adapters]
    results = apply_json_batch(plans, dry_run=args.dry_run)
    if args.dry_run:
        _show_diff(results)
    else:
        for path, _ in results:
            print('Applied:', path)
    return 0


def cmd_restore(args):
    if args.app == 'all':
        names = list(StateManager.load_state().get('applied', {}))
        if not names:
            print('No recorded changes.')
            return 0
    else:
        names = [a.app_id for a in _targets(args)]
    results = restore_json_batch(names, dry_run=args.dry_run)
    if args.dry_run:
        _show_diff(results)
    else:
        for path, _ in results:
            print('Restored:', path)
    return 0


def cmd_status(args):
    data = {'profiles': {name: ProxyProfile.from_dict(p).to_safe_url() for name, p in StateManager.list_profiles().items()},
            'applied': {k: list(v) for k, v in StateManager.load_state().get('applied', {}).items()},
            'environment': get_environment_diagnostics()}
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_detect(args):
    found = LocalProxyDetector.scan_active_clients()
    print(json.dumps(found, indent=2, ensure_ascii=False))
    if args.save:
        index = int(input('Client number (1-based): ')) - 1
        if not 0 <= index < len(found):
            raise ValueError('Invalid client selection.')
        candidate = found[index]
        profile = ProxyProfile(input('Profile name: ') or 'local', candidate['protocol'], candidate['host'], candidate['port'])
        StateManager.save_profile(profile.to_dict())
    return 0


def interactive_wizard(initial_proxy=None):
    print('DevProxy', __version__)
    raw = initial_proxy or getpass.getpass('Proxy URL (hidden): ')
    app = input('Application ID (antigravity, cursor, vscode, codex, opencode, claude): ').strip()
    return main(['run', app, '--proxy', raw])


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        message = re.sub(r'\S*://\S+@\S*|\S+:\S+@\S+', '<credentials hidden>', message)
        super().error(message)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ['--status']:
        argv = ['status']
    elif argv == ['--remove']:
        argv = ['restore', '--app', 'all']
    elif argv and not argv[0].startswith('-') and ':' in argv[0]:
        # Old shorthand now launches a chosen session instead of modifying every
        # IDE, Git and global environment. The supplied proxy is not discarded.
        try:
            ProxyProfile.parse(argv[0])
            return interactive_wizard(argv[0])
        except (OSError, ValueError, EOFError):
            print('Invalid proxy or incomplete interactive input.', file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            return 130
    parser = SafeParser(description='DevProxy: process-scoped proxy sessions')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='action')
    profile = commands.add_parser('profile')
    profiles = profile.add_subparsers(dest='profile_action', required=True)
    add = profiles.add_parser('add')
    add.add_argument('proxy', nargs='?')
    add.add_argument('--name', '-n', default='default')
    add.add_argument('--proxy-stdin', action='store_true')
    add.set_defaults(handler=cmd_profile_add)
    profiles.add_parser('list').set_defaults(handler=cmd_profile_list)
    remove = profiles.add_parser('remove')
    remove.add_argument('name')
    remove.set_defaults(handler=cmd_profile_remove)
    apps = commands.add_parser('apps')
    apps.add_subparsers(required=True).add_parser('list').set_defaults(handler=cmd_apps_list)
    for name, handler in [('test', cmd_test), ('run', cmd_run), ('exec', cmd_exec), ('serve', cmd_serve), ('apply', cmd_apply)]:
        command = commands.add_parser(name)
        command.set_defaults(handler=handler)
        command.add_argument('--profile', '-p')
        command.add_argument('--proxy')
        command.add_argument('--proxy-stdin', action='store_true')
        command.add_argument('--ca-file')
        if name in ('run', 'exec', 'apply'):
            command.add_argument('--dry-run', action='store_true')
        if name in ('run', 'exec'):
            command.add_argument('--no-proxy', help='Override inherited bypass list; empty means loopback only')
        if name == 'run':
            command.add_argument('app')
            command.add_argument('--executable')
            command.add_argument('--user-data-dir')
            command.set_defaults(extra_args=[])
        if name == 'exec':
            command.set_defaults(command=[])
        if name == 'serve':
            command.add_argument('--port', type=int, default=0)
        if name == 'test':
            command.add_argument('--targets', help='Comma-separated host[:port] list')
            command.add_argument('--echo', action='store_true')
            command.add_argument('--json', action='store_true')
        if name == 'apply':
            command.add_argument('--app', '-a', required=True)
            command.add_argument('--config-path')
    restore = commands.add_parser('restore')
    restore.add_argument('--app', '-a', required=True)
    restore.add_argument('--dry-run', action='store_true')
    restore.set_defaults(handler=cmd_restore)
    commands.add_parser('status').set_defaults(handler=cmd_status)
    commands.add_parser('doctor').set_defaults(handler=cmd_status)
    detect = commands.add_parser('detect')
    detect.add_argument('--save', action='store_true')
    detect.set_defaults(handler=cmd_detect)
    try:
        if not argv:
            return interactive_wizard()
        rest = []
        if '--' in argv:
            split = argv.index('--')
            argv, rest = argv[:split], argv[split + 1:]
        args = parser.parse_args(argv)
        if args.action == 'run':
            args.extra_args = rest
        elif args.action == 'exec':
            args.command = rest
        elif rest:
            parser.error('Extra command arguments require run or exec.')
        if not hasattr(args, 'handler'):
            parser.print_help()
            return 2
        return args.handler(args) or 0
    except KeyboardInterrupt:
        print('Session stopped.', file=sys.stderr)
        return 130
    except EOFError:
        print('Input ended.', file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print('Error:', str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
