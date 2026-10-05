"""
CLI Interface for DevProxy v2.0.0.
Implements commands:
- devproxy profile add [URL] [--name NAME]
- devproxy profile list
- devproxy profile remove NAME
- devproxy apps list
- devproxy test [--profile NAME] [--app TARGET] [--echo]
- devproxy run TARGET [--profile NAME] [--dry-run] [-- APP_ARGS...]
- devproxy apply --app TARGET [--profile NAME]
- devproxy restore --app TARGET
- devproxy detect
- devproxy status
- interactive wizard: "Insert proxy -> Test -> Select App -> Run/Apply"
"""

import sys
import os
import argparse
import subprocess
from typing import List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .core.profile import ProxyProfile
from .core.secrets import SecretStore
from .core.validator import ProxyValidator
from .core.launcher import Launcher
from .core.recovery import StateManager
from .core.diagnostics import get_environment_diagnostics, test_ip_echo
from .adapters import list_adapters, get_adapter
from .detector import LocalProxyDetector


class Colors:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("============================================================")
    print("  DevProxy 2.0.0 — Universal IDE & Dev Tools Proxy Manager  ")
    print("  Google Antigravity | VS Code | Cursor | Windsurf | Codex  ")
    print("============================================================")
    print(f"{Colors.RESET}")


def resolve_profile(profile_name: Optional[str] = None, proxy_str: Optional[str] = None) -> Optional[ProxyProfile]:
    """Resolves profile from name or raw string, injecting password from SecretStore."""
    if proxy_str:
        p = ProxyProfile.parse(proxy_str, name=profile_name or "adhoc")
        if p.password:
            SecretStore.store_password(p.name, p.username or "", p.password)
        return p

    name = profile_name or "default"
    prof_dict = StateManager.get_profile(name)
    if not prof_dict:
        # Check if only 1 profile exists
        all_profs = StateManager.list_profiles()
        if len(all_profs) == 1:
            prof_dict = next(iter(all_profs.values()))
            name = prof_dict["name"]

    if not prof_dict:
        return None

    pwd = SecretStore.get_password(name)
    return ProxyProfile.from_dict(prof_dict, password=pwd)


def cmd_profile_add(args):
    raw = args.proxy
    name = args.name or "default"
    try:
        profile = ProxyProfile.parse(raw, name=name)
        if profile.password:
            backend = SecretStore.store_password(name, profile.username or "", profile.password)
            print(f"{Colors.GREEN}[✓] Пароль надежно сохранен ({backend}).{Colors.RESET}")
            # Do not persist plaintext password in JSON state
            profile.password = None

        StateManager.save_profile(profile.to_dict(include_password=False))
        print(f"{Colors.GREEN}[✓] Профиль '{name}' успешно сохранен: {profile.to_safe_url()}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Ошибка добавления профиля: {e}{Colors.RESET}")


def cmd_profile_list(args):
    profs = StateManager.list_profiles()
    if not profs:
        print("Нет сохраненных профилей. Добавьте командой: devproxy profile add [URL]")
        return
    print(f"\n{Colors.BOLD}Сохраненные профили:{Colors.RESET}")
    for name, data in profs.items():
        pwd = SecretStore.get_password(name)
        p = ProxyProfile.from_dict(data, password=pwd)
        has_sec = "🔒 (с авторизацией)" if p.has_auth else "🌐 (без пароля)"
        print(f"  • {Colors.CYAN}{name:16}{Colors.RESET}: {p.to_safe_url()} {has_sec}")
    print()


def cmd_profile_remove(args):
    name = args.name
    SecretStore.delete_password(name)
    if StateManager.delete_profile(name):
        print(f"{Colors.GREEN}[✓] Профиль '{name}' удален.{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Профиль '{name}' не найден.{Colors.RESET}")


def cmd_apps_list(args):
    print(f"\n{Colors.BOLD}Поддерживаемые приложения:{Colors.RESET}\n")
    for adapter in list_adapters():
        exe = adapter.detect_executable()
        status = f"{Colors.GREEN}Установлено ({exe}){Colors.RESET}" if exe else f"{Colors.YELLOW}Не найдено{Colors.RESET}"
        print(f"  • {Colors.CYAN}{adapter.app_id:14}{Colors.RESET} [{adapter.display_name}] -> {status}")
    print()


def cmd_test(args):
    profile = resolve_profile(args.profile, args.proxy)
    if not profile:
        print(f"{Colors.RED}[-] Профиль не найден. Укажите --profile или строку прокси.{Colors.RESET}")
        return

    print(f"Тестирование подключения через: {profile.to_safe_url()}")
    res = ProxyValidator.validate(profile)

    if not res.tcp_reachable:
        print(f"  {Colors.RED}✗ Хост прокси недоступен по TCP{Colors.RESET}")
        for err in res.errors:
            print(f"    {Colors.RED}! {err}{Colors.RESET}")
        return

    print(f"  {Colors.GREEN}✓ TCP соединение с прокси установлено (пинг: {res.tcp_latency_ms} ms){Colors.RESET}")
    for t in res.target_checks:
        if t["success"]:
            print(f"  {Colors.GREEN}✓ {t['name']:32}: доступен ({t['latency_ms']} ms, TLS OK){Colors.RESET}")
        else:
            print(f"  {Colors.RED}✗ {t['name']:32}: ошибка ({t.get('error')}){Colors.RESET}")

    if args.echo:
        print("\nЗапрос к внешнему сервису диагностики (Cloudflare Trace)...")
        echo_res = test_ip_echo(profile)
        if echo_res["success"]:
            print(f"  {Colors.GREEN}✓ Исходящий IP прокси: {echo_res['egress_ip']}{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}! Ошибка диагностики IP: {echo_res.get('error')}{Colors.RESET}")

    if res.overall_success:
        print(f"\n{Colors.GREEN}[✓] Прокси готов к работе!{Colors.RESET}\n")
    else:
        print(f"\n{Colors.RED}[-] Соединение не готово к работе.{Colors.RESET}\n")


def cmd_run(args):
    app_id = args.app
    adapter = get_adapter(app_id)
    if not adapter:
        print(f"{Colors.RED}[-] Неизвестное приложение '{app_id}'. Список: devproxy apps list{Colors.RESET}")
        return

    exe = adapter.detect_executable()
    if not exe:
        print(f"{Colors.RED}[-] Исполняемый файл для '{adapter.display_name}' не найден на компьютере.{Colors.RESET}")
        return

    profile = resolve_profile(args.profile, args.proxy)
    if not profile:
        print(f"{Colors.RED}[-] Не указан прокси-профиль.{Colors.RESET}")
        return

    print(f"{Colors.CYAN}[+] Запуск {adapter.display_name} через прокси {profile.to_safe_url()} (Режим сессии)...{Colors.RESET}")
    flags = adapter.get_cli_launch_flags(profile)

    if args.dry_run:
        print(f"  [Dry-Run] Команда: {exe}")
        print(f"  [Dry-Run] Флаги: {flags}")
        print(f"  [Dry-Run] Аргументы: {args.extra_args}")
        return

    try:
        proc, tunnel = Launcher.launch_with_tunnel(
            executable=exe,
            profile=profile,
            adapter_cli_flags=flags,
            extra_args=args.extra_args,
            wait=True
        )
        print(f"{Colors.GREEN}[✓] Сессия {adapter.display_name} завершена. Локальный туннель остановлен.{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Сессия прервана пользователем.{Colors.RESET}")


def cmd_apply(args):
    app_targets = [x.strip() for x in args.app.split(",") if x.strip()]
    profile = resolve_profile(args.profile, args.proxy)
    if not profile:
        print(f"{Colors.RED}[-] Профиль не найден.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}[+] Применение настроек прокси: {profile.to_safe_url()}{Colors.RESET}")
    for target in app_targets:
        adapter = get_adapter(target)
        if not adapter:
            print(f"  {Colors.RED}✗ {target:16}: неизвестный адаптер{Colors.RESET}")
            continue

        ok, msg = adapter.apply_persistent(profile)
        if ok:
            print(f"  {Colors.GREEN}✓ {adapter.display_name:16}: успешно ({msg}){Colors.RESET}")
        else:
            print(f"  {Colors.RED}✗ {adapter.display_name:16}: ошибка ({msg}){Colors.RESET}")
    print()


def cmd_restore(args):
    app_targets = [x.strip() for x in args.app.split(",") if x.strip()]
    print(f"\n{Colors.YELLOW}[-] Восстановление исходных настроек...{Colors.RESET}")
    for target in app_targets:
        adapter = get_adapter(target)
        if not adapter:
            print(f"  {Colors.RED}✗ {target:16}: неизвестный адаптер{Colors.RESET}")
            continue

        ok, msg = adapter.restore_persistent()
        if ok:
            print(f"  {Colors.GREEN}✓ {adapter.display_name:16}: восстановлено ({msg}){Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}! {adapter.display_name:16}: {msg}{Colors.RESET}")
    print()


def cmd_detect(args):
    print(f"\n{Colors.CYAN}[?] Поиск локально запущенных прокси-клиентов...{Colors.RESET}")
    found = LocalProxyDetector.scan_active_clients()
    if not found:
        print("  Активных локальных клиентов не обнаружено на стандартных портах.")
        return

    print(f"\n{Colors.GREEN}Обнаружены локальные прокси:{Colors.RESET}")
    for i, c in enumerate(found, 1):
        url = f"{c['protocol']}://{c['host']}:{c['port']}"
        print(f"  [{i}] {c['name']} -> {url}")

    if args.save:
        choice_idx = int(input("\nВыберите номер для сохранения [1..]: ").strip()) - 1
        if 0 <= choice_idx < len(found):
            c = found[choice_idx]
            prof_name = input("Имя профиля [local]: ").strip() or "local"
            p = ProxyProfile(name=prof_name, protocol=c["protocol"], host=c["host"], port=c["port"])
            StateManager.save_profile(p.to_dict())
            print(f"{Colors.GREEN}[✓] Сохранен профиль '{prof_name}'{Colors.RESET}")


def cmd_status(args):
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== СТАТУС DEVPROXY ==={Colors.RESET}")
    profs = StateManager.list_profiles()
    print(f"\nПрофилей сохранено: {len(profs)}")
    for name, data in profs.items():
        pwd = SecretStore.get_password(name)
        p = ProxyProfile.from_dict(data, password=pwd)
        print(f"  • {name:16}: {p.to_safe_url()}")

    print(f"\n{Colors.BOLD}Состояние сред и конфигураций:{Colors.RESET}")
    for adapter in list_adapters():
        configs = adapter.detect_config_files()
        cfg_status = "не найден"
        for c in configs:
            if os.path.exists(c):
                cfg_status = f"на диске ({c})"
                break
        applied_rec = StateManager.get_applied_record(adapter.app_id)
        applied_info = f"{Colors.GREEN}[Применен persistent]{Colors.RESET}" if applied_rec else "[Без persistent изменений]"
        print(f"  • {adapter.display_name:24}: {cfg_status} {applied_info}")

    print(f"\n{Colors.BOLD}Переменные окружения текущего процесса:{Colors.RESET}")
    diag = get_environment_diagnostics()
    for k, v in diag.items():
        if v != "<not set>":
            print(f"  • {k:20}: {v}")
    print()


def interactive_wizard():
    print_banner()
    while True:
        print("Главное меню:")
        print("  [1] Добавить / ввести свой прокси и запустить приложение")
        print("  [2] Проверить соединение через сохраненный профиль")
        print("  [3] Применить настройки к выбранному приложению (persistent)")
        print("  [4] Восстановить (откатить) настройки приложения")
        print("  [5] Найти запущенный локальный клиент (опционально)")
        print("  [6] Список профилей и статус системы")
        print("  [0] Выход")

        try:
            choice = input("\nВыберите действие [0-6]: ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            print("\nВставьте строку прокси (например: socks5://127.0.0.1:10808 или http://user:pass@host:port):")
            try:
                raw_proxy = input("Прокси: ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not raw_proxy:
                continue

            try:
                profile = ProxyProfile.parse(raw_proxy, name="custom")
            except Exception as e:
                print(f"{Colors.RED}Ошибка формата: {e}{Colors.RESET}\n")
                continue

            print(f"\nПроверка соединения с {profile.to_safe_url()}...")
            res = ProxyValidator.validate(profile)
            if not res.overall_success:
                print(f"{Colors.YELLOW}Внимание: Прокси не ответил на все тесты.{Colors.RESET}")
                for err in res.errors:
                    print(f"  ! {err}")
                cont = input("Продолжить запуск приложения? [y/N]: ").strip().lower()
                if cont != 'y':
                    continue
            else:
                print(f"{Colors.GREEN}[✓] Соединение проверено успешно!{Colors.RESET}")

            # Save profile?
            save = input("Сохранить этот профиль для постоянного использования? [y/N]: ").strip().lower()
            if save == 'y':
                pname = input("Имя профиля [myproxy]: ").strip() or "myproxy"
                profile.name = pname
                if profile.password:
                    SecretStore.store_password(pname, profile.username or "", profile.password)
                StateManager.save_profile(profile.to_dict(include_password=False))
                print(f"{Colors.GREEN}[✓] Профиль сохранен как '{pname}'.{Colors.RESET}")

            # Choose app
            print("\nВыберите приложение для запуска:")
            adapters = list_adapters()
            for i, a in enumerate(adapters, 1):
                exe = a.detect_executable()
                st = "✓ найдено" if exe else "- не найдено"
                print(f"  [{i}] {a.display_name} ({st})")

            try:
                app_choice = input(f"Номер приложения [1..{len(adapters)}]: ").strip()
                app_idx = int(app_choice) - 1
                if 0 <= app_idx < len(adapters):
                    sel_adapter = adapters[app_idx]
                    exe = sel_adapter.detect_executable()
                    if not exe:
                        print(f"{Colors.RED}Исполняемый файл для {sel_adapter.display_name} не найден.{Colors.RESET}")
                        continue
                    print(f"\n{Colors.CYAN}Запуск {sel_adapter.display_name}...{Colors.RESET}")
                    flags = sel_adapter.get_cli_launch_flags(profile)
                    Launcher.launch_with_tunnel(exe, profile, adapter_cli_flags=flags, wait=True)
            except Exception as e:
                print(f"Ошибка: {e}")

        elif choice == "2":
            cmd_test(argparse.Namespace(profile=None, proxy=None, echo=False))
        elif choice == "3":
            print("\nДоступные приложения:")
            for a in list_adapters():
                print(f"  • {a.app_id} ({a.display_name})")
            target = input("Введите ID приложения: ").strip()
            pname = input("Имя профиля [default]: ").strip() or "default"
            cmd_apply(argparse.Namespace(app=target, profile=pname, proxy=None))
        elif choice == "4":
            target = input("Введите ID приложения для отката: ").strip()
            cmd_restore(argparse.Namespace(app=target))
        elif choice == "5":
            cmd_detect(argparse.Namespace(save=True))
        elif choice == "6":
            cmd_status(argparse.Namespace())
        elif choice in ("0", "q", "exit"):
            break


def main():
    parser = argparse.ArgumentParser(description="DevProxy — Universal IDE & Dev Tools Proxy Manager", add_help=True)
    subparsers = parser.add_subparsers(dest="subcommand")

    # profile
    p_prof = subparsers.add_parser("profile", help="Manage proxy profiles")
    p_prof_sub = p_prof.add_subparsers(dest="profile_action")
    p_add = p_prof_sub.add_parser("add", help="Add proxy profile")
    p_add.add_argument("proxy", help="Proxy URL or host:port:user:pass")
    p_add.add_argument("--name", "-n", default="default", help="Profile name")

    p_list = p_prof_sub.add_parser("list", help="List proxy profiles")
    p_del = p_prof_sub.add_parser("remove", help="Delete profile")
    p_del.add_argument("name", help="Profile name to delete")

    # apps
    p_apps = subparsers.add_parser("apps", help="Application adapters")
    p_apps_sub = p_apps.add_subparsers(dest="apps_action")
    p_apps_sub.add_parser("list", help="List supported applications")

    # test
    p_test = subparsers.add_parser("test", help="Test connectivity")
    p_test.add_argument("--profile", "-p", help="Profile name")
    p_test.add_argument("--proxy", help="Ad-hoc proxy URL")
    p_test.add_argument("--echo", action="store_true", help="Query external IP diagnostic")

    # run
    p_run = subparsers.add_parser("run", help="Launch application in isolated session")
    p_run.add_argument("app", help="Target application ID (antigravity, vscode, cursor, codex, etc.)")
    p_run.add_argument("--profile", "-p", help="Profile name")
    p_run.add_argument("--proxy", help="Ad-hoc proxy string")
    p_run.add_argument("--dry-run", action="store_true", help="Show command without launching")
    p_run.add_argument("extra_args", nargs="*", help="Extra arguments passed to application")

    # apply
    p_apply = subparsers.add_parser("apply", help="Apply persistent settings")
    p_apply.add_argument("--app", "-a", required=True, help="App ID or comma-separated list")
    p_apply.add_argument("--profile", "-p", help="Profile name")
    p_apply.add_argument("--proxy", help="Ad-hoc proxy string")

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore original settings")
    p_restore.add_argument("--app", "-a", required=True, help="App ID or comma-separated list")

    # detect
    p_det = subparsers.add_parser("detect", help="Scan local proxy clients")
    p_det.add_argument("--save", action="store_true", help="Offer to save found client as profile")

    # status
    subparsers.add_parser("status", help="Show current status")

    if len(sys.argv) == 1:
        interactive_wizard()
        return

    # Check if first arg is an ad-hoc proxy URL (backward compatibility with devproxy v1)
    first = sys.argv[1]
    if first.startswith(("http://", "https://", "socks5://", "socks5h://")) or (":" in first and not first.startswith("-") and first not in ["profile", "apps", "test", "run", "apply", "restore", "detect", "status"]):
        interactive_wizard()
        return

    # Split extra args after '--'
    raw_argv = sys.argv[1:]
    extra_after_dash = []
    if "--" in raw_argv:
        dash_idx = raw_argv.index("--")
        extra_after_dash = raw_argv[dash_idx + 1:]
        raw_argv = raw_argv[:dash_idx]

    args = parser.parse_args(raw_argv)
    if hasattr(args, "extra_args"):
        args.extra_args = (args.extra_args or []) + extra_after_dash

    if args.subcommand == "profile":
        if args.profile_action == "add": cmd_profile_add(args)
        elif args.profile_action == "list": cmd_profile_list(args)
        elif args.profile_action == "remove": cmd_profile_remove(args)
        else: p_prof.print_help()
    elif args.subcommand == "apps":
        if args.apps_action == "list": cmd_apps_list(args)
        else: p_apps.print_help()
    elif args.subcommand == "test":
        cmd_test(args)
    elif args.subcommand == "run":
        cmd_run(args)
    elif args.subcommand == "apply":
        cmd_apply(args)
    elif args.subcommand == "restore":
        cmd_restore(args)
    elif args.subcommand == "detect":
        cmd_detect(args)
    elif args.subcommand == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
