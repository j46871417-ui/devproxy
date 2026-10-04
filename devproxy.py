#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevProxy CLI v1.0.0
Universal proxy configuration tool for Cursor, VS Code, Windsurf, VSCodium, Terminals & Git.
"""

import os
import sys
import json
import re
import urllib.request
import urllib.parse
import subprocess
import shutil

# Safe Windows stdout encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

class Colors:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def get_target_configs():
    appdata = os.environ.get("APPDATA", "")
    home = os.path.expanduser("~")

    if sys.platform == "win32":
        targets = [
            {
                "name": "Cursor",
                "path": os.path.join(appdata, "Cursor", "User", "settings.json"),
                "dir": os.path.join(appdata, "Cursor", "User")
            },
            {
                "name": "VS Code",
                "path": os.path.join(appdata, "Code", "User", "settings.json"),
                "dir": os.path.join(appdata, "Code", "User")
            },
            {
                "name": "Windsurf",
                "path": os.path.join(appdata, "Windsurf", "User", "settings.json"),
                "dir": os.path.join(appdata, "Windsurf", "User")
            },
            {
                "name": "VSCodium",
                "path": os.path.join(appdata, "VSCodium", "User", "settings.json"),
                "dir": os.path.join(appdata, "VSCodium", "User")
            },
            {
                "name": "Antigravity IDE",
                "path": os.path.join(appdata, "Antigravity", "User", "settings.json"),
                "dir": os.path.join(appdata, "Antigravity", "User")
            }
        ]
    elif sys.platform == "darwin":
        targets = [
            {
                "name": "Cursor",
                "path": os.path.join(home, "Library", "Application Support", "Cursor", "User", "settings.json"),
                "dir": os.path.join(home, "Library", "Application Support", "Cursor", "User")
            },
            {
                "name": "VS Code",
                "path": os.path.join(home, "Library", "Application Support", "Code", "User", "settings.json"),
                "dir": os.path.join(home, "Library", "Application Support", "Code", "User")
            },
            {
                "name": "Windsurf",
                "path": os.path.join(home, "Library", "Application Support", "Windsurf", "User", "settings.json"),
                "dir": os.path.join(home, "Library", "Application Support", "Windsurf", "User")
            },
            {
                "name": "VSCodium",
                "path": os.path.join(home, "Library", "Application Support", "VSCodium", "User", "settings.json"),
                "dir": os.path.join(home, "Library", "Application Support", "VSCodium", "User")
            }
        ]
    else:
        # Linux
        targets = [
            {
                "name": "Cursor",
                "path": os.path.join(home, ".config", "Cursor", "User", "settings.json"),
                "dir": os.path.join(home, ".config", "Cursor", "User")
            },
            {
                "name": "VS Code",
                "path": os.path.join(home, ".config", "Code", "User", "settings.json"),
                "dir": os.path.join(home, ".config", "Code", "User")
            },
            {
                "name": "Windsurf",
                "path": os.path.join(home, ".config", "Windsurf", "User", "settings.json"),
                "dir": os.path.join(home, ".config", "Windsurf", "User")
            },
            {
                "name": "VSCodium",
                "path": os.path.join(home, ".config", "VSCodium", "User", "settings.json"),
                "dir": os.path.join(home, ".config", "VSCodium", "User")
            }
        ]
    return targets

def strip_json_comments(text: str) -> str:
    """Safe state-machine comment stripper preserving URLs inside quotes."""
    out = []
    in_string = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue

        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue

        if c == '/' and i + 1 < n:
            if text[i + 1] == '/':
                # Line comment
                while i < n and text[i] != '\n':
                    i += 1
                if i < n:
                    out.append(text[i])
                    i += 1
                continue
            elif text[i + 1] == '*':
                # Block comment
                i += 2
                while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                    i += 1
                i += 2
                continue

        out.append(c)
        i += 1
    return "".join(out)

def normalize_proxy_string(raw: str) -> str:
    raw = raw.strip().strip("'\"")
    if not raw:
        return ""
    if raw.startswith(("http://", "https://", "socks5://", "socks5h://")):
        return raw

    parts = raw.split(":")
    if len(parts) == 4:
        # host:port:user:pass
        host, port, user, password = parts
        return f"http://{user}:{password}@{host}:{port}"
    elif len(parts) == 2:
        # host:port
        return f"http://{raw}"

    return f"http://{raw}"

def read_json_settings(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        cleaned = strip_json_comments(raw)
        cleaned = re.sub(r',\s*([\}\]])', r'\1', cleaned)
        return json.loads(cleaned)
    except Exception:
        return {}

def write_json_settings(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
        except Exception:
            pass
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


import socket, threading, select
AI_DOMAINS = [
    "googleapis.com", "google.com", "google.dev", "gstatic.com",
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "claudeusercontent.com",
    "x.ai", "grok.com", "sora.com", "cursor.sh", "cursor.com",
    "windsurf.ai", "codeium.com", "githubcopilot.com", "perplexity.ai",
    "huggingface.co", "midjourney.com"
]

def is_ai_domain(host):
    host = host.lower().split(':')[0]
    for d in AI_DOMAINS:
        if host == d or host.endswith("." + d):
            return True
    return False

def handle_client(client_sock, upstream_url):
    try:
        req = client_sock.recv(8192)
        if not req:
            client_sock.close()
            return
        lines = req.split(b'\r\n')
        first_line = lines[0].decode('utf-8', 'ignore')
        method, url, proto = first_line.split(' ')
        host = ""
        port = 80
        if method == "CONNECT":
            host_port = url.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            for line in lines[1:]:
                if line.lower().startswith(b'host:'):
                    host_val = line.split(b':', 1)[1].strip().decode('utf-8', 'ignore')
                    if ':' in host_val:
                        host = host_val.split(':')[0]
                        port = int(host_val.split(':')[1])
                    else:
                        host = host_val
                    break
        use_proxy = is_ai_domain(host)
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_proxy:
            import urllib.parse
            parsed = urllib.parse.urlparse(upstream_url)
            up_host = parsed.hostname
            up_port = parsed.port or 80
            remote_sock.connect((up_host, up_port))
            if method == "CONNECT":
                auth = ""
                if parsed.username and parsed.password:
                    import base64
                    cred = f"{parsed.username}:{parsed.password}"
                    b64 = base64.b64encode(cred.encode()).decode()
                    auth = f"Proxy-Authorization: Basic {b64}\r\n"
                connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n"
                remote_sock.sendall(connect_req.encode())
                resp = remote_sock.recv(8192)
                if b"200 Connection" not in resp:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    client_sock.close()
                    remote_sock.close()
                    return
                client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                if parsed.username and parsed.password:
                    import base64
                    cred = f"{parsed.username}:{parsed.password}"
                    b64 = base64.b64encode(cred.encode()).decode()
                    auth_header = f"Proxy-Authorization: Basic {b64}\r\n".encode()
                    req = req.replace(b"\r\n", b"\r\n" + auth_header, 1)
                remote_sock.sendall(req)
        else:
            remote_sock.connect((host, port))
            if method == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                remote_sock.sendall(req)
        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data: break
                    dst.sendall(data)
            except: pass
            finally:
                src.close()
                dst.close()
        threading.Thread(target=pipe, args=(client_sock, remote_sock)).start()
        threading.Thread(target=pipe, args=(remote_sock, client_sock)).start()
    except Exception as e:
        client_sock.close()

def run_local_proxy(port, upstream_url):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", port))
    server.listen(100)
    print(f"Local AI Split Proxy listening on 127.0.0.1:{port}")
    print(f"Upstream: {upstream_url}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, upstream_url)).start()


def apply_proxy(proxy_url: str):
    import subprocess, sys
    if "--daemon" not in sys.argv:
        print(f"\n{Colors.CYAN}{Colors.BOLD}[*] Р—Р°РїСѓСЃРєР°РµРј Р»РѕРєР°Р»СЊРЅС‹Р№ AI split-proxy РІ С„РѕРЅРµ...{Colors.RESET}")
        subprocess.Popen([sys.executable, __file__, "--daemon", proxy_url], creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0)
        proxy_url = "http://127.0.0.1:11438"

    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Применяем прокси: {proxy_url}{Colors.RESET}")
    targets = get_target_configs()

    # 1. Update IDE configs
    for t in targets:
        name = t["name"]
        path = t["path"]
        exists = os.path.exists(t["dir"]) or os.path.exists(path)
        try:
            settings = read_json_settings(path)
            settings["http.proxy"] = proxy_url
            settings["http.proxyStrictSSL"] = False
            settings["http.proxySupport"] = "on"
            write_json_settings(path, settings)
            status_text = "обновлен" if exists else "создан конфиг"
            print(f"  {Colors.GREEN}✓{Colors.RESET} {name:16}: {status_text} ({path})")
        except Exception as e:
            print(f"  {Colors.RED}✗{Colors.RESET} {name:16}: ошибка: {e}")

    # 2. Update System / Shell Environment Variables
    if sys.platform == "win32":
        try:
            subprocess.run(f'setx HTTP_PROXY "{proxy_url}" >nul 2>&1', shell=True)
            subprocess.run(f'setx HTTPS_PROXY "{proxy_url}" >nul 2>&1', shell=True)
            subprocess.run(f'setx ALL_PROXY "{proxy_url}" >nul 2>&1', shell=True)
            os.environ["HTTP_PROXY"] = proxy_url
            os.environ["HTTPS_PROXY"] = proxy_url
            os.environ["ALL_PROXY"] = proxy_url
            print(f"  {Colors.GREEN}✓{Colors.RESET} {'Windows Env':16}: системные переменные пользователя установлены (setx)")
        except Exception as e:
            print(f"  {Colors.YELLOW}!{Colors.RESET} Windows Env: {e}")
    else:
        # Linux & macOS shell environment
        rc_files = [os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.zshrc"), os.path.expanduser("~/.profile")]
        block = (
            "\n# >>> devproxy proxy configuration >>>\n"
            f'export http_proxy="{proxy_url}"\n'
            f'export https_proxy="{proxy_url}"\n'
            f'export all_proxy="{proxy_url}"\n'
            f'export HTTP_PROXY="{proxy_url}"\n'
            f'export HTTPS_PROXY="{proxy_url}"\n'
            f'export ALL_PROXY="{proxy_url}"\n'
            'export no_proxy="localhost,127.0.0.1,::1"\n'
            'export NO_PROXY="localhost,127.0.0.1,::1"\n'
            "# <<< devproxy proxy configuration <<<\n"
        )
        for rc in rc_files:
            if os.path.exists(rc) or rc.endswith(".bashrc"):
                try:
                    content = ""
                    if os.path.exists(rc):
                        with open(rc, "r", encoding="utf-8") as f:
                            content = f.read()
                    content = re.sub(r'# >>> devproxy proxy configuration >>>.*?# <<< devproxy proxy configuration <<<\n?', '', content, flags=re.DOTALL)
                    with open(rc, "w", encoding="utf-8") as f:
                        f.write(content.rstrip() + "\n" + block)
                except Exception:
                    pass
        for v in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            os.environ[v] = proxy_url
        print(f"  {Colors.GREEN}✓{Colors.RESET} {'Linux Shell':16}: переменные прокси добавлены в ~/.bashrc / ~/.zshrc")

    # 3. Update Git global configuration
    try:
        subprocess.run(["git", "config", "--global", "http.proxy", proxy_url], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "--global", "https.proxy", proxy_url], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  {Colors.GREEN}✓{Colors.RESET} {'Git Config':16}: глобальные настройки обновлены (http.proxy, https.proxy)")
    except Exception:
        print(f"  {Colors.YELLOW}!{Colors.RESET} {'Git Config':16}: git не найден или вернул ошибку (пропущено)")

    # 4. Connection Test
    test_proxy_connection(proxy_url)

    print(f"\n{Colors.GREEN}{Colors.BOLD}[✓] ГОТОВО! Прокси успешно внедрен во все редакторы и терминал.{Colors.RESET}")
    print(f"{Colors.YELLOW}Совет: Если редактор уже открыт, перезапустите его или нажмите Ctrl+Shift+P -> Reload Window.{Colors.RESET}\n")

def test_proxy_connection(proxy_url: str):
    print(f"  {Colors.CYAN}?{Colors.RESET} Проверка связи через прокси...", end="", flush=True)
    proxy_handler = urllib.request.ProxyHandler({
        'http': proxy_url,
        'https': proxy_url
    })
    opener = urllib.request.build_opener(proxy_handler)

    test_endpoints = [
        "https://generativelanguage.googleapis.com",
        "https://www.google.com"
    ]

    for ep in test_endpoints:
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=7) as resp:
                print(f" {Colors.GREEN}УСПЕШНО! (Код {resp.status}){Colors.RESET}")
                return
        except urllib.error.HTTPError as he:
            if he.code in (200, 404, 400):
                print(f" {Colors.GREEN}УСПЕШНО! Соединение установлено (HTTP {he.code}){Colors.RESET}")
                return
        except Exception:
            pass

    print(f" {Colors.YELLOW}Внимание: Прокси требует специального шлюза или хост ограничен.{Colors.RESET}")

def remove_proxy():
    print(f"\n{Colors.YELLOW}[-] Сброс и удаление настроек прокси...{Colors.RESET}")
    targets = get_target_configs()

    for t in targets:
        name = t["name"]
        path = t["path"]
        if os.path.exists(path):
            try:
                settings = read_json_settings(path)
                changed = False
                for k in ["http.proxy", "http.proxyStrictSSL", "http.proxySupport"]:
                    if k in settings:
                        del settings[k]
                        changed = True
                if changed:
                    write_json_settings(path, settings)
                    print(f"  {Colors.GREEN}✓{Colors.RESET} {name:16}: очищен")
            except Exception as e:
                print(f"  {Colors.RED}✗{Colors.RESET} {name:16}: {e}")

    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_ALL_ACCESS)
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
                try:
                    winreg.DeleteValue(key, var)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            print(f"  {Colors.GREEN}✓{Colors.RESET} {'Windows Env':16}: переменные пользователя удалены")
        except Exception:
            pass
    else:
        # Linux & macOS
        rc_files = [os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.zshrc"), os.path.expanduser("~/.profile")]
        for rc in rc_files:
            if os.path.exists(rc):
                try:
                    with open(rc, "r", encoding="utf-8") as f:
                        content = f.read()
                    cleaned = re.sub(r'# >>> devproxy proxy configuration >>>.*?# <<< devproxy proxy configuration <<<\n?', '', content, flags=re.DOTALL)
                    with open(rc, "w", encoding="utf-8") as f:
                        f.write(cleaned)
                except Exception:
                    pass
        print(f"  {Colors.GREEN}✓{Colors.RESET} {'Linux Shell':16}: переменные удалены из ~/.bashrc / ~/.zshrc")

    try:
        subprocess.run(["git", "config", "--global", "--unset", "http.proxy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "config", "--global", "--unset", "https.proxy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  {Colors.GREEN}✓{Colors.RESET} {'Git Config':16}: настройки git очищены")
    except Exception:
        pass

    print(f"\n{Colors.GREEN}[✓] Все настройки прокси успешно сброшены.{Colors.RESET}\n")

def show_status():
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== ТЕКУЩИЙ СТАТУС НАСТРОЕК ПРОКСИ ==={Colors.RESET}")
    targets = get_target_configs()
    for t in targets:
        name = t["name"]
        path = t["path"]
        val = "не настроен"
        if os.path.exists(path):
            settings = read_json_settings(path)
            if "http.proxy" in settings:
                val = settings["http.proxy"]
        print(f"  * {name:16}: {val}")

    if sys.platform == "win32":
        http_env = os.environ.get("HTTP_PROXY", "не задана")
        https_env = os.environ.get("HTTPS_PROXY", "не задана")
        print(f"  * {'HTTP_PROXY':16}: {http_env}")
        print(f"  * {'HTTPS_PROXY':16}: {https_env}")
    print()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_local_proxy(11438, sys.argv[2])
        return

    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ("--remove", "-r", "clean", "remove"):
            remove_proxy()
            return
        elif arg in ("--status", "-s", "status"):
            show_status()
            return
        elif arg in ("--help", "-h", "help"):
            print("DevProxy CLI v1.0.0")
            print("Использование:")
            print("  python devproxy.py [ПРОКСИ]")
            print("  python devproxy.py --status")
            print("  python devproxy.py --remove")
            return
        else:
            norm = normalize_proxy_string(arg)
            if norm:
                apply_proxy(norm)
                return

    while True:
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("============================================================")
        print("  [+] DevProxy CLI v1.0.0")
        print("      Универсальная настройка Cursor, VS Code, Windsurf, Git")
        print("============================================================")
        print(f"{Colors.RESET}")
        print("  [1] Встроить / обновить прокси (вставить строку или ссылку)")
        print("  [2] Проверить текущий статус настроек")
        print("  [3] Отключить / удалить прокси со всех IDE")
        print("  [0] Выход")
        print(f"{Colors.CYAN}------------------------------------------------------------{Colors.RESET}")

        try:
            choice = input("Выберите действие [0-3]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nВыход.")
            break

        if choice == "1":
            print("\nВставьте строку прокси в любом поддерживаемом формате:")
            print("  - http://user:pass@host:port")
            print("  - host:port:user:pass")
            print("  - socks5://host:port")
            print("  - host:port")
            try:
                raw_proxy = input("\nПрокси: ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if raw_proxy:
                norm = normalize_proxy_string(raw_proxy)
                if norm:
                    apply_proxy(norm)
                else:
                    print(f"{Colors.RED}Неверный формат.{Colors.RESET}")
        elif choice == "2":
            show_status()
        elif choice == "3":
            remove_proxy()
        elif choice in ("0", "q", "exit"):
            print("Завершение работы.")
            break
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()
