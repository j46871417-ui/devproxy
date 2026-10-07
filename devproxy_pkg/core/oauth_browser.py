"""A dedicated Chromium login profile on the IDE's own proxy bridge."""
import os
from pathlib import Path
import re
import urllib.parse
import time
import hashlib
import socket
import ssl
from .transport import read_headers
from .recovery import get_devproxy_state_path
from .user_errors import UserInputError


def validate_login_url(url):
    url = url.strip()
    if len(url) > 16384 or any(ord(c) < 32 for c in url):
        raise UserInputError("Некорректная ссылка входа.")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ("accounts.google.com", "antigravity.google")
            or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443)):
        raise UserInputError("Вставьте HTTPS-ссылку входа Google или Antigravity из приложения.")
    return url


def find_browser():
    names = ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe")
    if os.name == "nt":
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for name in names:
                try:
                    with winreg.OpenKey(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + name) as key:
                        path = Path(winreg.QueryValueEx(key, "")[0].strip('"'))
                        if path.is_file():
                            return str(path)
                except OSError:
                    pass
    for directory in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA")):
        if directory:
            for relative in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe",
                             "BraveSoftware/Brave-Browser/Application/brave.exe", "Yandex/YandexBrowser/Application/browser.exe"):
                path = Path(directory) / relative
                if path.is_file():
                    return str(path)
    return None


def latest_login_url():
    """Read a bounded, recent log tail; never save, print or send its contents."""
    appdata = Path(os.environ.get("APPDATA", str(Path.home())))
    path = appdata / "antigravity" / "logs" / "language_server.log"
    try:
        if time.time() - path.stat().st_mtime > 300:
            return None
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 131072))
            text = stream.read(131072).decode("utf-8", "replace")
        matches = re.findall(r'https://accounts\.google\.com/(?:o/oauth2/|v3/signin/|signin/)[^\s<>"\x1b]+', text)
        return validate_login_url(matches[-1]) if matches else None
    except (OSError, ValueError):
        return None


def check_local_callback(url):
    """Reject a stale desktop callback without sending an auth code to it."""
    callbacks = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get('redirect_uri', [])
    if not callbacks:
        return
    callback = urllib.parse.urlsplit(callbacks[0])
    if callback.hostname not in ('localhost','127.0.0.1','::1'):
        return  # Other supported flows are handled by the Google/client UI.
    try:
        port = callback.port or (443 if callback.scheme == 'https' else 80)
        with socket.create_connection((callback.hostname,port),timeout=2):
            pass
    except (OSError, ValueError):
        raise UserInputError('Ссылка входа устарела: локальный приёмник Antigravity не работает. '
                             'Нажмите вход в Antigravity ещё раз и вставьте новую ссылку.') from None


def check_login_tunnel(session, timeout=15):
    """Verify the actual browser bridge and Google TLS before opening OAuth."""
    provider = session.tunnel.profile_provider
    if provider is not None:
        try:
            provider()
        except Exception:
            raise UserInputError('Действующий мост потерял привязку к сохранённому профилю. '
                                 'Обновите DevProxy и перезапустите агент; пароль и профиль удалять не нужно.') from None
    try:
        deadline = time.monotonic()+timeout
        with socket.create_connection((session.tunnel.bind_host,session.tunnel.allocated_port),timeout=timeout) as client:
            client.sendall(b'CONNECT accounts.google.com:443 HTTP/1.1\r\nHost: accounts.google.com:443\r\n\r\n')
            headers, tail = read_headers(client)
            if headers.splitlines()[0].split()[1:2] != [b'200'] or tail:
                failures = session.tunnel.diagnostics().get('failures',[])
                details = next((entry['message'] for entry in reversed(failures)
                                if entry.get('host') == 'accounts.google.com'),None)
                raise UserInputError(details or 'Прокси не открыл туннель к accounts.google.com. '
                                     'Проверьте профиль и разрешённые назначения.')
            client.settimeout(max(0.001,deadline-time.monotonic()))
            with ssl.create_default_context().wrap_socket(client,server_hostname='accounts.google.com') as tls:
                tls.settimeout(max(0.001,deadline-time.monotonic()))
                # An unauthenticated HEAD closes the remote side promptly;
                # OAuth URL, state, PKCE and user credentials are never sent.
                tls.sendall(b'HEAD / HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n')
                read_headers(tls)
    except UserInputError:
        raise
    except ssl.SSLCertVerificationError:
        raise UserInputError('Не удалось проверить сертификат Google. Вход не открыт; '
                             'проверка TLS не отключается.') from None
    except OSError as error:
        raise UserInputError('Защищённое соединение браузера с accounts.google.com не установлено: '
                             +type(error).__name__+'. Вход не открыт.') from None


def launch_login_browser(session, url, executable=None):
    url = validate_login_url(url)
    executable = executable or find_browser()
    if not executable:
        raise UserInputError("Браузер не найден. Выберите установленный Chrome, Edge, Brave или Яндекс Браузер.")
    if Path(executable).name.lower() not in ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe"):
        raise UserInputError("Для входа выберите Chrome, Edge, Brave или Яндекс Браузер.")
    check_local_callback(url)
    check_login_tunnel(session)
    provider = session.tunnel.profile_provider
    identity = getattr(provider, "profile_id", None) or session.tunnel.session_id
    directory = Path(get_devproxy_state_path()).parent / "oauth-browser" / hashlib.sha256(str(identity).encode()).hexdigest()[:24]
    directory.mkdir(parents=True, exist_ok=True)
    if hasattr(provider, "pin"):
        provider.pin()
    flags = ["--proxy-server={PROXY_URL}", "--user-data-dir=" + str(directory),
             "--no-first-run", "--no-default-browser-check", "--new-window", url]
    # Proxy credentials stay in the bridge; the URL is neither logged nor persisted.
    return session.launch(executable, flags=flags, electron=True, preserve_profile=True)
