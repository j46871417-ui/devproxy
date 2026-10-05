# Область поддержки

Статусы описывают механизм и необходимые проверки. Не обозначают гарантированную работу всех расширений, аккаунтов и сетей.

| Приложение | ID | Сессионный механизм | Persistent | Особенности |
|---|---|---|---|---|
| Antigravity | antigravity | Chromium proxy flag + process ENV, отдельный user-data-dir | HTTP/HTTPS без auth, JSONC | Отдельные language servers и внешний OAuth требуют проверки |
| VS Code | vscode | То же | То же | Уже открытая обычная IDE не используется с отдельным каталогом данных |
| Cursor | cursor | То же | То же | AI/extension transports могут отличаться по версии |
| Windsurf | windsurf | То же | То же | Старый Codeium daemon может сохранить прежнее окружение |
| VSCodium | vscodium | То же | То же | Конкретные Flatpak/Portable пути нужно выбрать явно при неоднозначности |
| Codex CLI | codex | HTTP_PROXY/HTTPS_PROXY через loopback bridge | Не заявлен | Sandbox и background workers проверяются отдельно |
| Codex Desktop | codex-gui | Chromium flag + ENV, экспериментально | Не заявлен | Windows/macOS; packaged launch может быть ограничен ОС |
| OpenCode CLI | opencode | HTTP_PROXY/HTTPS_PROXY через loopback bridge | Не заявлен | Нужен доступ к выбранному AI-провайдеру; catalog/update могут требовать models.dev/opencode.ai |
| Claude Code CLI | claude | HTTP_PROXY/HTTPS_PROXY через loopback bridge | Не заявлен | Desktop/cloud/background sessions имеют другой scope настроек |
| Git | git | Process `-c http.proxy` и strict TLS | Не меняется глобально | Только HTTP/HTTPS; SSH требует отдельной настройки |
| Произвольная команда | exec | Proxy ENV в дочернем процессе | Нет | Команда должна поддерживать ENV proxy |

Целевые ОС: Windows и Linux. macOS-код оставлен экспериментальным; отдельная сборка и нативный Keychain-тест не заявлены.

## Проверяемые уровни

1. Unit/regression: JSONC, входные данные, отсутствие секретов в state/dry-run, exit codes, журнал, конфликты, rollback нескольких файлов.
2. Loopback integration: HTTP/HTTPS CONNECT, auth, fragmented SOCKS5, проверка CA/expiry/hostname, coalesced payload, half-close, 2 МБ transfer/backpressure, idle >30 секунд, stop активных соединений, clean install.
3. Native Windows storage: уникальные test credentials; Credential Manager и DPAPI. Ограниченный service/sandbox token может не иметь доступа к vault; интерактивная пользовательская сессия проверяется отдельно.
4. Real proxy: проверка TLS/CONNECT к конкретным domains. Не доказывает полноценный AI-запрос.
5. App end-to-end: вход в аккаунт, запрос/stream, инструменты и поведение при падении upstream. Этот уровень нельзя объявлять пройденным только по dry-run или detect.

На остановку upstream мост отвечает ошибкой и не подключается напрямую к destination. Это свойство самого моста. Оно не запрещает сторонней программе игнорировать proxy ENV и открыть собственное соединение. UDP/QUIC через мост не поддерживаются; GUI sessions отключают Chromium QUIC. WebSocket/HTTP2/gRPC внутри CONNECT передаются как непрозрачные байты, однако конкретные приложения могут применять другие пути.

Официальные контракты: [VS Code CLI](https://code.visualstudio.com/docs/configure/command-line), [OpenCode network](https://opencode.ai/docs/network/), [Claude Code network](https://code.claude.com/docs/en/network-config), [Codex config schema](https://learn.chatgpt.com/docs/config-schema.json).
