# Матрица поддержки инструментов разработки и сред

В таблице представлена подтвержденная матрица интеграции: **Приложение × ОС × Способ подключения**.

| Приложение / Инструмент | ОС | Способ подключения (Сессионный запуск) | Способ подключения (Persistent конфиг) | Авторизация Upstream | TLS / Сертификаты | gRPC / HTTP2 Стриминг | Статус валидации |
|---|---|---|---|---|---|---|---|
| **Google Antigravity** | Win, Mac, Linux | `--proxy-server={LOCAL_TUNNEL}` + env `HTTP_PROXY` | `Antigravity/User/settings.json` (`http.proxy`) | Basic / SOCKS5 handshake через LocalTunnel | Строгий TLS (без `--ignore-certificate-errors`) | Полная (TCP-туннель для gRPC language_server) | **Автоматические тесты + Интеграция** |
| **Visual Studio Code** | Win, Mac, Linux | `--proxy-server={LOCAL_TUNNEL}` + env | `Code/User/settings.json` (`http.proxy`) | Basic / SOCKS5 | Строгий TLS (`proxyStrictSSL=true`) | Поддерживается | **Автоматические тесты + Интеграция** |
| **Cursor** | Win, Mac, Linux | `--proxy-server={LOCAL_TUNNEL}` + env | `Cursor/User/settings.json` (`http.proxy`) | Basic / SOCKS5 | Строгий TLS | Поддерживается (api2.cursor.sh) | **Автоматические тесты + Интеграция** |
| **Windsurf** | Win, Mac, Linux | `--proxy-server={LOCAL_TUNNEL}` + env | `Windsurf/User/settings.json` (`http.proxy`) | Basic / SOCKS5 | Строгий TLS | Поддерживается (Codeium backend) | **Автоматические тесты + Интеграция** |
| **VSCodium** | Win, Mac, Linux | `--proxy-server={LOCAL_TUNNEL}` + env | `VSCodium/User/settings.json` (`http.proxy`) | Basic / SOCKS5 | Строгий TLS | Поддерживается | **Автоматические тесты + Интеграция** |
| **OpenCode** | Win, Mac, Linux | Env `HTTP_PROXY`, `HTTPS_PROXY` | `.opencode/config.json` | Basic / SOCKS5 | Строгий TLS (Node.js ca store) | Chunked transfer / SSE | **Автоматические тесты + Интеграция** |
| **Codex CLI** | Win, Mac, Linux | Env `HTTP_PROXY`, `HTTPS_PROXY` (наследуется sandboxes) | `.codex/config.toml` (`proxy = "..."`) | Basic / SOCKS5 | Строгий TLS | SSE потоковые ответы | **Автоматические тесты + Интеграция** |
| **Codex Desktop (GUI)** | Win, Mac | `--proxy-server={LOCAL_TUNNEL}` + env | `.codex/config.toml` | Basic / SOCKS5 | Строгий TLS | SSE / stdio backend | **Автоматические тесты + Интеграция** |
| **Git** | Win, Mac, Linux | Изолированная команда | Отдельная команда `git config --global http.proxy` | Basic Auth | Строгий TLS (`http.sslVerify=true`) | N/A | **Автоматические тесты** |

---

## Уровни проверки

1. **Автоматические тесты**: Полноценный запуск набора модульных тестов (`tests/test_*.py`):
   - Парсинг всех схем URL, IPv6, URL-encoded паролей, `host:port:user:pass`.
   - Сохранение комментариев JSONC и атомарный откат изменений.
   - Изоляция паролей в SecretStore (Windows Credential Manager / macOS Keychain / Linux Secret Service).
   - Защита от прямого выхода (Fail-Closed) в LocalTunnel при недоступности прокси.
   - Корректная генерация флагов запуска для каждого адаптера.
2. **Реальная интеграционная проверка**:
   - Обнаружение бинарников Google Antigravity и Codex CLI в реальной файловой системе пользователя.
   - Проверка запуска с dry-run флагами.
   - Компиляция и проверка контрольной суммы автономного исполняемого файла `devproxy.exe`.
3. **Неподтвержденные режимы / Ограничения**:
   - Автоматический сброс в прямой незащищенный интернет строго запрещен (всегда возвращается 502/504 при отказе прокси).
   - Изменение ответов AI провайдеров (`loadCodeAssist` и др.) строго исключено.
