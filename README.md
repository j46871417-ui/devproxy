# DevProxy 2.0 ⚡

> **Универсальный и безопасный менеджер подключения IDE и инструментов разработки через собственный прокси пользователя.**  
> Поддержка: **Google Antigravity, VS Code, Cursor, Windsurf, VSCodium, OpenCode, Codex CLI и Codex Desktop (GUI)**.  
> Кроссплатформенно: Windows, macOS, Linux.

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Audited](https://img.shields.io/badge/Security-OS%20Keyring%20%7C%20Fail--Closed-blue.svg)]()

---

## 🎯 Ключевые возможности

1. **Главный сценарий: собственный прокси**:
   - Пользователь вставляет свой собственный прокси (HTTP, HTTPS, SOCKS5, SOCKS5h).
   - Утилита проверяет соединение (TCP пинг, авторизация прокси, доступ к AI-провайдерам без автоматического слива IP).
   - Сохраняет именованный профиль в защищенном хранилище.
   - Запускает выбранное приложение через изолированный профиль (Режим сессии по умолчанию) либо применяет постоянные настройки по выбору.
2. **Безопасность первого класса**:
   - 🔒 **Строгий TLS всегда включен**: Никаких `proxyStrictSSL=false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` или `--ignore-certificate-errors`.
   - 🛡️ **Защищенное хранение паролей**: Пароли сохраняются только в платформенном защищенном хранилище: **Windows Credential Manager / DPAPI**, **macOS Keychain**, **Linux Secret Service**. В конфигурационные файлы, переменные окружения, логи или консольный вывод открытые пароли никогда не попадают.
   - 🚫 **Fail-Closed**: При обрыве или ошибке прокси локальный мост не сбрасывает трафик в прямой незащищенный интернет (возвращается 502/504 Bad Gateway).
   - 📦 **Никакого MitM**: Трафик между приложением и AI-провайдером (Google, OpenAI, Anthropic) передается сквозными зашифрованными TLS-байтами без чтения промптов, токенов или подмены ответов.
3. **Модульная архитектура адаптеров**:
   - `ProxyProfile`: Валидация и нормализация URL, IPv6 `[::1]`, URL-encoded спецсимволов.
   - `SecretStore`: Платформенное шифрование учетных данных.
   - `ProxyValidator`: Пошаговое тестирование канала.
   - `ApplicationAdapter`: Индивидуальные адаптеры для Antigravity, VS Code, Cursor, Windsurf, VSCodium, OpenCode, Codex CLI, Codex GUI.
   - `Launcher`: Безопасный запуск процессов (без `shell=True`).
   - `ConfigEditor`: Бережное редактирование JSONC/TOML с сохранением комментариев и атомарной записью.
   - `Tunnel`: Локальный петлевой мост (loopback `127.0.0.1`) для прозрачного SOCKS5/HTTP подключения.
   - `Recovery`: Точный откат только внесенных утилитой изменений.

---

## 🚀 Быстрый старт

### Интерактивный мастер (простейший путь):
```bash
python devproxy.py
# или в Windows:
devproxy.exe
# или в Linux / macOS:
./devproxy
```
Мастер проведет по шагам:  
**«Вставить свой прокси → проверить → выбрать приложение → запустить»**.

---

## 💻 Команды CLI

### 1. Управление профилями
```bash
# Добавить профиль со своим прокси
python devproxy.py profile add "socks5://user:password@1.2.3.4:10808" --name mynode
python devproxy.py profile add "http://1.2.3.4:8080" --name office

# Просмотреть сохраненные профили (секреты надежно замаскированы)
python devproxy.py profile list

# Удалить профиль
python devproxy.py profile remove mynode
```

### 2. Проверка соединения
```bash
# Проверить профиль
python devproxy.py test --profile mynode

# Проверить ad-hoc прокси без сохранения
python devproxy.py test --proxy "socks5://127.0.0.1:10808"

# Опциональная проверка исходящего внешнего IP (с явным указанием целевого хоста)
python devproxy.py test --profile mynode --echo
```

### 3. Список приложений
```bash
python devproxy.py apps list
```
Показывает установленные на компьютере среды разработки (`antigravity`, `vscode`, `cursor`, `windsurf`, `vscodium`, `opencode`, `codex`, `codex-gui`) и пути к их исполняемым файлам.

### 4. Режим сессии (Запуск без изменения системных настроек)
```bash
# Запустить Google Antigravity через профиль mynode
python devproxy.py run antigravity --profile mynode

# Запустить Cursor с передачей дополнительных аргументов рабочей директории
python devproxy.py run cursor --profile mynode -- .

# Запустить Codex CLI
python devproxy.py run codex --profile mynode
```

### 5. Постоянная настройка (Persistent) и Откат (Recovery)
```bash
# Применить настройки к выбранному приложению
python devproxy.py apply --app antigravity --profile mynode
python devproxy.py apply --app vscode,cursor --profile mynode

# Безопасный откат настроек приложения к исходным
python devproxy.py restore --app antigravity
python devproxy.py restore --app vscode,cursor
```

### 6. Дополнительно: Поиск локальных клиентов
```bash
python devproxy.py detect
python devproxy.py detect --save
```
*(Функция исключительно по запросу: никогда не запускается автоматически и не меняет введенный адрес без подтверждения).*

---

## 📊 Матрица поддержки

Подробная матрица интеграции **Приложение × ОС × Способ подключения** доступна в [MATRIX.md](MATRIX.md).

---

## 🛡️ Безопасность и проверка подлинности сборок

- Исходный код C# скомпилирован через официальный компилятор платформы.
- Контрольная сумма `devproxy.exe`:
  - **SHA-256**: `D1104B97008E7E7EBD3A329109BF4CFFF616B0CC6E210429A50F0AADE383794A`
- Запуск тестов:
  ```bash
  python -m unittest discover -s tests -p "test_*.py"
  ```
