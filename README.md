# DevProxy CLI ⚡

> **Универсальная легковесная утилита для автоматического внедрения и переключения прокси во всех средах разработки (Cursor, VS Code, Windsurf, VSCodium), Git и терминале в один клик. Работает на Windows, Linux и macOS.**

[![Release](https://img.shields.io/badge/Release-v1.1.0-blue.svg)](https://github.com/j46871417-ui/devproxy/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Зачем это нужно?

При разработке с AI-ассистентами в современных IDE (Cursor, VS Code, Windsurf), а также при работе через VPN или корпоративные шлюзы разработчикам регулярно требуется прокси.
Ручная правка `settings.json`, системных переменных среды (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`) и конфигурации Git отнимает кучу времени, приводит к синтаксическим ошибкам и ломает комментарии в JSONC.

**DevProxy** решает это мгновенно:
- Вставьте прокси в любом формате (ссылку `http://...`, `host:port:user:pass`, `socks5://...`).
- Утилита сама корректно распарсит строку, безопасно обновит конфигурации всех установленных IDE, настроит переменные терминала и конфигурацию Git, создаст бэкап и проверит соединение!

---

## ✨ Возможности

- 🚀 **Поддержка популярных IDE**:
  - [Cursor](https://cursor.com) (`~/.config/Cursor` / `%APPDATA%\Cursor`)
  - [Visual Studio Code](https://code.visualstudio.com) (`~/.config/Code` / `%APPDATA%\Code`)
  - [Windsurf](https://codeium.com/windsurf) (`~/.config/Windsurf` / `%APPDATA%\Windsurf`)
  - [VSCodium](https://vscodium.com) (`~/.config/VSCodium` / `%APPDATA%\VSCodium`)
  - [Antigravity IDE](https://github.com)
  - Поддержка Flatpak версий в Linux (`~/.var/app/...`)
- 🌐 **Системная интеграция**:
  - **Linux / macOS**: персистентная запись в `~/.bashrc`, `~/.zshrc` и `~/.profile` (экспорт `http_proxy`, `https_proxy`, `all_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `no_proxy`).
  - **Windows**: установка переменных среды пользователя (`setx HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`).
  - **Git**: настройка глобального `git config` (`http.proxy` и `https.proxy`).
- 🛡️ **Бережная работа с JSONC**:
  - Умный автомат удаляет `//` и `/* */` комментарии без повреждения ссылок `http://` и строк.
  - Автоматическое создание бэкапа `.bak` перед любым изменением.
- 🔄 **Автонормализация любых форматов**:
  - `http://username:password@1.2.3.4:8080`
  - `1.2.3.4:8080:username:password` (популярный формат прокси-провайдеров)
  - `socks5://1.2.3.4:1080`
  - `1.2.3.4:8080`
- 🧪 **Встроенная проверка связи**:
  - Автоматическое тестирование туннеля с пингом целевых хостов (Google Generative AI / Web) с передачей Proxy Basic Auth.
- 🧹 **Сброс в 1 клик**:
  - Полное удаление настроек прокси из всех редакторов, Git и переменных окружения (`--remove`).
- 📦 **Zero-dependency**:
  - **Windows**: Автономный `.exe` (C#), работает сразу без установки чего-либо.
  - **Linux / macOS**: Нативный Bash-скрипт `devproxy` или кроссплатформенный Python CLI `devproxy.py`.

---

## 🐧 Быстрый старт на Linux & macOS

### Вариант 1: Быстрая установка в 1 команду (curl)
```bash
curl -fsSL https://raw.githubusercontent.com/j46871417-ui/devproxy/main/install.sh | bash
```
После установки утилита доступна напрямую в терминале:
```bash
# Интерактивное меню
devproxy

# Применить прокси сразу
devproxy http://user:pass@1.2.3.4:8080
devproxy 1.2.3.4:8080:user:pass

# Проверить статус
devproxy --status

# Полностью удалить прокси со всех IDE и терминала
devproxy --remove
```

### Вариант 2: Запуск из репозитория или архива
```bash
# Клонировать репозиторий
git clone https://github.com/j46871417-ui/devproxy.git
cd devproxy

# Сделать исполняемым и запустить
chmod +x devproxy
./devproxy
```

---

## 🪟 Быстрый старт на Windows

1. Скачайте `devproxy.exe` из [Releases](https://github.com/j46871417-ui/devproxy/releases).
2. Запустите двойным кликом или из консоли:
   ```cmd
   devproxy.exe
   ```
3. Выберите `[1]` и вставьте строку прокси.

```cmd
:: Применить прокси аргументом
devproxy.exe http://user:pass@1.2.3.4:8080
devproxy.exe 1.2.3.4:8080:user:pass

:: Статус
devproxy.exe --status

:: Сброс
devproxy.exe --remove
```

---

## 🐍 Кроссплатформенный запуск через Python

```bash
python3 devproxy.py
# или:
python3 devproxy.py "http://user:pass@host:port"
python3 devproxy.py --status
python3 devproxy.py --remove
```

---

## 🛠️ Сборка Windows бинарника (.exe) из исходников

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /target:exe /out:devproxy.exe DevProxy.cs
```

---

## 📄 Лицензия

MIT License. Свободно для личного и коммерческого использования.
