# DevProxy CLI ⚡

> **Универсальная легковесная утилита для автоматического внедрения и переключения прокси во всех средах разработки (Cursor, VS Code, Windsurf, VSCodium), Git и системном терминале в один клик.**

[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/j46871417-ui/devproxy/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Зачем это нужно?

При разработке с AI-ассистентами в современных IDE (Cursor, VS Code, Windsurf), а также при работе через VPN или корпоративные шлюзы разработчикам регулярно требуется прокси.
Ручная правка `settings.json`, системных переменных среды `HTTP_PROXY`/`HTTPS_PROXY` и конфигурации Git отнимает кучу времени, приводит к синтаксическим ошибкам и ломает комментарии в JSONC.

**DevProxy** решает это мгновенно:
- Вставьте прокси в любом формате (ссылку `http://...`, `host:port:user:pass`, `socks5://...`).
- Утилита сама корректно распарсит строку, безопасно обновит конфигурации всех установленных IDE, установит системные переменные и настройки Git, создаст бэкап и проверит соединение!

---

## ✨ Возможности

- 🚀 **Поддержка популярных IDE**:
  - [Cursor](https://cursor.com)
  - [Visual Studio Code](https://code.visualstudio.com)
  - [Windsurf](https://codeium.com/windsurf)
  - [VSCodium](https://vscodium.com)
  - [Antigravity IDE](https://github.com)
- 🌐 **Системная интеграция**:
  - Установка переменных среды `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (пользовательский уровень Windows/Shell).
  - Настройка глобального `git config` (`http.proxy` и `https.proxy`).
- 🛡️ **Бережная работа с JSONC**:
  - Умный автомат удаляет `//` и `/* */` комментарии без повреждения ссылок `http://` и строк.
  - Автоматическое создание бэкапа `.bak` перед любым изменением.
- 🔄 **Автонормализация любых форматов**:
  - `http://username:password@1.2.3.4:8080`
  - `1.2.3.4:8080:username:password` (популярный формат прокси-провайдеров)
  - `socks5://1.2.3.4:1080`
  - `1.2.3.4:8080`
- 🧪 **Встроенная проверка связи**:
  - Тестирование соединения с пингом через указанный прокси сразу после применения.
- 🧹 **Сброс в 1 клик**:
  - Полное удаление настроек прокси из всех редакторов, Git и переменных окружения (`--remove`).
- 📦 **Zero-dependency Native Windows EXE**:
  - Скомпилированный C# исполняемый файл работает на любой Windows 10/11 без установки Python, Node.js или сторонних библиотек.

---

## 🚀 Быстрый старт

### Вариант 1: Запуск готового `.exe` (Windows, без установки зависимостей)
1. Скачайте `devproxy.exe` из [Releases](https://github.com/j46871417-ui/devproxy/releases).
2. Запустите двойным кликом или из командной строки:
   ```cmd
   devproxy.exe
   ```
3. Выберите пункт `[1]` и вставьте строку прокси.

#### Аргументы командной строки:
```cmd
:: Применить прокси
devproxy.exe http://user:pass@1.2.3.4:8080
devproxy.exe 1.2.3.4:8080:user:pass

:: Проверить текущий статус
devproxy.exe --status

:: Полностью отключить и удалить прокси
devproxy.exe --remove
```

---

### Вариант 2: Запуск через Python (Кроссплатформенно: Windows / macOS / Linux)
```bash
# Клонировать репозиторий
git clone https://github.com/j46871417-ui/devproxy.git
cd devproxy

# Запустить интерактивное меню
python devproxy.py

# Или сразу аргументом:
python devproxy.py "http://user:pass@host:port"
python devproxy.py --status
python devproxy.py --remove
```

---

## 🛠️ Сборка бинарного файла из исходников

Если вы хотите собрать `.exe` самостоятельно на Windows:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /target:exe /out:devproxy.exe DevProxy.cs
```

---

## 📄 Лицензия

MIT License. Свободно для личного и коммерческого использования.
