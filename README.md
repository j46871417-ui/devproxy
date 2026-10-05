# DevProxy 2.0.2

DevProxy запускает приложения через HTTP, HTTPS или SOCKS5-прокси. Локальный HTTP-мост на `127.0.0.1` выполняет авторизацию на upstream, поэтому приложение получает адрес без логина и пароля. Для HTTPS-прокси проверяется его сертификат. TLS между приложением и конечным сервисом остаётся сквозным.

Целевые ОС: Windows и Linux. Python-ядро требует Python 3.11+. Автономные сборки создаются одним workflow из этого же ядра. Старые EXE и независимая C#-реализация удалены. macOS-адаптеры оставлены для экспериментальной проверки; отдельный macOS-релиз не заявлен.

## Windows

Распакуйте portable ZIP и запустите `devproxy.exe` или `НАСТРОИТЬ_ПРОКСИ.bat`. Выбор выполняется цифрами, вводить ID приложений не нужно:

```text
1. Запустить приложение через прокси
2. Проверить подключение прокси
3. Выбрать / изменить прокси
4. Сохранить текущий прокси
5. Показать состояние и диагностику
6. Показать найденные приложения
7. Восстановить изменённые настройки
8. Запустить локальный прокси-мост
0. Выход
```

Для первого запуска выберите `1`, затем номер приложения. Если программа не найдена, укажите путь к её исполняемому файлу: путь с пробелами и в кавычках поддерживается. Затем выберите сохранённый профиль по номеру или введите новый URL прокси в скрытом вводе. Прокси и вручную выбранные пути остаются доступными до выхода из меню. Для сохранения прокси между запусками используйте пункт `4`.

Неверный номер запрашивается повторно. Ошибка запуска, проверки или сохранения остаётся на экране; Enter возвращает в главное меню. Ctrl+C во время действия отменяет его, а в главном меню завершает программу. Пока работает GUI или локальный мост, терминал нужно держать открытым. Эти же меню доступны в Linux.

Для запуска из исходников:

```powershell
python devproxy.py
python devproxy.py --version
```

Чтобы сохранить профиль, выполните следующую команду: URL будет запрошен без отображения на экране.

```powershell
.\devproxy.exe profile add --name work
.\devproxy.exe test --profile work
.\devproxy.exe run antigravity --profile work
.\devproxy.exe run cursor --profile work
.\devproxy.exe run vscode --profile work
.\devproxy.exe run codex --profile work
.\devproxy.exe run opencode --profile work
.\devproxy.exe run claude --profile work
```

В исходниках замените `.\devproxy.exe` на `python devproxy.py`. `claude` означает Claude Code CLI. Для Codex Desktop есть отдельный экспериментальный ID `codex-gui`.

Секрет профиля хранится в Windows Credential Manager; при недоступном vault используется шифрование DPAPI текущего пользователя. Пароли не записываются в state.json. Копирование профиля на другой компьютер/ОС не переносит доступ к секрету: добавьте его заново там.

## Linux

В распакованном исходном архиве:

```bash
python3 install.py --from-checkout
export PATH="$HOME/.local/bin:$PATH"
devproxy --version
devproxy
```

Установщик размещает весь пакет в `~/.local/lib/devproxy`, создаёт лаунчер в `~/.local/bin` и не редактирует `.bashrc`/`.zshrc`. Для установки из ZIP:

```bash
python3 install.py --archive devproxy-source-2.0.2.zip --sha256 EXPECTED_SHA256
```

После публикации тега `v2.0.2` также доступна загрузка фиксированного тега через `python3 install.py --version v2.0.2`. До публикации тега используйте локальный архив или checkout.

Для сохранения пароля требуется доступный Secret Service и `secret-tool` (обычно пакет `libsecret-tools`). На headless Linux без vault пароль можно использовать только в текущей сессии: запустите `devproxy` и введите URL скрыто либо подайте его через `--proxy-stdin`. Программа не объявляет пароль сохранённым, если secure backend недоступен.

## Сессии и отдельный мост

GUI запускается с отдельным каталогом данных DevProxy, чтобы уже открытая обычная IDE не перехватила запуск со старым окружением. При первом запуске может потребоваться повторный вход в IDE. Можно выбрать свой каталог через `--user-data-dir`. Повторная одновременная сессия с тем же каталогом отклоняется. Если launcher аварийно завершился и оставил `.devproxy-session.lock`, сначала закройте соответствующую IDE, затем удалите этот lock.

**Терминал DevProxy должен оставаться открытым.** Если launcher IDE завершился раньше окна, DevProxy продолжает обслуживать мост. Закройте IDE и нажмите Ctrl+C для завершения сессии. На Windows процессам назначается Job Object, на Linux — отдельная группа процессов. Уже запущенные сторонние workers могут потребовать отдельного перезапуска.

```text
devproxy run codex --profile work -- exec "Ответь одним словом OK"
devproxy run claude --profile work -- --help
devproxy exec --profile work -- COMMAND ARGUMENTS
devproxy serve --profile work --port 18080
```

`serve` позволяет отдельно держать мост `http://127.0.0.1:18080`. Запускаемые после настройки приложения могут использовать его в HTTP_PROXY/HTTPS_PROXY. На loopback логин и пароль не нужны; доступ к нему имеют локальные процессы вашего компьютера. Прокси не является механизмом изоляции от других локальных пользователей.

```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
```

Дочерним процессам задаются uppercase и lowercase HTTP_PROXY/HTTPS_PROXY/ALL_PROXY. Существующий NO_PROXY сохраняется и дополняется loopback. Чтобы оставить только loopback, используйте `--no-proxy ""` в `run`/`exec`. Внешние браузеры OAuth и программы, игнорирующие эти переменные, требуют собственной настройки. DevProxy не устанавливает firewall/VPN и не обещает перехватить все сетевые запросы машины.

## Протоколы, сертификаты и диагностика

Принимаются `http://host:port`, `https://host:port`, `socks5://host:port`, `socks5h://host:port`, URL с percent-encoded credentials, `host:port[:user:password]` и bracketed IPv6. Порт 0, неправильный host, управляющие символы, path/query/fragment отклоняются. `socks5` разрешает имена локально; `socks5h` передаёт их proxy-серверу.

```text
devproxy test --profile work
devproxy test --profile work --targets api.openai.com,api.anthropic.com --json
devproxy test --profile work --ca-file /path/to/trusted-ca.pem
devproxy test --profile work --echo
devproxy run cursor --profile work --dry-run
devproxy status
devproxy detect
```

`test` проверяет TCP, CONNECT и строгий TLS ко **всем** выбранным endpoints. Это не проверка API-ключа, подписки, AI-ответа или конкретного extension host. `--echo` отдельно разрешает запрос к Cloudflare Trace для определения исходящего IP. CA добавляется к системным доверенным сертификатам; insecure-режима нет.

Если upstream возвращает 403/407/502, исправьте доступ/авторизацию у своего proxy-провайдера. DevProxy не переключается на прямой маршрут. Для OpenCode проверьте также `models.dev` и выбранного провайдера. При запрещённой загрузке каталога поддерживаемые версии OpenCode имеют `OPENCODE_DISABLE_MODELS_FETCH=1` для отключения обновления каталога; это не открывает доступ к заблокированному AI-сервису. [Документация OpenCode](https://dev.opencode.ai/docs/cli/).

## Постоянные изменения и восстановление

Persistent поддерживается только для JSONC-настроек VS Code-family/Antigravity с **неавторизованным HTTP/HTTPS-прокси**. Для authenticated/SOCKS-прокси используйте `run` или `serve`. В OpenCode, Codex и Claude не создаются вымышленные поля `proxy`.

```text
devproxy apply --app vscode --proxy http://127.0.0.1:18080 --config-path /path/to/settings.json --dry-run
devproxy apply --app vscode --proxy http://127.0.0.1:18080 --config-path /path/to/settings.json
devproxy restore --app vscode --dry-run
devproxy restore --app vscode
```

Без `--config-path` выбирается единственный существующий config; при нескольких/отсутствующих файлах нужна явная цель. Profiles/Portable/Insiders можно выбрать через `--config-path`; XDG_CONFIG_HOME учитывается. Сначала проверяются все цели, сохраняется журнал, затем выполняются записи. Ошибки видны в exit code. Первый `.bak` не перезаписывается. Ручные изменения proxy-полей вызывают конфликт: restore не уничтожает их и сохраняет журнал.

Старые recovery records версии 2.0.0 без applied values не восстанавливаются автоматически: невозможно надёжно отличить ручные изменения. Сохраните state.json и `.bak`, сравните их с текущими настройками и восстановите нужные поля вручную. Утилита не очищает такой журнал под видом успешного restore.

Старые `--status` и `--remove` сопоставлены с `status` и `restore --app all`. Одиночный proxy URL запускает выбор приложения для сессии и больше не меняет глобальные Git/env-настройки всех программ.

## Разработка и выпуск

```text
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -v
python -m pip install -r requirements-build.txt
python -m PyInstaller --onefile --clean --name devproxy devproxy.py
python scripts/package_release.py --name devproxy-windows-x86_64 --output release
```

Сетевые тесты используют только loopback и тестовые credentials. Тестовый CA создаётся на время теста, ключи не публикуются. Нативные Windows vault/DPAPI-тесты включаются через `DEVPROXY_NATIVE_SECRET_TEST=1` и используют уникальные временные записи с удалением. Linux/macOS vault требуют самостоятельной проверки в пользовательской desktop-сессии.

PR-CI проверяет Windows/Linux и Python 3.11/3.14 и собирает оба portable ZIP. Linux binary собирается на Ubuntu 22.04 для x86_64; для старых дистрибутивов и musl/Alpine используйте Python-исходники. Tag workflow проверяет тесты и версию frozen EXE, затем создаёт portable ZIP и SHA-256; GitHub release создаётся черновиком. Публикация результатов CI не равна проверке каждой версии IDE: реальные ограничения перечислены в [MATRIX.md](MATRIX.md).
