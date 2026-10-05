"""Numbered terminal menus. Failed operations return to the owning menu."""
import getpass
import os
import shutil
import sys

from . import __version__
from .adapters import list_adapters
from .core.launcher import command_for
from .core.profile import ProxyProfile
from .core.recovery import StateManager


def choose(title, labels, zero='Назад'):
    print('\n' + title)
    for index, label in enumerate(labels, 1):
        print(f'  {index}. {label}')
    print(f'  0. {zero}')
    while True:
        raw = input('Номер: ').strip()
        if len(raw) <= len(str(len(labels))) and raw.isascii() and raw.isdecimal() and 0 <= int(raw) <= len(labels):
            return int(raw)
        print(f'Введите число от 0 до {len(labels)}.')


class InteractiveMenu:
    def __init__(self, initial_proxy=None):
        self.proxy_args = ['--proxy', initial_proxy] if initial_proxy else None
        self.proxy_label = ProxyProfile.parse(initial_proxy).to_safe_url() if initial_proxy else 'не выбран'
        self.executables = {}

    def error(self, error):
        from .cli import redact_error
        text = redact_error(str(error))
        if self.proxy_args and self.proxy_args[0] == '--proxy':
            profile = ProxyProfile.parse(self.proxy_args[1])
            for value in (self.proxy_args[1], profile.password, profile.username):
                if value:
                    text = text.replace(value, '<скрыто>')
        print(f'Ошибка ({type(error).__name__}): {text}', file=sys.stderr)

    def select_proxy(self):
        from .cli import resolve_profile
        try:
            profiles = StateManager.list_profiles()
        except (OSError, ValueError, RuntimeError) as error:
            self.error(error)
            print('Сохранённые профили недоступны. Можно ввести прокси для текущей сессии.')
            profiles = {}
        names = list(profiles)
        labels = ['Ввести новый прокси (только для текущей сессии)']
        labels += [f'{name} — {ProxyProfile.from_dict(profiles[name]).to_safe_url()}' for name in names]
        selection = choose('Выберите прокси', labels)
        if selection == 0:
            return False
        if selection == 1:
            print('Формат: http://host:port, https://user:password@host:port или socks5h://host:port')
            print('Ввод скрыт. Вставьте адрес и нажмите Enter; пустой ввод — назад.')
            while True:
                raw = getpass.getpass('Адрес прокси: ').strip()
                if not raw:
                    return False
                try:
                    profile = ProxyProfile.parse(raw)
                except ValueError as error:
                    self.error(error)
                    continue
                self.proxy_args = ['--proxy', raw]
                self.proxy_label = profile.to_safe_url()
                return True
        name = names[selection - 2]
        profile = resolve_profile(name)
        if profile is None:
            raise ValueError('Профиль больше не существует. Выберите другой прокси.')
        self.proxy_args = ['--profile', name]
        self.proxy_label = name + ' — ' + profile.to_safe_url()
        return True

    def ensure_proxy(self):
        return self.proxy_args is not None or self.select_proxy()

    def applications(self):
        adapters = [a for a in list_adapters() if sys.platform in a.supported_os]
        paths = []
        labels = []
        for adapter in adapters:
            try:
                executable = self.executables.get(adapter.app_id) or adapter.detect_executable()
                status = 'найдено' if executable else 'не найдено — можно указать путь'
            except (OSError, ValueError, RuntimeError) as error:
                executable = None
                status = 'поиск не удался — можно указать путь'
                self.error(error)
            paths.append(executable)
            labels.append(f'{adapter.display_name} [{status}]')
        return adapters, paths, labels

    def launch(self):
        from .cli import main
        adapters, paths, labels = self.applications()
        selected = choose('Выберите приложение', labels)
        if not selected:
            return
        adapter, executable = adapters[selected - 1], paths[selected - 1]
        while True:
            if executable:
                print('Программа:', executable)
                action = choose('Запуск', ['Запустить через прокси', 'Указать другой путь'])
                if not action:
                    return
                if action == 1:
                    try:
                        command_for(executable, [])
                    except (OSError, ValueError) as error:
                        self.error(error)
                    else:
                        break
            path = input('Путь к программе (пустой ввод — назад): ').strip().strip('"')
            if not path:
                return
            path = os.path.expandvars(os.path.expanduser(path))
            executable = path if os.path.isfile(path) else shutil.which(path)
            if not executable:
                print('Файл не найден. Укажите путь к исполняемому файлу, а не к папке.')
        self.executables[adapter.app_id] = executable
        if not self.ensure_proxy():
            return
        print('Запускаю', adapter.display_name + '. Ctrl+C завершает сессию и возвращает в меню.')
        code = main(['run', adapter.app_id, '--executable', executable] + self.proxy_args)
        if code not in (0, 130):
            print(f'Запуск завершился с кодом {code}. Сообщение об ошибке показано выше.')

    def save_proxy(self):
        from .cli import main
        if not self.ensure_proxy():
            return
        if self.proxy_args[0] == '--profile':
            print('Этот прокси уже сохранён как профиль.')
            return
        name = input('Название профиля [default], 0 — назад: ').strip() or 'default'
        if name == '0':
            return
        if StateManager.get_profile(name):
            if choose('Профиль уже существует', ['Заменить его текущим прокси']) != 1:
                return
        code = main(['profile', 'add', self.proxy_args[1], '--name', name])
        if code == 0:
            print('Профиль сохранён. Он будет доступен при следующем запуске.')
        else:
            print('Сохранение не выполнено. Текущий прокси остаётся доступен в этой сессии.')

    def restore(self):
        from .cli import main
        names = list(StateManager.load_state().get('applied', {}))
        if not names:
            print('Нет записанных изменений для восстановления.')
            return
        adapters = {a.app_id: a.display_name for a in list_adapters()}
        selected = choose('Восстановить настройки', ['Все записанные изменения'] + [adapters.get(n, n) for n in names])
        if selected:
            target = 'all' if selected == 1 else names[selected - 2]
            main(['restore', '--app', target])

    def run(self):
        from .cli import main
        print('DevProxy', __version__)
        while True:
            try:
                selected = choose('Главное меню — прокси: ' + self.proxy_label, [
                    'Запустить приложение через прокси',
                    'Проверить подключение прокси',
                    'Выбрать / изменить прокси',
                    'Сохранить текущий прокси',
                    'Показать состояние и диагностику',
                    'Показать найденные приложения',
                    'Восстановить изменённые настройки',
                    'Запустить локальный прокси-мост',
                ], zero='Выход')
            except (EOFError, KeyboardInterrupt):
                print('\nВыход.')
                return 0
            if not selected:
                return 0
            try:
                if selected == 1:
                    self.launch()
                elif selected in (2, 8):
                    if self.ensure_proxy():
                        main(['test' if selected == 2 else 'serve'] + self.proxy_args)
                elif selected == 3:
                    self.select_proxy()
                elif selected == 4:
                    self.save_proxy()
                elif selected == 5:
                    main(['status'])
                elif selected == 6:
                    _, paths, labels = self.applications()
                    for index, (label, path) in enumerate(zip(labels, paths), 1):
                        print(f'{index}. {label}: {path or "—"}')
                elif selected == 7:
                    self.restore()
            except EOFError:
                print('\nВвод завершён.')
                return 0
            except KeyboardInterrupt:
                print('\nДействие отменено.')
            except Exception as error:
                self.error(error)
            try:
                input('\nНажмите Enter, чтобы вернуться в главное меню...')
            except (EOFError, KeyboardInterrupt):
                return 0
