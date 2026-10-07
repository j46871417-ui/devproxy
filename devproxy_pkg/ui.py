"""Russian desktop workflow: profiles, persisted discovery and selected app sessions."""
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import uuid
from functools import partial

from .adapters import get_adapter
from .adapters.generic import GenericApplicationAdapter
from .cli import resolve_profile, resolve_saved_profile, SavedProfileProvider
from .core.launcher import ApplicationSession
from .core.profile import ProxyProfile
from .core.profiles import persist_profile, profile_from_fields, set_route_backups
from .core.recovery import StateManager
from .core.secrets import SecretStore
from .core.transport import connect_upstream
from .core.user_errors import describe_error, UserInputError
from .discovery import canonical, discover_applications, merge_applications
from .ui_editing import editable_entry
from . import __version__


def check_proxy(profile, target):
    """Check protocol/auth/connect using a user-visible destination; no fallback."""
    target = target.strip()
    if not target or any(c in target for c in "/\\@?# \r\n\t"):
        raise UserInputError("Для проверки введите имя сайта без https://, например github.com.")
    try:
        ProxyProfile("Проверка", "http", target, 443)
    except ValueError:
        raise UserInputError("Введите имя сайта без схемы, пути и порта, например github.com.") from None
    sock, _ = connect_upstream(profile, target, 443, timeout=8)
    sock.close()


class ProfileDialog:
    PROTOCOLS = {"SOCKS5": "socks5", "HTTP": "http", "HTTPS — защищённый прокси": "https"}

    def __init__(self, owner, original=None):
        self.owner, self.original = owner, original
        self.window = tk.Toplevel(owner.root)
        self.window.title("Изменить прокси" if original else "Добавить прокси")
        self.window.transient(owner.root)
        self.window.resizable(False, False)
        self.window.grab_set()
        data = StateManager.get_profile(original) if original else {}
        data = data or {}
        self.saved_secret = bool(data.get("secret_reference") or data.get("username") is not None)
        label = next((k for k, v in self.PROTOCOLS.items() if v == data.get("protocol")), "SOCKS5")
        existing_names = StateManager.list_profiles()
        index = 1
        while f"Прокси {index}" in existing_names:
            index += 1
        self.name = tk.StringVar(value=data.get("name", f"Прокси {index}"))
        self.protocol = tk.StringVar(value=label)
        self.host = tk.StringVar(value=data.get("host", ""))
        self.port = tk.StringVar(value=str(data.get("port", 1080)))
        self.auth = tk.BooleanVar(value=self.saved_secret)
        self.username = tk.StringVar(value=data.get("username") or "")
        self.password = tk.StringVar()
        self.result = tk.StringVar()
        frame = ttk.Frame(self.window, padding=20)
        frame.grid(sticky="nsew")
        ttk.Label(frame, text="Введите параметры прокси", font=("Segoe UI", 15, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Есть готовая ссылка? Вставьте её — поля заполнятся автоматически.").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 10))
        ttk.Button(frame, text="Вставить ссылку прокси", command=self.paste_url).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 12))
        for row, text, variable in ((3, "Название", self.name), (5, "Адрес сервера", self.host), (6, "Порт", self.port)):
            ttk.Label(frame, text=text).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=6)
            editable_entry(frame, textvariable=variable, width=42).grid(row=row, column=1, sticky="ew", pady=6)
        ttk.Label(frame, text="Тип прокси").grid(row=4, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.protocol, state="readonly", values=list(self.PROTOCOLS), width=39).grid(row=4, column=1, sticky="ew")
        ttk.Label(frame, text="Только адрес: 127.0.0.1 или proxy.example.com; IPv6 тоже поддерживается.").grid(row=7, column=0, columnspan=2, sticky="w", pady=(2, 10))
        ttk.Checkbutton(frame, text="Прокси требует логин и пароль", variable=self.auth, command=self.toggle_auth).grid(row=8, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Логин").grid(row=9, column=0, sticky="w", pady=6)
        self.user_entry = editable_entry(frame, textvariable=self.username, width=42)
        self.user_entry.grid(row=9, column=1, sticky="ew")
        ttk.Label(frame, text="Пароль").grid(row=10, column=0, sticky="w", pady=6)
        self.password_entry = editable_entry(frame, textvariable=self.password, show="•", width=42)
        self.password_entry.grid(row=10, column=1, sticky="ew")
        hint = ("Пароль уже сохранён в защищённом хранилище Windows.\n• Оставьте поле пустым — текущий пароль останется без изменений.\n• Введите новый пароль, если хотите его заменить."
                if self.saved_secret else "Пароль надёжно сохраняется в защищённом хранилище Windows (Credential Manager) без открытого текста.")
        ttk.Label(frame, text=hint, wraplength=530).grid(row=11, column=0, columnspan=2, sticky="w", pady=(4, 14))
        ttk.Label(frame, text="Сайт для проверки").grid(row=12, column=0, sticky="w")
        self.target = tk.StringVar(value=owner.target.get())
        editable_entry(frame, textvariable=self.target, width=42).grid(row=12, column=1, sticky="ew")
        ttk.Label(frame, textvariable=self.result, wraplength=530).grid(row=13, column=0, columnspan=2, sticky="w", pady=10)
        buttons = ttk.Frame(frame)
        buttons.grid(row=14, column=0, columnspan=2, sticky="e")
        self.test_button = ttk.Button(buttons, text="Проверить", command=self.test)
        self.test_button.pack(side="left", padx=6)
        ttk.Button(buttons, text="Отмена", command=self.close).pack(side="left", padx=6)
        self.save_button = ttk.Button(buttons, text="Сохранить", command=self.save)
        self.save_button.pack(side="left", padx=6)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.toggle_auth()

    def toggle_auth(self):
        state = "normal" if self.auth.get() else "disabled"
        self.user_entry["state"] = self.password_entry["state"] = state

    def fields(self):
        profile = profile_from_fields(self.name.get(), self.PROTOCOLS[self.protocol.get()],
                                      self.host.get(), self.port.get(), self.username.get(),
                                      self.password.get() if self.auth.get() else None, self.auth.get())
        keep = self.auth.get() and self.saved_secret and not self.password.get()
        if self.auth.get() and not self.password.get() and not keep:
            raise UserInputError("Введите пароль прокси.")
        return profile, keep

    def paste_url(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Вставить ссылку")
        dialog.transient(self.window)
        dialog.grab_set()
        ttk.Label(dialog, text="Например: socks5://логин:пароль@сервер:1080\nВведённая ссылка скрыта, чтобы не показывать пароль.", padding=12).pack(anchor="w")
        value = tk.StringVar()
        entry = editable_entry(dialog, textvariable=value, show="•", width=60)
        entry.pack(padx=12, pady=6)
        entry.focus_set()
        def apply():
            try:
                profile = ProxyProfile.parse(value.get(), self.name.get().strip() or "Мой прокси")
                self.name.set(profile.name)
                self.protocol.set(next(k for k, v in self.PROTOCOLS.items() if v == profile.protocol or v == "socks5" and profile.is_socks))
                self.host.set(profile.host)
                self.port.set(str(profile.port))
                self.auth.set(profile.has_auth)
                self.username.set(profile.username or "")
                self.password.set(profile.password or "")
                self.toggle_auth()
                value.set("")
                profile.password = None
                dialog.destroy()
                self.window.grab_set()
            except ValueError:
                messagebox.showerror("Ссылка не распознана", "Проверьте формат: тип://сервер:порт или сервер:порт:логин:пароль.", parent=dialog)
        ttk.Button(dialog, text="Заполнить поля", command=apply).pack(padx=12, pady=12)

    def save(self):
        try:
            profile, keep = self.fields()
            persist_profile(profile, self.original, keep)
            self.owner.refresh_profiles(profile.name)
            self.owner.status.set("Прокси сохранён. Отметьте приложения и нажмите «Запустить».")
            self.close()
        except Exception as error:
            self.result.set(describe_error(error, self.target.get()))

    def test(self):
        try:
            profile, keep = self.fields()
            target = self.target.get()
        except Exception as error:
            self.result.set(describe_error(error))
            return
        self.test_button["state"] = self.save_button["state"] = "disabled"
        self.result.set("Проверяем подключение, авторизацию и доступ к сайту…")
        # Preserve/resolve the existing secret in the backend worker, never in form fields.
        def work():
            try:
                if keep:
                    stored = resolve_profile(self.original)
                    profile.password = stored.password
                    stored.password = None
                check_proxy(profile, target)
                result = f"Проверка пройдена: прокси открыл соединение к {target}:443."
            except Exception as error:
                result = describe_error(error, target)
            finally:
                profile.password = None
            self.owner.events.put(("dialog_test", self, result))
        threading.Thread(target=work, daemon=True).start()

    def close(self):
        self.password.set("")
        self.window.destroy()


class DevProxyWindow:
    def __init__(self, root, auto_discover=True, background=None):
        self.root = root
        self.background = background
        self.tray = None
        self.background_closing = self.persistent_busy = False
        self._background_error = None
        self._snapshot_at = 0.0
        self._status_refresh_pending = threading.Event()
        root.title("DevProxy " + __version__ + " — прокси для приложений")
        root.geometry("1040x760")
        root.minsize(860, 650)
        style = ttk.Style(root)
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=(10, 6))
        self.events = queue.Queue()
        self.session = self.worker = self.scan_worker = None
        self.cancel = threading.Event()
        self.closing = False
        self.records = []
        self.profile = tk.StringVar()
        self.status = tk.StringVar(value="Добавьте прокси, отметьте приложения и нажмите «Запустить».")
        self.summary = tk.StringVar()
        self.discovery_status = tk.StringVar()
        self.target = tk.StringVar(value="github.com")
        self.rows = {}
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="DevProxy", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(frame, text="1. Добавьте прокси     →     2. Отметьте приложения     →     3. Запустите", font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 16))
        proxy_box = ttk.LabelFrame(frame, text="Прокси", padding=12)
        proxy_box.pack(fill="x")
        line = ttk.Frame(proxy_box)
        line.pack(fill="x")
        self.profile_combo = ttk.Combobox(line, textvariable=self.profile, state="readonly", width=32)
        self.profile_combo.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.profile_combo.bind("<<ComboboxSelected>>", lambda _: self.update_summary())
        self.profile_buttons = []
        for text, command in (("Добавить", self.add_profile), ("Изменить", self.edit_profile),
                              ("Удалить", self.delete_profile), ("Проверить", self.test_profile)):
            button = ttk.Button(line, text=text, command=command)
            button.pack(side="left", padx=3)
            self.profile_buttons.append(button)
        ttk.Label(proxy_box, textvariable=self.summary).pack(anchor="w", pady=(8, 4))
        target_line = ttk.Frame(proxy_box)
        target_line.pack(fill="x")
        ttk.Label(target_line, text="Сайт для проверки:").pack(side="left")
        self.target_entry = editable_entry(target_line, textvariable=self.target, width=26)
        self.target_entry.pack(side="left", padx=8)
        ttk.Label(target_line, text="Если сайт заблокирован вашим прокси, укажите другой.").pack(side="left")
        network_tools = ttk.Frame(proxy_box)
        network_tools.pack(fill="x", pady=(6, 0))
        ttk.Button(network_tools, text="Резервные прокси…", command=self.route_backups).pack(side="left")
        ttk.Button(network_tools, text="Вход Antigravity через прокси…", command=self.login_antigravity).pack(side="left", padx=8)
        footer = ttk.Frame(frame)
        footer.pack(side="bottom", fill="x")
        apps_box = ttk.LabelFrame(frame, text="Приложения — установленные IDE и инструменты добавляются автоматически", padding=12)
        apps_box.pack(fill="both", expand=True, pady=12)
        tools = ttk.Frame(apps_box)
        tools.pack(fill="x", pady=(0, 8))
        self.find_button = ttk.Button(tools, text="Найти приложения", command=self.scan)
        self.find_button.pack(side="left")
        self.add_app_button = ttk.Button(tools, text="Добавить EXE…", command=self.browse)
        self.add_app_button.pack(side="left", padx=6)
        self.remove_app_button = ttk.Button(tools, text="Убрать из списка", command=self.remove_app)
        self.remove_app_button.pack(side="left")
        ttk.Button(tools, text="Выбрать все", command=lambda: self.select_all(True)).pack(side="right", padx=6)
        ttk.Button(tools, text="Снять выбор", command=lambda: self.select_all(False)).pack(side="right")
        table_frame = ttk.Frame(apps_box)
        table_frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(table_frame, columns=("use", "name", "kind", "status", "path"), show="headings", selectmode="browse", height=10)
        for key, title, width in (("use", "Выбор", 62), ("name", "Приложение", 165), ("kind", "Тип", 80),
                                  ("status", "Состояние", 135), ("path", "Расположение", 340)):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=50, stretch=key in ("name", "path"), anchor="center" if key == "use" else "w")
        self.table.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(table_frame, command=self.table.yview)
        scroll.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scroll.set)
        self.table.bind("<Button-1>", self.toggle_row)
        self.table.bind("<space>", self.toggle_selected)
        self.table.bind("<<TreeviewSelect>>", self.on_select_app)
        self.selected_app_info = tk.StringVar(value="")
        self.selected_path_label = ttk.Label(apps_box, textvariable=self.selected_app_info, foreground="#444444", wraplength=980)
        self.selected_path_label.pack(side="bottom", anchor="w", pady=(2, 0), before=table_frame)
        self.discovery_label = ttk.Label(apps_box, textvariable=self.discovery_status, wraplength=980)
        self.discovery_label.pack(side="bottom", anchor="w", pady=(4, 0), before=table_frame)
        self.workflow_label = ttk.Label(footer, text="Запускаются только отмеченные приложения. «Остановить» завершает их и дочерние процессы.", wraplength=980)
        self.workflow_label.pack(anchor="w")
        self.limit_label = ttk.Label(footer, text="Некоторые приложения могут игнорировать прокси. Полная блокировка прямых подключений пока недоступна.", foreground="#984800", wraplength=980)
        self.limit_label.pack(anchor="w", pady=4)
        controls = ttk.Frame(footer)
        controls.pack(fill="x", pady=10)
        self.start_button = ttk.Button(controls, text="Запустить выбранные", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(controls, text="Остановить", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        self.status_label = ttk.Label(footer, textvariable=self.status, wraplength=980, font=("Segoe UI", 10))
        self.status_label.pack(anchor="w")
        self.enable_button = ttk.Button(controls, text="Включить постоянно", command=self.enable_permanent)
        self.enable_button.pack(side="left", padx=8)
        self.disable_button = ttk.Button(controls, text="Вернуть обычный запуск", command=self.disable_permanent)
        self.disable_button.pack(side="left")
        ttk.Button(controls, text="В трей", command=self.hide).pack(side="right")
        root.bind("<Unmap>", self.on_unmap, add="+")
        root.bind("<Configure>", self.resize_text)
        try:
            self.records = StateManager.list_applications()
            self.refresh_profiles(StateManager.load_state().get("selected_profile"))
        except Exception as error:
            self.status.set(describe_error(error))
        self.render_apps()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)
        if auto_discover:
            root.after(150, self.scan)

    def on_select_app(self, _):
        selected = self.table.selection()
        if selected and selected[0] in self.rows:
            rec = self.rows[selected[0]]
            self.selected_app_info.set(f"Выбрано: {rec.get('name', 'Приложение')} • Расположение: {rec.get('executable', '')}")

    def refresh_profiles(self, selected=None):
        names = list(StateManager.list_profiles())
        self.profile_combo["values"] = names
        if selected in names:
            self.profile.set(selected)
        elif self.profile.get() not in names:
            self.profile.set(names[0] if names else "")
        self.update_summary()

    def resize_text(self, event):
        if event.widget == self.root:
            width = max(400, event.width - 48)
            self.limit_label.configure(wraplength=width)
            self.status_label.configure(wraplength=width)
            self.workflow_label.configure(wraplength=width)
            if hasattr(self, "selected_path_label"):
                self.selected_path_label.configure(wraplength=width)
            if hasattr(self, "discovery_label"):
                self.discovery_label.configure(wraplength=width)

    def update_summary(self):
        data = StateManager.get_profile(self.profile.get()) if self.profile.get() else None
        if not data:
            self.summary.set("Прокси пока не настроен. Нажмите кнопку «Добавить», чтобы ввести адрес и порт.")
            return
        profile = ProxyProfile.from_dict(data)
        self.summary.set(f"{profile.protocol.upper()} • {profile.host}:{profile.port} • " +
                         ("с логином и сохранённым паролем" if profile.has_auth else "без авторизации"))

    def add_profile(self):
        ProfileDialog(self)

    def route_backups(self):
        name = self.profile.get()
        if not name:
            self.status.set("Сначала добавьте и выберите основной прокси.")
            return
        profiles = StateManager.list_profiles()
        primary = profiles.get(name, {})
        saved = StateManager.load_state().get("route_groups", {}).get(primary.get("profile_id"), [])
        dialog = tk.Toplevel(self.root)
        dialog.title("Резервные прокси")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Основной прокси: " + name, padding=12).pack(anchor="w")
        ttk.Label(dialog, text="Выберите до четырёх резервов. Выход сохраняется для сессии.\n"
                  "Переключение возможно до CONNECT; отказ сайта или пароля не обходится.\n"
                  "Добавьте серверы своих стран как обычные профили. Российский вход\n"
                  "включайте только при наличии настроенного маршрута через него.", padding=12).pack(anchor="w")
        choices = []
        for other, data in profiles.items():
            if other == name:
                continue
            selected = tk.BooleanVar(value=data.get("profile_id") in saved)
            ttk.Checkbutton(dialog, text=other, variable=selected).pack(anchor="w", padx=12, pady=3)
            choices.append((other, selected))
        def save():
            try:
                set_route_backups(name, [other for other, value in choices if value.get()])
                self.status.set("Резервные прокси сохранены. Уже открытые соединения продолжают работу.")
                dialog.destroy()
            except Exception as error:
                messagebox.showerror("Не удалось сохранить", describe_error(error), parent=dialog)
        ttk.Button(dialog, text="Сохранить", command=save).pack(padx=12, pady=12)

    def login_antigravity(self):
        from .core.oauth_browser import latest_login_url, find_browser, launch_login_browser
        dialog = tk.Toplevel(self.root)
        dialog.title("Вход Antigravity через выбранный прокси")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Нажмите вход в Antigravity. Вставьте полученную ссылку Google.\n"
                  "Свежая ссылка из журнала подставляется автоматически. Откроется\n"
                  "отдельный браузер через тот же прокси. Результат входа вернётся\n"
                  "в Antigravity через локальный адрес; если клиент запросит код, вставьте его.", padding=12).pack()
        url = tk.StringVar(value=latest_login_url() or "")
        editable_entry(dialog, textvariable=url, width=72, show="").pack(padx=12, fill="x")
        browser = find_browser()
        result = tk.StringVar(value="")
        ttk.Label(dialog, textvariable=result, wraplength=520).pack(padx=12, pady=6)
        def open_browser():
            nonlocal browser
            if not browser:
                browser = filedialog.askopenfilename(parent=dialog, title="Выберите Chrome, Edge, Brave или Яндекс Браузер",
                                                     filetypes=[("Приложения Windows", "*.exe")])
                if not browser:
                    return
            value = url.get()
            result.set("Проверяем профиль, туннель к Google и локальный адрес возврата…")
            button.configure(state="disabled")
            def work():
                try:
                    if self.session and any(r.get("id") == "antigravity" for r in getattr(self, "_manual_records", [])):
                        session = self.session
                    else:
                        with self.background.lock:
                            state = StateManager.load_state().get("background", {})
                            name = state.get("applications", {}).get("antigravity", {}).get("profile")
                            if not name:
                                raise UserInputError("Сначала запустите Antigravity или включите для неё постоянный режим.")
                            session = self.background._session(name, state["ports"][name])
                    launch_login_browser(session, value, browser)
                    self.events.put(("oauth_result", dialog, result, button, "Туннель к Google проверен, браузер открыт. Завершите вход; результат вернётся в Antigravity. Если клиент запросит код, вставьте его в приложение."))
                except Exception as error:
                    self.events.put(("oauth_result", dialog, result, button, describe_error(error)))
            threading.Thread(target=work, daemon=True, name="DevProxyOAuth").start()
        button = ttk.Button(dialog, text="Открыть вход через прокси", command=open_browser)
        button.pack(padx=12, pady=12)

    def edit_profile(self):
        if not self.profile.get():
            self.add_profile()
        else:
            ProfileDialog(self, self.profile.get())

    def delete_profile(self):
        name = self.profile.get()
        if name and messagebox.askyesno("Удалить прокси", f"Удалить профиль «{name}» и его сохранённый пароль?", parent=self.root):
            try:
                data = StateManager.get_profile(name) or {}
                StateManager.delete_profile(name)
                SecretStore.delete_password(data.get("secret_reference") or name)
                self.refresh_profiles()
                self.status.set("Прокси удалён.")
            except Exception as error:
                self.status.set(describe_error(error))

    def render_apps(self):
        self.table.delete(*self.table.get_children())
        self.rows.clear()
        for index, record in enumerate(self.records):
            if not isinstance(record, dict) or not isinstance(record.get("executable"), str):
                continue
            item = str(index)
            missing = not os.path.isfile(record["executable"])
            policies = self.background.policies() if self.background else {}
            status = "Файл не найден" if missing else ("Постоянный режим" if record["id"] in policies else "Готово к запуску")
            kind = "CLI" if record.get("id") in ("codex", "opencode", "claude", "git") else "Окно"
            self.table.insert("", "end", iid=item, values=("☑" if record.get("selected") else "☐", record.get("name", "Приложение"), kind, status, record["executable"]))
            self.rows[item] = record
        self.discovery_status.set(f"В списке: {len(self.rows)}. Поставьте галочки в столбце «Выбор».")

    def persist_apps(self, discovery=False):
        try:
            StateManager.save_applications(self.records, discovery, self.profile.get())
        except Exception as error:
            self.status.set(describe_error(error))

    def scan(self):
        if self.scan_worker and self.scan_worker.is_alive() or self.session:
            return
        self.find_button["state"] = "disabled"
        self.discovery_status.set("Ищем IDE, Codex, OpenCode и другие инструменты…")
        def work():
            try:
                self.events.put(("discovered", discover_applications()))
            except Exception as error:
                self.events.put(("discovery_error", describe_error(error)))
        self.scan_worker = threading.Thread(target=work, daemon=True)
        self.scan_worker.start()

    def browse(self):
        path = filedialog.askopenfilename(title="Выберите исполняемый файл приложения", filetypes=[("Приложения Windows", "*.exe")])
        if not path:
            return
        try:
            adapter = GenericApplicationAdapter(path)
            if any(canonical(record["executable"]) == canonical(path) and not record.get("arguments") for record in self.records):
                self.status.set("Это приложение уже есть в списке.")
                return
            self.records.append(dict(id="manual-" + uuid.uuid4().hex, name=adapter.display_name,
                                     executable=adapter.executable, arguments=[], electron=adapter.electron, selected=True, source="manual"))
            self.render_apps()
            self.persist_apps()
        except Exception as error:
            self.status.set(describe_error(error))

    def remove_app(self):
        if self.session or self.worker and self.worker.is_alive():
            return
        selected = self.table.selection()
        if selected:
            record = self.rows[selected[0]]
            self.records.remove(record)
            self.render_apps()
            self.persist_apps()

    def toggle_row(self, event):
        if self.table.identify_column(event.x) != "#1":
            return
        item = self.table.identify_row(event.y)
        self.toggle_item(item)

    def toggle_selected(self, _):
        selected = self.table.selection()
        if selected:
            self.toggle_item(selected[0])
        return "break"

    def toggle_item(self, item):
        if item in self.rows and not self.session and not (self.worker and self.worker.is_alive()):
            record = self.rows[item]
            record["selected"] = not record.get("selected")
            self.table.set(item, "use", "☑" if record["selected"] else "☐")
            self.persist_apps()

    def select_all(self, selected):
        if self.session or self.worker and self.worker.is_alive():
            return
        for item, record in self.rows.items():
            record["selected"] = bool(selected)
            self.table.set(item, "use", "☑" if selected else "☐")
        self.persist_apps()

    def set_controls(self, busy):
        self.start_button["state"] = "disabled" if busy else "normal"
        self.stop_button["state"] = "normal" if busy else "disabled"
        self.profile_combo["state"] = "disabled" if busy else "readonly"
        for button in self.profile_buttons + [self.add_app_button, self.remove_app_button]:
            button["state"] = "disabled" if busy else "normal"
        self.target_entry["state"] = "disabled" if busy else "normal"
        self.find_button["state"] = "disabled" if busy or self.scan_worker and self.scan_worker.is_alive() else "normal"

    def test_profile(self):
        if not self.profile.get():
            self.status.set("Сначала добавьте прокси.")
            return
        if self.worker and self.worker.is_alive() or self.session:
            return
        name, target = self.profile.get(), self.target.get()
        self.cancel.clear()
        self.set_controls(True)
        self.status.set("Проверяем подключение и авторизацию прокси…")
        def work():
            profile = None
            try:
                profile = resolve_profile(name)
                check_proxy(profile, target)
                self.events.put(("checked", f"Проверка пройдена: прокси открыл соединение к {target}:443. Можно запускать приложения."))
            except Exception as error:
                self.events.put(("checked", describe_error(error, target)))
            finally:
                if profile:
                    profile.password = None
                self.events.put(("worker_done",))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def start(self):
        if self.worker and self.worker.is_alive() or self.session:
            return
        selected = [dict(record) for record in self.records if record.get("selected")]
        if not self.profile.get():
            self.status.set("Сначала нажмите «Добавить» в блоке «Прокси».")
            return
        if not selected:
            self.status.set("Поставьте галочки напротив приложений, которые нужно запустить через прокси.")
            return
        if any(not os.path.isfile(record["executable"]) for record in selected):
            self.status.set("Среди выбранных есть отсутствующий EXE. Нажмите «Найти приложения» или уберите его галочку.")
            return
        name, target = self.profile.get(), self.target.get()
        self.cancel.clear()
        self.set_controls(True)
        self.status.set("Запускаем выбранные приложения с настройками прокси…")
        self.persist_apps()
        def work():
            session = None
            try:
                profile = resolve_profile(name)
                # Diagnostic destinations are optional: upstream allowlists may
                # permit the IDE's services while rejecting the check site.
                if self.cancel.is_set():
                    return
                session = ApplicationSession(profile, bind_port=0,
                                             profile_provider=SavedProfileProvider(name)).start()
                for record in selected:
                    if self.cancel.is_set():
                        break
                    adapter = get_adapter(record["id"])
                    flags = list(record.get("arguments", []))
                    if not flags and record.get("electron"):
                        flags = ["--proxy-server={PROXY_URL}"]
                    session.launch(record["executable"], flags, electron=bool(record.get("electron")),
                                   console=record["id"] in ("codex", "opencode", "claude", "git"),
                                   preserve_profile=record["id"] == "antigravity")
                if self.cancel.is_set():
                    session.stop()
                else:
                    self.events.put(("started", session, selected))
                    session = None
            except Exception as error:
                self.events.put(("error", describe_error(error, target), selected))
            finally:
                if session:
                    session.stop()
                self.events.put(("worker_done",))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def stop(self):
        self.cancel.set()
        session, self.session = self.session, None
        if session:
            self.status.set("Завершаем выбранные приложения и закрываем соединения…")
            def cleanup():
                try:
                    session.stop()
                finally:
                    self.events.put(("stopped",))
            self.worker = threading.Thread(target=cleanup, daemon=True)
            self.worker.start()

    def mark_apps(self, selected, status):
        ids = {record["id"] for record in selected}
        for item, record in self.rows.items():
            if record["id"] in ids:
                self.table.set(item, "status", status)

    def poll(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = event[0]
            if kind == "tray":
                action = event[1]
                if action == "show":
                    self.show()
                elif action == "exit":
                    self.shutdown()
                elif action == "disable":
                    self.disable_permanent(all_apps=True)
                elif action == "launch" and self.background:
                    try:
                        for app_id in self.background.policies():
                            self.background.launch(app_id)
                    except Exception as error:
                        self.show()
                        self.status.set(describe_error(error))
            elif kind == "agent_command":
                message, reply = event[1], event[2]
                try:
                    if message.get("command") == "show":
                        self.show()
                        result = {"ok": True}
                    elif message.get("command") == "exit":
                        self.shutdown()
                        result = {"ok": True}
                    elif message.get("command") == "status":
                        result = self.status_snapshot()
                    elif message.get("command") == "launch" and not self.persistent_busy:
                        arguments = message.get("arguments", [])
                        if not isinstance(arguments, list) or len(arguments) > 100 or any(not isinstance(a,str) or len(a)>4096 for a in arguments):
                            raise ValueError("Invalid launch arguments")
                        process = self.background.launch(message["app_id"], arguments)
                        result = {"ok": True, "pid": process.pid}
                    else:
                        raise ValueError("Unknown or busy background operation")
                except Exception as error:
                    result = {"ok": False, "error": describe_error(error)}
                reply.put(result)
            elif kind == "persistent_updated":
                self.persistent_busy = False
                self.enable_button["state"] = self.disable_button["state"] = "normal"
                self.status.set(event[1])
                self.render_apps()
            elif kind == "background_closed":
                self.background_closing = False
            elif kind == "oauth_result":
                dialog, result, button, text = event[1:]
                if dialog.winfo_exists():
                    result.set(text)
                    button.configure(state="normal")
            elif kind == "tray_error":
                self.show()
                self.status.set("Значок в трее недоступен. Окно оставлено открытым.")
            elif kind == "discovered":
                self.records = merge_applications(self.records, event[1])
                self.render_apps()
                self.persist_apps(discovery=True)
                names = ", ".join(r["name"] for r in event[1]) if event[1] else ""
                if event[1]:
                    self.discovery_status.set(f"Поиск завершён. Найдено установленных приложений ({len(event[1])}): {names}. Если вашей программы нет, добавьте её через «Добавить EXE…».")
                else:
                    self.discovery_status.set("Поиск завершён. Установленные IDE не найдены по стандартным путям. Вы можете добавить нужный .exe через «Добавить EXE…».")
                self.find_button["state"] = "normal" if not self.session else "disabled"
            elif kind == "discovery_error":
                self.discovery_status.set(event[1])
                self.find_button["state"] = "normal"
            elif kind == "dialog_test":
                dialog = event[1]
                if dialog.window.winfo_exists():
                    dialog.result.set(event[2])
                    dialog.test_button["state"] = dialog.save_button["state"] = "normal"
            elif kind == "checked":
                self.status.set(event[1])
            elif kind == "started":
                self.session = event[1]
                self._manual_records = event[2]
                if self.cancel.is_set():
                    self.stop()
                else:
                    self.mark_apps(event[2], "Запущено с прокси")
                    self.status.set("Выбранные приложения запущены с настройками прокси.")
            elif kind == "error":
                self.status.set(event[1])
                self.mark_apps(event[2], "Ошибка запуска")
            elif kind == "stopped":
                self.status.set("Остановлено. Приложения сессии завершены, исходные настройки сохранены.")
                self.render_apps()
            elif kind == "worker_done" and not self.session:
                self.set_controls(False)
                if self.cancel.is_set():
                    self.status.set("Остановлено.")
        if self.session:
            try:
                if self.session.tunnel.last_error:
                    self.status.set(self.session.tunnel.last_error)
                if not self.session.active():
                    self.stop()
            except OSError:
                self.stop()
        self.report_background_failure()
        busy = self.worker and self.worker.is_alive()
        if not busy and not self.session:
            self.set_controls(False)
        if self.closing and not busy and not self.session and not self.background_closing:
            self.root.destroy()
            return
        self.root.after(100, self.poll)

    def report_background_failure(self):
        """Surface a persistent-tunnel failure without blocking the window.

        The manager keeps a non-blocking cache, so this never waits on the lock
        that enable/disable holds during file work. A problem is announced once
        per distinct message so it cannot keep overwriting the result of the
        user's own action; a healthy status clears it again.
        """
        if not self.background or self.persistent_busy or self.worker and self.worker.is_alive():
            return
        now = time.monotonic()
        if now - self._snapshot_at >= 1.0 and not self._status_refresh_pending.is_set():
            self._snapshot_at = now
            self._status_refresh_pending.set()
            def refresh():
                try:
                    self.background.refresh()
                finally:
                    self._status_refresh_pending.clear()
            threading.Thread(target=refresh, daemon=True,
                             name="DevProxyStatus").start()
        try:
            error = self.background.snapshot().get("error")
        except Exception:
            return
        if not error:
            self._background_error = None
            return
        message = "Фоновый прокси: " + error
        if self._background_error == error or self.status.get() == message:
            return
        self._background_error = error
        if not self.session:
            self.status.set(message)

    def status_snapshot(self):
        """IPC status. Reads only cached state, so it cannot stall on file work."""
        snapshot = self.background.snapshot() if self.background else {}
        sessions = list(snapshot.get("sessions", []))
        ports = dict(snapshot.get("ports", {}))
        applications = list(snapshot.get("applications", []))
        error = snapshot.get("error")
        if self.session:
            sessions.append(dict(self.session.tunnel.diagnostics(), mode="manual"))
        failures = [entry for session in sessions for entry in session.get("failures", [])]
        if failures:
            error = max(failures, key=lambda entry: entry.get("time", 0))["message"]
        # Messages are produced by describe_error and never embed credentials.
        return {"ok": True, "applications": applications, "ports": ports,
                "error": error, "sessions": sessions, "version": __version__}

    def show(self):
        self.root.deiconify()
        self.root.state("normal")
        self.root.lift()
        self.root.focus_force()

    def hide(self):
        if self.tray and self.tray.available:
            self.persist_apps()
            self.root.withdraw()
        else:
            self.status.set("Значок в трее пока недоступен; окно остаётся открытым.")

    def on_unmap(self, event):
        if event.widget is self.root and self.root.state() == "iconic" and self.tray and self.tray.available:
            self.root.after_idle(self.hide)

    def enable_permanent(self):
        records = [dict(r) for r in self.records if r.get("selected")]
        name = self.profile.get()
        if not records or not name:
            self.status.set("Выберите прокси и отметьте приложения для постоянного запуска.")
            return
        self.permanent_work(lambda: self.background.enable(records, name),
                            "Постоянный режим включён. Запускайте приложения обычными ярлыками; DevProxy можно закрыть в трей. Автозапуск при входе в Windows включён.")

    def disable_permanent(self, all_apps=False):
        ids = None if all_apps else [r["id"] for r in self.records if r.get("selected")]
        if ids == []:
            self.status.set("Отметьте приложения, для которых нужно вернуть обычный запуск.")
            return
        self.permanent_work(lambda: self.background.disable(ids), "Обычные ярлыки восстановлены. Перезапустите выбранные приложения для обычного запуска.")

    def permanent_work(self, operation, success):
        if not self.background or self.persistent_busy:
            return
        self.persistent_busy = True
        self.enable_button["state"] = self.disable_button["state"] = "disabled"
        self.status.set("Обновляем постоянный режим и ярлыки…")
        def work():
            try:
                operation()
                result = success
            except Exception as error:
                result = describe_error(error)
            self.events.put(("persistent_updated", result))
        threading.Thread(target=work, daemon=True, name="DevProxyPolicy").start()

    def close(self):
        if self.tray and self.tray.available:
            self.hide()
        else:
            self.shutdown()

    def shutdown(self):
        if self.closing:
            return
        self.closing = True
        self.persist_apps()
        self.stop()
        if self.background:
            self.background_closing = True
            def cleanup():
                try:
                    self.background.close()
                finally:
                    self.events.put(("background_closed",))
            threading.Thread(target=cleanup, daemon=True).start()


def main(*, auto_discover=True, smoke=False, background=False):
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    from .core.background import BackgroundManager
    from .core.recovery import get_devproxy_state_path
    instance = tray = server = None
    manager = BackgroundManager()
    if sys.platform == "win32" and not smoke:
        from .windows_tray import SingleInstance
        instance = SingleInstance(get_devproxy_state_path())
        if not instance.acquired:
            try:
                from .core.agent_ipc import request
                request({"command": "show"}, timeout=5)
            except Exception:
                pass
            finally:
                instance.close()
            return
    root = tk.Tk()
    if smoke or background:
        root.withdraw()
    window = DevProxyWindow(root, auto_discover=auto_discover, background=manager)
    try:
        if sys.platform == "win32" and not smoke:
            from .windows_tray import WindowsTray
            from .core.agent_ipc import AgentServer
            tray = WindowsTray(root, window.events)
            window.tray = tray
            def dispatch(message):
                reply = queue.Queue()
                window.events.put(("agent_command", message, reply))
                try:
                    return reply.get(timeout=15)
                except queue.Empty:
                    return {"ok": False, "error": "Фоновый агент занят; повторите запуск."}
            server = AgentServer(dispatch)
            def resume():
                manager.resume()
                if manager.last_error:
                    window.events.put(("persistent_updated", manager.last_error))
            threading.Thread(target=resume, daemon=True).start()
            if background:
                root.after_idle(window.hide if tray.available else window.show)
        if smoke:
            root.after_idle(root.destroy)
        root.mainloop()
    finally:
        # Tk timers outlive their Python commands when a test destroys a root directly.
        for timer in root.tk.call("after", "info"):
            root.after_cancel(timer)
        if server:
            server.close()
        if tray:
            tray.close()
        manager.close()
        if instance:
            instance.close()


def smoke_test():
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        previous = os.environ.get("DEVPROXY_STATE_DIR")
        os.environ["DEVPROXY_STATE_DIR"] = directory
        try:
            main(auto_discover=False, smoke=True)
        finally:
            if previous is None:
                os.environ.pop("DEVPROXY_STATE_DIR", None)
            else:
                os.environ["DEVPROXY_STATE_DIR"] = previous
