"""Discovery, Russian workflows, credential-preserving edits and safe diagnostics."""
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
import tkinter as tk
import unittest
from unittest import mock

from devproxy_pkg.adapters import get_adapter, list_adapters
from devproxy_pkg.discovery import discover_applications, entry_paths, merge_applications, npm_candidate
from devproxy_pkg.core.profiles import persist_profile, profile_from_fields
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.secrets import SecretStore
from devproxy_pkg.core.transport import ProxyError, connect_upstream, read_headers
from devproxy_pkg.core.user_errors import UserInputError, describe_error
from devproxy_pkg.ui import DevProxyWindow, ProfileDialog, check_proxy, smoke_test


class IsolatedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        patch = mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=str(self.directory))
        patch.start()
        self.addCleanup(patch.stop)

    def fake_secrets(self):
        values = {}
        def store(name, username, password, require_persistent=False):
            values[name] = password
            return "os_keychain"
        patches = [
            mock.patch.object(SecretStore, "get_password", side_effect=lambda name: values.get(name)),
            mock.patch.object(SecretStore, "store_password", side_effect=store),
            mock.patch.object(SecretStore, "delete_password", side_effect=lambda name: values.pop(name, None)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return values


class ProfileEditingTests(IsolatedTests):
    def test_edit_host_preserves_hidden_password(self):
        secrets = self.fake_secrets()
        persist_profile(ProxyProfile("Рабочий", "http", "localhost", 8080, "alice", "keep-me"))
        profile = profile_from_fields("Рабочий", "http", "proxy.example", "3128", "alice", None, True)
        persist_profile(profile, "Рабочий", keep_password=True)
        self.assertEqual(StateManager.get_profile("Рабочий")["host"], "proxy.example")
        self.assertEqual(secrets["Рабочий"], "keep-me")
        self.assertIsNone(profile.password)
        self.assertNotIn("keep-me", (self.directory / "state.json").read_text(encoding="utf-8"))

    def test_rename_moves_credentials_without_duplicate_profile(self):
        secrets = self.fake_secrets()
        persist_profile(ProxyProfile("Старый", "socks5", "localhost", 1080, "user", "password"))
        profile = profile_from_fields("Новый", "socks5", "localhost", "1080", "user", None, True)
        persist_profile(profile, "Старый", keep_password=True)
        self.assertIsNone(StateManager.get_profile("Старый"))
        self.assertEqual(StateManager.get_profile("Новый")["secret_reference"], "Новый")
        self.assertEqual(secrets, {"Новый": "password"})

    def test_new_password_replaces_old(self):
        secrets = self.fake_secrets()
        persist_profile(ProxyProfile("x", "http", "localhost", 80, "user", "old"))
        profile = ProxyProfile("x", "http", "localhost", 80, "user", "new")
        persist_profile(profile, "x")
        self.assertEqual(secrets["x"], "new")
        self.assertIsNone(profile.password)

    def test_disabling_auth_removes_secret_after_metadata_saved(self):
        secrets = self.fake_secrets()
        persist_profile(ProxyProfile("x", "http", "localhost", 80, "user", "old"))
        persist_profile(ProxyProfile("x", "http", "localhost", 80), "x")
        self.assertEqual(secrets, {})
        self.assertIsNone(StateManager.get_profile("x")["secret_reference"])

    def test_edit_save_failure_restores_previous_secret_and_metadata(self):
        secrets = self.fake_secrets()
        persist_profile(ProxyProfile("x", "http", "localhost", 80, "user", "old"))
        profile = ProxyProfile("x", "http", "other", 81, "user", "new")
        with mock.patch.object(StateManager, "save_state", side_effect=OSError):
            with self.assertRaises(OSError):
                persist_profile(profile, "x")
        self.assertEqual(secrets["x"], "old")
        self.assertEqual(StateManager.get_profile("x")["host"], "localhost")

    def test_duplicate_new_profile_does_not_overwrite(self):
        self.fake_secrets()
        persist_profile(ProxyProfile("x", "http", "localhost", 80))
        with self.assertRaises(UserInputError):
            persist_profile(ProxyProfile("x", "http", "other", 81))
        self.assertEqual(StateManager.get_profile("x")["host"], "localhost")

    def test_specific_port_and_host_errors(self):
        for port in ("abc", "0", "65536"):
            with self.assertRaises(UserInputError) as error:
                profile_from_fields("Профиль", "http", "localhost", port)
            self.assertIn("Порт", str(error.exception))
        with self.assertRaises(UserInputError) as error:
            profile_from_fields("Профиль", "http", "http://host:80", "80")
        self.assertIn("Вставить ссылку", str(error.exception))


class DiscoveryTests(IsolatedTests):
    def fixture(self, relative):
        path = self.directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"installed fixture")
        return path

    def test_popular_catalog_contains_requested_tools(self):
        ids = {adapter.app_id for adapter in list_adapters()}
        self.assertTrue({"codex", "codex-gui", "opencode", "claude", "vscode", "vscode-insiders",
                         "cursor", "windsurf", "antigravity", "vscodium", "visualstudio",
                         "idea", "pycharm", "rider", "webstorm", "goland", "clion",
                         "androidstudio", "zed", "sublime"}.issubset(ids))

    def test_registry_install_location_nonstandard_disk(self):
        executable = self.fixture("custom/PyCharm/bin/pycharm64.exe")
        entry = dict(name="PyCharm Professional", path="", location=str(executable.parent.parent), source="registry")
        paths = entry_paths(entry, get_adapter("pycharm"))
        self.assertIn(str(executable), paths)

    def test_codex_cli_worker_not_classified_as_desktop(self):
        path = self.fixture("OpenAI/Codex/bin/version/codex.exe")
        entry = dict(name="Codex", path=str(path), location="", source="shortcut")
        self.assertEqual(entry_paths(entry, get_adapter("codex-gui")), [])
        self.assertIn(str(path), entry_paths(entry, get_adapter("codex")))

    def test_codex_desktop_not_classified_as_cli(self):
        path = self.fixture("Desktop/app/Codex.exe")
        entry = dict(name="Codex", path=str(path), location="", source="shortcut")
        self.assertEqual(entry_paths(entry, get_adapter("codex")), [])
        self.assertIn(str(path), entry_paths(entry, get_adapter("codex-gui")))

    def test_msix_manifest_resolves_desktop_executable(self):
        path = self.fixture("WindowsApps/OpenAI.Codex/custom/Codex.exe")
        manifest = path.parent.parent / "AppxManifest.xml"
        manifest.write_text('<Package><Applications><Application Executable="custom/Codex.exe"/></Applications></Package>', encoding="utf-8")
        entry = dict(name="OpenAI.Codex", path="", location=str(path.parent.parent), source="package")
        self.assertIn(str(path), entry_paths(entry, get_adapter("codex-gui")))

    def test_opencode_npm_native_binary(self):
        path = self.fixture("roaming/npm/node_modules/opencode-ai/node_modules/opencode-windows-x64/bin/opencode.exe")
        with mock.patch.dict(os.environ, APPDATA=str(self.directory / "roaming"), PATH=""):
            self.assertEqual(npm_candidate(get_adapter("opencode")), (str(path), []))

    def test_claude_npm_uses_node_exe_instead_of_cmd(self):
        script = self.fixture("roaming/npm/node_modules/@anthropic-ai/claude-code/cli.js")
        (script.parent / "package.json").write_text('{"bin":{"claude":"cli.js"}}', encoding="utf-8")
        node = self.fixture("node/node.exe")
        with mock.patch.dict(os.environ, APPDATA=str(self.directory / "roaming"), PATH=""), mock.patch("shutil.which", return_value=str(node)):
            self.assertEqual(npm_candidate(get_adapter("claude")), (str(node), [str(script)]))

    def test_toolbox_versioned_ide_and_codex_version_subfolder(self):
        idea = self.fixture("local/JetBrains/Toolbox/apps/IDEA-U/ch-0/2025.1/bin/idea64.exe")
        codex = self.fixture("local/OpenAI/Codex/bin/version/codex.exe")
        with mock.patch.dict(os.environ, LOCALAPPDATA=str(self.directory / "local"),
                             ProgramFiles=str(self.directory / "empty"), APPDATA=str(self.directory / "roaming"), PATH=""), mock.patch("shutil.which", return_value=None):
            records = {record["id"]: record for record in discover_applications(entries=[])}
        self.assertEqual(records["idea"]["executable"], str(idea))
        self.assertEqual(records["codex"]["executable"], str(codex))

    def test_merge_preserves_manual_apps_and_selection_updates_path(self):
        saved = [dict(id="vscode", executable="old.exe", selected=True, source="auto"),
                 dict(id="manual-1", executable="custom.exe", selected=True, source="manual")]
        found = [dict(id="vscode", executable="updated.exe", selected=False, source="auto"),
                 dict(id="opencode", executable="opencode.exe", selected=False, source="auto")]
        result = merge_applications(saved, found)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["executable"], "updated.exe")
        self.assertTrue(result[0]["selected"])
        self.assertEqual(result[1], saved[1])
        self.assertFalse(result[2]["selected"])

    def test_persisted_discovery_does_not_erase_profiles(self):
        StateManager.save_profile(ProxyProfile("Прокси", "http", "localhost", 80).to_dict())
        records = [dict(id="codex", name="Codex CLI", executable="codex.exe", source="auto", selected=True)]
        StateManager.save_applications(records, True)
        self.assertEqual(StateManager.list_applications(), records)
        self.assertTrue(StateManager.load_state()["discovery_completed"])
        self.assertIsNotNone(StateManager.get_profile("Прокси"))


class DiagnosticTests(unittest.TestCase):
    def test_auth_error_is_specific_russian_and_redacted(self):
        message = describe_error(ProxyError("password=never-display", "auth_failed", 407))
        self.assertIn("логин или пароль", message)
        self.assertNotIn("never-display", message)

    def test_blocked_destination_identifies_status_and_site(self):
        message = describe_error(ProxyError("raw secret", "http_rejected", 403), "test.example")
        self.assertIn("403", message)
        self.assertIn("test.example", message)
        self.assertNotIn("raw secret", message)

    def test_network_failure_messages_distinguish_causes(self):
        errors = [ConnectionRefusedError(), socket.gaierror(), TimeoutError(), ssl.SSLError(), ConnectionResetError()]
        messages = [describe_error(error) for error in errors]
        self.assertEqual(len(set(messages)), len(errors))
        self.assertTrue(all("прокси" in message.lower() for message in messages))

    def test_unknown_errors_never_echo_secret(self):
        for error in (RuntimeError("user:secret@server"), ValueError("user:secret@server"), OSError("user:secret@server")):
            self.assertNotIn("secret", describe_error(error))

    def test_check_destination_validation_precedes_network(self):
        with mock.patch("devproxy_pkg.ui.connect_upstream") as connect:
            for target in ("https://github.com", "user:secret@host", "github.com:443"):
                with self.assertRaises(UserInputError):
                    check_proxy(ProxyProfile("x", "http", "localhost", 80), target)
            connect.assert_not_called()

    def test_structured_stage_cause_action_formatting(self):
        msg = describe_error(ProxyError("failed", "auth_failed", 407))
        self.assertIn("Этап:", msg)
        self.assertIn("Причина:", msg)
        self.assertIn("Что делать:", msg)
        self.assertIn("HTTP 407", msg)

    def test_socks_auth_and_method_diagnostics(self):
        msg_auth = describe_error(ProxyError("secret", "auth_failed"))
        self.assertIn("Этап: авторизация", msg_auth)
        self.assertIn("логин или пароль", msg_auth)
        self.assertIn("Что делать:", msg_auth)

        msg_method = describe_error(ProxyError("secret", "auth_method"))
        self.assertIn("Этап:", msg_method)
        self.assertIn("SOCKS5", msg_method)
        self.assertIn("Что делать:", msg_method)

    def test_wrong_proxy_type_and_destination_rejected(self):
        msg_proto = describe_error(ProxyError("mismatch", "protocol_error"))
        self.assertIn("Этап:", msg_proto)
        self.assertIn("протокол", msg_proto.lower())
        self.assertIn("HTTP/SOCKS5", msg_proto)

        msg_dest = describe_error(ProxyError("dest fail", "destination_rejected"), "api.openai.com")
        self.assertIn("api.openai.com", msg_dest)
        self.assertIn("SOCKS5", msg_dest)

    def test_network_causes_have_actionable_instructions(self):
        for exc in (ConnectionRefusedError(), socket.gaierror(), TimeoutError()):
            msg = describe_error(exc)
            self.assertIn("Этап:", msg)
            self.assertIn("Причина:", msg)
            self.assertIn("Что делать:", msg)

    def test_secrets_and_auth_headers_never_leaked(self):
        leaks = [
            "password123",
            "Basic dXNlcjpwYXNzd29yZDEyMw==",
            "socks5://user:secret@127.0.0.1:1080",
            "Proxy-Authorization: Basic test",
        ]
        for leak in leaks:
            err = ProxyError(f"Critical leak: {leak}", "auth_failed", 407)
            msg = describe_error(err)
            self.assertNotIn(leak, msg)
            raw_err = RuntimeError(f"Raw crash: {leak}")
            self.assertNotIn(leak, describe_error(raw_err))


class RussianUiTests(IsolatedTests):
    def window(self, auto_discover=False):
        root = tk.Tk()
        root.withdraw()
        def cleanup():
            for timer in root.tk.call("after", "info"):
                root.after_cancel(timer)
            root.destroy()
        self.addCleanup(cleanup)
        window = DevProxyWindow(root, auto_discover=auto_discover)
        root.update()
        return root, window

    def test_main_entrypoint_initializes_and_exits(self):
        with mock.patch('devproxy_pkg.ui.discover_applications') as scan:
            smoke_test()
        scan.assert_not_called()

    def test_all_profile_fields_and_url_dialog_support_paste(self):
        root, window = self.window()
        try:
            previous = root.clipboard_get()
        except tk.TclError:
            previous = None
        dialog = ProfileDialog(window)
        def entries(widget):
            result = []
            for child in widget.winfo_children():
                if child.winfo_class() == "TEntry":
                    result.append(child)
                result.extend(entries(child))
            return result
        try:
            dialog.auth.set(True)
            dialog.toggle_auth()
            root.clipboard_clear()
            root.clipboard_append("pasted")
            fields = entries(dialog.window) + [window.target_entry]
            self.assertEqual(len(fields), 7)
            for entry in fields:
                entry.selection_range(0, "end")
                entry.edit_menu.invoke(2)
                self.assertEqual(entry.get(), "pasted")
            dialog.paste_url()
            url_window = next(child for child in dialog.window.winfo_children()
                              if isinstance(child, tk.Toplevel))
            url_entry = entries(url_window)[0]
            root.clipboard_clear()
            root.clipboard_append("socks5://localhost:1080")
            url_entry.edit_menu.invoke(2)
            self.assertEqual(url_entry.get(), "socks5://localhost:1080")
            self.assertEqual(url_entry.cget("show"), "•")
            for child in url_window.winfo_children():
                if child.winfo_class() == "TButton":
                    child.invoke()
                    break
            self.assertEqual(dialog.host.get(), "localhost")
            self.assertEqual(dialog.port.get(), "1080")
        finally:
            dialog.close()
            root.clipboard_clear()
            if previous is not None:
                root.clipboard_append(previous)
            root.update()

    def test_close_hides_in_tray_without_stopping_proxy(self):
        root, window = self.window()
        window.tray = mock.Mock(available=True)
        window.background = mock.Mock()
        window.session = mock.Mock()
        window.close()
        self.assertFalse(window.closing)
        self.assertEqual(root.state(), "withdrawn")
        window.session.stop.assert_not_called()
        window.background.close.assert_not_called()
        window.show()
        self.assertEqual(root.state(), "normal")
        window.session = None

    def test_start_works_when_proxy_allows_app_but_blocks_check_site(self):
        from test_regressions import FakeProxy

        class AllowlistProxy(FakeProxy):
            def handle(self, sock):
                with sock:
                    sock.settimeout(3)
                    headers, _ = read_headers(sock)
                    self.requests.append(headers)
                    if headers.startswith(b"GET http://allowed.invalid/"):
                        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied")
                    else:
                        sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        root, window = self.window()
        output = self.directory / "child-result.txt"
        code = "import urllib.request,sys;open(sys.argv[1],'wb').write(urllib.request.urlopen('http://allowed.invalid/',timeout=5).read())"
        window.records = [dict(id="codex", name="test child", executable=sys.executable,
                               arguments=["-c", code, str(output)], electron=False, selected=True)]
        window.profile.set("fixture")
        window.target.set("github.com")
        with AllowlistProxy() as proxy:
            # The default diagnostic really is forbidden by the upstream ACL.
            with self.assertRaises(ProxyError) as rejected:
                check_proxy(proxy.profile(authenticated=False), "github.com")
            self.assertEqual(rejected.exception.status, 403)
            proxy.requests.clear()
            with mock.patch("devproxy_pkg.ui.resolve_profile", return_value=proxy.profile(authenticated=False)):
                window.start()
                window.worker.join(10)
            self.assertFalse(window.worker.is_alive())
            events = []
            while not window.events.empty():
                events.append(window.events.get_nowait())
            started = next((event for event in events if event[0] == "started"), None)
            self.assertIsNotNone(started, str(events))
            session = started[1]
            try:
                self.assertEqual(session.processes[0].wait(timeout=10), 0)
                self.assertEqual(output.read_bytes(), b"proxied")
                self.assertEqual(len(proxy.requests), 1)
                self.assertIn(b"http://allowed.invalid/", proxy.requests[0])
                self.assertNotIn(b"github.com", proxy.requests[0])
            finally:
                session.stop()

    def test_main_controls_are_russian(self):
        root, window = self.window()
        self.assertEqual(window.start_button["text"], "Запустить выбранные")
        self.assertEqual(window.stop_button["text"], "Остановить")
        self.assertEqual([button["text"] for button in window.profile_buttons], ["Добавить", "Изменить", "Удалить", "Проверить"])
        self.assertIn("Прокси", window.summary.get())

    def test_start_and_status_visible_at_minimum_window_size(self):
        root, window = self.window()
        root.geometry("860x650+30000+30000")
        root.deiconify()
        root.update()
        self.assertTrue(window.start_button.winfo_ismapped())
        self.assertTrue(window.status_label.winfo_ismapped())
        bottom = window.status_label.winfo_rooty() - root.winfo_rooty() + window.status_label.winfo_height()
        self.assertLessEqual(bottom, root.winfo_height())

    def test_edit_dialog_does_not_read_back_password(self):
        self.fake_secrets()
        persist_profile(ProxyProfile("Профиль", "http", "localhost", 80, "user", "hidden"))
        root, window = self.window()
        with mock.patch.object(SecretStore, "get_password", side_effect=AssertionError("UI must not fetch passwords")):
            dialog = ProfileDialog(window, "Профиль")
            root.update()
            self.assertEqual(dialog.password.get(), "")
            profile, keep = dialog.fields()
            self.assertTrue(keep)
            self.assertEqual(profile.host, "localhost")
            dialog.close()

    def test_auto_first_launch_adds_and_persists_found_apps(self):
        path = self.directory / "codex.exe"
        path.write_bytes(b"fixture")
        record = dict(id="codex", name="Codex CLI", executable=str(path), arguments=[], electron=False, selected=False, source="auto")
        with mock.patch("devproxy_pkg.ui.discover_applications", return_value=[record]) as scan:
            root, window = self.window(auto_discover=True)
            deadline = time.monotonic() + 3
            while not StateManager.load_state().get("discovery_completed") and time.monotonic() < deadline:
                root.update()
                time.sleep(0.02)
            self.assertTrue(StateManager.load_state()["discovery_completed"])
            self.assertEqual(window.records[0]["id"], "codex")
            self.assertFalse(window.records[0]["selected"])
            self.assertEqual(scan.call_count, 1)
            window.toggle_item("0")
            self.assertTrue(StateManager.list_applications()[0]["selected"])


if __name__ == "__main__":
    unittest.main()
