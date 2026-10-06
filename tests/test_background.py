"""Persistent policy recovery, native IPC, and Electron's internal loopback UI."""
import copy
import http.server
import json
import os
from pathlib import Path
import queue
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from unittest import mock

from devproxy_pkg.core.background import BackgroundManager
from devproxy_pkg.core.launcher import ApplicationSession, Launcher
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.shortcuts import broker_shortcut, split_arguments
from test_regressions import FakeProxy


class LoopbackCompatibilityTests(unittest.TestCase):
    def test_selected_child_reaches_local_ui_without_upstream_proxy(self):
        class UI(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"local-antigravity-ui")
            def log_message(self, *_):
                pass
        origin = http.server.HTTPServer(("127.0.0.1", 0), UI)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        try:
            with FakeProxy() as proxy, ApplicationSession(proxy.profile()) as session:
                # stdout goes to a file to avoid affecting the release command's output.
                with tempfile.TemporaryDirectory() as directory:
                    result = str(Path(directory) / "ui.txt")
                    code = "import urllib.request,sys;open(sys.argv[2],'wb').write(urllib.request.urlopen(sys.argv[1],timeout=3).read())"
                    child = session.launch(sys.executable, extra_args=["-c", code, f"http://127.0.0.1:{origin.server_port}/", result])
                    self.assertEqual(child.wait(timeout=10), 0)
                    self.assertEqual(Path(result).read_bytes(), b"local-antigravity-ui")
                    self.assertEqual(proxy.requests, [])
        finally:
            origin.shutdown()
            origin.server_close()
            thread.join(2)

    def test_electron_preserves_profile_and_loopback_bypass(self):
        with ApplicationSession(ProxyProfile("x", "http", "localhost", 80)) as session:
            session._job = mock.Mock()
            process = mock.Mock()
            process.poll.return_value = 0
            with mock.patch.object(Launcher, "launch", return_value=process) as launch:
                session.launch("fixture.exe", flags=["--proxy-server={PROXY_URL}"], electron=True, preserve_profile=True)
            flags, environment = launch.call_args.args[1:3]
            self.assertFalse(any(flag.startswith("--user-data-dir") for flag in flags))
            self.assertNotIn("--proxy-bypass-list=<-loopback>", flags)
            self.assertIn("--proxy-bypass-list=localhost;127.0.0.1;[::1]", flags)
            self.assertEqual(environment["NO_PROXY"], "localhost,127.0.0.1,::1")
            self.assertEqual(environment["NODE_TLS_REJECT_UNAUTHORIZED"], "1")
            self.assertEqual(session._directories, [])


class PersistentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        patch = mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=str(self.directory))
        patch.start()
        self.addCleanup(patch.stop)
        self.exe = self.directory / "Antigravity.exe"
        self.exe.write_bytes(b"fixture")
        self.record = dict(id="antigravity", name="Antigravity", executable=str(self.exe), arguments=[], electron=True)
        self.original = dict(path=str(self.directory / "Antigravity.lnk"), target=str(self.exe), arguments='"C:\\project with spaces"', icon=str(self.exe) + ",0", directory=str(self.directory))
        self.links = {self.original["path"]: copy.deepcopy(self.original)}
        self.startup = {"value": "previous-owner", "kind": 1}
        self.startup_baseline = copy.deepcopy(self.startup)
        for name in ("profile-one", "profile-two"):
            StateManager.save_profile(ProxyProfile(name, "http", "localhost", 80).to_dict())
        self.manager = BackgroundManager()
        self.addCleanup(self.manager.close)
        self.session = mock.Mock()
        self.session.tunnel.allocated_port = 18787
        self.mock_patch("devproxy_pkg.core.background.inspect_shortcuts", side_effect=lambda exe: [copy.deepcopy(v) for v in self.links.values() if v["target"] == exe])
        self.mock_patch("devproxy_pkg.core.background.write_shortcut", side_effect=self.write_link)
        self.mock_patch("devproxy_pkg.core.background.LoginStartup.read", side_effect=lambda: copy.deepcopy(self.startup))
        self.mock_patch("devproxy_pkg.core.background.LoginStartup.expected", return_value={"value": "devproxy-gui.exe --background", "kind": 1})
        self.mock_patch("devproxy_pkg.core.background.LoginStartup.write", side_effect=self.write_startup)
        self.mock_patch("devproxy_pkg.core.background.broker_shortcut", side_effect=lambda original, app_id: dict(original, target="devproxy-gui.exe", arguments="--launch-app " + app_id))
        self.mock_patch("devproxy_pkg.core.background.BackgroundManager._session", return_value=self.session)

    def mock_patch(self, *args, **kwargs):
        patch = mock.patch(*args, **kwargs)
        result = patch.start()
        self.addCleanup(patch.stop)
        return result

    def write_link(self, path, expected, value):
        if self.links.get(path) != expected:
            raise RuntimeError("Conflict")
        if value is None:
            self.links.pop(path, None)
        else:
            self.links[path] = copy.deepcopy(value)

    def write_startup(self, expected, value):
        if self.startup != expected:
            raise RuntimeError("Startup conflict")
        self.startup = copy.deepcopy(value)

    def test_enable_persists_ledger_before_shortcut_write(self):
        original_write = self.write_link
        def check_journal(path, expected, value):
            ledger = StateManager.load_state()["background"]["shortcuts"]
            self.assertEqual(ledger[path]["original"], self.original)
            original_write(path, expected, value)
        with mock.patch("devproxy_pkg.core.background.write_shortcut", side_effect=check_journal):
            self.manager.enable([self.record], "profile-one")
        background = StateManager.load_state()["background"]
        self.assertEqual(background["applications"]["antigravity"]["profile"], "profile-one")
        self.assertEqual(background["ports"]["profile-one"], 18787)
        self.assertEqual(self.links[self.original["path"]]["target"], "devproxy-gui.exe")

    def test_disable_restores_exact_shortcut_and_previous_autostart(self):
        self.manager.enable([self.record], "profile-one")
        self.manager.disable()
        self.assertEqual(self.links[self.original["path"]], self.original)
        self.assertEqual(self.startup, self.startup_baseline)
        self.assertEqual(self.manager.policies(), {})

    def test_profile_change_keeps_original_shortcut_baseline(self):
        self.manager.enable([self.record], "profile-one")
        self.manager.enable([self.record], "profile-two")
        item = StateManager.load_state()["background"]["shortcuts"][self.original["path"]]
        self.assertEqual(item["original"], self.original)
        self.assertEqual(self.manager.policies()["antigravity"]["profile"], "profile-two")
        self.manager.disable()
        self.assertEqual(self.links[self.original["path"]], self.original)

    def test_external_shortcut_change_is_preserved_with_recovery_record(self):
        self.manager.enable([self.record], "profile-one")
        self.links[self.original["path"]]["arguments"] = "user-edited"
        with self.assertRaises(RuntimeError):
            self.manager.disable()
        self.assertEqual(self.links[self.original["path"]]["arguments"], "user-edited")
        self.assertIn(self.original["path"], StateManager.load_state()["background"]["shortcuts"])
        self.assertIn("antigravity", self.manager.policies())

    def test_startup_failure_rolls_back_shortcut_and_state(self):
        previous = StateManager.load_state()
        with mock.patch("devproxy_pkg.core.background.LoginStartup.write", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                self.manager.enable([self.record], "profile-one")
        self.assertEqual(self.links[self.original["path"]], self.original)
        self.assertEqual(StateManager.load_state(), previous)

    def test_launch_uses_approved_exe_preserved_profile_and_arguments(self):
        self.manager.enable([self.record], "profile-one")
        self.manager.launch("antigravity", ["C:\\project with spaces"])
        args = self.session.launch.call_args
        self.assertEqual(args.args[0], str(self.exe))
        self.assertTrue(args.kwargs["preserve_profile"])
        self.assertEqual(args.kwargs["extra_args"], ["C:\\project with spaces"])
        with self.assertRaises(ValueError):
            self.manager.launch("unregistered-app")

    def test_resume_keeps_saved_port(self):
        self.manager.enable([self.record], "profile-one")
        with mock.patch.object(self.manager, "_session", return_value=self.session) as start:
            self.assertEqual(self.manager.resume(), [])
        start.assert_called_once_with("profile-one", 18787)


@unittest.skipUnless(os.name == "nt", "Windows IPC and shortcut arguments")
class NativeBackgroundTests(unittest.TestCase):
    def test_shortcut_preserves_quoted_workspace_arguments(self):
        original = dict(path="fixture.lnk", target="Antigravity.exe", arguments='"C:\\project with spaces" --new-window', icon="Antigravity.exe,0", directory="C:\\")
        with mock.patch("devproxy_pkg.core.shortcuts.app_command", return_value=[r"C:\program with spaces\devproxy-gui.exe"]):
            applied = broker_shortcut(original, "antigravity")
        self.assertEqual(split_arguments(applied["arguments"]), ["--launch-app", "antigravity", "--", r"C:\project with spaces", "--new-window"])
        self.assertEqual(applied["icon"], original["icon"])
        self.assertEqual(applied["directory"], original["directory"])

    def test_single_instance_releases_mutex(self):
        from devproxy_pkg.windows_tray import SingleInstance
        identity = str(Path(tempfile.gettempdir()) / uuid.uuid4().hex)
        first = SingleInstance(identity)
        second = SingleInstance(identity)
        try:
            self.assertTrue(first.acquired)
            self.assertFalse(second.acquired)
        finally:
            second.close()
            first.close()
        third = SingleInstance(identity)
        try:
            self.assertTrue(third.acquired)
        finally:
            third.close()

    def test_native_authenticated_pipe_roundtrip_and_cleanup(self):
        from devproxy_pkg.core.agent_ipc import AgentServer, request, auth_key
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=directory):
            server = AgentServer(lambda message: {"ok": True, "command": message["command"]})
            try:
                result = request({"command": "status"})
                self.assertEqual(result["command"], "status")
                self.assertEqual(len(auth_key()), 32)
            finally:
                server.close()

    def test_occupied_saved_port_reports_error_instead_of_changing_policy(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=directory):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            StateManager.save_state(dict(profiles={}, applied={}, background={"applications": {"a": {"profile": "p"}}, "ports": {"p": port}}))
            manager = BackgroundManager()
            try:
                with mock.patch("devproxy_pkg.cli.resolve_profile", return_value=ProxyProfile("p", "http", "localhost", 80)):
                    self.assertEqual(manager.resume(), ["p"])
                self.assertEqual(StateManager.load_state()["background"]["ports"]["p"], port)
                self.assertTrue(manager.last_error)
            finally:
                manager.close()
                listener.close()


if __name__ == "__main__":
    unittest.main()
