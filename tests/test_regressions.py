"""Local protocol integration and lifecycle regressions. No Internet or real IDE needed."""
import base64
import contextlib
import io
import json
import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from devproxy_pkg.cli import main, resolve_profile
from devproxy_pkg.core.config_editor import ConfigEditor, parse_jsonc
from devproxy_pkg.core.launcher import ApplicationSession, Launcher, RoutingUnavailable
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.secrets import SecretStore, WindowsCredentialStore
from devproxy_pkg.core.transport import connect_upstream, recv_exact, read_headers, ProxyError
from devproxy_pkg.core.tunnel import LocalTunnel
from devproxy_pkg.adapters.generic import GenericApplicationAdapter
from devproxy_pkg.adapters.vscode_family import VSCodeAdapter


class FakeProxy:
    def __init__(self, protocol="http", reject=False, banner=b"", fragment=False):
        self.protocol, self.reject = protocol, reject
        self.banner, self.fragment = banner, fragment
        self.requests, self.errors, self.clients = [], [], []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.stopped = threading.Event()
        self.workers = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def send(self, sock, data):
        if self.fragment:
            for byte in data:
                sock.sendall(bytes((byte,)))
                time.sleep(0.001)
        else:
            sock.sendall(data)

    def serve(self):
        while not self.stopped.is_set():
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.clients.append(sock)
            thread = threading.Thread(target=self.handle, args=(sock,), daemon=True)
            self.workers.append(thread)
            thread.start()

    def handle(self, sock):
        try:
            if self.protocol == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                fixtures = Path(__file__).parent / "fixtures"
                context.load_cert_chain(fixtures / "localhost-cert.pem", fixtures / "localhost-key.pem")
                sock = context.wrap_socket(sock, server_side=True)
            with sock:
                sock.settimeout(3)
                if self.protocol == "socks5":
                    greeting = recv_exact(sock, 2)
                    methods = recv_exact(sock, greeting[1])
                    self.requests.append(("methods", methods))
                    method = 2 if 2 in methods else 0
                    self.send(sock, bytes((5, method)))
                    if method == 2:
                        version, size = recv_exact(sock, 2)
                        user = recv_exact(sock, size)
                        password = recv_exact(sock, recv_exact(sock, 1)[0])
                        self.requests.append(("auth", user, password))
                        self.send(sock, b"\x01\x01" if self.reject else b"\x01\x00")
                        if self.reject:
                            return
                    version, command, reserved, kind = recv_exact(sock, 4)
                    size = {1: 4, 4: 16}.get(kind)
                    if size is None:
                        size = recv_exact(sock, 1)[0]
                    host = recv_exact(sock, size)
                    port = int.from_bytes(recv_exact(sock, 2), "big")
                    self.requests.append(("destination", kind, host, port))
                    self.send(sock, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                else:
                    headers, tail = read_headers(sock)
                    self.requests.append(headers)
                    if not headers.startswith(b"CONNECT "):
                        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied")
                        return
                    if self.reject:
                        sock.sendall(b"HTTP/1.1 407 Error 200 misleading\r\nX-Secret: must-not-reflect\r\n\r\n")
                        return
                    self.send(sock, b"HTTP/1.1 200 OK\r\n\r\n" + self.banner)
                    if tail:
                        sock.sendall(tail)
                while True:
                    data = sock.recv(32768)
                    if not data:
                        return
                    sock.sendall(data)
        except OSError as exc:
            if not self.stopped.is_set() and not isinstance(exc, (ConnectionResetError, BrokenPipeError)):
                self.errors.append(exc)

    def profile(self, authenticated=True):
        return ProxyProfile("fixture", self.protocol, "127.0.0.1", self.port,
                            "alice" if authenticated else None, "test-secret" if authenticated else None)

    def close(self):
        self.stopped.set()
        self.listener.close()
        for sock in self.clients:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except OSError:
                pass
        self.thread.join(1)
        for thread in self.workers:
            thread.join(1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class ProtocolTests(unittest.TestCase):
    def connect(self, tunnel, target="example.invalid:443"):
        sock = socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=3)
        self.addCleanup(sock.close)
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return sock

    def test_fragmented_authenticated_socks_and_remote_dns(self):
        with FakeProxy("socks5", fragment=True) as proxy, LocalTunnel(proxy.profile()) as tunnel:
            sock = self.connect(tunnel)
            headers, _ = read_headers(sock)
            self.assertIn(b"200 ", headers)
            sock.sendall(b"payload")
            self.assertEqual(recv_exact(sock, 7), b"payload")
            self.assertIn(("auth", b"alice", b"test-secret"), proxy.requests)
            self.assertIn(("destination", 3, b"example.invalid", 443), proxy.requests)

    def test_socks_ipv4_and_ipv6_literals(self):
        for target, kind, packed in (("127.0.0.9:443", 1, socket.inet_pton(socket.AF_INET, "127.0.0.9")),
                                     ("[2001:db8::5]:443", 4, socket.inet_pton(socket.AF_INET6, "2001:db8::5"))):
            with FakeProxy("socks5") as proxy, LocalTunnel(proxy.profile(False)) as tunnel:
                sock = self.connect(tunnel, target)
                self.assertIn(b"200 ", read_headers(sock)[0])
                self.assertIn(("destination", kind, packed, 443), proxy.requests)

    def test_http_auth_and_response_tail(self):
        with FakeProxy(banner=b"banner") as proxy, LocalTunnel(proxy.profile()) as tunnel:
            sock = self.connect(tunnel, "[2001:db8::1]:443")
            headers, tail = read_headers(sock)
            self.assertIn(b"200 ", headers)
            self.assertEqual(tail, b"banner")
            request = proxy.requests[0]
            self.assertIn(b"CONNECT [2001:db8::1]:443", request)
            self.assertIn(base64.b64encode(b"alice:test-secret"), request)

    def test_https_proxy_strict_tls_with_test_ca(self):
        create_context = ssl.create_default_context
        fixture = Path(__file__).parent / "fixtures" / "localhost-cert.pem"
        with FakeProxy("https") as proxy, mock.patch("devproxy_pkg.core.transport.ssl.create_default_context", side_effect=lambda: create_context(cafile=str(fixture))):
            with LocalTunnel(proxy.profile()) as tunnel:
                sock = self.connect(tunnel)
                self.assertIn(b"200", read_headers(sock)[0])
                sock.sendall(b"encrypted outer transport")
                self.assertEqual(recv_exact(sock, 25), b"encrypted outer transport")

    def test_https_proxy_untrusted_certificate_rejected(self):
        with FakeProxy("https") as proxy, LocalTunnel(proxy.profile()) as tunnel:
            self.assertIn(b"502", self.connect(tunnel).recv(4096))

    def test_bounded_duplex_large_payload(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile()) as tunnel:
            sock = self.connect(tunnel)
            read_headers(sock)
            data = bytes(range(256)) * 16384
            def send():
                sock.sendall(data)
                sock.shutdown(socket.SHUT_WR)
            sender = threading.Thread(target=send)
            sender.start()
            self.assertEqual(recv_exact(sock, len(data)), data)
            sender.join(3)
            self.assertFalse(sender.is_alive())

    def test_concurrency_is_bounded(self):
        with LocalTunnel(ProxyProfile("x", "http", "localhost", 80), max_connections=1, handshake_timeout=0.5) as tunnel:
            with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=2) as first:
                deadline = time.monotonic() + 1
                while not tunnel._workers and time.monotonic() < deadline:
                    time.sleep(0.01)
                with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=2) as second:
                    self.assertEqual(second.recv(1), b"")
                self.assertEqual(len(tunnel._workers), 1)

    def test_rejected_http_not_mistaken_for_200(self):
        with FakeProxy(reject=True) as proxy, LocalTunnel(proxy.profile()) as tunnel:
            data = self.connect(tunnel).recv(4096)
            self.assertIn(b"502", data)
            self.assertNotIn(b"must-not-reflect", data)

    def test_rejected_socks_auth(self):
        with FakeProxy("socks5", reject=True) as proxy, LocalTunnel(proxy.profile()) as tunnel:
            self.assertIn(b"502", self.connect(tunnel).recv(4096))

    def test_fragmented_client_headers_and_early_data(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile(False)) as tunnel:
            with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=3) as sock:
                sock.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\n")
                time.sleep(0.01)
                sock.sendall(b"Host: example.invalid:443\r\n\r\nfirst")
                headers, tail = read_headers(sock)
                self.assertIn(b"200 ", headers)
                self.assertEqual(tail + recv_exact(sock, 5 - len(tail)), b"first")

    def test_http_forwarding_auth_replaced(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile()) as tunnel:
            with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=3) as sock:
                sock.sendall(b"GET http://example.invalid/path?q=1 HTTP/1.1\r\nHost: example.invalid\r\npRoXy-AuThOrIzAtIoN: attacker\r\n\r\n")
                headers, tail = read_headers(sock)
                self.assertIn(b"200", headers)
                self.assertIn(b"proxied", tail + sock.recv(4096))
                self.assertIn(b"GET http://example.invalid/path?q=1", proxy.requests[0])
                self.assertNotIn(b"attacker", proxy.requests[0])
                self.assertEqual(proxy.requests[0].lower().count(b"proxy-authorization:"), 1)

    def test_socks_http_origin_form_and_auth_removed(self):
        with FakeProxy("socks5") as proxy, LocalTunnel(proxy.profile()) as tunnel:
            with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=3) as sock:
                sock.sendall(b"GET http://example.invalid/path HTTP/1.1\r\nHost: example.invalid\r\nProxy-Authorization: local-secret\r\n\r\n")
                echoed, _ = read_headers(sock)
                self.assertTrue(echoed.startswith(b"GET /path HTTP/1.1"))
                self.assertNotIn(b"local-secret", echoed)

    def test_fail_closed_after_proxy_shutdown(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile()) as tunnel:
            sock = self.connect(tunnel)
            self.assertIn(b"200", read_headers(sock)[0])
            proxy.close()
            failed = self.connect(tunnel).recv(4096)
            self.assertIn(b"502", failed)

    def test_only_upstream_is_dialed(self):
        profile = ProxyProfile("x", "http", "proxy.invalid", 8080)
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError) as dial:
            with self.assertRaises(ConnectionRefusedError):
                connect_upstream(profile, "destination.invalid", 443)
            dial.assert_called_once()
            address, = dial.call_args.args
            self.assertEqual(address, ("proxy.invalid", 8080))
            # The dial budget shares one overall handshake deadline, so assert
            # the bound rather than a byte-exact float.
            self.assertLessEqual(dial.call_args.kwargs["timeout"], 10.0)
            self.assertGreater(dial.call_args.kwargs["timeout"], 9.0)

    def test_public_listener_refused(self):
        with self.assertRaises(ValueError):
            LocalTunnel(ProxyProfile("x", "http", "localhost", 80), "0.0.0.0")

    def test_stop_closes_active_and_stalled_connections(self):
        tunnel = LocalTunnel(ProxyProfile("x", "http", "localhost", 80), handshake_timeout=0.5)
        port = tunnel.start()
        self.assertEqual(port, tunnel.start())
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        time.sleep(0.03)
        tunnel.stop()
        tunnel.stop()
        self.assertFalse(tunnel._workers)
        self.assertFalse(tunnel._sockets)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)
        sock.close()

    def test_restart_same_owner(self):
        tunnel = LocalTunnel(ProxyProfile("x", "http", "localhost", 80))
        tunnel.start()
        tunnel.stop()
        tunnel.start()
        self.assertTrue(tunnel.is_running)
        tunnel.stop()

    def test_half_close_keeps_incoming_bytes(self):
        with FakeProxy() as proxy, LocalTunnel(proxy.profile()) as tunnel:
            sock = self.connect(tunnel)
            read_headers(sock)
            sock.sendall(b"final")
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_exact(sock, 5), b"final")

    def test_header_limit_and_idle_timeout(self):
        with LocalTunnel(ProxyProfile("x", "http", "localhost", 80), handshake_timeout=0.1) as tunnel:
            with socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=2) as sock:
                sock.sendall(b"X" * 32769)
                self.assertIn(b"502", sock.recv(1024))


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env = mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=self.directory.name)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_jsonc_nested_key_and_trailing_comment(self):
        raw = '{\n"nested": {"http.proxy": ["leave", {"a": -1e3}]},\n// "http.proxy": "fake"\n"url": "https://x/,}", // tail\n}'
        out = ConfigEditor.update_json_fields_preserving(raw, {"http.proxy": "http://new:8080"})
        parsed = parse_jsonc(out)
        self.assertEqual(parsed["nested"]["http.proxy"][0], "leave")
        self.assertEqual(parsed["url"], "https://x/,}")
        self.assertEqual(parsed["http.proxy"], "http://new:8080")
        self.assertIn('// "http.proxy": "fake"', out)
        self.assertIn("// tail", out)

    def test_jsonc_remove_only_top_level(self):
        raw = '{"nested": {"x": [1, {"v": 2}]}, "x": -1e3, "tail": true}'
        out = ConfigEditor.remove_json_fields_preserving(raw, ["x"])
        self.assertEqual(parse_jsonc(out), {"nested": {"x": [1, {"v": 2}]}, "tail": True})

    def test_jsonc_refuses_malformed_or_non_object(self):
        for raw in ('{"x": 1 /* unterminated', '[]', '{"x":1,"x":2}', '{"x":}'):
            with self.assertRaises(ValueError):
                ConfigEditor.update_json_fields_preserving(raw, {"proxy": "x"})

    def test_read_error_does_not_crash(self):
        parsed, raw = ConfigEditor.load_jsonc(self.directory.name)
        self.assertIsNone(parsed)
        self.assertIsNone(raw)

    def test_atomic_backup_and_failure_preserve_original(self):
        path = Path(self.directory.name) / "settings.json"
        path.write_text('{"x":1}', encoding="utf-8")
        with mock.patch("os.replace", side_effect=OSError):
            with self.assertRaises(OSError):
                ConfigEditor.atomic_write(str(path), '{"x":2}')
        self.assertEqual(path.read_text(), '{"x":1}')
        self.assertEqual(Path(str(path) + ".bak").read_text(), '{"x":1}')

    def test_corrupt_state_not_overwritten(self):
        path = Path(self.directory.name) / "state.json"
        path.write_text("corrupt", encoding="utf-8")
        with self.assertRaises(ValueError):
            StateManager.save_profile(ProxyProfile("x", "http", "localhost", 80).to_dict())
        self.assertEqual(path.read_text(), "corrupt")

    def test_rollback_preserves_unrelated_and_conflicts(self):
        path = Path(self.directory.name) / "settings.json"
        StateManager.record_applied_change("app", str(path), {"http.proxy": "session"}, {"http.proxy": {"$devproxy_missing": True}})
        path.write_text('{"http.proxy":"manual","font":14}', encoding="utf-8")
        self.assertFalse(StateManager.restore_app("app")[0])
        self.assertIsNotNone(StateManager.get_applied_record("app"))
        path.write_text('{"http.proxy":"session","font":18}', encoding="utf-8")
        self.assertTrue(StateManager.restore_app("app")[0])
        self.assertEqual(json.loads(path.read_text()), {"font": 18})

    def test_second_apply_preserves_original_rollback(self):
        path = str(Path(self.directory.name) / "settings.json")
        StateManager.record_applied_change("app", path, {"proxy": "first"}, {"proxy": None})
        StateManager.record_applied_change("app", path, {"proxy": "second"}, {"proxy": "first"})
        self.assertEqual(StateManager.get_applied_record("app")[path]["original_values"], {"proxy": None})

    def test_plaintext_config_rejected(self):
        with self.assertRaises(ValueError):
            ProxyProfile.from_dict({"name": "x", "host": "localhost", "port": 80, "password": "secret"})

    def test_invalid_input_errors_are_redacted(self):
        for raw in ("http://alice:super-secret@host:wrong", "http://alice:super-secret@/x", "socks5://host:0"):
            with self.assertRaises(ValueError) as error:
                ProxyProfile.parse(raw)
            self.assertNotIn("super-secret", str(error.exception))

    def test_invalid_direct_profiles(self):
        for changes in ({"protocol": "ftp"}, {"host": "x\\r\\nInjected"}, {"port": True}, {"port": "80"}):
            values = dict(name="x", protocol="http", host="localhost", port=80)
            values.update(changes)
            with self.assertRaises(ValueError):
                ProxyProfile(**values)

    def test_missing_secret_refuses_launch_profile(self):
        StateManager.save_profile(ProxyProfile("x", "http", "localhost", 80, username="user", secret_reference="x").to_dict())
        with mock.patch.object(SecretStore, "get_password", return_value=None):
            with self.assertRaises(ValueError):
                resolve_profile("x")

    def test_persistent_credentials_do_not_fallback(self):
        with mock.patch.object(WindowsCredentialStore, "set_password", return_value=False), mock.patch.object(WindowsCredentialStore, "is_available", return_value=True):
            with self.assertRaises(OSError):
                SecretStore.store_password("x", "user", "secret", require_persistent=True)

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_native_credential_roundtrip(self):
        name = "test-" + uuid.uuid4().hex
        self.addCleanup(SecretStore.delete_password, name)
        self.assertEqual(SecretStore.store_password(name, "user", "secret-ä", True), "os_keychain")
        self.assertEqual(WindowsCredentialStore.get_password(name), "secret-ä")

    def test_cli_rejects_secret_arguments_and_strict_mode(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            code = main(["profile", "add", "http://user:secret@localhost:80"])
        self.assertEqual(code, 1)
        self.assertNotIn("secret@", error.getvalue())


class SessionTests(unittest.TestCase):
    def test_require_enforced_routing_refused(self):
        session = ApplicationSession(ProxyProfile("x", "http", "localhost", 80))
        self.addCleanup(session.stop)
        with self.assertRaises(RoutingUnavailable):
            session.start(require_fail_closed=True)
        self.assertFalse(session.tunnel.is_running)

    def test_launch_failure_stops_listener(self):
        with self.assertRaises(FileNotFoundError):
            Launcher.launch_with_tunnel("nonexistent-executable-123", ProxyProfile("x", "http", "localhost", 80))
        self.assertFalse(any(t.name == "DevProxyTunnel" and t.is_alive() for t in threading.enumerate()))

    def test_env_isolated_and_never_contains_proxy_password(self):
        profile = ProxyProfile("x", "http", "localhost", 80, "user", "do-not-expose")
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "env.json")
            original = os.environ.copy()
            with ApplicationSession(profile) as session:
                script = "import os,json,sys;json.dump(dict(os.environ),open(sys.argv[1],'w'))"
                process = session.launch(sys.executable, extra_args=["-c", script, target])
                self.assertEqual(process.wait(timeout=10), 0)
                data = json.loads(Path(target).read_text())
                self.assertEqual(data["HTTP_PROXY"], session.tunnel.proxy_url)
                self.assertEqual(data["NO_PROXY"], "localhost,127.0.0.1,::1")
                self.assertNotIn("do-not-expose", json.dumps(data))
            self.assertEqual(dict(os.environ), dict(original))

    def test_selected_process_uses_proxy_and_unselected_keeps_env(self):
        with FakeProxy() as proxy, tempfile.TemporaryDirectory() as directory:
            proxied = str(Path(directory) / "proxied.txt")
            direct = str(Path(directory) / "direct.txt")
            with ApplicationSession(proxy.profile()) as session:
                script = "import urllib.request,sys;open(sys.argv[1],'wb').write(urllib.request.urlopen('http://example.invalid/test',timeout=3).read())"
                process = session.launch(sys.executable, extra_args=["-c", script, proxied])
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertEqual(Path(proxied).read_bytes(), b"proxied")
                env = os.environ.copy()
                for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                    env.pop(key, None)
                child = subprocess.run([sys.executable, "-c", "import os,sys;open(sys.argv[1],'w').write(os.getenv('HTTP_PROXY','direct'))", direct], env=env, timeout=10)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(Path(direct).read_text(), "direct")

    def test_local_end_to_end_route_and_outage(self):
        received = []
        class Origin(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"direct")
            def log_message(self, *_):
                pass
        origin = http.server.HTTPServer(("127.0.0.1", 0), Origin)
        server = threading.Thread(target=origin.serve_forever, daemon=True)
        server.start()
        try:
            with FakeProxy() as proxy, tempfile.TemporaryDirectory() as directory:
                url = f"http://external.invalid:{origin.server_port}/route"
                path = str(Path(directory) / "result.txt")
                with ApplicationSession(proxy.profile()) as session:
                    script = "import urllib.request,sys;open(sys.argv[2],'wb').write(urllib.request.urlopen(sys.argv[1],timeout=3).read())"
                    selected = session.launch(sys.executable, extra_args=["-c", script, url, path])
                    self.assertEqual(selected.wait(timeout=10), 0)
                    self.assertEqual(Path(path).read_bytes(), b"proxied")
                    self.assertEqual(received, [])
                    direct_script = "import http.client,sys;c=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]));c.request('GET','/route');print(c.getresponse().read().decode())"
                    direct = subprocess.run([sys.executable, "-c", direct_script, str(origin.server_port)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(direct.stdout.strip(), "direct")
                    self.assertEqual(len(received), 1)
                    proxy.close()
                    outage_script = "import urllib.request,urllib.error,sys\ntry: urllib.request.urlopen(sys.argv[1],timeout=3);sys.exit(2)\nexcept urllib.error.HTTPError as e: sys.exit(0 if e.code==502 else 3)"
                    selected = session.launch(sys.executable, extra_args=["-c", outage_script, url])
                    self.assertEqual(selected.wait(timeout=10), 0)
                    self.assertEqual(len(received), 1, "Selected request must not reach the direct origin during an outage")
        finally:
            origin.shutdown()
            origin.server_close()
            server.join(2)

    def test_generic_executable_matching(self):
        adapter = GenericApplicationAdapter(sys.executable)
        self.assertTrue(adapter.matches_executable(sys.executable))
        self.assertFalse(adapter.matches_executable(sys.executable + ".other"))

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_batch_launch_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x.cmd"
            path.write_text("@echo should-not-run")
            with self.assertRaises(ValueError):
                Launcher.launch(str(path))

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_job_kills_descendant_on_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "pid.txt")
            session = ApplicationSession(ProxyProfile("x", "http", "localhost", 80)).start()
            self.addCleanup(session.stop)
            script = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); open(sys.argv[1],'w').write(str(p.pid) + '\\n'); time.sleep(60)"
            process = session.launch(sys.executable, extra_args=["-c", script, path])
            deadline = time.monotonic() + 10
            pid = None
            while time.monotonic() < deadline:
                if Path(path).exists():
                    try:
                        content = Path(path).read_text().strip()
                        if content:
                            pid = int(content)
                            break
                    except (PermissionError, OSError, ValueError):
                        pass
                time.sleep(0.02)
            self.assertIsNotNone(pid, "Timed out waiting for descendant PID to be written")
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32")
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel.OpenProcess(0x100000, False, pid)
            self.assertTrue(handle)
            try:
                session.stop()
                self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0)
                self.assertIsNotNone(process.poll())
            finally:
                kernel.CloseHandle(handle)

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_job_kills_application_on_controller_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "child.txt")
            controller_code = "from devproxy_pkg.core.launcher import ApplicationSession;from devproxy_pkg.core.profile import ProxyProfile;import sys,time;s=ApplicationSession(ProxyProfile('x','http','localhost',80)).start();p=s.launch(sys.executable,extra_args=['-c','import time;time.sleep(60)']);open(sys.argv[1],'w').write(str(p.pid) + '\\n');time.sleep(60)"
            controller = subprocess.Popen([sys.executable, "-c", controller_code, path])
            self.addCleanup(lambda: controller.poll() is None and controller.kill())
            deadline = time.monotonic() + 10
            child = None
            while time.monotonic() < deadline:
                if Path(path).exists():
                    try:
                        content = Path(path).read_text().strip()
                        if content:
                            child = int(content)
                            break
                    except (PermissionError, OSError, ValueError):
                        pass
                time.sleep(0.02)
            self.assertIsNotNone(child, "Timed out waiting for child PID to be written")
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32")
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel.OpenProcess(0x100000, False, child)
            self.assertTrue(handle)
            try:
                controller.kill()
                controller.wait(timeout=5)
                self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0)
            finally:
                kernel.CloseHandle(handle)

    def test_discovery_standard_code_location(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "Programs" / "Microsoft VS Code" / "Code.exe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            with mock.patch.dict(os.environ, LOCALAPPDATA=directory), mock.patch("shutil.which", return_value=None), mock.patch("sys.platform", "win32"):
                self.assertEqual(VSCodeAdapter().detect_executable(), str(executable.resolve()))


if __name__ == "__main__":
    unittest.main()
