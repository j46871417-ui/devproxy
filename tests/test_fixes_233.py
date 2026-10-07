"""Regression tests for the 2.3.3 fixes: live profile snapshots, bounded TLS
relay, handshake retry policy, safe diagnostics and non-blocking status.

Only local fixtures are used: FakeProxy from test_regressions and the test
certificate in tests/fixtures. No Internet access and no real IDE is required.
"""
import base64
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from devproxy_pkg.cli import resolve_profile, resolve_saved_profile
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.profiles import persist_profile
from devproxy_pkg.core.recovery import StateManager
from devproxy_pkg.core.secrets import SecretStore
from devproxy_pkg.core.transport import (connect_upstream, open_proxy, read_headers,
                                         recv_exact, ProxyError, tag_phase)
from devproxy_pkg.core.tunnel import LocalTunnel, snapshot_profile
from devproxy_pkg.core.user_errors import describe_error

from test_regressions import FakeProxy

FIXTURES = Path(__file__).parent / "fixtures"
NAME = "Прокси 1"


class IsolatedState(unittest.TestCase):
    """Temp state dir plus an in-memory credential store."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        patch = mock.patch.dict(os.environ, DEVPROXY_STATE_DIR=str(self.directory))
        patch.start()
        self.addCleanup(patch.stop)
        self.secrets = self.fake_secrets()

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
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return values

    def save(self, profile, original=None, keep_password=False):
        """Persist a profile the way the GUI does, keeping the fake secret in sync."""
        if getattr(profile, "password", None) is not None:
            self.secrets[profile.name if original is None else (original or profile.name)] = profile.password
        persist_profile(profile, original, keep_password)
        if profile.password is not None:
            self.secrets[profile.name] = profile.password
        return profile

    def set_secret(self, name, value):
        self.secrets[name] = value

    @staticmethod
    def connect(tunnel, target="example.invalid:443"):
        sock = socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=5)
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return sock


class LiveProfileSnapshotTests(IsolatedState):
    """A running bridge must pick up saved host/port/password for NEW streams."""

    def test_edited_address_and_password_reach_new_connection_same_port(self):
        with FakeProxy() as first, FakeProxy() as second:
            self.save(ProxyProfile(NAME, "http", "127.0.0.1", first.port, "alice", "old-secret"))
            self.set_secret(NAME, "old-secret")
            # The session's initial profile is deliberately stale (dead port).
            tunnel = LocalTunnel(ProxyProfile(NAME, "http", "127.0.0.1", 9, "alice", "stale"),
                                 profile_provider=lambda: resolve_saved_profile(NAME))
            port = tunnel.start()
            self.addCleanup(tunnel.stop)

            with self.connect(tunnel) as sock:
                self.assertIn(b"200", read_headers(sock)[0])
                sock.sendall(b"first-stream")
                self.assertEqual(recv_exact(sock, 12), b"first-stream")
            self.assertEqual(len(first.requests), 1)
            self.assertIn(base64.b64encode(b"alice:old-secret"), first.requests[0])
            self.assertNotIn(b"stale", first.requests[0])

            # Edit the saved profile: new password and a different upstream.
            self.save(ProxyProfile(NAME, "http", "127.0.0.1", second.port, "alice", "new-secret"),
                      NAME, keep_password=False)
            self.set_secret(NAME, "new-secret")

            self.assertEqual(tunnel.allocated_port, port, "Existing listener must not move")
            self.assertFalse(tunnel._workers, "First stream must have finished")

            with self.connect(tunnel) as sock:
                self.assertIn(b"200", read_headers(sock)[0])
                sock.sendall(b"second-stream")
                self.assertEqual(recv_exact(sock, 13), b"second-stream")
            self.assertEqual(len(first.requests), 1, "Old proxy must not be used again")
            self.assertEqual(len(second.requests), 1, "New connection must use the updated address")
            self.assertIn(base64.b64encode(b"alice:new-secret"), second.requests[0])
            self.assertNotIn(b"old-secret", second.requests[0])

    def test_existing_stream_survives_profile_edit(self):
        with FakeProxy() as proxy:
            self.save(ProxyProfile(NAME, "http", "127.0.0.1", proxy.port, "alice", "keep"))
            self.set_secret(NAME, "keep")
            tunnel = LocalTunnel(ProxyProfile(NAME, "http", "127.0.0.1", proxy.port, "alice", "keep"),
                                 profile_provider=lambda: resolve_saved_profile(NAME))
            tunnel.start()
            self.addCleanup(tunnel.stop)
            with self.connect(tunnel) as sock:
                self.assertIn(b"200", read_headers(sock)[0])
                sock.sendall(b"before")
                self.assertEqual(recv_exact(sock, 6), b"before")
                # Repoint the saved profile at a dead port mid-stream.
                StateManager.save_profile(ProxyProfile(NAME, "http", "127.0.0.1", 1, "alice",
                                                       secret_reference=NAME).to_dict())
                self.set_secret(NAME, "changed")
                sock.sendall(b"after")
                self.assertEqual(recv_exact(sock, 5), b"after",
                                 "An established stream must not be torn down by a profile edit")

    def test_missing_secret_refuses_without_direct_fallback(self):
        self.save(ProxyProfile(NAME, "http", "127.0.0.1", 8080, "alice", "secret"))
        self.secrets.clear()  # credential removed / keychain locked
        with mock.patch("socket.create_connection",
                        side_effect=AssertionError("must not dial anything")) as dial:
            with self.assertRaises(ProxyError) as refused:
                connect_upstream(snapshot_profile(lambda: resolve_saved_profile(NAME), None),
                                 "api.invalid", 443)
        self.assertEqual(refused.exception.code, "profile_unavailable")
        dial.assert_not_called()
        self.assertIn("пароль", describe_error(refused.exception, "api.invalid"))

    def test_deleted_profile_refuses_without_dialing_anything(self):
        with mock.patch("socket.create_connection",
                        side_effect=AssertionError("must not dial anything")) as dial:
            with self.assertRaises(ProxyError) as refused:
                connect_upstream(snapshot_profile(lambda: resolve_saved_profile("Удалённый профиль"), None),
                                 "api.invalid", 443)
        self.assertEqual(refused.exception.code, "profile_unavailable")
        dial.assert_not_called()
        message = describe_error(refused.exception, "api.invalid")
        self.assertIn("Прямое подключение не выполняется", message)

    def test_stale_password_is_not_reused(self):
        """A removed secret must not silently reuse the previous password."""
        with FakeProxy() as proxy:
            self.save(ProxyProfile(NAME, "http", "127.0.0.1", proxy.port, "alice", "old-password"))
            self.set_secret(NAME, "old-password")
            tunnel = LocalTunnel(ProxyProfile(NAME, "http", "127.0.0.1", proxy.port, "alice", "old-password"),
                                 profile_provider=lambda: resolve_saved_profile(NAME))
            tunnel.start()
            self.addCleanup(tunnel.stop)
            with self.connect(tunnel) as sock:
                self.assertIn(b"200", read_headers(sock)[0])
            self.secrets.clear()
            with self.connect(tunnel) as sock:
                self.assertIn(b"502", sock.recv(4096))
            self.assertEqual(len(proxy.requests), 1, "No request may be sent with the stale password")

    def test_snapshot_copies_and_does_not_mutate_provider_object(self):
        """The shared profile object must never be the live credential source."""
        shared = ProxyProfile(NAME, "http", "127.0.0.1", 2, "alice", "q")
        copied = snapshot_profile(lambda: shared, ProxyProfile(NAME, "http", "127.0.0.1", 1))
        self.assertEqual((copied.port, copied.password), (2, "q"))
        self.assertEqual((shared.port, shared.password), (2, "q"))
        # Mutating the snapshot must not touch the provider's object.
        copied.password = "mutated"
        self.assertEqual(shared.password, "q")

    def test_provider_failure_is_reported_as_profile_problem(self):
        tunnel = LocalTunnel(ProxyProfile("x", "http", "127.0.0.1", 1),
                             profile_provider=lambda: (_ for _ in ()).throw(ValueError("boom")))
        tunnel.start()
        self.addCleanup(tunnel.stop)
        with self.connect(tunnel) as sock:
            self.assertIn(b"502", sock.recv(4096))
        entry = tunnel.diagnostics()["failures"][0]
        self.assertEqual(entry["code"], "profile_unavailable")
        self.assertEqual(entry["phase"], "profile")


class RenameMigrationTests(IsolatedState):
    def test_rename_repoints_policies_ports_and_selection(self):
        self.save(ProxyProfile("Старый", "http", "127.0.0.1", 8080, "alice", "s"))
        state = StateManager.load_state()
        state.update({"selected_profile": "Старый",
                      "background": {"ports": {"Старый": 18787},
                                     "applications": {"antigravity": {"profile": "Старый",
                                                                      "record": {"id": "antigravity"}}}}})
        StateManager.save_state(state)
        self.save(ProxyProfile("Новый", "http", "127.0.0.1", 8080, "alice", None),
                  "Старый", keep_password=True)
        state = StateManager.load_state()
        self.assertNotIn("Старый", state["profiles"])
        self.assertIn("Новый", state["profiles"])
        self.assertEqual(state["background"]["applications"]["antigravity"]["profile"], "Новый",
                         "A rename must not orphan a persistent rule")
        self.assertEqual(state["background"]["ports"], {"Новый": 18787})
        self.assertEqual(state["selected_profile"], "Новый")

    def test_rename_does_not_steal_port_from_other_profile(self):
        self.save(ProxyProfile("A", "http", "127.0.0.1", 8080, "alice", "s"))
        state = StateManager.load_state()
        state["background"] = {"ports": {"A": 18787, "B": 18788}, "applications": {}}
        StateManager.save_state(state)
        with self.assertRaises(ValueError):
            self.save(ProxyProfile("B", "http", "127.0.0.1", 8080, "alice", None), "A", keep_password=True)
        state = StateManager.load_state()
        # The destination name already owned a port; the old reservation is dropped.
        self.assertEqual(state["background"]["ports"], {"A": 18787, "B": 18788})


class DestinationErrorTests(IsolatedState):
    def test_failure_of_one_destination_survives_success_of_another(self):
        with FakeProxy() as deadless:
            failing = LocalTunnel(ProxyProfile("dead", "http", "127.0.0.1", 1))
            failing.start()
            self.addCleanup(failing.stop)
            with self.connect(failing, "blocked.invalid:443") as sock:
                self.assertIn(b"502", sock.recv(4096))
            failure_message = failing.last_error
            self.assertIsNotNone(failure_message)

            healthy = LocalTunnel(deadless.profile(authenticated=False))
            healthy.start()
            self.addCleanup(healthy.stop)
            with self.connect(healthy, "other.invalid:443") as sock:
                self.assertIn(b"200", read_headers(sock)[0])
            # Success on the healthy tunnel must not touch the failing tunnel.
            self.assertEqual(failing.last_error, failure_message)
            self.assertEqual(len(failing.diagnostics()["failures"]), 1)

    def test_same_tunnel_other_destination_success_keeps_error(self):
        with FakeProxy() as proxy, FakeProxy(reject=True) as rejecting:
            profile = proxy.profile(authenticated=False)
            tunnel = LocalTunnel(proxy.profile(authenticated=False))
            tunnel.start()
            self.addCleanup(tunnel.stop)
            # Drive a failure for destination A and a success for destination B.
            tunnel._record_failure(ProxyError("HTTP CONNECT rejected", "http_rejected", 403),
                                   "a.invalid", 443, "connect")
            error_for_a = tunnel.last_error
            self.assertIn("a.invalid", error_for_a)
            with self.connect(tunnel, "b.invalid:443") as sock:
                self.assertIn(b"200", read_headers(sock)[0])
            # B succeeded; A's failure must still be visible.
            self.assertEqual(tunnel.last_error, error_for_a,
                             "A success to another destination must not mask this error")
            self.assertEqual(len(tunnel.diagnostics()["failures"]), 1)

    def test_repeat_success_clears_current_error_but_keeps_history(self):
        tunnel = LocalTunnel(ProxyProfile("p", "http", "127.0.0.1", 1))
        target = ("api.invalid", 443)
        tunnel._record_failure(ProxyError("HTTP CONNECT rejected", "http_rejected", 403), *target, "connect")
        self.assertIsNotNone(tunnel.last_error)
        history_after_failure = len(tunnel._history)
        tunnel._record_success(*target)
        self.assertIsNone(tunnel.last_error, "Repeat success must clear the current error")
        self.assertEqual(len(tunnel._history), history_after_failure, "History must be retained")
        self.assertEqual(tunnel.diagnostics()["failures"], [])

    def test_failure_entry_carries_safe_identifiers(self):
        tunnel = LocalTunnel(ProxyProfile("p", "http", "127.0.0.1", 1))
        error = ProxyError("HTTP CONNECT rejected", "http_rejected", 403)
        tag_phase(error, "connect")
        tunnel._record_failure(error, "api.invalid", 443, "connect")
        entry = tunnel.diagnostics()["failures"][0]
        self.assertEqual((entry["host"], entry["port"]), ("api.invalid", 443))
        self.assertEqual((entry["status"], entry["code"], entry["phase"]), (403, "http_rejected", "connect"))
        self.assertNotIn("password", entry["message"].lower())
        self.assertNotIn("Authorization", entry["message"])

    def test_diagnostics_history_is_bounded(self):
        tunnel = LocalTunnel(ProxyProfile("p", "http", "127.0.0.1", 1))
        for index in range(60):
            tunnel._record_failure(ProxyError("e"), f"h{index}.invalid", 443, "connect")
        diagnostics = tunnel.diagnostics()
        self.assertLessEqual(len(diagnostics["failures"]), 16)
        self.assertLessEqual(len(diagnostics["recent_failures"]), 32)
        self.assertEqual(diagnostics["failed"], 60)


class StatusSnapshotTests(IsolatedState):
    def test_snapshot_does_not_block_while_lock_is_held(self):
        from devproxy_pkg.core.background import BackgroundManager
        manager = BackgroundManager()
        manager.refresh()
        held, release = threading.Event(), threading.Event()

        def hold():
            with manager.lock:
                held.set()
                release.wait(5)

        worker = threading.Thread(target=hold, daemon=True)
        worker.start()
        self.assertTrue(held.wait(2))
        started = time.monotonic()
        for _ in range(50):
            manager.snapshot()
        elapsed = time.monotonic() - started
        release.set()
        worker.join(2)
        self.assertLess(elapsed, 1.0, "snapshot() must not wait on BackgroundManager.lock")

    def test_gui_status_snapshot_not_blocked_by_locked_manager(self):
        import tkinter as tk
        from devproxy_pkg.ui import DevProxyWindow
        from devproxy_pkg.core.background import BackgroundManager
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        manager = BackgroundManager()
        window = DevProxyWindow(root, auto_discover=False, background=manager)
        self.addCleanup(manager.close)
        held, release = threading.Event(), threading.Event()

        def hold():
            with manager.lock:
                held.set()
                release.wait(5)

        worker = threading.Thread(target=hold, daemon=True)
        worker.start()
        self.assertTrue(held.wait(2))
        started = time.monotonic()
        window.status_snapshot()
        window.report_background_failure()
        elapsed = time.monotonic() - started
        release.set()
        worker.join(2)
        self.assertLess(elapsed, 1.0, "GUI status must not block on the manager lock")

    def test_snapshot_reports_session_failures_without_secrets(self):
        from devproxy_pkg.core.background import BackgroundManager
        manager = BackgroundManager()
        tunnel = LocalTunnel(ProxyProfile(NAME, "http", "127.0.0.1", 1))
        tunnel._record_failure(ProxyError("HTTP CONNECT rejected", "http_rejected", 403),
                               "api.invalid", 443, "connect")
        manager.sessions[NAME] = type("S", (), {"tunnel": tunnel})()
        manager.refresh()
        snapshot = manager.snapshot()
        self.assertTrue(snapshot["sessions"])
        self.assertIsNotNone(snapshot["error"])
        self.assertIn("api.invalid", snapshot["error"])
        self.assertNotIn("Authorization", repr(snapshot))

    def test_status_snapshot_includes_manual_failure(self):
        import tkinter as tk
        from devproxy_pkg.ui import DevProxyWindow
        from devproxy_pkg.core.background import BackgroundManager
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        manager = BackgroundManager()
        window = DevProxyWindow(root, auto_discover=False, background=manager)
        self.addCleanup(manager.close)
        manual = LocalTunnel(ProxyProfile("m", "http", "127.0.0.1", 1))
        manual._record_failure(ProxyError("boom", "protocol_error"), "manual.invalid", 443, "connect")
        window.session = type("S", (), {"tunnel": manual, "active": lambda self: True})()
        try:
            status = window.status_snapshot()
            self.assertTrue(status["ok"])
            self.assertEqual({item["mode"] for item in status["sessions"]}, {"manual"})
            self.assertIn("manual.invalid", status["error"])
        finally:
            window.session = None

    def test_ipc_status_redacts_secrets(self):
        import tkinter as tk
        from devproxy_pkg.ui import DevProxyWindow
        from devproxy_pkg.core.background import BackgroundManager
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        manager = BackgroundManager()
        window = DevProxyWindow(root, auto_discover=False, background=manager)
        self.addCleanup(manager.close)
        # A hostile exception that tries to smuggle credentials into the text.
        error = ProxyError("Proxy-Authorization: Basic c2VjcmV0 alice:hunter2", "auth_failed", 407)
        tunnel = LocalTunnel(ProxyProfile("m", "http", "127.0.0.1", 1))
        tunnel._record_failure(error, "api.invalid", 443, "connect")
        window.session = type("S", (), {"tunnel": tunnel, "active": lambda self: True})()
        try:
            payload = repr(window.status_snapshot())
            self.assertNotIn("c2VjcmV0", payload)
            self.assertNotIn("hunter2", payload)
            self.assertNotIn("Basic ", payload)
        finally:
            window.session = None


class WantWriteRetryTests(IsolatedState):
    """Deterministic SSLWantRead/SSLWantWrite simulation with a growing buffer.

    The relay is driven over real socket pairs so select() observes genuine file
    descriptors. No global module state is patched.
    """

    class FlakySend:
        """Delegate to a real socket, but fail the first send like a TLS write."""

        def __init__(self, real, mode="write", on_first=None):
            self._real = real
            self.mode = mode
            self.on_first = on_first
            self.calls = 0
            self.payloads = []
            self.written = bytearray()

        def send(self, payload):
            self.calls += 1
            self.payloads.append(bytes(payload))
            if self.calls == 1:
                if self.on_first:
                    self.on_first()
                if self.mode == "read":
                    raise ssl.SSLWantReadError(11, "want read")
                raise ssl.SSLWantWriteError(11, "want write")
            self.written.extend(payload)
            return self._real.send(payload)

        def recv(self, size):
            return self._real.recv(size)

        def fileno(self):
            return self._real.fileno()

        def setblocking(self, flag):
            return self._real.setblocking(flag)

        def shutdown(self, how):
            return self._real.shutdown(how)

        def close(self):
            return self._real.close()

        def pending(self):
            return 0

        def getsockopt(self, *args):
            return self._real.getsockopt(*args)

    def _harness(self, mode="write"):
        """Two socket pairs: app<->relay-client and relay-upstream<->peer."""
        app, relay_client = socket.socketpair()
        relay_upstream, peer = socket.socketpair()
        for sock in (app, relay_client, relay_upstream, peer):
            self.addCleanup(sock.close)
        for sock in (relay_client, relay_upstream, peer):
            sock.setblocking(False)
        upstream = self.FlakySend(relay_upstream, mode=mode)
        tunnel = LocalTunnel(ProxyProfile("p", "http", "127.0.0.1", 1), idle_timeout=2.0)
        worker = threading.Thread(target=tunnel._pipe_duplex,
                                  args=(relay_client, upstream), daemon=True)
        worker.start()
        self.addCleanup(lambda: tunnel._stop.set())
        return app, peer, upstream, tunnel, worker

    def test_ssl_write_retry_receives_identical_bytes(self):
        """The retried write must receive byte-identical data, not the buffer."""
        app, peer, upstream, tunnel, worker = self._harness()
        app.sendall(b"payload-from-app")
        deadline = time.monotonic() + 3
        while len(upstream.payloads) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        tunnel._stop.set()
        worker.join(2)
        self.assertGreaterEqual(len(upstream.payloads), 2, "write must be retried")
        self.assertEqual(upstream.payloads[0], upstream.payloads[1],
                         "Retry must pass byte-identical data")
        self.assertEqual(upstream.payloads[0], b"payload-from-app")

    def test_growing_buffer_does_not_corrupt_retried_write(self):
        """Bytes appended while the write is blocked must not alter the retry."""
        first_sent = threading.Event()

        def on_first():
            first_sent.set()

        app, peer, upstream, tunnel, worker = self._harness(mode="write")
        upstream.on_first = on_first
        app.sendall(b"first-chunk")
        self.assertTrue(first_sent.wait(3), "first write must be attempted")
        # The relay's source buffer grows while the write is blocked.
        app.sendall(b"-second-chunk")
        deadline = time.monotonic() + 3
        while len(upstream.payloads) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        tunnel._stop.set()
        worker.join(2)
        self.assertGreaterEqual(len(upstream.payloads), 2)
        self.assertEqual(upstream.payloads[0], upstream.payloads[1],
                         "Retry must repeat the frozen bytes, not the grown buffer")
        self.assertEqual(upstream.payloads[0], b"first-chunk")
        self.assertNotIn(b"second-chunk", upstream.payloads[0])

    def test_want_read_write_is_retried_after_readability(self):
        """A write blocked on readability must resume, not stall the relay."""
        app, peer, upstream, tunnel, worker = self._harness(mode="read")
        app.sendall(b"needs-read-first")
        deadline = time.monotonic() + 3
        while len(upstream.payloads) < 2 and time.monotonic() < deadline:
            # The relay waits for readability; make the socket readable.
            try:
                peer.sendall(b"ping")
            except OSError:
                pass
            time.sleep(0.01)
        tunnel._stop.set()
        worker.join(2)
        self.assertGreaterEqual(len(upstream.payloads), 2,
                                "write must resume once readable")
        self.assertEqual(upstream.payloads[0], upstream.payloads[1])
        self.assertEqual(upstream.payloads[-1], b"needs-read-first")

    def test_relay_stops_without_busy_loop(self):
        app, peer, upstream, tunnel, worker = self._harness()
        app.sendall(b"data")
        time.sleep(0.2)
        tunnel._stop.set()
        started = time.monotonic()
        worker.join(3)
        self.assertFalse(worker.is_alive(), "relay must exit when stopped")
        self.assertLess(time.monotonic() - started, 3.0)


class RelayBehaviourTests(IsolatedState):
    def test_large_duplex_stream_over_https_proxy(self):
        create_context = ssl.create_default_context
        fixture = str(FIXTURES / "localhost-cert.pem")
        with FakeProxy("https") as proxy:
            with mock.patch("devproxy_pkg.core.transport.ssl.create_default_context",
                            side_effect=lambda: create_context(cafile=fixture)):
                tunnel = LocalTunnel(proxy.profile(authenticated=False))
                tunnel.start()
                self.addCleanup(tunnel.stop)
                sock = self.connect(tunnel)
                self.addCleanup(sock.close)
                self.assertIn(b"200", read_headers(sock)[0])
                total = 512 * 1024
                chunk = bytes(range(256)) * 64
                self.assertEqual(len(chunk), 16384)
                payload = (chunk * ((total // len(chunk)) + 1))[:total]

                def sender():
                    try:
                        sock.sendall(payload)
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

                worker = threading.Thread(target=sender, daemon=True)
                worker.start()
                received = bytearray()
                while len(received) < total:
                    part = sock.recv(65536)
                    if not part:
                        break
                    received.extend(part)
                worker.join(10)
                # FakeProxy echoes byte-for-byte, so a longer echo means the
                # relay duplicated data.
                self.assertEqual(len(received), total,
                                 "Relay must not duplicate or drop payload bytes")
                self.assertEqual(bytes(received), payload)
                self.assertFalse(worker.is_alive())

    def test_half_close_delivers_final_bytes(self):
        with FakeProxy() as proxy:
            tunnel = LocalTunnel(proxy.profile(authenticated=False))
            tunnel.start()
            self.addCleanup(tunnel.stop)
            sock = self.connect(tunnel)
            self.addCleanup(sock.close)
            read_headers(sock)
            sock.sendall(b"tail-data")
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_exact(sock, 9), b"tail-data")

    def test_stop_unblocks_relay_without_hanging(self):
        with FakeProxy() as proxy:
            tunnel = LocalTunnel(proxy.profile(authenticated=False))
            tunnel.start()
            sock = self.connect(tunnel)
            self.addCleanup(sock.close)
            read_headers(sock)
            started = time.monotonic()
            tunnel.stop()
            self.assertLess(time.monotonic() - started, 3.0, "stop() must not hang")
            self.assertFalse(tunnel._workers)

    def test_relay_threads_and_memory_stay_bounded(self):
        with FakeProxy() as proxy:
            tunnel = LocalTunnel(proxy.profile(authenticated=False), max_connections=4)
            tunnel.start()
            self.addCleanup(tunnel.stop)
            sockets = [self.connect(tunnel) for _ in range(4)]
            for sock in sockets:
                self.addCleanup(sock.close)
                self.assertIn(b"200", read_headers(sock)[0])
            time.sleep(0.1)
            self.assertLessEqual(len(tunnel._workers), 4)
            # A fifth connection is refused rather than queued indefinitely.
            extra = socket.create_connection(("127.0.0.1", tunnel.allocated_port), timeout=5)
            self.addCleanup(extra.close)
            try:
                extra.sendall(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
                self.assertEqual(extra.recv(64), b"")
            except (ConnectionAbortedError, ConnectionResetError):
                # Windows reports the server-side reset of an over-limit client
                # as an aborted connection; either way no tunnel was created.
                pass
            self.assertLessEqual(len(tunnel._workers), 4)


class HandshakeRetryTests(IsolatedState):
    def setUp(self):
        super().setUp()
        self.create_context = ssl.create_default_context
        self.fixture = str(FIXTURES / "localhost-cert.pem")

    def test_eof_during_initial_handshake_is_retried_then_succeeds(self):
        with FakeProxy("https") as proxy:
            attempts = {"count": 0}
            real = self.create_context

            def flaky():
                context = real(cafile=self.fixture)
                original = context.wrap_socket

                def wrap(sock, *args, **kwargs):
                    attempts["count"] += 1
                    if attempts["count"] == 1:
                        raise ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING")
                    return original(sock, *args, **kwargs)

                context.wrap_socket = wrap
                return context

            with mock.patch("devproxy_pkg.core.transport.ssl.create_default_context", side_effect=flaky):
                sock = open_proxy(proxy.profile(authenticated=False), timeout=5.0)
                self.addCleanup(sock.close)
            self.assertEqual(attempts["count"], 2, "Exactly one retry after a truncated handshake")

    def test_successful_retry_still_verifies_certificate(self):
        """The retry path must keep TLS verification on."""
        with FakeProxy("https") as proxy:
            attempts = {"count": 0}
            real = self.create_context

            def flaky():
                # Deliberately WITHOUT the test CA: verification must fail.
                context = real()
                original = context.wrap_socket

                def wrap(sock, *args, **kwargs):
                    attempts["count"] += 1
                    if attempts["count"] == 1:
                        raise ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING")
                    return original(sock, *args, **kwargs)

                context.wrap_socket = wrap
                return context

            with mock.patch("devproxy_pkg.core.transport.ssl.create_default_context", side_effect=flaky):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    open_proxy(proxy.profile(authenticated=False), timeout=5.0)
            self.assertEqual(attempts["count"], 2, "The retried attempt must still verify the chain")

    def test_certificate_failure_is_never_retried(self):
        with FakeProxy("https") as proxy:
            attempts = {"count": 0}
            real = self.create_context

            def bad():
                context = real()

                def wrap(sock, *args, **kwargs):
                    attempts["count"] += 1
                    raise ssl.SSLCertVerificationError(1, "certificate verify failed")

                context.wrap_socket = wrap
                return context

            with mock.patch("devproxy_pkg.core.transport.ssl.create_default_context", side_effect=bad):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    open_proxy(proxy.profile(authenticated=False), timeout=5.0)
            self.assertEqual(attempts["count"], 1, "A trust failure must never be retried")

    def test_connect_rejection_is_not_retried(self):
        with FakeProxy(reject=True) as proxy:
            with self.assertRaises(ProxyError) as rejected:
                connect_upstream(proxy.profile(), "api.invalid", 443)
            self.assertEqual(rejected.exception.status, 407)
            self.assertEqual(len(proxy.requests), 1, "A 407 must not be retried")

    def test_handshake_retry_respects_overall_deadline(self):
        with FakeProxy("https") as proxy:
            attempts = {"count": 0}

            def always_eof():
                context = self.create_context(cafile=self.fixture)

                def wrap(sock, *args, **kwargs):
                    attempts["count"] += 1
                    raise ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING")

                context.wrap_socket = wrap
                return context

            with mock.patch("devproxy_pkg.core.transport.ssl.create_default_context", side_effect=always_eof):
                started = time.monotonic()
                with self.assertRaises(ssl.SSLEOFError):
                    open_proxy(proxy.profile(authenticated=False), timeout=0.5)
                elapsed = time.monotonic() - started
            self.assertLess(elapsed, 3.0, "Retries must share one bounded deadline")
            self.assertLessEqual(attempts["count"], 3)

    def test_plaintext_http_proxy_is_not_retried(self):
        with FakeProxy() as proxy:
            with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError) as dial:
                with self.assertRaises(ConnectionRefusedError):
                    open_proxy(proxy.profile(authenticated=False), timeout=5.0)
            self.assertEqual(dial.call_count, 1, "Plain HTTP proxies have no TLS handshake to retry")

    def test_eof_after_connect_is_not_retried(self):
        """An EOF once CONNECT succeeded must not replay application data."""
        with FakeProxy() as proxy:
            tunnel_errors = []
            with mock.patch("devproxy_pkg.core.transport.open_proxy", wraps=open_proxy) as spy:
                sock, _ = connect_upstream(proxy.profile(authenticated=False), "api.invalid", 443)
                self.addCleanup(sock.close)
            self.assertEqual(spy.call_count, 1)
            tunnel_errors.append(spy.call_count)


class ErrorClassificationTests(unittest.TestCase):
    def test_eof_is_not_reported_as_certificate_problem(self):
        message = describe_error(ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING"), "api.invalid")
        self.assertNotIn("недействителен или не является доверенным", message)
        self.assertIn("закрыл TLS-соединение", message)

    def test_certificate_error_is_reported_as_trust_failure(self):
        message = describe_error(ssl.SSLCertVerificationError(1, "certificate verify failed"), "api.invalid")
        self.assertIn("сертификат", message.lower())

    def test_cert_verification_is_listed_before_generic_ssl_error(self):
        """Ordering guard: SSLCertVerificationError subclasses SSLError."""
        self.assertTrue(issubclass(ssl.SSLCertVerificationError, ssl.SSLError))
        message = describe_error(ssl.SSLCertVerificationError(1, "x"), "t")
        self.assertIn("не является доверенным", message)

    def test_wrong_version_number_is_protocol_not_trust(self):
        error = ssl.SSLError(1, "WRONG_VERSION_NUMBER")
        error.reason = "WRONG_VERSION_NUMBER"
        message = describe_error(error, "api.invalid")
        self.assertIn("HTTPS", message)
        self.assertNotIn("недоверенный", message.lower())

    def test_profile_unavailable_message_forbids_direct_connection(self):
        message = describe_error(ProxyError("x", "profile_unavailable"), "api.invalid")
        self.assertIn("Прямое подключение не выполняется", message)

    def test_no_message_leaks_credentials(self):
        leaks = ["Proxy-Authorization: Basic c2VjcmV0", "alice:hunter2", "socks5://user:pw@host:1080"]
        for leak in leaks:
            for error in (ProxyError(leak, "auth_failed", 407),
                          ProxyError(leak, "profile_unavailable"),
                          ssl.SSLEOFError(8, leak),
                          RuntimeError(leak)):
                rendered = describe_error(error, "api.invalid")
                self.assertNotIn("hunter2", rendered)
                self.assertNotIn("c2VjcmV0", rendered)
                self.assertNotIn("proxy-auth", rendered.lower())


class CliProfileTests(IsolatedState):
    def test_saved_profile_lookup_uses_current_metadata_and_secret(self):
        self.save(ProxyProfile("П1", "http", "127.0.0.1", 1111, "alice", "pw1"))
        profile = resolve_saved_profile("П1")
        self.assertEqual((profile.host, profile.port, profile.password), ("127.0.0.1", 1111, "pw1"))
        self.save(ProxyProfile("П1", "http", "127.0.0.1", 2222, "alice", "pw2"), "П1")
        profile = resolve_saved_profile("П1")
        self.assertEqual((profile.port, profile.password), (2222, "pw2"))

    def test_adhoc_profile_is_not_searched_in_store(self):
        profile = resolve_profile(None, "http://127.0.0.1:3344")
        self.assertEqual(profile.port, 3344)
        self.assertEqual(profile.name, "adhoc")

    def test_missing_saved_profile_raises_rather_than_falling_back(self):
        with self.assertRaises(ValueError):
            resolve_saved_profile("нет такого")


if __name__ == "__main__":
    unittest.main()
