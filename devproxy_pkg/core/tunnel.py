"""Bounded loopback HTTP bridge. No direct destination connections."""
import ipaddress
import logging
import select
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
from collections import OrderedDict, deque
from dataclasses import replace
from .transport import connect_upstream, open_proxy, auth_header, read_headers, ProxyError
from .user_errors import describe_error

LOG = logging.getLogger("devproxy.tunnel")

MAX_FAILURES = 16
MAX_HISTORY = 32
MAX_BUFFER = 65536
CHUNK = 32768


def snapshot_profile(provider, fallback):
    """One immutable view of the profile for a single new connection.

    The provider reads current saved metadata and the secret together, so a
    connection never mixes a new port with an old password. Existing streams
    keep the object they opened with; only new streams see the update.
    """
    if provider is None:
        return fallback
    try:
        profile = provider()
    except Exception as error:
        raise _profile_error(error) from None
    if profile is None:
        raise _profile_error(None)
    return replace(profile)


def _profile_error(cause):
    error = ProxyError("Сохранённый профиль недоступен"
                       + (": " + type(cause).__name__ if cause is not None else ""),
                       "profile_unavailable")
    # Stage is set here so later handshake code cannot relabel it as a connect
    # failure, and so diagnostics can name the real cause.
    error.devproxy_phase = "profile"
    return error


class LocalTunnel:
    def __init__(self, profile, bind_host="127.0.0.1", bind_port=0,
                 max_connections=64, handshake_timeout=10.0, idle_timeout=120.0,
                 profile_provider=None):
        if not ipaddress.ip_address(bind_host).is_loopback:
            raise ValueError("Local listener must use a loopback address")
        if max_connections < 1 or handshake_timeout <= 0 or idle_timeout <= 0:
            raise ValueError("Limits and timeouts must be positive")
        self.profile, self.bind_host, self.bind_port = profile, bind_host, bind_port
        self.profile_provider = profile_provider
        self.handshake_timeout, self.idle_timeout = handshake_timeout, idle_timeout
        self.server_sock = None
        self.allocated_port = 0
        self.is_running = False
        self._thread = None
        self._lock = threading.RLock()
        self._workers, self._sockets = set(), set()
        self._slots = threading.BoundedSemaphore(max_connections)
        self._stop = threading.Event()
        self.session_id = uuid.uuid4().hex
        self.last_error = None
        self._failures = OrderedDict()
        self._history = deque(maxlen=MAX_HISTORY)
        self._success_count = self._failure_count = 0

    def _record_failure(self, error, host, port, phase):
        entry = {"host": host, "port": port, "phase": getattr(error, "devproxy_phase", phase),
                 "type": type(error).__name__, "code": getattr(error, "code", None),
                 "status": getattr(error, "status", None), "time": time.time(),
                 "message": describe_error(error, host)}
        with self._lock:
            key = (host, port)
            self._failures.pop(key, None)
            self._failures[key] = entry
            while len(self._failures) > MAX_FAILURES:
                self._failures.popitem(last=False)
            self._history.append(entry)
            self._failure_count += 1
            self.last_error = entry["message"]

    def _record_success(self, host, port):
        """Clear only this destination's error; other destinations stay visible."""
        with self._lock:
            self._failures.pop((host, port), None)
            self._success_count += 1
            self.last_error = next(reversed(self._failures.values()))["message"] if self._failures else None

    def diagnostics(self):
        with self._lock:
            route = self.profile_provider.route_status() if hasattr(self.profile_provider, "route_status") else None
            return {"profile": self.profile.name, "port": self.allocated_port, "running": self.is_running,
                    "connections": len(self._workers), "succeeded": self._success_count,
                    "failed": self._failure_count, "failures": [dict(e) for e in self._failures.values()],
                    "recent_failures": [dict(e) for e in self._history], "error": self.last_error, "route": route}

    @property
    def proxy_url(self):
        host = f"[{self.bind_host}]" if ":" in self.bind_host else self.bind_host
        return f"http://{host}:{self.allocated_port}"

    def start(self, timeout=3.0):
        with self._lock:
            if self.is_running:
                return self.allocated_port
            self._stop.clear()
            sock = socket.socket(socket.AF_INET6 if ":" in self.bind_host else socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind((self.bind_host, self.bind_port))
                sock.listen(64)
                sock.settimeout(0.2)
            except BaseException:
                sock.close()
                raise
            self.server_sock = sock
            self.allocated_port = sock.getsockname()[1]
            self.is_running = True
            self._thread = threading.Thread(target=self._serve_loop, args=(sock,), daemon=True)
            self._thread.start()
        LOG.info("listener_started session=%s", self.session_id)
        return self.allocated_port

    @staticmethod
    def _close(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def stop(self):
        with self._lock:
            self.is_running = False
            self._stop.set()
            listener, self.server_sock = self.server_sock, None
            sockets = tuple(self._sockets)
        if listener:
            self._close(listener)
        for sock in sockets:
            self._close(sock)
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(1.0)
        deadline = time.monotonic() + self.handshake_timeout + 1
        with self._lock:
            workers = tuple(self._workers)
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        LOG.info("listener_stopped session=%s", self.session_id)

    def _track(self, sock, replaced=None):
        with self._lock:
            if replaced:
                self._sockets.discard(replaced)
            if self._stop.is_set():
                self._close(sock)
                raise ProxyError("Session stopped")
            self._sockets.add(sock)

    def _serve_loop(self, listener):
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop.is_set():
                client.close()
                break
            if not self._slots.acquire(blocking=False):
                client.close()
                continue
            worker = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
            with self._lock:
                self._sockets.add(client)
                self._workers.add(worker)
                worker.start()

    @staticmethod
    def _destination(target, connect):
        parsed = urllib.parse.urlsplit("//" + target if connect else target)
        if not connect and parsed.scheme != "http":
            raise ValueError("Use CONNECT for HTTPS")
        if parsed.username is not None or parsed.password is not None or not parsed.hostname:
            raise ValueError("Invalid request destination")
        host = parsed.hostname
        if any(ord(c) <= 32 or ord(c) == 127 for c in host):
            raise ValueError("Invalid request hostname")
        return host, parsed.port or (443 if connect else 80), parsed

    def _handle_client(self, client):
        upstream = None
        established = False
        valid_request = False
        host = port = None
        try:
            client.settimeout(self.handshake_timeout)
            headers, tail = read_headers(client)
            lines = headers.split(b"\r\n")
            method, target, protocol = lines[0].decode("ascii").split()
            if protocol not in ("HTTP/1.0", "HTTP/1.1") or not method.isalpha():
                raise ValueError("Invalid request line")
            host, port, parsed = self._destination(target, method == "CONNECT")
            valid_request = True
            profile = snapshot_profile(self.profile_provider, self.profile)
            forward_http = method != "CONNECT" and not profile.is_socks
            connector = getattr(self.profile_provider, "open_connection", None)
            if connector is not None:
                upstream, upstream_tail, profile = connector(host, port, self.handshake_timeout,
                                                            self._track, forward_http)
            elif forward_http:
                upstream = open_proxy(profile, self.handshake_timeout, self._track)
                upstream_tail = b""
            else:
                upstream, upstream_tail = connect_upstream(profile, host, port, self.handshake_timeout, self._track)
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + upstream_tail)
            else:
                path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                if forward_http:
                    path = urllib.parse.urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, ""))
                clean = [line for line in lines[1:] if not line.lower().startswith((b"proxy-authorization:", b"proxy-connection:", b"connection:"))]
                request = f"{method} {path} {protocol}\r\n".encode("ascii")
                credentials = auth_header(profile) if forward_http else b""
                upstream.sendall(request + b"\r\n".join(clean) + b"\r\n" + credentials + b"Connection: close\r\n\r\n")
                if upstream_tail:
                    client.sendall(upstream_tail)
            established = True
            self._record_success(host, port)
            if tail:
                upstream.sendall(tail)
            self._pipe_duplex(client, upstream)
        except (ValueError, UnicodeError) as exc:
            if not established and valid_request:
                self._record_failure(exc, host, port, "profile")
            self._error(client, 502 if valid_request else 400, "Bad Gateway" if valid_request else "Bad Request")
        except Exception as exc:
            if not self._stop.is_set() and valid_request:
                self._record_failure(exc, host, port, "relay" if established else "connect")
            LOG.warning("connection_failed session=%s error=%s", self.session_id, type(exc).__name__)
            if not established:
                self._error(client, 502, "Bad Gateway")
        finally:
            for sock in (client, upstream):
                if sock:
                    self._close(sock)
                    with self._lock:
                        self._sockets.discard(sock)
            with self._lock:
                self._sockets = {s for s in self._sockets if s.fileno() != -1}
                self._workers.discard(threading.current_thread())
            self._slots.release()

    @staticmethod
    def _error(client, status, phrase):
        try:
            client.sendall(f"HTTP/1.1 {status} {phrase}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        except OSError:
            pass

    @staticmethod
    def _half_close(sock):
        """Close only the write direction of a *plain* socket.

        ``socket.shutdown(SHUT_WR)`` acts on the raw file descriptor. On an
        ``SSLSocket`` that bypasses OpenSSL: it emits a bare TCP FIN with no TLS
        close_notify and desynchronises the record layer, so the peer then reads
        ciphertext instead of plaintext (reproduced: a 256 KiB echo over an
        HTTPS proxy arrives corrupted at the first half-close). Calling
        ``unwrap()`` instead is not safe either -- it waits for the peer's
        close_notify and truncates the stream under a non-blocking relay.

        TLS endpoints are therefore left open in the write direction; the relay
        keeps serving the opposite direction and the final close tears the
        connection down. Returns True only when an fd-level half-close happened.
        """
        if isinstance(sock, ssl.SSLSocket):
            return False
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return True

    def _pipe_duplex(self, client, upstream):
        """Bounded relay with direction-aware SSL retries and visible failures."""
        peers = {client: upstream, upstream: client}
        buffers = {sock: bytearray() for sock in peers}
        pending = {sock: None for sock in peers}
        read_wait = {sock: "read" for sock in peers}
        write_wait = {sock: "write" for sock in peers}
        eof, write_closed = set(), set()
        for sock in peers:
            sock.setblocking(False)
        last_activity = time.monotonic()
        while not self._stop.is_set():
            for source, dest in peers.items():
                if source in eof and not buffers[dest] and dest not in write_closed:
                    self._half_close(dest)
                    write_closed.add(dest)
            if len(eof) == 2 and not any(buffers.values()):
                return
            remaining = self.idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                return
            read_ops = [s for s in peers if s not in eof and len(buffers[peers[s]]) < MAX_BUFFER]
            write_ops = [s for s in peers if buffers[s]]
            readers = list({s for s in read_ops if read_wait[s] == "read"} |
                           {s for s in write_ops if write_wait[s] == "read"})
            writers = list({s for s in read_ops if read_wait[s] == "write"} |
                           {s for s in write_ops if write_wait[s] == "write"})
            decrypted = {s for s in read_ops if read_wait[s] == "read"
                         and getattr(s, "pending", None) and s.pending()}
            ready, writable, errors = select.select(readers, writers, list(peers),
                                                    0 if decrypted else min(.2, remaining))
            if self._stop.is_set():
                return
            if errors:
                raise ConnectionResetError("Socket exception during relay")
            ready, writable = set(ready) | decrypted, set(writable)
            for dest in write_ops:
                if dest not in (ready if write_wait[dest] == "read" else writable):
                    continue
                if pending[dest] is None:
                    pending[dest] = bytes(buffers[dest][:CHUNK])
                try:
                    size = dest.send(pending[dest])
                    if not size:
                        raise ConnectionResetError("Peer closed during send")
                except ssl.SSLWantReadError:
                    write_wait[dest] = "read"
                    continue
                except (BlockingIOError, InterruptedError, ssl.SSLWantWriteError):
                    write_wait[dest] = "write"
                    continue
                del buffers[dest][:size]
                pending[dest] = None
                write_wait[dest] = "write"
                last_activity = time.monotonic()
            for source in read_ops:
                if source not in (ready if read_wait[source] == "read" else writable):
                    continue
                dest = peers[source]
                try:
                    data = source.recv(min(CHUNK, MAX_BUFFER - len(buffers[dest])))
                except ssl.SSLWantWriteError:
                    read_wait[source] = "write"
                    continue
                except (BlockingIOError, InterruptedError, ssl.SSLWantReadError):
                    read_wait[source] = "read"
                    continue
                read_wait[source] = "read"
                if data:
                    buffers[dest].extend(data)
                    last_activity = time.monotonic()
                else:
                    eof.add(source)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()
