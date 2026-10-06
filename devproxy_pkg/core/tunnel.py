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
from .transport import connect_upstream, open_proxy, auth_header, read_headers, ProxyError
from .user_errors import describe_error

LOG = logging.getLogger("devproxy.tunnel")


class LocalTunnel:
    def __init__(self, profile, bind_host="127.0.0.1", bind_port=0,
                 max_connections=64, handshake_timeout=10.0, idle_timeout=120.0):
        if not ipaddress.ip_address(bind_host).is_loopback:
            raise ValueError("Local listener must use a loopback address")
        if max_connections < 1 or handshake_timeout <= 0 or idle_timeout <= 0:
            raise ValueError("Limits and timeouts must be positive")
        self.profile, self.bind_host, self.bind_port = profile, bind_host, bind_port
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
        sock.close()

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
        try:
            client.settimeout(self.handshake_timeout)
            headers, tail = read_headers(client)
            lines = headers.split(b"\r\n")
            method, target, protocol = lines[0].decode("ascii").split()
            if protocol not in ("HTTP/1.0", "HTTP/1.1") or not method.isalpha():
                raise ValueError("Invalid request line")
            host, port, parsed = self._destination(target, method == "CONNECT")
            valid_request = True
            forward_http = method != "CONNECT" and not self.profile.is_socks
            if forward_http:
                upstream = open_proxy(self.profile, self.handshake_timeout, self._track)
                upstream_tail = b""
            else:
                upstream, upstream_tail = connect_upstream(self.profile, host, port, self.handshake_timeout, self._track)
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + upstream_tail)
            else:
                path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                if forward_http:
                    path = urllib.parse.urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, ""))
                clean = [line for line in lines[1:] if not line.lower().startswith((b"proxy-authorization:", b"proxy-connection:", b"connection:"))]
                request = f"{method} {path} {protocol}\r\n".encode("ascii")
                credentials = auth_header(self.profile) if forward_http else b""
                upstream.sendall(request + b"\r\n".join(clean) + b"\r\n" + credentials + b"Connection: close\r\n\r\n")
                if upstream_tail:
                    client.sendall(upstream_tail)
            established = True
            self.last_error = None
            if tail:
                upstream.sendall(tail)
            self._pipe_duplex(client, upstream)
        except (ValueError, UnicodeError) as exc:
            if not established:
                if valid_request:
                    self.last_error = describe_error(exc, host if 'host' in locals() else "целевой сервер")
                self._error(client, 502 if valid_request else 400, "Bad Gateway" if valid_request else "Bad Request")
        except Exception as exc:
            if not self._stop.is_set():
                self.last_error = describe_error(exc, host if 'host' in locals() else "целевой сервер")
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

    def _pipe_duplex(self, client, upstream):
        peers = {client: upstream, upstream: client}
        buffers = {client: bytearray(), upstream: bytearray()}
        eof, write_closed = set(), set()
        for sock in peers:
            sock.setblocking(False)
        last_activity = time.monotonic()
        while not self._stop.is_set():
            for source, dest in peers.items():
                if source in eof and not buffers[dest] and dest not in write_closed:
                    try:
                        dest.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    write_closed.add(dest)
            if len(eof) == 2 and not any(buffers.values()):
                break
            remaining = self.idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                break
            readers = [s for s in peers if s not in eof and len(buffers[peers[s]]) < 65536]
            writers = [s for s in peers if buffers[s]]
            buffered = [s for s in readers if hasattr(s, "pending") and s.pending()]
            ready, writable, errors = select.select(readers, writers, list(peers), 0 if buffered else min(0.2, remaining))
            ready = list(dict.fromkeys(buffered + ready))
            if errors:
                break
            for dest in writable:
                try:
                    size = dest.send(buffers[dest])
                    if not size:
                        raise OSError("Peer closed during send")
                    del buffers[dest][:size]
                    last_activity = time.monotonic()
                except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            for source in ready:
                dest = peers[source]
                try:
                    data = source.recv(min(32768, 65536 - len(buffers[dest])))
                except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
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
