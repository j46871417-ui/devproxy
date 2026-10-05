"""Loopback HTTP bridge to a designated HTTP, HTTPS or SOCKS5 upstream."""
import ipaddress
import re
import select
import socket
import ssl
import threading
import time
import urllib.parse
from .transport import (read_headers, parse_authority, authority, connect_upstream,
                        http_connect, socks5_connect, proxy_auth_header)


class LocalTunnel:
    def __init__(self, profile, bind_host='127.0.0.1', bind_port=0, idle_timeout=None):
        if not ipaddress.ip_address(bind_host).is_loopback:
            raise ValueError('Tunnel listener must use a loopback address.')
        self.profile, self.bind_host, self.bind_port = profile, bind_host, bind_port
        self.idle_timeout = idle_timeout
        self.server_sock = None
        self.is_running = False
        self.allocated_port = 0
        self._thread = None
        self._lock = threading.Lock()
        self._connections = set()
        self._workers = set()

    def start(self, timeout=3):
        if self.is_running:
            return self.allocated_port
        family = socket.AF_INET6 if ':' in self.bind_host else socket.AF_INET
        server = socket.socket(family, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_host, self.bind_port))
            server.listen(128)
            server.settimeout(0.2)
        except Exception:
            server.close()
            raise
        self.server_sock = server
        self.allocated_port = server.getsockname()[1]
        self.is_running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True, name='DevProxyTunnel')
        self._thread.start()
        return self.allocated_port

    def stop(self):
        self.is_running = False
        if self.server_sock:
            self.server_sock.close()
        with self._lock:
            sockets, workers = list(self._connections), list(self._workers)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for worker in [self._thread] + workers:
            if worker and worker is not threading.current_thread():
                worker.join(timeout=2)

    def _track(self, sock):
        with self._lock:
            if not self.is_running:
                sock.close()
                raise OSError('Proxy session stopped.')
            self._connections.add(sock)

    def _serve_loop(self):
        while self.is_running:
            try:
                client, _ = self.server_sock.accept()
                with self._lock:
                    if not self.is_running:
                        client.close()
                        break
                    if len(self._workers) >= 128:
                        client.close()
                        continue
                    self._connections.add(client)
                    worker = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                    self._workers.add(worker)
                worker.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client_sock):
        upstream, established = None, False
        try:
            client_sock.settimeout(15)
            headers, client_tail = read_headers(client_sock)
            lines = headers[:-4].split(b'\r\n')
            parts = lines[0].decode('ascii').split(' ')
            if len(parts) != 3 or parts[2] not in ('HTTP/1.0', 'HTTP/1.1'):
                raise ValueError('Invalid request line.')
            method, target, version = parts
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
                raise ValueError('Invalid request method.')
            fields = []
            for line in lines[1:]:
                key, separator, value = line.partition(b':')
                if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                    raise ValueError('Invalid request header.')
                if b'\r' in value or b'\n' in value or b'\x00' in value:
                    raise ValueError('Invalid request header value.')
                if key.lower() not in (b'proxy-authorization', b'proxy-connection'):
                    fields.append((key, value.strip()))
            if method == 'CONNECT':
                host, port = parse_authority(target)
            else:
                parsed = urllib.parse.urlsplit(target)
                if parsed.scheme:
                    if parsed.scheme != 'http' or parsed.username is not None or parsed.fragment:
                        raise ValueError('Use CONNECT for HTTPS destinations.')
                    host, port = parse_authority(parsed.netloc, 80)
                else:
                    hosts = [v.decode('ascii') for k, v in fields if k.lower() == b'host']
                    if len(hosts) != 1 or not target.startswith('/'):
                        raise ValueError('Missing/ambiguous destination host.')
                    host, port = parse_authority(hosts[0], 80)
                    parsed = urllib.parse.urlsplit('http://' + authority(host, port) + target)
            try:
                upstream = connect_upstream(self.profile)
                self._track(upstream)
                if self.profile.is_socks:
                    if not self._socks5_connect_upstream(upstream, host, port):
                        raise OSError('SOCKS5 handshake rejected.')
                    server_tail = b''
                elif method == 'CONNECT':
                    server_tail = http_connect(upstream, self.profile, host, port)
                else:
                    server_tail = b''
            except (OSError, ValueError):
                client_sock.sendall(b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                return
            if method == 'CONNECT':
                client_sock.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n' + server_tail)
                if client_tail:
                    upstream.sendall(client_tail)
            else:
                request_target = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
                if not self.profile.is_socks:
                    request_target = 'http://' + authority(host, port) + request_target
                fields = [(k, v) for k, v in fields if k.lower() != b'host']
                fields.insert(0, (b'Host', authority(host, port).encode('ascii')))
                lengths = [v for k, v in fields if k.lower() == b'content-length']
                encodings = [v.lower() for k, v in fields if k.lower() == b'transfer-encoding']
                if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
                    raise ValueError('Ambiguous HTTP request framing.')
                if lengths and (not lengths[0].isdigit() or len(lengths[0]) > 18):
                    raise ValueError('Invalid Content-Length.')
                if encodings and encodings != [b'chunked']:
                    raise ValueError('Unsupported Transfer-Encoding.')
                expects = [v.lower() for k, v in fields if k.lower() == b'expect']
                if expects and expects != [b'100-continue']:
                    raise ValueError('Unsupported Expect header.')
                fields = [(k, v) for k, v in fields if k.lower() not in (b'connection', b'expect')]
                fields.append((b'Connection', b'close'))
                request = f'{method} {request_target} {version}\r\n'.encode('ascii')
                request += b''.join(k + b': ' + v + b'\r\n' for k, v in fields)
                if not self.profile.is_socks:
                    request += proxy_auth_header(self.profile)
                upstream.sendall(request + b'\r\n')
                if expects:
                    client_sock.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
                self._forward_http_body(client_sock, upstream, client_tail, lengths, encodings)
                established = True
                client_sock.settimeout(None)
                upstream.settimeout(None)
                while True:
                    data = upstream.recv(32768)
                    if not data:
                        break
                    client_sock.sendall(data)
                return
            established = True
            self._pipe_duplex(client_sock, upstream)
        except (OSError, ValueError, UnicodeError):
            if not established:
                try:
                    client_sock.sendall(b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                except OSError:
                    pass
        finally:
            for sock in (client_sock, upstream):
                if sock is not None:
                    sock.close()
                    with self._lock:
                        self._connections.discard(sock)
            with self._lock:
                self._workers.discard(threading.current_thread())

    @staticmethod
    def _forward_http_body(client, upstream, prefix, lengths, encodings):
        # Exactly one HTTP message: pipelined requests cannot leak their proxy
        # authorization or change destination on an established SOCKS stream.
        buffered = bytearray(prefix)

        def take(count):
            result = bytearray()
            while len(result) < count:
                if not buffered:
                    part = client.recv(min(32768, count - len(result)))
                    if not part:
                        raise OSError('Incomplete HTTP body.')
                    buffered.extend(part)
                amount = min(count - len(result), len(buffered))
                result.extend(buffered[:amount])
                del buffered[:amount]
            return bytes(result)

        def line():
            result = bytearray()
            while not result.endswith(b'\r\n'):
                if len(result) >= 8192:
                    raise ValueError('Chunk header exceeds limit.')
                result.extend(take(1))
            return bytes(result)

        if encodings:
            while True:
                header = line()
                size_text = header[:-2].split(b';', 1)[0]
                if not size_text or any(c not in b'0123456789abcdefABCDEF' for c in size_text) or len(size_text) > 16:
                    raise ValueError('Invalid chunk size.')
                size = int(size_text, 16)
                if size == 0:
                    upstream.sendall(b'0\r\n')
                    total = 0
                    while True:
                        trailer = line()
                        total += len(trailer)
                        if total > 65536:
                            raise ValueError('Trailers exceed limit.')
                        if trailer == b'\r\n':
                            upstream.sendall(trailer)
                            return
                        name, separator, _ = trailer.partition(b':')
                        if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or b'\x00' in trailer:
                            raise ValueError('Invalid trailer.')
                        if name.lower() not in (b'proxy-authorization', b'proxy-connection', b'connection', b'content-length', b'transfer-encoding', b'host'):
                            upstream.sendall(trailer)
                upstream.sendall(header)
                while size:
                    data = take(min(size, 32768))
                    upstream.sendall(data)
                    size -= len(data)
                if take(2) != b'\r\n':
                    raise ValueError('Invalid chunk terminator.')
                upstream.sendall(b'\r\n')
        else:
            size = int(lengths[0]) if lengths else 0
            while size:
                data = take(min(size, 32768))
                upstream.sendall(data)
                size -= len(data)

    def _socks5_connect_upstream(self, sock, host, port):
        try:
            socks5_connect(sock, self.profile, host, port)
            return True
        except (OSError, ValueError):
            return False

    def _pipe_duplex(self, first, second):
        """One I/O owner, bounded queues, partial writes, TLS readiness, half-close."""
        peers = {first: second, second: first}
        queued = {first: bytearray(), second: bytearray()}
        pending = {first: b'', second: b''}
        readable = {first: True, second: True}
        half_closed = set()
        read_wants_write, write_wants_read = set(), set()
        last_activity = time.monotonic()
        for sock in peers:
            sock.setblocking(False)
        while any(readable.values()) or any(queued.values()) or any(pending.values()):
            reads, writes = [], []
            for sock, peer in peers.items():
                if readable[sock] and len(queued[peer]) < 1024 * 1024:
                    (writes if sock in read_wants_write else reads).append(sock)
                if pending[sock] or queued[sock]:
                    (reads if sock in write_wants_read else writes).append(sock)
                if not readable[peer] and not queued[sock] and not pending[sock] and sock not in half_closed:
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    half_closed.add(sock)
            r, w, _ = select.select(reads, writes, [], 0.2)
            for sock in peers:
                if isinstance(sock, ssl.SSLSocket) and sock.pending() and readable[sock] and len(queued[peers[sock]]) < 1024 * 1024:
                    if sock not in r:
                        r.append(sock)
            for sock in peers:
                can_write = sock in (r if sock in write_wants_read else w)
                if can_write and (pending[sock] or queued[sock]):
                    if not pending[sock]:
                        pending[sock] = bytes(queued[sock][:32768])
                        del queued[sock][:len(pending[sock])]
                    try:
                        sent = sock.send(pending[sock])
                        if sent == 0:
                            raise OSError('Socket stopped accepting data.')
                        pending[sock] = pending[sock][sent:]
                        write_wants_read.discard(sock)
                        last_activity = time.monotonic()
                    except ssl.SSLWantReadError:
                        write_wants_read.add(sock)
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        write_wants_read.discard(sock)
                can_read = sock in (w if sock in read_wants_write else r)
                if can_read and readable[sock] and len(queued[peers[sock]]) < 1024 * 1024:
                    try:
                        data = sock.recv(32768)
                        if data:
                            queued[peers[sock]].extend(data)
                            last_activity = time.monotonic()
                        else:
                            readable[sock] = False
                        read_wants_write.discard(sock)
                    except ssl.SSLWantWriteError:
                        read_wants_write.add(sock)
                    except (ssl.SSLWantReadError, BlockingIOError):
                        read_wants_write.discard(sock)
            if self.idle_timeout is not None and time.monotonic() - last_activity >= self.idle_timeout:
                return
