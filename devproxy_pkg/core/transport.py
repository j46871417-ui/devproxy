"""Shared upstream handshake. Destination DNS stays at the selected proxy."""
import base64
import ipaddress
import socket
import ssl
import time
import threading
import weakref

# Only a truncated initial TLS handshake to the proxy is worth retrying: the
# connection is not yet authenticated and carries no application bytes, so a
# replay cannot duplicate a request. Everything after CONNECT is never retried.
TRANSIENT_TLS = (ssl.SSLEOFError, ConnectionResetError, ssl.SSLZeroReturnError)
HANDSHAKE_ATTEMPTS = 3
_TLS_GATES = weakref.WeakValueDictionary()
_TLS_GATES_LOCK = threading.Lock()


def _tls_gate(profile):
    # Bound only initial handshakes per endpoint, not established streams.
    # Idle endpoints disappear from the registry without growing global state.
    with _TLS_GATES_LOCK:
        key = (profile.host, profile.port)
        gate = _TLS_GATES.get(key)
        if gate is None:
            gate = threading.BoundedSemaphore(2)
            _TLS_GATES[key] = gate
        return gate


class ProxyError(OSError):
    def __init__(self, message, code="protocol_error", status=None):
        super().__init__(message)
        self.code = code
        self.status = status


def tag_phase(error, phase):
    """Record the failing stage on the exception for safe diagnostics."""
    if isinstance(error, Exception) and not hasattr(error, "devproxy_phase"):
        try:
            error.devproxy_phase = phase
        except (AttributeError, TypeError):
            pass
    return error


def remaining(deadline):
    return max(0.0, deadline - time.monotonic())


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProxyError("Unexpected EOF during handshake")
        data.extend(chunk)
    return bytes(data)


def read_headers(sock, limit=32768):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            raise ProxyError("Incomplete HTTP headers")
        data.extend(chunk)
        if len(data) > limit:
            raise ProxyError("HTTP headers exceed limit")
    return bytes(data).split(b"\r\n\r\n", 1)


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def socks_connect(sock, profile, host, port):
    method = 2 if profile.has_auth else 0
    sock.sendall(bytes((5, 1, method)))
    if recv_exact(sock, 2) != bytes((5, method)):
        raise ProxyError("SOCKS5 authentication method rejected", "auth_method")
    if method == 2:
        user = (profile.username or "").encode("utf-8")
        password = (profile.password or "").encode("utf-8")
        if not 1 <= len(user) <= 255 or not 1 <= len(password) <= 255:
            raise ProxyError("SOCKS5 credentials must contain 1..255 UTF-8 bytes", "credential_length")
        sock.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
        if recv_exact(sock, 2) != b"\x01\x00":
            raise ProxyError("SOCKS5 authentication failed", "auth_failed")
    try:
        ip = ipaddress.ip_address(host)
        address = bytes((1 if ip.version == 4 else 4,)) + ip.packed
    except ValueError:
        name = host.encode("idna")
        if not 1 <= len(name) <= 255:
            raise ProxyError("Invalid destination hostname length")
        address = bytes((3, len(name))) + name
    sock.sendall(b"\x05\x01\x00" + address + port.to_bytes(2, "big"))
    version, reply, reserved, kind = recv_exact(sock, 4)
    if version != 5 or reserved != 0 or reply != 0:
        raise ProxyError("SOCKS5 connection rejected", "destination_rejected", reply)
    if kind == 1:
        recv_exact(sock, 6)
    elif kind == 4:
        recv_exact(sock, 18)
    elif kind == 3:
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)
    else:
        raise ProxyError("Invalid SOCKS5 address type")


def auth_header(profile):
    if not profile.has_auth:
        return b""
    value = base64.b64encode(f"{profile.username or ''}:{profile.password or ''}".encode())
    return b"Proxy-Authorization: Basic " + value + b"\r\n"


def _tls_handshake(plain, host, timeout):
    """Complete the TLS handshake with certificate verification ON.

    The handshake is driven in blocking mode and the socket is returned to
    blocking state afterwards. Leaving a manually-driven handshake socket in a
    half-configured state makes later non-blocking reads hand back raw TLS
    records instead of plaintext, so the relay must receive a socket whose SSL
    layer was finalised by a normal, fully blocking handshake.
    """
    context = ssl.create_default_context()
    # Certificate verification stays on: no unverified context, ever.
    plain.settimeout(timeout)
    wrapped = context.wrap_socket(plain, server_hostname=host)
    try:
        wrapped.settimeout(timeout)
    except OSError:
        wrapped.close()
        raise
    return wrapped


def _discard(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def open_proxy(profile, timeout=10.0, on_socket=None):
    deadline = time.monotonic() + timeout
    if profile.protocol != "https":
        return _open_proxy(profile, timeout, on_socket)
    gate = _tls_gate(profile)
    if not gate.acquire(timeout=max(0, remaining(deadline))):
        raise tag_phase(TimeoutError("Proxy TLS handshake queue deadline exceeded"), "proxy_tls")
    try:
        return _open_proxy(profile, remaining(deadline), on_socket)
    finally:
        gate.release()


def _open_proxy(profile, timeout=10.0, on_socket=None):
    """Open (and TLS-wrap) the proxy connection.

    Retries are limited to a truncated handshake during the very first TLS
    negotiation with the proxy, share one overall deadline, and never apply to
    a certificate or protocol-version error.
    """
    deadline = time.monotonic() + timeout
    last_error = None
    for attempt in range(HANDSHAKE_ATTEMPTS):
        budget = remaining(deadline)
        if budget <= 0:
            if last_error is not None:
                raise tag_phase(last_error, "proxy_tls")
            raise TimeoutError("Proxy handshake deadline exceeded")
        sock = None
        phase = "proxy_tcp"
        try:
            sock = socket.create_connection((profile.host, profile.port), timeout=budget)
            if on_socket:
                on_socket(sock)
            if profile.protocol != "https":
                sock.settimeout(max(0.001, remaining(deadline)))
                return sock
            plain = sock
            phase = "proxy_tls"
            sock = _tls_handshake(plain, profile.host, max(0.001, remaining(deadline)))
            if on_socket:
                on_socket(sock, plain)
            sock.settimeout(max(0.001, remaining(deadline)))
            return sock
        except ssl.SSLCertVerificationError as error:
            # Never retried, never downgraded: report the trust failure as-is.
            _discard(sock)
            tag_phase(error, "proxy_tls")
            raise
        except BaseException as error:
            _discard(sock)
            tag_phase(error, phase)
            last_error = error
            retryable = (profile.protocol == "https"
                         and phase == "proxy_tls"
                         and isinstance(error, TRANSIENT_TLS)
                         and not isinstance(error, ssl.SSLCertVerificationError))
            if not retryable or attempt == HANDSHAKE_ATTEMPTS - 1:
                raise
            pause = min(0.1 * (attempt + 1), remaining(deadline))
            if pause <= 0:
                raise
            time.sleep(pause)
    raise tag_phase(last_error or ProxyError("Proxy handshake failed"), "proxy_tls")


def connect_upstream(profile, host, port, timeout=10.0, on_socket=None):
    sock = open_proxy(profile, timeout, on_socket)
    try:
        if profile.is_socks:
            socks_connect(sock, profile, host, port)
            return sock, b""
        dest = authority(host, port)
        request = f"CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n"
        sock.sendall(request.encode("ascii") + auth_header(profile) + b"\r\n")
        headers, tail = read_headers(sock)
        status = headers.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] != b"200":
            code = int(status[1]) if len(status) >= 2 and status[1].isdigit() else None
            raise ProxyError("HTTP CONNECT rejected", "auth_failed" if code == 407 else "http_rejected", code)
        return sock, tail
    except BaseException as error:
        sock.close()
        # Do not relabel an error that already knows its stage (for example a
        # profile lookup failure raised before this function was entered).
        tag_phase(error, "proxy_connect")
        raise
