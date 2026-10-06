"""Shared upstream handshake. Destination DNS stays at the selected proxy."""
import base64
import ipaddress
import socket
import ssl


class ProxyError(OSError):
    def __init__(self, message, code="protocol_error", status=None):
        super().__init__(message)
        self.code = code
        self.status = status


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


def open_proxy(profile, timeout=10.0, on_socket=None):
    sock = socket.create_connection((profile.host, profile.port), timeout=timeout)
    try:
        if on_socket:
            on_socket(sock)
        if profile.protocol == "https":
            plain = sock
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=profile.host)
            if on_socket:
                on_socket(sock, plain)
        sock.settimeout(timeout)
        return sock
    except BaseException:
        sock.close()
        raise


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
    except BaseException:
        sock.close()
        raise
