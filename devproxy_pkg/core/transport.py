"""Shared, bounded proxy handshakes. No direct-destination fallback."""
import base64
import ipaddress
import re
import socket
import ssl
import urllib.parse

HEADER_LIMIT = 65536


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise OSError('Unexpected EOF during proxy handshake.')
        result.extend(part)
    return bytes(result)


def read_headers(sock, limit=HEADER_LIMIT):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        part = sock.recv(min(4096, limit + 1 - len(data)))
        if not part:
            raise OSError('Unexpected EOF before HTTP headers.')
        data.extend(part)
        end = data.find(b'\r\n\r\n')
        if end >= 0:
            if end + 4 > limit:
                raise ValueError('HTTP headers exceed limit.')
            return bytes(data[:end + 4]), bytes(data[end + 4:])
        if len(data) >= limit:
            raise ValueError('HTTP headers exceed limit.')
    raise ValueError('Invalid HTTP headers.')


def authority(host, port):
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


def parse_authority(value, default_port=443):
    if any(c.isspace() or ord(c) < 32 for c in value) or any(c in value for c in '/?#@'):
        raise ValueError('Invalid destination authority.')
    parsed = urllib.parse.urlsplit('//' + value)
    host, port = parsed.hostname, parsed.port
    if not host or (port is not None and not 1 <= port <= 65535):
        raise ValueError('Invalid destination authority.')
    return host.encode('idna').decode('ascii'), default_port if port is None else port


def status_code(headers):
    line = headers.split(b'\r\n', 1)[0]
    match = re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?', line)
    if not match:
        raise ValueError('Invalid proxy response status line.')
    return int(match.group(1))


def proxy_auth_header(profile):
    if not profile.has_auth:
        return b''
    token = base64.b64encode(f'{profile.username or ""}:{profile.password or ""}'.encode('utf-8'))
    return b'Proxy-Authorization: Basic ' + token + b'\r\n'


def connect_upstream(profile, timeout=10):
    sock = socket.create_connection((profile.host, profile.port), timeout=timeout)
    try:
        if profile.protocol == 'https':
            context = ssl.create_default_context()
            if profile.ca_file:
                context.load_verify_locations(cafile=profile.ca_file)
            sock = context.wrap_socket(sock, server_hostname=profile.host)
        return sock
    except Exception:
        sock.close()
        raise


def socks5_connect(sock, profile, host, port):
    methods = b'\x02' if profile.has_auth else b'\x00'
    sock.sendall(b'\x05\x01' + methods)
    version, method = recv_exact(sock, 2)
    if version != 5 or method != methods[0]:
        raise OSError('SOCKS5 authentication method rejected.')
    if method == 2:
        user, password = (profile.username or '').encode('utf-8'), (profile.password or '').encode('utf-8')
        if not (1 <= len(user) <= 255 and 1 <= len(password) <= 255):
            raise ValueError('SOCKS5 credentials must contain 1–255 UTF-8 bytes.')
        sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if recv_exact(sock, 2) != b'\x01\x00':
            raise OSError('SOCKS5 authentication failed.')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if profile.dns_remote:
            domain = host.encode('idna')
            if not 1 <= len(domain) <= 255:
                raise ValueError('SOCKS5 domain exceeds limit.')
            encoded = b'\x03' + bytes([len(domain)]) + domain
        else:
            address = ipaddress.ip_address(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0])
            encoded = (b'\x01' if address.version == 4 else b'\x04') + address.packed
    else:
        encoded = (b'\x01' if address.version == 4 else b'\x04') + address.packed
    sock.sendall(b'\x05\x01\x00' + encoded + port.to_bytes(2, 'big'))
    version, reply, reserved, atyp = recv_exact(sock, 4)
    if version != 5 or reserved != 0 or reply != 0:
        raise OSError('SOCKS5 connection rejected.')
    if atyp == 1:
        recv_exact(sock, 6)
    elif atyp == 4:
        recv_exact(sock, 18)
    elif atyp == 3:
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)
    else:
        raise OSError('SOCKS5 returned an invalid address type.')


def http_connect(sock, profile, host, port):
    endpoint = authority(host, port).encode('ascii')
    sock.sendall(b'CONNECT ' + endpoint + b' HTTP/1.1\r\nHost: ' + endpoint + b'\r\n' + proxy_auth_header(profile) + b'\r\n')
    headers, remaining = read_headers(sock)
    if not 200 <= status_code(headers) < 300:
        raise OSError('HTTP proxy rejected CONNECT (status %s).' % status_code(headers))
    return remaining
