"""Validated proxy endpoints. Errors never echo submitted credentials."""
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProxyProfile:
    name: str
    protocol: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    dns_remote: bool = False
    notes: Optional[str] = None
    ca_file: Optional[str] = None

    def __post_init__(self):
        self.protocol = self.protocol.lower()
        if self.protocol not in ('http', 'https', 'socks5', 'socks5h'):
            raise ValueError('Supported protocols: http, https, socks5, socks5h.')
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError('Port must be an integer from 1 to 65535.')
        if not self.host or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.host):
            raise ValueError('Invalid proxy host.')
        try:
            self.host = str(ipaddress.ip_address(self.host))
        except ValueError:
            try:
                self.host = self.host.encode('idna').decode('ascii').lower()
            except UnicodeError:
                raise ValueError('Invalid proxy host.') from None
            labels = self.host.rstrip('.').split('.')
            if len(self.host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in labels):
                raise ValueError('Invalid proxy host.')
        if not self.name or any(ord(c) < 32 or ord(c) == 127 for c in self.name):
            raise ValueError('Invalid profile name.')
        if self.username is not None and ':' in self.username:
            raise ValueError('Username must not contain a colon.')
        for item in (self.username, self.password):
            if item is not None and any(ord(c) < 32 or ord(c) == 127 for c in item):
                raise ValueError('Credentials must not contain control characters.')
        if self.is_socks and self.has_auth:
            if not self.username or len(self.username.encode('utf-8')) > 255:
                raise ValueError('SOCKS username must contain 1–255 UTF-8 bytes.')
            if self.password is not None and not 1 <= len(self.password.encode('utf-8')) <= 255:
                raise ValueError('SOCKS password must contain 1–255 UTF-8 bytes.')
        self.dns_remote = self.protocol == 'socks5h' or bool(self.dns_remote)

    @property
    def is_socks(self):
        return self.protocol in ('socks5', 'socks5h')

    @property
    def has_auth(self):
        return bool(self.username or self.password)

    def to_url(self, include_auth=True):
        host = f'[{self.host}]' if ':' in self.host else self.host
        auth = ''
        if include_auth and self.has_auth:
            auth = urllib.parse.quote(self.username or '', safe='') + ':' + urllib.parse.quote(self.password or '', safe='') + '@'
        return f'{self.protocol}://{auth}{host}:{self.port}'

    def to_safe_url(self):
        if not self.has_auth:
            return self.to_url(False)
        host = f'[{self.host}]' if ':' in self.host else self.host
        user = urllib.parse.quote(self.username or '', safe='')
        return f'{self.protocol}://{user}:***@{host}:{self.port}'

    def to_dict(self, include_password=False):
        result = {k: getattr(self, k) for k in ('name', 'protocol', 'host', 'port', 'username', 'dns_remote', 'notes', 'ca_file')}
        if include_password and self.password is not None:
            result['password'] = self.password
        return result

    @classmethod
    def from_dict(cls, data, password=None):
        return cls(name=data['name'], protocol=data.get('protocol', 'http'), host=data['host'],
                   port=int(data['port']), username=data.get('username'), password=password,
                   dns_remote=data.get('dns_remote', False), notes=data.get('notes'), ca_file=data.get('ca_file'))

    @classmethod
    def parse(cls, raw, name='default', fallback_protocol='http'):
        if not isinstance(raw, str) or any(ord(c) < 32 or ord(c) == 127 for c in raw):
            raise ValueError('Proxy input contains control characters.')
        raw = raw.strip()
        if not raw:
            raise ValueError('Proxy string cannot be empty.')
        try:
            if '://' in raw:
                parts = urllib.parse.urlsplit(raw)
                if parts.path or parts.query or parts.fragment or '?' in raw or '#' in raw:
                    raise ValueError('Proxy URL must contain only an endpoint.')
                if re.search(r'%(?![0-9a-fA-F]{2})', raw):
                    raise ValueError('Invalid percent escape.')
                port = parts.port
                if port is None:
                    if parts.netloc.endswith(':'):
                        raise ValueError('Missing port.')
                    port = {'http': 8080, 'https': 443, 'socks5': 1080, 'socks5h': 1080}.get(parts.scheme, 0)
                return cls(name, parts.scheme, parts.hostname or '', port,
                           urllib.parse.unquote(parts.username, errors='strict') if parts.username is not None else None,
                           urllib.parse.unquote(parts.password, errors='strict') if parts.password is not None else None)
            if raw.startswith('['):
                match = re.fullmatch(r'\[([^]]+)\]:(.+)', raw)
                if not match:
                    raise ValueError('Invalid IPv6 endpoint.')
                host, rest = match.groups()
            else:
                host, rest = raw.split(':', 1)
            fields = rest.split(':', 2)
            if len(fields) not in (1, 3) or not fields[0].isascii() or not fields[0].isdigit():
                raise ValueError('Invalid shorthand endpoint.')
            return cls(name, fallback_protocol, host, int(fields[0]),
                       fields[1] if len(fields) == 3 else None, fields[2] if len(fields) == 3 else None)
        except (ValueError, UnicodeError):
            raise ValueError('Invalid proxy endpoint. Check scheme, host, port and encoded credentials.') from None
