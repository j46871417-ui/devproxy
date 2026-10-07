"""Validated proxy metadata; secrets never serialize or appear in parse errors."""
import ipaddress
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
    dns_remote: bool = True
    notes: Optional[str] = None
    secret_reference: Optional[str] = None
    profile_id: Optional[str] = None

    def __post_init__(self):
        self.protocol = self.protocol.lower()
        if self.protocol not in ("http", "https", "socks5", "socks5h"):
            raise ValueError("Unsupported proxy protocol")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("Proxy port must be an integer in 1..65535")
        if not self.name or len(self.name) > 128 or any(ord(c) < 32 for c in self.name):
            raise ValueError("Invalid profile name")
        if not self.host or any(ord(c) <= 32 or ord(c) == 127 or c in "/\\@?#[]" for c in self.host):
            raise ValueError("Invalid proxy hostname")
        if ":" in self.host:
            try:
                ipaddress.IPv6Address(self.host)
            except ValueError:
                raise ValueError("Invalid IPv6 proxy address") from None
        else:
            try:
                self.host.encode("idna")
            except UnicodeError:
                raise ValueError("Invalid proxy hostname") from None
        if self.username and ":" in self.username and not self.is_socks:
            raise ValueError("HTTP Basic username cannot contain a colon")
        if self.protocol == "socks5h":
            self.dns_remote = True

    @property
    def is_socks(self):
        return self.protocol in ("socks5", "socks5h")

    @property
    def has_auth(self):
        return self.username is not None or self.password is not None or self.secret_reference is not None

    def to_url(self, include_auth=False):
        host = f"[{self.host}]" if ":" in self.host else self.host
        auth = ""
        if include_auth and self.has_auth:
            raise ValueError("Credentials in proxy URLs are prohibited")
        return f"{self.protocol}://{auth}{host}:{self.port}"

    def to_safe_url(self):
        return self.to_url()

    def to_dict(self, include_password=False):
        if include_password:
            raise ValueError("Secret serialization is prohibited")
        return dict(name=self.name, protocol=self.protocol, host=self.host, port=self.port,
                    username=self.username, dns_remote=self.dns_remote, notes=self.notes,
                    secret_reference=self.secret_reference, profile_id=self.profile_id)

    @classmethod
    def from_dict(cls, data, password=None):
        if "password" in data:
            raise ValueError("Plaintext credentials in configuration; migrate to the credential store")
        return cls(name=data["name"], protocol=data.get("protocol", "http"), host=data["host"],
                   port=data["port"], username=data.get("username"), password=password,
                   dns_remote=data.get("dns_remote", True), notes=data.get("notes"),
                   secret_reference=data.get("secret_reference"), profile_id=data.get("profile_id"))

    @classmethod
    def parse(cls, raw, name="default", fallback_protocol="http"):
        try:
            raw = raw.strip().strip("'\"")
            if not raw or any(ord(c) < 32 for c in raw):
                raise ValueError()
            if "://" not in raw:
                if raw.startswith("["):
                    closing = raw.index("]")
                    host = raw[1:closing]
                    parts = raw[closing + 1:].removeprefix(":").split(":", 2)
                else:
                    host, rest = raw.split(":", 1)
                    parts = rest.split(":", 2)
                if len(parts) not in (1, 3):
                    raise ValueError()
                return cls(name, fallback_protocol, host, int(parts[0]),
                           parts[1] if len(parts) == 3 else None,
                           parts[2] if len(parts) == 3 else None)
            url = urllib.parse.urlsplit(raw)
            if url.path not in ("", "/") or url.query or url.fragment:
                raise ValueError()
            port = url.port
            if port is None:
                port = 443 if url.scheme == "https" else 1080 if url.scheme in ("socks5", "socks5h") else 8080
            return cls(name, url.scheme, url.hostname, port,
                       urllib.parse.unquote(url.username) if url.username is not None else None,
                       urllib.parse.unquote(url.password) if url.password is not None else None)
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise ValueError("Invalid proxy address; use scheme://host:port (IPv6 in brackets)") from None
