"""
ProxyProfile: Data model and parsing logic for proxy configurations.
Supports:
- http://host:port, https://host:port
- http://user:password@host:port, https://user:password@host:port
- socks5://host:port, socks5://user:password@host:port
- socks5h://host:port, socks5h://user:password@host:port
- host:port
- host:port:user:password (deterministic parsing)
- IPv6 addresses in [::1] bracket format.
"""

import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass
class ProxyProfile:
    name: str
    protocol: str  # 'http', 'https', 'socks5', 'socks5h'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    dns_remote: bool = False  # True for socks5h, or when explicitly requested
    notes: Optional[str] = None

    def __post_init__(self):
        self.protocol = self.protocol.lower()
        if self.protocol == "socks5h":
            self.dns_remote = True
        if not self.port or self.port < 1 or self.port > 65535:
            raise ValueError(f"Invalid port: {self.port}. Must be 1-65535.")
        if not self.host:
            raise ValueError("Host cannot be empty.")

    @property
    def is_socks(self) -> bool:
        return self.protocol in ("socks5", "socks5h")

    @property
    def has_auth(self) -> bool:
        return bool(self.username or self.password)

    def to_url(self, include_auth: bool = True) -> str:
        """Constructs canonical URL."""
        proto = self.protocol
        host_str = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        if include_auth and self.has_auth:
            user = urllib.parse.quote(self.username or "", safe="")
            pwd = urllib.parse.quote(self.password or "", safe="")
            return f"{proto}://{user}:{pwd}@{host_str}:{self.port}"
        return f"{proto}://{host_str}:{self.port}"

    def to_safe_url(self) -> str:
        """Returns URL with masked password for display/logging."""
        if not self.has_auth:
            return self.to_url(include_auth=False)
        proto = self.protocol
        host_str = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        user = urllib.parse.quote(self.username or "", safe="")
        return f"{proto}://{user}:***@{host_str}:{self.port}"

    def to_dict(self, include_password: bool = False) -> dict:
        d = {
            "name": self.name,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "dns_remote": self.dns_remote,
            "notes": self.notes
        }
        if include_password and self.password:
            d["password"] = self.password
        return d

    @classmethod
    def from_dict(cls, data: dict, password: Optional[str] = None) -> "ProxyProfile":
        return cls(
            name=data["name"],
            protocol=data.get("protocol", "http"),
            host=data["host"],
            port=int(data["port"]),
            username=data.get("username"),
            password=password or data.get("password"),
            dns_remote=bool(data.get("dns_remote", False)),
            notes=data.get("notes")
        )

    @classmethod
    def parse(cls, raw: str, name: str = "default", fallback_protocol: str = "http") -> "ProxyProfile":
        """
        Parses proxy string into a ProxyProfile.
        Handles:
        1. Full URL formats (http://, https://, socks5://, socks5h://)
        2. host:port
        3. host:port:user:password
        4. IPv6 addresses [::1]:port
        """
        raw = raw.strip().strip("'\"")
        if not raw:
            raise ValueError("Proxy string cannot be empty.")

        # 1. Scheme check
        if "://" in raw:
            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https", "socks5", "socks5h"):
                raise ValueError(f"Unsupported proxy scheme: '{scheme}'. Use http, https, socks5, or socks5h.")
            
            host = parsed.hostname
            port = parsed.port
            if not host:
                raise ValueError(f"Invalid host in proxy URL: '{raw}'")
            if not port:
                # Default ports
                port = 443 if scheme == "https" else 1080 if "socks" in scheme else 8080

            username = urllib.parse.unquote(parsed.username) if parsed.username is not None else None
            password = urllib.parse.unquote(parsed.password) if parsed.password is not None else None

            dns_remote = (scheme == "socks5h")
            return cls(
                name=name,
                protocol=scheme,
                host=host,
                port=port,
                username=username,
                password=password,
                dns_remote=dns_remote
            )

        # 2. Bracketed IPv6 without scheme: e.g. [::1]:8080 or [::1]:8080:user:pass
        if raw.startswith("["):
            end_bracket = raw.find("]")
            if end_bracket != -1:
                host = raw[1:end_bracket]
                remainder = raw[end_bracket+1:]
                if remainder.startswith(":"):
                    parts = remainder[1:].split(":")
                    if len(parts) == 1:
                        port = int(parts[0])
                        return cls(name=name, protocol=fallback_protocol, host=host, port=port)
                    elif len(parts) == 3:
                        port = int(parts[0])
                        user, pwd = parts[1], parts[2]
                        return cls(name=name, protocol=fallback_protocol, host=host, port=port, username=user, password=pwd)

        # 3. Formats with colons: host:port:user:pass or host:port
        parts = raw.split(":")
        if len(parts) == 4:
            # host:port:user:pass
            host, port_str, user, pwd = parts
            try:
                port = int(port_str)
                return cls(name=name, protocol=fallback_protocol, host=host, port=port, username=user, password=pwd)
            except ValueError:
                raise ValueError(f"Invalid port in 'host:port:user:pass': '{port_str}'")

        if len(parts) == 2:
            # host:port
            host, port_str = parts
            try:
                port = int(port_str)
                return cls(name=name, protocol=fallback_protocol, host=host, port=port)
            except ValueError:
                raise ValueError(f"Invalid port in 'host:port': '{port_str}'")

        # If it doesn't match standard patterns
        raise ValueError(
            f"Cannot deterministically parse proxy string '{raw}'. "
            "Please use full URL (e.g. 'http://user:pass@host:port' or 'socks5://host:port') "
            "or 'host:port'."
        )
