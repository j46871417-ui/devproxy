"""Diagnostics use exactly the same transport as application sessions."""
import socket
import ssl
import time
from .tunnel import LocalTunnel
from .transport import read_headers, authority, ProxyError
from .user_errors import describe_error

DEFAULT_TARGETS = [
    ("Google AI", "generativelanguage.googleapis.com", 443),
    ("OpenAI API", "api.openai.com", 443),
    ("Anthropic API", "api.anthropic.com", 443),
    ("GitHub", "github.com", 443),
]


class ValidationResult:
    def __init__(self, profile):
        self.profile = profile
        self.tcp_reachable = self.auth_required = self.auth_success = False
        self.tls_strict_verified = self.overall_success = False
        self.tcp_latency_ms = None
        self.target_checks, self.errors = [], []

    def to_dict(self):
        return dict(profile=self.profile.name, url=self.profile.to_safe_url(),
                    tcp_reachable=self.tcp_reachable, tcp_latency_ms=self.tcp_latency_ms,
                    auth_required=self.auth_required, auth_success=self.auth_success,
                    tls_strict_verified=self.tls_strict_verified, targets=self.target_checks,
                    overall_success=self.overall_success, errors=self.errors)


class ProxyValidator:
    @staticmethod
    def test_tcp_connect(host, port, timeout=4.0):
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, round((time.monotonic() - start) * 1000, 2), None
        except OSError as exc:
            return False, None, describe_error(exc)

    @staticmethod
    def test_http_proxy(profile, target_host="github.com", target_port=443, timeout=6.0):
        connected = False
        try:
            with LocalTunnel(profile, handshake_timeout=timeout) as tunnel:
                with socket.create_connection((tunnel.bind_host, tunnel.allocated_port), timeout=timeout) as sock:
                    dest = authority(target_host, target_port)
                    sock.sendall(f"CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n\r\n".encode("ascii"))
                    headers, tail = read_headers(sock)
                    if headers.split(b"\r\n")[0].split()[1] != b"200" or tail:
                        return False, False, False, describe_error(ProxyError("Proxy tunnel rejected", "protocol_error"), target_host)
                    connected = True
                    with ssl.create_default_context().wrap_socket(sock, server_hostname=target_host) as tls:
                        tls.getpeercert()
                        return True, True, True, None
        except Exception as exc:
            return connected, connected, False, describe_error(exc, target_host)

    test_socks5_proxy = test_http_proxy

    @classmethod
    def validate(cls, profile, targets=None):
        result = ValidationResult(profile)
        result.auth_required = profile.has_auth
        result.tcp_reachable, result.tcp_latency_ms, error = cls.test_tcp_connect(profile.host, profile.port)
        if error:
            result.errors.append(error)
            return result
        for name, host, port in (DEFAULT_TARGETS if targets is None else targets):
            start = time.monotonic()
            connected, auth, tls, error = cls.test_http_proxy(profile, host, port)
            success = connected and auth and tls
            result.target_checks.append(dict(name=name, host=host, success=success,
                                             latency_ms=round((time.monotonic() - start) * 1000, 2), error=error))
            result.auth_success |= auth
            result.tls_strict_verified |= tls
            if error:
                result.errors.append(f"{name}: {error}")
        result.overall_success = bool(result.target_checks) and all(t["success"] for t in result.target_checks)
        return result
