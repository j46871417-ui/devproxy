"""Validate the same forwarding path used by sessions, with strict target TLS."""
import socket
import ssl
import time
from .profile import ProxyProfile
from .transport import http_connect
from .tunnel import LocalTunnel

DEFAULT_TARGETS = [
    ('Google AI', 'generativelanguage.googleapis.com', 443),
    ('OpenAI API', 'api.openai.com', 443),
    ('Anthropic API', 'api.anthropic.com', 443),
    ('GitHub', 'github.com', 443),
]


class ValidationResult:
    def __init__(self, profile):
        self.profile = profile
        self.tcp_reachable = False
        self.tcp_latency_ms = None
        self.auth_required = profile.has_auth
        self.auth_success = False
        self.tls_strict_verified = False
        self.target_checks = []
        self.overall_success = False
        self.errors = []

    def to_dict(self):
        return dict(profile=self.profile.name, url=self.profile.to_safe_url(),
                    tcp_reachable=self.tcp_reachable, tcp_latency_ms=self.tcp_latency_ms,
                    auth_required=self.auth_required, auth_success=self.auth_success,
                    tls_strict_verified=self.tls_strict_verified, targets=self.target_checks,
                    overall_success=self.overall_success, errors=self.errors)


class ProxyValidator:
    @staticmethod
    def test_tcp_connect(host, port, timeout=4):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, round((time.monotonic() - started) * 1000, 2), None
        except OSError as error:
            return False, None, str(error)

    @classmethod
    def test_http_proxy(cls, profile, target_host='generativelanguage.googleapis.com', target_port=443, timeout=10):
        tunnel = LocalTunnel(profile)
        connected = False
        try:
            port = tunnel.start()
            with socket.create_connection(('127.0.0.1', port), timeout=timeout) as sock:
                local = ProxyProfile('validation', 'http', '127.0.0.1', port)
                remaining = http_connect(sock, local, target_host, target_port)
                if remaining:
                    raise OSError('Unexpected bytes before target TLS handshake.')
                connected = True
                context = ssl.create_default_context()
                if profile.ca_file:
                    context.load_verify_locations(cafile=profile.ca_file)
                with context.wrap_socket(sock, server_hostname=target_host) as target:
                    return True, True, bool(target.getpeercert()), None
        except (OSError, ValueError) as error:
            return connected, connected, False, str(error)
        finally:
            tunnel.stop()

    @classmethod
    def test_socks5_proxy(cls, profile, target_host='generativelanguage.googleapis.com', target_port=443, timeout=10):
        return cls.test_http_proxy(profile, target_host, target_port, timeout)

    @classmethod
    def validate(cls, profile, targets=None, timeout=10):
        result = ValidationResult(profile)
        endpoints = DEFAULT_TARGETS if targets is None else targets
        ok, latency, error = cls.test_tcp_connect(profile.host, profile.port, timeout)
        result.tcp_reachable, result.tcp_latency_ms = ok, latency
        if not ok:
            result.errors.append('Proxy TCP unavailable: ' + (error or 'unknown error'))
            return result
        for label, host, port in endpoints:
            started = time.monotonic()
            test = cls.test_socks5_proxy if profile.is_socks else cls.test_http_proxy
            connected, authenticated, verified, error = test(profile, host, port, timeout)
            success = connected and verified
            result.target_checks.append(dict(name=label, host=host, port=port, success=success,
                                             latency_ms=round((time.monotonic() - started) * 1000, 1), error=error))
            if error:
                result.errors.append(label + ': ' + error)
            if authenticated:
                result.auth_success = True
        result.overall_success = bool(result.target_checks) and all(t['success'] for t in result.target_checks)
        result.tls_strict_verified = result.overall_success
        return result
