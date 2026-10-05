"""
ProxyValidator: Multi-step connectivity and routing verifier.
Distinguishes between:
1. Syntax validity
2. TCP reachability of the proxy host/port
3. Proxy authentication status
4. Target provider endpoints reachability (e.g. Gemini, OpenAI, Claude, GitHub)
5. Strict TLS certificate verification (never accepts invalid certs or disables TLS)
6. Latency measurement.
"""

import socket
import ssl
import time
import base64
import urllib.parse
from typing import Dict, Any, List, Optional
from .profile import ProxyProfile


DEFAULT_TARGETS = [
    ("Google AI (Generative Language)", "generativelanguage.googleapis.com", 443),
    ("OpenAI API", "api.openai.com", 443),
    ("Anthropic API", "api.anthropic.com", 443),
    ("GitHub", "github.com", 443),
]


class ValidationResult:
    def __init__(self, profile: ProxyProfile):
        self.profile = profile
        self.tcp_reachable: bool = False
        self.tcp_latency_ms: Optional[float] = None
        self.auth_required: bool = False
        self.auth_success: bool = False
        self.tls_strict_verified: bool = False
        self.target_checks: List[Dict[str, Any]] = []
        self.overall_success: bool = False
        self.errors: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile.name,
            "url": self.profile.to_safe_url(),
            "tcp_reachable": self.tcp_reachable,
            "tcp_latency_ms": self.tcp_latency_ms,
            "auth_required": self.auth_required,
            "auth_success": self.auth_success,
            "tls_strict_verified": self.tls_strict_verified,
            "targets": self.target_checks,
            "overall_success": self.overall_success,
            "errors": self.errors
        }


class ProxyValidator:
    @staticmethod
    def test_tcp_connect(host: str, port: int, timeout: float = 4.0) -> (bool, Optional[float], Optional[str]):
        """Tests pure TCP socket connection and measures round-trip time."""
        t0 = time.time()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            latency = (time.time() - t0) * 1000.0
            sock.close()
            return True, round(latency, 2), None
        except Exception as e:
            return False, None, str(e)

    @classmethod
    def test_http_proxy(cls, profile: ProxyProfile, target_host: str = "generativelanguage.googleapis.com", target_port: int = 443, timeout: float = 6.0) -> (bool, bool, bool, Optional[str]):
        """
        Tests HTTP CONNECT handshake through HTTP/HTTPS proxy.
        Returns: (connect_ok, auth_ok, tls_ok, error_msg)
        """
        try:
            sock = socket.create_connection((profile.host, profile.port), timeout=timeout)
            
            # If upstream proxy itself uses HTTPS (protocol == https)
            if profile.protocol == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=profile.host)

            # Build CONNECT request
            connect_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
            headers = [connect_line, "Proxy-Connection: Keep-Alive\r\n"]

            if profile.has_auth:
                cred = f"{profile.username or ''}:{profile.password or ''}"
                b64 = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                headers.append(f"Proxy-Authorization: Basic {b64}\r\n")

            headers.append("\r\n")
            req_data = "".join(headers).encode("latin-1")
            sock.sendall(req_data)

            # Read response
            resp_buf = b""
            while b"\r\n\r\n" not in resp_buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_buf += chunk
                if len(resp_buf) > 16384:
                    break

            if not resp_buf:
                sock.close()
                return False, False, False, "Empty response from proxy on CONNECT"

            first_line = resp_buf.split(b"\r\n")[0].decode("latin-1", errors="replace")
            parts = first_line.split(" ")
            status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            if status_code == 407:
                sock.close()
                return False, False, False, "HTTP 407 Proxy Authentication Required (Invalid or missing credentials)"

            if status_code != 200:
                sock.close()
                return False, False, False, f"Proxy returned HTTP {status_code}: {first_line}"

            # CONNECT succeeded! Now verify strict TLS to target endpoint through tunnel
            ctx = ssl.create_default_context()
            # Certificate validation MUST be kept ON (never disable check_hostname or verify_mode)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            
            tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
            # Check certificate
            cert = tls_sock.getpeercert()
            tls_sock.close()

            if cert:
                return True, True, True, None
            return True, True, False, "TLS certificate verification failed"

        except ssl.SSLCertVerificationError as e:
            return False, False, False, f"Strict TLS Verification Failed: {e}"
        except Exception as e:
            return False, False, False, str(e)

    @classmethod
    def test_socks5_proxy(cls, profile: ProxyProfile, target_host: str = "generativelanguage.googleapis.com", target_port: int = 443, timeout: float = 6.0) -> (bool, bool, bool, Optional[str]):
        """
        Tests SOCKS5 / SOCKS5h handshake, optional username/password auth, and target connect.
        Returns: (connect_ok, auth_ok, tls_ok, error_msg)
        """
        try:
            sock = socket.create_connection((profile.host, profile.port), timeout=timeout)
            
            # SOCKS5 greeting
            if profile.has_auth:
                sock.sendall(b"\x05\x02\x00\x02")  # methods: 00 (no auth), 02 (user/pass)
            else:
                sock.sendall(b"\x05\x01\x00")

            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != 0x05:
                sock.close()
                return False, False, False, "Invalid SOCKS5 greeting response"

            auth_method = resp[1]
            if auth_method == 0xFF:
                sock.close()
                return False, False, False, "SOCKS5 No acceptable authentication methods"

            if auth_method == 0x02:
                # Username/password subnegotiation
                user_bytes = (profile.username or "").encode("utf-8")
                pwd_bytes = (profile.password or "").encode("utf-8")
                auth_req = bytearray([0x01, len(user_bytes)]) + user_bytes + bytearray([len(pwd_bytes)]) + pwd_bytes
                sock.sendall(auth_req)
                auth_resp = sock.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                    sock.close()
                    return False, False, False, "SOCKS5 Authentication failed (bad username or password)"

            # CONNECT request
            # Domain name (0x03) allows remote DNS resolution (SOCKS5h)
            host_bytes = target_host.encode("utf-8")
            port_bytes = target_port.to_bytes(2, byteorder="big")
            cmd = bytearray([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + port_bytes
            sock.sendall(cmd)

            conn_resp = sock.recv(4)
            if len(conn_resp) < 4 or conn_resp[1] != 0x00:
                rep_code = conn_resp[1] if len(conn_resp) >= 2 else -1
                sock.close()
                return False, True, False, f"SOCKS5 Connect rejected by proxy (code 0x{rep_code:02x})"

            # Skip bound address
            atyp = conn_resp[3]
            if atyp == 0x01:
                sock.recv(4 + 2)
            elif atyp == 0x03:
                dlen = sock.recv(1)[0]
                sock.recv(dlen + 2)
            elif atyp == 0x04:
                sock.recv(16 + 2)

            # Now perform strict TLS handshake to target
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
            cert = tls_sock.getpeercert()
            tls_sock.close()

            return True, True, bool(cert), None

        except ssl.SSLCertVerificationError as e:
            return False, False, False, f"Strict TLS Verification Failed: {e}"
        except Exception as e:
            return False, False, False, str(e)

    @classmethod
    def validate(cls, profile: ProxyProfile, targets: Optional[List[tuple]] = None, timeout: float = 5.0) -> ValidationResult:
        """Runs full suite of checks for profile."""
        res = ValidationResult(profile)
        check_targets = targets or DEFAULT_TARGETS

        # 1. TCP Reachability
        tcp_ok, latency, err = cls.test_tcp_connect(profile.host, profile.port, timeout=timeout)
        res.tcp_reachable = tcp_ok
        res.tcp_latency_ms = latency
        if not tcp_ok:
            res.errors.append(f"Proxy host unreachable ({profile.host}:{profile.port}): {err}")
            return res

        # 2. Check each target
        passed_any = False
        for label, host, port in check_targets:
            t_start = time.time()
            if profile.is_socks:
                ok, auth_ok, tls_ok, msg = cls.test_socks5_proxy(profile, host, port, timeout=timeout)
            else:
                ok, auth_ok, tls_ok, msg = cls.test_http_proxy(profile, host, port, timeout=timeout)
            
            elapsed = round((time.time() - t_start) * 1000.0, 1)
            target_entry = {
                "name": label,
                "host": host,
                "port": port,
                "success": ok and tls_ok,
                "latency_ms": elapsed,
                "error": msg
            }
            res.target_checks.append(target_entry)

            if ok and tls_ok:
                passed_any = True
                res.auth_success = True
                res.tls_strict_verified = True
            elif msg and "Authentication" in msg:
                res.auth_required = True
                res.errors.append(f"Auth error on {label}: {msg}")

        res.overall_success = passed_any
        if not passed_any and not res.errors:
            res.errors.append("Failed to establish secure tunnel to any target endpoint.")
        return res
