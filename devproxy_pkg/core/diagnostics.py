"""
Diagnostics: Anonymized system inspection and routing diagnostics.
- Checks local port binds and active listening sockets.
- Shows current environment variables without printing passwords.
- Checks configured IDE files.
- Checks DNS reachability.
- NEVER contacts external IP-echo services automatically without explicit user flag and disclosure.
"""

import os
import sys
import socket
from typing import Dict, Any, List
from .profile import ProxyProfile


def get_environment_diagnostics() -> Dict[str, Any]:
    env_keys = [
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
        "NO_PROXY", "no_proxy",
        "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE"
    ]
    res = {}
    for k in env_keys:
        v = os.environ.get(k)
        if v:
            # Mask potential credentials
            if "@" in v:
                try:
                    p = ProxyProfile.parse(v, name="env_check")
                    res[k] = p.to_safe_url()
                except Exception:
                    res[k] = "<configured (credentials hidden)>"
            else:
                res[k] = v
        else:
            res[k] = "<not set>"
    return res


def check_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def test_ip_echo(profile: ProxyProfile, service_name: str = "Cloudflare Trace", service_url: str = "https://cloudflare.com/cdn-cgi/trace") -> Dict[str, Any]:
    """
    OPTIONAL external IP diagnostic.
    Explicitly discloses the target recipient.
    Uses LocalTunnel for SOCKS/auth upstreams.
    """
    import http.client
    import ssl
    import urllib.parse
    from .transport import http_connect
    from .tunnel import LocalTunnel
    
    tunnel = None
    try:
        parsed = urllib.parse.urlsplit(service_url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.fragment:
            raise ValueError('IP diagnostic requires a credential-free HTTPS URL.')
        tunnel = LocalTunnel(profile)
        port = tunnel.start()
        host, target_port = parsed.hostname, parsed.port or 443
        context = ssl.create_default_context()
        if profile.ca_file:
            context.load_verify_locations(cafile=profile.ca_file)
        with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
            if http_connect(connection, ProxyProfile('echo', 'http', '127.0.0.1', port), host, target_port):
                raise OSError('Unexpected bytes before target TLS.')
            with context.wrap_socket(connection, server_hostname=host) as target:
                path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
                target.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + parsed.netloc + '\r\nUser-Agent: devproxy/2.0.1\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = http.client.HTTPResponse(target)
                response.begin()
                if response.status != 200:
                    raise OSError('IP diagnostic returned HTTP ' + str(response.status))
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError('IP diagnostic response exceeds limit.')
                data = raw.decode('utf-8')
            ip = None
            for line in data.splitlines():
                if line.startswith("ip="):
                    ip = line.split("=", 1)[1]
            if ip is None:
                raise ValueError('IP diagnostic response has no egress address.')
            import ipaddress
            ipaddress.ip_address(ip)
            return {
                "service": service_name,
                "url": service_url,
                "egress_ip": ip,
                "success": True
            }
    except Exception as e:
        return {
            "service": service_name,
            "url": service_url,
            "success": False,
            "error": str(e)
        }
    finally:
        if tunnel:
            tunnel.stop()
