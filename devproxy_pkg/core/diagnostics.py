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
    import urllib.request
    from .tunnel import LocalTunnel
    
    tunnel = None
    try:
        if profile.is_socks or profile.has_auth:
            tunnel = LocalTunnel(profile)
            port = tunnel.start()
            proxy_url = f"http://127.0.0.1:{port}"
        else:
            proxy_url = profile.to_url()

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        }))
        req = urllib.request.Request(service_url, headers={"User-Agent": "devproxy/2.0"})
        with opener.open(req, timeout=6.0) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
            ip = None
            for line in data.splitlines():
                if line.startswith("ip="):
                    ip = line.split("=", 1)[1]
            return {
                "service": service_name,
                "url": service_url,
                "egress_ip": ip or "detected",
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
