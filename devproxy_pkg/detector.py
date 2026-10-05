"""
LocalProxyDetector: Optional client discovery.
Rule:
- Purely manual/optional helper (never runs automatically on startup).
- Never overwrites custom user proxy or switches profile without confirmation.
- Detects commonly used local VPN/proxy clients listening on loopback ports.
"""

import socket
from typing import List, Dict, Any


KNOWN_LOCAL_CLIENTS = [
    {"name": "Happ / V2Ray / Xray", "protocol": "socks5", "host": "127.0.0.1", "port": 10808},
    {"name": "Happ / V2Ray (HTTP)", "protocol": "http", "host": "127.0.0.1", "port": 10809},
    {"name": "Sing-box / Hiddify (SOCKS5)", "protocol": "socks5", "host": "127.0.0.1", "port": 2080},
    {"name": "Sing-box / Hiddify (Mixed/HTTP)", "protocol": "http", "host": "127.0.0.1", "port": 2081},
    {"name": "Clash / Clash Verge / Mihomo (Mixed)", "protocol": "http", "host": "127.0.0.1", "port": 7890},
    {"name": "Clash / Clash Verge (SOCKS5)", "protocol": "socks5", "host": "127.0.0.1", "port": 7891},
    {"name": "NekoRay (SOCKS5)", "protocol": "socks5", "host": "127.0.0.1", "port": 2080},
    {"name": "NekoBox (SOCKS5)", "protocol": "socks5", "host": "127.0.0.1", "port": 2080},
    {"name": "Tor Browser / Service", "protocol": "socks5", "host": "127.0.0.1", "port": 9050},
    {"name": "Tor Browser Bundle", "protocol": "socks5", "host": "127.0.0.1", "port": 9150},
]


class LocalProxyDetector:
    @staticmethod
    def scan_active_clients() -> List[Dict[str, Any]]:
        """Scans loopback ports of known proxy clients."""
        active = []
        for client in KNOWN_LOCAL_CLIENTS:
            host = client["host"]
            port = client["port"]
            try:
                s = socket.create_connection((host, port), timeout=0.2)
                s.close()
                active.append(dict(client))
            except Exception:
                pass
        return active
