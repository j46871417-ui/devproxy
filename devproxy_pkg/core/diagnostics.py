"""Explicit external-IP diagnostics using a forced local CONNECT, ignoring NO_PROXY."""
import http.client
import os
import ipaddress
from .tunnel import LocalTunnel


def get_environment_diagnostics():
    return {key: "<configured>" if os.environ.get(key) else "<not set>"
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                        "http_proxy", "https_proxy", "all_proxy", "no_proxy")}


def test_ip_echo(profile):
    try:
        with LocalTunnel(profile) as tunnel:
            connection = http.client.HTTPSConnection(tunnel.bind_host, tunnel.allocated_port, timeout=10)
            try:
                connection.set_tunnel("cloudflare.com", 443)
                connection.request("GET", "/cdn-cgi/trace", headers={"Host": "cloudflare.com", "User-Agent": "devproxy/2.1"})
                response = connection.getresponse()
                if response.status != 200:
                    raise OSError("IP echo HTTP failure")
                text = response.read(65536).decode("utf-8")
                ip = next(line[3:] for line in text.splitlines() if line.startswith("ip="))
                ipaddress.ip_address(ip)
                return {"success": True, "egress_ip": ip}
            finally:
                connection.close()
    except Exception as exc:
        return {"success": False, "error": type(exc).__name__}
