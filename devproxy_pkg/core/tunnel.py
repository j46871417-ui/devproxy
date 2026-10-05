"""
Tunnel: Local loopback forwarder and transport proxy bridge.
Ensures:
- Local loopback only (127.0.0.1 or ::1) on an ephemeral or designated port.
- Transparent streaming of encrypted bytes (NO MitM decryption, NO inspecting prompts/code, NO tampering with responses).
- Bridges tools that only understand plain HTTP proxy to SOCKS5 or authenticated upstreams.
- Injects Proxy-Authorization only toward the designated upstream proxy.
- FAIL-CLOSED: Errors from upstream proxy return 502/504 Bad Gateway, NEVER falling back to unproxied direct connection.
"""

import socket
import threading
import select
import base64
import time
import urllib.parse
from typing import Optional, Tuple
from .profile import ProxyProfile


class LocalTunnel:
    def __init__(self, profile: ProxyProfile, bind_host: str = "127.0.0.1", bind_port: int = 0):
        self.profile = profile
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.server_sock: Optional[socket.socket] = None
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.allocated_port: int = 0

    def start(self, timeout: float = 3.0) -> int:
        """Starts loopback server and returns bound port."""
        family = socket.AF_INET6 if ":" in self.bind_host else socket.AF_INET
        self.server_sock = socket.socket(family, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.bind_host, self.bind_port))
        self.server_sock.listen(128)
        self.allocated_port = self.server_sock.getsockname()[1]
        self.is_running = True

        self._thread = threading.Thread(target=self._serve_loop, daemon=True, name="DevProxyTunnel")
        self._thread.start()

        # Readiness check
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                test_sock = socket.create_connection((self.bind_host, self.allocated_port), timeout=0.2)
                test_sock.close()
                return self.allocated_port
            except Exception:
                time.sleep(0.05)

        return self.allocated_port

    def stop(self):
        """Stops server and terminates connections."""
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

    def _serve_loop(self):
        while self.is_running:
            try:
                client_sock, addr = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                if not self.is_running:
                    break

    def _handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(15.0)
            req_data = client_sock.recv(8192)
            if not req_data:
                client_sock.close()
                return

            lines = req_data.split(b"\r\n")
            if not lines:
                client_sock.close()
                return

            first_line = lines[0].decode("latin-1", errors="replace")
            parts = first_line.split(" ")
            if len(parts) < 3:
                client_sock.close()
                return

            method, target_uri, proto = parts[0].upper(), parts[1], parts[2]
            
            dest_host = ""
            dest_port = 80

            if method == "CONNECT":
                # target_uri is host:port
                if ":" in target_uri:
                    hp = target_uri.split(":")
                    dest_host = hp[0]
                    dest_port = int(hp[1])
                else:
                    dest_host = target_uri
                    dest_port = 443
            else:
                # Normal HTTP request (GET http://host:port/path HTTP/1.1 or GET /path with Host: header)
                if target_uri.startswith("http://") or target_uri.startswith("https://"):
                    p = urllib.parse.urlsplit(target_uri)
                    dest_host = p.hostname
                    dest_port = p.port or (443 if p.scheme == "https" else 80)
                else:
                    for line in lines[1:]:
                        if line.lower().startswith(b"host:"):
                            hval = line.split(b":", 1)[1].strip().decode("latin-1")
                            if ":" in hval:
                                hp = hval.split(":")
                                dest_host = hp[0]
                                dest_port = int(hp[1])
                            else:
                                dest_host = hval
                                dest_port = 80
                            break

            if not dest_host:
                client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                client_sock.close()
                return

            # Establish connection to UPSTREAM proxy (FAIL-CLOSED: never bypass upstream)
            upstream_sock = None
            try:
                upstream_sock = socket.create_connection((self.profile.host, self.profile.port), timeout=2.0)
            except Exception as e:
                # Return 502 Bad Gateway to client
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway (Proxy Unreachable)\r\n\r\n")
                client_sock.close()
                return

            # Route through upstream depending on its protocol
            if self.profile.is_socks:
                # Upstream is SOCKS5
                if not self._socks5_connect_upstream(upstream_sock, dest_host, dest_port):
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway (SOCKS5 Handshake Failed)\r\n\r\n")
                    client_sock.close()
                    upstream_sock.close()
                    return

                if method == "CONNECT":
                    # Tell client HTTP 200 Connection established
                    client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    # Forward the plain HTTP request bytes to SOCKS5 tunnel
                    upstream_sock.sendall(req_data)

            else:
                # Upstream is HTTP/HTTPS proxy
                if method == "CONNECT":
                    # Send CONNECT to upstream proxy with Proxy-Authorization if required
                    conn_headers = [f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\n"]
                    if self.profile.has_auth:
                        cred = f"{self.profile.username or ''}:{self.profile.password or ''}"
                        b64 = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                        conn_headers.append(f"Proxy-Authorization: Basic {b64}\r\n")
                    conn_headers.append("\r\n")
                    upstream_sock.sendall("".join(conn_headers).encode("latin-1"))

                    # Read upstream response
                    resp_buf = b""
                    while b"\r\n\r\n" not in resp_buf:
                        chunk = upstream_sock.recv(4096)
                        if not chunk: break
                        resp_buf += chunk
                    
                    if b"200 " not in resp_buf:
                        client_sock.sendall(resp_buf if resp_buf else b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        client_sock.close()
                        upstream_sock.close()
                        return
                    
                    # Notify client 200 OK
                    client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    # Forward HTTP request with injected Proxy-Authorization
                    if self.profile.has_auth and b"Proxy-Authorization:" not in req_data:
                        cred = f"{self.profile.username or ''}:{self.profile.password or ''}"
                        b64 = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                        auth_hdr = f"Proxy-Authorization: Basic {b64}\r\n".encode("latin-1")
                        req_data = req_data.replace(b"\r\n", b"\r\n" + auth_hdr, 1)
                    upstream_sock.sendall(req_data)

            # Bidirectional streaming of raw bytes (end-to-end TLS preserved without decryption)
            self._pipe_duplex(client_sock, upstream_sock)

        except Exception:
            try: client_sock.close()
            except Exception: pass

    def _socks5_connect_upstream(self, sock: socket.socket, host: str, port: int) -> bool:
        """Performs SOCKS5 greeting + auth + CONNECT command."""
        try:
            sock.settimeout(10.0)
            if self.profile.has_auth:
                sock.sendall(b"\x05\x02\x00\x02")
            else:
                sock.sendall(b"\x05\x01\x00")
            
            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != 0x05:
                return False
            
            auth_method = resp[1]
            if auth_method == 0x02:
                user_b = (self.profile.username or "").encode("utf-8")
                pwd_b = (self.profile.password or "").encode("utf-8")
                req = bytearray([0x01, len(user_b)]) + user_b + bytearray([len(pwd_b)]) + pwd_b
                sock.sendall(req)
                auth_resp = sock.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                    return False
            elif auth_method != 0x00:
                return False

            # CONNECT by domain name (0x03)
            hb = host.encode("utf-8")
            pb = port.to_bytes(2, byteorder="big")
            cmd = bytearray([0x05, 0x01, 0x00, 0x03, len(hb)]) + hb + pb
            sock.sendall(cmd)

            conn_resp = sock.recv(4)
            if len(conn_resp) < 4 or conn_resp[1] != 0x00:
                return False
            
            atyp = conn_resp[3]
            if atyp == 0x01: sock.recv(4 + 2)
            elif atyp == 0x03:
                dlen = sock.recv(1)[0]
                sock.recv(dlen + 2)
            elif atyp == 0x04: sock.recv(16 + 2)
            
            return True
        except Exception:
            return False

    def _pipe_duplex(self, sock1: socket.socket, sock2: socket.socket):
        """High-performance duplex forwarding between sockets using select."""
        sockets = [sock1, sock2]
        try:
            sock1.setblocking(False)
            sock2.setblocking(False)
            while True:
                r, _, _ = select.select(sockets, [], sockets, 30.0)
                if not r:
                    break
                for s in r:
                    other = sock2 if s is sock1 else sock1
                    data = s.recv(32768)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            try: sock1.close()
            except Exception: pass
            try: sock2.close()
            except Exception: pass
