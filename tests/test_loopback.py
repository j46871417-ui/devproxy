"""Network acceptance checks using only loopback and dummy credentials."""
import base64
from pathlib import Path
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.tunnel import LocalTunnel


def headers(sock):
    result = b''
    while b'\r\n\r\n' not in result:
        chunk = sock.recv(4096)
        if not chunk:
            break
        result += chunk
    return result


class Loopback(unittest.TestCase):
    def fixture(self, handler, scheme='http', credentials=''):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen()
        server.settimeout(3)
        self.addCleanup(server.close)
        self.errors = []

        def serve():
            try:
                peer, _ = server.accept()
                with peer:
                    peer.settimeout(2)
                    handler(peer)
            except Exception as error:
                self.errors.append(repr(error))

        self.worker = threading.Thread(target=serve, daemon=True)
        self.worker.start()
        profile = ProxyProfile.parse(f'{scheme}://{credentials}127.0.0.1:{server.getsockname()[1]}')
        tunnel = LocalTunnel(profile)
        self.addCleanup(tunnel.stop)
        port = tunnel.start()
        client = socket.create_connection(('127.0.0.1', port), timeout=2)
        self.addCleanup(client.close)
        return client

    def test_authenticated_http_connect_roundtrip(self):
        captured = []

        def upstream(peer):
            captured.append(headers(peer))
            peer.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            peer.sendall(peer.recv(1024))

        client = self.fixture(upstream, credentials='dummy:dummy-password@')
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        self.assertIn(b'200 Connection established', headers(client))
        client.sendall(b'opaque-client-data')
        self.assertEqual(client.recv(1024), b'opaque-client-data')
        self.worker.join(2)
        self.assertEqual(self.errors, [])
        self.assertIn(b'Proxy-Authorization: Basic ' + base64.b64encode(b'dummy:dummy-password'), captured[0])

    def test_https_upstream_starts_with_tls_not_plaintext_connect(self):
        captured = []
        ready = threading.Event()

        def upstream(peer):
            captured.append(peer.recv(8192))
            ready.set()

        client = self.fixture(upstream, scheme='https', credentials='dummy:dummy-password@')
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        self.assertTrue(ready.wait(2))
        self.assertEqual(captured[0][:1], b'\x16', repr(captured[0]))

    def test_connect_preserves_payload_coalesced_with_response_headers(self):
        def upstream(peer):
            peer.sendall(b'HTTP/1.1 200 Connection established\r\n\r\nORIGIN-BANNER')
            time.sleep(0.2)

        client = self.fixture(upstream)
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        result = headers(client)
        while True:
            chunk = client.recv(1024)
            if not chunk:
                break
            result += chunk
        self.assertIn(b'ORIGIN-BANNER', result)

    def test_socks5_accepts_fragmented_greeting(self):
        def upstream(peer):
            peer.recv(1024)
            peer.sendall(b'\x05')
            time.sleep(0.1)
            peer.sendall(b'\x00')
            request = peer.recv(1024)
            if request:
                peer.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                time.sleep(0.1)

        client = self.fixture(upstream, scheme='socks5h')
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        self.assertIn(b'200 Connection established', headers(client))

    def test_plain_http_forwards_only_one_message_and_replaces_client_auth(self):
        from devproxy_pkg.core.transport import read_headers, recv_exact
        captured = []
        def upstream(peer):
            head, body = read_headers(peer)
            if len(body) < 4:
                body += recv_exact(peer, 4-len(body))
            captured.append(head+body)
            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        client = self.fixture(upstream, credentials='dummy:dummy-password@')
        client.sendall(b'POST http://example.test/path HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic client-secret\r\nContent-Length: 4\r\n\r\nBODYGET http://other.test/ HTTP/1.1\r\nProxy-Authorization: pipelined-secret\r\n\r\n')
        self.assertIn(b'200 OK', headers(client))
        self.worker.join(2)
        self.assertEqual(self.errors, [])
        self.assertTrue(captured[0].endswith(b'BODY'))
        self.assertNotIn(b'client-secret',captured[0])
        self.assertNotIn(b'pipelined-secret',captured[0])

    def test_chunked_body_drops_proxy_authorization_trailer(self):
        from devproxy_pkg.core.transport import read_headers
        captured = []
        def upstream(peer):
            head, body = read_headers(peer)
            while not body.endswith(b'0\r\nX-Safe: yes\r\n\r\n'):
                part = peer.recv(4096)
                if not part:
                    break
                body += part
            captured.append(head+body)
            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        client = self.fixture(upstream)
        client.sendall(b'POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nBODY\r\n0\r\nProxy-Authorization: trailer-secret\r\nX-Safe: yes\r\n\r\n')
        self.assertIn(b'200 OK', headers(client))
        self.worker.join(2)
        self.assertEqual(self.errors, [])
        self.assertNotIn(b'trailer-secret',captured[0])
        self.assertTrue(captured[0].endswith(b'4\r\nBODY\r\n0\r\nX-Safe: yes\r\n\r\n'))

    def test_http_expect_continue_does_not_deadlock_body(self):
        from devproxy_pkg.core.transport import read_headers, recv_exact
        def upstream(peer):
            head, body = read_headers(peer)
            if len(body) < 4:
                body += recv_exact(peer, 4-len(body))
            self.assertNotIn(b'Expect:',head)
            self.assertEqual(body,b'BODY')
            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        client = self.fixture(upstream)
        client.sendall(b'POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n')
        self.assertIn(b'100 Continue', headers(client))
        client.sendall(b'BODY')
        self.assertIn(b'200 OK', headers(client))
        self.worker.join(2)
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
