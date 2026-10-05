"""Real loopback tests, including verified HTTPS upstream and backpressure."""
import datetime
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from devproxy_pkg.core.profile import ProxyProfile
from devproxy_pkg.core.transport import read_headers, recv_exact
from devproxy_pkg.core.tunnel import LocalTunnel

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError:
    x509 = None


@unittest.skipIf(x509 is None, 'Install requirements-test.txt for TLS acceptance tests')
class NetworkAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = Path(cls.directory.name)
        now = datetime.datetime.now(datetime.timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DevProxy temporary test CA')])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=2))
              .not_valid_after(now + datetime.timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
              .sign(key, hashes.SHA256()))
        (cls.base / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        for variant in ('valid', 'expired', 'mismatch'):
            server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'loopback')]))
                    .issuer_name(name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=2))
                    .not_valid_after(now - datetime.timedelta(days=1) if variant == 'expired' else now + datetime.timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.2' if variant == 'mismatch' else '127.0.0.1'))]), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(key, hashes.SHA256()))
            (cls.base / (variant + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (cls.base / (variant + '.key')).write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def upstream(self, handler, tls=None):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(5)
        listener.settimeout(4)
        self.addCleanup(listener.close)
        errors = []

        def serve():
            try:
                peer, _ = listener.accept()
                if tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.base / (tls + '.pem'), self.base / (tls + '.key'))
                    peer = context.wrap_socket(peer, server_side=True)
                with peer:
                    peer.settimeout(40)
                    handler(peer)
            except (OSError, ValueError) as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        self.addCleanup(lambda: worker.join(2))
        return listener.getsockname()[1], errors

    def client(self, port, protocol='http', ca=True):
        profile = ProxyProfile.parse(f'{protocol}://dummy:dummy-password@127.0.0.1:{port}')
        if ca:
            profile.ca_file = str(self.base / 'ca.pem')
        tunnel = LocalTunnel(profile)
        self.addCleanup(tunnel.stop)
        client = socket.create_connection(('127.0.0.1', tunnel.start()), timeout=40)
        self.addCleanup(client.close)
        return client, tunnel

    def test_verified_https_with_auth_and_large_bidirectional_transfer(self):
        payload = os.urandom(2 * 1024 * 1024)
        captured = []

        def echo(peer):
            head, rest = read_headers(peer)
            captured.append(head)
            peer.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            # Force buffering and backpressure instead of a single small send.
            time.sleep(0.1)
            data = rest + recv_exact(peer, len(payload) - len(rest))
            peer.sendall(data)

        port, errors = self.upstream(echo, 'valid')
        client, _ = self.client(port, 'https')
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        self.assertIn(b'200', read_headers(client)[0])
        client.sendall(payload)
        self.assertEqual(recv_exact(client, len(payload)), payload)
        self.assertIn(b'Proxy-Authorization: Basic ', captured[0])
        self.assertFalse(errors)

    def test_untrusted_expired_and_hostname_mismatch_fail_closed(self):
        for variant, trusted in [('valid', False), ('expired', True), ('mismatch', True)]:
            with self.subTest(certificate=variant, trusted=trusted):
                touched = []
                port, _ = self.upstream(lambda peer: touched.append(peer.recv(2048)), variant)
                client, _ = self.client(port, 'https', ca=trusted)
                client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
                self.assertIn(b'502', read_headers(client)[0])
                self.assertEqual(touched, [])

    def test_fragmented_request_and_half_close_preserve_final_response(self):
        def origin(peer):
            read_headers(peer)
            peer.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            body = bytearray()
            while True:
                data = peer.recv(1024)
                if not data:
                    break
                body.extend(data)
            peer.sendall(b'final:' + body)

        port, _ = self.upstream(origin)
        client, _ = self.client(port)
        client.sendall(b'CON')
        time.sleep(0.05)
        client.sendall(b'NECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        read_headers(client)
        client.sendall(b'payload')
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(recv_exact(client, 13), b'final:payload')

    def test_idle_connection_survives_old_30_second_cutoff(self):
        def echo(peer):
            read_headers(peer)
            peer.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            peer.sendall(peer.recv(1024))

        port, _ = self.upstream(echo)
        client, _ = self.client(port)
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        read_headers(client)
        time.sleep(31)
        client.sendall(b'still-alive')
        self.assertEqual(recv_exact(client, 11), b'still-alive')

    def test_stop_closes_active_connections(self):
        def hold(peer):
            read_headers(peer)
            peer.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            peer.recv(1024)

        port, _ = self.upstream(hold)
        client, tunnel = self.client(port)
        client.sendall(b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n')
        read_headers(client)
        tunnel.stop()
        self.assertEqual(client.recv(1024), b'')
        self.assertFalse(tunnel.is_running)

    def test_loopback_only_and_bounded_headers(self):
        with self.assertRaises(ValueError):
            LocalTunnel(ProxyProfile.parse('http://localhost:8080'), bind_host='0.0.0.0')
        tunnel = LocalTunnel(ProxyProfile.parse('http://localhost:1'))
        self.addCleanup(tunnel.stop)
        client = socket.create_connection(('127.0.0.1', tunnel.start()), timeout=3)
        self.addCleanup(client.close)
        with patch('devproxy_pkg.core.tunnel.connect_upstream') as connect:
            try:
                client.sendall(b'GET / HTTP/1.1\r\nX: ' + b'x' * 70000)
                self.assertIn(b'400', client.recv(1024))
            except ConnectionResetError:
                # Windows may reset a rejected connection with unread input
                # instead of delivering the queued 400 response. Both reject
                # oversized headers; neither may open an upstream connection.
                pass
            tunnel.stop()
            connect.assert_not_called()
