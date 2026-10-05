import unittest
from devproxy_pkg.core.profile import ProxyProfile


class TestProxyProfile(unittest.TestCase):
    def test_parse_http(self):
        p = ProxyProfile.parse("http://127.0.0.1:8080")
        self.assertEqual(p.protocol, "http")
        self.assertEqual(p.host, "127.0.0.1")
        self.assertEqual(p.port, 8080)
        self.assertFalse(p.has_auth)
        self.assertEqual(p.to_url(), "http://127.0.0.1:8080")

    def test_parse_socks5_with_auth(self):
        p = ProxyProfile.parse("socks5://user:pass123@myproxy.net:1080")
        self.assertEqual(p.protocol, "socks5")
        self.assertEqual(p.username, "user")
        self.assertEqual(p.password, "pass123")
        self.assertTrue(p.is_socks)
        self.assertEqual(p.to_safe_url(), "socks5://user:***@myproxy.net:1080")

    def test_parse_socks5h(self):
        p = ProxyProfile.parse("socks5h://remote.host:10808")
        self.assertEqual(p.protocol, "socks5h")
        self.assertTrue(p.dns_remote)

    def test_parse_host_port_colon(self):
        p = ProxyProfile.parse("192.168.1.50:8888")
        self.assertEqual(p.protocol, "http")
        self.assertEqual(p.host, "192.168.1.50")
        self.assertEqual(p.port, 8888)

    def test_parse_host_port_user_pass(self):
        p = ProxyProfile.parse("proxy.co:3128:alice:secretP@ss")
        self.assertEqual(p.host, "proxy.co")
        self.assertEqual(p.port, 3128)
        self.assertEqual(p.username, "alice")
        self.assertEqual(p.password, "secretP@ss")
        self.assertEqual(p.to_safe_url(), "http://alice:***@proxy.co:3128")

    def test_ipv6_bracketed(self):
        p = ProxyProfile.parse("http://[2001:db8::1]:8080")
        self.assertEqual(p.host, "2001:db8::1")
        self.assertEqual(p.port, 8080)
        self.assertEqual(p.to_url(), "http://[2001:db8::1]:8080")

    def test_url_encoded_symbols(self):
        p = ProxyProfile.parse("http://user%40domain:p%40ss%23word@proxy:8080")
        self.assertEqual(p.username, "user@domain")
        self.assertEqual(p.password, "p@ss#word")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            ProxyProfile.parse("http://host:99999")


if __name__ == "__main__":
    unittest.main()
