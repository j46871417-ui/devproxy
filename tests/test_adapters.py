import unittest
from devproxy_pkg.adapters import list_adapters, get_adapter
from devproxy_pkg.core.profile import ProxyProfile


class TestAdapters(unittest.TestCase):
    def test_registered_adapters(self):
        ids = [a.app_id for a in list_adapters()]
        expected = ["antigravity", "vscode", "cursor", "windsurf", "vscodium", "opencode", "codex", "codex-gui"]
        for exp in expected:
            self.assertIn(exp, ids)

    def test_antigravity_flags(self):
        adapter = get_adapter("antigravity")
        self.assertIsNotNone(adapter)
        p = ProxyProfile.parse("http://127.0.0.1:8080")
        flags = adapter.get_cli_launch_flags(p)
        self.assertTrue(any("--proxy-server" in f for f in flags))

    def test_limitations_defined(self):
        for adapter in list_adapters():
            lims = adapter.get_limitations()
            self.assertIsInstance(lims, list)
            self.assertGreater(len(lims), 0)


if __name__ == "__main__":
    unittest.main()
