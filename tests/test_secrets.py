import unittest
from devproxy_pkg.core.secrets import SecretStore, EphemeralStore


class TestSecretStore(unittest.TestCase):
    def test_ephemeral_store(self):
        EphemeralStore.set("test-prof", "secret-pass")
        self.assertEqual(EphemeralStore.get("test-prof"), "secret-pass")
        EphemeralStore.delete("test-prof")
        self.assertIsNone(EphemeralStore.get("test-prof"))

    def test_secret_store_facade(self):
        backend = SecretStore.store_password("unit-test-prof", "user1", "super-secret")
        self.assertIn(backend, ["os_keychain", "session_memory"])
        val = SecretStore.get_password("unit-test-prof")
        self.assertEqual(val, "super-secret")
        SecretStore.delete_password("unit-test-prof")


if __name__ == "__main__":
    unittest.main()
