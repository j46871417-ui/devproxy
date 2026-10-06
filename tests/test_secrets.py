import unittest
import uuid
from devproxy_pkg.core.secrets import SecretStore, EphemeralStore


class TestSecretStore(unittest.TestCase):
    def test_ephemeral_store(self):
        EphemeralStore.set("test-prof", "secret-pass")
        self.assertEqual(EphemeralStore.get("test-prof"), "secret-pass")
        EphemeralStore.delete("test-prof")
        self.assertIsNone(EphemeralStore.get("test-prof"))

    def test_secret_store_facade(self):
        name = "test-" + uuid.uuid4().hex
        self.addCleanup(SecretStore.delete_password, name)
        backend = SecretStore.store_password(name, "user1", "super-secret")
        self.assertIn(backend, ["os_keychain", "session_memory"])
        val = SecretStore.get_password(name)
        self.assertEqual(val, "super-secret")
        SecretStore.delete_password(name)


if __name__ == "__main__":
    unittest.main()
