import os
import unittest
from unittest.mock import patch

from acp_workbench.config import enforce_target_safety, from_environment, is_loopback_target
from acp_workbench.models import ConnectionConfig
from acp_workbench.transcript import redact


class ConfigTests(unittest.TestCase):
    def test_loopback(self):
        self.assertTrue(is_loopback_target("ws://127.0.0.1:123/acp"))
        self.assertTrue(is_loopback_target("ws://[::1]:123/acp"))
        self.assertFalse(is_loopback_target("wss://prism.example/acp"))
        with self.assertRaises(PermissionError):
            enforce_target_safety("wss://prism.example/acp", allow_live_target=False)

    def test_environment(self):
        with patch.dict(os.environ, {"ACP_WORKBENCH_TIMEOUT": "7.5", "ACP_WORKBENCH_ALLOW_PLAINTEXT": "true"}):
            config = from_environment(ConnectionConfig(target="ws://localhost/acp"))
        self.assertEqual(config.timeout, 7.5)
        self.assertTrue(config.allow_plaintext)

    def test_redaction(self):
        self.assertEqual(redact({"token": "bad", "nested": [{"password": "bad"}]}), {
            "token": {"$redacted": True}, "nested": [{"password": {"$redacted": True}}],
        })

    def test_nested_trust_material_is_redacted(self):
        cleaned = redact({"payload": {
            "auth": {"mode": "enrolled", "credential": "bearer", "proof": "proof"},
            "device_credential": "secret",
            "public_label": "safe",
        }})
        self.assertEqual(cleaned["payload"]["auth"], {"$redacted": True})
        self.assertEqual(cleaned["payload"]["device_credential"], {"$redacted": True})
        self.assertEqual(cleaned["payload"]["public_label"], "safe")


if __name__ == "__main__":
    unittest.main()
