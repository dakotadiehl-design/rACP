import contextlib
import io
import unittest
from pathlib import Path

from acp_workbench.cli import main

ROOT = Path(__file__).parents[1]


class CliTests(unittest.TestCase):
    def test_list_profiles(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["list", "profiles"])
        self.assertEqual(result, 0)
        self.assertIn("remote-prism", output.getvalue())

    def test_validate(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["validate", str(ROOT / "scenarios")])
        self.assertEqual(result, 0)
        self.assertIn("go-authoritative-state", output.getvalue())

    def test_live_target_is_refused_without_connecting(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            result = main([
                "connect",
                "--target",
                "wss://prism.example/acp",
                "--duration",
                "0.01",
            ])
        self.assertEqual(result, 5)
        self.assertIn("non-loopback", error.getvalue())


if __name__ == "__main__":
    unittest.main()
