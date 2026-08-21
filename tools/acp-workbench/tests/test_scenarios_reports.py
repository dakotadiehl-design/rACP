import json
import tempfile
import unittest
from pathlib import Path

from acp_workbench.models import RunResult, ScenarioResult
from acp_workbench.reports import write_json, write_junit
from acp_workbench.scenarios import discover_scenarios, load_scenario, parse_scenario, substitute

ROOT = Path(__file__).parents[1]


class ScenarioTests(unittest.TestCase):
    def test_all_bundled_scenarios_parse(self):
        files = discover_scenarios(ROOT / "scenarios")
        self.assertGreaterEqual(len(files), 3)
        for path in files:
            self.assertEqual(load_scenario(path).schema_version, 1)

    def test_strict_unknown_key(self):
        with self.assertRaisesRegex(ValueError, "unknown scenario keys"):
            parse_scenario({
                "schema_version": 1, "id": "x", "name": "x", "simulate": "remote",
                "profile": "remote-prism", "steps": [{"connect": {}}], "typo": True,
            })

    def test_strict_unknown_step_parameter(self):
        with self.assertRaisesRegex(ValueError, "unknown parameters"):
            parse_scenario({
                "schema_version": 1,
                "id": "x",
                "name": "x",
                "simulate": "remote",
                "profile": "remote-prism",
                "steps": [{"connect": {"typo": True}}],
            })

    def test_substitution(self):
        self.assertEqual(substitute({"x": "${value}", "y": "a-${value}"}, {"value": 2}), {"x": 2, "y": "a-2"})

    def test_reports(self):
        run = RunResult(True, [ScenarioResult("x", "X", True, [], "now", 0.1)], "now", 0.1)
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "result.json"
            xml_path = Path(directory) / "result.xml"
            write_json(run, json_path)
            write_junit(run, xml_path)
            self.assertTrue(json.loads(json_path.read_text())["passed"])
            self.assertIn("testsuite", xml_path.read_text())


if __name__ == "__main__":
    unittest.main()
