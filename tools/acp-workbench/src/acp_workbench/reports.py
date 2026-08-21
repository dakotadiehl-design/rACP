from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

from .models import RunResult


def write_json(result: RunResult, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(result), indent=2, default=str) + "\n", encoding="utf-8")


def write_junit(result: RunResult, path: str | Path) -> None:
    suite = ET.Element("testsuite", {
        "name": "ACP Workbench",
        "tests": str(len(result.scenarios)),
        "failures": str(sum(not item.passed for item in result.scenarios)),
        "time": f"{result.duration_s:.6f}",
    })
    for scenario in result.scenarios:
        case = ET.SubElement(suite, "testcase", {
            "classname": "acp-workbench",
            "name": scenario.scenario_id,
            "time": f"{scenario.duration_s:.6f}",
        })
        if not scenario.passed:
            failure = ET.SubElement(case, "failure", {"message": scenario.error or "assertion failed"})
            failure.text = "\n".join(item.message for item in scenario.assertions if not item.passed)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(target, encoding="utf-8", xml_declaration=True)


def console_summary(result: RunResult) -> str:
    lines = []
    for scenario in result.scenarios:
        mark = "PASS" if scenario.passed else "FAIL"
        lines.append(f"{mark} {scenario.scenario_id} ({scenario.duration_s:.3f}s)")
        if scenario.error:
            lines.append(f"  {scenario.error}")
    lines.append(f"{sum(item.passed for item in result.scenarios)}/{len(result.scenarios)} passed")
    return "\n".join(lines)

