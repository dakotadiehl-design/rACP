"""Human, JSON, transcript, and JUnit reporting."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .model import RunReport, Status


def write_report(report: RunReport, output_dir: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_dir / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = output_dir / f"{stamp}-{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True)

    payload = asdict(report)
    (run_dir / "report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    transcript = "".join(f"{entry.elapsed:10.3f} {entry.direction:4} {entry.line}\n" for entry in report.transcripts)
    (run_dir / "wire.log").write_text(transcript, encoding="utf-8")
    _write_junit(report, run_dir / "junit.xml")
    return run_dir


def _write_junit(report: RunReport, path: Path) -> None:
    failures = sum(result.status is Status.FAIL for result in report.results)
    skipped = sum(result.status is Status.SKIP for result in report.results)
    suite = ET.Element(
        "testsuite",
        name="Prism rACP integration",
        tests=str(len(report.results)),
        failures=str(failures),
        skipped=str(skipped),
        time=f"{sum(item.duration for item in report.results):.6f}",
    )
    for result in report.results:
        case = ET.SubElement(suite, "testcase", name=result.name, time=f"{result.duration:.6f}")
        if result.status is Status.FAIL:
            ET.SubElement(case, "failure", message=result.detail).text = result.detail
        elif result.status is Status.SKIP:
            ET.SubElement(case, "skipped", message=result.detail)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def summary(report: RunReport) -> str:
    counts = {status: sum(item.status is status for item in report.results) for status in Status}
    lines = [
        f"Prism rACP target: {report.target}",
        f"PASS {counts[Status.PASS]}  FAIL {counts[Status.FAIL]}  SKIP {counts[Status.SKIP]}",
    ]
    for result in report.results:
        detail = f" — {result.detail}" if result.detail else ""
        lines.append(f"[{result.status.value.upper():4}] {result.name}{detail}")
    return "\n".join(lines)

