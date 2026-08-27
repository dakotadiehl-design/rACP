#!/usr/bin/env python3
"""Validate ACP documentation status, local links, and high-risk stale claims."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURRENT = [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]
DOCUMENTS = [*CURRENT, ROOT / "DesignDocs/README.md", *(ROOT / "DesignDocs").rglob("*.md")]
REQUIRED = {
    "docs/README.md",
    "docs/ACP_SPEC.md",
    "docs/SECURITY.md",
    "docs/REMOTE.md",
    "docs/STATE_MACHINES.md",
    "docs/WIRE_ENCODING.md",
    "docs/IMPLEMENTATION_STATUS.md",
    "docs/TRACEABILITY.md",
}

failures: list[str] = []
for relative in REQUIRED:
    text = (ROOT / relative).read_text(encoding="utf-8")
    if "Status:" not in text:
        failures.append(f"{relative}: missing status metadata")

link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")
for path in dict.fromkeys(DOCUMENTS):
    text = path.read_text(encoding="utf-8")
    for target in link_pattern.findall(text):
        if target.startswith(("http://", "https://", "#")):
            continue
        destination = target.split("#", 1)[0]
        if destination and not (path.parent / destination).resolve().exists():
            failures.append(f"{path.relative_to(ROOT)}: broken link {target}")

security = (ROOT / "docs/SECURITY.md").read_text(encoding="utf-8")
for required in (
    "Neither secure custody path available",
    "explicit_audited_grace",
    "Conductor may join an existing domain",
    "There is no fallback to an exportable software key",
):
    if required not in security:
        failures.append(f"docs/SECURITY.md: missing frozen rule: {required}")
if "Candidate Freeze 2.1.1" in security:
    failures.append("docs/SECURITY.md: stale Candidate Freeze status")

for path in (ROOT / "DesignDocs").rglob("*.md"):
    if path.name != "README.md" and "> **Historical record.**" not in path.read_text(encoding="utf-8"):
        failures.append(f"{path.relative_to(ROOT)}: missing historical banner")

if failures:
    raise SystemExit("FAIL:\n" + "\n".join(f"- {item}" for item in failures))
print(f"PASS: documentation metadata, historical labels, frozen claims, and local links ({len(CURRENT)} current files)")
