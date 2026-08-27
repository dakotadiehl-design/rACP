#!/usr/bin/env python3
"""Idempotently label DesignDocs Markdown files as historical records."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in sorted((ROOT / "DesignDocs").rglob("*.md")):
    if path.name == "README.md":
        continue
    text = path.read_text(encoding="utf-8")
    if "> **Historical record.**" in text:
        continue
    lines = text.splitlines(keepends=True)
    heading = next((index for index, line in enumerate(lines) if line.startswith("#")), None)
    if heading is None:
        lines.insert(0, "# Historical ACP record\n")
        heading = 0
    depth = len(path.relative_to(ROOT / "DesignDocs").parents) - 1
    prefix = "../" * (depth + 1)
    banner = (
        "\n> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. "
        f"For current normative and integration guidance, start at [`docs/README.md`]({prefix}docs/README.md).\n"
    )
    lines.insert(heading + 1, banner)
    path.write_text("".join(lines), encoding="utf-8")
