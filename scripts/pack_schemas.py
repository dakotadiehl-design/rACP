#!/usr/bin/env python3
"""Pack canonical schemas + registry pointers for Rust/Swift validators."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema"
OUT = SCHEMA / "schema_pack.json"
PYTHON_OUT = ROOT / "python" / "src" / "acp" / "data" / "schema" / "schema_pack.json"
SWIFT_OUT = ROOT / "Sources" / "AuroraACP" / "Codec" / "schema_pack.json"


def main() -> int:
    docs: dict[str, object] = {}
    for path in sorted(SCHEMA.rglob("*.schema.json")):
        rel = path.relative_to(SCHEMA).as_posix()
        docs[rel] = json.loads(path.read_text())
    registry = json.loads((SCHEMA / "registry.json").read_text())
    messages = {row["type"]: row["schema"] for row in registry["messages"]}
    pack = {"docs": docs, "messages": messages}
    text = json.dumps(pack, indent=2, sort_keys=True) + "\n"
    for dest in (OUT, PYTHON_OUT, SWIFT_OUT):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    print(f"packed {len(docs)} schemas, {len(messages)} messages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
