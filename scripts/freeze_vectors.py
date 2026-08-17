#!/usr/bin/env python3
"""Freeze or verify golden JSON/CBOR vectors. Regeneration requires --regen."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "src"))

from acp.codec import encode_cbor  # noqa: E402
from acp.envelope import Envelope  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--regen", action="store_true")
    args = parser.parse_args()
    vectors = ROOT / "vectors"
    manifest_path = vectors / "manifest.json"
    if not manifest_path.exists():
        print("no vectors/manifest.json", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())
    errors = []
    for item in manifest["vectors"]:
        json_path = vectors / item["json"]
        cbor_path = vectors / item["cbor"]
        env = Envelope.from_dict(json.loads(json_path.read_text()))
        encoded = encode_cbor(env)
        digest = sha256(encoded)
        if args.regen:
            cbor_path.parent.mkdir(parents=True, exist_ok=True)
            cbor_path.write_bytes(encoded)
            item["sha256"] = digest
        else:
            if not cbor_path.is_file():
                errors.append(f"missing {cbor_path}")
                continue
            actual = cbor_path.read_bytes()
            if actual != encoded:
                errors.append(f"{item['id']}: CBOR drift (run with --regen only after a spec change)")
            if item.get("sha256") and item["sha256"] != sha256(actual):
                errors.append(f"{item['id']}: sha256 mismatch")
    if args.regen:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print("regenerated", len(manifest["vectors"]), "vectors")
        return 0
    if errors:
        print("vector check failed:", file=sys.stderr)
        for err in errors:
            print(" -", err, file=sys.stderr)
        return 1
    print(f"vectors ok: {len(manifest['vectors'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
