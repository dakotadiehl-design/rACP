#!/usr/bin/env python3
"""Fail if schema files and registry.json drift apart."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema"
REGISTRY = SCHEMA / "registry.json"

REQUIRED_KEYS = {
    "type",
    "min_protocol",
    "profiles",
    "direction",
    "valid_senders",
    "valid_destinations",
    "qos_default",
    "qos_allowed",
    "ack",
    "idempotent",
    "legal_before_handshake",
    "security_class",
    "schema",
}


def resolve_schema(ref: str) -> Path:
    path = ref.split("#", 1)[0]
    return SCHEMA / path


def main() -> int:
    if not REGISTRY.exists():
        print("missing schema/registry.json — run scripts/gen_registry.py", file=sys.stderr)
        return 1
    data = json.loads(REGISTRY.read_text())
    messages = data["messages"]
    types = [m["type"] for m in messages]
    errors: list[str] = []
    if len(types) != len(set(types)):
        errors.append("duplicate message types in registry")
    for msg in messages:
        missing = REQUIRED_KEYS - set(msg)
        if missing:
            errors.append(f"{msg.get('type', '?')}: missing keys {sorted(missing)}")
            continue
        schema_path = resolve_schema(msg["schema"])
        if not schema_path.is_file():
            errors.append(f"{msg['type']}: schema file missing: {schema_path}")
            continue
        if "#" in msg["schema"]:
            pointer = msg["schema"].split("#", 1)[1]
            doc = json.loads(schema_path.read_text())
            node: object = doc
            for part in pointer.strip("/").split("/"):
                if not isinstance(node, dict) or part not in node:
                    errors.append(f"{msg['type']}: schema pointer {pointer} not found")
                    break
                node = node[part]
    # Every family messages.schema.json should be referenced at least once
    for family_file in SCHEMA.rglob("*.schema.json"):
        rel = family_file.relative_to(SCHEMA).as_posix()
        if rel in {"envelope.schema.json", "common/defs.schema.json"}:
            continue
        referenced = any(m["schema"].split("#", 1)[0] == rel for m in messages)
        if not referenced:
            errors.append(f"schema file not referenced by registry: {rel}")
    by_type = {m["type"]: m for m in messages}
    manifest = ROOT / "vectors" / "manifest.json"
    if manifest.is_file():
        for item in json.loads(manifest.read_text())["vectors"]:
            vec_type = item["id"]
            if vec_type not in by_type:
                errors.append(f"vector {vec_type} has no registry row")
                continue
            payload = json.loads((ROOT / "vectors" / item["json"]).read_text())
            if payload.get("type") != vec_type:
                errors.append(f"vector {vec_type} type mismatch")
            if payload.get("qos") not in by_type[vec_type]["qos_allowed"]:
                errors.append(f"vector {vec_type} qos not allowed")
    errors.extend(_packaged_data_drift())
    try:
        errors.extend(_compile_and_validate_vectors(messages))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"schema compiler failed: {exc}")
    if errors:
        print("registry check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"registry ok: {len(messages)} messages")
    return 0


def _compile_and_validate_vectors(messages: list[dict]) -> list[str]:
    sys.path.insert(0, str(ROOT / "python" / "src"))
    from acp.validate import ValidationError, validate_message  # type: ignore

    errors: list[str] = []
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    registry = Registry()
    for path in SCHEMA.rglob("*.schema.json"):
        doc = json.loads(path.read_text())
        uri = doc.get("$id") or path.resolve().as_uri()
        registry = registry.with_resource(uri, Resource.from_contents(doc, default_specification=DRAFT202012))
        cls = validator_for(doc)
        cls.check_schema(doc)

    manifest = ROOT / "vectors" / "manifest.json"
    if not manifest.is_file():
        return errors
    from acp.codec import decode_cbor  # type: ignore

    for item in json.loads(manifest.read_text())["vectors"]:
        data = json.loads((ROOT / "vectors" / item["json"]).read_text())
        try:
            validate_message(data)
        except ValidationError as exc:
            errors.append(f"vector {item['id']} failed schema: {exc}")
        cbor_path = ROOT / "vectors" / item["cbor"]
        if cbor_path.is_file():
            try:
                again = decode_cbor(cbor_path.read_bytes())
                validate_message(again.to_dict())
            except Exception as exc:  # noqa: BLE001
                errors.append(f"vector {item['id']} decoded CBOR failed schema: {exc}")
    invalid = ROOT / "schema" / "invariants" / "invalid_envelope.json"
    if invalid.is_file():
        try:
            validate_message(json.loads(invalid.read_text()))
            errors.append("invalid fixture unexpectedly passed schema validation")
        except (ValidationError, Exception):
            pass
    return errors


def _packaged_data_drift() -> list[str]:
    errors: list[str] = []
    packaged = ROOT / "python" / "src" / "acp" / "data"
    pairs = [
        (SCHEMA / "constants.json", packaged / "constants.json", "packaged constants.json"),
        (REGISTRY, packaged / "registry.json", "packaged registry.json"),
    ]
    for src, dst, label in pairs:
        if not dst.is_file():
            errors.append(f"{label} is missing")
        elif dst.read_bytes() != src.read_bytes():
            errors.append(f"{label} is out of date")
    schema_packaged = packaged / "schema"
    for path in SCHEMA.rglob("*"):
        if not path.is_file() or path.suffix != ".json":
            continue
        rel = path.relative_to(SCHEMA)
        other = schema_packaged / rel
        if not other.is_file():
            errors.append(f"packaged schema missing {rel.as_posix()}")
        elif other.read_bytes() != path.read_bytes():
            errors.append(f"packaged schema drift: {rel.as_posix()}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
