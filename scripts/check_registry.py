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
    referenced_files = {m["schema"].split("#", 1)[0] for m in messages}
    referenced_files.update(_schema_ref_closure(referenced_files))
    for family_file in SCHEMA.rglob("*.schema.json"):
        rel = family_file.relative_to(SCHEMA).as_posix()
        if rel in {"envelope.schema.json", "common/defs.schema.json"}:
            continue
        if rel not in referenced_files:
            errors.append(f"schema file not referenced by registry: {rel}")
    by_type = {m["type"]: m for m in messages}
    manifest = ROOT / "vectors" / "manifest.json"
    covered: set[str] = set()
    if manifest.is_file():
        for item in json.loads(manifest.read_text())["vectors"]:
            vec_type = item.get("type") or item["id"]
            covered.add(vec_type)
            if vec_type not in by_type:
                errors.append(f"vector {item['id']} has no registry row")
                continue
            payload = json.loads((ROOT / "vectors" / item["json"]).read_text())
            if payload.get("type") != vec_type:
                errors.append(f"vector {item['id']} type mismatch")
            if payload.get("qos") not in by_type[vec_type]["qos_allowed"]:
                errors.append(f"vector {item['id']} qos not allowed")
    for typ in by_type:
        if typ not in covered:
            errors.append(f"missing vector for {typ}")
    errors.extend(_packaged_data_drift())
    errors.extend(_schema_pack_drift())
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


def _schema_ref_closure(roots: set[str]) -> set[str]:
    found: set[str] = set()
    pending = list(roots)
    while pending:
        rel = pending.pop()
        path = SCHEMA / rel
        if not path.is_file():
            continue
        text = path.read_text()
        doc = json.loads(text)
        for ref in _walk_refs(doc):
            target = ref.split("#", 1)[0]
            if not target:
                continue
            if target.startswith("../"):
                target = str((path.parent / target).resolve().relative_to(SCHEMA.resolve()))
            elif "/" not in target and not target.startswith("http"):
                target = f"{path.parent.relative_to(SCHEMA).as_posix()}/{target}"
            if target.endswith(".json") and target not in found and target not in roots:
                found.add(target)
                pending.append(target)
    return found


def _walk_refs(node: object) -> list[str]:
    refs: list[str] = []
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for value in node.values():
            refs.extend(_walk_refs(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_walk_refs(item))
    return refs


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
                decoded = again.to_dict()
                payload = decoded.get("payload")
                data = payload.get("data") if isinstance(payload, dict) else None
                if again.type == "resource.chunk" and isinstance(data, (bytes, bytearray)):
                    import base64
                    payload = dict(payload)
                    payload["data"] = base64.b64encode(bytes(data)).decode("ascii")
                    decoded["payload"] = payload
                validate_message(decoded)
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
        (REGISTRY, ROOT / "Sources" / "AuroraACP" / "Session" / "registry.json", "Swift registry.json"),
        (SCHEMA / "constants.json", ROOT / "Sources" / "AuroraACP" / "Security" / "constants.json", "Swift constants.json"),
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


def _schema_pack_drift() -> list[str]:
    docs: dict[str, object] = {}
    for path in sorted(SCHEMA.rglob("*.schema.json")):
        rel = path.relative_to(SCHEMA).as_posix()
        docs[rel] = json.loads(path.read_text())
    messages = {row["type"]: row["schema"] for row in json.loads(REGISTRY.read_text())["messages"]}
    expected = json.dumps({"docs": docs, "messages": messages}, indent=2, sort_keys=True) + "\n"
    errors: list[str] = []
    for dest in (
        SCHEMA / "schema_pack.json",
        ROOT / "python" / "src" / "acp" / "data" / "schema" / "schema_pack.json",
        ROOT / "Sources" / "AuroraACP" / "Codec" / "schema_pack.json",
    ):
        if not dest.is_file():
            errors.append(f"schema pack missing {dest}")
        elif dest.read_text() != expected:
            errors.append(f"schema pack out of date: {dest} (run scripts/pack_schemas.py)")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
