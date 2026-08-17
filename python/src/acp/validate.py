"""JSON Schema 2020-12 validation for ACP envelopes and payloads."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .constants import schema_root
from .registry import lookup


class ValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@lru_cache(maxsize=1)
def _registry() -> Registry:
    registry = Registry()
    root = schema_root()
    for path in root.rglob("*.schema.json"):
        doc = json.loads(path.read_text())
        uri = doc.get("$id") or path.resolve().as_uri()
        registry = registry.with_resource(uri, Resource.from_contents(doc, default_specification=DRAFT202012))
    return registry


@lru_cache(maxsize=64)
def _schema_document(rel: str) -> dict[str, Any]:
    return json.loads((schema_root() / rel).read_text())


def _payload_schema_uri(ref: str) -> dict[str, Any]:
    path, _, pointer = ref.partition("#")
    doc = _schema_document(path)
    base = doc.get("$id") or (schema_root() / path).resolve().as_uri()
    if pointer:
        return {"$ref": base + "#" + pointer}
    return {"$ref": base}


def validate_message(data: dict[str, Any]) -> None:
    try:
        Draft202012Validator(_schema_document("envelope.schema.json"), registry=_registry()).validate(data)
    except JsonSchemaError as exc:
        raise ValidationError("malformed_envelope", exc.message) from exc
    message_type = str(data.get("type", ""))
    row = lookup(message_type)
    if row is None:
        raise ValidationError("unsupported_message", f"unknown type {message_type}")
    try:
        Draft202012Validator(_payload_schema_uri(row["schema"]), registry=_registry()).validate(data.get("payload"))
    except JsonSchemaError as exc:
        raise ValidationError("invalid_type", exc.message) from exc


def filter_payload(message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    row = lookup(message_type)
    if not row:
        return payload
    path, _, pointer = row["schema"].partition("#")
    doc = _schema_document(path)
    node: Any = doc
    if pointer:
        for part in pointer.strip("/").split("/"):
            if not isinstance(node, dict) or part not in node:
                return payload
            node = node[part]
    props = _collect_properties(node, doc)
    if not props:
        return payload
    return {k: v for k, v in payload.items() if k in props}


def _collect_properties(node: Any, doc: dict[str, Any], seen: set[str] | None = None) -> set[str]:
    seen = seen or set()
    props: set[str] = set()
    if not isinstance(node, dict):
        return props
    if "properties" in node:
        props.update(node["properties"])
    for key in ("allOf", "anyOf", "oneOf"):
        for item in node.get(key) or []:
            props.update(_collect_properties(item, doc, seen))
    ref = node.get("$ref")
    if isinstance(ref, str) and ref not in seen:
        seen.add(ref)
        if ref.startswith("#/"):
            target: Any = doc
            for part in ref.strip("#/").split("/"):
                target = target[part]
            props.update(_collect_properties(target, doc, seen))
        else:
            path, _, pointer = ref.replace("../", "").partition("#")
            try:
                other = _schema_document(path)
            except OSError:
                return props
            target = other
            if pointer:
                for part in pointer.strip("/").split("/"):
                    target = target[part]
            props.update(_collect_properties(target, other, seen))
    return props
