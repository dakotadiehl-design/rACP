"""JSON + ACP-CDE-1.2 envelope codec."""

from __future__ import annotations

import base64
import json
import math
from typing import Any

from .cbor_cde import CborError, CborTag
from .cbor_cde import decode as cbor_decode
from .cbor_cde import encode as cbor_encode
from .constants import limits
from .envelope import Envelope
from .types import parse_ts
from .validate import ValidationError, filter_payload, validate_message


class CodecError(ValueError):
    pass


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise CodecError("NaN/Inf forbidden")
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)


def _prep_for_cbor(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _prep_for_cbor(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_prep_for_cbor(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


def _restore_chunk_bytes(payload: dict[str, Any], message_type: str) -> dict[str, Any]:
    if message_type != "resource.chunk":
        return payload
    data = payload.get("data")
    if isinstance(data, str):
        try:
            decoded = base64.b64decode(data, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise CodecError("invalid resource.chunk data") from exc
        payload = dict(payload)
        payload["data"] = decoded
        data = decoded
    if isinstance(data, (bytes, bytearray)) and payload.get("length") is not None:
        try:
            declared = int(payload["length"])
        except (TypeError, ValueError) as exc:
            raise CodecError("invalid resource.chunk length") from exc
        if declared != len(data):
            raise CodecError("resource.chunk length does not match decoded bytes")
    return payload


def _check_size(raw: bytes | str) -> None:
    n = len(raw) if isinstance(raw, bytes) else len(raw.encode("utf-8"))
    if n > limits()["max_message_bytes"]:
        raise CodecError("envelope exceeds max_message_bytes")


def _envelope_from_object(data: dict[str, Any]) -> Envelope:
    _reject_nonfinite(data)
    payload = data.get("payload")
    if (
        str(data.get("type", "")) == "resource.chunk"
        and isinstance(payload, dict)
        and isinstance(payload.get("data"), (bytes, bytearray))
    ):
        payload = dict(payload)
        payload["data"] = base64.b64encode(bytes(payload["data"])).decode("ascii")
        data = dict(data)
        data["payload"] = payload
    try:
        validate_message(data)
    except ValidationError as exc:
        raise CodecError(f"{exc.code}: {exc}") from exc
    if isinstance(data.get("payload"), dict):
        message_type = str(data.get("type", ""))
        payload = filter_payload(message_type, dict(data["payload"]))
        payload = _restore_chunk_bytes(payload, message_type)
        data = dict(data)
        data["payload"] = payload
    try:
        return Envelope.from_dict(data)
    except Exception as exc:  # noqa: BLE001
        raise CodecError(str(exc)) from exc


def encode_json(envelope: Envelope) -> bytes:
    data = envelope.to_dict()
    _reject_nonfinite(data)
    payload = data.get("payload")
    if envelope.type == "resource.chunk" and isinstance(payload, dict):
        chunk = dict(payload)
        raw = chunk.get("data")
        if isinstance(raw, (bytes, bytearray)):
            chunk["data"] = base64.b64encode(bytes(raw)).decode("ascii")
        data["payload"] = chunk
    return json.dumps(
        data,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def encode_cbor(envelope: Envelope) -> bytes:
    data = envelope.to_dict()
    _reject_nonfinite(data)
    ts = data["timestamp_utc"]
    data["timestamp_utc"] = CborTag(0, ts)
    payload = data.get("payload")
    if envelope.type == "resource.chunk" and isinstance(payload, dict):
        chunk = dict(payload)
        raw = chunk.get("data")
        if isinstance(raw, str):
            chunk["data"] = base64.b64decode(raw)
        data["payload"] = chunk
    encoded = cbor_encode(_prep_for_cbor(data))
    if len(encoded) > limits()["max_message_bytes"]:
        raise CodecError("envelope exceeds max_message_bytes")
    return encoded


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except ValueError as exc:
        raise CodecError("invalid JSON") from exc


def decode_json(raw: bytes | str) -> Envelope:
    _check_size(raw)
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    data = _parse_json(text)
    if not isinstance(data, dict):
        raise CodecError("envelope must be an object")
    return _envelope_from_object(dict(data))


def _unwrap_ts(value: Any) -> str:
    if isinstance(value, CborTag):
        if value.tag != 0 or not isinstance(value.value, str):
            raise CodecError("timestamp must be CBOR tag 0 text")
        parse_ts(value.value)
        return value.value
    raise CodecError("timestamp_utc must be CBOR tag 0")


def decode_cbor(raw: bytes) -> Envelope:
    if len(raw) > limits()["max_message_bytes"]:
        raise CodecError("envelope exceeds max_message_bytes")
    try:
        data = cbor_decode(raw)
    except CborError as exc:
        raise CodecError(str(exc)) from exc
    if not isinstance(data, dict):
        raise CodecError("envelope must be a map")
    data = dict(data)
    if "timestamp_utc" not in data:
        raise CodecError("missing timestamp_utc")
    data["timestamp_utc"] = _unwrap_ts(data["timestamp_utc"])
    if isinstance(data.get("payload"), dict):
        payload = dict(data["payload"])
        if str(data.get("type", "")) == "resource.chunk" and isinstance(payload.get("data"), str):
            payload["data"] = base64.b64decode(payload["data"])
        data["payload"] = payload
    return _envelope_from_object(data)


def encode(envelope: Envelope, encoding: str, max_bytes: int | None = None) -> bytes:
    if encoding == "json":
        raw = encode_json(envelope)
    elif encoding == "cbor":
        raw = encode_cbor(envelope)
    else:
        raise CodecError(f"unknown encoding {encoding}")
    limit = max_bytes if max_bytes is not None else limits()["max_message_bytes"]
    if len(raw) > limit:
        raise CodecError("envelope exceeds negotiated max_message_bytes")
    return raw


def decode(raw: bytes, encoding: str) -> Envelope:
    if encoding == "json":
        return decode_json(raw)
    if encoding == "cbor":
        return decode_cbor(raw)
    raise CodecError(f"unknown encoding {encoding}")
