"""ACP-CDE-1.2: RFC 8949 preferred + deterministic encoding with ACP restrictions."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any

MAX_NESTING = 32
MAX_ITEMS = 1_048_576
MAX_BYTES = 8 * 1024 * 1024


class CborError(ValueError):
    """Malformed or non-canonical CBOR."""


@dataclass(frozen=True, slots=True)
class CborTag:
    tag: int
    value: Any


def encode(value: Any) -> bytes:
    return _encode(value)


def decode(data: bytes) -> Any:
    if len(data) > MAX_BYTES:
        raise CborError("CBOR document exceeds limit")
    value, offset = _decode(data, 0, 0)
    if offset != len(data):
        raise CborError("trailing bytes after CBOR item")
    return value


def _encode_uint(value: int) -> bytes:
    if value < 0:
        raise CborError("unsigned expected")
    if value < 24:
        return bytes([value])
    if value < 256:
        return bytes([24, value])
    if value < 65536:
        return bytes([25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([27]) + value.to_bytes(8, "big")
    raise CborError("integer exceeds uint64")


def _head(major: int, value: int) -> bytes:
    extra = _encode_uint(value)
    return bytes([(major << 5) | extra[0]]) + extra[1:]


def _encode(value: Any) -> bytes:
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, CborTag):
        return _head(6, value.tag) + _encode(value.value)
    if isinstance(value, bool):  # noqa: SIM114 - after True/False for safety
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value < 2**64:
            return _head(0, value)
        if -(2**64) <= value < 0:
            return _head(1, -1 - value)
        raise CborError("integer out of int64/uint64 range")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CborError("NaN/Inf forbidden")
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return _head(2, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        body = b"".join(_encode(item) for item in value)
        return _head(4, len(value)) + body
    if isinstance(value, dict):
        pairs: list[tuple[bytes, bytes]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CborError("map keys must be text strings")
            pairs.append((_encode(key), _encode(item)))
        pairs.sort(key=lambda kv: kv[0])
        # reject duplicate encoded keys
        seen: set[bytes] = set()
        for encoded_key, _ in pairs:
            if encoded_key in seen:
                raise CborError("duplicate map key")
            seen.add(encoded_key)
        body = b"".join(k + v for k, v in pairs)
        return _head(5, len(pairs)) + body
    raise CborError(f"cannot encode type {type(value)!r}")


def _require_len(n: int, limit: int, what: str) -> None:
    if n < 0 or n > limit:
        raise CborError(f"{what} exceeds limit")


def _read(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if size < 0 or offset < 0 or offset > len(data) or size > len(data) - offset:
        raise CborError("truncated CBOR")
    end = offset + size
    return data[offset:end], end


def _decode_argument(ai: int, data: bytes, offset: int) -> tuple[int, int]:
    if ai < 24:
        return ai, offset
    if ai == 24:
        raw, offset = _read(data, offset, 1)
        value = raw[0]
        if value < 24:
            raise CborError("non-preferred integer encoding")
        return value, offset
    if ai == 25:
        raw, offset = _read(data, offset, 2)
        value = int.from_bytes(raw, "big")
        if value < 256:
            raise CborError("non-preferred integer encoding")
        return value, offset
    if ai == 26:
        raw, offset = _read(data, offset, 4)
        value = int.from_bytes(raw, "big")
        if value < 65536:
            raise CborError("non-preferred integer encoding")
        return value, offset
    if ai == 27:
        raw, offset = _read(data, offset, 8)
        value = int.from_bytes(raw, "big")
        if value < 2**32:
            raise CborError("non-preferred integer encoding")
        return value, offset
    if ai >= 28:
        raise CborError("indefinite length or reserved additional info forbidden")
    raise CborError("invalid additional info")


def _decode(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_NESTING:
        raise CborError("nesting too deep")
    if offset >= len(data):
        raise CborError("truncated CBOR")
    initial = data[offset]
    offset += 1
    major = initial >> 5
    ai = initial & 0x1F
    if ai == 31:
        raise CborError("indefinite length forbidden")
    if major == 0:
        value, offset = _decode_argument(ai, data, offset)
        return value, offset
    if major == 1:
        value, offset = _decode_argument(ai, data, offset)
        return -1 - value, offset
    if major == 2:
        length, offset = _decode_argument(ai, data, offset)
        _require_len(length, MAX_BYTES, "byte string")
        raw, offset = _read(data, offset, length)
        return raw, offset
    if major == 3:
        length, offset = _decode_argument(ai, data, offset)
        _require_len(length, MAX_BYTES, "text string")
        raw, offset = _read(data, offset, length)
        return raw.decode("utf-8"), offset
    if major == 4:
        length, offset = _decode_argument(ai, data, offset)
        _require_len(length, MAX_ITEMS, "array")
        items = []
        for _ in range(length):
            item, offset = _decode(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        length, offset = _decode_argument(ai, data, offset)
        _require_len(length, MAX_ITEMS, "map")
        mapping: dict[str, Any] = {}
        last_key: bytes | None = None
        for _ in range(length):
            key_start = offset
            key, offset = _decode(data, offset, depth + 1)
            encoded_key = data[key_start:offset]
            if last_key is not None and encoded_key < last_key:
                raise CborError("map keys not in CDE order")
            if last_key == encoded_key:
                raise CborError("duplicate map key")
            last_key = encoded_key
            if not isinstance(key, str):
                raise CborError("map keys must be text strings")
            if key in mapping:
                raise CborError("duplicate map key")
            value, offset = _decode(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset
    if major == 6:
        tag, offset = _decode_argument(ai, data, offset)
        if tag != 0:
            raise CborError(f"CBOR tag {tag} is not permitted in ACP-CDE-1.2")
        inner, offset = _decode(data, offset, depth + 1)
        return CborTag(tag, inner), offset
    # major 7
    if ai == 20:
        return False, offset
    if ai == 21:
        return True, offset
    if ai == 22:
        return None, offset
    if ai == 25:
        raw, offset = _read(data, offset, 2)
        f16 = _decode_float16(raw)
        _reject_nonfinite(f16)
        return f16, offset
    if ai == 26:
        raw, offset = _read(data, offset, 4)
        f32 = struct.unpack(">f", raw)[0]
        _reject_nonfinite(f32)
        return float(f32), offset
    if ai == 27:
        raw, offset = _read(data, offset, 8)
        f64 = struct.unpack(">d", raw)[0]
        _reject_nonfinite(f64)
        return f64, offset
    raise CborError(f"unsupported simple/float additional info {ai}")


def _reject_nonfinite(value: float) -> None:
    if not math.isfinite(value):
        raise CborError("NaN/Inf forbidden")


def _decode_float16(raw: bytes) -> float:
    bits = int.from_bytes(raw, "big")
    sign = -1 if bits & 0x8000 else 1
    exp = (bits >> 10) & 0x1F
    frac = bits & 0x3FF
    if exp == 0:
        return sign * (2**-14) * (frac / 1024)
    if exp == 31:
        return math.copysign(math.inf if frac == 0 else math.nan, sign)
    return sign * (2 ** (exp - 15)) * (1 + frac / 1024)
