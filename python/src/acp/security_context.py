"""Frozen Aurora Trust deterministic context, transcript, and identifier helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from typing import Any

from .cbor_cde import encode as cbor_encode

CONTEXT_KEYS = frozenset(
    {
        "acp_version",
        "application",
        "attempt_id",
        "candidate_instance_id",
        "candidate_node_id",
        "commissioner_instance_id",
        "commissioner_node_id",
        "enrollment_id",
        "extension_version",
        "identity_algorithm",
        "identity_key_id",
        "purpose",
        "requested_permissions_digest",
        "requested_role",
        "suite",
        "trust_domain_id",
    }
)


def canonical_enrollment_context(values: Mapping[str, str]) -> bytes:
    if set(values) != CONTEXT_KEYS or any(not isinstance(value, str) for value in values.values()):
        raise ValueError("enrollment context must contain exactly the frozen text fields")
    return cbor_encode(dict(values))


def canonical_transcript(items: Sequence[bytes]) -> bytes:
    if len(items) != 5 or any(not isinstance(item, bytes) or not item for item in items):
        raise ValueError("transcript requires exactly five non-empty byte strings")
    return cbor_encode(list(items))


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def digest_id(value: bytes) -> str:
    return "sha256:" + sha256(value).hex()


def transcript_hash(items: Sequence[bytes]) -> bytes:
    return sha256(canonical_transcript(items))


def permission_digest(permissions: Mapping[str, Any]) -> str:
    return digest_id(cbor_encode(dict(permissions)))


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
    if not 0 <= length <= 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    output = bytearray()
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(pseudorandom_key, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
    return bytes(output[:length])


def derive_enrollment_keys(shared_key: bytes, transcript_digest: bytes) -> dict[str, bytes]:
    root = hkdf_extract(transcript_digest, shared_key)
    labels = ("candidate confirm", "commissioner confirm", "approval AEAD", "audit binding", "SAS")
    return {label: hkdf_expand(root, f"ACP enrollment {label} v1".encode(), 32) for label in labels}


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("base64url must be non-empty and unpadded")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValueError("invalid base64url") from exc
    if base64url_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def channel_bindings_equal(left: bytes, right: bytes) -> bool:
    return len(left) == 32 and len(right) == 32 and hmac.compare_digest(left, right)
