from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from .constants import data_file
from .negotiate import version_at_least


@lru_cache(maxsize=1)
def load_registry() -> dict[str, dict[str, Any]]:
    data = json.loads(data_file("registry.json").read_text())
    return {row["type"]: row for row in data["messages"]}


def lookup(message_type: str) -> dict[str, Any] | None:
    return load_registry().get(message_type)


def allowed_to_send(
    message_type: str,
    *,
    session_version: str,
    sender_role: str,
    negotiated_capabilities: set[str],
    handshake_complete: bool,
) -> str | None:
    return _check(
        message_type,
        session_version=session_version,
        sender_role=sender_role,
        negotiated_capabilities=negotiated_capabilities,
        handshake_complete=handshake_complete,
        qos=None,
    )


def allowed_to_receive(
    message_type: str,
    *,
    session_version: str,
    sender_role: str,
    negotiated_capabilities: set[str],
    handshake_complete: bool,
    qos: str | None = None,
    envelope_version: str | None = None,
) -> str | None:
    return _check(
        message_type,
        session_version=session_version,
        sender_role=sender_role,
        negotiated_capabilities=negotiated_capabilities,
        handshake_complete=handshake_complete,
        qos=qos,
        unknown_is_error=True,
        envelope_version=envelope_version,
    )


def _check(
    message_type: str,
    *,
    session_version: str,
    sender_role: str,
    negotiated_capabilities: set[str],
    handshake_complete: bool,
    qos: str | None,
    unknown_is_error: bool = False,
    envelope_version: str | None = None,
) -> str | None:
    row = lookup(message_type)
    if row is None:
        return "unsupported_message" if unknown_is_error or handshake_complete else None
    if not handshake_complete and not row["legal_before_handshake"]:
        return "malformed_envelope"
    check_ver = envelope_version or session_version
    if handshake_complete and not version_at_least(check_ver, row["min_protocol"]):
        return "unsupported_message"
    cap = row.get("required_capability")
    if cap and cap not in negotiated_capabilities:
        return "capability_not_permitted"
    if sender_role not in row["valid_senders"]:
        return "capability_not_permitted"
    if qos is not None and qos not in row.get("qos_allowed", [qos]):
        return "invalid_type"
    return None


def expected_response_type(message_type: str) -> str | None:
    row = lookup(message_type)
    if not row:
        return None
    return row.get("response_type")
