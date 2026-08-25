"""Fail-closed Aurora Trust transport evidence and HELLO exporter binding."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from .cbor_cde import encode
from .security import CredentialState, SecurityAdmissionError, TransportEvidence
from .security_context import base64url_decode, base64url_encode
from .security_models import AuthenticationMode, SecurityProfile

HELLO_EXPORTER_LABEL = b"EXPORTER-Aurora-ACP-1.2-HELLO"
LIGHTWEIGHT_EXPORTER_LABEL = b"EXPORTER-Aurora-ACP-1.2-LIGHTWEIGHT-FINISHED"


class TLSExporter(Protocol):
    def __call__(self, label: bytes, context: bytes, length: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class FullTLSHandshake:
    protocol: str
    mutual_authentication: bool
    isolated_trust_store: bool
    peer_certificate_valid: bool
    local_credential_selected: bool
    peer_san_extracted: bool
    trust_domain_id: str
    node_id: str
    credential_id: str
    identity_key_id: str
    role_constraints: frozenset[str]
    credential_state: CredentialState
    zero_rtt_used: bool = False
    resumption_used: bool = False


def _closed(source: Mapping[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    try:
        return {key: source[key] for key in keys}
    except KeyError as exc:
        raise SecurityAdmissionError("security.credential_invalid") from exc


def _capabilities(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise SecurityAdmissionError("security.credential_invalid")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise SecurityAdmissionError("security.credential_invalid")
        result.append(_closed(item, ("id", "version")))
    return result


def project_hello_for_exporter(hello: Mapping[str, Any]) -> dict[str, Any]:
    """Build the frozen semantic projection without reconstructing ordered arrays."""
    node = hello.get("node")
    protocol = hello.get("protocol")
    auth = hello.get("auth")
    if not all(isinstance(value, Mapping) for value in (node, protocol, auth)):
        raise SecurityAdmissionError("security.credential_invalid")
    node = cast(Mapping[str, Any], node)
    protocol = cast(Mapping[str, Any], protocol)
    auth = cast(Mapping[str, Any], auth)
    projected_auth = _closed(
        auth, ("mode", "trust_domain_id", "credential_id", "identity_key_id", "security_capabilities")
    )
    projected_auth["security_capabilities"] = _capabilities(projected_auth["security_capabilities"])
    projected = {
        "node": _closed(node, ("node_id", "instance_id", "role", "name")),
        "protocol": _closed(protocol, ("min", "max")),
        "encodings": hello.get("encodings"),
        "profiles": hello.get("profiles"),
        "capabilities": _capabilities(hello.get("capabilities")),
        "auth": projected_auth,
    }
    if not all(isinstance(projected[key], list) for key in ("encodings", "profiles", "capabilities")):
        raise SecurityAdmissionError("security.credential_invalid")
    return projected


def hello_exporter_context(hello: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(encode(project_hello_for_exporter(hello))).digest()


def full_transport_evidence(
    hello: Mapping[str, Any], handshake: FullTLSHandshake, exporter: TLSExporter
) -> TransportEvidence:
    if not (
        handshake.protocol == "TLSv1.3"
        and handshake.mutual_authentication
        and handshake.isolated_trust_store
        and handshake.peer_certificate_valid
        and handshake.local_credential_selected
        and handshake.peer_san_extracted
    ):
        raise SecurityAdmissionError("security.authentication_failed")
    if handshake.zero_rtt_used or handshake.resumption_used:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if handshake.credential_state is CredentialState.REVOKED:
        raise SecurityAdmissionError("security.credential_revoked")
    if handshake.credential_state is CredentialState.EXPIRED:
        raise SecurityAdmissionError("security.credential_expired")
    if handshake.credential_state is not CredentialState.ACTIVE:
        raise SecurityAdmissionError("security.credential_invalid")
    context = hello_exporter_context(hello)
    exported = exporter(HELLO_EXPORTER_LABEL, context, 32)
    if len(exported) != 32:
        raise SecurityAdmissionError("security.authentication_failed")
    claimed = hello.get("auth", {}).get("channel_binding")
    try:
        verified = isinstance(claimed, str) and hmac.compare_digest(base64url_decode(claimed), exported)
    except ValueError:
        verified = False
    if not verified:
        raise SecurityAdmissionError("security.authentication_failed")
    return TransportEvidence(
        AuthenticationMode.AURORA_TRUST,
        handshake.trust_domain_id,
        handshake.node_id,
        handshake.credential_id,
        handshake.identity_key_id,
        "x509",
        base64url_encode(exported),
        handshake.role_constraints,
        handshake.credential_state,
        True,
        False,
        False,
        SecurityProfile.FULL,
    )


def parse_lightweight_preface(
    data: bytes, validate: Callable[[bytes], TransportEvidence]
) -> tuple[TransportEvidence, bytes]:
    if len(data) < 3:
        raise SecurityAdmissionError("security.credential_invalid")
    length = int.from_bytes(data[:2], "big")
    if not 1 <= length <= 2048 or len(data) != length + 2:
        raise SecurityAdmissionError("security.credential_invalid")
    credential = data[2:]
    evidence = validate(credential)
    if evidence.profile is not SecurityProfile.LIGHTWEIGHT or evidence.credential_state is not CredentialState.ACTIVE:
        raise SecurityAdmissionError("security.credential_invalid")
    return evidence, credential


def verify_lightweight_finished(exported_key: bytes, context: bytes, received: bytes) -> None:
    if len(exported_key) != 32 or len(context) > 8192 or len(received) != 32:
        raise SecurityAdmissionError("security.authentication_failed")
    expected = hmac.new(exported_key, context, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received):
        raise SecurityAdmissionError("security.authentication_failed")
