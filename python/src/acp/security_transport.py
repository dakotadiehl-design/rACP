"""Fail-closed Aurora Trust transport evidence and HELLO exporter binding."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import MISSING, dataclass
from typing import Any, Protocol, cast

from .cbor_cde import encode
from .security import CredentialState, SecurityAdmissionError, TransportEvidence, _verified_transport_evidence
from .security_context import base64url_decode, base64url_encode
from .security_models import AuthenticationMode, SecurityProfile

HELLO_EXPORTER_LABEL = b"EXPORTER-Aurora-ACP-1.2-HELLO"
LIGHTWEIGHT_EXPORTER_LABEL = b"EXPORTER-Aurora-ACP-1.2-LIGHTWEIGHT-FINISHED"


class TLSExporter(Protocol):
    def __call__(self, label: bytes, context: bytes, length: int) -> bytes: ...


_HANDSHAKE_PROVENANCE = object()


@dataclass(frozen=True, slots=True, init=False)
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

    def __init__(self, *, _provenance: object, **values: Any) -> None:
        if _provenance is not _HANDSHAKE_PROVENANCE:
            raise TypeError("TLS handshake facts may only be created by a transport provider")
        fields = self.__dataclass_fields__
        unknown = values.keys() - fields.keys()
        if unknown:
            raise TypeError(f"unknown TLS handshake fields: {sorted(unknown)!r}")
        for name, field in fields.items():
            if name not in values and field.default is MISSING:
                raise TypeError(f"missing TLS handshake field: {name}")
            object.__setattr__(self, name, values[name] if name in values else field.default)


def _verified_full_tls_handshake(**values: Any) -> FullTLSHandshake:
    """Transport-adapter-only factory for verified handshake facts."""
    return FullTLSHandshake(_provenance=_HANDSHAKE_PROVENANCE, **values)


@dataclass(frozen=True, slots=True)
class LightweightFinishedInputs:
    client_credential: bytes
    server_credential: bytes
    client_spki: bytes
    server_spki: bytes
    client_node_id: str
    server_node_id: str
    trust_domain_id: str


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
    return _verified_transport_evidence(
        mode=AuthenticationMode.AURORA_TRUST,
        trust_domain_id=handshake.trust_domain_id,
        node_id=handshake.node_id,
        credential_id=handshake.credential_id,
        identity_key_id=handshake.identity_key_id,
        credential_format="x509_der",
        channel_binding=base64url_encode(exported),
        role_constraints=handshake.role_constraints,
        credential_state=handshake.credential_state,
        channel_binding_verified=True,
        zero_rtt_used=False,
        resumption_used=False,
        profile=SecurityProfile.FULL,
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
    if (
        not isinstance(evidence, TransportEvidence)
        or evidence.profile is not SecurityProfile.LIGHTWEIGHT
        or evidence.credential_format != "acp-compact-credential-v1"
        or evidence.credential_state is not CredentialState.ACTIVE
    ):
        raise SecurityAdmissionError("security.credential_invalid")
    return evidence, credential


def lightweight_finished_context(inputs: LightweightFinishedInputs) -> bytes:
    blobs = (inputs.client_credential, inputs.server_credential, inputs.client_spki, inputs.server_spki)
    if any(not value or len(value) > 2048 for value in blobs):
        raise SecurityAdmissionError("security.resource_limit")
    context = encode(
        [
            "ACP lightweight finished v1",
            *blobs,
            inputs.client_node_id,
            inputs.server_node_id,
            inputs.trust_domain_id,
        ]
    )
    if len(context) > 8192:
        raise SecurityAdmissionError("security.resource_limit")
    return context


def verify_lightweight_finished(exported_key: bytes, inputs: LightweightFinishedInputs, received: bytes) -> None:
    if len(exported_key) != 32 or len(received) != 32:
        raise SecurityAdmissionError("security.authentication_failed")
    context = lightweight_finished_context(inputs)
    expected = hmac.new(exported_key, context, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received):
        raise SecurityAdmissionError("security.authentication_failed")
