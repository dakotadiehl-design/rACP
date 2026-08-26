from __future__ import annotations

import copy
import json

import pytest

from acp.__main__ import redact_security
from acp.cbor_cde import decode as decode_cbor_value
from acp.cbor_cde import encode as encode_cbor_value
from acp.codec import CodecError, decode_cbor, decode_json, encode_cbor
from acp.constants import load
from acp.registry import allowed_to_receive, lookup
from acp.security import (
    AuthenticationMode,
    CredentialState,
    PrincipalState,
    SecurityAdmissionError,
    bind_hello_auth,
    effective_permissions,
    profile_limits,
    AuthenticatedPrincipal,
    TransportEvidence,
)
from acp.testkit import unsafe_replace_security_value_for_testing, unsafe_transport_evidence_for_testing
from acp.validate import ValidationError, validate_message

ROOT_ID = "0193f8d8-4c4e-7d8b-a2ab-000000000090"
NODE_ID = "0193f8d8-4c4e-7d8b-a2ab-000000000002"
DIGEST = "sha256:" + "a" * 64
BINDING = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def authenticated_auth() -> dict[str, object]:
    return {
        "mode": "aurora_trust",
        "trust_domain_id": ROOT_ID,
        "credential_id": DIGEST,
        "identity_key_id": DIGEST,
        "channel_binding": BINDING,
        "security_capabilities": [{"id": "aurora-trust", "version": "1.0"}],
    }


def evidence():
    return unsafe_transport_evidence_for_testing(
        mode=AuthenticationMode.AURORA_TRUST,
        trust_domain_id=ROOT_ID,
        node_id=NODE_ID,
        credential_id=DIGEST,
        identity_key_id=DIGEST,
        credential_format="x509_der",
        channel_binding=BINDING,
        credential_state=CredentialState.ACTIVE,
        channel_binding_verified=True,
    )


def test_security_results_cannot_be_constructed_by_application_code() -> None:
    with pytest.raises(TypeError, match="_provenance"):
        TransportEvidence(mode=AuthenticationMode.AURORA_TRUST)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="_provenance"):
        AuthenticatedPrincipal(  # type: ignore[call-arg]
            state=PrincipalState.AUTHENTICATED,
            mode=AuthenticationMode.AURORA_TRUST,
            trust_domain_id=ROOT_ID,
            node_id=NODE_ID,
            credential_id=DIGEST,
            identity_key_id=DIGEST,
            credential_format="x509_der",
            role_constraints=frozenset(),
        )


def test_authenticated_hello_is_bound_to_transport_evidence() -> None:
    principal = bind_hello_auth(
        NODE_ID,
        authenticated_auth(),
        evidence(),
        hardened=True,
        security_capabilities=(("aurora-trust", "1.0"),),
    )
    assert principal.state is PrincipalState.AUTHENTICATED
    assert principal.node_id == NODE_ID


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"trust_domain_id": "0193f8d8-4c4e-7d8b-a2ab-000000000099"}, "security.trust_domain_mismatch"),
        ({"credential_id": "sha256:" + "b" * 64}, "security.identity_mismatch"),
        ({"channel_binding": "altered"}, "security.identity_mismatch"),
        ({"mode": "trusted_lan"}, "security.downgrade_forbidden"),
    ],
)
def test_authenticated_hello_rejects_binding_mutations(mutation: dict[str, object], code: str) -> None:
    auth = authenticated_auth() | mutation
    with pytest.raises(SecurityAdmissionError, match=code.replace(".", r"\.")):
        bind_hello_auth(
            NODE_ID,
            auth,
            evidence(),
            hardened=True,
            security_capabilities=(("aurora-trust", "1.0"),),
        )


def test_claimed_authentication_without_transport_evidence_fails_closed() -> None:
    with pytest.raises(SecurityAdmissionError, match="downgrade_forbidden"):
        bind_hello_auth(NODE_ID, authenticated_auth(), None, hardened=True)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"credential_state": CredentialState.REVOKED}, "security.credential_revoked"),
        ({"credential_state": CredentialState.EXPIRED}, "security.credential_expired"),
        ({"channel_binding_verified": False}, "security.authentication_failed"),
        ({"zero_rtt_used": True}, "security.downgrade_forbidden"),
        ({"resumption_used": True}, "security.downgrade_forbidden"),
    ],
)
def test_invalid_transport_security_state_fails_closed(change: dict[str, object], code: str) -> None:
    with pytest.raises(SecurityAdmissionError, match=code.replace(".", r"\.")):
        bind_hello_auth(
            NODE_ID,
            authenticated_auth(),
            unsafe_replace_security_value_for_testing(evidence(), **change),
            hardened=True,
            security_capabilities=(("aurora-trust", "1.0"),),
        )


@pytest.mark.parametrize(
    "capabilities", [(), (("security.identity", "1.0"),), (("aurora-trust", "1.0"), ("aurora-trust", "1.0"))]
)
def test_missing_wrong_or_duplicate_trust_capability_fails_closed(
    capabilities: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(SecurityAdmissionError):
        bind_hello_auth(
            NODE_ID,
            authenticated_auth(),
            evidence(),
            hardened=True,
            security_capabilities=capabilities,
        )


def test_trusted_lan_never_creates_authenticated_principal() -> None:
    principal = bind_hello_auth(NODE_ID, {"mode": "trusted_lan"}, None, hardened=False)
    assert principal.state is PrincipalState.UNAUTHENTICATED
    assert principal.node_id is None


def test_permissions_are_a_five_layer_intersection() -> None:
    assert effective_permissions(
        {"observe", "control"}, {"observe", "control"}, {"observe", "control"}, {"observe"}
    ) == {"observe"}


def test_frozen_limits_and_catalogs() -> None:
    security = load()["security"]
    assert profile_limits("full")["concurrent_attempts"] == 2
    assert profile_limits("lightweight")["concurrent_attempts"] == 1
    assert profile_limits("full")["max_security_message_bytes"] == 65536
    assert profile_limits("lightweight")["max_credential_bytes"] == 2048
    assert security["downgrade_policy"]["hardened_allows_trusted_lan_fallback"] is False
    assert len(security["errors"]) == 18
    assert security["capabilities"]["security.enrollment"] == "1.0"


def test_security_crypto_structures_reject_unknown_fields() -> None:
    path = __import__("pathlib").Path(__file__).parents[2] / "vectors/json/security.enrollment.begin.json"
    message = json.loads(path.read_text())
    validate_message(message)
    altered = copy.deepcopy(message)
    altered["payload"]["undefined_transcript_field"] = "forbidden"
    with pytest.raises(ValidationError):
        validate_message(altered)


def test_security_cbor_uses_byte_strings_and_rejects_text_substitution() -> None:
    path = __import__("pathlib").Path(__file__).parents[2] / "vectors/json/security.enrollment.challenge.json"
    envelope = decode_json(path.read_bytes())
    encoded = encode_cbor(envelope)
    raw = decode_cbor_value(encoded)
    assert isinstance(raw["payload"]["identity_public_key"], bytes)
    assert isinstance(raw["payload"]["shareP"], bytes)
    raw["payload"]["shareP"] = envelope.payload["shareP"]
    with pytest.raises(CodecError, match="CBOR byte string"):
        decode_cbor(encode_cbor_value(raw))


def test_security_cbor_uses_tag_zero_for_nested_timestamps() -> None:
    path = __import__("pathlib").Path(__file__).parents[2] / "vectors/json/security.enrollment.status.json"
    envelope = decode_json(path.read_bytes())
    raw = decode_cbor_value(encode_cbor(envelope))
    tagged = raw["payload"]["expires_at"]
    assert getattr(tagged, "tag", None) == 0
    raw["payload"]["expires_at"] = envelope.payload["expires_at"]
    with pytest.raises(CodecError, match="CBOR tag 0"):
        decode_cbor(encode_cbor_value(raw))


def test_aurora_trust_hello_requires_all_frozen_binding_fields() -> None:
    path = __import__("pathlib").Path(__file__).parents[2] / "vectors/json/session.hello.json"
    message = json.loads(path.read_text())
    message["payload"]["auth"] = authenticated_auth()
    validate_message(message)
    del message["payload"]["auth"]["channel_binding"]
    with pytest.raises(ValidationError):
        validate_message(message)


def test_rotation_and_credential_result_conditionals_are_unambiguous() -> None:
    root = __import__("pathlib").Path(__file__).parents[2]
    renew = json.loads((root / "vectors/json/security.credential.renew.json").read_text())
    validate_message(renew)
    no_rotation = copy.deepcopy(renew)
    no_rotation["payload"]["rotation"] = False
    del no_rotation["payload"]["requested_public_key"]
    validate_message(no_rotation)
    no_rotation["payload"]["requested_public_key"] = renew["payload"]["requested_public_key"]
    with pytest.raises(ValidationError):
        validate_message(no_rotation)

    result = json.loads((root / "vectors/json/security.credential.result.json").read_text())
    denied = copy.deepcopy(result)
    denied["payload"] = {
        "status": "denied",
        "error": {
            "code": "security.permission_denied",
            "category": "authorization",
            "severity": "error",
            "message": "denied",
            "retryable": False,
        },
    }
    validate_message(denied)
    denied["payload"]["credential"] = "AQIDBA"
    with pytest.raises(ValidationError):
        validate_message(denied)


def test_enrollment_router_is_restricted_by_explicit_state() -> None:
    versions = {"security.enrollment": "1.0"}
    assert (
        allowed_to_receive(
            "security.enrollment.begin",
            session_version="1.2",
            sender_role="conductor",
            negotiated_capabilities={"security.enrollment"},
            negotiated_versions=versions,
            handshake_complete=False,
            qos="reliable",
            session_state="EnrollmentRestricted",
        )
        is None
    )
    assert (
        allowed_to_receive(
            "security.enrollment.begin",
            session_version="1.2",
            sender_role="conductor",
            negotiated_capabilities={"security.enrollment"},
            negotiated_versions=versions,
            handshake_complete=True,
            qos="reliable",
            session_state="Established",
        )
        == "security.permission_denied"
    )
    assert lookup("remote.control.invoke")["legal_before_handshake"] is False


def test_sensitive_annotations_survive_packaging_and_registry_generation() -> None:
    root = __import__("pathlib").Path(__file__).parents[2]
    canonical = json.loads((root / "schema/common/defs.schema.json").read_text())
    packaged = json.loads((root / "python/src/acp/data/schema/common/defs.schema.json").read_text())
    packed = json.loads((root / "schema/schema_pack.json").read_text())["docs"]["common/defs.schema.json"]
    for document in (canonical, packaged, packed):
        crypto = document["$defs"]["crypto_bytes"]
        assert crypto["x-acp-sensitive"] is True
        assert crypto["x-acp-log-policy"] == "never"
    row = lookup("security.enrollment.approval")
    assert row["sensitive_field_policy"] == "secret"
    assert row["legal_session_states"] == ["EnrollmentRestricted"]


def test_inspector_redacts_security_material_but_keeps_public_ids() -> None:
    value = redact_security(
        {
            "trust_domain_id": ROOT_ID,
            "credential_id": DIGEST,
            "shareP": "secret-share",
            "nested": {"channel_binding": "secret-binding"},
        }
    )
    assert value["trust_domain_id"] == ROOT_ID
    assert value["credential_id"] == DIGEST
    assert value["shareP"] == "<redacted>"
    assert value["nested"]["channel_binding"] == "<redacted>"
