from __future__ import annotations

import copy
import json

import pytest

from acp.constants import load
from acp.registry import allowed_to_receive, lookup
from acp.security import (
    AuthenticationMode,
    PrincipalState,
    SecurityAdmissionError,
    TransportEvidence,
    bind_hello_auth,
    effective_permissions,
    profile_limits,
)
from acp.validate import ValidationError, validate_message
from acp.__main__ import redact_security


ROOT_ID = "0193f8d8-4c4e-7d8b-a2ab-000000000090"
NODE_ID = "0193f8d8-4c4e-7d8b-a2ab-000000000002"
DIGEST = "sha256:" + "a" * 64


def authenticated_auth() -> dict[str, object]:
    return {
        "mode": "aurora_trust",
        "trust_domain_id": ROOT_ID, "credential_id": DIGEST, "identity_key_id": DIGEST,
        "channel_binding": "AQIDBA", "security_capabilities": [{"id": "security.identity", "version": "1.0"}],
    }


def evidence() -> TransportEvidence:
    return TransportEvidence(AuthenticationMode.AURORA_TRUST, ROOT_ID, NODE_ID, DIGEST, DIGEST, "x509_der", "AQIDBA")


def test_authenticated_hello_is_bound_to_transport_evidence() -> None:
    principal = bind_hello_auth(NODE_ID, authenticated_auth(), evidence(), hardened=True)
    assert principal.state is PrincipalState.AUTHENTICATED
    assert principal.node_id == NODE_ID


@pytest.mark.parametrize("mutation,code", [
    ({"trust_domain_id": "0193f8d8-4c4e-7d8b-a2ab-000000000099"}, "security.trust_domain_mismatch"),
    ({"credential_id": "sha256:" + "b" * 64}, "security.identity_mismatch"),
    ({"channel_binding": "altered"}, "security.identity_mismatch"),
    ({"mode": "trusted_lan"}, "security.downgrade_forbidden"),
])
def test_authenticated_hello_rejects_binding_mutations(mutation: dict[str, object], code: str) -> None:
    auth = authenticated_auth() | mutation
    with pytest.raises(SecurityAdmissionError, match=code.replace(".", r"\.")):
        bind_hello_auth(NODE_ID, auth, evidence(), hardened=True)


def test_claimed_authentication_without_transport_evidence_fails_closed() -> None:
    with pytest.raises(SecurityAdmissionError, match="downgrade_forbidden"):
        bind_hello_auth(NODE_ID, authenticated_auth(), None, hardened=True)


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


def test_aurora_trust_hello_requires_all_frozen_binding_fields() -> None:
    path = __import__("pathlib").Path(__file__).parents[2] / "vectors/json/session.hello.json"
    message = json.loads(path.read_text())
    message["payload"]["auth"] = authenticated_auth()
    validate_message(message)
    del message["payload"]["auth"]["channel_binding"]
    with pytest.raises(ValidationError):
        validate_message(message)


def test_enrollment_router_is_restricted_by_explicit_state() -> None:
    versions = {"security.enrollment": "1.0"}
    assert allowed_to_receive(
        "security.enrollment.begin", session_version="1.2", sender_role="conductor",
        negotiated_capabilities={"security.enrollment"}, negotiated_versions=versions,
        handshake_complete=False, qos="reliable", session_state="EnrollmentRestricted",
    ) is None
    assert allowed_to_receive(
        "security.enrollment.begin", session_version="1.2", sender_role="conductor",
        negotiated_capabilities={"security.enrollment"}, negotiated_versions=versions,
        handshake_complete=True, qos="reliable", session_state="Established",
    ) == "security.permission_denied"
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
    value = redact_security({
        "trust_domain_id": ROOT_ID, "credential_id": DIGEST,
        "shareP": "secret-share", "nested": {"channel_binding": "secret-binding"},
    })
    assert value["trust_domain_id"] == ROOT_ID
    assert value["credential_id"] == DIGEST
    assert value["shareP"] == "<redacted>"
    assert value["nested"]["channel_binding"] == "<redacted>"
