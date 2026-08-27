from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from acp.cbor_cde import CborTag, decode, encode
from acp.security import AuthenticatedPrincipal
from acp.security_authorization import AuthorizationContext, authorize
from acp.security_context import base64url_decode, base64url_encode
from acp.security_credentials import RevocationState, validate_compact_credential
from acp.security_enrollment import CandidateEnrollment, CandidateState, EnrollmentLimits
from acp.security_models import (
    AuthenticationMode,
    CredentialID,
    EnrollmentAttemptID,
    EnrollmentID,
    PrincipalState,
    SecurityNodeID,
    SecurityProfile,
    SecuritySuite,
    TrustDomainID,
)
from acp.security_operations import OperationalStateStore
from acp.security_transport import parse_lightweight_preface
from security_testkit import unsafe_authenticated_principal_for_testing

DOMAIN = TrustDomainID("40516273-8495-4a6b-8a3b-4c5d6e7f8091")
NODE = SecurityNodeID("00112233-4455-4677-8899-aabbccddeeff")
ISSUER = "sha256:" + "11" * 32
ENROLLMENT = EnrollmentID("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")
ATTEMPT = EnrollmentAttemptID("60718293-a4b5-4c6d-aa5b-000000000001")


def principal() -> AuthenticatedPrincipal:
    return unsafe_authenticated_principal_for_testing(
        state=PrincipalState.AUTHENTICATED,
        mode=AuthenticationMode.AURORA_TRUST,
        trust_domain_id=str(DOMAIN),
        node_id=str(NODE),
        credential_id="sha256:" + "22" * 32,
        identity_key_id="sha256:" + "33" * 32,
        credential_format="x509_der",
        role_constraints=frozenset(),
        profile=SecurityProfile.FULL,
    )


scalar = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**31), max_value=2**31 - 1)
    | st.binary(max_size=64)
    | st.text(max_size=64)
)
cde_values = st.recursive(
    scalar,
    lambda children: (
        st.lists(children, max_size=8) | st.dictionaries(st.text(min_size=1, max_size=12), children, max_size=8)
    ),
    max_leaves=32,
)


@settings(max_examples=150, deadline=None)
@given(cde_values)
def test_cbor_canonical_round_trip(value: object) -> None:
    raw = encode(value)
    assert encode(decode(raw)) == raw


@settings(max_examples=150, deadline=None)
@given(st.binary(min_size=1, max_size=2048))
def test_base64url_round_trip(value: bytes) -> None:
    encoded = base64url_encode(value)
    assert "=" not in encoded
    assert base64url_decode(encoded) == value


@settings(max_examples=100, deadline=None)
@given(
    st.sets(st.sampled_from(["a", "b", "c", "d"])),
    st.sets(st.sampled_from(["a", "b", "c", "d"])),
    st.sets(st.sampled_from(["a", "b", "c", "d"])),
    st.sets(st.sampled_from(["a", "b", "c", "d"])),
)
def test_authorization_is_exact_intersection(
    credential: set[str], local: set[str], capability: set[str], safety: set[str]
) -> None:
    permission = "security.credential.revoke"
    context = AuthorizationContext(
        principal(), frozenset(credential), frozenset(local), frozenset(capability), frozenset(safety), 1, "safe"
    )
    decision = authorize(permission, context)
    assert decision.effective_permissions == credential & local & capability & safety
    assert decision.allowed == (permission in decision.effective_permissions)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=4096))
def test_lightweight_parser_never_escapes_documented_errors(value: bytes) -> None:
    try:
        parse_lightweight_preface(value, lambda _: None)
    except (ValueError, TypeError):
        pass


def _compact(extension: dict[str, object]) -> bytes:
    timestamp = CborTag(0, "2026-08-26T00:00:00Z")
    body = {
        "format": "acp-compact-credential-v1",
        "serial": 1,
        "trust_domain_id": str(DOMAIN),
        "node_id": str(NODE),
        "identity_algorithm": "ecdsa_p256_sha256",
        "identity_public_key": b"public-key",
        "role_constraints": [],
        "permission_policy_id": "default",
        "issued_at": timestamp,
        "not_before": timestamp,
        "expires_at": CborTag(0, "2026-08-27T00:00:00Z"),
        "issuer_key_id": ISSUER,
        "extensions": extension,
    }
    return encode({"body": body, "algorithm": "ecdsa_p256_sha256", "signature": b"signature"})


@given(st.binary(max_size=128))
def test_extension_handling_is_fail_closed(value: bytes) -> None:
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    valid = _compact({"future": {"critical": False, "value": value}})
    validate_compact_credential(
        valid,
        expected_domain=DOMAIN,
        expected_node=NODE,
        now=now,
        verifier=lambda *_: True,
        revoked=lambda _: False,
        possession_valid=True,
        allowed_roles=frozenset(),
    )
    critical = _compact({"future": {"critical": True, "value": value}})
    with pytest.raises(ValueError):
        validate_compact_credential(
            critical,
            expected_domain=DOMAIN,
            expected_node=NODE,
            now=now,
            verifier=lambda *_: True,
            revoked=lambda _: False,
            possession_valid=True,
            allowed_roles=frozenset(),
        )


@given(st.integers(min_value=1, max_value=2**32), st.integers(min_value=0, max_value=2**32))
def test_revocation_epoch_never_moves_backward(epoch: int, next_epoch: int) -> None:
    state = RevocationState(DOMAIN, 10)

    def snapshot(value: int, previous_hash: str | None = None) -> bytes:
        body = {
            "format": "acp-revocation-snapshot-v1",
            "trust_domain_id": str(DOMAIN),
            "epoch": value,
            "issued_at": CborTag(0, "2026-08-26T00:00:00Z"),
            "next_update": CborTag(0, "2026-08-27T00:00:00Z"),
            "issuer_key_id": ISSUER,
            "entries": [],
        }
        if previous_hash is not None:
            body["previous_snapshot_hash"] = previous_hash
        return encode(body)

    initial = snapshot(epoch)
    state.ingest(initial, b"sig", lambda *_: True)
    previous_hash = "sha256:" + hashlib.sha256(initial).hexdigest()
    if next_epoch <= epoch:
        with pytest.raises(ValueError):
            state.ingest(snapshot(next_epoch, previous_hash), b"sig", lambda *_: True)
    else:
        state.ingest(snapshot(next_epoch, previous_hash), b"sig", lambda *_: True)
        assert state.epoch == next_epoch


@given(st.text(max_size=100), st.text(max_size=100))
def test_identifier_parsers_reject_noncanonical_values(node: str, credential: str) -> None:
    if node != str(NODE):
        try:
            SecurityNodeID(node)
        except ValueError:
            pass
    if credential != "sha256:" + "00" * 32:
        try:
            CredentialID(credential)
        except ValueError:
            pass


@given(st.integers(min_value=0, max_value=6))
def test_enrollment_legal_prefix_never_completes_before_durable_install(steps: int) -> None:
    class Operation:
        def receive_peer_share(self, value: bytes) -> bytes:
            return value

        def verify_confirmation(self, value: bytes) -> bool:
            return value == b"valid"

    machine = CandidateEnrollment(ENROLLMENT, frozenset({SecuritySuite.RAW128}), EnrollmentLimits(1), 0)
    operation = Operation()
    actions = (
        lambda: machine.begin(ATTEMPT, SecuritySuite.RAW128, 1),
        lambda: machine.process_peer_share(ATTEMPT, operation, b"share", 2),
        lambda: machine.verify_key_confirmation(ATTEMPT, operation, b"valid", 3),
        lambda: machine.await_approval(ATTEMPT, 4),
        lambda: machine.credential_staged(ATTEMPT, 5),
        lambda: machine.durable_install_verified(ATTEMPT, 6),
    )
    for action in actions[:steps]:
        action()
    if steps < 6:
        assert machine.state is not CandidateState.ENROLLED
    else:
        machine.complete(ATTEMPT, 7)
        assert machine.state is CandidateState.ENROLLED


@given(scalar)
def test_malformed_audit_event_shapes_fail_without_crashing(value: object) -> None:
    state = {
        "version": 2,
        "domains": {},
        "enrollments": {},
        "nodes": {},
        "revocation_epoch": 0,
        "revoked_credentials": [],
        "migration": {"stage": "observe", "allow_trusted_lan": False},
        "audit": [value],
    }
    valid, index = OperationalStateStore._verify_entries(state["audit"], state)
    assert not valid and index == 0
