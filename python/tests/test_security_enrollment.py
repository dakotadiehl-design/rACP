from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.security_context import (
    canonical_approval_aad,
    canonical_install_result_without_confirmation,
    install_confirmation,
    install_proof_digest,
)
from acp.security_enrollment import (
    CandidateEnrollment,
    CandidateState,
    CommissionerEnrollment,
    CommissionerState,
    EnrollmentLimits,
    EnrollmentTransitionError,
    OneShotApprovalProtector,
    select_enrollment_suite,
)
from acp.security_models import EnrollmentAttemptID, EnrollmentID, SecurityErrorCode, SecuritySuite
from acp.security_secrets import SecretBytes
from security_test_providers import DeterministicRandom

ROOT = Path(__file__).parents[2]
EID = EnrollmentID("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")


def aid(value: int) -> EnrollmentAttemptID:
    return EnrollmentAttemptID(f"60718293-a4b5-4c6d-aa5b-{value:012x}")


def candidate(concurrent: int = 2) -> CandidateEnrollment:
    return CandidateEnrollment(EID, frozenset({SecuritySuite.RAW128}), EnrollmentLimits(concurrent), 0)


class ConfirmationOperation:
    def __init__(self, valid: bool = True) -> None:
        self.valid = valid

    def receive_peer_share(self, encoded_share: bytes) -> bytes:
        return encoded_share

    def verify_confirmation(self, confirmation: bytes) -> bool:
        return self.valid and confirmation == b"valid"


def test_candidate_legal_path_requires_durable_install() -> None:
    machine = candidate()
    attempt = aid(1)
    machine.begin(attempt, SecuritySuite.RAW128, 1)
    assert machine.process_peer_share(attempt, ConfirmationOperation(), b"share", 2) == b"share"
    machine.verify_key_confirmation(attempt, ConfirmationOperation(), b"valid", 2)
    machine.await_approval(attempt, 3)
    machine.credential_staged(attempt, 4)
    with pytest.raises(EnrollmentTransitionError, match="security.storage_failed"):
        machine.complete(attempt, 5)
    machine.durable_install_verified(attempt, 5)
    machine.complete(attempt, 6)
    assert machine.state is CandidateState.ENROLLED
    with pytest.raises(EnrollmentTransitionError, match="security.enrollment_replayed"):
        machine.verify_key_confirmation(attempt, ConfirmationOperation(), b"valid", 7)


def test_candidate_concurrency_replay_expiry_restart_and_lockout() -> None:
    machine = candidate()
    machine.begin(aid(1), SecuritySuite.RAW128, 1)
    machine.begin(aid(2), SecuritySuite.RAW128, 1)
    with pytest.raises(EnrollmentTransitionError, match="security.resource_limit"):
        machine.begin(aid(3), SecuritySuite.RAW128, 1)
    machine.restart()
    assert machine.state is CandidateState.FAILED
    assert {aid(1), aid(2)} <= machine.consumed_attempts

    machine = candidate()
    for number in range(1, 6):
        attempt = aid(number)
        machine.begin(attempt, SecuritySuite.RAW128, number)
        machine.cryptographic_failure(attempt)
    assert machine.state is CandidateState.LOCKED
    with pytest.raises(EnrollmentTransitionError, match="security.enrollment_locked"):
        machine.begin(aid(9), SecuritySuite.RAW128, 10)

    expiring = CandidateEnrollment(EID, frozenset({SecuritySuite.RAW128}), EnrollmentLimits(1, attempt_timeout_ns=5), 0)
    expiring.begin(aid(1), SecuritySuite.RAW128, 1)
    with pytest.raises(EnrollmentTransitionError, match="security.enrollment_expired"):
        expiring.verify_key_confirmation(aid(1), ConfirmationOperation(), b"valid", 6)


def test_commissioner_requires_verified_install_and_consumes_failure() -> None:
    illegal = CommissionerEnrollment(EID, aid(7), 100)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        illegal.transition(CommissionerState.IDLE, CommissionerState.COMPLETE, 1)
    machine = CommissionerEnrollment(EID, aid(1), 100)
    path = [
        (CommissionerState.IDLE, CommissionerState.CANDIDATE_SELECTED),
        (CommissionerState.CANDIDATE_SELECTED, CommissionerState.SECRET_ACQUIRED),
        (CommissionerState.SECRET_ACQUIRED, CommissionerState.NEGOTIATING),
        (CommissionerState.NEGOTIATING, CommissionerState.KEY_CONFIRMED),
        (CommissionerState.KEY_CONFIRMED, CommissionerState.AWAITING_OPERATOR_APPROVAL),
        (CommissionerState.AWAITING_OPERATOR_APPROVAL, CommissionerState.ISSUING_CREDENTIAL),
        (CommissionerState.ISSUING_CREDENTIAL, CommissionerState.AWAITING_INSTALL_RECEIPT),
    ]
    for expected, target in path:
        machine.transition(expected, target, 1)
    machine.complete_after_verified_install(2, hmac_valid=True, proof_valid=True)
    assert machine.state is CommissionerState.COMPLETE and machine.consumed

    failed = CommissionerEnrollment(EID, aid(2), 100, CommissionerState.AWAITING_INSTALL_RECEIPT)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        failed.complete_after_verified_install(2, hmac_valid=False, proof_valid=True)
    assert failed.consumed


def test_frozen_approval_and_installation_vectors() -> None:
    approval = json.loads((ROOT / "vectors/security/approval/primary.json").read_text())
    context = json.loads((ROOT / "vectors/security/context/primary.json").read_text())["semantic"]
    aad = {
        "message_type": "security.enrollment.approval",
        "attempt_id": context["attempt_id"],
        "enrollment_id": context["enrollment_id"],
        "candidate_node_id": context["candidate_node_id"],
        "commissioner_node_id": context["commissioner_node_id"],
        "trust_domain_id": context["trust_domain_id"],
        "acp_version": context["acp_version"],
        "extension_version": context["extension_version"],
        "suite": context["suite"],
        "identity_algorithm": context["identity_algorithm"],
        "identity_key_id": context["identity_key_id"],
        "transcript_hash": bytes.fromhex("1713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba"),
    }
    assert canonical_approval_aad(aad).hex() == approval["aad_cbor_hex"]

    install = json.loads((ROOT / "vectors/security/installation/primary.json").read_text())
    values = {
        "attempt_id": context["attempt_id"],
        "status": "installed",
        "credential_id": "sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20",
        "identity_key_id": context["identity_key_id"],
        "trust_domain_id": context["trust_domain_id"],
        "storage_posture": {"class": "os_protected", "hardware_backed": False, "private_key_exportable": False},
        "proof_of_possession": bytes.fromhex(install["proof_der_hex"]),
    }
    assert (
        canonical_install_result_without_confirmation(values).hex() == install["install_without_confirmation_cbor_hex"]
    )
    key = bytes.fromhex("2e6621403e7994557bcfe9fd9e7b2be4c20fad8ca91d95f7603e5d3016c1d190")
    assert install_confirmation(key, values).hex() == install["confirmation_hex"]
    assert install_proof_digest(aad["transcript_hash"], values["credential_id"]).hex() == install["signed_digest_hex"]


def test_mutated_closed_maps_fail() -> None:
    with pytest.raises(ValueError):
        canonical_approval_aad({})
    with pytest.raises(ValueError):
        canonical_install_result_without_confirmation({})
    assert SecurityErrorCode.AUTHENTICATION_FAILED.value == "security.authentication_failed"
    assert (
        select_enrollment_suite((SecuritySuite.PBKDF2_100K, SecuritySuite.RAW128), frozenset({SecuritySuite.RAW128}))
        is SecuritySuite.RAW128
    )
    with pytest.raises(EnrollmentTransitionError, match="security.no_common_suite"):
        select_enrollment_suite((SecuritySuite.PBKDF2_100K,), frozenset({SecuritySuite.RAW128}))


def test_illegal_transitions_and_wrong_suite_fail_closed() -> None:
    machine = candidate()
    with pytest.raises(EnrollmentTransitionError, match="security.no_common_suite"):
        machine.begin(aid(1), SecuritySuite.PBKDF2_100K, 1)
    machine.begin(aid(1), SecuritySuite.RAW128, 1)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        machine.credential_staged(aid(1), 2)
    failed = candidate()
    failed.begin(aid(2), SecuritySuite.RAW128, 1)
    failed.process_peer_share(aid(2), ConfirmationOperation(), b"share", 1)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        failed.verify_key_confirmation(aid(2), ConfirmationOperation(False), b"wrong", 2)
    assert aid(2) in failed.consumed_attempts

    missing = candidate()
    missing.begin(aid(3), SecuritySuite.RAW128, 1)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        missing.verify_key_confirmation(aid(3), ConfirmationOperation(), b"valid", 2)
    duplicate = candidate()
    duplicate.begin(aid(4), SecuritySuite.RAW128, 1)
    duplicate.process_peer_share(aid(4), ConfirmationOperation(), b"share", 2)
    with pytest.raises(EnrollmentTransitionError, match="security.authentication_failed"):
        duplicate.process_peer_share(aid(4), ConfirmationOperation(), b"share", 3)


def test_approval_key_is_one_shot() -> None:
    class FakeAEAD:
        def seal(self, key: SecretBytes, plaintext: SecretBytes, nonce: bytes, associated_data: bytes) -> bytes:
            return plaintext.use(bytes) + nonce + associated_data

        def open(self, key: SecretBytes, ciphertext: bytes, nonce: bytes, associated_data: bytes) -> SecretBytes:
            raise AssertionError("not used")

    protector = OneShotApprovalProtector(FakeAEAD(), DeterministicRandom(bytes(range(12))))
    key, plaintext = SecretBytes(bytes(32)), SecretBytes(b"approval")
    nonce, _ = protector.seal(aid(1), key, plaintext, b"aad")
    assert nonce == bytes(range(12))
    with pytest.raises(EnrollmentTransitionError, match="security.enrollment_replayed"):
        protector.seal(aid(1), key, plaintext, b"aad")


def test_transition_audit_is_structured_and_redacted() -> None:
    class CaptureAudit:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, object]]] = []

        def record(self, event: str, public_fields: dict[str, object]) -> None:
            self.events.append((event, public_fields))

    audit = CaptureAudit()
    machine = CandidateEnrollment(
        EID, frozenset({SecuritySuite.RAW128}), EnrollmentLimits(1), 0, audit=audit
    )
    operation = ConfirmationOperation()
    machine.begin(aid(1), SecuritySuite.RAW128, 1)
    machine.process_peer_share(aid(1), operation, b"share", 2)
    machine.verify_key_confirmation(aid(1), operation, b"valid", 3)
    assert any("attempt_started" in event for event, _ in audit.events)
    assert any("key_confirmed" in event for event, _ in audit.events)
    serialized_fields = repr([fields for _, fields in audit.events])
    assert "share" not in serialized_fields and "valid" not in serialized_fields
