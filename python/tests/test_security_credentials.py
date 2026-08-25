from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from acp.cbor_cde import decode
from acp.security_credentials import (
    ActiveSessionRevocationPolicy,
    CredentialGeneration,
    CredentialLifecycleError,
    JournaledIdentityStore,
    PersistenceBoundary,
    RenewalPlan,
    RevocationState,
    RotationCoordinator,
    RotationPhase,
    SecureTimeCheckpoint,
    TrustDomainAuthority,
    TrustDomainIdentity,
    X509ValidationEvidence,
    accepted_time,
    revocation_session_action,
    validate_compact_credential,
)
from acp.security_models import (
    ClockTrustState,
    CredentialID,
    IdentityKeyID,
    SecurityErrorCode,
    SecurityNodeID,
    TrustDomainID,
)

ROOT = Path(__file__).parents[2]
DOMAIN = TrustDomainID("40516273-8495-4a6b-8a3b-4c5d6e7f8091")
NODE = SecurityNodeID("00112233-4455-4677-8899-aabbccddeeff")


def generation(number: int) -> CredentialGeneration:
    digest = f"sha256:{number:064x}"
    return CredentialGeneration(number, CredentialID(digest), IdentityKeyID(digest), f"credential-{number}".encode())


def test_compact_credential_frozen_vector_and_negative_policy() -> None:
    vector = json.loads((ROOT / "vectors/security/compact_credential/primary.json").read_text())
    raw = bytes.fromhex(vector["credential_cbor_hex"])
    signature = bytes.fromhex(vector["signature_der_hex"])
    digest = bytes.fromhex(vector["signature_input_sha256_hex"])
    result = validate_compact_credential(
        raw,
        expected_domain=DOMAIN,
        expected_node=NODE,
        now=datetime(2026, 8, 25, tzinfo=UTC),
        verifier=lambda _issuer, value, candidate: value == digest and candidate == signature,
        revoked=lambda _: False,
        possession_valid=True,
        allowed_roles=frozenset({"remote"}),
    )
    assert str(result.credential_id) == vector["credential_id"]
    assert result.node_id == NODE

    for change in ("domain", "node", "signature", "possession", "revoked"):
        signature_valid = change != "signature"
        is_revoked = change == "revoked"
        with pytest.raises(CredentialLifecycleError):
            validate_compact_credential(
                raw,
                expected_domain=TrustDomainID("50516273-8495-4a6b-8a3b-4c5d6e7f8091") if change == "domain" else DOMAIN,
                expected_node=SecurityNodeID("10112233-4455-4677-8899-aabbccddeeff") if change == "node" else NODE,
                now=datetime(2026, 8, 25, tzinfo=UTC),
                verifier=lambda _issuer, value, candidate, valid=signature_valid: (
                    valid and value == digest and candidate == signature
                ),
                revoked=lambda _, value=is_revoked: value,
                possession_valid=change != "possession",
                allowed_roles=frozenset({"remote"}),
            )


def test_x509_evidence_fails_each_ordered_policy_check() -> None:
    fields = list(X509ValidationEvidence.__dataclass_fields__)
    baseline = {field: True for field in fields}
    baseline["unknown_critical_extensions"] = False
    X509ValidationEvidence(**baseline).require_valid()
    for field in fields:
        values = baseline.copy()
        values[field] = True if field == "unknown_critical_extensions" else False
        with pytest.raises(CredentialLifecycleError, match="security.credential_invalid"):
            X509ValidationEvidence(**values).require_valid()


def test_revocation_vector_monotonic_signature_domain_and_bounds() -> None:
    vector = json.loads((ROOT / "vectors/security/revocation/snapshot_epoch_7.json").read_text())
    body = bytes.fromhex(vector["body_cbor_hex"])
    signature = bytes.fromhex(vector["signature_der_hex"])
    digest = bytes.fromhex(vector["signature_input_sha256_hex"])
    state = RevocationState(DOMAIN, 128)

    def verify(_issuer: str, value: bytes, candidate: bytes) -> bool:
        return value == digest and candidate == signature

    state.ingest(body, signature, verify)
    assert state.epoch == 7 and len(state.entries) == 1
    state.require_fresh(datetime(2026, 8, 22, tzinfo=UTC), timedelta(days=2))
    with pytest.raises(CredentialLifecycleError):
        state.require_fresh(datetime(2026, 8, 23, tzinfo=UTC), timedelta(days=2))
    assert (
        revocation_session_action(revoked=True, policy=ActiveSessionRevocationPolicy.HARDENED_TERMINATE) == "terminate"
    )
    assert (
        revocation_session_action(revoked=True, policy=ActiveSessionRevocationPolicy.EXPLICIT_AUDITED_GRACE)
        == "audited_grace"
    )
    with pytest.raises(CredentialLifecycleError, match="security.authentication_failed"):
        state.ingest(body, signature, verify)
    wrong = RevocationState(TrustDomainID("50516273-8495-4a6b-8a3b-4c5d6e7f8091"), 128)
    with pytest.raises(CredentialLifecycleError):
        wrong.ingest(body, signature, verify)
    with pytest.raises(CredentialLifecycleError):
        RevocationState(DOMAIN, 0).ingest(body, signature, verify)


def test_journal_store_recovers_only_complete_generations(tmp_path: Path) -> None:
    store = JournaledIdentityStore(tmp_path / "identities")
    first = generation(1)
    store.stage(first)
    store.validate_staged(1, lambda value: value == first)
    store.commit(1)
    assert store.recover() == first
    second = generation(2)
    store.stage(second)
    assert store.recover() == first
    store.validate_staged(2, lambda value: value == second)
    store.commit(2)
    assert store.recover() == second
    assert (tmp_path / "identities" / "identity-1.json").exists()
    assert not (tmp_path / "assets").exists()
    with pytest.raises(CredentialLifecycleError, match=SecurityErrorCode.STORAGE_FAILED.value):
        store.stage(first)


def test_cleanup_retains_previous_complete_nonsequential_generation(tmp_path: Path) -> None:
    store = JournaledIdentityStore(tmp_path / "identities")
    for number in (1, 9, 42):
        value = generation(number)
        store.stage(value)
        store.validate_staged(number, lambda candidate, expected=value: candidate == expected)
        store.commit(number)
    store.cleanup()
    assert store.recover() == generation(42)
    assert (tmp_path / "identities" / "identity-9.json").exists()
    assert not (tmp_path / "identities" / "identity-1.json").exists()


@pytest.mark.parametrize("boundary", list(PersistenceBoundary))
def test_failure_injection_never_loses_previous_generation(tmp_path: Path, boundary: PersistenceBoundary) -> None:
    class InjectedFailure(RuntimeError):
        pass

    root = tmp_path / boundary.value
    base = JournaledIdentityStore(root)
    first = generation(1)
    base.stage(first)
    base.validate_staged(1, lambda _: True)
    base.commit(1)
    fired = False

    def inject(current: PersistenceBoundary) -> None:
        nonlocal fired
        if not fired and current is boundary:
            fired = True
            raise InjectedFailure

    store = JournaledIdentityStore(root, inject=inject)
    rotation = RotationCoordinator(store)
    try:
        rotation.prepare(generation(2))
        rotation.credential_obtained()
        rotation.stage(lambda _: True)
        rotation.possession_proved(True)
        rotation.activate()
        store.cleanup()
    except InjectedFailure:
        pass
    assert JournaledIdentityStore(root).recover() in {first, generation(2)}


def test_rotation_requires_previous_identity_and_proof(tmp_path: Path) -> None:
    empty = RotationCoordinator(JournaledIdentityStore(tmp_path / "empty"))
    with pytest.raises(CredentialLifecycleError, match="security.storage_failed"):
        empty.prepare(generation(1))
    store = JournaledIdentityStore(tmp_path / "store")
    first = generation(1)
    store.stage(first)
    store.validate_staged(1, lambda _: True)
    store.commit(1)
    rotation = RotationCoordinator(store)
    rotation.prepare(generation(2))
    rotation.credential_obtained()
    rotation.stage(lambda _: True)
    with pytest.raises(CredentialLifecycleError):
        rotation.possession_proved(False)
    assert rotation.phase is RotationPhase.IDLE and store.recover() == first


def test_clock_policy_rejects_untrusted_and_rollback() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    assert (
        accepted_time(
            ClockTrustState.TRUSTED_WALL_CLOCK,
            wall_time=now,
            checkpoint=None,
            authenticated_commissioner_time=None,
            last_checkpoint=None,
        )
        == now
    )
    with pytest.raises(CredentialLifecycleError, match=SecurityErrorCode.CLOCK_UNTRUSTED.value):
        accepted_time(
            ClockTrustState.UNTRUSTED,
            wall_time=now,
            checkpoint=None,
            authenticated_commissioner_time=None,
            last_checkpoint=None,
        )
    with pytest.raises(CredentialLifecycleError, match=SecurityErrorCode.CLOCK_UNTRUSTED.value):
        accepted_time(
            ClockTrustState.AUTHENTICATED_CHECKPOINT,
            wall_time=None,
            checkpoint=now,
            authenticated_commissioner_time=None,
            last_checkpoint=datetime(2026, 8, 26, tzinfo=UTC),
        )


def test_secure_time_checkpoint_is_durable_and_monotonic(tmp_path: Path) -> None:
    store = JournaledIdentityStore(tmp_path / "clock")
    checkpoint = SecureTimeCheckpoint(datetime(2026, 8, 25, tzinfo=UTC), 9, "boot-a", 3, 7)
    store.store_checkpoint(checkpoint)
    assert JournaledIdentityStore(tmp_path / "clock").load_checkpoint() == checkpoint
    with pytest.raises(CredentialLifecycleError, match=SecurityErrorCode.CLOCK_UNTRUSTED.value):
        store.store_checkpoint(SecureTimeCheckpoint(datetime(2026, 8, 24, tzinfo=UTC), 10, "boot-b", 3, 7))


def test_authority_restore_issuance_and_renewal_preserve_identity() -> None:
    vector = json.loads((ROOT / "vectors/security/compact_credential/primary.json").read_text())
    body = decode(bytes.fromhex(vector["body_cbor_hex"]))
    signature = bytes.fromhex(vector["signature_der_hex"])
    issuer = IdentityKeyID(body["issuer_key_id"])

    class Key:
        key_id = str(issuer)

        def sign_digest(self, digest: bytes) -> bytes:
            assert digest.hex() == vector["signature_input_sha256_hex"]
            return signature

    identity = TrustDomainIdentity(DOMAIN, issuer)
    authority = TrustDomainAuthority.restore(identity, identity, Key())
    assert authority.issue_compact(body).hex() == vector["credential_cbor_hex"]
    with pytest.raises(CredentialLifecycleError, match="security.trust_domain_mismatch"):
        TrustDomainAuthority.restore(
            identity,
            TrustDomainIdentity(TrustDomainID("50516273-8495-4a6b-8a3b-4c5d6e7f8091"), issuer),
            Key(),
        )

    current = IdentityKeyID("sha256:" + "1" * 64)
    renewed = RenewalPlan.create(NODE, current, rotation=False, requested_key_id=None)
    assert renewed.next_key_id == current and renewed.node_id == NODE
    rotated = RenewalPlan.create(NODE, current, rotation=True, requested_key_id=IdentityKeyID("sha256:" + "2" * 64))
    assert rotated.next_key_id != current and rotated.node_id == NODE
