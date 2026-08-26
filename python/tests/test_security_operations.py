from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from acp.security_cli import main, redact
from acp.security_credentials import CredentialGeneration, JournaledIdentityStore
from acp.security_models import CredentialID, IdentityKeyID
from acp.security_operations import MigrationStage, OperationalStateStore, migration_decision

KEY1 = "sha256:" + "11" * 32
KEY2 = "sha256:" + "22" * 32
KEY3 = "sha256:" + "33" * 32
CRED1 = "sha256:" + "44" * 32
CRED2 = "sha256:" + "55" * 32
CRED3 = "sha256:" + "66" * 32
CRED4 = "sha256:" + "77" * 32
NODE = "00112233-4455-4677-8899-aabbccddeeff"
NODE2 = "11223344-5566-4778-899a-bbccddeeff00"


def test_offline_operational_lifecycle_and_audit(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    domain = store.create_domain("Offline show", KEY1)
    enrollment = store.open_enrollment(domain["trust_domain_id"], b"one-time-bootstrap")
    store.advance_enrollment(enrollment["enrollment_id"], "candidate")
    completed = store.advance_enrollment(enrollment["enrollment_id"], "commissioner", NODE, CRED1, KEY2)
    node_id = completed["node_id"]
    original_key = store.load()["nodes"][node_id]["identity_key_id"]
    renewed = store.credential_action(node_id, "renew", credential_id=CRED2)
    assert renewed["identity_key_id"] == original_key
    rotated = store.credential_action(node_id, "rotate", credential_id=CRED3, identity_key_id=KEY3)
    assert rotated["identity_key_id"] != original_key
    identities = JournaledIdentityStore(tmp_path / "identities")
    generation = CredentialGeneration(3, CredentialID(CRED3), IdentityKeyID(KEY3), b"credential")
    identities.stage(generation)
    identities.validate_staged(3, lambda _: True)
    identities.commit(3)
    assert store.recover_identity(node_id, identities.root)["status"] == "recovered"
    store.credential_action(node_id, "revoke")
    valid, entries = store.verify_audit()
    assert valid and entries == 8
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"
    assert len(store.load()["revoked_credentials"]) == 1
    try:
        store.recover_identity(node_id, identities.root)
        raise AssertionError("revoked identity must not recover")
    except ValueError as exc:
        assert str(exc) == "security.credential_revoked"


def test_audit_tampering_and_migration_fail_closed(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    store.create_domain("domain", KEY1)
    state = store.load()
    state["audit"][0]["event"] = "forged"
    store.path.write_text(json.dumps(state))
    assert store.verify_audit() == (False, 0)
    enforce = migration_decision(MigrationStage.ENFORCE, authenticated=False, explicitly_allow_trusted_lan=True)
    assert not enforce.connection_allowed and not enforce.sensitive_control_allowed
    failed = migration_decision(
        MigrationStage.OBSERVE, authenticated=False, explicitly_allow_trusted_lan=True, stronger_auth_failed=True
    )
    assert not failed.connection_allowed
    authenticated_only = migration_decision(
        MigrationStage.ENFORCE, authenticated=True, authorized=False, explicitly_allow_trusted_lan=False
    )
    assert authenticated_only.connection_allowed and not authenticated_only.sensitive_control_allowed


def test_cli_secret_file_and_all_output_are_redacted(tmp_path: Path, capsys) -> None:
    state_dir = tmp_path / "state"
    secret = tmp_path / "secret"
    secret.write_text("extremely-secret-bootstrap\n")
    secret.chmod(0o600)
    assert (
        main(
            ["--state-dir", str(state_dir), "--json", "domain", "create", "--name", "show", "--authority-key-id", KEY1]
        )
        == 0
    )
    domain_id = next(iter(OperationalStateStore(state_dir).load()["domains"]))
    assert (
        main(["--state-dir", str(state_dir), "--json", "enrollment", "open", domain_id, "--secret-file", str(secret)])
        == 0
    )
    output = capsys.readouterr().out
    forbidden = ("extremely-secret-bootstrap", "private_key", "derived_key", "approval_plaintext")
    assert not any(value in output for value in forbidden)
    assert redact({"nested": {"bootstrap_secret": "value"}})["nested"]["bootstrap_secret"] == "<redacted>"


def test_cli_rejects_unprotected_secret_file(tmp_path: Path, capsys) -> None:
    secret = tmp_path / "secret"
    secret.write_text("secret")
    secret.chmod(0o644)
    assert (
        main(["--state-dir", str(tmp_path / "state"), "enrollment", "open", "domain", "--secret-file", str(secret)])
        == 2
    )
    assert "owner-only regular file" in capsys.readouterr().err


def test_cli_rejects_symlinked_or_oversized_secret_file(tmp_path: Path, capsys) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"x" * 4097)
    secret.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(secret)
    for source in (secret, link):
        assert (
            main(["--state-dir", str(tmp_path / "state"), "enrollment", "open", "domain", "--secret-file", str(source)])
            == 2
        )
    assert "error:" in capsys.readouterr().err


def test_concurrent_transactions_are_serialized_and_audit_is_bounded(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path, max_audit_entries=21)
    store.create_domain("domain", KEY1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: store.set_migration(MigrationStage.OBSERVE, False), range(20)))
    assert store.verify_audit() == (True, 21)
    try:
        store.set_migration(MigrationStage.ENROLL, False)
        raise AssertionError("full audit queue must fail closed")
    except ValueError as exc:
        assert str(exc) == "security.resource_limit"


def test_state_tampering_is_bound_to_last_audit_entry(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    domain = store.create_domain("domain", KEY1)
    state = store.load()
    state["domains"][domain["trust_domain_id"]]["name"] = "forged"
    store.path.write_text(json.dumps(state))
    assert store.verify_audit() == (False, 0)
    try:
        store.set_migration(MigrationStage.ENROLL, False)
        raise AssertionError("tampered state must reject mutation")
    except ValueError as exc:
        assert str(exc) == "security.storage_failed"


def test_unaudited_or_structurally_malformed_state_fails_closed(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    forged = store.load()
    forged["domains"]["forged"] = {"authority_key_id": KEY1}
    store.path.write_text(json.dumps(forged))
    store.path.chmod(0o600)
    assert store.verify_audit() == (False, 0)

    forged["audit"] = [None]
    store.path.write_text(json.dumps(forged))
    assert store.verify_audit() == (False, 0)

    forged.pop("nodes")
    store.path.write_text(json.dumps(forged))
    try:
        store.load()
        raise AssertionError("incomplete state schema must fail closed")
    except ValueError as exc:
        assert str(exc) == "security.storage_failed"


def test_identity_collisions_invalid_roles_and_reset_fail_closed(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    domain = store.create_domain("domain", KEY1)
    enrollment = store.open_enrollment(domain["trust_domain_id"], b"secret")
    try:
        store.advance_enrollment(enrollment["enrollment_id"], "attacker")
        raise AssertionError("unknown enrollment role must fail")
    except ValueError as exc:
        assert str(exc) == "security.credential_invalid"
    store.advance_enrollment(enrollment["enrollment_id"], "candidate")
    store.advance_enrollment(enrollment["enrollment_id"], "commissioner", NODE, CRED1, KEY2)

    second = store.open_enrollment(domain["trust_domain_id"], b"secret")
    store.advance_enrollment(second["enrollment_id"], "candidate")
    try:
        store.advance_enrollment(second["enrollment_id"], "commissioner", NODE2, CRED1, KEY3)
        raise AssertionError("credential collision must fail")
    except ValueError as exc:
        assert str(exc) == "security.identity_mismatch"

    reset = store.credential_action(NODE, "reset")
    assert reset["status"] == "unenrolled"
    state = store.load()
    assert state["revocation_epoch"] == 1 and CRED1 in state["revoked_credentials"]
    try:
        store.credential_action(NODE, "renew", credential_id=CRED4)
        raise AssertionError("reset identity must not reactivate")
    except ValueError as exc:
        assert str(exc) == "security.credential_revoked"


def test_operational_state_rejects_oversized_file_before_json_parsing(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    with store.path.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    store.path.chmod(0o600)
    with pytest.raises(ValueError, match="security.storage_failed"):
        store.load()
