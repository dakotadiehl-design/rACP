from __future__ import annotations

import os
from pathlib import Path

from acp.security_cli import main, redact
from acp.security_operations import MigrationStage, OperationalStateStore, migration_decision


def test_offline_operational_lifecycle_and_audit(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    domain = store.create_domain("Offline show")
    enrollment = store.open_enrollment(domain["trust_domain_id"], b"one-time-bootstrap")
    store.advance_enrollment(enrollment["enrollment_id"], "candidate")
    completed = store.advance_enrollment(enrollment["enrollment_id"], "commissioner")
    node_id = completed["node_id"]
    original_key = store.load()["nodes"][node_id]["identity_key_id"]
    renewed = store.credential_action(node_id, "renew")
    assert renewed["identity_key_id"] == original_key
    rotated = store.credential_action(node_id, "rotate")
    assert rotated["identity_key_id"] != original_key
    store.credential_action(node_id, "recover")
    store.credential_action(node_id, "revoke")
    valid, entries = store.verify_audit()
    assert valid and entries == 8
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"
    assert len(store.load()["revoked_credentials"]) == 1
    try:
        store.credential_action(node_id, "recover")
        raise AssertionError("revoked identity must not recover")
    except ValueError as exc:
        assert str(exc) == "security.credential_revoked"


def test_audit_tampering_and_migration_fail_closed(tmp_path: Path) -> None:
    store = OperationalStateStore(tmp_path)
    store.create_domain("domain")
    state = store.load()
    state["audit"][0]["event"] = "forged"
    store.save(state)
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
    assert main(["--state-dir", str(state_dir), "--json", "domain", "create", "--name", "show"]) == 0
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
    assert "must not be accessible" in capsys.readouterr().err
