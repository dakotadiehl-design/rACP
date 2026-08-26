"""Offline Aurora Trust operational state, audit chain, and migration policy."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .security_credentials import JournaledIdentityStore
from .security_models import CredentialID, IdentityKeyID, SecurityNodeID, TrustDomainID


class MigrationStage(str, Enum):
    OBSERVE = "observe"
    ENROLL = "enroll"
    PREFER_AUTHENTICATED = "prefer_authenticated"
    ENFORCE = "enforce"


@dataclass(frozen=True, slots=True)
class MigrationDecision:
    connection_allowed: bool
    sensitive_control_allowed: bool
    prefer_authenticated: bool
    reason: str


def migration_decision(
    stage: MigrationStage,
    *,
    authenticated: bool,
    authorized: bool = False,
    explicitly_allow_trusted_lan: bool,
    stronger_auth_failed: bool = False,
) -> MigrationDecision:
    prefer = stage in {MigrationStage.PREFER_AUTHENTICATED, MigrationStage.ENFORCE}
    if authenticated:
        return MigrationDecision(
            True, authorized, prefer, "authenticated_authorized" if authorized else "security.permission_denied"
        )
    if stronger_auth_failed or stage is MigrationStage.ENFORCE:
        return MigrationDecision(False, False, prefer, "security.downgrade_forbidden")
    allowed = explicitly_allow_trusted_lan
    return MigrationDecision(
        allowed, False, prefer, "trusted_lan_view_only" if allowed else "security.permission_denied"
    )


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class OperationalStateStore:
    """Restricted, atomic JSON store. It persists public operational metadata only."""

    def __init__(self, root: Path, *, max_audit_entries: int = 10_000) -> None:
        if root.is_symlink() or max_audit_entries < 1:
            raise ValueError("security.storage_failed")
        self.root = root
        self.max_audit_entries = max_audit_entries
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        self.path = root / "operations.json"
        self.lock_path = root / "operations.lock"

    def load(self) -> dict[str, Any]:
        if self.path.is_symlink():
            raise ValueError("security.storage_failed")
        if not self.path.exists():
            return {
                "version": 2,
                "domains": {},
                "enrollments": {},
                "nodes": {},
                "revocation_epoch": 0,
                "revoked_credentials": [],
                "migration": {"stage": "observe", "allow_trusted_lan": False},
                "audit": [],
            }
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_size > 16 * 1024 * 1024
            ):
                raise ValueError("security.storage_failed")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                raw = stream.read(16 * 1024 * 1024 + 1)
                if len(raw.encode("utf-8")) > 16 * 1024 * 1024:
                    raise ValueError("security.storage_failed")
                value = json.loads(raw)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        required = {
            "version",
            "domains",
            "enrollments",
            "nodes",
            "revocation_epoch",
            "revoked_credentials",
            "migration",
            "audit",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("version") != 2
            or not isinstance(value.get("audit"), list)
        ):
            raise ValueError("security.storage_failed")
        return value

    @contextmanager
    def _locked(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("security.storage_failed")
            os.chmod(self.lock_path, 0o600)
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _save(self, value: dict[str, Any]) -> None:
        if self.path.is_symlink():
            raise ValueError("security.storage_failed")
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        descriptor, temporary = tempfile.mkstemp(prefix="operations-", suffix=".tmp", dir=self.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _audit(state: dict[str, Any], event: str, fields: dict[str, Any]) -> None:
        entries = state["audit"]
        previous = entries[-1]["hash"] if entries else "sha256:" + "0" * 64
        state_hash = _digest(
            json.dumps(
                {key: value for key, value in state.items() if key != "audit"}, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        public = {
            "index": len(entries),
            "timestamp": _utc_now(),
            "event": event,
            "fields": fields,
            "previous_hash": previous,
            "state_hash": state_hash,
        }
        encoded = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        entries.append({**public, "hash": _digest(encoded)})

    def transact(self, event: str, fields: dict[str, Any], mutate: Any) -> dict[str, Any]:
        with self._locked():
            state = self.load()
            valid, _ = self._verify_entries(state["audit"], state)
            if not valid:
                raise ValueError("security.storage_failed")
            if len(state["audit"]) >= self.max_audit_entries:
                raise ValueError("security.resource_limit")
            result = mutate(state)
            self._audit(state, event, fields)
            self._save(state)
            return result

    def verify_audit(self) -> tuple[bool, int]:
        state = self.load()
        return self._verify_entries(state["audit"], state)

    @staticmethod
    def _verify_entries(entries: list[dict[str, Any]], state: dict[str, Any]) -> tuple[bool, int]:
        previous = "sha256:" + "0" * 64
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or entry.get("index") != index or entry.get("previous_hash") != previous:
                return False, index
            try:
                public = {
                    key: entry[key] for key in ("index", "timestamp", "event", "fields", "previous_hash", "state_hash")
                }
                encoded = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
            except (KeyError, TypeError, ValueError):
                return False, index
            if entry.get("hash") != _digest(encoded):
                return False, index
            previous = entry["hash"]
        if entries:
            current_hash = _digest(
                json.dumps(
                    {key: value for key, value in state.items() if key != "audit"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            if entries[-1].get("state_hash") != current_hash:
                return False, len(entries) - 1
        elif state != {
            "version": 2,
            "domains": {},
            "enrollments": {},
            "nodes": {},
            "revocation_epoch": 0,
            "revoked_credentials": [],
            "migration": {"stage": "observe", "allow_trusted_lan": False},
            "audit": [],
        }:
            return False, 0
        return True, len(entries)

    def create_domain(self, name: str, authority_key_id: str) -> dict[str, Any]:
        domain_id = str(uuid.uuid4())
        IdentityKeyID(authority_key_id)
        record = {
            "trust_domain_id": domain_id,
            "name": name,
            "authority_key_id": authority_key_id,
            "created_at": _utc_now(),
        }
        return self.transact(
            "security.domain.created",
            {"trust_domain_id": domain_id},
            lambda state: state["domains"].setdefault(domain_id, record),
        )

    def import_domain(self, package: dict[str, Any]) -> dict[str, Any]:
        allowed = {"trust_domain_id", "name", "authority_key_id", "created_at"}
        if set(package) != allowed or not all(isinstance(package[key], str) for key in allowed):
            raise ValueError("security.credential_invalid")
        domain_id = package["trust_domain_id"]
        TrustDomainID(domain_id)
        IdentityKeyID(package["authority_key_id"])

        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            existing = state["domains"].get(domain_id)
            if existing is not None and existing != package:
                raise ValueError("security.identity_mismatch")
            state["domains"][domain_id] = package
            return package

        return self.transact(
            "security.domain.imported",
            {"trust_domain_id": domain_id},
            mutate,
        )

    def open_enrollment(self, domain_id: str, bootstrap_secret: bytes) -> dict[str, Any]:
        if not bootstrap_secret:
            raise ValueError("security.credential_invalid")
        enrollment_id = str(uuid.uuid4())
        record = {
            "enrollment_id": enrollment_id,
            "trust_domain_id": domain_id,
            "state": "open",
            "opened_at": _utc_now(),
        }

        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            if domain_id not in state["domains"]:
                raise ValueError("security.trust_domain_mismatch")
            state["enrollments"][enrollment_id] = record
            return record

        return self.transact(
            "security.enrollment.opened", {"enrollment_id": enrollment_id, "trust_domain_id": domain_id}, mutate
        )

    def advance_enrollment(
        self,
        enrollment_id: str,
        role: str,
        node_id: str | None = None,
        credential_id: str | None = None,
        identity_key_id: str | None = None,
    ) -> dict[str, Any]:
        if role not in {"candidate", "commissioner"}:
            raise ValueError("security.credential_invalid")
        target = "candidate_ready" if role == "candidate" else "complete"

        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            enrollment = state["enrollments"].get(enrollment_id)
            if enrollment is None or enrollment["state"] not in (
                {"open"} if role == "candidate" else {"candidate_ready"}
            ):
                raise ValueError("security.authentication_failed")
            enrollment["state"] = target
            if role == "commissioner":
                if node_id is None or credential_id is None or identity_key_id is None:
                    raise ValueError("security.credential_invalid")
                actual_node = node_id
                SecurityNodeID(actual_node)
                CredentialID(credential_id)
                IdentityKeyID(identity_key_id)
                if actual_node in state["nodes"]:
                    raise ValueError("security.identity_mismatch")
                if credential_id in state["revoked_credentials"] or any(
                    node["credential_id"] == credential_id or node["identity_key_id"] == identity_key_id
                    for node in state["nodes"].values()
                ):
                    raise ValueError("security.identity_mismatch")
                state["nodes"][actual_node] = {
                    "node_id": actual_node,
                    "trust_domain_id": enrollment["trust_domain_id"],
                    "credential_id": credential_id,
                    "identity_key_id": identity_key_id,
                    "status": "active",
                    "generation": 1,
                }
                enrollment["node_id"] = actual_node
            return enrollment

        return self.transact(f"security.enrollment.{role}", {"enrollment_id": enrollment_id}, mutate)

    def credential_action(
        self,
        node_id: str,
        action: str,
        *,
        credential_id: str | None = None,
        identity_key_id: str | None = None,
    ) -> dict[str, Any]:
        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            node = state["nodes"].get(node_id)
            if node is None:
                raise ValueError("security.credential_invalid")
            if action in {"renew", "rotate"}:
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
                if credential_id is None:
                    raise ValueError("security.credential_invalid")
                CredentialID(credential_id)
                if credential_id in state["revoked_credentials"] or any(
                    other_id != node_id and other["credential_id"] == credential_id
                    for other_id, other in state["nodes"].items()
                ):
                    raise ValueError("security.identity_mismatch")
                if credential_id == node["credential_id"]:
                    raise ValueError("security.credential_invalid")
                node["credential_id"] = credential_id
                if action == "rotate":
                    if identity_key_id is None:
                        raise ValueError("security.credential_invalid")
                    IdentityKeyID(identity_key_id)
                    if identity_key_id == node["identity_key_id"] or any(
                        other_id != node_id and other["identity_key_id"] == identity_key_id
                        for other_id, other in state["nodes"].items()
                    ):
                        raise ValueError("security.identity_mismatch")
                    node["identity_key_id"] = identity_key_id
                node["generation"] += 1
                node["status"] = "active"
            elif action == "revoke":
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
                node["status"] = "revoked"
                state["revocation_epoch"] += 1
                state["revoked_credentials"].append(node["credential_id"])
            elif action == "reset":
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
                node["status"] = "unenrolled"
                state["revocation_epoch"] += 1
                state["revoked_credentials"].append(node["credential_id"])
            elif action == "recover":
                raise ValueError("security.credential_invalid")
            else:
                raise ValueError("security.credential_invalid")
            return dict(node)

        return self.transact(f"security.credential.{action}", {"node_id": node_id}, mutate)

    def recover_identity(self, node_id: str, identity_store: Path) -> dict[str, Any]:
        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            node = state["nodes"].get(node_id)
            if node is None or node["status"] != "active":
                raise ValueError("security.credential_revoked")
            recovered = JournaledIdentityStore(identity_store).recover()
            if recovered is None or str(recovered.credential_id) != node["credential_id"]:
                raise ValueError("security.storage_failed")
            if str(recovered.identity_key_id) != node["identity_key_id"]:
                raise ValueError("security.identity_mismatch")
            return {
                "node_id": node_id,
                "credential_id": node["credential_id"],
                "identity_key_id": node["identity_key_id"],
                "generation": recovered.generation,
                "status": "recovered",
            }

        return self.transact("security.identity.recovered", {"node_id": node_id}, mutate)

    def set_migration(self, stage: MigrationStage, allow_trusted_lan: bool) -> dict[str, Any]:
        if stage is MigrationStage.ENFORCE and allow_trusted_lan:
            raise ValueError("security.downgrade_forbidden")
        value = {"stage": stage.value, "allow_trusted_lan": allow_trusted_lan}
        return self.transact(
            "security.migration.changed", value, lambda state: state.__setitem__("migration", value) or value
        )
