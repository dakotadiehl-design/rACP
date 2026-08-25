"""Offline Aurora Trust operational state, audit chain, and migration policy."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .security_models import IdentityKeyID, SecurityNodeID, TrustDomainID


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

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        self.path = root / "operations.json"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "version": 1,
                "domains": {},
                "enrollments": {},
                "nodes": {},
                "revocation_epoch": 0,
                "revoked_credentials": [],
                "migration": {"stage": "observe", "allow_trusted_lan": False},
                "audit": [],
            }
        value = json.loads(self.path.read_text())
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError("security.storage_failed")
        value.setdefault("revoked_credentials", [])
        return value

    def save(self, value: dict[str, Any]) -> None:
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
        public = {
            "index": len(entries),
            "timestamp": _utc_now(),
            "event": event,
            "fields": fields,
            "previous_hash": previous,
        }
        encoded = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        entries.append({**public, "hash": _digest(encoded)})

    def transact(self, event: str, fields: dict[str, Any], mutate: Any) -> dict[str, Any]:
        state = self.load()
        valid, _ = self._verify_entries(state["audit"])
        if not valid:
            raise ValueError("security.storage_failed")
        result = mutate(state)
        self._audit(state, event, fields)
        self.save(state)
        return result

    def verify_audit(self) -> tuple[bool, int]:
        return self._verify_entries(self.load()["audit"])

    @staticmethod
    def _verify_entries(entries: list[dict[str, Any]]) -> tuple[bool, int]:
        previous = "sha256:" + "0" * 64
        for index, entry in enumerate(entries):
            if entry.get("index") != index or entry.get("previous_hash") != previous:
                return False, index
            public = {key: entry[key] for key in ("index", "timestamp", "event", "fields", "previous_hash")}
            if entry.get("hash") != _digest(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()):
                return False, index
            previous = entry["hash"]
        return True, len(entries)

    def create_domain(self, name: str) -> dict[str, Any]:
        domain_id = str(uuid.uuid4())
        authority_key_id = _digest(os.urandom(32))
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

    def advance_enrollment(self, enrollment_id: str, role: str, node_id: str | None = None) -> dict[str, Any]:
        target = "candidate_ready" if role == "candidate" else "complete"

        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            enrollment = state["enrollments"].get(enrollment_id)
            if enrollment is None or enrollment["state"] not in (
                {"open"} if role == "candidate" else {"candidate_ready"}
            ):
                raise ValueError("security.authentication_failed")
            enrollment["state"] = target
            if role == "commissioner":
                actual_node = node_id or str(uuid.uuid4())
                SecurityNodeID(actual_node)
                if actual_node in state["nodes"]:
                    raise ValueError("security.identity_mismatch")
                credential_id, key_id = _digest(os.urandom(32)), _digest(os.urandom(32))
                state["nodes"][actual_node] = {
                    "node_id": actual_node,
                    "trust_domain_id": enrollment["trust_domain_id"],
                    "credential_id": credential_id,
                    "identity_key_id": key_id,
                    "status": "active",
                    "generation": 1,
                }
                enrollment["node_id"] = actual_node
            return enrollment

        return self.transact(f"security.enrollment.{role}", {"enrollment_id": enrollment_id}, mutate)

    def credential_action(self, node_id: str, action: str) -> dict[str, Any]:
        def mutate(state: dict[str, Any]) -> dict[str, Any]:
            node = state["nodes"].get(node_id)
            if node is None:
                raise ValueError("security.credential_invalid")
            if action in {"renew", "rotate"}:
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
                node["credential_id"] = _digest(os.urandom(32))
                if action == "rotate":
                    node["identity_key_id"] = _digest(os.urandom(32))
                node["generation"] += 1
                node["status"] = "active"
            elif action == "revoke":
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
                node["status"] = "revoked"
                state["revocation_epoch"] += 1
                state["revoked_credentials"].append(node["credential_id"])
            elif action == "reset":
                node["status"] = "unenrolled"
            elif action == "recover":
                if node["status"] != "active":
                    raise ValueError("security.credential_revoked")
            else:
                raise ValueError("security.credential_invalid")
            return dict(node)

        return self.transact(f"security.credential.{action}", {"node_id": node_id}, mutate)

    def set_migration(self, stage: MigrationStage, allow_trusted_lan: bool) -> dict[str, Any]:
        if stage is MigrationStage.ENFORCE and allow_trusted_lan:
            raise ValueError("security.downgrade_forbidden")
        value = {"stage": stage.value, "allow_trusted_lan": allow_trusted_lan}
        return self.transact(
            "security.migration.changed", value, lambda state: state.__setitem__("migration", value) or value
        )
