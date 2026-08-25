"""Aurora Trust credential validation, persistence, rotation, and revocation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import NoReturn, Protocol

from .cbor_cde import CborTag, decode, encode
from .security_models import (
    ClockTrustState,
    CredentialID,
    IdentityKeyID,
    SecurityErrorCode,
    SecurityNodeID,
    TrustDomainID,
)
from .security_providers import SigningKeyHandle


class CredentialLifecycleError(ValueError):
    def __init__(self, code: SecurityErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def _fail(code: SecurityErrorCode = SecurityErrorCode.CREDENTIAL_INVALID) -> NoReturn:
    raise CredentialLifecycleError(code)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, CborTag) or value.tag != 0 or not isinstance(value.value, str):
        _fail()
    try:
        parsed = datetime.fromisoformat(value.value.replace("Z", "+00:00"))
    except ValueError:
        _fail()
    if parsed.tzinfo is None:
        _fail()
    return parsed.astimezone(UTC)


class SignatureVerifier(Protocol):
    def __call__(self, issuer_key_id: str, digest: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class TrustDomainIdentity:
    trust_domain_id: TrustDomainID
    authority_key_id: IdentityKeyID


class X509IssuanceProvider(Protocol):
    def issue_node_certificate(
        self, trust_domain_id: TrustDomainID, node_id: SecurityNodeID, public_key_spki: bytes
    ) -> bytes: ...


@dataclass(slots=True)
class TrustDomainAuthority:
    identity: TrustDomainIdentity
    signing_key: SigningKeyHandle

    def __post_init__(self) -> None:
        if self.signing_key.key_id != str(self.identity.authority_key_id):
            _fail()

    @classmethod
    def restore(
        cls, expected: TrustDomainIdentity, restored: TrustDomainIdentity, signing_key: SigningKeyHandle
    ) -> TrustDomainAuthority:
        if restored != expected:
            _fail(SecurityErrorCode.TRUST_DOMAIN_MISMATCH)
        return cls(restored, signing_key)

    def issue_compact(self, body: dict[str, object]) -> bytes:
        if body.get("trust_domain_id") != str(self.identity.trust_domain_id):
            _fail(SecurityErrorCode.TRUST_DOMAIN_MISMATCH)
        if body.get("issuer_key_id") != str(self.identity.authority_key_id):
            _fail()
        body_bytes = encode(body)
        digest = hashlib.sha256(b"ACP compact credential v1" + body_bytes).digest()
        signature = self.signing_key.sign_digest(digest)
        return encode({"body": body, "algorithm": "ecdsa_p256_sha256", "signature": signature})

    def issue_x509(self, provider: X509IssuanceProvider, node_id: SecurityNodeID, public_key_spki: bytes) -> bytes:
        return provider.issue_node_certificate(self.identity.trust_domain_id, node_id, public_key_spki)

    def publish_revocation(self, body: dict[str, object]) -> tuple[bytes, bytes]:
        if body.get("trust_domain_id") != str(self.identity.trust_domain_id):
            _fail(SecurityErrorCode.TRUST_DOMAIN_MISMATCH)
        body_bytes = encode(body)
        digest = hashlib.sha256(b"ACP revocation state v1" + body_bytes).digest()
        return body_bytes, self.signing_key.sign_digest(digest)


@dataclass(frozen=True, slots=True)
class RenewalPlan:
    node_id: SecurityNodeID
    current_key_id: IdentityKeyID
    next_key_id: IdentityKeyID
    rotation: bool

    @classmethod
    def create(
        cls,
        node_id: SecurityNodeID,
        current_key_id: IdentityKeyID,
        *,
        rotation: bool,
        requested_key_id: IdentityKeyID | None,
    ) -> RenewalPlan:
        if rotation:
            if requested_key_id is None or requested_key_id == current_key_id:
                _fail()
            next_key = requested_key_id
        else:
            if requested_key_id is not None:
                _fail()
            next_key = current_key_id
        return cls(node_id, current_key_id, next_key, rotation)


@dataclass(frozen=True, slots=True)
class ValidatedCredential:
    credential_id: CredentialID
    identity_key_id: IdentityKeyID
    trust_domain_id: TrustDomainID
    node_id: SecurityNodeID
    public_key: bytes
    role_constraints: frozenset[str]
    not_before: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class X509ValidationEvidence:
    """Ordered facts produced by an X.509 adapter; core code cannot manufacture it."""

    der_parsed: bool
    isolated_chain: bool
    signature_valid: bool
    san_well_formed: bool
    domain_matches: bool
    node_matches: bool
    eku_valid: bool
    ku_valid: bool
    ca_constraints_valid: bool
    validity_valid: bool
    revocation_valid: bool
    credential_id_valid: bool
    identity_key_id_valid: bool
    possession_valid: bool
    local_policy_valid: bool
    unknown_critical_extensions: bool = False

    def require_valid(self) -> None:
        checks = (
            self.der_parsed,
            self.isolated_chain,
            self.signature_valid,
            self.san_well_formed,
            self.domain_matches,
            self.node_matches,
            self.eku_valid,
            self.ku_valid,
            self.ca_constraints_valid,
            self.validity_valid,
            self.revocation_valid,
            self.credential_id_valid,
            self.identity_key_id_valid,
            self.possession_valid,
            self.local_policy_valid,
        )
        if not all(checks) or self.unknown_critical_extensions:
            _fail()


def validate_compact_credential(
    raw: bytes,
    *,
    expected_domain: TrustDomainID,
    expected_node: SecurityNodeID,
    now: datetime,
    verifier: SignatureVerifier,
    revoked: Callable[[CredentialID], bool],
    possession_valid: bool,
    allowed_roles: frozenset[str],
    max_bytes: int = 2048,
) -> ValidatedCredential:
    if not raw or len(raw) > max_bytes:
        _fail(SecurityErrorCode.RESOURCE_LIMIT)
    try:
        outer = decode(raw)
    except ValueError:
        _fail()
    if encode(outer) != raw or not isinstance(outer, dict) or set(outer) != {"body", "algorithm", "signature"}:
        _fail()
    body, algorithm, signature = outer["body"], outer["algorithm"], outer["signature"]
    required = {
        "format",
        "serial",
        "trust_domain_id",
        "node_id",
        "identity_algorithm",
        "identity_public_key",
        "role_constraints",
        "permission_policy_id",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "extensions",
    }
    if not isinstance(body, dict) or set(body) != required or algorithm != "ecdsa_p256_sha256":
        _fail()
    if body["format"] != "acp-compact-credential-v1" or body["identity_algorithm"] != algorithm:
        _fail()
    try:
        domain = TrustDomainID(body["trust_domain_id"])
        node = SecurityNodeID(body["node_id"])
        issuer_key_id = IdentityKeyID(body["issuer_key_id"])
    except (TypeError, ValueError):
        _fail()
    if domain != expected_domain or node != expected_node:
        _fail()
    public_key = body["identity_public_key"]
    roles = body["role_constraints"]
    extensions = body["extensions"]
    if not isinstance(public_key, bytes) or not public_key or not isinstance(roles, list) or len(roles) > 64:
        _fail()
    if (
        not all(isinstance(role, str) and 0 < len(role.encode()) <= 64 for role in roles)
        or roles != sorted(set(roles), key=str.encode)
        or not set(roles) <= allowed_roles
    ):
        _fail()
    if not isinstance(extensions, dict) or len(extensions) > 64:
        _fail()
    for extension in extensions.values():
        if not isinstance(extension, dict) or set(extension) != {"critical", "value"}:
            _fail()
        if not isinstance(extension["critical"], bool) or not isinstance(extension["value"], bytes):
            _fail()
        if extension["critical"] is True:
            _fail()
    not_before, expires_at = _timestamp(body["not_before"]), _timestamp(body["expires_at"])
    issued_at = _timestamp(body["issued_at"])
    now = now.astimezone(UTC)
    if issued_at > now or now < not_before or now > expires_at or not_before > expires_at:
        _fail(SecurityErrorCode.CREDENTIAL_EXPIRED)
    body_bytes = encode(body)
    if not isinstance(signature, bytes) or not verifier(
        str(issuer_key_id), hashlib.sha256(b"ACP compact credential v1" + body_bytes).digest(), signature
    ):
        _fail()
    credential_id = CredentialID("sha256:" + hashlib.sha256(raw).hexdigest())
    identity_key_id = IdentityKeyID("sha256:" + hashlib.sha256(public_key).hexdigest())
    if revoked(credential_id):
        _fail(SecurityErrorCode.CREDENTIAL_REVOKED)
    if not possession_valid:
        _fail()
    return ValidatedCredential(
        credential_id, identity_key_id, domain, node, public_key, frozenset(roles), not_before, expires_at
    )


@dataclass(frozen=True, slots=True)
class RevocationEntry:
    credential_id: CredentialID
    node_id: SecurityNodeID
    revoked_at: datetime
    reason: str


@dataclass(slots=True)
class RevocationState:
    trust_domain_id: TrustDomainID
    max_entries: int
    epoch: int = 0
    entries: dict[CredentialID, RevocationEntry] = field(default_factory=dict)
    issued_at: datetime | None = None
    next_update: datetime | None = None

    def ingest(self, raw_body: bytes, signature: bytes, verifier: SignatureVerifier) -> None:
        try:
            body = decode(raw_body)
        except ValueError:
            _fail()
        if encode(body) != raw_body or not isinstance(body, dict):
            _fail()
        required = {"format", "trust_domain_id", "epoch", "issued_at", "next_update", "issuer_key_id", "entries"}
        allowed = required | {"base_epoch", "previous_snapshot_hash"}
        if not required <= set(body) <= allowed or body["format"] not in {
            "acp-revocation-snapshot-v1",
            "acp-revocation-delta-v1",
        }:
            _fail()
        if body["trust_domain_id"] != str(self.trust_domain_id):
            _fail()
        epoch = body["epoch"]
        issuer = body["issuer_key_id"]
        values = body["entries"]
        if not isinstance(epoch, int) or epoch <= self.epoch or not isinstance(values, list):
            _fail(SecurityErrorCode.AUTHENTICATION_FAILED)
        if body["format"] == "acp-revocation-delta-v1":
            if body.get("base_epoch") != self.epoch or epoch != self.epoch + 1:
                _fail(SecurityErrorCode.AUTHENTICATION_FAILED)
        elif "base_epoch" in body:
            _fail()
        prospective = len(values) if body["format"] == "acp-revocation-snapshot-v1" else len(values) + len(self.entries)
        if len(values) > self.max_entries or prospective > self.max_entries:
            _fail(SecurityErrorCode.RESOURCE_LIMIT)
        if not isinstance(issuer, str) or not verifier(
            issuer, hashlib.sha256(b"ACP revocation state v1" + raw_body).digest(), signature
        ):
            _fail()
        issued_at = _timestamp(body["issued_at"])
        next_update = _timestamp(body["next_update"])
        if next_update <= issued_at:
            _fail()
        parsed: list[RevocationEntry] = []
        previous = ""
        for value in values:
            entry_required = {"credential_id", "node_id", "revoked_at", "reason"}
            if not isinstance(value, dict) or not entry_required <= set(value) <= entry_required | {
                "replacement_credential_id"
            }:
                _fail()
            credential = CredentialID(value["credential_id"])
            if str(credential) <= previous:
                _fail()
            previous = str(credential)
            parsed.append(
                RevocationEntry(
                    credential, SecurityNodeID(value["node_id"]), _timestamp(value["revoked_at"]), value["reason"]
                )
            )
        if body["format"] == "acp-revocation-snapshot-v1":
            self.entries = {}
        self.entries.update({entry.credential_id: entry for entry in parsed})
        self.epoch = epoch
        self.issued_at = issued_at
        self.next_update = next_update

    def contains(self, credential_id: CredentialID) -> bool:
        return credential_id in self.entries

    def require_fresh(self, now: datetime, maximum_snapshot_age: timedelta) -> None:
        if self.issued_at is None or self.next_update is None or maximum_snapshot_age.total_seconds() < 0:
            _fail(SecurityErrorCode.AUTHENTICATION_FAILED)
        deadline = min(self.next_update, self.issued_at + maximum_snapshot_age)
        if now.astimezone(UTC) > deadline:
            _fail(SecurityErrorCode.AUTHENTICATION_FAILED)


class ActiveSessionRevocationPolicy(str, Enum):
    HARDENED_TERMINATE = "hardened_terminate"
    EXPLICIT_AUDITED_GRACE = "explicit_audited_grace"


def revocation_session_action(*, revoked: bool, policy: ActiveSessionRevocationPolicy) -> str:
    if not revoked:
        return "retain"
    return "terminate" if policy is ActiveSessionRevocationPolicy.HARDENED_TERMINATE else "audited_grace"


@dataclass(frozen=True, slots=True)
class CredentialGeneration:
    generation: int
    credential_id: CredentialID
    identity_key_id: IdentityKeyID
    credential: bytes


@dataclass(frozen=True, slots=True)
class SecureTimeCheckpoint:
    authenticated_time: datetime
    monotonic_counter: int | None
    boot_id: str | None
    credential_epoch: int
    revocation_epoch: int


class PersistenceBoundary(str, Enum):
    BEFORE_WRITE = "before_write"
    PARTIAL_WRITE = "partial_write"
    AFTER_STAGE = "after_stage"
    BEFORE_VALIDATION = "before_validation"
    AFTER_VALIDATION = "after_validation"
    BEFORE_COMMIT = "before_commit_marker"
    AFTER_COMMIT = "after_commit_marker"
    DURING_CLEANUP = "during_cleanup"
    DURING_ROTATION = "during_rotation_activation"


FailureInjector = Callable[[PersistenceBoundary], None]


class JournaledIdentityStore:
    """Restricted, checksummed, fsynced two-generation file store."""

    def __init__(self, root: Path, *, inject: FailureInjector | None = None) -> None:
        self.root = root
        self.inject = inject or (lambda _: None)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)

    def _path(self, generation: int) -> Path:
        return self.root / f"identity-{generation}.json"

    @staticmethod
    def _document(value: CredentialGeneration, committed: bool) -> bytes:
        payload = {
            "generation": value.generation,
            "credential_id": str(value.credential_id),
            "identity_key_id": str(value.identity_key_id),
            "credential": base64.b64encode(value.credential).decode("ascii"),
            "committed": committed,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return json.dumps(
            {"payload": payload, "sha256": hashlib.sha256(encoded).hexdigest()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def _atomic_write(self, path: Path, data: bytes) -> None:
        self.inject(PersistenceBoundary.BEFORE_WRITE)
        temporary = path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            if self.inject is not None:
                self.inject(PersistenceBoundary.PARTIAL_WRITE)
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def stage(self, value: CredentialGeneration) -> None:
        self._atomic_write(self._path(value.generation), self._document(value, False))
        self.inject(PersistenceBoundary.AFTER_STAGE)

    def validate_staged(self, generation: int, validator: Callable[[CredentialGeneration], bool]) -> None:
        self.inject(PersistenceBoundary.BEFORE_VALIDATION)
        value, committed = self._read(self._path(generation))
        if committed or not validator(value):
            _fail(SecurityErrorCode.STORAGE_FAILED)
        self.inject(PersistenceBoundary.AFTER_VALIDATION)

    def commit(self, generation: int) -> None:
        value, committed = self._read(self._path(generation))
        if committed:
            return
        self.inject(PersistenceBoundary.BEFORE_COMMIT)
        self._atomic_write(self._path(generation), self._document(value, True))
        self.inject(PersistenceBoundary.AFTER_COMMIT)
        self._write_selector(generation)

    def _write_selector(self, generation: int) -> None:
        self._atomic_write(self.root / "active", f"{generation}\n".encode())

    def recover(self) -> CredentialGeneration | None:
        valid: list[CredentialGeneration] = []
        for path in self.root.glob("identity-*.json"):
            try:
                value, committed = self._read(path)
                if committed:
                    valid.append(value)
            except (OSError, ValueError, TypeError, KeyError, CredentialLifecycleError):
                continue
        return max(valid, key=lambda item: item.generation, default=None)

    def cleanup(self) -> None:
        self.inject(PersistenceBoundary.DURING_CLEANUP)
        active = self.recover()
        if active is None:
            return
        keep = {active.generation, max(0, active.generation - 1)}
        for path in self.root.glob("identity-*.json"):
            generation = int(path.stem.split("-")[1])
            if generation not in keep:
                path.unlink()

    def reset_trust(self) -> None:
        for path in [
            *self.root.glob("identity-*.json"),
            self.root / "active",
            self.root / "secure-time-checkpoint.json",
        ]:
            if path.exists():
                path.unlink()

    def store_checkpoint(self, value: SecureTimeCheckpoint) -> None:
        current = self.load_checkpoint()
        if current is not None and (
            value.authenticated_time < current.authenticated_time
            or value.credential_epoch < current.credential_epoch
            or value.revocation_epoch < current.revocation_epoch
        ):
            _fail(SecurityErrorCode.CLOCK_UNTRUSTED)
        payload = {
            "authenticated_time": value.authenticated_time.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "monotonic_counter": value.monotonic_counter,
            "boot_id": value.boot_id,
            "credential_epoch": value.credential_epoch,
            "revocation_epoch": value.revocation_epoch,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        document = json.dumps(
            {"payload": payload, "sha256": hashlib.sha256(encoded).hexdigest()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._atomic_write(self.root / "secure-time-checkpoint.json", document)

    def load_checkpoint(self) -> SecureTimeCheckpoint | None:
        path = self.root / "secure-time-checkpoint.json"
        if not path.exists():
            return None
        document = json.loads(path.read_bytes())
        payload = document["payload"]
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if document["sha256"] != hashlib.sha256(encoded).hexdigest():
            _fail(SecurityErrorCode.STORAGE_FAILED)
        try:
            authenticated_time = datetime.fromisoformat(payload["authenticated_time"].replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            _fail(SecurityErrorCode.STORAGE_FAILED)
        if authenticated_time.tzinfo is None:
            _fail(SecurityErrorCode.STORAGE_FAILED)
        return SecureTimeCheckpoint(
            authenticated_time.astimezone(UTC),
            payload["monotonic_counter"],
            payload["boot_id"],
            payload["credential_epoch"],
            payload["revocation_epoch"],
        )

    @staticmethod
    def _read(path: Path) -> tuple[CredentialGeneration, bool]:
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            _fail(SecurityErrorCode.STORAGE_FAILED)
        document = json.loads(path.read_bytes())
        payload = document["payload"]
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if document["sha256"] != hashlib.sha256(encoded).hexdigest():
            _fail(SecurityErrorCode.STORAGE_FAILED)
        return (
            CredentialGeneration(
                payload["generation"],
                CredentialID(payload["credential_id"]),
                IdentityKeyID(payload["identity_key_id"]),
                base64.b64decode(payload["credential"], validate=True),
            ),
            payload["committed"],
        )


class RotationPhase(str, Enum):
    IDLE = "idle"
    KEY_PREPARED = "key_prepared"
    CREDENTIAL_OBTAINED = "credential_obtained"
    STAGED = "staged"
    POSSESSION_PROVED = "possession_proved"
    ACTIVE = "active"


@dataclass(slots=True)
class RotationCoordinator:
    store: JournaledIdentityStore
    phase: RotationPhase = RotationPhase.IDLE
    pending: CredentialGeneration | None = None

    def prepare(self, pending: CredentialGeneration) -> None:
        if self.phase is not RotationPhase.IDLE or self.store.recover() is None:
            _fail(SecurityErrorCode.STORAGE_FAILED)
        self.pending = pending
        self.phase = RotationPhase.KEY_PREPARED

    def credential_obtained(self) -> None:
        self._advance(RotationPhase.KEY_PREPARED, RotationPhase.CREDENTIAL_OBTAINED)

    def stage(self, validator: Callable[[CredentialGeneration], bool]) -> None:
        if self.phase is not RotationPhase.CREDENTIAL_OBTAINED or self.pending is None:
            _fail()
        pending = self.pending
        self.store.stage(pending)
        self.store.validate_staged(pending.generation, validator)
        self.phase = RotationPhase.STAGED

    def possession_proved(self, valid: bool) -> None:
        if not valid:
            self.abort()
            _fail()
        self._advance(RotationPhase.STAGED, RotationPhase.POSSESSION_PROVED)

    def activate(self) -> None:
        if self.phase is not RotationPhase.POSSESSION_PROVED or self.pending is None:
            _fail()
        pending = self.pending
        self.store.inject(PersistenceBoundary.DURING_ROTATION)
        self.store.commit(pending.generation)
        self.phase = RotationPhase.ACTIVE

    def abort(self) -> None:
        self.pending = None
        self.phase = RotationPhase.IDLE

    def _advance(self, expected: RotationPhase, target: RotationPhase) -> None:
        if self.phase is not expected:
            _fail()
        self.phase = target


def accepted_time(
    state: ClockTrustState,
    *,
    wall_time: datetime | None,
    checkpoint: datetime | None,
    authenticated_commissioner_time: datetime | None,
    last_checkpoint: datetime | None,
) -> datetime:
    if state is ClockTrustState.TRUSTED_WALL_CLOCK and wall_time is not None:
        candidate = wall_time
    elif state is ClockTrustState.AUTHENTICATED_CHECKPOINT and checkpoint is not None:
        candidate = checkpoint
    elif state is ClockTrustState.COMMISSIONER_BOUNDED and authenticated_commissioner_time is not None:
        candidate = authenticated_commissioner_time
    else:
        _fail(SecurityErrorCode.CLOCK_UNTRUSTED)
    candidate = candidate.astimezone(UTC)
    if last_checkpoint is not None and candidate < last_checkpoint.astimezone(UTC):
        _fail(SecurityErrorCode.CLOCK_UNTRUSTED)
    return candidate
