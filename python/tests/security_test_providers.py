from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from acp.security_models import ClockTrustState, CredentialID
from acp.security_providers import SigningKeyHandle
from acp.security_secrets import SecretBytes


@dataclass(slots=True)
class DeterministicRandom:
    fixture: bytes
    offset: int = 0

    def bytes(self, count: int) -> SecretBytes:
        if count <= 0 or self.offset + count > len(self.fixture):
            raise RuntimeError("deterministic fixture exhausted")
        value = self.fixture[self.offset : self.offset + count]
        self.offset += count
        return SecretBytes(value)


@dataclass(frozen=True, slots=True)
class DeterministicClock:
    monotonic_value_ns: int
    timestamp: str | None
    trust_state: ClockTrustState

    def monotonic_ns(self) -> int:
        return self.monotonic_value_ns

    def utc_timestamp(self) -> str | None:
        return self.timestamp


@dataclass(slots=True)
class InMemoryIdentityStore:
    staged: tuple[CredentialID, bytes, SigningKeyHandle] | None = None
    active: tuple[CredentialID, bytes, SigningKeyHandle] | None = None

    def stage(self, credential_id: CredentialID, credential: bytes, key: SigningKeyHandle) -> None:
        self.staged = (credential_id, credential, key)

    def commit(self, credential_id: CredentialID) -> None:
        if self.staged is None or self.staged[0] != credential_id:
            raise RuntimeError("no matching staged credential")
        self.active, self.staged = self.staged, None

    def rollback(self) -> None:
        self.staged = None


@dataclass(slots=True)
class CapturingAuditSink:
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def record(self, event: str, public_fields: dict[str, Any]) -> None:
        self.events.append((event, dict(public_fields)))
