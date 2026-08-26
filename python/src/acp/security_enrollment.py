"""Bounded Aurora Trust candidate and commissioner enrollment state machines."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .security_models import (
    EnrollmentAttemptID,
    EnrollmentID,
    SecurityErrorCode,
    SecurityProfile,
    SecuritySuite,
)
from .security_providers import AeadProvider, AuditSink, SecureRandomProvider, Spake2PlusOperation
from .security_secrets import SecretBytes


class EnrollmentTransitionError(ValueError):
    def __init__(self, code: SecurityErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class CandidateState(str, Enum):
    UNENROLLED = "unenrolled"
    ENROLLMENT_OPEN = "enrollment_open"
    NEGOTIATING = "negotiating"
    KEY_CONFIRMED = "key_confirmed"
    AWAITING_APPROVAL = "awaiting_approval"
    CREDENTIAL_STAGED = "credential_staged"
    ENROLLED = "enrolled"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    LOCKED = "locked"
    FAILED = "failed"


class CommissionerState(str, Enum):
    IDLE = "idle"
    CANDIDATE_SELECTED = "candidate_selected"
    SECRET_ACQUIRED = "secret_acquired"
    NEGOTIATING = "negotiating"
    KEY_CONFIRMED = "key_confirmed"
    AWAITING_OPERATOR_APPROVAL = "awaiting_operator_approval"
    ISSUING_CREDENTIAL = "issuing_credential"
    AWAITING_INSTALL_RECEIPT = "awaiting_install_receipt"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    LOCKED = "locked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class EnrollmentLimits:
    concurrent_attempts: int
    attempts_per_enrollment: int = 5
    attempt_timeout_ns: int = 60_000_000_000
    enrollment_window_ns: int = 600_000_000_000

    def __post_init__(self) -> None:
        values = (
            self.concurrent_attempts,
            self.attempts_per_enrollment,
            self.attempt_timeout_ns,
            self.enrollment_window_ns,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
            raise EnrollmentTransitionError(SecurityErrorCode.RESOURCE_LIMIT)

    @classmethod
    def for_profile(cls, profile: SecurityProfile) -> EnrollmentLimits:
        return cls(concurrent_attempts=2 if profile is SecurityProfile.FULL else 1)


def select_enrollment_suite(preferred: tuple[SecuritySuite, ...], supported: frozenset[SecuritySuite]) -> SecuritySuite:
    try:
        return next(suite for suite in preferred if suite in supported)
    except StopIteration as exc:
        raise EnrollmentTransitionError(SecurityErrorCode.NO_COMMON_SUITE) from exc


@dataclass(slots=True)
class OneShotApprovalProtector:
    aead: AeadProvider
    random: SecureRandomProvider
    consumed_attempts: set[EnrollmentAttemptID] = field(default_factory=set)

    def seal(
        self, attempt_id: EnrollmentAttemptID, key: SecretBytes, plaintext: SecretBytes, associated_data: bytes
    ) -> tuple[bytes, bytes]:
        if attempt_id in self.consumed_attempts:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_REPLAYED)
        self.consumed_attempts.add(attempt_id)
        nonce_secret = self.random.bytes(12)
        nonce = nonce_secret.use(bytes)
        if len(nonce) != 12:
            raise EnrollmentTransitionError(SecurityErrorCode.RESOURCE_LIMIT)
        return nonce, self.aead.seal(key, plaintext, nonce, associated_data)


@dataclass(slots=True)
class CandidateAttempt:
    deadline_ns: int
    state: CandidateState = CandidateState.NEGOTIATING
    peer_share_processed: bool = False
    durable_install_verified: bool = False


@dataclass(slots=True)
class CandidateEnrollment:
    enrollment_id: EnrollmentID
    supported_suites: frozenset[SecuritySuite]
    limits: EnrollmentLimits
    opened_ns: int
    state: CandidateState = CandidateState.ENROLLMENT_OPEN
    failed_attempts: int = 0
    active_attempts: dict[EnrollmentAttemptID, CandidateAttempt] = field(default_factory=dict)
    consumed_attempts: set[EnrollmentAttemptID] = field(default_factory=set)
    audit: AuditSink | None = field(default=None, repr=False)

    def _record(self, event: str, attempt_id: EnrollmentAttemptID | None = None) -> None:
        if self.audit is not None:
            fields = {"enrollment_id": str(self.enrollment_id), "state": self.state.value}
            if attempt_id is not None:
                fields["attempt_id"] = str(attempt_id)
            self.audit.record(event, fields)

    def begin(self, attempt_id: EnrollmentAttemptID, suite: SecuritySuite, now_ns: int) -> None:
        if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns < 0 or self.opened_ns < 0:
            raise EnrollmentTransitionError(SecurityErrorCode.RESOURCE_LIMIT)
        self._expire_if_needed(now_ns)
        if self.state is CandidateState.LOCKED:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_LOCKED)
        if self.state not in {CandidateState.ENROLLMENT_OPEN, CandidateState.NEGOTIATING}:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_CLOSED)
        if attempt_id in self.active_attempts or attempt_id in self.consumed_attempts:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_REPLAYED)
        if suite not in self.supported_suites:
            raise EnrollmentTransitionError(SecurityErrorCode.NO_COMMON_SUITE)
        if len(self.active_attempts) >= self.limits.concurrent_attempts:
            raise EnrollmentTransitionError(SecurityErrorCode.RESOURCE_LIMIT)
        self.active_attempts[attempt_id] = CandidateAttempt(now_ns + self.limits.attempt_timeout_ns)
        self.state = CandidateState.NEGOTIATING
        self._record("security.enrollment.attempt_started", attempt_id)

    def verify_key_confirmation(
        self, attempt_id: EnrollmentAttemptID, operation: Spake2PlusOperation, confirmation: bytes, now_ns: int
    ) -> None:
        self._require_active(attempt_id, now_ns, CandidateState.NEGOTIATING)
        if not self.active_attempts[attempt_id].peer_share_processed:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        try:
            verified = operation.verify_confirmation(confirmation)
        except Exception as exc:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED) from exc
        if not verified:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        self.active_attempts[attempt_id].state = CandidateState.KEY_CONFIRMED
        self._record("security.enrollment.key_confirmed", attempt_id)

    def process_peer_share(
        self, attempt_id: EnrollmentAttemptID, operation: Spake2PlusOperation, encoded_share: bytes, now_ns: int
    ) -> bytes:
        self._require_active(attempt_id, now_ns, CandidateState.NEGOTIATING)
        if self.active_attempts[attempt_id].peer_share_processed:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        try:
            response = operation.receive_peer_share(encoded_share)
        except Exception as exc:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED) from exc
        if not response:
            self.cryptographic_failure(attempt_id)
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        self.active_attempts[attempt_id].peer_share_processed = True
        self._record("security.enrollment.peer_share_processed", attempt_id)
        return response

    def await_approval(self, attempt_id: EnrollmentAttemptID, now_ns: int) -> None:
        self._require_active(attempt_id, now_ns, CandidateState.KEY_CONFIRMED)
        self.active_attempts[attempt_id].state = CandidateState.AWAITING_APPROVAL
        self._record("security.enrollment.awaiting_approval", attempt_id)

    def credential_staged(self, attempt_id: EnrollmentAttemptID, now_ns: int) -> None:
        self._require_active(attempt_id, now_ns, CandidateState.AWAITING_APPROVAL)
        self.active_attempts[attempt_id].state = CandidateState.CREDENTIAL_STAGED
        self._record("security.enrollment.credential_staged", attempt_id)

    def durable_install_verified(self, attempt_id: EnrollmentAttemptID, now_ns: int) -> None:
        self._require_active(attempt_id, now_ns, CandidateState.CREDENTIAL_STAGED)
        self.active_attempts[attempt_id].durable_install_verified = True
        self._record("security.enrollment.durable_install_verified", attempt_id)

    def complete(self, attempt_id: EnrollmentAttemptID, now_ns: int) -> None:
        self._require_active(attempt_id, now_ns, CandidateState.CREDENTIAL_STAGED)
        if not self.active_attempts[attempt_id].durable_install_verified:
            raise EnrollmentTransitionError(SecurityErrorCode.STORAGE_FAILED)
        self._consume(attempt_id)
        self._consume_all()
        self.state = CandidateState.ENROLLED
        self._record("security.enrollment.enrolled", attempt_id)

    def cryptographic_failure(self, attempt_id: EnrollmentAttemptID) -> None:
        self._consume(attempt_id)
        self.failed_attempts += 1
        if self.failed_attempts >= self.limits.attempts_per_enrollment:
            self._consume_all()
            self.state = CandidateState.LOCKED
        else:
            self.state = CandidateState.NEGOTIATING if self.active_attempts else CandidateState.ENROLLMENT_OPEN
        self._record("security.enrollment.cryptographic_failure", attempt_id)

    def cancel(self) -> None:
        self._consume_all()
        self.state = CandidateState.CANCELLED
        self._record("security.enrollment.cancelled")

    def restart(self) -> None:
        self._consume_all()
        if self.state not in {CandidateState.ENROLLED, CandidateState.LOCKED}:
            self.state = CandidateState.FAILED
        self._record("security.enrollment.restart_invalidated")

    def _require_active(self, attempt_id: EnrollmentAttemptID, now_ns: int, expected: CandidateState) -> None:
        self._expire_if_needed(now_ns)
        attempt = self.active_attempts.get(attempt_id)
        if attempt is None or attempt_id in self.consumed_attempts:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_REPLAYED)
        if now_ns >= attempt.deadline_ns:
            self._consume(attempt_id)
            self.state = CandidateState.EXPIRED
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_EXPIRED)
        if attempt.state is not expected:
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)

    def _expire_if_needed(self, now_ns: int) -> None:
        if now_ns >= self.opened_ns + self.limits.enrollment_window_ns:
            self._consume_all()
            self.state = CandidateState.EXPIRED
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_EXPIRED)

    def _consume(self, attempt_id: EnrollmentAttemptID) -> None:
        self.active_attempts.pop(attempt_id, None)
        self.consumed_attempts.add(attempt_id)

    def _consume_all(self) -> None:
        self.consumed_attempts.update(self.active_attempts)
        self.active_attempts.clear()


@dataclass(slots=True)
class CommissionerEnrollment:
    enrollment_id: EnrollmentID
    attempt_id: EnrollmentAttemptID
    deadline_ns: int
    state: CommissionerState = CommissionerState.IDLE
    consumed: bool = False
    audit: AuditSink | None = field(default=None, repr=False)

    def _record(self, event: str) -> None:
        if self.audit is not None:
            self.audit.record(
                event,
                {
                    "enrollment_id": str(self.enrollment_id),
                    "attempt_id": str(self.attempt_id),
                    "state": self.state.value,
                },
            )

    def transition(self, expected: CommissionerState, target: CommissionerState, now_ns: int) -> None:
        if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns < 0 or self.deadline_ns <= 0:
            raise EnrollmentTransitionError(SecurityErrorCode.RESOURCE_LIMIT)
        if self.consumed:
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_REPLAYED)
        if now_ns >= self.deadline_ns:
            self.consumed = True
            self.state = CommissionerState.EXPIRED
            raise EnrollmentTransitionError(SecurityErrorCode.ENROLLMENT_EXPIRED)
        if self.state is not expected:
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        legal = {
            CommissionerState.IDLE: CommissionerState.CANDIDATE_SELECTED,
            CommissionerState.CANDIDATE_SELECTED: CommissionerState.SECRET_ACQUIRED,
            CommissionerState.SECRET_ACQUIRED: CommissionerState.NEGOTIATING,
            CommissionerState.NEGOTIATING: CommissionerState.KEY_CONFIRMED,
            CommissionerState.KEY_CONFIRMED: CommissionerState.AWAITING_OPERATOR_APPROVAL,
            CommissionerState.AWAITING_OPERATOR_APPROVAL: CommissionerState.ISSUING_CREDENTIAL,
            CommissionerState.ISSUING_CREDENTIAL: CommissionerState.AWAITING_INSTALL_RECEIPT,
            CommissionerState.AWAITING_INSTALL_RECEIPT: CommissionerState.COMPLETE,
        }
        if legal.get(self.state) is not target:
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        self.state = target
        self._record("security.enrollment.commissioner_transition")

    def complete_after_verified_install(self, now_ns: int, *, hmac_valid: bool, proof_valid: bool) -> None:
        if not hmac_valid or not proof_valid:
            self.fail()
            raise EnrollmentTransitionError(SecurityErrorCode.AUTHENTICATION_FAILED)
        self.transition(CommissionerState.AWAITING_INSTALL_RECEIPT, CommissionerState.COMPLETE, now_ns)
        self.consumed = True
        self._record("security.enrollment.install_verified")

    def fail(self) -> None:
        self.consumed = True
        self.state = CommissionerState.FAILED
        self._record("security.enrollment.failed")

    def cancel(self) -> None:
        self.consumed = True
        self.state = CommissionerState.CANCELLED
        self._record("security.enrollment.cancelled")
