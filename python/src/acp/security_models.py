"""Typed Aurora Trust 1.0 models shared by enrollment and session security."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class _UUIDIdentifier:
    value: str

    def __post_init__(self) -> None:
        if not _UUID.fullmatch(self.value):
            raise ValueError(f"invalid {type(self).__name__}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class TrustDomainID(_UUIDIdentifier):
    pass


@dataclass(frozen=True, slots=True)
class SecurityNodeID(_UUIDIdentifier):
    pass


@dataclass(frozen=True, slots=True)
class EnrollmentID(_UUIDIdentifier):
    pass


@dataclass(frozen=True, slots=True)
class EnrollmentAttemptID(_UUIDIdentifier):
    pass


@dataclass(frozen=True, slots=True)
class _DigestIdentifier:
    value: str

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.value):
            raise ValueError(f"invalid {type(self).__name__}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CredentialID(_DigestIdentifier):
    pass


@dataclass(frozen=True, slots=True)
class IdentityKeyID(_DigestIdentifier):
    pass


class SecuritySuite(str, Enum):
    RAW128 = "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1"
    PBKDF2_100K = "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-PBKDF2-100K-v1"


class AuthenticationMode(str, Enum):
    TRUSTED_LAN = "trusted_lan"
    TLS = "tls"
    AURORA_TRUST = "aurora_trust"
    ENROLLMENT_SPAKE2PLUS = "enrollment_spake2plus"


class SecurityProfile(str, Enum):
    FULL = "full"
    LIGHTWEIGHT = "lightweight"


class PrincipalState(str, Enum):
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    REVOKED = "revoked"
    EXPIRED = "expired"
    IDENTITY_CONFLICT = "identity_conflict"
    INVALID = "invalid"


class CredentialFormat(str, Enum):
    X509_DER = "x509_der"
    COMPACT_V1 = "acp-compact-credential-v1"


class CredentialStatus(str, Enum):
    STAGED = "staged"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class EnrollmentMethod(str, Enum):
    MANUAL_CODE = "manual_code"
    QR = "qr"
    PROVISIONING_FILE = "provisioning_file"


class EnrollmentState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
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


class StorageClass(str, Enum):
    HARDWARE_BACKED = "hardware_backed"
    OS_PROTECTED = "os_protected"
    ENCRYPTED_FILE = "encrypted_file"
    PROTECTED_FLASH = "protected_flash"
    PLAIN_FILE = "plain_file"
    EPHEMERAL = "ephemeral"


@dataclass(frozen=True, slots=True)
class StoragePosture:
    storage_class: StorageClass
    hardware_backed: bool
    private_key_exportable: bool


class ClockTrustState(str, Enum):
    TRUSTED_WALL_CLOCK = "trusted_wall_clock"
    AUTHENTICATED_CHECKPOINT = "authenticated_checkpoint"
    COMMISSIONER_BOUNDED = "commissioner_bounded"
    UNTRUSTED = "untrusted"


class SecurityErrorCode(str, Enum):
    ENROLLMENT_CLOSED = "security.enrollment_closed"
    ENROLLMENT_EXPIRED = "security.enrollment_expired"
    ENROLLMENT_LOCKED = "security.enrollment_locked"
    ENROLLMENT_REPLAYED = "security.enrollment_replayed"
    NO_COMMON_SUITE = "security.no_common_suite"
    AUTHENTICATION_FAILED = "security.authentication_failed"
    KEY_CONFIRMATION_FAILED = "security.key_confirmation_failed"
    TRANSCRIPT_MISMATCH = "security.transcript_mismatch"
    IDENTITY_MISMATCH = "security.identity_mismatch"
    TRUST_DOMAIN_MISMATCH = "security.trust_domain_mismatch"
    CREDENTIAL_EXPIRED = "security.credential_expired"
    CREDENTIAL_REVOKED = "security.credential_revoked"
    CREDENTIAL_INVALID = "security.credential_invalid"
    PERMISSION_DENIED = "security.permission_denied"
    DOWNGRADE_FORBIDDEN = "security.downgrade_forbidden"
    STORAGE_FAILED = "security.storage_failed"
    RESOURCE_LIMIT = "security.resource_limit"
    CLOCK_UNTRUSTED = "security.clock_untrusted"


@dataclass(frozen=True, slots=True)
class SecurityCapabilityVersion:
    identifier: str
    version: str

    def __post_init__(self) -> None:
        if not self.identifier or not self.version:
            raise ValueError("security capability ID and version must be non-empty")


@dataclass(frozen=True, slots=True)
class DowngradePolicy:
    hardened: bool
    allow_trusted_lan: bool

    @classmethod
    def hardened_production(cls) -> DowngradePolicy:
        return cls(hardened=True, allow_trusted_lan=False)

    @classmethod
    def migration(cls, *, allow_trusted_lan: bool) -> DowngradePolicy:
        return cls(hardened=False, allow_trusted_lan=allow_trusted_lan)

    def permits_unauthenticated(self, *, stronger_auth_attempted: bool) -> bool:
        return self.allow_trusted_lan and not self.hardened and not stronger_auth_attempted
