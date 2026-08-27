"""Portable ACP trust-domain authority metadata; never signing evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from .security_models import CredentialID, IdentityKeyID, SecurityNodeID, TrustDomainID


def _canonical_uuid(value: str) -> str:
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID must use canonical lowercase representation")
    return value


@dataclass(frozen=True, slots=True)
class TrustDomainAuthorityIdentity:
    trust_domain_id: TrustDomainID
    authority_key_id: IdentityKeyID
    trust_anchor_credential_id: CredentialID


@dataclass(frozen=True, slots=True)
class CommissionerIdentity:
    node_id: SecurityNodeID
    instance_id: str
    credential_id: CredentialID
    identity_key_id: IdentityKeyID

    def __post_init__(self) -> None:
        _canonical_uuid(self.instance_id)


class PortableIssuancePurpose(str, Enum):
    INITIAL = "initial"
    RENEWAL = "renewal"
    KEY_ROTATION = "key_rotation"


@dataclass(frozen=True, slots=True)
class PortableIssuanceMetadata:
    authorization_id: str
    enrollment_id: str
    attempt_id: str
    trust_domain_id: TrustDomainID
    authority_key_id: IdentityKeyID
    commissioner_node_id: SecurityNodeID
    candidate_node_id: SecurityNodeID
    identity_key_id: IdentityKeyID
    credential_id: CredentialID
    purpose: PortableIssuancePurpose
    replaces_credential_id: CredentialID | None = None

    def __post_init__(self) -> None:
        _canonical_uuid(self.authorization_id)
        _canonical_uuid(self.enrollment_id)
        _canonical_uuid(self.attempt_id)
        if (self.purpose is PortableIssuancePurpose.INITIAL) != (self.replaces_credential_id is None):
            raise ValueError("initial issuance and replacement metadata disagree")


@dataclass(frozen=True, slots=True)
class PortableRevocationMetadata:
    trust_domain_id: TrustDomainID
    authority_key_id: IdentityKeyID
    epoch: int
    snapshot_id: CredentialID
    previous_snapshot_id: CredentialID | None = None

    def __post_init__(self) -> None:
        if self.epoch <= 0:
            raise ValueError("revocation epoch must be positive")
