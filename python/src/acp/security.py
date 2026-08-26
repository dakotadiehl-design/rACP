from __future__ import annotations

from collections.abc import Mapping
from dataclasses import MISSING, dataclass
from enum import Enum
from typing import Any, NoReturn, SupportsIndex

from .constants import load
from .security_context import base64url_decode
from .security_models import (
    AuthenticationMode,
    CredentialID,
    IdentityKeyID,
    PrincipalState,
    SecurityNodeID,
    SecurityProfile,
    TrustDomainID,
)


class CredentialState(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


_EVIDENCE_PROVENANCE = object()
_PRINCIPAL_PROVENANCE = object()


@dataclass(frozen=True, init=False)
class TransportEvidence:
    mode: AuthenticationMode
    trust_domain_id: str | None = None
    node_id: str | None = None
    credential_id: str | None = None
    identity_key_id: str | None = None
    credential_format: str | None = None
    channel_binding: str | None = None
    role_constraints: frozenset[str] = frozenset()
    credential_state: CredentialState = CredentialState.INVALID
    channel_binding_verified: bool = False
    zero_rtt_used: bool = False
    resumption_used: bool = False
    profile: SecurityProfile = SecurityProfile.FULL

    def __init__(self, *, _provenance: object, **values: Any) -> None:
        if _provenance is not _EVIDENCE_PROVENANCE:
            raise TypeError("transport evidence may only be created by an authenticated transport provider")
        fields = self.__dataclass_fields__
        unknown = values.keys() - fields.keys()
        if unknown:
            raise TypeError(f"unknown transport evidence fields: {sorted(unknown)!r}")
        for name, field in fields.items():
            if name not in values and field.default is MISSING:
                raise TypeError(f"missing transport evidence field: {name}")
            value = values[name] if name in values else field.default
            object.__setattr__(self, name, value)

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("transport evidence cannot be serialized")


def _verified_transport_evidence(**values: Any) -> TransportEvidence:
    """Provider-only factory. Application code must never manufacture evidence."""
    return TransportEvidence(_provenance=_EVIDENCE_PROVENANCE, **values)


@dataclass(frozen=True, init=False)
class AuthenticatedPrincipal:
    state: PrincipalState
    mode: AuthenticationMode
    trust_domain_id: str | None
    node_id: str | None
    credential_id: str | None
    identity_key_id: str | None
    credential_format: str | None
    role_constraints: frozenset[str]
    profile: SecurityProfile | None = None

    def __init__(self, *, _provenance: object, **values: Any) -> None:
        if _provenance is not _PRINCIPAL_PROVENANCE:
            raise TypeError("authenticated principals may only be created by security admission")
        fields = self.__dataclass_fields__
        unknown = values.keys() - fields.keys()
        if unknown:
            raise TypeError(f"unknown principal fields: {sorted(unknown)!r}")
        for name, field in fields.items():
            if name not in values and field.default is MISSING:
                raise TypeError(f"missing principal field: {name}")
            value = values[name] if name in values else field.default
            object.__setattr__(self, name, value)

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("authenticated principals cannot be serialized")


def _admitted_principal(**values: Any) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(_provenance=_PRINCIPAL_PROVENANCE, **values)


class SecurityAdmissionError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _validate_evidence_identity(evidence: TransportEvidence) -> None:
    values = (
        evidence.trust_domain_id,
        evidence.node_id,
        evidence.credential_id,
        evidence.identity_key_id,
        evidence.channel_binding,
    )
    if not all(isinstance(value, str) for value in values):
        raise SecurityAdmissionError("security.credential_invalid")
    trust_domain_id, node_id, credential_id, identity_key_id, channel_binding = values
    assert isinstance(trust_domain_id, str) and isinstance(node_id, str)
    assert isinstance(credential_id, str) and isinstance(identity_key_id, str)
    assert isinstance(channel_binding, str)
    try:
        TrustDomainID(trust_domain_id)
        SecurityNodeID(node_id)
        CredentialID(credential_id)
        IdentityKeyID(identity_key_id)
        binding = base64url_decode(channel_binding)
    except (TypeError, ValueError) as exc:
        raise SecurityAdmissionError("security.credential_invalid") from exc
    expected_format = "x509_der" if evidence.profile is SecurityProfile.FULL else "acp-compact-credential-v1"
    if evidence.credential_format != expected_format or len(binding) != 32 or len(evidence.role_constraints) > 16:
        raise SecurityAdmissionError("security.credential_invalid")
    if any(not isinstance(role, str) or not 1 <= len(role.encode()) <= 64 for role in evidence.role_constraints):
        raise SecurityAdmissionError("security.credential_invalid")


def bind_hello_auth(
    claimed_node_id: str,
    auth: Mapping[str, Any],
    evidence: TransportEvidence | None,
    *,
    hardened: bool,
    security_capabilities: tuple[tuple[str, str], ...] = (),
) -> AuthenticatedPrincipal:
    """Bind HELLO claims to verified transport evidence; claims never create authority."""
    try:
        claimed_mode = AuthenticationMode(str(auth["mode"]))
    except (KeyError, ValueError) as exc:
        raise SecurityAdmissionError("security.credential_invalid") from exc

    if evidence is None:
        if claimed_mode is AuthenticationMode.TRUSTED_LAN and not hardened:
            return _admitted_principal(
                state=PrincipalState.UNAUTHENTICATED, mode=claimed_mode, trust_domain_id=None, node_id=None,
                credential_id=None, identity_key_id=None, credential_format=None, role_constraints=frozenset()
            )
        raise SecurityAdmissionError("security.downgrade_forbidden" if hardened else "security.credential_invalid")
    if claimed_mode is not evidence.mode:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if claimed_mode is not AuthenticationMode.AURORA_TRUST:
        if hardened:
            raise SecurityAdmissionError("security.downgrade_forbidden")
        return _admitted_principal(
            state=PrincipalState.UNAUTHENTICATED, mode=claimed_mode, trust_domain_id=None, node_id=None,
            credential_id=None, identity_key_id=None, credential_format=None, role_constraints=frozenset()
        )
    if evidence.zero_rtt_used or evidence.resumption_used:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if evidence.credential_state is CredentialState.REVOKED:
        raise SecurityAdmissionError("security.credential_revoked")
    if evidence.credential_state is CredentialState.EXPIRED:
        raise SecurityAdmissionError("security.credential_expired")
    if evidence.credential_state is not CredentialState.ACTIVE:
        raise SecurityAdmissionError("security.credential_invalid")
    if not evidence.channel_binding_verified:
        raise SecurityAdmissionError("security.authentication_failed")
    if len({item[0] for item in security_capabilities}) != len(security_capabilities):
        raise SecurityAdmissionError("security.credential_invalid")
    if ("aurora-trust", "1.0") not in security_capabilities:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if not all(
        (
            evidence.node_id,
            evidence.trust_domain_id,
            evidence.credential_id,
            evidence.identity_key_id,
            evidence.channel_binding,
        )
    ):
        raise SecurityAdmissionError("security.credential_invalid")
    _validate_evidence_identity(evidence)
    bindings = {
        "trust_domain_id": evidence.trust_domain_id,
        "credential_id": evidence.credential_id,
        "identity_key_id": evidence.identity_key_id,
        "channel_binding": evidence.channel_binding,
    }
    if claimed_node_id != evidence.node_id:
        raise SecurityAdmissionError("security.identity_mismatch")
    for field, verified in bindings.items():
        if not verified or auth.get(field) != verified:
            raise SecurityAdmissionError(
                "security.trust_domain_mismatch" if field == "trust_domain_id" else "security.identity_mismatch"
            )
    return _admitted_principal(
        state=PrincipalState.AUTHENTICATED,
        mode=claimed_mode,
        trust_domain_id=evidence.trust_domain_id,
        node_id=evidence.node_id,
        credential_id=evidence.credential_id,
        identity_key_id=evidence.identity_key_id,
        credential_format=evidence.credential_format,
        role_constraints=evidence.role_constraints,
        profile=evidence.profile,
    )


def principal_from_verified_evidence(expected_node_id: str, evidence: TransportEvidence) -> AuthenticatedPrincipal:
    """Revalidate provider evidence when a peer sends no repeatable auth object (HELLO_ACK)."""
    if evidence.mode is not AuthenticationMode.AURORA_TRUST:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if evidence.zero_rtt_used or evidence.resumption_used:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if evidence.credential_state is CredentialState.REVOKED:
        raise SecurityAdmissionError("security.credential_revoked")
    if evidence.credential_state is CredentialState.EXPIRED:
        raise SecurityAdmissionError("security.credential_expired")
    if evidence.credential_state is not CredentialState.ACTIVE:
        raise SecurityAdmissionError("security.credential_invalid")
    if not evidence.channel_binding_verified or not evidence.channel_binding:
        raise SecurityAdmissionError("security.authentication_failed")
    if evidence.node_id != expected_node_id:
        raise SecurityAdmissionError("security.identity_mismatch")
    if not all((evidence.trust_domain_id, evidence.credential_id, evidence.identity_key_id)):
        raise SecurityAdmissionError("security.credential_invalid")
    _validate_evidence_identity(evidence)
    return _admitted_principal(
        state=PrincipalState.AUTHENTICATED,
        mode=evidence.mode,
        trust_domain_id=evidence.trust_domain_id,
        node_id=evidence.node_id,
        credential_id=evidence.credential_id,
        identity_key_id=evidence.identity_key_id,
        credential_format=evidence.credential_format,
        role_constraints=evidence.role_constraints,
        profile=evidence.profile,
    )


def effective_permissions(
    credential_constraints: set[str], local_policy: set[str], capabilities: set[str], safety_policy: set[str]
) -> frozenset[str]:
    return frozenset(credential_constraints & local_policy & capabilities & safety_policy)


def profile_limits(profile: str) -> Mapping[str, Any]:
    return load()["security"]["limits"][profile]
