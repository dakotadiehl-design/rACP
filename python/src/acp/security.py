from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .constants import load
from .security_models import AuthenticationMode, PrincipalState, SecurityProfile


class CredentialState(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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


class SecurityAdmissionError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


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
            return AuthenticatedPrincipal(
                PrincipalState.UNAUTHENTICATED, claimed_mode, None, None, None, None, None, frozenset()
            )
        raise SecurityAdmissionError("security.downgrade_forbidden" if hardened else "security.credential_invalid")
    if claimed_mode is not evidence.mode:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if claimed_mode is not AuthenticationMode.AURORA_TRUST:
        if hardened:
            raise SecurityAdmissionError("security.downgrade_forbidden")
        return AuthenticatedPrincipal(
            PrincipalState.UNAUTHENTICATED, claimed_mode, None, None, None, None, None, frozenset()
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
    return AuthenticatedPrincipal(
        PrincipalState.AUTHENTICATED,
        claimed_mode,
        evidence.trust_domain_id,
        evidence.node_id,
        evidence.credential_id,
        evidence.identity_key_id,
        evidence.credential_format,
        evidence.role_constraints,
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
    return AuthenticatedPrincipal(
        PrincipalState.AUTHENTICATED,
        evidence.mode,
        evidence.trust_domain_id,
        evidence.node_id,
        evidence.credential_id,
        evidence.identity_key_id,
        evidence.credential_format,
        evidence.role_constraints,
        evidence.profile,
    )


def effective_permissions(
    credential_constraints: set[str], local_policy: set[str], capabilities: set[str], safety_policy: set[str]
) -> frozenset[str]:
    return frozenset(credential_constraints & local_policy & capabilities & safety_policy)


def profile_limits(profile: str) -> Mapping[str, Any]:
    return load()["security"]["limits"][profile]
