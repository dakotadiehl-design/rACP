from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, FrozenSet, Mapping

from .constants import load


class AuthenticationMode(str, Enum):
    TRUSTED_LAN = "trusted_lan"
    TLS = "tls"
    AURORA_TRUST = "aurora_trust"
    ENROLLMENT_SPAKE2PLUS = "enrollment_spake2plus"


class PrincipalState(str, Enum):
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    REVOKED = "revoked"
    EXPIRED = "expired"
    IDENTITY_CONFLICT = "identity_conflict"
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
    role_constraints: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    state: PrincipalState
    mode: AuthenticationMode
    trust_domain_id: str | None
    node_id: str | None
    credential_id: str | None
    identity_key_id: str | None
    credential_format: str | None
    role_constraints: FrozenSet[str]


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
        raise SecurityAdmissionError(
            "security.downgrade_forbidden" if hardened else "security.credential_invalid"
        )
    if claimed_mode is not evidence.mode:
        raise SecurityAdmissionError("security.downgrade_forbidden")
    if claimed_mode is not AuthenticationMode.AURORA_TRUST:
        if hardened:
            raise SecurityAdmissionError("security.downgrade_forbidden")
        return AuthenticatedPrincipal(
            PrincipalState.UNAUTHENTICATED, claimed_mode, None, None, None, None, None, frozenset()
        )
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
    )


def effective_permissions(
    credential_constraints: set[str], local_policy: set[str], capabilities: set[str], safety_policy: set[str]
) -> frozenset[str]:
    return frozenset(credential_constraints & local_policy & capabilities & safety_policy)


def profile_limits(profile: str) -> Mapping[str, Any]:
    return load()["security"]["limits"][profile]
