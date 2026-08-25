"""Central Aurora Trust authorization and immutable handler context."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

from .registry import lookup
from .security import AuthenticatedPrincipal
from .security_models import PrincipalState

SENSITIVE_OPERATION_PERMISSIONS = {
    "remote.control.invoke": "remote.control.invoke",
    "remote.macro.invoke": "remote.macro.invoke",
    "remote.navigation.invoke": "remote.navigation.invoke",
}


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    trust_domain_id: str
    node_id: str
    credential_id: str
    identity_key_id: str


@dataclass(frozen=True, slots=True)
class OperatorIdentity:
    operator_id: str
    authenticated: bool
    permissions: frozenset[str]


class SessionRevalidationAction(str, Enum):
    RETAIN = "retain"
    TERMINATE = "terminate"


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    principal: AuthenticatedPrincipal
    credential_permissions: frozenset[str]
    local_policy_permissions: frozenset[str]
    capability_permissions: frozenset[str]
    safety_permissions: frozenset[str]
    policy_revision: int
    safety_state: str
    operator: OperatorIdentity | None = None
    operator_required: bool = False
    audit_correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    permission: str | None
    effective_permissions: frozenset[str]
    policy_revision: int
    audit_correlation_id: str
    reason: str
    principal: AuthenticatedPrincipal
    safety_state: str


def device_identity(principal: AuthenticatedPrincipal) -> DeviceIdentity:
    values = (principal.trust_domain_id, principal.node_id, principal.credential_id, principal.identity_key_id)
    if principal.state is not PrincipalState.AUTHENTICATED or any(value is None for value in values):
        raise PermissionError("security.permission_denied")
    trust_domain_id, node_id, credential_id, identity_key_id = values
    assert trust_domain_id is not None and node_id is not None
    assert credential_id is not None and identity_key_id is not None
    return DeviceIdentity(trust_domain_id, node_id, credential_id, identity_key_id)


def effective_permissions(context: AuthorizationContext) -> frozenset[str]:
    try:
        device_identity(context.principal)
    except PermissionError:
        return frozenset()
    effective = (
        context.credential_permissions
        & context.local_policy_permissions
        & context.capability_permissions
        & context.safety_permissions
    )
    if context.operator_required:
        if context.operator is None or not context.operator.authenticated:
            return frozenset()
        effective &= context.operator.permissions
    return frozenset(effective)


def required_permission(operation: str) -> str | None:
    if operation in SENSITIVE_OPERATION_PERMISSIONS:
        return SENSITIVE_OPERATION_PERMISSIONS[operation]
    row = lookup(operation)
    return None if row is None else row.get("authorization_permission")


def authorize(operation: str, context: AuthorizationContext) -> AuthorizationDecision:
    permission = required_permission(operation)
    effective = effective_permissions(context)
    allowed = permission is not None and permission in effective
    return AuthorizationDecision(
        allowed,
        permission,
        effective,
        context.policy_revision,
        context.audit_correlation_id,
        "authorized" if allowed else "security.permission_denied",
        context.principal,
        context.safety_state,
    )


@dataclass(slots=True)
class AuthorizationPolicyStore:
    permissions_by_node: dict[str, frozenset[str]] = field(default_factory=dict)
    revision: int = 1

    def replace(self, value: Mapping[str, frozenset[str]]) -> int:
        self.permissions_by_node = dict(value)
        self.revision += 1
        return self.revision

    def permissions(self, node_id: str) -> frozenset[str]:
        return self.permissions_by_node.get(node_id, frozenset())

    def revalidation_action(
        self, previous: AuthorizationDecision, current: AuthorizationDecision
    ) -> SessionRevalidationAction:
        if previous.allowed and not current.allowed:
            return SessionRevalidationAction.TERMINATE
        return SessionRevalidationAction.RETAIN


Result = TypeVar("Result")


def invoke_sensitive(
    operation: str,
    context: AuthorizationContext,
    handler: Callable[[AuthorizationDecision, Any], Result],
    payload: Any,
) -> Result:
    decision = authorize(operation, context)
    if not decision.allowed:
        raise PermissionError(decision.reason)
    return handler(decision, payload)


@dataclass(slots=True)
class RemoteAuthorityHost:
    """Authenticated production boundary around an existing Remote safety core."""

    invoke_core: Callable[[AuthorizationDecision, Mapping[str, Any]], Any]
    allow_unauthenticated_view: bool = False

    def invoke(self, operation: str, context: AuthorizationContext, payload: Mapping[str, Any]) -> Any:
        return invoke_sensitive(operation, context, self.invoke_core, payload)

    def may_view(self, context: AuthorizationContext | None) -> bool:
        if context is None:
            return self.allow_unauthenticated_view
        try:
            device_identity(context.principal)
        except PermissionError:
            return self.allow_unauthenticated_view
        return True
