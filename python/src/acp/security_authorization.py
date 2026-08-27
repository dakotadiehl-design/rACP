"""Central Aurora Trust authorization and immutable handler context."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from threading import RLock
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
    authenticated_session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role_assignment_revision: int = 0
    capability_revision: int = 0
    credential_generation: int = 0
    lifecycle_generation: int = 0
    revocation_generation: int = 0
    operator: OperatorIdentity | None = None
    operator_required: bool = False
    audit_correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(slots=True)
class AuthorizationDecision:
    allowed: bool
    permission: str | None
    effective_permissions: frozenset[str]
    policy_revision: int
    audit_correlation_id: str
    reason: str
    principal: AuthenticatedPrincipal
    safety_state: str
    authenticated_session_id: str
    operation: str
    target_scope: str | None
    role_assignment_revision: int
    capability_revision: int
    credential_generation: int
    lifecycle_generation: int
    revocation_generation: int
    _consumed: bool = field(default=False, init=False, repr=False, compare=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    def consume(
        self,
        *,
        session_id: str,
        operation: str,
        target_scope: str | None,
        policy_revision: int,
        role_assignment_revision: int,
        capability_revision: int,
        credential_generation: int,
        lifecycle_generation: int,
        revocation_generation: int,
    ) -> bool:
        """Atomically consume this decision, even when a binding is stale."""
        with self._lock:
            if self._consumed:
                return False
            self._consumed = True
            return self.allowed and (
                session_id == self.authenticated_session_id
                and operation == self.operation
                and target_scope == self.target_scope
                and policy_revision == self.policy_revision
                and role_assignment_revision == self.role_assignment_revision
                and capability_revision == self.capability_revision
                and credential_generation == self.credential_generation
                and lifecycle_generation == self.lifecycle_generation
                and revocation_generation == self.revocation_generation
            )


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


def authorize(
    operation: str,
    context: AuthorizationContext,
    *,
    target_scope: str | None = None,
    session_id: str | None = None,
) -> AuthorizationDecision:
    permission = required_permission(operation)
    effective = effective_permissions(context)
    requested_session_id = context.authenticated_session_id if session_id is None else session_id
    session_matches = requested_session_id == context.authenticated_session_id
    revisions = (
        context.policy_revision,
        context.role_assignment_revision,
        context.capability_revision,
        context.credential_generation,
        context.lifecycle_generation,
        context.revocation_generation,
    )
    bindings_bounded = (
        1 <= len(requested_session_id.encode()) <= 128
        and 1 <= len(context.audit_correlation_id.encode()) <= 128
        and 1 <= len(context.safety_state.encode()) <= 64
        and (target_scope is None or 1 <= len(target_scope.encode()) <= 256)
        and all(
            isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**64 - 1
            for value in revisions
        )
    )
    allowed = session_matches and bindings_bounded and permission is not None and permission in effective
    return AuthorizationDecision(
        allowed,
        permission,
        effective,
        context.policy_revision,
        context.audit_correlation_id,
        (
            "authorized"
            if allowed
            else "security.session_mismatch"
            if not session_matches
            else "security.binding_invalid"
            if not bindings_bounded
            else "security.permission_denied"
        ),
        context.principal,
        context.safety_state,
        context.authenticated_session_id,
        operation,
        target_scope,
        context.role_assignment_revision,
        context.capability_revision,
        context.credential_generation,
        context.lifecycle_generation,
        context.revocation_generation,
    )


@dataclass(slots=True)
class AuthorizationPolicyStore:
    permissions_by_node: dict[str, frozenset[str]] = field(default_factory=dict)
    revision: int = 1
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def replace(self, value: Mapping[str, frozenset[str]]) -> int:
        with self._lock:
            self.permissions_by_node = dict(value)
            if self.revision < 2**64 - 1:
                self.revision += 1
            return self.revision

    def permissions(self, node_id: str) -> frozenset[str]:
        with self._lock:
            return self.permissions_by_node.get(node_id, frozenset())

    def authorize(
        self,
        operation: str,
        context: AuthorizationContext,
        *,
        target_scope: str | None = None,
        session_id: str | None = None,
    ) -> AuthorizationDecision:
        with self._lock:
            identity = device_identity(context.principal)
            current = replace(
                context,
                local_policy_permissions=self.permissions_by_node.get(identity.node_id, frozenset()),
                policy_revision=self.revision,
            )
            return authorize(operation, current, target_scope=target_scope, session_id=session_id)

    def authorize_and_consume(
        self,
        operation: str,
        context: AuthorizationContext,
        *,
        session_id: str,
        target_scope: str | None = None,
    ) -> AuthorizationDecision | None:
        """Authorize and consume while preventing an interleaved policy update."""
        with self._lock:
            decision = self.authorize(
                operation, context, target_scope=target_scope, session_id=session_id
            )
            if not decision.consume(
                session_id=session_id,
                operation=operation,
                target_scope=target_scope,
                policy_revision=self.revision,
                role_assignment_revision=context.role_assignment_revision,
                capability_revision=context.capability_revision,
                credential_generation=context.credential_generation,
                lifecycle_generation=context.lifecycle_generation,
                revocation_generation=context.revocation_generation,
            ):
                return None
            return decision

    def revalidation_action(
        self, previous: AuthorizationDecision, current: AuthorizationDecision
    ) -> SessionRevalidationAction:
        if previous.allowed and (
            not current.allowed
            or previous.principal != current.principal
            or previous.authenticated_session_id != current.authenticated_session_id
            or previous.operation != current.operation
            or previous.target_scope != current.target_scope
            or previous.permission != current.permission
            or previous.effective_permissions != current.effective_permissions
            or previous.policy_revision != current.policy_revision
            or previous.role_assignment_revision != current.role_assignment_revision
            or previous.capability_revision != current.capability_revision
            or previous.credential_generation != current.credential_generation
            or previous.lifecycle_generation != current.lifecycle_generation
            or previous.revocation_generation != current.revocation_generation
            or previous.safety_state != current.safety_state
        ):
            return SessionRevalidationAction.TERMINATE
        return SessionRevalidationAction.RETAIN


Result = TypeVar("Result")


def invoke_sensitive(
    operation: str,
    context: AuthorizationContext,
    handler: Callable[[AuthorizationDecision, Any], Result],
    payload: Any,
    *,
    session_id: str,
    target_scope: str | None = None,
) -> Result:
    decision = authorize(operation, context, target_scope=target_scope, session_id=session_id)
    if not decision.consume(
        session_id=session_id,
        operation=operation,
        target_scope=target_scope,
        policy_revision=context.policy_revision,
        role_assignment_revision=context.role_assignment_revision,
        capability_revision=context.capability_revision,
        credential_generation=context.credential_generation,
        lifecycle_generation=context.lifecycle_generation,
        revocation_generation=context.revocation_generation,
    ):
        raise PermissionError(decision.reason)
    return handler(decision, payload)


@dataclass(slots=True)
class RemoteAuthorityHost:
    """Authenticated production boundary around an existing Remote safety core."""

    invoke_core: Callable[[AuthorizationDecision, Mapping[str, Any]], Any]
    policy_store: AuthorizationPolicyStore
    allow_unauthenticated_view: bool = False

    def invoke(
        self,
        operation: str,
        context: AuthorizationContext,
        payload: Mapping[str, Any],
        *,
        session_id: str,
        target_scope: str | None = None,
    ) -> Any:
        decision = self.policy_store.authorize_and_consume(
            operation, context, session_id=session_id, target_scope=target_scope
        )
        if decision is None:
            raise PermissionError("security.permission_denied")
        return self.invoke_core(decision, payload)

    def may_view(self, context: AuthorizationContext | None) -> bool:
        if context is None:
            return self.allow_unauthenticated_view
        try:
            device_identity(context.principal)
        except PermissionError:
            return self.allow_unauthenticated_view
        return True
