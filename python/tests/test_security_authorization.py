from __future__ import annotations

from dataclasses import replace

import pytest
from security_testkit import unsafe_authenticated_principal_for_testing

from acp.security import AuthenticatedPrincipal
from acp.security_authorization import (
    AuthorizationContext,
    AuthorizationPolicyStore,
    OperatorIdentity,
    RemoteAuthorityHost,
    SessionRevalidationAction,
    authorize,
    device_identity,
)
from acp.security_models import AuthenticationMode, PrincipalState, SecurityProfile

PERMISSION = "security.credential.revoke"


def principal(state: PrincipalState = PrincipalState.AUTHENTICATED) -> AuthenticatedPrincipal:
    return unsafe_authenticated_principal_for_testing(
        state=state,
        mode=AuthenticationMode.AURORA_TRUST,
        trust_domain_id="domain",
        node_id="node",
        credential_id="credential",
        identity_key_id="key",
        credential_format="x509_der",
        role_constraints=frozenset({"self-claimed-admin"}),
        profile=SecurityProfile.FULL,
    )


def context(*, allowed: bool = True, state: PrincipalState = PrincipalState.AUTHENTICATED) -> AuthorizationContext:
    permissions = frozenset({PERMISSION}) if allowed else frozenset()
    return AuthorizationContext(principal(state), permissions, permissions, permissions, permissions, 7, "armed")


def test_sensitive_catalog_and_intersection_fail_closed() -> None:
    decision = authorize("security.credential.revoke", context())
    assert decision.allowed and decision.effective_permissions == {PERMISSION}
    for field in ("credential_permissions", "local_policy_permissions", "capability_permissions", "safety_permissions"):
        assert not authorize("security.credential.revoke", replace(context(), **{field: frozenset()})).allowed
    assert not authorize("unknown.operation", context()).allowed
    for state in (PrincipalState.UNAUTHENTICATED, PrincipalState.REVOKED, PrincipalState.EXPIRED):
        assert not authorize("security.credential.revoke", context(state=state)).allowed


def test_operator_assignment_is_separate_from_device_identity() -> None:
    original = context()
    before = device_identity(original.principal)
    reassigned = replace(original, operator=OperatorIdentity("operator-b", True, frozenset({PERMISSION})))
    assert device_identity(reassigned.principal) == before
    required = replace(reassigned, operator_required=True)
    assert authorize("security.credential.revoke", required).allowed
    assert not authorize("security.credential.revoke", replace(required, operator=None)).allowed


def test_policy_removal_terminates_and_remote_host_rejects_claims() -> None:
    cached_assets = {"layout": b"cached-layout"}
    store = AuthorizationPolicyStore({"node": frozenset({PERMISSION})})
    previous = authorize("security.credential.revoke", context())
    store.replace({"node": frozenset()})
    current = authorize(
        "security.credential.revoke",
        replace(context(), local_policy_permissions=store.permissions("node"), policy_revision=store.revision),
    )
    assert store.revalidation_action(previous, current) is SessionRevalidationAction.TERMINATE
    assert cached_assets == {"layout": b"cached-layout"}
    host = RemoteAuthorityHost(
        lambda decision, payload: (decision.principal.node_id, payload["value"]),
        AuthorizationPolicyStore({"node": frozenset({PERMISSION})}),
    )
    allowed_context = context()
    assert host.invoke(
        "security.credential.revoke",
        allowed_context,
        {"value": 1},
        session_id=allowed_context.authenticated_session_id,
    ) == ("node", 1)
    with pytest.raises(PermissionError):
        denied_context = context(allowed=False)
        host.invoke(
            "security.credential.revoke",
            denied_context,
            {"claimed_node_id": "node", "value": 1},
            session_id=denied_context.authenticated_session_id,
        )


def test_remote_host_rebinds_stale_context_to_current_policy() -> None:
    store = AuthorizationPolicyStore({"node": frozenset({PERMISSION})})
    host = RemoteAuthorityHost(lambda decision, payload: payload, store)
    stale = context()
    store.replace({"node": frozenset()})
    with pytest.raises(PermissionError):
        host.invoke(
            "security.credential.revoke", stale, {}, session_id=stale.authenticated_session_id
        )


def test_remote_host_rejects_authenticated_session_substitution() -> None:
    current = replace(context(), authenticated_session_id="authenticated-session")
    host = RemoteAuthorityHost(
        lambda decision, payload: payload,
        AuthorizationPolicyStore({"node": frozenset({PERMISSION})}),
    )
    with pytest.raises(PermissionError):
        host.invoke(PERMISSION, current, {}, session_id="attacker-session")


def consume(decision, current: AuthorizationContext, **changes: object) -> bool:
    bindings: dict[str, object] = {
        "session_id": current.authenticated_session_id,
        "operation": PERMISSION,
        "target_scope": "device-a",
        "policy_revision": current.policy_revision,
        "role_assignment_revision": current.role_assignment_revision,
        "capability_revision": current.capability_revision,
        "credential_generation": current.credential_generation,
        "lifecycle_generation": current.lifecycle_generation,
        "revocation_generation": current.revocation_generation,
    }
    bindings.update(changes)
    return decision.consume(**bindings)


@pytest.mark.parametrize(
    ("binding", "stale_value"),
    [
        ("session_id", "replacement-session"),
        ("policy_revision", 8),
        ("role_assignment_revision", 3),
        ("capability_revision", 4),
        ("credential_generation", 5),
        ("lifecycle_generation", 6),
        ("revocation_generation", 7),
    ],
)
def test_stale_authorization_cannot_survive_security_context_change(
    binding: str, stale_value: object
) -> None:
    current = replace(
        context(),
        authenticated_session_id="authenticated-session",
        role_assignment_revision=2,
        capability_revision=3,
        credential_generation=4,
        lifecycle_generation=5,
        revocation_generation=6,
    )
    decision = authorize(PERMISSION, current, target_scope="device-a")
    assert decision.allowed
    assert not consume(decision, current, **{binding: stale_value})
    # A failed stale use consumes the capability; correcting the binding cannot replay it.
    assert not consume(decision, current)


def test_authorization_is_operation_target_bound_and_one_shot() -> None:
    current = replace(context(), authenticated_session_id="authenticated-session")
    wrong_target = authorize(PERMISSION, current, target_scope="device-a")
    assert not consume(wrong_target, current, target_scope="device-b")

    wrong_operation = authorize(PERMISSION, current, target_scope="device-a")
    assert not consume(wrong_operation, current, operation="security.credential.renew")

    exact = authorize(PERMISSION, current, target_scope="device-a")
    assert consume(exact, current)
    assert not consume(exact, current)


def test_policy_store_update_invalidates_outstanding_decision() -> None:
    current = replace(context(), authenticated_session_id="authenticated-session")
    store = AuthorizationPolicyStore({"node": frozenset({PERMISSION})})
    decision = store.authorize(PERMISSION, current, target_scope="device-a")
    new_revision = store.replace({"node": frozenset({PERMISSION})})
    assert decision.allowed
    assert not consume(decision, current, policy_revision=new_revision)


def test_revalidation_terminates_on_allowed_security_binding_change() -> None:
    current = replace(
        context(),
        authenticated_session_id="authenticated-session",
        role_assignment_revision=2,
        capability_revision=3,
        credential_generation=4,
        lifecycle_generation=5,
        revocation_generation=6,
    )
    store = AuthorizationPolicyStore()
    for change in (
        {"authenticated_session_id": "replacement-session"},
        {"policy_revision": 8},
        {"role_assignment_revision": 3},
        {"capability_revision": 4},
        {"credential_generation": 5},
        {"lifecycle_generation": 6},
        {"revocation_generation": 7},
    ):
        previous = authorize(PERMISSION, current, target_scope="device-a")
        changed = authorize(PERMISSION, replace(current, **change), target_scope="device-a")
        assert previous.allowed and changed.allowed
        assert store.revalidation_action(previous, changed) is SessionRevalidationAction.TERMINATE
