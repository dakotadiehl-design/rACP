from __future__ import annotations

from dataclasses import replace

import pytest

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
from acp.testkit import unsafe_authenticated_principal_for_testing

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
    assert host.invoke("security.credential.revoke", context(), {"value": 1}) == ("node", 1)
    with pytest.raises(PermissionError):
        host.invoke("security.credential.revoke", context(allowed=False), {"claimed_node_id": "node", "value": 1})


def test_remote_host_rebinds_stale_context_to_current_policy() -> None:
    store = AuthorizationPolicyStore({"node": frozenset({PERMISSION})})
    host = RemoteAuthorityHost(lambda decision, payload: payload, store)
    stale = context()
    store.replace({"node": frozenset()})
    with pytest.raises(PermissionError):
        host.invoke("security.credential.revoke", stale, {})
