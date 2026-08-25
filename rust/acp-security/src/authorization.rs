use crate::{
    AuthenticatedPrincipal, CredentialId, IdentityKeyId, PrincipalState, SecurityNodeId,
    TrustDomainId,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub trust_domain_id: TrustDomainId,
    pub node_id: SecurityNodeId,
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorIdentity {
    pub operator_id: String,
    pub authenticated: bool,
    pub permissions: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    pub principal: AuthenticatedPrincipal,
    pub credential_permissions: HashSet<String>,
    pub local_policy_permissions: HashSet<String>,
    pub capability_permissions: HashSet<String>,
    pub safety_permissions: HashSet<String>,
    pub policy_revision: u64,
    pub safety_state: String,
    pub audit_correlation_id: String,
    pub operator: Option<OperatorIdentity>,
    pub operator_required: bool,
}

#[derive(Debug, Clone)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub permission: Option<String>,
    pub effective_permissions: HashSet<String>,
    pub policy_revision: u64,
    pub audit_correlation_id: String,
    pub reason: &'static str,
    pub principal: AuthenticatedPrincipal,
    pub safety_state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRevalidationAction {
    Retain,
    Terminate,
}

pub fn device_identity(principal: &AuthenticatedPrincipal) -> Option<DeviceIdentity> {
    if principal.state != PrincipalState::Authenticated {
        return None;
    }
    Some(DeviceIdentity {
        trust_domain_id: principal.trust_domain_id.clone()?,
        node_id: principal.node_id.clone()?,
        credential_id: principal.credential_id.clone()?,
        identity_key_id: principal.identity_key_id.clone()?,
    })
}

pub fn effective_permissions(context: &AuthorizationContext) -> HashSet<String> {
    if device_identity(&context.principal).is_none() {
        return HashSet::new();
    }
    let mut result: HashSet<String> = context
        .credential_permissions
        .intersection(&context.local_policy_permissions)
        .filter(|permission| {
            context.capability_permissions.contains(*permission)
                && context.safety_permissions.contains(*permission)
        })
        .cloned()
        .collect();
    if context.operator_required {
        let Some(operator) = context
            .operator
            .as_ref()
            .filter(|value| value.authenticated)
        else {
            return HashSet::new();
        };
        result.retain(|permission| operator.permissions.contains(permission));
    }
    result
}

/// The caller must resolve the operation through the canonical registry. `None`
/// is an unknown or non-sensitive operation and is denied by this boundary.
pub fn authorize(
    required_permission: Option<&str>,
    context: &AuthorizationContext,
) -> AuthorizationDecision {
    let effective = effective_permissions(context);
    let allowed = required_permission.is_some_and(|permission| effective.contains(permission));
    AuthorizationDecision {
        allowed,
        permission: required_permission.map(str::to_owned),
        effective_permissions: effective,
        policy_revision: context.policy_revision,
        audit_correlation_id: context.audit_correlation_id.clone(),
        reason: if allowed {
            "authorized"
        } else {
            "security.permission_denied"
        },
        principal: context.principal.clone(),
        safety_state: context.safety_state.clone(),
    }
}

#[derive(Debug)]
pub struct AuthorizationPolicyStore {
    permissions_by_node: HashMap<String, HashSet<String>>,
    revision: u64,
}

impl Default for AuthorizationPolicyStore {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}

impl AuthorizationPolicyStore {
    pub fn new(permissions_by_node: HashMap<String, HashSet<String>>) -> Self {
        Self {
            permissions_by_node,
            revision: 1,
        }
    }
    pub fn replace(&mut self, value: HashMap<String, HashSet<String>>) -> u64 {
        self.permissions_by_node = value;
        self.revision = self.revision.saturating_add(1);
        self.revision
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn permissions(&self, node_id: &str) -> HashSet<String> {
        self.permissions_by_node
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }
    pub fn revalidation_action(
        previous: &AuthorizationDecision,
        current: &AuthorizationDecision,
    ) -> SessionRevalidationAction {
        if previous.allowed && !current.allowed {
            SessionRevalidationAction::Terminate
        } else {
            SessionRevalidationAction::Retain
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthenticationMode, CredentialFormat, SecurityProfile};

    const PERMISSION: &str = "security.credential.revoke";

    fn set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn principal(state: PrincipalState) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            state,
            mode: AuthenticationMode::AuroraTrust,
            profile: Some(SecurityProfile::Full),
            trust_domain_id: Some(
                TrustDomainId::parse("40516273-8495-4a6b-8a3b-4c5d6e7f8091").unwrap(),
            ),
            node_id: Some(SecurityNodeId::parse("00112233-4455-4677-8899-aabbccddeeff").unwrap()),
            credential_id: Some(
                CredentialId::parse(format!("sha256:{}", "11".repeat(32))).unwrap(),
            ),
            identity_key_id: Some(
                IdentityKeyId::parse(format!("sha256:{}", "22".repeat(32))).unwrap(),
            ),
            credential_format: Some(CredentialFormat::X509Der),
            role_constraints: set(&["self-claimed-admin"]),
        }
    }

    fn context() -> AuthorizationContext {
        AuthorizationContext {
            principal: principal(PrincipalState::Authenticated),
            credential_permissions: set(&[PERMISSION]),
            local_policy_permissions: set(&[PERMISSION]),
            capability_permissions: set(&[PERMISSION]),
            safety_permissions: set(&[PERMISSION]),
            policy_revision: 7,
            safety_state: "armed".into(),
            audit_correlation_id: "audit-1".into(),
            operator: None,
            operator_required: false,
        }
    }

    #[test]
    fn authorization_intersects_every_authority_and_denies_unknown() {
        assert!(authorize(Some(PERMISSION), &context()).allowed);
        assert!(!authorize(None, &context()).allowed);
        let mut denied = context();
        denied.safety_permissions.clear();
        assert!(!authorize(Some(PERMISSION), &denied).allowed);
        denied = context();
        denied.principal.state = PrincipalState::Revoked;
        assert!(!authorize(Some(PERMISSION), &denied).allowed);
    }

    #[test]
    fn operator_assignment_does_not_mutate_device_identity() {
        let mut value = context();
        let before = device_identity(&value.principal).unwrap();
        value.operator_required = true;
        value.operator = Some(OperatorIdentity {
            operator_id: "operator-b".into(),
            authenticated: true,
            permissions: set(&[PERMISSION]),
        });
        assert!(authorize(Some(PERMISSION), &value).allowed);
        assert_eq!(device_identity(&value.principal).unwrap(), before);
        value.operator = None;
        assert!(!authorize(Some(PERMISSION), &value).allowed);
    }

    #[test]
    fn policy_removal_terminates_authorized_session() {
        let previous = authorize(Some(PERMISSION), &context());
        let mut store = AuthorizationPolicyStore::new(HashMap::from([(
            "00112233-4455-4677-8899-aabbccddeeff".into(),
            set(&[PERMISSION]),
        )]));
        store.replace(HashMap::new());
        let mut current_context = context();
        current_context.local_policy_permissions =
            store.permissions("00112233-4455-4677-8899-aabbccddeeff");
        current_context.policy_revision = store.revision();
        let current = authorize(Some(PERMISSION), &current_context);
        assert_eq!(
            AuthorizationPolicyStore::revalidation_action(&previous, &current),
            SessionRevalidationAction::Terminate
        );
    }
}
