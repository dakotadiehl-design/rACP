use std::collections::{HashMap, HashSet};

pub fn authorize_operation(
    operation: &str,
    context: &acp_security::AuthorizationContext,
) -> acp_security::AuthorizationDecision {
    let explicit = match operation {
        "remote.control.invoke" | "remote.macro.invoke" | "remote.navigation.invoke" => {
            Some(operation)
        }
        _ => crate::registry::lookup(operation)
            .and_then(|row| row.authorization_permission.as_deref()),
    };
    acp_security::authorize(explicit, context)
}

const CONSTANTS: &str = include_str!("../../../schema/constants.json");

pub fn security_catalog() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(CONSTANTS).expect("canonical ACP constants")
        ["security"]
        .clone()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMode {
    TrustedLan,
    Tls,
    AuroraTrust,
    EnrollmentSpake2Plus,
}

impl AuthenticationMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "trusted_lan" => Some(Self::TrustedLan),
            "tls" => Some(Self::Tls),
            "aurora_trust" => Some(Self::AuroraTrust),
            "enrollment_spake2plus" => Some(Self::EnrollmentSpake2Plus),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportEvidence {
    pub mode: AuthenticationMode,
    pub trust_domain_id: Option<String>,
    pub node_id: Option<String>,
    pub credential_id: Option<String>,
    pub identity_key_id: Option<String>,
    pub credential_format: Option<String>,
    pub channel_binding: Option<String>,
    pub role_constraints: HashSet<String>,
    pub credential_state: CredentialState,
    pub channel_binding_verified: bool,
    pub zero_rtt_used: bool,
    pub resumption_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalState {
    Unauthenticated,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    Active,
    Expired,
    Revoked,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub state: PrincipalState,
    pub mode: AuthenticationMode,
    pub trust_domain_id: Option<String>,
    pub node_id: Option<String>,
    pub credential_id: Option<String>,
    pub identity_key_id: Option<String>,
    pub credential_format: Option<String>,
    pub role_constraints: HashSet<String>,
}

pub fn bind_hello_auth(
    claimed_node_id: &str,
    auth: &HashMap<String, String>,
    evidence: Option<&TransportEvidence>,
    hardened: bool,
    security_capabilities: &[(&str, &str)],
) -> Result<AuthenticatedPrincipal, &'static str> {
    let mode = auth
        .get("mode")
        .and_then(|v| AuthenticationMode::parse(v))
        .ok_or("security.credential_invalid")?;
    let Some(evidence) = evidence else {
        if mode == AuthenticationMode::TrustedLan && !hardened {
            return Ok(unauthenticated(mode));
        }
        return Err(if hardened {
            "security.downgrade_forbidden"
        } else {
            "security.credential_invalid"
        });
    };
    if mode != evidence.mode {
        return Err("security.downgrade_forbidden");
    }
    if mode != AuthenticationMode::AuroraTrust {
        return if hardened {
            Err("security.downgrade_forbidden")
        } else {
            Ok(unauthenticated(mode))
        };
    }
    if evidence.zero_rtt_used || evidence.resumption_used {
        return Err("security.downgrade_forbidden");
    }
    match evidence.credential_state {
        CredentialState::Active => {}
        CredentialState::Revoked => return Err("security.credential_revoked"),
        CredentialState::Expired => return Err("security.credential_expired"),
        CredentialState::Invalid => return Err("security.credential_invalid"),
    }
    if !evidence.channel_binding_verified {
        return Err("security.authentication_failed");
    }
    let ids: HashSet<&str> = security_capabilities.iter().map(|(id, _)| *id).collect();
    if ids.len() != security_capabilities.len() {
        return Err("security.credential_invalid");
    }
    if !security_capabilities
        .iter()
        .any(|(id, version)| *id == "aurora-trust" && *version == "1.0")
    {
        return Err("security.downgrade_forbidden");
    }
    if evidence.node_id.is_none()
        || evidence.trust_domain_id.is_none()
        || evidence.credential_id.is_none()
        || evidence.identity_key_id.is_none()
        || evidence.channel_binding.is_none()
    {
        return Err("security.credential_invalid");
    }
    if evidence.node_id.as_deref() != Some(claimed_node_id) {
        return Err("security.identity_mismatch");
    }
    if auth.get("trust_domain_id") != evidence.trust_domain_id.as_ref() {
        return Err("security.trust_domain_mismatch");
    }
    for (name, expected) in [
        ("credential_id", &evidence.credential_id),
        ("identity_key_id", &evidence.identity_key_id),
        ("channel_binding", &evidence.channel_binding),
    ] {
        if auth.get(name) != expected.as_ref() {
            return Err("security.identity_mismatch");
        }
    }
    Ok(AuthenticatedPrincipal {
        state: PrincipalState::Authenticated,
        mode,
        trust_domain_id: evidence.trust_domain_id.clone(),
        node_id: evidence.node_id.clone(),
        credential_id: evidence.credential_id.clone(),
        identity_key_id: evidence.identity_key_id.clone(),
        credential_format: evidence.credential_format.clone(),
        role_constraints: evidence.role_constraints.clone(),
    })
}

fn unauthenticated(mode: AuthenticationMode) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        state: PrincipalState::Unauthenticated,
        mode,
        trust_domain_id: None,
        node_id: None,
        credential_id: None,
        identity_key_id: None,
        credential_format: None,
        role_constraints: HashSet::new(),
    }
}

pub fn effective_permissions(
    credential: &HashSet<String>,
    local: &HashSet<String>,
    capabilities: &HashSet<String>,
    safety: &HashSet<String>,
) -> HashSet<String> {
    credential
        .intersection(local)
        .filter(|p| capabilities.contains(*p) && safety.contains(*p))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_auth() -> HashMap<String, String> {
        HashMap::from([
            ("mode".into(), "aurora_trust".into()),
            ("trust_domain_id".into(), "domain".into()),
            ("credential_id".into(), "credential".into()),
            ("identity_key_id".into(), "key".into()),
            ("channel_binding".into(), "binding".into()),
        ])
    }

    fn valid_evidence() -> TransportEvidence {
        TransportEvidence {
            mode: AuthenticationMode::AuroraTrust,
            trust_domain_id: Some("domain".into()),
            node_id: Some("node".into()),
            credential_id: Some("credential".into()),
            identity_key_id: Some("key".into()),
            credential_format: Some("x509_der".into()),
            channel_binding: Some("binding".into()),
            role_constraints: HashSet::new(),
            credential_state: CredentialState::Active,
            channel_binding_verified: true,
            zero_rtt_used: false,
            resumption_used: false,
        }
    }

    #[test]
    fn claimed_aurora_trust_without_evidence_fails_closed() {
        let auth = HashMap::from([("mode".into(), "aurora_trust".into())]);
        assert_eq!(
            bind_hello_auth("node", &auth, None, true, &[]),
            Err("security.downgrade_forbidden")
        );
    }

    #[test]
    fn verified_active_transport_and_frozen_capability_are_required() {
        let auth = valid_auth();
        let valid = valid_evidence();
        assert!(bind_hello_auth(
            "node",
            &auth,
            Some(&valid),
            true,
            &[("aurora-trust", "1.0")]
        )
        .is_ok());

        let cases = [
            (
                CredentialState::Revoked,
                false,
                false,
                false,
                "security.credential_revoked",
            ),
            (
                CredentialState::Expired,
                false,
                false,
                false,
                "security.credential_expired",
            ),
            (
                CredentialState::Active,
                true,
                false,
                false,
                "security.authentication_failed",
            ),
            (
                CredentialState::Active,
                false,
                true,
                false,
                "security.downgrade_forbidden",
            ),
            (
                CredentialState::Active,
                false,
                false,
                true,
                "security.downgrade_forbidden",
            ),
        ];
        for (state, unverified, zero_rtt, resumed, expected) in cases {
            let mut evidence = valid.clone();
            evidence.credential_state = state;
            evidence.channel_binding_verified = !unverified;
            evidence.zero_rtt_used = zero_rtt;
            evidence.resumption_used = resumed;
            assert_eq!(
                bind_hello_auth(
                    "node",
                    &auth,
                    Some(&evidence),
                    true,
                    &[("aurora-trust", "1.0")]
                ),
                Err(expected)
            );
        }
        assert_eq!(
            bind_hello_auth("node", &auth, Some(&valid), true, &[]),
            Err("security.downgrade_forbidden")
        );
        assert_eq!(
            bind_hello_auth(
                "node",
                &auth,
                Some(&valid),
                true,
                &[("aurora-trust", "1.0"), ("aurora-trust", "1.0")]
            ),
            Err("security.credential_invalid")
        );
    }

    #[test]
    fn permissions_are_an_intersection() {
        let all = HashSet::from(["observe".to_string(), "control".to_string()]);
        let observe = HashSet::from(["observe".to_string()]);
        assert_eq!(effective_permissions(&all, &all, &all, &observe), observe);
    }

    #[test]
    fn frozen_security_catalog_is_consumed() {
        let catalog = security_catalog();
        assert_eq!(catalog["version"], "1.0");
        assert_eq!(catalog["limits"]["full"]["concurrent_attempts"], 2);
        assert_eq!(
            catalog["limits"]["lightweight"]["max_credential_bytes"],
            2048
        );
        assert_eq!(catalog["capabilities"]["security.enrollment"], "1.0");
        assert!(catalog["errors"]["security.downgrade_forbidden"].is_object());
    }
}
