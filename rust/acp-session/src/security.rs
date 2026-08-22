use std::collections::{HashMap, HashSet};

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalState {
    Unauthenticated,
    Authenticated,
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

    #[test]
    fn claimed_aurora_trust_without_evidence_fails_closed() {
        let auth = HashMap::from([("mode".into(), "aurora_trust".into())]);
        assert_eq!(
            bind_hello_auth("node", &auth, None, true),
            Err("security.downgrade_forbidden")
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
