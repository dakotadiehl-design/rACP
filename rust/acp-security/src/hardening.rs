#[cfg(test)]
mod tests {
    use crate::*;
    use std::collections::HashSet;

    #[test]
    fn malformed_lightweight_frames_never_panic() {
        let mut state = 0xA0Cu64;
        for length in 0..4096 {
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            let result =
                parse_lightweight_preface(&bytes, |_| Err(SecurityErrorCode::CredentialInvalid));
            assert!(result.is_err());
        }
    }

    #[test]
    fn authorization_intersection_exhaustive_boolean_matrix() {
        let permission = "security.credential.revoke".to_owned();
        let principal = AuthenticatedPrincipal {
            state: PrincipalState::Authenticated,
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
            role_constraints: HashSet::new(),
        };
        for mask in 0u8..16 {
            let set = |bit| {
                if mask & bit != 0 {
                    HashSet::from([permission.clone()])
                } else {
                    HashSet::new()
                }
            };
            let context = AuthorizationContext {
                principal: principal.clone(),
                credential_permissions: set(1),
                local_policy_permissions: set(2),
                capability_permissions: set(4),
                safety_permissions: set(8),
                policy_revision: 1,
                safety_state: "safe".into(),
                audit_correlation_id: "audit".into(),
                operator: None,
                operator_required: false,
            };
            assert_eq!(authorize(Some(&permission), &context).allowed, mask == 15);
        }
    }
}
