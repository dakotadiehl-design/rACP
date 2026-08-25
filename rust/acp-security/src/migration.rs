#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStage {
    Observe,
    Enroll,
    PreferAuthenticated,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationDecision {
    pub connection_allowed: bool,
    pub sensitive_control_allowed: bool,
    pub prefer_authenticated: bool,
    pub reason: &'static str,
}

pub fn migration_decision(
    stage: MigrationStage,
    authenticated: bool,
    authorized: bool,
    explicitly_allow_trusted_lan: bool,
    stronger_authentication_failed: bool,
) -> MigrationDecision {
    let prefer = matches!(
        stage,
        MigrationStage::PreferAuthenticated | MigrationStage::Enforce
    );
    if authenticated {
        return MigrationDecision {
            connection_allowed: true,
            sensitive_control_allowed: authorized,
            prefer_authenticated: prefer,
            reason: if authorized {
                "authenticated_authorized"
            } else {
                "security.permission_denied"
            },
        };
    }
    if stronger_authentication_failed || stage == MigrationStage::Enforce {
        return MigrationDecision {
            connection_allowed: false,
            sensitive_control_allowed: false,
            prefer_authenticated: prefer,
            reason: "security.downgrade_forbidden",
        };
    }
    MigrationDecision {
        connection_allowed: explicitly_allow_trusted_lan,
        sensitive_control_allowed: false,
        prefer_authenticated: prefer,
        reason: if explicitly_allow_trusted_lan {
            "trusted_lan_view_only"
        } else {
            "security.permission_denied"
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_never_grants_unauthenticated_control_or_downgrade() {
        for stage in [
            MigrationStage::Observe,
            MigrationStage::Enroll,
            MigrationStage::PreferAuthenticated,
            MigrationStage::Enforce,
        ] {
            let decision = migration_decision(stage, false, false, true, false);
            assert!(!decision.sensitive_control_allowed);
        }
        assert!(
            !migration_decision(MigrationStage::Observe, false, false, true, true)
                .connection_allowed
        );
        assert!(
            !migration_decision(MigrationStage::Enforce, false, false, true, false)
                .connection_allowed
        );
        assert!(
            !migration_decision(MigrationStage::Enforce, true, false, false, false)
                .sensitive_control_allowed
        );
    }
}
