public enum ACPMigrationStage: String, Codable, Sendable, CaseIterable {
    case observe, enroll
    case preferAuthenticated = "prefer_authenticated"
    case enforce
}

public struct ACPMigrationDecision: Sendable, Equatable {
    public let connectionAllowed, sensitiveControlAllowed, preferAuthenticated: Bool
    public let reason: String
}

public enum ACPMigrationSecurity {
    public static func decide(
        stage: ACPMigrationStage, authenticated: Bool, authorized: Bool = false, explicitlyAllowTrustedLAN: Bool,
        strongerAuthenticationFailed: Bool = false
    ) -> ACPMigrationDecision {
        let prefer = stage == .preferAuthenticated || stage == .enforce
        if authenticated {
            return .init(connectionAllowed: true, sensitiveControlAllowed: authorized,
                         preferAuthenticated: prefer,
                         reason: authorized ? "authenticated_authorized" : "security.permission_denied")
        }
        if strongerAuthenticationFailed || stage == .enforce {
            return .init(connectionAllowed: false, sensitiveControlAllowed: false,
                         preferAuthenticated: prefer, reason: "security.downgrade_forbidden")
        }
        return .init(connectionAllowed: explicitlyAllowTrustedLAN, sensitiveControlAllowed: false,
                     preferAuthenticated: prefer,
                     reason: explicitlyAllowTrustedLAN ? "trusted_lan_view_only" : "security.permission_denied")
    }
}
