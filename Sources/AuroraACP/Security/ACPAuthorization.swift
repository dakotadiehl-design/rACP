import Foundation

public struct ACPDeviceIdentity: Sendable, Equatable {
    public let trustDomainID, nodeID, credentialID, identityKeyID: String
}

public struct ACPOperatorIdentity: Sendable, Equatable {
    public let operatorID: String
    public let authenticated: Bool
    public let permissions: Set<String>
    public init(operatorID: String, authenticated: Bool, permissions: Set<String>) {
        self.operatorID = operatorID; self.authenticated = authenticated; self.permissions = permissions
    }
}

public struct ACPAuthorizationContext: Sendable {
    public let principal: ACPAuthenticatedPrincipal
    public let credentialPermissions, localPolicyPermissions, capabilityPermissions, safetyPermissions: Set<String>
    public let policyRevision: UInt64
    public let safetyState, auditCorrelationID: String
    public let operatorIdentity: ACPOperatorIdentity?
    public let operatorRequired: Bool
    public init(
        principal: ACPAuthenticatedPrincipal, credentialPermissions: Set<String>,
        localPolicyPermissions: Set<String>, capabilityPermissions: Set<String>, safetyPermissions: Set<String>,
        policyRevision: UInt64, safetyState: String, auditCorrelationID: String = UUID().uuidString.lowercased(),
        operatorIdentity: ACPOperatorIdentity? = nil, operatorRequired: Bool = false
    ) {
        self.principal = principal; self.credentialPermissions = credentialPermissions
        self.localPolicyPermissions = localPolicyPermissions; self.capabilityPermissions = capabilityPermissions
        self.safetyPermissions = safetyPermissions; self.policyRevision = policyRevision
        self.safetyState = safetyState; self.auditCorrelationID = auditCorrelationID
        self.operatorIdentity = operatorIdentity; self.operatorRequired = operatorRequired
    }
}

public struct ACPAuthorizationDecision: Sendable {
    public let allowed: Bool
    public let permission: String?
    public let effectivePermissions: Set<String>
    public let policyRevision: UInt64
    public let auditCorrelationID, reason, safetyState: String
    public let principal: ACPAuthenticatedPrincipal
}

public enum ACPSessionRevalidationAction: Sendable, Equatable { case retain, terminate }

public enum ACPAuthorization {
    private static let extraCatalog = [
        "remote.control.invoke": "remote.control.invoke",
        "remote.macro.invoke": "remote.macro.invoke",
        "remote.navigation.invoke": "remote.navigation.invoke",
    ]
    public static func deviceIdentity(_ principal: ACPAuthenticatedPrincipal) throws -> ACPDeviceIdentity {
        guard principal.state == .authenticated, let domain = principal.trustDomainID, let node = principal.nodeID,
              let credential = principal.credentialID, let key = principal.identityKeyID
        else { throw ACPSecurityAdmissionError.authenticationFailed }
        return .init(trustDomainID: domain, nodeID: node, credentialID: credential, identityKeyID: key)
    }
    public static func effectivePermissions(_ context: ACPAuthorizationContext) -> Set<String> {
        guard (try? deviceIdentity(context.principal)) != nil else { return [] }
        var result = context.credentialPermissions.intersection(context.localPolicyPermissions)
            .intersection(context.capabilityPermissions).intersection(context.safetyPermissions)
        if context.operatorRequired {
            guard let identity = context.operatorIdentity, identity.authenticated else { return [] }
            result.formIntersection(identity.permissions)
        }
        return result
    }
    public static func requiredPermission(_ operation: String) -> String? {
        extraCatalog[operation] ?? ACPRegistry.lookup(operation)?.authorizationPermission
    }
    public static func authorize(_ operation: String, context: ACPAuthorizationContext) -> ACPAuthorizationDecision {
        let permission = requiredPermission(operation), effective = effectivePermissions(context)
        let allowed = permission.map(effective.contains) ?? false
        return .init(allowed: allowed, permission: permission, effectivePermissions: effective,
                     policyRevision: context.policyRevision, auditCorrelationID: context.auditCorrelationID,
                     reason: allowed ? "authorized" : "security.permission_denied",
                     safetyState: context.safetyState, principal: context.principal)
    }
    public static func revalidation(previous: ACPAuthorizationDecision, current: ACPAuthorizationDecision)
        -> ACPSessionRevalidationAction {
        previous.allowed && !current.allowed ? .terminate : .retain
    }
}

public actor ACPAuthorizationPolicyStore {
    public private(set) var revision: UInt64 = 1
    private var permissionsByNode: [String: Set<String>]
    public init(_ value: [String: Set<String>] = [:]) { permissionsByNode = value }
    @discardableResult public func replace(_ value: [String: Set<String>]) -> UInt64 {
        permissionsByNode = value
        if revision < UInt64.max { revision += 1 }
        return revision
    }
    public func permissions(nodeID: String) -> Set<String> { permissionsByNode[nodeID] ?? [] }
}
