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
    public let roleAssignmentRevision, capabilityRevision, credentialGeneration: UInt64
    public let lifecycleGeneration, revocationGeneration: UInt64
    public let authenticatedSessionID: String
    public let safetyState, auditCorrelationID: String
    public let operatorIdentity: ACPOperatorIdentity?
    public let operatorRequired: Bool
    public init(
        principal: ACPAuthenticatedPrincipal, credentialPermissions: Set<String>,
        localPolicyPermissions: Set<String>, capabilityPermissions: Set<String>, safetyPermissions: Set<String>,
        policyRevision: UInt64, safetyState: String, auditCorrelationID: String = UUID().uuidString.lowercased(),
        authenticatedSessionID: String = UUID().uuidString.lowercased(),
        roleAssignmentRevision: UInt64 = 0, capabilityRevision: UInt64 = 0,
        credentialGeneration: UInt64 = 0, lifecycleGeneration: UInt64 = 0,
        revocationGeneration: UInt64 = 0,
        operatorIdentity: ACPOperatorIdentity? = nil, operatorRequired: Bool = false
    ) {
        self.principal = principal; self.credentialPermissions = credentialPermissions
        self.localPolicyPermissions = localPolicyPermissions; self.capabilityPermissions = capabilityPermissions
        self.safetyPermissions = safetyPermissions; self.policyRevision = policyRevision
        self.safetyState = safetyState; self.auditCorrelationID = auditCorrelationID
        self.authenticatedSessionID = authenticatedSessionID
        self.roleAssignmentRevision = roleAssignmentRevision
        self.capabilityRevision = capabilityRevision
        self.credentialGeneration = credentialGeneration
        self.lifecycleGeneration = lifecycleGeneration
        self.revocationGeneration = revocationGeneration
        self.operatorIdentity = operatorIdentity; self.operatorRequired = operatorRequired
    }
}

public final class ACPAuthorizationDecision: @unchecked Sendable {
    public let allowed: Bool
    public let permission: String?
    public let effectivePermissions: Set<String>
    public let policyRevision: UInt64
    public let auditCorrelationID, reason, safetyState: String
    public let principal: ACPAuthenticatedPrincipal
    public let authenticatedSessionID, operation: String
    public let targetScope: String?
    public let roleAssignmentRevision, capabilityRevision, credentialGeneration: UInt64
    public let lifecycleGeneration, revocationGeneration: UInt64
    private let lock = NSLock()
    private var consumed = false

    fileprivate init(
        allowed: Bool, permission: String?, effectivePermissions: Set<String>,
        policyRevision: UInt64, auditCorrelationID: String, reason: String,
        safetyState: String, principal: ACPAuthenticatedPrincipal,
        authenticatedSessionID: String, operation: String, targetScope: String?,
        roleAssignmentRevision: UInt64, capabilityRevision: UInt64,
        credentialGeneration: UInt64, lifecycleGeneration: UInt64,
        revocationGeneration: UInt64
    ) {
        self.allowed = allowed; self.permission = permission
        self.effectivePermissions = effectivePermissions; self.policyRevision = policyRevision
        self.auditCorrelationID = auditCorrelationID; self.reason = reason
        self.safetyState = safetyState; self.principal = principal
        self.authenticatedSessionID = authenticatedSessionID; self.operation = operation
        self.targetScope = targetScope; self.roleAssignmentRevision = roleAssignmentRevision
        self.capabilityRevision = capabilityRevision; self.credentialGeneration = credentialGeneration
        self.lifecycleGeneration = lifecycleGeneration; self.revocationGeneration = revocationGeneration
    }

    public func consume(
        sessionID: String, operation: String, targetScope: String?,
        policyRevision: UInt64, roleAssignmentRevision: UInt64,
        capabilityRevision: UInt64, credentialGeneration: UInt64,
        lifecycleGeneration: UInt64, revocationGeneration: UInt64,
        operationClass: ACPSecurityOperationClass = .ordinaryControl,
        auditSink: (any ACPSecurityAuditSink)? = nil,
        auditFailurePolicy: ACPAuditFailurePolicy = .init()
    ) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !consumed else { return false }
        consumed = true
        let bindingValid = allowed && sessionID == authenticatedSessionID
            && operation == self.operation && targetScope == self.targetScope
            && policyRevision == self.policyRevision
            && roleAssignmentRevision == self.roleAssignmentRevision
            && capabilityRevision == self.capabilityRevision
            && credentialGeneration == self.credentialGeneration
            && lifecycleGeneration == self.lifecycleGeneration
            && revocationGeneration == self.revocationGeneration
        guard bindingValid else { return false }
        guard let auditSink else {
            return auditFailurePolicy.permitsOperationAfterAuditFailure(operationClass)
        }
        do {
            try auditSink.record(ACPSecurityAuditEvent(
                operationClass: operationClass, operation: operation,
                outcome: "authorized", auditCorrelationID: auditCorrelationID,
                sessionID: sessionID, nodeID: principal.nodeID,
                credentialID: principal.credentialID, targetScope: targetScope,
                policyRevision: policyRevision))
            return true
        } catch {
            return auditFailurePolicy.permitsOperationAfterAuditFailure(operationClass)
        }
    }
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
    public static func authorize(
        _ operation: String, targetScope: String? = nil,
        sessionID: String? = nil, context: ACPAuthorizationContext
    ) -> ACPAuthorizationDecision {
        let permission = requiredPermission(operation), effective = effectivePermissions(context)
        let requestedSessionID = sessionID ?? context.authenticatedSessionID
        let sessionMatches = requestedSessionID == context.authenticatedSessionID
        let bindingsBounded = (1...128).contains(requestedSessionID.utf8.count)
            && (1...128).contains(context.auditCorrelationID.utf8.count)
            && (1...64).contains(context.safetyState.utf8.count)
            && (targetScope.map { (1...256).contains($0.utf8.count) } ?? true)
        let allowed = sessionMatches && bindingsBounded
            && (permission.map(effective.contains) ?? false)
        return .init(allowed: allowed, permission: permission, effectivePermissions: effective,
                     policyRevision: context.policyRevision, auditCorrelationID: context.auditCorrelationID,
                     reason: allowed ? "authorized" : !sessionMatches
                        ? "security.session_mismatch" : !bindingsBounded
                        ? "security.binding_invalid" : "security.permission_denied",
                     safetyState: context.safetyState, principal: context.principal,
                     authenticatedSessionID: context.authenticatedSessionID,
                     operation: operation, targetScope: targetScope,
                     roleAssignmentRevision: context.roleAssignmentRevision,
                     capabilityRevision: context.capabilityRevision,
                     credentialGeneration: context.credentialGeneration,
                     lifecycleGeneration: context.lifecycleGeneration,
                     revocationGeneration: context.revocationGeneration)
    }
    public static func revalidation(previous: ACPAuthorizationDecision, current: ACPAuthorizationDecision)
        -> ACPSessionRevalidationAction {
        guard previous.allowed else { return .retain }
        guard current.allowed,
              previous.principal == current.principal,
              previous.authenticatedSessionID == current.authenticatedSessionID,
              previous.operation == current.operation,
              previous.targetScope == current.targetScope,
              previous.permission == current.permission,
              previous.effectivePermissions == current.effectivePermissions,
              previous.policyRevision == current.policyRevision,
              previous.roleAssignmentRevision == current.roleAssignmentRevision,
              previous.capabilityRevision == current.capabilityRevision,
              previous.credentialGeneration == current.credentialGeneration,
              previous.lifecycleGeneration == current.lifecycleGeneration,
              previous.revocationGeneration == current.revocationGeneration,
              previous.safetyState == current.safetyState
        else { return .terminate }
        return .retain
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
    public func authorize(
        _ operation: String, targetScope: String? = nil,
        sessionID: String? = nil, context: ACPAuthorizationContext
    ) -> ACPAuthorizationDecision {
        guard let identity = try? ACPAuthorization.deviceIdentity(context.principal) else {
            return ACPAuthorization.authorize(
                operation, targetScope: targetScope, sessionID: sessionID, context: context)
        }
        let current = ACPAuthorizationContext(
            principal: context.principal, credentialPermissions: context.credentialPermissions,
            localPolicyPermissions: permissionsByNode[identity.nodeID] ?? [],
            capabilityPermissions: context.capabilityPermissions, safetyPermissions: context.safetyPermissions,
            policyRevision: revision, safetyState: context.safetyState,
            auditCorrelationID: context.auditCorrelationID,
            authenticatedSessionID: context.authenticatedSessionID,
            roleAssignmentRevision: context.roleAssignmentRevision,
            capabilityRevision: context.capabilityRevision,
            credentialGeneration: context.credentialGeneration,
            lifecycleGeneration: context.lifecycleGeneration,
            revocationGeneration: context.revocationGeneration,
            operatorIdentity: context.operatorIdentity,
            operatorRequired: context.operatorRequired)
        return ACPAuthorization.authorize(
            operation, targetScope: targetScope, sessionID: sessionID, context: current)
    }

    /// Authorizes and consumes one decision without allowing a policy update
    /// to interleave between the two operations. All revision bindings come
    /// from the authenticated context or this actor's current policy state;
    /// callers cannot echo values out of the decision to satisfy the check.
    public func authorizeAndConsume(
        _ operation: String, targetScope: String? = nil, sessionID: String,
        context: ACPAuthorizationContext,
        operationClass: ACPSecurityOperationClass = .ordinaryControl,
        auditSink: (any ACPSecurityAuditSink)? = nil,
        auditFailurePolicy: ACPAuditFailurePolicy = .init()
    ) -> ACPAuthorizationDecision? {
        let decision = authorize(
            operation, targetScope: targetScope, sessionID: sessionID, context: context)
        guard decision.consume(
            sessionID: sessionID, operation: operation, targetScope: targetScope,
            policyRevision: revision,
            roleAssignmentRevision: context.roleAssignmentRevision,
            capabilityRevision: context.capabilityRevision,
            credentialGeneration: context.credentialGeneration,
            lifecycleGeneration: context.lifecycleGeneration,
            revocationGeneration: context.revocationGeneration,
            operationClass: operationClass, auditSink: auditSink,
            auditFailurePolicy: auditFailurePolicy)
        else { return nil }
        return decision
    }
}
