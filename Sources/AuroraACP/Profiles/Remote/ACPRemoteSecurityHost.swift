import Foundation

public actor ACPRemoteSecurityHost {
    private let core: ACPRemoteAuthorityCore
    private let policyStore: ACPAuthorizationPolicyStore
    private let auditSink: (any ACPSecurityAuditSink)?
    private let auditFailurePolicy: ACPAuditFailurePolicy
    public let allowUnauthenticatedView: Bool
    public init(core: ACPRemoteAuthorityCore, policyStore: ACPAuthorizationPolicyStore,
                allowUnauthenticatedView: Bool = false,
                auditSink: (any ACPSecurityAuditSink)? = nil,
                auditFailurePolicy: ACPAuditFailurePolicy = .init()) {
        self.core = core; self.policyStore = policyStore
        self.allowUnauthenticatedView = allowUnauthenticatedView
        self.auditSink = auditSink; self.auditFailurePolicy = auditFailurePolicy
    }
    public func invoke(
        context: ACPAuthorizationContext, instanceID: String, sessionID: String,
        controlID: String, invocationID: String, interaction: ACPRemoteInteraction,
        leaseID: String? = nil, claimedRoles: [String] = []
    ) async -> (status: String, code: String?, leaseID: String?, hold: ACPRemoteHoldState?) {
        let operation = "remote.control.invoke"
        guard let decision = await policyStore.authorizeAndConsume(
            operation, targetScope: controlID, sessionID: sessionID, context: context,
            operationClass: .ordinaryControl, auditSink: auditSink,
            auditFailurePolicy: auditFailurePolicy),
              let nodeID = decision.principal.nodeID else {
            return ("rejected", "remote.control.permission_denied", nil, nil)
        }
        return await core.invoke(
            principal: .init(nodeID: nodeID, instanceID: instanceID, sessionID: sessionID),
            controlID: controlID, invocationID: invocationID, interaction: interaction,
            claimedRoles: claimedRoles, leaseID: leaseID)
    }
    public func mayView(_ context: ACPAuthorizationContext?) -> Bool {
        guard let context else { return allowUnauthenticatedView }
        return (try? ACPAuthorization.deviceIdentity(context.principal)) != nil || allowUnauthenticatedView
    }
}
