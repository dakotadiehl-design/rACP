import Foundation

public actor ACPRemoteSecurityHost {
    private let core: ACPRemoteAuthorityCore
    public let allowUnauthenticatedView: Bool
    public init(core: ACPRemoteAuthorityCore, allowUnauthenticatedView: Bool = false) {
        self.core = core; self.allowUnauthenticatedView = allowUnauthenticatedView
    }
    public func invoke(
        context: ACPAuthorizationContext, instanceID: String, sessionID: String,
        controlID: String, invocationID: String, interaction: ACPRemoteInteraction,
        leaseID: String? = nil, claimedRoles: [String] = []
    ) async -> (status: String, code: String?, leaseID: String?, hold: ACPRemoteHoldState?) {
        let decision = ACPAuthorization.authorize("remote.control.invoke", context: context)
        guard decision.allowed, let nodeID = decision.principal.nodeID else {
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
