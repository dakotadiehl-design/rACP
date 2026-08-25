import XCTest
@testable import AuroraACP

final class ACPAuthorizationTests: XCTestCase {
    private let permission = "security.credential.revoke"

    private func principal(_ state: ACPPrincipalState = .authenticated) -> ACPAuthenticatedPrincipal {
        .init(state: state, mode: .auroraTrust, profile: .full, trustDomainID: "domain", nodeID: "node-a",
              credentialID: "credential", identityKeyID: "key", credentialFormat: "x509_der",
              roleConstraints: ["self-claimed-admin"])
    }

    private func context(_ state: ACPPrincipalState = .authenticated) -> ACPAuthorizationContext {
        .init(principal: principal(state), credentialPermissions: [permission], localPolicyPermissions: [permission],
              capabilityPermissions: [permission], safetyPermissions: [permission], policyRevision: 7,
              safetyState: "armed", auditCorrelationID: "audit-1")
    }

    func testIntersectionUnknownAndCredentialStateFailClosed() {
        XCTAssertTrue(ACPAuthorization.authorize(permission, context: context()).allowed)
        XCTAssertFalse(ACPAuthorization.authorize("unknown.operation", context: context()).allowed)
        XCTAssertFalse(ACPAuthorization.authorize(permission, context: context(.revoked)).allowed)
        let denied = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [permission], localPolicyPermissions: [permission],
            capabilityPermissions: [permission], safetyPermissions: [], policyRevision: 7, safetyState: "disarmed")
        XCTAssertFalse(ACPAuthorization.authorize(permission, context: denied).allowed)
    }

    func testOperatorReassignmentDoesNotChangeDeviceIdentity() throws {
        let before = try ACPAuthorization.deviceIdentity(principal())
        let value = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [permission], localPolicyPermissions: [permission],
            capabilityPermissions: [permission], safetyPermissions: [permission], policyRevision: 7,
            safetyState: "armed", operatorIdentity: .init(operatorID: "operator-b", authenticated: true,
                                                           permissions: [permission]), operatorRequired: true)
        XCTAssertTrue(ACPAuthorization.authorize(permission, context: value).allowed)
        XCTAssertEqual(try ACPAuthorization.deviceIdentity(value.principal), before)
    }

    func testPolicyRemovalRequiresTermination() async {
        let previous = ACPAuthorization.authorize(permission, context: context())
        let store = ACPAuthorizationPolicyStore(["node-a": [permission]])
        let revision = await store.replace(["node-a": []])
        let current = ACPAuthorization.authorize(permission, context: .init(
            principal: principal(), credentialPermissions: [permission],
            localPolicyPermissions: await store.permissions(nodeID: "node-a"),
            capabilityPermissions: [permission], safetyPermissions: [permission], policyRevision: revision,
            safetyState: "armed"))
        XCTAssertEqual(ACPAuthorization.revalidation(previous: previous, current: current), .terminate)
    }

    func testRemoteProductionHostRequiresAuthenticatedPermissionAndIgnoresClaims() async {
        let layout = ACPRemoteLayout(layoutID: "lay", revision: 1, showID: "show", name: "Test", controls: [
            .init(controlID: "go", label: "GO", controlType: "button", permission: "remote.operator", action: "cue.go")
        ])
        let core = ACPRemoteAuthorityCore(showID: "show", layout: layout,
            policy: ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.operator"]]),
            router: ACPRemoteMemoryRouter())
        let host = ACPRemoteSecurityHost(core: core)
        let remotePermission = "remote.control.invoke"
        let allowed = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [remotePermission], localPolicyPermissions: [remotePermission],
            capabilityPermissions: [remotePermission], safetyPermissions: [remotePermission], policyRevision: 1,
            safetyState: "armed")
        let applied = await host.invoke(context: allowed, instanceID: "i", sessionID: "s", controlID: "go",
                                        invocationID: "inv-1", interaction: .activate,
                                        claimedRoles: ["remote.admin"])
        XCTAssertEqual(applied.status, "applied")
        let unauthenticated = ACPAuthorizationContext(
            principal: principal(.unauthenticated), credentialPermissions: [remotePermission],
            localPolicyPermissions: [remotePermission], capabilityPermissions: [remotePermission],
            safetyPermissions: [remotePermission], policyRevision: 1, safetyState: "armed")
        let rejected = await host.invoke(context: unauthenticated, instanceID: "i", sessionID: "s",
                                         controlID: "go", invocationID: "inv-2", interaction: .activate,
                                         claimedRoles: ["remote.admin"])
        XCTAssertEqual(rejected.code, "remote.control.permission_denied")
    }
}
