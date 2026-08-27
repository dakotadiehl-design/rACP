import XCTest
@testable import AuroraACP

final class ACPAuthorizationTests: XCTestCase {
    private let permission = "security.credential.revoke"

    func testMigrationNeverGrantsUnauthenticatedControlOrDowngrade() {
        for stage in ACPMigrationStage.allCases {
            XCTAssertFalse(ACPMigrationSecurity.decide(
                stage: stage, authenticated: false, explicitlyAllowTrustedLAN: true
            ).sensitiveControlAllowed)
        }
        XCTAssertFalse(ACPMigrationSecurity.decide(
            stage: .observe, authenticated: false, explicitlyAllowTrustedLAN: true,
            strongerAuthenticationFailed: true).connectionAllowed)
        XCTAssertFalse(ACPMigrationSecurity.decide(
            stage: .enforce, authenticated: false, explicitlyAllowTrustedLAN: true).connectionAllowed)
        let authenticatedOnly = ACPMigrationSecurity.decide(
            stage: .enforce, authenticated: true, authorized: false, explicitlyAllowTrustedLAN: false)
        XCTAssertTrue(authenticatedOnly.connectionAllowed)
        XCTAssertFalse(authenticatedOnly.sensitiveControlAllowed)
    }

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

    func testAuthorizationDecisionIsSessionTargetRevisionBoundAndOneShot() {
        let value = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [permission],
            localPolicyPermissions: [permission], capabilityPermissions: [permission],
            safetyPermissions: [permission], policyRevision: 7, safetyState: "armed",
            authenticatedSessionID: "session-a", roleAssignmentRevision: 2,
            capabilityRevision: 3, credentialGeneration: 4,
            lifecycleGeneration: 5, revocationGeneration: 6)
        let wrong = ACPAuthorization.authorize(
            permission, targetScope: "device-a", context: value)
        XCTAssertFalse(wrong.consume(
            sessionID: "session-b", operation: permission, targetScope: "device-a",
            policyRevision: 7, roleAssignmentRevision: 2, capabilityRevision: 3,
            credentialGeneration: 4, lifecycleGeneration: 5, revocationGeneration: 6))
        XCTAssertFalse(wrong.consume(
            sessionID: "session-a", operation: permission, targetScope: "device-a",
            policyRevision: 7, roleAssignmentRevision: 2, capabilityRevision: 3,
            credentialGeneration: 4, lifecycleGeneration: 5, revocationGeneration: 6))

        let exact = ACPAuthorization.authorize(
            permission, targetScope: "device-a", context: value)
        XCTAssertTrue(exact.consume(
            sessionID: "session-a", operation: permission, targetScope: "device-a",
            policyRevision: 7, roleAssignmentRevision: 2, capabilityRevision: 3,
            credentialGeneration: 4, lifecycleGeneration: 5, revocationGeneration: 6))
        XCTAssertFalse(exact.consume(
            sessionID: "session-a", operation: permission, targetScope: "device-a",
            policyRevision: 7, roleAssignmentRevision: 2, capabilityRevision: 3,
            credentialGeneration: 4, lifecycleGeneration: 5, revocationGeneration: 6))
    }

    func testAuditFailurePolicyIsOperationClassSpecificAndBufferIsBounded() throws {
        let value = context()
        let administration = ACPAuthorization.authorize(permission, context: value)
        XCTAssertFalse(administration.consume(
            sessionID: value.authenticatedSessionID, operation: permission, targetScope: nil,
            policyRevision: 7, roleAssignmentRevision: 0, capabilityRevision: 0,
            credentialGeneration: 0, lifecycleGeneration: 0, revocationGeneration: 0,
            operationClass: .trustLifecycle))

        let log = try ACPBoundedSecurityAuditLog(maximumEvents: 1)
        let audited = ACPAuthorization.authorize(permission, context: value)
        XCTAssertTrue(audited.consume(
            sessionID: value.authenticatedSessionID, operation: permission, targetScope: nil,
            policyRevision: 7, roleAssignmentRevision: 0, capabilityRevision: 0,
            credentialGeneration: 0, lifecycleGeneration: 0, revocationGeneration: 0,
            operationClass: .trustLifecycle, auditSink: log))
        XCTAssertEqual(log.count, 1)

        let fullBufferAdministration = ACPAuthorization.authorize(permission, context: value)
        XCTAssertFalse(fullBufferAdministration.consume(
            sessionID: value.authenticatedSessionID, operation: permission, targetScope: nil,
            policyRevision: 7, roleAssignmentRevision: 0, capabilityRevision: 0,
            credentialGeneration: 0, lifecycleGeneration: 0, revocationGeneration: 0,
            operationClass: .securityAdministration, auditSink: log))

        let liveControl = ACPAuthorization.authorize(permission, context: value)
        XCTAssertTrue(liveControl.consume(
            sessionID: value.authenticatedSessionID, operation: permission, targetScope: nil,
            policyRevision: 7, roleAssignmentRevision: 0, capabilityRevision: 0,
            credentialGeneration: 0, lifecycleGeneration: 0, revocationGeneration: 0,
            operationClass: .safetyCriticalLiveControl, auditSink: log))
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

    func testRevisionChangeTerminatesEvenWhenPermissionRemainsAllowed() {
        let previous = ACPAuthorization.authorize(permission, context: context())
        let changed = ACPAuthorization.authorize(permission, context: .init(
            principal: principal(), credentialPermissions: [permission],
            localPolicyPermissions: [permission], capabilityPermissions: [permission],
            safetyPermissions: [permission], policyRevision: 8,
            safetyState: "armed", authenticatedSessionID: previous.authenticatedSessionID))
        XCTAssertTrue(previous.allowed)
        XCTAssertTrue(changed.allowed)
        XCTAssertEqual(
            ACPAuthorization.revalidation(previous: previous, current: changed), .terminate)
    }

    func testRemoteProductionHostRequiresAuthenticatedPermissionAndIgnoresClaims() async {
        let layout = ACPRemoteLayout(layoutID: "lay", revision: 1, showID: "show", name: "Test", controls: [
            .init(controlID: "go", label: "GO", controlType: "button", permission: "remote.operator", action: "cue.go")
        ])
        let core = ACPRemoteAuthorityCore(showID: "show", layout: layout,
            policy: ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.operator"]]),
            router: ACPRemoteMemoryRouter())
        let remotePermission = "remote.control.invoke"
        let policyStore = ACPAuthorizationPolicyStore(["node-a": [remotePermission]])
        let host = ACPRemoteSecurityHost(core: core, policyStore: policyStore)
        let allowed = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [remotePermission], localPolicyPermissions: [remotePermission],
            capabilityPermissions: [remotePermission], safetyPermissions: [remotePermission], policyRevision: 1,
            safetyState: "armed", authenticatedSessionID: "s")
        let applied = await host.invoke(context: allowed, instanceID: "i", sessionID: "s", controlID: "go",
                                        invocationID: "inv-1", interaction: .activate,
                                        claimedRoles: ["remote.admin"])
        XCTAssertEqual(applied.status, "applied")
        let substituted = await host.invoke(
            context: allowed, instanceID: "i", sessionID: "attacker-session",
            controlID: "go", invocationID: "inv-substitution", interaction: .activate)
        XCTAssertEqual(substituted.code, "remote.control.permission_denied")
        let unauthenticated = ACPAuthorizationContext(
            principal: principal(.unauthenticated), credentialPermissions: [remotePermission],
            localPolicyPermissions: [remotePermission], capabilityPermissions: [remotePermission],
            safetyPermissions: [remotePermission], policyRevision: 1, safetyState: "armed")
        let rejected = await host.invoke(context: unauthenticated, instanceID: "i", sessionID: "s",
                                         controlID: "go", invocationID: "inv-2", interaction: .activate,
                                         claimedRoles: ["remote.admin"])
        XCTAssertEqual(rejected.code, "remote.control.permission_denied")
        _ = await policyStore.replace(["node-a": []])
        let stale = await host.invoke(context: allowed, instanceID: "i", sessionID: "s", controlID: "go",
                                     invocationID: "inv-3", interaction: .activate)
        XCTAssertEqual(stale.code, "remote.control.permission_denied")
    }
}
