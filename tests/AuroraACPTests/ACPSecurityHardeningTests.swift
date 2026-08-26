import XCTest
@testable import AuroraACP

final class ACPSecurityHardeningTests: XCTestCase {
    private func principal() -> ACPAuthenticatedPrincipal {
        .init(state: .authenticated, mode: .auroraTrust, profile: .full,
              trustDomainID: "domain", nodeID: "node", credentialID: "credential",
              identityKeyID: "key", credentialFormat: "x509_der", roleConstraints: [])
    }

    func testAuthorizationIntersectionExhaustiveBooleanMatrix() {
        let permission = "security.credential.revoke"
        for mask in 0..<16 {
            let value: (Int) -> Set<String> = { mask & $0 == 0 ? [] : [permission] }
            let context = ACPAuthorizationContext(
                principal: principal(), credentialPermissions: value(1), localPolicyPermissions: value(2),
                capabilityPermissions: value(4), safetyPermissions: value(8), policyRevision: 1,
                safetyState: "safe")
            XCTAssertEqual(ACPAuthorization.authorize(permission, context: context).allowed, mask == 15)
        }
    }

    func testPolicyUpdateRacingAuthorizationEndsFailClosed() async {
        let permission = "security.credential.revoke"
        let store = ACPAuthorizationPolicyStore(["node": [permission]])
        let context = ACPAuthorizationContext(
            principal: principal(), credentialPermissions: [permission], localPolicyPermissions: [permission],
            capabilityPermissions: [permission], safetyPermissions: [permission], policyRevision: 1,
            safetyState: "safe")
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<100 {
                group.addTask { _ = await store.replace(index == 99 ? ["node": []] : ["node": [permission]]) }
                group.addTask { _ = await store.authorize(permission, context: context) }
            }
        }
        _ = await store.replace(["node": []])
        let finalDecision = await store.authorize(permission, context: context)
        XCTAssertFalse(finalDecision.allowed)
    }
}
