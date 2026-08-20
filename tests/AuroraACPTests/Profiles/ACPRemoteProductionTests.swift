import XCTest
@testable import AuroraACP

final class ACPRemoteProductionTests: XCTestCase {
    func layout() -> ACPRemoteLayout {
        ACPRemoteLayout(
            layoutID: "lay",
            revision: 1,
            showID: "show",
            name: "Test",
            controls: [
                ACPRemoteControl(controlID: "go", label: "GO", controlType: "button", permission: "remote.operator", action: "cue.go"),
                ACPRemoteControl(controlID: "fog", label: "Fog", controlType: "momentary", permission: "remote.busker", action: "busk.fog.output", maxHoldMs: 50),
            ]
        )
    }

    func testClientClaimedRolesDoNotGrantAccess() async {
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.viewer"]])
        let auth = ACPRemoteProductionAuthority(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s")
        let granted = await auth.helloRoles(principal: principal, claimed: ["remote.admin"])
        XCTAssertEqual(granted, ["remote.viewer"])
        let result = await auth.invoke(
            principal: principal,
            controlID: "go",
            invocationID: "inv-1",
            interaction: .activate,
            claimedRoles: ["remote.operator"]
        )
        XCTAssertEqual(result.status, "rejected")
        XCTAssertEqual(result.code, "remote.control.permission_denied")
    }

    func testDuplicateInvokeDoesNotApplyTwice() async {
        let box = CountRouter()
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.operator"]])
        let auth = ACPRemoteProductionAuthority(showID: "show", layout: layout(), policy: policy, router: box)
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s1")
        let first = await auth.invoke(principal: principal, controlID: "go", invocationID: "inv-go", interaction: .activate)
        let second = await auth.invoke(
            principal: ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s2"),
            controlID: "go",
            invocationID: "inv-go",
            interaction: .activate
        )
        XCTAssertEqual(first.status, "applied")
        XCTAssertEqual(second.status, "applied")
        XCTAssertEqual(box.applyCount, 1)
    }

    func testLeaseExpiryAndFailedReleaseStayUnsafe() async {
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.busker"]])
        let auth = ACPRemoteProductionAuthority(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s")
        let begin = await auth.invoke(principal: principal, controlID: "fog", invocationID: "fog-1", interaction: .momentaryBegin)
        XCTAssertEqual(begin.status, "applied")
        XCTAssertNotNil(begin.leaseID)
        await auth.simulatePhysicalReleaseFailure(true)
        await auth.advanceTime(100)
        let hold = await auth.hold(invocationID: "fog-1")
        XCTAssertEqual(hold?.releasePending, true)
        XCTAssertEqual(hold?.physicalActive, true)
    }

    func testDisconnectReleasesHold() async {
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.busker"]])
        let auth = ACPRemoteProductionAuthority(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s")
        _ = await auth.invoke(principal: principal, controlID: "fog", invocationID: "fog-2", interaction: .momentaryBegin)
        await auth.disconnect(nodeID: "node-a")
        let after = await auth.hold(invocationID: "fog-2")
        XCTAssertNil(after)
    }
}

private final class CountRouter: ACPRemoteActionRouting, @unchecked Sendable {
    var applyCount = 0
    func apply(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        applyCount += 1
        return ACPRemoteRouterResult(ok: true)
    }
    func begin(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: true)
    }
    func end(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: false)
    }
    func forceRelease(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: false)
    }
}
