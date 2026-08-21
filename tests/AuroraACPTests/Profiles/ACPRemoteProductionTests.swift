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
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
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
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: box)
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

    func testConcurrentDuplicateIsReservedBeforeRouterAwait() async {
        let router = SlowRouter()
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.operator"]])
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: router)
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "i", sessionID: "s")
        async let first = auth.invoke(principal: principal, controlID: "go", invocationID: "race", interaction: .activate)
        try? await Task.sleep(nanoseconds: 10_000_000)
        async let duplicate = auth.invoke(principal: principal, controlID: "go", invocationID: "race", interaction: .activate)
        let results = await (first, duplicate)
        XCTAssertEqual(results.0.status, "applied")
        XCTAssertEqual(results.1.status, "in_flight")
        let count = await router.count
        XCTAssertEqual(count, 1)
    }

    func testReplacementSessionReplayConflictsWhenCommandIdentityChanges() async {
        let box = CountRouter()
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.operator"]])
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: box)
        let first = await auth.invoke(
            principal: ACPRemotePrincipal(nodeID: "node-a", instanceID: "i1", sessionID: "s1"),
            controlID: "go",
            invocationID: "same-command",
            interaction: .activate
        )
        let conflict = await auth.invoke(
            principal: ACPRemotePrincipal(nodeID: "node-a", instanceID: "i2", sessionID: "s2"),
            controlID: "fog",
            invocationID: "same-command",
            interaction: .activate
        )
        XCTAssertEqual(first.status, "applied")
        XCTAssertEqual(conflict.status, "conflict")
        XCTAssertEqual(conflict.code, "command_identity_conflict")
        XCTAssertEqual(box.applyCount, 1)
    }

    func testTwoPrincipalsCannotOverwriteEachOthersHoldAndLeaseIsMandatory() async {
        let policy = ACPRemoteStaticPolicy(rolesByNode: [
            "node-a": ["remote.busker"],
            "node-b": ["remote.busker"],
        ])
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
        let a = ACPRemotePrincipal(nodeID: "node-a", instanceID: "a", sessionID: "sa")
        let b = ACPRemotePrincipal(nodeID: "node-b", instanceID: "b", sessionID: "sb")
        let first = await auth.invoke(principal: a, controlID: "fog", invocationID: "shared", interaction: .momentaryBegin)
        let second = await auth.invoke(principal: b, controlID: "fog", invocationID: "shared", interaction: .momentaryBegin)
        XCTAssertNotEqual(first.leaseID, second.leaseID)
        let heldA = await auth.hold(principalNodeID: "node-a", invocationID: "shared")
        let heldB = await auth.hold(principalNodeID: "node-b", invocationID: "shared")
        XCTAssertNotNil(heldA)
        XCTAssertNotNil(heldB)

        let missing = await auth.invoke(principal: a, controlID: "fog", invocationID: "shared", interaction: .momentaryEnd)
        XCTAssertEqual(missing.status, "rejected")
        let wrongOwner = await auth.invoke(
            principal: b,
            controlID: "fog",
            invocationID: "shared",
            interaction: .momentaryEnd,
            leaseID: first.leaseID
        )
        XCTAssertEqual(wrongOwner.status, "rejected")
        let ended = await auth.invoke(
            principal: a,
            controlID: "fog",
            invocationID: "shared",
            interaction: .momentaryEnd,
            leaseID: first.leaseID
        )
        XCTAssertEqual(ended.status, "applied")
        let releasedA = await auth.hold(principalNodeID: "node-a", invocationID: "shared")
        let remainingB = await auth.hold(principalNodeID: "node-b", invocationID: "shared")
        XCTAssertNil(releasedA)
        XCTAssertNotNil(remainingB)
        await auth.shutdown()
    }

    func testAutonomousLeaseExpiryDoesNotRequireInboundTraffic() async throws {
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.busker"]])
        let shortLayout = ACPRemoteLayout(
            layoutID: "layout",
            revision: 1,
            showID: "show",
            name: "Short lease",
            controls: [ACPRemoteControl(
                controlID: "fog", label: "Fog", controlType: "momentary",
                permission: "remote.busker", action: "fog", maxHoldMs: 30
            )]
        )
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: shortLayout, policy: policy, router: ACPRemoteMemoryRouter())
        let principal = ACPRemotePrincipal(nodeID: "node-a", instanceID: "a", sessionID: "s")
        _ = await auth.invoke(principal: principal, controlID: "fog", invocationID: "timer", interaction: .momentaryBegin)
        try await Task.sleep(nanoseconds: 150_000_000)
        let expired = await auth.hold(principalNodeID: "node-a", invocationID: "timer")
        XCTAssertNil(expired)
        await auth.shutdown()
    }

    func testLeaseExpiryAndFailedReleaseStayUnsafe() async {
        let policy = ACPRemoteStaticPolicy(rolesByNode: ["node-a": ["remote.busker"]])
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
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
        let auth = ACPRemoteAuthorityCore(showID: "show", layout: layout(), policy: policy, router: ACPRemoteMemoryRouter())
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

private actor SlowRouter: ACPRemoteActionRouting {
    private(set) var count = 0
    func apply(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        count += 1
        try? await Task.sleep(nanoseconds: 80_000_000)
        return ACPRemoteRouterResult(ok: true)
    }
    func begin(action: String, controlID: String) async -> ACPRemoteRouterResult {
        ACPRemoteRouterResult(ok: false)
    }
    func end(action: String, controlID: String) async -> ACPRemoteRouterResult {
        ACPRemoteRouterResult(ok: false)
    }
    func forceRelease(action: String, controlID: String) async -> ACPRemoteRouterResult {
        ACPRemoteRouterResult(ok: false)
    }
}
