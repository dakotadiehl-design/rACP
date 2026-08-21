import XCTest
import AuroraACP

final class ACPRemoteTests: XCTestCase {
    func sampleLayout() -> ACPRemoteLayout {
        ACPRemoteLayout(
            layoutID: "0193f8d8-4c4e-7d8b-a2ab-0000000000a0",
            revision: 8,
            showID: "0193f8d8-4c4e-7d8b-a2ab-000000000050",
            name: "FOH",
            controls: [
                ACPRemoteControl(controlID: "cue_go", label: "GO", controlType: "button", permission: "remote.operator", action: "cue.go"),
                ACPRemoteControl(controlID: "fog_burst", label: "FOG", controlType: "momentary", permission: "remote.busker", action: "busk.fog.output"),
            ]
        )
    }

    func testGoIdempotentAndDirtyDisconnect() async {
        let auth = ACPRemoteAuthority(showID: "show", layout: sampleLayout())
        await auth.grant(sessionID: "s1", roles: ["remote.operator", "remote.busker"])
        let first = await auth.invoke(sessionID: "s1", controlID: "cue_go", invocationID: "inv", interaction: .activate, showID: "show")
        let again = await auth.invoke(sessionID: "s1", controlID: "cue_go", invocationID: "inv", interaction: .activate, showID: "show")
        let count = await auth.goCount
        XCTAssertEqual(first.status, "applied")
        XCTAssertEqual(again.status, "applied")
        XCTAssertEqual(count, 1)
        _ = await auth.invoke(sessionID: "s1", controlID: "fog_burst", invocationID: "h", interaction: .momentaryBegin)
        var active = await auth.effectActive("fog_burst")
        XCTAssertTrue(active)
        await auth.onSessionLost("s1")
        active = await auth.effectActive("fog_burst")
        XCTAssertFalse(active)
    }

    func testCrossSessionEndDenied() async {
        let auth = ACPRemoteAuthority(showID: "show", layout: sampleLayout())
        await auth.grant(sessionID: "s1", roles: ["remote.operator", "remote.busker"])
        await auth.grant(sessionID: "s2", roles: ["remote.busker"])
        let begun = await auth.invoke(sessionID: "s1", controlID: "fog_burst", invocationID: "h", interaction: .momentaryBegin)
        let stolen = await auth.invoke(sessionID: "s2", controlID: "fog_burst", invocationID: "h", interaction: .momentaryEnd, leaseID: begun.leaseID)
        XCTAssertEqual(stolen.code, "remote.control.permission_denied")
        let active = await auth.effectActive("fog_burst")
        XCTAssertTrue(active)
    }

    func testRemoteSessionNotReadyWhileStale() async throws {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(
            session: session,
            identity: ACPRemoteIdentity(
                nodeID: "0193f8d8-4c4e-7d8b-a2ab-0000000000b0",
                instanceID: UUID().uuidString.lowercased(),
                deviceID: UUID().uuidString.lowercased(),
                remoteID: UUID().uuidString.lowercased(),
                deviceName: "FOH",
                platform: "ipados",
                appVersion: "1.0.0"
            )
        )
        do {
            _ = try await remote.invoke(controlID: "cue_go", interaction: .activate)
            XCTFail("expected not ready")
        } catch {
            // expected
        }
        await remote.prepare(layout: sampleLayout())
        _ = try await remote.invoke(controlID: "cue_go", interaction: .activate, wait: false)
    }

    func testMinCapabilityVersionFailsClosed() {
        XCTAssertEqual(
            acpMinCapabilityAllowed(
                requiredCapability: "remote.control.invoke",
                minCapabilityVersion: "1.0",
                negotiatedVersions: [:]
            ),
            "capability_not_permitted"
        )
        XCTAssertEqual(
            acpMinCapabilityAllowed(
                requiredCapability: "remote.control.invoke",
                minCapabilityVersion: "1.0",
                negotiatedVersions: ["remote.control.invoke": "not-a-version"]
            ),
            "capability_not_permitted"
        )
        XCTAssertEqual(
            acpMinCapabilityAllowed(
                requiredCapability: "remote.control.invoke",
                minCapabilityVersion: "1.0",
                negotiatedVersions: ["remote.control.invoke": "0.9"]
            ),
            "capability_not_permitted"
        )
        XCTAssertNil(
            acpMinCapabilityAllowed(
                requiredCapability: "remote.control.invoke",
                minCapabilityVersion: "1.0",
                negotiatedVersions: ["remote.control.invoke": "1.0"]
            )
        )
    }

    func testLeaseRequiredToEnd() async {
        let auth = ACPRemoteAuthority(showID: "show", layout: sampleLayout())
        await auth.grant(sessionID: "s1", roles: ["remote.operator", "remote.busker"])
        let begun = await auth.invoke(sessionID: "s1", controlID: "fog_burst", invocationID: "h", interaction: .momentaryBegin)
        let missing = await auth.invoke(sessionID: "s1", controlID: "fog_burst", invocationID: "h", interaction: .momentaryEnd)
        XCTAssertEqual(missing.code, "remote.momentary.unknown_invocation")
        let ended = await auth.invoke(sessionID: "s1", controlID: "fog_burst", invocationID: "h", interaction: .momentaryEnd, leaseID: begun.leaseID)
        XCTAssertEqual(ended.status, "applied")
        let active = await auth.effectActive("fog_burst")
        XCTAssertFalse(active)
    }

    func testIdempotencyConflictAndAckLease() async {
        let auth = ACPRemoteAuthority(showID: "show", layout: sampleLayout())
        await auth.grant(sessionID: "s1", roles: ["remote.operator", "remote.busker"])
        let first = await auth.invoke(sessionID: "s1", controlID: "cue_go", invocationID: "inv", interaction: .activate, showID: "show")
        let conflict = await auth.invoke(sessionID: "s1", controlID: "cue_go", invocationID: "inv", interaction: .activate, showID: "show", leaseID: "different-lease")
        XCTAssertEqual(first.status, "applied")
        XCTAssertEqual(conflict.code, "conflict")

        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(
            session: session,
            identity: ACPRemoteIdentity(
                nodeID: "0193f8d8-4c4e-7d8b-a2ab-0000000000b0",
                instanceID: UUID().uuidString.lowercased(),
                deviceID: UUID().uuidString.lowercased(),
                remoteID: UUID().uuidString.lowercased(),
                deviceName: "FOH",
                platform: "ipados",
                appVersion: "1.0.0"
            )
        )
        let lease = UUID().uuidString.lowercased()
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "command.ack",
            source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "status": .string("applied"),
                "result": .object([
                    "control_id": .string("fog_burst"),
                    "active": .bool(true),
                    "lease_id": .string(lease),
                ]),
            ]
        )
        await remote.applyAcknowledgement(invocationID: "hold", ack: ack)
        let stored = await remote.leases["hold"]
        XCTAssertEqual(stored, lease)
    }
}
