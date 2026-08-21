import XCTest
@testable import AuroraACP

final class ACPRemoteClientTests: XCTestCase {
    func sampleIdentity() -> ACPRemoteIdentity {
        ACPRemoteIdentity(
            nodeID: "0193f8d8-4c4e-7d8b-a2ab-0000000000b0",
            instanceID: UUID().uuidString.lowercased(),
            deviceID: UUID().uuidString.lowercased(),
            remoteID: UUID().uuidString.lowercased(),
            deviceName: "FOH",
            platform: "ipados",
            appVersion: "1.0.0"
        )
    }

    func testPresetUsesCatalogIDsAndNotGenericDefaults() {
        let ids = Set(ACPCapabilitySet.prismRemoteClient.map(\.id))
        XCTAssertTrue(ids.isSuperset(of: ACPCapabilitySet.prismRemoteRequiredIDs))
        XCTAssertTrue(ids.contains("remote.presentation"))
        XCTAssertTrue(ids.contains("output.grand_master"))
        XCTAssertFalse(ACPCapabilitySet.prismRemoteClient.contains { $0.id == "aurora.remote.conductor.v1" })
        XCTAssertNotEqual(
            Set(ACPCapabilitySet.prismRemoteClient.map(\.id)),
            Set(ACPSession.defaultCapabilities.map(\.id))
        )
    }

    func testPrismRemoteProfileNegotiationSucceeds() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let clientSession = ACPSession(
            transport: ta,
            local: ACPIdentity(role: "remote", name: "pad"),
            isServer: false,
            allowPlaintext: true
        )
        let server = ACPSession(
            transport: tb,
            local: ACPIdentity(role: "prism", name: "auth"),
            isServer: true,
            allowPlaintext: true
        )
        await server.setProfiles(["core", "remote", ACPRemoteProfileID.prismV1.rawValue])
        await server.setCapabilities(ACPCapabilitySet.prismRemoteProvider)
        let client = ACPRemoteClient(session: clientSession, identity: sampleIdentity())
        async let serverAck = server.handshake()
        try await client.handshake()
        _ = try await serverAck
        let profiles = await clientSession.negotiatedProfiles
        XCTAssertTrue(profiles.contains(ACPRemoteProfileID.prismV1.rawValue))
        let handshakeComplete = await client.handshakeComplete
        XCTAssertTrue(handshakeComplete)
        await clientSession.goodbye()
        await server.goodbye()
    }

    func testMissingPrismRemoteProfileFailsClosed() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let clientSession = ACPSession(
            transport: ta,
            local: ACPIdentity(role: "remote", name: "pad"),
            isServer: false,
            allowPlaintext: true
        )
        let server = ACPSession(
            transport: tb,
            local: ACPIdentity(role: "prism", name: "auth"),
            isServer: true,
            allowPlaintext: true
        )
        await server.setProfiles(["core"])
        await server.setCapabilities(ACPCapabilitySet.prismRemoteProvider)
        let client = ACPRemoteClient(session: clientSession, identity: sampleIdentity())
        async let serverAck = server.handshake()
        do {
            try await client.handshake()
            XCTFail("missing prism remote profile must fail closed")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "unsupported_version")
        }
        _ = try? await serverAck
        let readyAfterMissingProfile = await client.ready
        XCTAssertFalse(readyAfterMissingProfile)
        await clientSession.goodbye()
        await server.goodbye()
    }

    func testRequiredCapabilityUnavailableFailsClosed() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let clientSession = ACPSession(
            transport: ta,
            local: ACPIdentity(role: "remote", name: "pad"),
            isServer: false,
            allowPlaintext: true
        )
        let server = ACPSession(
            transport: tb,
            local: ACPIdentity(role: "prism", name: "auth"),
            isServer: true,
            allowPlaintext: true
        )
        await server.setProfiles(["core", "remote", ACPRemoteProfileID.prismV1.rawValue])
        await server.setCapabilities([ACPCapability(id: "health.heartbeat", version: "1.0")])
        let client = ACPRemoteClient(session: clientSession, identity: sampleIdentity())
        async let serverAck = server.handshake()
        do {
            try await client.handshake()
            XCTFail("missing required remote capability must fail closed")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "capability_not_permitted")
        }
        _ = try? await serverAck
        let readyAfterMissingCapability = await client.ready
        XCTAssertFalse(readyAfterMissingCapability)
        await clientSession.goodbye()
        await server.goodbye()
    }

    func snapshot(epoch: UInt64, revision: UInt64, resources: [String: AnySendable]) -> ACPEnvelope {
        let items: [AnySendable] = resources.map { key, value in
            .object([
                "resource": .string(key),
                "revision": .uint(revision),
                "value": value,
            ])
        }
        return ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "state.snapshot",
            source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "authority_epoch": .uint(epoch),
                "revision": .uint(revision),
                "resources": .array(items),
            ]
        )
    }

    func delta(epoch: UInt64, base: UInt64, revision: UInt64, resource: String, value: AnySendable) -> ACPEnvelope {
        ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "state.delta",
            source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .latest,
            payload: [
                "authority_epoch": .uint(epoch),
                "base_revision": .uint(base),
                "revision": .uint(revision),
                "changes": .array([
                    .object([
                        "resource": .string(resource),
                        "revision": .uint(revision),
                        "value": value,
                    ]),
                ]),
            ]
        )
    }

    func testAckDoesNotChangeAuthoritativeState() async {
        let store = ACPRemoteStateStore()
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "command.ack",
            source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "status": .string("accepted"),
                "result": .object([
                    "control_id": .string("master"),
                    "value": .double(0.5),
                ]),
            ]
        )
        await remote.applyAcknowledgement(invocationID: "inv", ack: ack)
        XCTAssertNil(store.grandMaster)
        let values = await remote.values
        XCTAssertTrue(values.isEmpty)
    }

    func testStateDeltaUpdatesAuthoritativeClientState() throws {
        var store = ACPRemoteStateStore()
        try store.apply(snapshot(epoch: 1, revision: 1, resources: [
            "output.grand_master": .double(0.2),
        ]))
        try store.apply(delta(epoch: 1, base: 1, revision: 2, resource: "output.grand_master", value: .double(0.75)))
        XCTAssertEqual(store.grandMaster, 0.75)
        XCTAssertEqual(store.revision, 2)
        XCTAssertFalse(store.stale)
    }

    func testStaleStateDeltaIsRejected() throws {
        var store = ACPRemoteStateStore()
        try store.apply(snapshot(epoch: 1, revision: 4, resources: [:]))
        XCTAssertThrowsError(
            try store.apply(delta(epoch: 1, base: 2, revision: 3, resource: "output.grand_master", value: .double(1)))
        )
        XCTAssertNil(store.grandMaster)
    }

    func testRevisionGapTriggersResynchronization() throws {
        var store = ACPRemoteStateStore()
        try store.apply(snapshot(epoch: 1, revision: 1, resources: [:]))
        XCTAssertThrowsError(
            try store.apply(delta(epoch: 1, base: 3, revision: 4, resource: "output.blackout", value: .bool(true)))
        )
        XCTAssertTrue(store.needsSnapshot)
        XCTAssertTrue(store.stale)
    }

    func testClientsConvergeOnPublishedState() throws {
        var a = ACPRemoteStateStore()
        var b = ACPRemoteStateStore()
        let snap = snapshot(epoch: 2, revision: 1, resources: [
            "show.current_song": .object(["song_id": .string("haywire")]),
            "output.blackout": .bool(false),
        ])
        let next = delta(epoch: 2, base: 1, revision: 2, resource: "output.grand_master", value: .double(0.4))
        try a.apply(snap)
        try b.apply(snap)
        try a.apply(next)
        try b.apply(next)
        XCTAssertEqual(a.currentSong, b.currentSong)
        XCTAssertEqual(a.grandMaster, b.grandMaster)
        XCTAssertEqual(a.revision, b.revision)
    }

    func testReconnectRejectsPreviousAuthorityEpoch() throws {
        var store = ACPRemoteStateStore()
        try store.apply(snapshot(epoch: 5, revision: 9, resources: [
            "output.grand_master": .double(0.9),
        ]))
        store.markInterrupted()
        XCTAssertThrowsError(
            try store.apply(delta(epoch: 4, base: 9, revision: 10, resource: "output.grand_master", value: .double(0.1)))
        )
        XCTAssertThrowsError(
            try store.apply(snapshot(epoch: 4, revision: 1, resources: [
                "output.grand_master": .double(0.1),
            ]))
        )
        try store.apply(snapshot(epoch: 5, revision: 10, resources: [
            "output.grand_master": .double(0.3),
        ]))
        XCTAssertEqual(store.grandMaster, 0.3)
    }

    func layoutFOH() -> ACPRemoteLayout {
        ACPRemoteLayout(
            layoutID: "0193f8d8-4c4e-7d8b-a2ab-0000000000a0",
            revision: 1,
            showID: "0193f8d8-4c4e-7d8b-a2ab-000000000050",
            name: "FOH",
            controls: [
                ACPRemoteControl(controlID: "cue_go", label: "GO", controlType: "button", permission: "cue.execute", action: "cue.go"),
                ACPRemoteControl(controlID: "master", label: "Master", controlType: "slider", permission: "output.grand_master", action: "output.grand_master.set"),
                ACPRemoteControl(controlID: "fog", label: "Fog", controlType: "momentary", permission: "busk.execute", action: "busk.fog.output"),
            ]
        )
    }

    func testDuplicateGoSendsOnce() async throws {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        await remote.prepare(layout: layoutFOH())
        let id = "0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
        _ = try await remote.invoke(controlID: "cue_go", interaction: .activate, invocationID: id, wait: false)
        _ = try await remote.invoke(controlID: "cue_go", interaction: .activate, invocationID: id, wait: false)
        let sent = await remote.sentCount
        XCTAssertEqual(sent, 1)
    }

    func testStaleGoIsNotReplayedAfterDisconnect() async throws {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        await remote.prepare(layout: layoutFOH())
        let id = try await remote.invoke(controlID: "cue_go", interaction: .activate, wait: false)
        let pendingBefore = await remote.pendingInvocationIDs
        XCTAssertTrue(pendingBefore.contains(id))
        await remote.markDisconnected()
        let pendingAfter = await remote.pendingInvocationIDs
        XCTAssertFalse(pendingAfter.contains(id))
        let sent = await remote.sentCount
        await remote.prepare(layout: layoutFOH())
        let sentAfterReconnectPrep = await remote.sentCount
        XCTAssertEqual(sent, sentAfterReconnectPrep)
    }

    func testMomentaryEndWithoutLeaseFails() async {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        await remote.prepare(layout: layoutFOH())
        do {
            _ = try await remote.invoke(controlID: "fog", interaction: .momentaryEnd, invocationID: UUID().uuidString.lowercased(), wait: false)
            XCTFail("lease_id must be required")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "invalid_type")
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testLostMomentaryClearsLocalHold() async throws {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        await remote.prepare(layout: layoutFOH())
        let id = try await remote.invoke(controlID: "fog", interaction: .momentaryBegin, wait: false)
        await remote.applyAcknowledgement(
            invocationID: id,
            ack: ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "command.ack",
                source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .reliable,
                payload: [
                    "status": .string("applied"),
                    "result": .object(["lease_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000aa"), "active": .bool(true)]),
                ]
            )
        )
        let held = await remote.leases[id]
        XCTAssertEqual(held, "0193f8d8-4c4e-7d8b-a2ab-0000000000aa")
        await remote.markDisconnected()
        let cleared = await remote.leases
        XCTAssertTrue(cleared.isEmpty)
    }

    func testStaleLeaseIsNotReusedAfterNewBegin() async throws {
        let (ta, _) = await acpLinkedTransports()
        let session = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false, allowPlaintext: true)
        let remote = ACPRemoteSession(session: session, identity: sampleIdentity())
        await remote.prepare(layout: layoutFOH())
        let first = "0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
        _ = try await remote.invoke(controlID: "fog", interaction: .momentaryBegin, invocationID: first, wait: false)
        await remote.applyAcknowledgement(
            invocationID: first,
            ack: ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "command.ack",
                source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .reliable,
                payload: [
                    "status": .string("applied"),
                    "result": .object(["lease_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000aa"), "active": .bool(true)]),
                ]
            )
        )
        let oldLease = await remote.leases[first]
        let second = "0193f8d8-4c4e-7d8b-a2ab-0000000000d2"
        _ = try await remote.invoke(controlID: "fog", interaction: .momentaryBegin, invocationID: second, wait: false)
        await remote.applyAcknowledgement(
            invocationID: second,
            ack: ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "command.ack",
                source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .reliable,
                payload: [
                    "status": .string("applied"),
                    "result": .object(["lease_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000bb"), "active": .bool(true)]),
                ]
            )
        )
        let newLease = await remote.leases[second]
        XCTAssertNotEqual(oldLease, newLease)
        XCTAssertEqual(newLease, "0193f8d8-4c4e-7d8b-a2ab-0000000000bb")
    }

    func testReconnectDoesNotResendStatefulCommands() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let clientSession = ACPSession(
            transport: ta,
            local: ACPIdentity(role: "remote", name: "pad"),
            isServer: false,
            allowPlaintext: true
        )
        let server = ACPSession(
            transport: tb,
            local: ACPIdentity(role: "prism", name: "auth"),
            isServer: true,
            allowPlaintext: true
        )
        await server.setProfiles(["core", "remote", ACPRemoteProfileID.prismV1.rawValue])
        await server.setCapabilities(ACPCapabilitySet.prismRemoteProvider)
        let client = ACPRemoteClient(session: clientSession, identity: sampleIdentity())
        async let serverAck = server.handshake()
        try await client.handshake()
        _ = try await serverAck
        await client.commands.prepare(layout: layoutFOH())
        _ = try await client.commands.invoke(controlID: "master", interaction: .set, value: .double(0.8), wait: false)
        let sentBefore = await client.commands.sentCount
        await client.markInterrupted()
        try await client.resyncFromSnapshot(snapshot(epoch: 1, revision: 1, resources: [
            "output.grand_master": .double(0.4),
        ]))
        let sentAfter = await client.commands.sentCount
        XCTAssertEqual(sentBefore, sentAfter)
        let master = await client.state.grandMaster
        XCTAssertEqual(master, 0.4)
        await clientSession.goodbye()
        await server.goodbye()
    }
}
