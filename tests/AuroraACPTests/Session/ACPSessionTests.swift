import Foundation
import XCTest
import AuroraACP

final class ACPSessionTests: XCTestCase {
    func testHandshakePeerRole() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        let server = ACPSession(transport: tb, local: ACPIdentity(role: "bridge", name: "b"), isServer: true)
        async let serverAck = server.handshake()
        let _ = try await client.handshake()
        _ = try await serverAck
        let peer = await client.peer
        XCTAssertEqual(peer?.role, "bridge")
        let state = await client.state
        XCTAssertEqual(state, .established)
        await client.goodbye()
        await server.goodbye()
    }

    func testAssignRequiresEstablished() async {
        let (ta, _) = await acpLinkedTransports()
        let s = ACPSession(transport: ta, local: ACPIdentity(role: "tool", name: "t"), isServer: false)
        do {
            _ = try await s.assignSequence(
                // compile-only: assign before handshake
                ACPEnvelope(
                    acp: "1.2",
                    messageID: "0193f8d8-4c4e-7d8b-a2ab-000000000002",
                    type: "session.goodbye",
                    source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
                    timestampUTC: "2026-08-17T16:42:15.231Z",
                    qos: .bestEffort
                )
            )
            XCTFail("expected throw")
        } catch {
            // expected
        }
    }

    func testSecondSequenceGapFails() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        let server = ACPSession(transport: tb, local: ACPIdentity(role: "bridge", name: "b"), isServer: true)
        async let serverAck = server.handshake()
        _ = try await client.handshake()
        _ = try await serverAck
        let sid = await client.sessionID
        let peer = await client.peer
        XCTAssertNotNil(sid)
        XCTAssertNotNil(peer)

        func heartbeat(_ seq: UInt64) -> ACPEnvelope {
            ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "health.heartbeat",
                source: ACPEndpoint(nodeID: peer!.nodeID),
                sessionID: sid,
                sequence: seq,
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .latest,
                payload: ["uptime_ms": .int(1), "status": .string("ok")]
            )
        }

        try await tb.send(try ACPEncoding.encodeCBOR(heartbeat(2)))
        _ = try await client.pumpOnce()
        try await tb.send(try ACPEncoding.encodeCBOR(heartbeat(5)))
        do {
            _ = try await client.pumpOnce()
            XCTFail("second gap should fail")
        } catch {
            let state = await client.state
            XCTAssertEqual(state, .failed)
        }
        await client.goodbye()
        await server.goodbye()
    }

    func testNegotiatesRemoteProfiles() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false)
        let server = ACPSession(transport: tb, local: ACPIdentity(role: "conductor", name: "auth"), isServer: true)
        await client.setProfiles(["core", "remote", "aurora.remote.prism.v1"])
        await server.setProfiles(["core", "remote", "aurora.remote.prism.v1"])
        async let serverAck = server.handshake()
        _ = try await client.handshake()
        _ = try await serverAck
        let profiles = await client.negotiatedProfiles
        XCTAssertTrue(profiles.contains("aurora.remote.prism.v1"))
        await client.goodbye()
        await server.goodbye()
    }

    func testRequestMatchesRegistryResponse() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "remote", name: "pad"), isServer: false)
        let server = ACPSession(transport: tb, local: ACPIdentity(role: "conductor", name: "auth"), isServer: true)
        async let serverAck = server.handshake()
        _ = try await client.handshake()
        _ = try await serverAck
        let destID = await client.peer?.nodeID
        let localID = await client.local.nodeID
        let req = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "state.request",
            source: ACPEndpoint(nodeID: localID),
            destination: destID.map { ACPEndpoint(nodeID: $0) },
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: ["resources": .array([])]
        )
        async let reply = client.request(req, timeout: 2)
        let inbound = try await server.pumpOnce()
        XCTAssertEqual(inbound?.type, "state.request")
        if let inbound {
            _ = try await server.send(ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "state.snapshot",
                source: ACPEndpoint(nodeID: server.local.nodeID),
                destination: ACPEndpoint(nodeID: inbound.source.nodeID),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                correlationID: inbound.correlationID ?? inbound.messageID,
                qos: .reliable,
                payload: ["resources": .array([])]
            ))
        }
        let ack = try await reply
        XCTAssertEqual(ack.type, "state.snapshot")
        await client.goodbye()
        await server.goodbye()
    }

    func testRejectsDisjointProtocolAndEncoding() async throws {
        let (ta, tb) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        let server = ACPSession(transport: tb, local: ACPIdentity(role: "bridge", name: "b"), isServer: true)
        await client.setHandshakeTimeout(0.4)
        await server.setHandshakeTimeout(0.4)
        await client.setProtocolRange(min: "1.0", max: "1.0")
        await server.setProtocolRange(min: "1.2", max: "1.2")
        async let serverAck = server.handshake()
        do {
            _ = try await client.handshake()
            XCTFail("expected protocol reject")
        } catch {
            let state = await client.state
            XCTAssertEqual(state, .failed)
        }
        _ = try? await serverAck
        await client.goodbye()
        await server.goodbye()

        let (tc, td) = await acpLinkedTransports()
        let c2 = ACPSession(transport: tc, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        let s2 = ACPSession(transport: td, local: ACPIdentity(role: "bridge", name: "b"), isServer: true)
        await c2.setHandshakeTimeout(0.4)
        await s2.setHandshakeTimeout(0.4)
        await c2.setEncodings(["json"])
        await s2.setEncodings(["cbor"])
        async let s2ack = s2.handshake()
        do {
            _ = try await c2.handshake()
            XCTFail("expected encoding reject")
        } catch {
            let state = await c2.state
            XCTAssertEqual(state, .failed)
        }
        _ = try? await s2ack
        await c2.goodbye()
        await s2.goodbye()
    }

    func testApplyHelloAckRequiresFields() async throws {
        let (ta, _) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "session.hello_ack",
            source: ACPEndpoint(nodeID: "0193f8d8-4c4e-7d8b-a2ab-000000000001"),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: ["accepted": .bool(true), "session_id": .string("0193f8d8-4c4e-7d8b-a2ab-000000000013")]
        )
        do {
            try await client.applyHelloAck(ack)
            XCTFail("missing fields")
        } catch {
            // expected
        }
    }

    func testFramedAcceptAndHandshakeTimeoutsAreBounded() async throws {
        let listener = try ACPFramedListener(port: 0)
        try await listener.start(timeout: 2)
        let start = Date()
        do {
            _ = try await listener.accept(timeout: 0.3)
            XCTFail("expected accept timeout")
        } catch {
            XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        }
        await listener.cancel()
    }

    func testFramedHandshakeTimeoutClosesSession() async throws {
        let listener = try ACPFramedListener(port: 0)
        try await listener.start(timeout: 2)
        let port = await listener.port
        async let inbound = listener.accept(timeout: 2)
        let transport = try await ACPFramedConnection.connect(host: "127.0.0.1", port: port, timeout: 2)
        _ = try await inbound
        let client = ACPSession(transport: transport, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        await client.setHandshakeTimeout(0.4)
        let start = Date()
        do {
            _ = try await client.handshake()
            XCTFail("expected handshake timeout")
        } catch {
            XCTAssertLessThan(Date().timeIntervalSince(start), 2)
            let state = await client.state
            XCTAssertEqual(state, .failed)
        }
        await listener.cancel()
    }

    func testHandshakeTimeoutIsBounded() async throws {
        let (ta, _) = await acpLinkedTransports()
        let client = ACPSession(transport: ta, local: ACPIdentity(role: "conductor", name: "c"), isServer: false)
        await client.setHandshakeTimeout(0.3)
        let start = Date()
        do {
            _ = try await client.handshake()
            XCTFail("expected timeout")
        } catch {
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertLessThan(elapsed, 2)
            let state = await client.state
            XCTAssertEqual(state, .failed)
        }
    }
}
