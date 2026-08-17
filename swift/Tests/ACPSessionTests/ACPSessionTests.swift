import Foundation
import XCTest
import ACPModel
import ACPEncoding
import ACPSession

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
}
