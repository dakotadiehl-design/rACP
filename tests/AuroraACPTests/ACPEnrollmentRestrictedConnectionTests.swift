import XCTest
@testable import AuroraACP

final class ACPEnrollmentRestrictedConnectionTests: XCTestCase {
    private let host = ACPSecurityNodeID(
        rawValue: "10213243-5465-4768-9a0b-1c2d3e4f5061")!

    func testCancelIsAdmittedAndTerminatesWithoutCreatingSession() async throws {
        let (server, client) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host)
        let handled = Counter()
        let task = Task {
            try await connection.run { envelope in
                await handled.increment()
                XCTAssertEqual(envelope.type, "security.enrollment.cancel")
                return .init()
            }
        }
        try await client.send(try ACPEncoding.encodeJSON(cancel()), text: true)
        try await task.value
        let handledCount = await handled.value
        XCTAssertEqual(handledCount, 1)
    }

    func testOrdinarySessionTrafficIsRejected() async throws {
        let (server, client) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host)
        let task = Task {
            try await connection.run { _ in
                XCTFail("ordinary session message reached handler")
                return .init()
            }
        }
        try await client.send(try ACPEncoding.encodeJSON(goodbye()), text: true)
        do {
            try await task.value
            XCTFail("ordinary session traffic was accepted")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .messageNotAllowed)
        }
    }

    func testMessageBoundClosesNonterminalConnection() async throws {
        let (server, client) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host, maximumMessages: 1)
        let task = Task {
            try await connection.run { _ in .init() }
        }
        try await client.send(try ACPEncoding.encodeJSON(begin()), text: true)
        do {
            try await task.value
            XCTFail("connection exceeded its message bound")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .resourceLimit)
        }
    }

    func testReceiveDeadlineClosesIdleConnection() async throws {
        let (server, _) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host, timeoutNanoseconds: 10_000_000)
        do {
            try await connection.run { _ in .init() }
            XCTFail("idle connection did not time out")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .timeout)
        }
    }

    func testResponseTypeSubstitutionFailsClosed() async throws {
        let (server, client) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host)
        let task = Task {
            try await connection.run { request in
                .init(response: self.cancel(correlationID: request.messageID))
            }
        }
        try await client.send(try ACPEncoding.encodeJSON(begin()), text: true)
        do {
            try await task.value
            XCTFail("substituted response type was sent")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .invalidSequence)
        }
    }

    func testResponseWithoutCorrelationFailsClosed() async throws {
        let (server, client) = await acpLinkedTransports()
        let connection = try ACPEnrollmentRestrictedConnection(
            transport: server, localNodeID: host)
        let task = Task {
            try await connection.run { _ in
                .init(response: self.challenge(correlationID: nil))
            }
        }
        try await client.send(try ACPEncoding.encodeJSON(begin()), text: true)
        do {
            try await task.value
            XCTFail("uncorrelated response was sent")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .invalidSequence)
        }
    }

    func testSecurityBinaryFieldsRoundTripAsBytesAcrossJSONAndCBOR() throws {
        let original = challenge(correlationID: UUID().uuidString.lowercased())
        for decoded in [
            try ACPEncoding.decodeJSON(ACPEncoding.encodeJSON(original)),
            try ACPEncoding.decodeCBOR(ACPEncoding.encodeCBOR(original)),
        ] {
            XCTAssertEqual(decoded.payload["identity_public_key"],
                           .bytes(Data(repeating: 2, count: 91)))
            XCTAssertEqual(decoded.payload["shareP"],
                           .bytes(Data(repeating: 3, count: 65)))
        }
    }

    private func begin() -> ACPEnvelope {
        envelope(type: "security.enrollment.begin", payload: [
            "enrollment_id": .string("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1"),
            "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
            "candidate_node_id": .string("00112233-4455-4677-8899-aabbccddeeff"),
            "commissioner_node_id": .string(host.rawValue),
            "commissioner_instance_id": .string("20314253-6475-4869-8a1b-2c3d4e5f6071"),
            "trust_domain_id": .string("40516273-8495-4a6b-8a3b-4c5d6e7f8091"),
            "suite": .string(ACPSecuritySuite.raw128.rawValue),
            "requested_role": .string("remote"),
            "requested_permissions_digest": .string(
                "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"),
        ])
    }

    private func cancel(correlationID: String? = nil) -> ACPEnvelope {
        envelope(type: "security.enrollment.cancel", correlationID: correlationID, payload: [
            "enrollment_id": .string("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1"),
            "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
            "reason": .string("operator_cancelled"),
        ])
    }


    private func challenge(correlationID: String?) -> ACPEnvelope {
        envelope(type: "security.enrollment.challenge", correlationID: correlationID, payload: [
            "enrollment_id": .string("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1"),
            "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
            "candidate_node_id": .string("00112233-4455-4677-8899-aabbccddeeff"),
            "candidate_instance_id": .string("30415263-7485-496a-8b2c-3d4e5f607182"),
            "commissioner_node_id": .string(host.rawValue),
            "commissioner_instance_id": .string("20314253-6475-4869-8a1b-2c3d4e5f6071"),
            "trust_domain_id": .string("40516273-8495-4a6b-8a3b-4c5d6e7f8091"),
            "suite": .string(ACPSecuritySuite.raw128.rawValue),
            "requested_role": .string("remote"),
            "requested_permissions_digest": .string(
                "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"),
            "identity_algorithm": .string("ecdsa_p256_sha256"),
            "identity_key_id": .string("sha256:" + String(repeating: "1", count: 64)),
            "identity_public_key": .bytes(Data(repeating: 2, count: 91)),
            "shareP": .bytes(Data(repeating: 3, count: 65)),
        ])
    }

    private func goodbye() -> ACPEnvelope {
        envelope(type: "session.goodbye", payload: ["reason": .string("done")])
    }

    private func envelope(type: String, correlationID: String? = nil,
                          payload: [String: AnySendable]) -> ACPEnvelope {
        ACPEnvelope(
            acp: "1.2", messageID: UUID().uuidString.lowercased(), type: type,
            source: .init(nodeID: "00112233-4455-4677-8899-aabbccddeeff"),
            destination: .init(nodeID: host.rawValue),
            timestampUTC: "2026-08-27T14:00:00.000Z", correlationID: correlationID,
            qos: type == "security.enrollment.status" ? .latest : .reliable,
            payload: payload)
    }
}

private actor Counter {
    private(set) var value = 0
    func increment() { value += 1 }
}
