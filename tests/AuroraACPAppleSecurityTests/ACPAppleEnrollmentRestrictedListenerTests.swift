import AuroraACP
@testable import AuroraACPAppleSecurity
import XCTest

final class ACPAppleEnrollmentRestrictedListenerTests: XCTestCase {
    func testLoopbackListenerCreatesOnlyRestrictedConnection() async throws {
        let host = ACPSecurityNodeID(
            rawValue: "10213243-5465-4768-9a0b-1c2d3e4f5061")!
        let listener = try ACPAppleEnrollmentRestrictedListener(
            localNodeID: host,
            configuration: try .init(connectionTimeoutNanoseconds: 1_000_000_000))
        try await listener.start()
        let port = await listener.port
        let accept = Task { try await listener.accept() }
        let client = try await ACPFramedConnection.connect(
            host: "127.0.0.1", port: port, timeout: 2)
        let restricted = try await accept.value
        let handled = EnrollmentHandledFlag()
        let run = Task {
            try await restricted.run { envelope in
                await handled.set()
                XCTAssertEqual(envelope.type, "security.enrollment.cancel")
                return .init()
            }
        }
        try await client.send(try ACPEncoding.encodeCBOR(cancel(host: host)), text: false)
        try await run.value
        let wasHandled = await handled.read()
        XCTAssertTrue(wasHandled)
        await listener.shutdown()
    }

    func testCommissionerListenerRejectsInboundBeginDirection() async throws {
        let host = ACPSecurityNodeID(
            rawValue: "10213243-5465-4768-9a0b-1c2d3e4f5061")!
        let listener = try ACPAppleEnrollmentRestrictedListener(
            localNodeID: host,
            configuration: try .init(connectionTimeoutNanoseconds: 1_000_000_000))
        try await listener.start()
        let port = await listener.port
        let accept = Task { try await listener.accept() }
        let client = try await ACPFramedConnection.connect(
            host: "127.0.0.1", port: port, timeout: 2)
        let restricted = try await accept.value
        let run = Task {
            try await restricted.run { _ in
                XCTFail("inbound commissioner begin reached the handler")
                return .init()
            }
        }
        try await client.send(try ACPEncoding.encodeCBOR(begin(host: host)), text: false)
        do {
            try await run.value
            XCTFail("inbound commissioner begin was accepted")
        } catch {
            XCTAssertEqual(error as? ACPEnrollmentRestrictedError, .messageNotAllowed)
        }
        await listener.shutdown()
    }

    private func cancel(host: ACPSecurityNodeID) -> ACPEnvelope {
        ACPEnvelope(
            acp: "1.2", messageID: UUID().uuidString.lowercased(),
            type: "security.enrollment.cancel",
            source: .init(nodeID: "00112233-4455-4677-8899-aabbccddeeff"),
            destination: .init(nodeID: host.rawValue),
            timestampUTC: "2026-08-27T14:00:00.000Z", qos: .reliable,
            payload: [
                "enrollment_id": .string("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1"),
                "attempt_id": .string("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
                "reason": .string("operator_cancelled"),
            ])
    }


    private func begin(host: ACPSecurityNodeID) -> ACPEnvelope {
        ACPEnvelope(
            acp: "1.2", messageID: UUID().uuidString.lowercased(),
            type: "security.enrollment.begin",
            source: .init(nodeID: "00112233-4455-4677-8899-aabbccddeeff"),
            destination: .init(nodeID: host.rawValue),
            timestampUTC: "2026-08-27T14:00:00.000Z", qos: .reliable,
            payload: [
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
}

private actor EnrollmentHandledFlag {
    private var value = false
    func set() { value = true }
    func read() -> Bool { value }
}
