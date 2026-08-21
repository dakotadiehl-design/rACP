import XCTest
@testable import AuroraACP

final class ACPReadinessTests: XCTestCase {
    let node = "0193f8d8-4c4e-7d8b-a2ab-000000000001"
    let command = "0193f8d8-4c4e-7d8b-a2ab-000000000099"

    func testSnapshotDeltaEpochRecovery() throws {
        let payload = ACPStateRevision.deltaPayload(
            authorityEpoch: 3,
            baseRevision: 9,
            revision: 10,
            changes: []
        )
        let next = try ACPStateRevision.applyDelta(localEpoch: 3, localRevision: 9, payload: payload)
        XCTAssertEqual(next.0, 3)
        XCTAssertEqual(next.1, 10)
        XCTAssertThrowsError(try ACPStateRevision.applyDelta(localEpoch: 1, localRevision: 9, payload: payload))
    }

    func testPreconditionsRejectStaleCue() {
        XCTAssertThrowsError(
            try ACPStateRevision.evaluatePreconditions(
                [ACPPrecondition(op: "equals", field: "current_cue_id", value: .string("cue-a"))],
                authorityEpoch: 1,
                revision: 4,
                currentCueID: "cue-b"
            )
        )
    }

    func testEpochPreconditionTreatsJSONSignedAndUnsignedValuesEqually() throws {
        try ACPStateRevision.evaluatePreconditions(
            [ACPPrecondition(op: "equals", field: "authority_epoch", value: .int(7))],
            authorityEpoch: 7,
            revision: 1
        )
    }

    func testCommandLedgerHidesOtherPrincipalsAndSurvivesSessionReplace() async throws {
        let ledger = ACPCommandLedger()
        let first = try await ledger.remember(ACPCommandRecord(
            commandID: command,
            originNodeID: node,
            originInstanceID: node,
            operation: "performance.go",
            disposition: "applied",
            originPrincipal: "alice",
            originSessionID: "session-1",
            resultingEpoch: 1,
            resultingRevision: 2
        ))
        let found = await ledger.lookup(originNodeID: node, commandID: command, originPrincipal: "alice")
        XCTAssertEqual(found, first)
        let hidden = await ledger.lookup(originNodeID: node, commandID: command, originPrincipal: "bob")
        XCTAssertNil(hidden)
        let again = try await ledger.remember(ACPCommandRecord(
            commandID: command,
            originNodeID: node,
            originInstanceID: node,
            operation: "performance.go",
            disposition: "applied",
            originPrincipal: "alice",
            originSessionID: "session-2"
        ))
        XCTAssertEqual(again.originSessionID, "session-1")
    }

    func testCommandLedgerAtomicallyReservesAndCompletesOnce() async throws {
        let ledger = ACPCommandLedger()
        let reservation = ACPCommandRecord(
            commandID: command,
            originNodeID: node,
            originInstanceID: node,
            operation: "performance.go",
            disposition: "in_flight",
            idempotencyKey: command,
            originPrincipal: "alice",
            fingerprint: "go|epoch=1|cue=cue-a"
        )
        guard case .reserved = await ledger.reserve(reservation) else {
            return XCTFail("first request must reserve")
        }
        guard case .existing(let duplicate) = await ledger.reserve(reservation) else {
            return XCTFail("duplicate must observe the reservation")
        }
        XCTAssertEqual(duplicate.disposition, "in_flight")

        var terminal = reservation
        terminal.disposition = "applied"
        terminal.resultingEpoch = 1
        terminal.resultingRevision = 8
        let completed = try await ledger.complete(terminal)
        XCTAssertEqual(completed.disposition, "applied")
        XCTAssertEqual(completed.resultingRevision, 8)
        guard case .existing(let replay) = await ledger.reserve(reservation) else {
            return XCTFail("replay must return the terminal disposition")
        }
        XCTAssertEqual(replay.disposition, "applied")
    }

    func testCommandLedgerRejectsSameIdentityWithDifferentFingerprint() async {
        let ledger = ACPCommandLedger()
        let first = ACPCommandRecord(
            commandID: command,
            originNodeID: node,
            originInstanceID: node,
            operation: "performance.go",
            disposition: "in_flight",
            originPrincipal: "alice",
            fingerprint: "cue-a"
        )
        guard case .reserved = await ledger.reserve(first) else {
            return XCTFail("first request must reserve")
        }
        var changed = first
        changed.fingerprint = "cue-b"
        guard case .conflict = await ledger.reserve(changed) else {
            return XCTFail("changed request must conflict")
        }
    }

    func testCommandLedgerNeverEvictsInflightAndRequiresFingerprint() async throws {
        let ledger = ACPCommandLedger(maxRecords: 1)
        let first = ACPCommandRecord(
            commandID: command,
            originNodeID: node,
            originInstanceID: node,
            operation: "performance.go",
            disposition: "in_flight",
            originPrincipal: "alice",
            fingerprint: "go-a"
        )
        guard case .reserved = await ledger.reserve(first) else { return XCTFail("must reserve") }
        var second = first
        second.commandID = "0193f8d8-4c4e-7d8b-a2ab-000000000098"
        second.idempotencyKey = nil
        second.fingerprint = "go-b"
        guard case .unavailable = await ledger.reserve(second) else {
            return XCTFail("must backpressure instead of evicting in-flight")
        }
        var missing = second
        missing.fingerprint = nil
        guard case .conflict = await ledger.reserve(missing) else {
            return XCTFail("fingerprint-less mutation must fail closed")
        }
        var invalidCompletion = first
        invalidCompletion.disposition = "accepted"
        do {
            _ = try await ledger.complete(invalidCompletion)
            XCTFail("nonterminal completion must fail")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "invalid_type")
        }
    }

    func testPriorityNeverCoalescesGo() {
        var q = ACPPriorityQueue()
        XCTAssertTrue(q.push(ACPOutboundItem(
            trafficClass: .interactive,
            payload: .string("go"),
            coalescingKey: "go",
            delivery: "latest_value_wins",
            action: "performance.go"
        )))
        XCTAssertTrue(q.push(ACPOutboundItem(
            trafficClass: .state,
            payload: .int(1),
            coalescingKey: "prism.output.master",
            delivery: "latest_value_wins"
        )))
        XCTAssertTrue(q.push(ACPOutboundItem(
            trafficClass: .state,
            payload: .int(2),
            coalescingKey: "prism.output.master",
            delivery: "latest_value_wins"
        )))
        XCTAssertEqual(q.pop()?.action, "performance.go")
        XCTAssertEqual(q.pop()?.payload, .int(2))
    }

    func testDiscoveryTXTDoesNotCarryCredentials() {
        let endpoint = ACPDiscoveryEndpoint(
            nodeID: node,
            instanceID: node,
            role: "prism",
            name: "Prism",
            endpointURL: "ws://127.0.0.1:27421/acp"
        )
        let txt = endpoint.bonjourTXT
        XCTAssertNil(txt["pin"])
        XCTAssertNil(txt["token"])
        XCTAssertEqual(txt["url"], endpoint.endpointURL)
        XCTAssertEqual(ACPDiscoveryEndpoint.fromBonjourTXT(txt)?.nodeID, node)
        XCTAssertEqual(ACPDiscoveryEndpoint.bonjourServiceType, "_acp._tcp")
    }

    func testCommandStatusVectorsValidate() throws {
        let root = RepoRoot.url()
        for name in ["command.status_request", "command.status_report"] {
            let data = try Data(contentsOf: root.appendingPathComponent("vectors/json/\(name).json"))
            let env = try ACPEncoding.decodeJSON(data)
            XCTAssertEqual(env.type, name)
        }
        let snap = try ACPEncoding.decodeJSON(
            Data(contentsOf: root.appendingPathComponent("vectors/json/state.snapshot.json"))
        )
        XCTAssertEqual(snap.payload["authority_epoch"], .int(1))
    }

    func testWebSocketListenerStartsAndStops() async throws {
        let bound = try ACPWebSocketListener(port: 27431)
        try await bound.start()
        await bound.stop()
        do {
            try await bound.start(timeout: 0.1)
            XCTFail("listener restart must be explicitly rejected")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "conflict")
        }
    }

    func testWebSocketLoopbackRoundTrip() async throws {
        let port = UInt16.random(in: 29100...29299)
        let listener = try ACPWebSocketListener(port: port, loopbackOnly: true)
        try await listener.start()
        let bound = await listener.port ?? port
        async let accepted = listener.accept(timeout: 8)
        let client = try await ACPWebSocketConnection.connect(host: "127.0.0.1", port: bound, timeout: 8)
        let server = try await accepted
        let payload = Data("acp-ws".utf8)
        try await client.send(payload, text: true)
        let received = try await server.recv()
        XCTAssertEqual(received.0, payload)
        XCTAssertTrue(received.1)
        await client.close()
        await server.close()
        await listener.stop()
    }

    func testWebSocketAcceptTimeoutDoesNotStealNextConnection() async throws {
        let listener = try ACPWebSocketListener(port: 0, loopbackOnly: true)
        try await listener.start()
        let advertisedPort = await listener.port
        let port = try XCTUnwrap(advertisedPort)
        let started = Date()
        do {
            _ = try await listener.accept(timeout: 0.05)
            XCTFail("expected timeout")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "timeout")
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)

        async let accepted = listener.accept(timeout: 2)
        let client = try await ACPWebSocketConnection.connect(host: "127.0.0.1", port: port, timeout: 2)
        let server = try await accepted
        try await client.send(Data("next".utf8), text: true)
        let received = try await server.recv()
        XCTAssertEqual(received.0, Data("next".utf8))
        await client.close()
        await server.close()
        await listener.stop()
    }
}
