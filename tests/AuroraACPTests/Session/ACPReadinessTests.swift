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
    }
}
