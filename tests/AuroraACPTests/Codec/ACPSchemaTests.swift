import XCTest
@testable import AuroraACP

final class ACPSchemaTests: XCTestCase {
    func invokeEnvelope(
        interaction: String,
        leaseID: String? = nil,
        controlID: String = "fog_burst"
    ) -> Data {
        var payload: [String: Any] = [
            "control_id": controlID,
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
            "interaction": interaction,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
        ]
        if let leaseID {
            payload["lease_id"] = leaseID
        }
        let env: [String: Any] = [
            "acp": "1.2",
            "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000042",
            "type": "remote.control.invoke",
            "source": ["node_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"],
            "timestamp_utc": "2026-08-17T16:42:15.231Z",
            "qos": "reliable",
            "flags": [] as [String],
            "payload": payload,
        ]
        return try! JSONSerialization.data(withJSONObject: env)
    }

    func testMomentaryEndWithLeaseSucceeds() throws {
        _ = try ACPEncoding.decodeJSON(invokeEnvelope(
            interaction: "momentary_end",
            leaseID: "0193f8d8-4c4e-7d8b-a2ab-0000000000aa"
        ))
    }

    func testMomentaryEndWithoutLeaseFails() {
        XCTAssertThrowsError(try ACPEncoding.decodeJSON(invokeEnvelope(interaction: "momentary_end"))) { error in
            XCTAssertTrue(String(describing: error).contains("invalid_type"), "\(error)")
        }
    }

    func testActivateWithoutLeaseSucceeds() throws {
        _ = try ACPEncoding.decodeJSON(invokeEnvelope(interaction: "activate"))
    }

    func testMomentaryCancelWithLeaseSucceeds() throws {
        _ = try ACPEncoding.decodeJSON(invokeEnvelope(
            interaction: "momentary_cancel",
            leaseID: "0193f8d8-4c4e-7d8b-a2ab-0000000000aa"
        ))
    }

    func testIfThenElseSyntheticSchema() throws {
        let schema: [String: Any] = [
            "if": [
                "properties": ["kind": ["enum": ["a"]]],
                "required": ["kind"],
            ],
            "then": ["required": ["alpha"]],
            "else": ["required": ["beta"]],
        ]
        try ACPSchema.validateInstance(["kind": "a", "alpha": 1], schema: schema)
        XCTAssertThrowsError(try ACPSchema.validateInstance(["kind": "a"], schema: schema))
        try ACPSchema.validateInstance(["kind": "b", "beta": 1], schema: schema)
        XCTAssertThrowsError(try ACPSchema.validateInstance(["kind": "b"], schema: schema))
    }

    func testConstKeywordIsEnforced() throws {
        try ACPSchema.validateInstance("lyric.chart", schema: ["const": "lyric.chart"])
        XCTAssertThrowsError(try ACPSchema.validateInstance("other", schema: ["const": "lyric.chart"]))
        let url = RepoRoot.url()
            .appendingPathComponent("vectors/invalid/chart.metadata-bad-asset-type.json")
        let data = try Data(contentsOf: url)
        XCTAssertThrowsError(try ACPEncoding.decodeJSON(data)) { error in
            XCTAssertTrue(String(describing: error).contains("invalid_type"), "\(error)")
        }
    }
}
