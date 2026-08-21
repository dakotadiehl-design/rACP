import XCTest
@testable import AuroraACP

final class ACPModelTests: XCTestCase {
    func testProtocolVersion() {
        XCTAssertEqual(ACPModel.protocolVersion, "1.2")
    }

    func testRemoteLayoutLookup() {
        let layout = ACPRemoteLayout(
            layoutID: "l",
            revision: 1,
            showID: "s",
            name: "FOH",
            controls: [ACPRemoteControl(controlID: "go", label: "GO", controlType: "button", permission: "remote.operator", action: "cue.go")]
        )
        XCTAssertEqual(layout.control("go")?.action, "cue.go")
        XCTAssertEqual(layout.surfaceID, "l")
        XCTAssertEqual(layout.layoutID, layout.surfaceID)
        XCTAssertEqual(ACPRemoteInteraction.momentaryBegin.rawValue, "momentary_begin")
    }

    func testTypedRemoteVocabulary() {
        XCTAssertEqual(ACPRemoteProfileID.prismV1.rawValue, "aurora.remote.prism.v1")
        XCTAssertEqual(ACPRemoteProfileID.conductorV1.rawValue, "aurora.remote.conductor.v1")
        XCTAssertTrue(ACPRemoteProfileID.conductorV1.isReserved)
        XCTAssertEqual(ACPRemotePermission.cueExecute.rawValue, "cue.execute")
        XCTAssertTrue(ACPRemotePermission(rawValue: "future.perm").isKnown == false)
        XCTAssertTrue(ACPRemoteControlType.slider.isKnown)
        XCTAssertFalse(ACPRemoteControlType(rawValue: "hologram_well").isKnown)
        XCTAssertTrue(ACPRemoteAction.showSongStop.isAllowlisted)
        XCTAssertTrue(ACPRemoteAction.effectsStop.isAllowlisted)
        XCTAssertEqual(ACPRemoteAction.cueGo.delivery, "live_ephemeral")
        XCTAssertEqual(ACPRemoteAction.buskFogOutput.delivery, "live_ephemeral")
        XCTAssertEqual(ACPRemoteAction.outputGrandMasterSet.delivery, "stateful")
        XCTAssertEqual(ACPRemoteAction.navSongSelect.delivery, "stateful")
        XCTAssertFalse(ACPRemoteAction(rawValue: "prism.internal.setChannel").isAllowlisted)
    }

    func testDecodesSchemaShapedSurfaceAndControl() {
        let payload: [String: AnySendable] = [
            "surface_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000a0"),
            "revision": .uint(8),
            "schema_version": .string("1.0"),
            "min_client_schema": .string("1.0"),
            "max_client_schema": .string("1.0"),
            "compatible_profile": .string("aurora.remote.prism.v1"),
            "show_id": .string("0193f8d8-4c4e-7d8b-a2ab-000000000050"),
            "name": .string("FOH"),
            "sha256": .string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "pages": .array([
                .object([
                    "page_id": .string("main"),
                    "title": .string("Live"),
                    "groups": .array([
                        .object([
                            "group_id": .string("live"),
                            "controls": .array([.string("master")]),
                        ]),
                    ]),
                ]),
            ]),
            "controls": .array([
                .object([
                    "control_id": .string("master"),
                    "label": .string("Master"),
                    "accessibility_label": .string("Grand master"),
                    "accessibility_hint": .string("Sets house intensity"),
                    "control_type": .string("slider"),
                    "permission": .string("output.grand_master"),
                    "delivery": .string("stateful"),
                    "traffic_class": .string("state"),
                    "feedback": .string("state"),
                    "style": .string("primary"),
                    "min": .double(0),
                    "max": .double(1),
                    "step": .double(0.01),
                    "units": .string("percent"),
                    "availability_binding": .string("output.grand_master"),
                    "binding": .object([
                        "target": .string("prism"),
                        "action": .string("output.grand_master.set"),
                        "parameters": .object(["value": .double(0.75)]),
                    ]),
                    "safety": .object([
                        "class": .string("caution"),
                        "failsafe": .string("hold_last_state"),
                        "failsafe_required": .bool(false),
                        "max_hold_ms": .uint(0),
                    ]),
                ]),
            ]),
        ]
        guard let layout = ACPRemoteLayout.from(payload) else {
            return XCTFail("expected schema-shaped surface to decode")
        }
        XCTAssertEqual(layout.surfaceID, "0193f8d8-4c4e-7d8b-a2ab-0000000000a0")
        XCTAssertEqual(layout.layoutID, layout.surfaceID)
        XCTAssertEqual(layout.compatibleProfile, ACPRemoteProfileID.prismV1.rawValue)
        XCTAssertEqual(layout.pages.first?.groups.first?.controls, ["master"])
        let control = layout.control("master")
        XCTAssertEqual(control?.binding.target, "prism")
        XCTAssertEqual(control?.binding.action, "output.grand_master.set")
        XCTAssertEqual(control?.action, "output.grand_master.set")
        XCTAssertEqual(control?.min, 0)
        XCTAssertEqual(control?.max, 1)
        XCTAssertEqual(control?.accessibilityLabel, "Grand master")
        XCTAssertEqual(control?.safety.safetyClass, "caution")
    }

    func testLayoutIdAliasStillDecodes() {
        let payload: [String: AnySendable] = [
            "layout_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000a0"),
            "revision": .int(2),
            "show_id": .string("0193f8d8-4c4e-7d8b-a2ab-000000000050"),
            "name": .string("Legacy"),
            "controls": .array([
                .object([
                    "control_id": .string("go"),
                    "label": .string("GO"),
                    "control_type": .string("button"),
                    "binding": .object([
                        "target": .string("prism"),
                        "action": .string("cue.go"),
                    ]),
                ]),
            ]),
        ]
        XCTAssertEqual(ACPRemoteLayout.from(payload)?.layoutID, "0193f8d8-4c4e-7d8b-a2ab-0000000000a0")
    }
}
