import XCTest
@testable import AuroraACP

final class ACPRemoteSurfaceTests: XCTestCase {
    func sampleSurface(
        extraControl: [String: AnySendable]? = nil,
        sha256: String? = nil,
        minSchema: String = "1.0",
        maxSchema: String = "1.0",
        script: Bool = false
    ) -> [String: AnySendable] {
        var control: [String: AnySendable] = [
            "control_id": .string("go"),
            "label": .string("GO"),
            "control_type": .string("button"),
            "permission": .string("cue.execute"),
            "binding": .object([
                "target": .string("prism"),
                "action": .string("cue.go"),
            ]),
        ]
        if script {
            control["script"] = .string("alert(1)")
        }
        var controls: [AnySendable] = [.object(control)]
        if let extraControl {
            controls.append(.object(extraControl))
        }
        var object: [String: AnySendable] = [
            "surface_id": .string("0193f8d8-4c4e-7d8b-a2ab-0000000000a0"),
            "revision": .uint(1),
            "schema_version": .string("1.0"),
            "min_client_schema": .string(minSchema),
            "max_client_schema": .string(maxSchema),
            "compatible_profile": .string("aurora.remote.prism.v1"),
            "show_id": .string("0193f8d8-4c4e-7d8b-a2ab-000000000050"),
            "name": .string("FOH"),
            "pages": .array([
                .object([
                    "page_id": .string("main"),
                    "title": .string("Live"),
                    "groups": .array([
                        .object([
                            "group_id": .string("live"),
                            "controls": .array([.string("go")]),
                        ]),
                    ]),
                ]),
            ]),
            "controls": .array(controls),
        ]
        object["sha256"] = .string(sha256 ?? ACPRemoteSurfaceValidator.fingerprint(object))
        return object
    }

    func testHashMismatchRejected() {
        let object = sampleSurface(sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        if case .rejected(let reason) = ACPRemoteSurfaceValidator.evaluate(object) {
            XCTAssertEqual(reason, "hash_mismatch")
        } else {
            XCTFail("expected hash mismatch")
        }
    }

    func testUnknownControlTypeDoesNotExecuteAndKeepsSiblings() {
        let extra: [String: AnySendable] = [
            "control_id": .string("future"),
            "label": .string("Future"),
            "control_type": .string("hologram_well"),
            "binding": .object([
                "target": .string("prism"),
                "action": .string("cue.go"),
            ]),
        ]
        let object = sampleSurface(extraControl: extra)
        guard case .accepted(let layout, let skipped) = ACPRemoteSurfaceValidator.evaluate(object) else {
            return XCTFail("unknown control type must not reject the surface")
        }
        XCTAssertEqual(skipped, ["future"])
        XCTAssertEqual(layout.control("go")?.action, "cue.go")
        XCTAssertFalse(ACPRemoteSurfaceValidator.isInvocable(layout.control("future")!))
        XCTAssertTrue(ACPRemoteSurfaceValidator.isInvocable(layout.control("go")!))
    }

    func testExecutableSurfaceRejected() {
        let object = sampleSurface(script: true)
        if case .rejected(let reason) = ACPRemoteSurfaceValidator.evaluate(object) {
            XCTAssertEqual(reason, "executable surface payload")
        } else {
            XCTFail("expected executable rejection")
        }
    }

    func testIncompatibleClientSchemaRejected() {
        let object = sampleSurface(minSchema: "9.0", maxSchema: "9.0")
        if case .rejected(let reason) = ACPRemoteSurfaceValidator.evaluate(object) {
            XCTAssertEqual(reason, "incompatible surface schema")
        } else {
            XCTFail("expected schema incompatibility")
        }
    }

    func testPermissionDenialIsExplicit() {
        let control = ACPRemoteControl(
            controlID: "go",
            label: "GO",
            controlType: "button",
            permission: "cue.execute",
            action: "cue.go"
        )
        XCTAssertEqual(control.permission, ACPRemotePermission.cueExecute.rawValue)
        XCTAssertNotEqual(control.permission, ACPRemoteRole.viewer.rawValue)
    }

    func testRejectedSurfaceLeavesNativeControlsAvailable() async throws {
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
        let client = ACPRemoteClient(
            session: clientSession,
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
        async let serverAck = server.handshake()
        try await client.handshake()
        _ = try await serverAck
        do {
            try await client.activateSurface(sampleSurface(script: true))
            XCTFail("unsafe surface must be rejected")
        } catch let error as ACPSessionError {
            XCTAssertEqual(error.code, "remote.layout.incompatible")
        }
        let native = await client.nativeControlsAvailable
        XCTAssertTrue(native)
        let song = await client.nativeActionAvailable(.showSongSelect)
        let go = await client.nativeActionAvailable(.cueGo)
        let master = await client.nativeActionAvailable(.outputGrandMasterSet)
        let blackout = await client.nativeActionAvailable(.outputBlackoutSet)
        XCTAssertTrue(song && go && master && blackout)
        let surface = await client.activatedSurface
        XCTAssertNil(surface)
        let sessionState = await clientSession.state
        XCTAssertEqual(sessionState, .established)
        await clientSession.goodbye()
        await server.goodbye()
    }
}
