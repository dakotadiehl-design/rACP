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
        XCTAssertEqual(ACPRemoteInteraction.momentaryBegin.rawValue, "momentary_begin")
    }
}
