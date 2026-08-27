import Foundation
import XCTest

final class ACPAppleDistributionPolicyTests: XCTestCase {
    func testSPAKE2ArtifactMatchesDocumentedArm64OnlyPolicy() throws {
        let tests = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let plist = tests.appendingPathComponent(
            "Artifacts/AuroraACPSPAKE2.xcframework/Info.plist")
        let value = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: plist), format: nil)
        let root = try XCTUnwrap(value as? [String: Any])
        let libraries = try XCTUnwrap(root["AvailableLibraries"] as? [[String: Any]])
        XCTAssertEqual(Set(libraries.compactMap { $0["LibraryIdentifier"] as? String }), [
            "macos-arm64", "ios-arm64", "ios-arm64-simulator",
        ])
        XCTAssertTrue(libraries.allSatisfy {
            ($0["SupportedArchitectures"] as? [String]) == ["arm64"]
        })
    }
}
