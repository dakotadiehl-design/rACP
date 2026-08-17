import XCTest
@testable import ACPModel

final class ACPModelTests: XCTestCase {
    func testProtocolVersion() {
        XCTAssertEqual(ACPModel.protocolVersion, "1.2")
    }
}
