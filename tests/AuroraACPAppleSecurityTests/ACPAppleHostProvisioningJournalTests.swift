import AuroraACP
@testable import AuroraACPAppleSecurity
import XCTest

final class ACPAppleHostProvisioningJournalTests: XCTestCase {
    func testReserveIsIdempotentAndNodeBound() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let node = ACPSecurityNodeID(
            rawValue: "00112233-4455-4677-8899-aabbccddeeff")!

        let first = try fixture.journal.loadOrReserve(nodeID: node)
        let reopened = try fixture.journal.loadOrReserve(nodeID: node)

        XCTAssertEqual(first, reopened)
        XCTAssertEqual(first.phase, .reserved)
        XCTAssertThrowsError(try fixture.journal.loadOrReserve(nodeID: ACPSecurityNodeID(
            rawValue: "10112233-4455-4677-8899-aabbccddeeff")!)) { error in
                XCTAssertEqual(error as? ACPAppleHostProvisioningError, .corruptState)
            }
    }

    func testJournalRejectsSkippedTransitionAndRotatesOnlyAuthorityAttempt() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let node = ACPSecurityNodeID(
            rawValue: "00112233-4455-4677-8899-aabbccddeeff")!
        let reserved = try fixture.journal.loadOrReserve(nodeID: node)

        XCTAssertThrowsError(try fixture.journal.advance(reserved, to: .identityActive))
        XCTAssertThrowsError(try fixture.journal.rotateAttempt(reserved))
    }

    func testCorruptPersistedJournalFailsClosed() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let node = ACPSecurityNodeID(
            rawValue: "00112233-4455-4677-8899-aabbccddeeff")!
        _ = try fixture.journal.loadOrReserve(nodeID: node)
        try fixture.backend.write(name: "host-provisioning", data: Data("{}".utf8))

        XCTAssertThrowsError(try fixture.journal.load()) { error in
            XCTAssertEqual(error as? ACPAppleHostProvisioningError, .corruptState)
        }
    }
}

private struct Fixture {
    let service: String
    let journal: ACPAppleHostProvisioningJournal
    let backend: ACPKeychainCredentialBackend

    init() throws {
        service = "com.aurora.acp.host-journal-test.\(UUID().uuidString.lowercased())"
        journal = try ACPAppleHostProvisioningJournal(service: service)
        backend = ACPKeychainCredentialBackend(service: service)
    }

    func cleanup() {
        try? backend.delete(name: "host-provisioning")
    }
}
