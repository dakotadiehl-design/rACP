import AuroraACP
@testable import AuroraACPAppleSecurity
import XCTest

final class ACPAppleEnrollmentBootstrapTests: XCTestCase {
    func testRAW128RegistrationMatchesFrozenCrossLanguageVector() throws {
        let password = Data([
            0x00, 0xff, 0x80, 0x7f, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ])
        let result = try ACPAppleEnrollmentBootstrap.registrationRecord(
            secret: .highEntropyCode(crockford(password)),
            enrollmentID: ACPEnrollmentID(rawValue:
                "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1")!,
            candidateNodeID: ACPSecurityNodeID(rawValue:
                "00112233-4455-4677-8899-aabbccddeeff")!,
            commissionerNodeID: ACPSecurityNodeID(rawValue:
                "10213243-5465-4768-9a0b-1c2d3e4f5061")!)
        defer { result.record.clear() }

        XCTAssertEqual(result.suite, .raw128)
        let recordHex = result.record.withUnsafeBytes {
            Data($0).map { String(format: "%02x", $0) }.joined()
        }
        XCTAssertEqual(recordHex,
            "ef98bb660c071b67b43df14ba429f9a8fd9a65ca15dc648f64c545ffcc7bdd51"
            + "0437a46cecbd4bbfeb4aadc21b036dc2f6170695f228ab5442baac3ad3eaf137e"
            + "876458ccc2747da78df575c1ab9dd1fcc88c0a237cde82c957d58b3b03c0875db")
    }

    func testBootstrapSecretFormsFailClosed() throws {
        let enrollment = ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!
        let candidate = ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!
        let commissioner = ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!
        XCTAssertThrowsError(try ACPAppleEnrollmentBootstrap.registrationRecord(
            secret: .highEntropyCode("0000"), enrollmentID: enrollment,
            candidateNodeID: candidate, commissionerNodeID: commissioner))
        XCTAssertThrowsError(try ACPAppleEnrollmentBootstrap.registrationRecord(
            secret: .manualNumericCode("1234abcd"), enrollmentID: enrollment,
            candidateNodeID: candidate, commissionerNodeID: commissioner))
    }

    private func crockford(_ data: Data) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var bits: [UInt8] = [0, 0]
        for byte in data {
            for shift in stride(from: 7, through: 0, by: -1) {
                bits.append((byte >> shift) & 1)
            }
        }
        return stride(from: 0, to: bits.count, by: 5).map { start in
            let value = bits[start..<start + 5].reduce(0) { ($0 << 1) | Int($1) }
            return alphabet[value]
        }.map(String.init).joined()
    }
}
