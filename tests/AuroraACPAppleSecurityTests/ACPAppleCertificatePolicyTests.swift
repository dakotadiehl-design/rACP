import AuroraACP
import AuroraACPAppleSecurity
import Foundation
import Security
import XCTest

final class ACPAppleCertificatePolicyTests: XCTestCase {
    private struct Revoked: ACPAppleRevocationChecking {
        func isRevoked(_ credentialID: ACPCredentialID) -> Bool { true }
    }
    private func fixture() throws -> (SecCertificate, SecCertificate, [String: Any]) {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("vectors/security/x509/full_profile.json")
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: root)) as! [String: Any]
        let leaf = SecCertificateCreateWithData(nil, Data(base64Encoded: object["leaf_der_base64"] as! String)! as CFData)!
        let authority = SecCertificateCreateWithData(nil, Data(base64Encoded: object["root_der_base64"] as! String)! as CFData)!
        return (leaf, authority, object)
    }

    func testFrozenACPChainAndIdentifiersValidate() throws {
        let (leaf, authority, object) = try fixture()
        let result = try ACPAppleCertificatePolicy.validate(
            chain: [leaf, authority], anchors: [authority],
            expectedDomain: ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!,
            expectedNode: ACPSecurityNodeID(rawValue: "00112233-4455-4677-8899-aabbccddeeff")!,
            evaluationDate: ISO8601DateFormatter().date(from: "2026-08-26T12:00:00Z")!
        )
        XCTAssertEqual(result.credentialID.rawValue, object["leaf_credential_id"] as? String)
        XCTAssertEqual(result.nodeID.rawValue, "00112233-4455-4677-8899-aabbccddeeff")
    }

    func testWrongNodeDomainAndUntrustedAnchorFailClosed() throws {
        let (leaf, authority, _) = try fixture()
        let date = ISO8601DateFormatter().date(from: "2026-08-26T12:00:00Z")!
        XCTAssertThrowsError(try ACPAppleCertificatePolicy.validate(
            chain: [leaf, authority], anchors: [authority],
            expectedDomain: ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!,
            expectedNode: ACPSecurityNodeID(rawValue: "11112233-4455-4677-8899-aabbccddeeff")!,
            evaluationDate: date
        ))
        XCTAssertThrowsError(try ACPAppleCertificatePolicy.validate(
            chain: [leaf, authority], anchors: [authority],
            expectedDomain: ACPTrustDomainID(rawValue: "50516273-8495-4a6b-8a3b-4c5d6e7f8091")!,
            evaluationDate: date
        ))
        XCTAssertThrowsError(try ACPAppleCertificatePolicy.validate(
            chain: [leaf], anchors: [leaf],
            expectedDomain: ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!,
            evaluationDate: date
        ))
    }

    func testExpiredFutureAndRevokedCredentialsFailClosed() throws {
        let (leaf, authority, _) = try fixture()
        let domain = ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!
        for date in ["2026-08-20T12:00:00Z", "2027-08-22T12:00:00Z"] {
            XCTAssertThrowsError(try ACPAppleCertificatePolicy.validate(
                chain: [leaf, authority], anchors: [authority], expectedDomain: domain,
                evaluationDate: ISO8601DateFormatter().date(from: date)!
            ))
        }
        XCTAssertThrowsError(try ACPAppleCertificatePolicy.validate(
            chain: [leaf, authority], anchors: [authority], expectedDomain: domain,
            evaluationDate: ISO8601DateFormatter().date(from: "2026-08-26T12:00:00Z")!, revocation: Revoked()
        )) { XCTAssertEqual($0 as? ACPAppleSecurityError, .revoked) }
    }
}
