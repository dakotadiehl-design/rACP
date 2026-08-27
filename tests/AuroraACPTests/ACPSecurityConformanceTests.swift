import CryptoKit
import Foundation
import XCTest
@testable import AuroraACP

final class ACPSecurityConformanceTests: XCTestCase {
    private var root: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("vectors/security/conformance")
    }

    func testManifestHashesDependenciesAndForeignProducers() throws {
        let object = try JSONSerialization.jsonObject(
            with: Data(contentsOf: root.appendingPathComponent("manifest.json"))) as! [String: Any]
        XCTAssertEqual(object["fixture_set_version"] as? String, "1.0.0")
        let fixtures = try XCTUnwrap(object["fixtures"] as? [[String: Any]])
        let ids = Set(fixtures.compactMap { $0["id"] as? String })
        XCTAssertEqual(ids.count, fixtures.count)
        var foreignLanguages = Set<String>()
        for fixture in fixtures {
            let path = try XCTUnwrap(fixture["path"] as? String)
            let expected = try XCTUnwrap(fixture["sha256"] as? String)
            let bytes = try Data(contentsOf: root.appendingPathComponent(path))
            XCTAssertEqual(Self.sha256(bytes), expected, path)
            for dependency in fixture["dependencies"] as? [String] ?? [] {
                XCTAssertTrue(ids.contains(dependency), "missing dependency \(dependency)")
            }
            if let producer = fixture["producer"] as? [String: Any],
               let language = producer["language"] as? String, language != "swift" {
                foreignLanguages.insert(language)
            }
        }
        XCTAssertEqual(foreignLanguages, ["rust", "python"])
    }

    func testSwiftConsumesRustSPKIAndIssuanceMetadata() throws {
        let spki = try json("spki/rust-primary.json")
        let bytes = try XCTUnwrap(Data(hexConformance: spki["spki_der_hex"] as? String ?? ""))
        XCTAssertEqual(ACPCredentialIdentifiers.identityKeyID(for: bytes).rawValue,
                       spki["identity_key_id"] as? String)

        let issuance = try JSONDecoder().decode(
            ACPPortableIssuanceMetadata.self,
            from: Data(contentsOf: root.appendingPathComponent("issuance/rust-primary.json")))
        XCTAssertEqual(issuance.trustDomainID.rawValue,
                       "40516273-8495-4a6b-8a3b-4c5d6e7f8091")
        XCTAssertEqual(issuance.purpose, .initial)
        XCTAssertNil(issuance.replacesCredentialID)
    }

    func testSwiftConsumesPythonRevocationAndRejectsWrongDomainMutation() throws {
        let revocation = try json("revocation/python-primary.json")
        let snapshot = try XCTUnwrap(Data(hexConformance: revocation["snapshot_cbor_hex"] as? String ?? ""))
        XCTAssertEqual(ACPCredentialIdentifiers.credentialID(for: snapshot).rawValue,
                       revocation["snapshot_id"] as? String)
        XCTAssertEqual(revocation["epoch"] as? Int, 7)

        let negative = try json("negatives/python-wrong-domain.json")
        let mutation = try XCTUnwrap(negative["mutation"] as? [String: Any])
        XCTAssertNotEqual(mutation["value"] as? String,
                          revocation["trust_domain_id"] as? String)
        XCTAssertEqual(negative["expected_error"] as? String,
                       ACPSecurityErrorCode.trustDomainMismatch.rawValue)
    }

    private func json(_ path: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(
            with: Data(contentsOf: root.appendingPathComponent(path))) as! [String: Any]
    }
    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private extension Data {
    init?(hexConformance: String) {
        guard hexConformance.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8](); bytes.reserveCapacity(hexConformance.count / 2)
        var index = hexConformance.startIndex
        while index < hexConformance.endIndex {
            let next = hexConformance.index(index, offsetBy: 2)
            guard let byte = UInt8(hexConformance[index..<next], radix: 16) else { return nil }
            bytes.append(byte); index = next
        }
        self = Data(bytes)
    }
}
