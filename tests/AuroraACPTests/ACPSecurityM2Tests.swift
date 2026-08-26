import Foundation
import XCTest
@testable import AuroraACP

final class ACPSecurityM2Tests: XCTestCase {
    private let context: [String: String] = [
        "acp_version": "1.2", "application": "Aurora Communications Protocol",
        "attempt_id": "60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1",
        "candidate_instance_id": "20314253-6475-4869-aa1b-2c3d4e5f6071",
        "candidate_node_id": "00112233-4455-4677-8899-aabbccddeeff",
        "commissioner_instance_id": "30415263-7485-496a-ba2b-3c4d5e6f7081",
        "commissioner_node_id": "10213243-5465-4768-9a0b-1c2d3e4f5061",
        "enrollment_id": "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1", "extension_version": "1.0",
        "identity_algorithm": "ecdsa_p256_sha256",
        "identity_key_id": "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d",
        "purpose": "security.enrollment",
        "requested_permissions_digest": "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0",
        "requested_role": "remote", "suite": "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1",
        "trust_domain_id": "40516273-8495-4a6b-8a3b-4c5d6e7f8091",
    ]

    func testFrozenContextTranscriptAndKeySchedule() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let expectedContext = try Data(contentsOf: root.appendingPathComponent("vectors/security/context/primary.cbor"))
        let canonical = try ACPSecurityContext.canonicalEnrollment(context)
        XCTAssertEqual(canonical, expectedContext)
        XCTAssertEqual(ACPSecurityContext.digestID(canonical), "sha256:5236d0f7af47b5953368218918e49f65e023f548119b3b12a132d973c1e8a1c9")

        let expectedTranscript = try Data(contentsOf: root.appendingPathComponent("vectors/security/transcript/primary.cbor"))
        let decoded = try ACPEncoding.decodeValue(expectedTranscript)
        guard case .array(let values) = decoded else { return XCTFail("transcript vector") }
        let items = values.compactMap { if case .bytes(let value) = $0 { value } else { nil } }
        XCTAssertEqual(try ACPSecurityContext.canonicalTranscript(items), expectedTranscript)

        let shared = Data(hex: "b9824463682ad84c7cf15c61b4d71a5bab9c5f882e868d04f58a68f6862cdd75")!
        let hash = Data(hex: "1713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba")!
        let keys = ACPSecurityContext.deriveEnrollmentKeys(sharedKey: shared, transcriptHash: hash)
        XCTAssertEqual(keys["candidate confirm"], Data(hex: "2e6621403e7994557bcfe9fd9e7b2be4c20fad8ca91d95f7603e5d3016c1d190"))
        XCTAssertEqual(keys["SAS"], Data(hex: "944e3bdfdf07dc2a3a8860c84d6587c3fe3db65d64207dd62a7fe4d0531828fa"))
        XCTAssertEqual(try ACPSecurityContext.permissionDigest([:]), "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0")
    }

    func testSecretsAndDowngradeAreFailClosed() throws {
        let fixture = Data(hex: "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffee")!
        let secret = try XCTUnwrap(ACPSecretBytes(fixture, label: "fixture"))
        XCTAssertFalse(String(describing: secret).contains(fixture.map { String(format: "%02x", $0) }.joined()))
        XCTAssertFalse(ACPDowngradePolicy.hardenedProduction.permitsUnauthenticated(strongerAuthenticationAttempted: false))
        XCTAssertFalse(ACPDowngradePolicy.migration(allowTrustedLAN: true).permitsUnauthenticated(strongerAuthenticationAttempted: true))
        XCTAssertThrowsError(try ACPSecurityContext.base64URLDecode("AA=="))
    }

    func testSecretConcurrentAccessAndClearAreSerialized() throws {
        let secret = try XCTUnwrap(ACPSecretBytes(Data(repeating: 0xA5, count: 32)))
        DispatchQueue.concurrentPerform(iterations: 100) { index in
            if index.isMultiple(of: 7) {
                secret.clear()
            } else {
                secret.withUnsafeBytes { XCTAssertEqual($0.count, 32) }
            }
        }
        XCTAssertTrue(String(describing: secret).contains("redacted"))
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var value = Data(); var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            value.append(byte); index = next
        }
        self = value
    }
}
