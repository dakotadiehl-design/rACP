import AuroraACP
import XCTest
@testable import AuroraACPAppleSecurity

final class ACPAppleTrustedPeerStoreTests: XCTestCase {
    func testTrustAndRevocationPersistAndRepeatedRevocationIsDeterministic() throws {
        let service = "com.aurora.acp.tests.\(UUID().uuidString)"
        let account = UUID().uuidString
        let store = try ACPAppleTrustedPeerStore(service: service, account: account)
        defer { try? store.reset() }
        let certificate = verifiedCertificate()
        try store.recordAuthenticated(certificate, displayName: "Qualification iPad",
                                      at: Date(timeIntervalSince1970: 100))
        XCTAssertEqual(store.trustedPeers().first?.state, .trusted)

        let restored = try ACPAppleTrustedPeerStore(service: service, account: account)
        XCTAssertEqual(restored.trustedPeers().first?.displayName, "Qualification iPad")
        XCTAssertEqual(try restored.revoke(certificate.credentialID,
                                           at: Date(timeIntervalSince1970: 200)), .revoked)
        XCTAssertEqual(try restored.revoke(certificate.credentialID), .alreadyRevoked)

        let afterRestart = try ACPAppleTrustedPeerStore(service: service, account: account)
        XCTAssertTrue(afterRestart.isRevoked(certificate.credentialID))
        XCTAssertEqual(afterRestart.trustedPeers().first?.state, .revoked)
        XCTAssertEqual(try afterRestart.revoke(ACPCredentialID(
            rawValue: "sha256:" + String(repeating: "f", count: 64))!), .unknownCredential)
    }

    func testResetSeparatesTrustLifecycleFromIdentityAndAssets() throws {
        let service = "com.aurora.acp.tests.\(UUID().uuidString)"
        let account = UUID().uuidString
        let store = try ACPAppleTrustedPeerStore(service: service, account: account)
        try store.recordAuthenticated(verifiedCertificate(), displayName: nil)
        try store.reset()
        XCTAssertTrue(store.trustedPeers().isEmpty)
        XCTAssertTrue(try ACPAppleTrustedPeerStore(service: service, account: account).trustedPeers().isEmpty)
    }

    private func verifiedCertificate() -> ACPAppleVerifiedCertificate {
        ACPAppleVerifiedCertificate(
            trustDomainID: ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!,
            nodeID: ACPSecurityNodeID(rawValue: "00112233-4455-4677-8899-aabbccddeeff")!,
            credentialID: ACPCredentialID(rawValue: "sha256:" + String(repeating: "1", count: 64))!,
            identityKeyID: ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "2", count: 64))!,
            leafDER: Data([1, 2, 3]))
    }
}
