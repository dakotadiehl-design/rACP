import XCTest
@testable import AuroraACP

final class ACPAuthenticatedConnectionTests: XCTestCase {
    func testObservationCannotBecomeAuthorityAndConnectionIsOneShot() async throws {
        let (transport, _) = await acpLinkedTransports()
        let observation = ACPUnverifiedPeerObservation(
            protocolVersion: "TLSv1.3", certificateSubject: "attacker supplied",
            claimedNodeID: "00112233-4455-4677-8899-aabbccddeeff",
            claimedTrustDomainID: "40516273-8495-4a6b-8a3b-4c5d6e7f8091"
        )
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust,
            trustDomainID: "40516273-8495-4a6b-8a3b-4c5d6e7f8091",
            nodeID: "00112233-4455-4677-8899-aabbccddeeff",
            credentialID: "sha256:" + String(repeating: "1", count: 64),
            identityKeyID: "sha256:" + String(repeating: "2", count: 64),
            credentialFormat: "x509_der",
            channelBinding: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            credentialState: .active,
            channelBindingVerified: true
        )
        let connection = try ACPAuthenticatedConnection(
            transport: transport, evidence: evidence,
            providerManifestDigest: "sha256:" + String(repeating: "a", count: 64),
            observation: observation
        )
        XCTAssertEqual(connection.peerNodeID, evidence.nodeID)
        XCTAssertEqual(connection.observation, observation)
        _ = try connection.consume()
        XCTAssertNil(connection.peerNodeID)
        XCTAssertThrowsError(try connection.consume()) {
            XCTAssertEqual($0 as? ACPAuthenticatedConnectionError, .alreadyConsumed)
        }
    }

    func testProviderManifestDigestIsMandatory() async throws {
        let (transport, _) = await acpLinkedTransports()
        let evidence = ACPTransportEvidence(mode: .auroraTrust)
        XCTAssertThrowsError(try ACPAuthenticatedConnection(
            transport: transport, evidence: evidence, providerManifestDigest: "unqualified"
        ))
    }

    func testReservedFrameFlagsAreRejectedExplicitly() throws {
        for flag: UInt8 in [2, 3, 255] {
            XCTAssertThrowsError(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, flag])))
        }
        XCTAssertFalse(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, 0])).text)
        XCTAssertTrue(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, 1])).text)
    }
}
