import XCTest
@testable import AuroraACP

final class ACPAuthenticatedConnectionTests: XCTestCase {
    private func provenance(status: String = "PASS") throws -> ACPProviderProvenance {
        let json = """
        {"schema_version":"1.0","adapter_id":"test.adapter","source_revision":"\(String(repeating: "a", count: 40))","provider":{"name":"test","version":"1"},"target_triple":"arm64-apple-macosx","profiles":["full"],"key_storage_classes":["keychain"],"qualification":{"status":"\(status)","artifact_sha256":"\(String(repeating: "b", count: 64))"}}
        """
        return try ACPProviderProvenance(jsonData: Data(json.utf8), requireQualified: status == "PASS")
    }

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
            providerProvenance: try provenance(),
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

    func testProviderManifestMustBeValidatedAndQualified() async throws {
        let (transport, _) = await acpLinkedTransports()
        let evidence = ACPTransportEvidence(mode: .auroraTrust)
        XCTAssertThrowsError(try ACPAuthenticatedConnection(
            transport: transport, evidence: evidence, providerProvenance: provenance(status: "BLOCKED")
        ))
        XCTAssertThrowsError(try ACPProviderProvenance(jsonData: Data("{}".utf8)))
    }

    func testReservedFrameFlagsAreRejectedExplicitly() throws {
        for flag: UInt8 in [2, 3, 255] {
            XCTAssertThrowsError(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, flag])))
        }
        XCTAssertFalse(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, 0])).text)
        XCTAssertTrue(try ACPFramedConnection.parseHeader(Data([0, 0, 0, 0, 1])).text)
    }

    func testOversizedOutboundFrameProducesNoWritableBytes() {
        let oversized = Data(repeating: 0, count: ACPFramedConnection.maximumFrameLength + 1)
        var bytesMadeWritable: Data?
        XCTAssertThrowsError(bytesMadeWritable = try ACPFramedConnection.prepareFrame(oversized, text: false))
        XCTAssertNil(bytesMadeWritable)
    }

    func testUnqualifiedLightweightProfileCannotBeSelectedForProduction() throws {
        XCTAssertNoThrow(try ACPProductionProfileSupport.requireSupported(.full))
        XCTAssertThrowsError(try ACPProductionProfileSupport.requireSupported(.lightweight))
    }
}
