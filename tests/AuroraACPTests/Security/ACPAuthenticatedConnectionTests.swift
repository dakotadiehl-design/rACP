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
            role: .serverHelloReceived,
            localNodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
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
            transport: transport, evidence: evidence, providerProvenance: provenance(status: "BLOCKED"),
            role: .serverHelloReceived, localNodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
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

    func testAuthenticatedServerSessionBindsCertificateIdentityToPrefetchedHello() async throws {
        let (serverTransport, clientTransport) = await acpLinkedTransports()
        let peerNode = "00112233-4455-4677-8899-aabbccddeeff"
        let domain = "40516273-8495-4a6b-8a3b-4c5d6e7f8091"
        let credential = "sha256:" + String(repeating: "1", count: 64)
        let key = "sha256:" + String(repeating: "2", count: 64)
        let binding = Data(repeating: 0, count: 32)
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust, trustDomainID: domain, nodeID: peerNode,
            credentialID: credential, identityKeyID: key, credentialFormat: "x509_der",
            channelBinding: ACPSecurityContext.base64URLEncode(binding),
            credentialState: .active, channelBindingVerified: true
        )
        let hello = authenticatedHello(node: peerNode, domain: domain, credential: credential,
                                       key: key, binding: binding)
        let connection = try ACPAuthenticatedConnection(
            transport: serverTransport, evidence: evidence, providerProvenance: try provenance(),
            role: .serverHelloReceived, prefetchedHello: hello,
            localNodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        )
        let session = try connection.makeSession(local: .init(
            nodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", role: "prism", name: "Host"))
        async let received = clientTransport.recv()
        _ = try await session.handshake()
        let ack = try ACPEncoding.decodeCBOR(try await received.0)
        XCTAssertEqual(ack.type, "session.hello_ack")
        let establishedPeer = await session.peer?.nodeID
        XCTAssertEqual(establishedPeer, peerNode)
        XCTAssertThrowsError(try connection.makeSession(local: .init(
            nodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", role: "prism", name: "Host")))
    }

    func testAuthenticatedServerSessionRejectsClaimedNodeMismatch() async throws {
        let (transport, _) = await acpLinkedTransports()
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust, trustDomainID: "40516273-8495-4a6b-8a3b-4c5d6e7f8091",
            nodeID: "00112233-4455-4677-8899-aabbccddeeff",
            credentialID: "sha256:" + String(repeating: "1", count: 64),
            identityKeyID: "sha256:" + String(repeating: "2", count: 64), credentialFormat: "x509_der",
            channelBinding: ACPSecurityContext.base64URLEncode(Data(repeating: 0, count: 32)),
            credentialState: .active, channelBindingVerified: true
        )
        let hello = authenticatedHello(node: "11112233-4455-4677-8899-aabbccddeeff",
            domain: evidence.trustDomainID!, credential: evidence.credentialID!,
            key: evidence.identityKeyID!, binding: Data(repeating: 0, count: 32))
        let connection = try ACPAuthenticatedConnection(
            transport: transport, evidence: evidence, providerProvenance: try provenance(),
            role: .serverHelloReceived, prefetchedHello: hello,
            localNodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        let session = try connection.makeSession(local: .init(
            nodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", role: "prism", name: "Host"))
        do { _ = try await session.handshake(); XCTFail("claimed node must not become principal") }
        catch { XCTAssertEqual((error as? ACPSessionError)?.code, "authentication") }
    }

    func testAuthenticatedSessionRejectsApplicationLocalNodeSubstitution() async throws {
        let (transport, _) = await acpLinkedTransports()
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust, trustDomainID: "40516273-8495-4a6b-8a3b-4c5d6e7f8091",
            nodeID: "00112233-4455-4677-8899-aabbccddeeff",
            credentialID: "sha256:" + String(repeating: "1", count: 64),
            identityKeyID: "sha256:" + String(repeating: "2", count: 64), credentialFormat: "x509_der",
            channelBinding: ACPSecurityContext.base64URLEncode(Data(repeating: 0, count: 32)),
            credentialState: .active, channelBindingVerified: true)
        let connection = try ACPAuthenticatedConnection(
            transport: transport, evidence: evidence, providerProvenance: try provenance(),
            role: .serverHelloReceived, localNodeID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        XCTAssertThrowsError(try connection.makeSession(local: .init(
            nodeID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", role: "prism", name: "Host"))) {
            XCTAssertEqual($0 as? ACPSecurityAdmissionError, .identityMismatch)
        }
        XCTAssertNil(connection.peerNodeID)
    }

    private func authenticatedHello(node: String, domain: String, credential: String,
                                    key: String, binding: Data) -> ACPEnvelope {
        ACPEnvelope(acp: "1.2", messageID: UUID().uuidString.lowercased(), type: "session.hello",
            source: .init(nodeID: node), timestampUTC: "2026-08-26T00:00:00Z", qos: .reliable,
            payload: [
                "node": .object(["node_id": .string(node), "instance_id": .string(UUID().uuidString.lowercased()),
                                 "role": .string("remote"), "name": .string("Peer")]),
                "protocol": .object(["min": .string("1.0"), "max": .string("1.2")]),
                "encodings": .array([.string("cbor")]), "profiles": .array([.string("core")]),
                "capabilities": .array([]),
                "auth": .object(["mode": .string("aurora_trust"), "trust_domain_id": .string(domain),
                    "credential_id": .string(credential), "identity_key_id": .string(key),
                    "channel_binding": .bytes(binding),
                    "security_capabilities": .array([.object(["id": .string("aurora-trust"),
                                                               "version": .string("1.0")])])])])
    }
}
