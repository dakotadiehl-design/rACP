import CryptoKit
import XCTest
@testable import AuroraACP

final class ACPCredentialLifecycleTests: XCTestCase {
    private let domain = ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!
    private let node = ACPSecurityNodeID(rawValue: "00112233-4455-4677-8899-aabbccddeeff")!

    func testCompactAndRevocationFrozenVectors() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let compactJSON = try json(root.appendingPathComponent("vectors/security/compact_credential/primary.json"))
        let compact = Data(hexM4: compactJSON["credential_cbor_hex"] as! String)!
        let verifier = ExpectedCredentialVerifier(
            digest: Data(hexM4: compactJSON["signature_input_sha256_hex"] as! String)!,
            signature: Data(hexM4: compactJSON["signature_der_hex"] as! String)!
        )
        let validated = try ACPValidateCompactCredential(
            compact, verifier: verifier, revoked: { _ in false },
            policy: .init(expectedDomain: domain, expectedNode: node, possessionValid: true,
                          allowedRoles: ["remote"], maximumBytes: 2048,
                          evaluationTime: ISO8601DateFormatter().date(from: "2026-08-25T00:00:00Z")!)
        )
        XCTAssertEqual(validated.credentialID.rawValue, compactJSON["credential_id"] as? String)

        let revocationJSON = try json(root.appendingPathComponent("vectors/security/revocation/snapshot_epoch_7.json"))
        let body = Data(hexM4: revocationJSON["body_cbor_hex"] as! String)!
        let signature = Data(hexM4: revocationJSON["signature_der_hex"] as! String)!
        let revocationVerifier = ExpectedCredentialVerifier(
            digest: Data(hexM4: revocationJSON["signature_input_sha256_hex"] as! String)!, signature: signature
        )
        var state = ACPRevocationState(trustDomainID: domain, maximumEntries: 128)
        try state.ingest(bodyRaw: body, signature: signature, verifier: revocationVerifier)
        try state.requireFresh(at: ISO8601DateFormatter().date(from: "2026-08-22T12:00:00Z")!, maximumSnapshotAge: 172_800)
        XCTAssertThrowsError(try state.requireFresh(at: ISO8601DateFormatter().date(from: "2026-08-23T12:00:00Z")!, maximumSnapshotAge: 172_800))
        XCTAssertEqual(ACPRevocationAction(revoked: true), .terminate)
        XCTAssertEqual(ACPRevocationAction(revoked: true, policy: .explicitAuditedGrace), .auditedGrace)
        XCTAssertEqual(ACPActiveSessionRevocationPolicy.resolve(persistedValue: nil), .hardenedTerminate)
        XCTAssertEqual(ACPActiveSessionRevocationPolicy.resolve(persistedValue: "unknown"), .hardenedTerminate)
        XCTAssertEqual(ACPActiveSessionRevocationPolicy.resolve(
            persistedValue: "explicit_audited_grace"), .explicitAuditedGrace)
        XCTAssertEqual(state.epoch, 7); XCTAssertEqual(state.entries.count, 1)
        XCTAssertThrowsError(try state.ingest(bodyRaw: body, signature: signature, verifier: revocationVerifier))
    }

    func testX509EvidenceRequiresAllFacts() throws {
        let valid = evidence()
        XCTAssertNoThrow(try valid.requireValid())
        var invalid = valid; invalid.nodeMatches = false
        XCTAssertThrowsError(try invalid.requireValid())
        invalid = valid; invalid.unknownCriticalExtensions = true
        XCTAssertThrowsError(try invalid.requireValid())
    }

    func testTwoSlotRecoveryAndRotationFailure() async throws {
        let backend = MemoryCredentialBackend()
        let store = ACPTwoSlotIdentityStore(backend: backend)
        let first = generation(1), second = generation(2)
        try await store.stage(first); try await store.validateStaged(generation: 1, valid: true)
        try await store.commit(generation: 1)
        try await store.stage(second)
        let stagedRecovery = try await store.recover()
        XCTAssertEqual(stagedRecovery, first)

        let rotation = ACPRotationCoordinator()
        try await rotation.prepare(second, store: store); try await rotation.credentialObtained()
        try await rotation.stage(store: store, valid: true)
        do { try await rotation.possessionProved(false); XCTFail("invalid proof accepted") } catch {}
        let failedRecovery = try await store.recover()
        XCTAssertEqual(failedRecovery, first)
    }

    func testTwoSlotNonsequentialGenerationPreservesActiveIdentity() async throws {
        let store = ACPTwoSlotIdentityStore(backend: MemoryCredentialBackend())
        let first = generation(2), next = generation(4)
        try await store.stage(first); try await store.validateStaged(generation: 2, valid: true)
        try await store.commit(generation: 2)
        try await store.stage(next)
        let staged = try await store.recover()
        XCTAssertEqual(staged, first)
        try await store.validateStaged(generation: 4, valid: true)
        try await store.commit(generation: 4)
        let committed = try await store.recover()
        XCTAssertEqual(committed, next)
    }

    func testClockPolicyRejectsUntrustedAndRollback() throws {
        let now = Date(timeIntervalSince1970: 10)
        XCTAssertEqual(try ACPAcceptedTime(state: .trustedWallClock, wall: now, checkpoint: nil, commissioner: nil, lastCheckpoint: Date(timeIntervalSince1970: 9)), now)
        XCTAssertThrowsError(try ACPAcceptedTime(state: .untrusted, wall: now, checkpoint: nil, commissioner: nil, lastCheckpoint: nil))
        XCTAssertThrowsError(try ACPAcceptedTime(state: .authenticatedCheckpoint, wall: nil, checkpoint: Date(timeIntervalSince1970: 8), commissioner: nil, lastCheckpoint: Date(timeIntervalSince1970: 9)))
    }

    func testAuthorityIssuanceAndRenewalIdentityRules() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let compactJSON = try json(root.appendingPathComponent("vectors/security/compact_credential/primary.json"))
        let bodyRaw = Data(hexM4: compactJSON["body_cbor_hex"] as! String)!
        guard case .object(let body) = try ACPEncoding.decodeValue(bodyRaw),
              case .string(let issuerText) = body["issuer_key_id"],
              let issuer = ACPIdentityKeyID(rawValue: issuerText)
        else { return XCTFail("invalid fixture") }
        let key = FixtureAuthorityKey(
            keyID: issuer,
            digest: Data(hexM4: compactJSON["signature_input_sha256_hex"] as! String)!,
            signature: Data(hexM4: compactJSON["signature_der_hex"] as! String)!
        )
        let identity = ACPTrustDomainIdentity(trustDomainID: domain, authorityKeyID: issuer)
        let authority = try ACPCredentialAuthority.restore(expected: identity, restored: identity, signingKey: key)
        XCTAssertEqual(try authority.issueCompact(body: body), Data(hexM4: compactJSON["credential_cbor_hex"] as! String))

        let current = ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "1", count: 64))!
        let renewed = try ACPRenewalPlan.create(nodeID: node, currentKeyID: current, rotation: false, requestedKeyID: nil)
        XCTAssertEqual(renewed.nextKeyID, current); XCTAssertEqual(renewed.nodeID, node)
        let next = ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "2", count: 64))!
        let rotated = try ACPRenewalPlan.create(nodeID: node, currentKeyID: current, rotation: true, requestedKeyID: next)
        XCTAssertEqual(rotated.nextKeyID, next); XCTAssertEqual(rotated.nodeID, node)
    }

    func testFullTransportFrozenExporterAndFailClosedFacts() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let vector = try json(root.appendingPathComponent("vectors/security/hello_binding/primary.json"))
        let canonical = Data(hexM4: vector["canonical_cbor_hex"] as! String)!
        guard case .object(var hello) = try ACPEncoding.decodeValue(canonical), case .object(var auth) = hello["auth"]
        else { return XCTFail("invalid fixture") }
        auth["channel_binding"] = .bytes(Data(repeating: 0x65, count: 32)); hello["auth"] = .object(auth)
        XCTAssertEqual(try ACPAuthenticatedTransport.helloExporterContext(hello).hexM4,
                       vector["exporter_context_sha256_hex"] as? String)
        let handshake = fullHandshake()
        let evidence = try ACPAuthenticatedTransport.fullEvidence(
            hello: hello, handshake: handshake, exporter: FixedExporter(Data(repeating: 0x65, count: 32))
        )
        XCTAssertTrue(evidence.channelBindingVerified)
        let invalid = ACPFullTLSHandshake(
            protocolVersion: "TLSv1.2", mutualAuthentication: true, isolatedTrustStore: true,
            peerCertificateValid: true, localCredentialSelected: true, peerSANExtracted: true,
            trustDomainID: handshake.trustDomainID, nodeID: handshake.nodeID,
            credentialID: handshake.credentialID, identityKeyID: handshake.identityKeyID,
            roleConstraints: [], credentialState: .active
        )
        XCTAssertThrowsError(try ACPAuthenticatedTransport.fullEvidence(
            hello: hello, handshake: invalid, exporter: FixedExporter(Data(repeating: 0x65, count: 32))))
    }

    func testLightweightPrefaceAndFinishedAreBounded() throws {
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust, profile: .lightweight, trustDomainID: domain.rawValue,
            nodeID: node.rawValue, credentialID: "sha256:" + String(repeating: "1", count: 64),
            identityKeyID: "sha256:" + String(repeating: "2", count: 64),
            credentialFormat: "acp-compact-credential-v1", credentialState: .active, channelBindingVerified: true)
        let credential = Data("credential".utf8)
        let preface = Data([0, UInt8(credential.count)]) + credential
        let (parsed, raw) = try ACPAuthenticatedTransport.parseLightweightPreface(preface) { _ in evidence }
        XCTAssertEqual(parsed, evidence); XCTAssertEqual(raw, credential)
        let key = Data(repeating: 0x6b, count: 32)
        let inputs = ACPLightweightFinishedInputs(
            clientCredential: credential, serverCredential: credential,
            clientSPKI: Data("client-spki".utf8), serverSPKI: Data("server-spki".utf8),
            clientNodeID: node.rawValue, serverNodeID: node.rawValue, trustDomainID: domain.rawValue)
        let context = try ACPAuthenticatedTransport.lightweightFinishedContext(inputs)
        let finished = Data(HMAC<SHA256>.authenticationCode(for: context, using: SymmetricKey(data: key)))
        XCTAssertNoThrow(try ACPAuthenticatedTransport.verifyLightweightFinished(
            exportedKey: key, inputs: inputs, received: finished))
        XCTAssertThrowsError(try ACPAuthenticatedTransport.verifyLightweightFinished(
            exportedKey: key, inputs: inputs, received: Data(repeating: 0, count: 32)))
    }

    private func generation(_ value: UInt64) -> ACPCredentialGeneration {
        let text = "sha256:" + String(format: "%064llx", value)
        return .init(generation: value, credentialID: ACPCredentialID(rawValue: text)!,
                     identityKeyID: ACPIdentityKeyID(rawValue: text)!, credential: Data([UInt8(value)]))
    }
    private func evidence() -> ACPX509ValidationEvidence {
        .init(derParsed: true, isolatedChain: true, signatureValid: true, sanWellFormed: true,
              domainMatches: true, nodeMatches: true, ekuValid: true, kuValid: true,
              caConstraintsValid: true, validityValid: true, revocationValid: true,
              credentialIDValid: true, identityKeyIDValid: true, possessionValid: true,
              localPolicyValid: true, unknownCriticalExtensions: false)
    }
    private func json(_ url: URL) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }
    private func fullHandshake() -> ACPFullTLSHandshake {
        .init(
            protocolVersion: "TLSv1.3", mutualAuthentication: true, isolatedTrustStore: true,
            peerCertificateValid: true, localCredentialSelected: true, peerSANExtracted: true,
            trustDomainID: domain.rawValue, nodeID: node.rawValue,
            credentialID: "sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20",
            identityKeyID: "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d",
            roleConstraints: ["remote"], credentialState: .active)
    }
}

private struct FixedExporter: ACPTLSExporter {
    let value: Data
    init(_ value: Data) { self.value = value }
    func export(label: String, context: Data, length: Int) throws -> Data {
        guard label == ACPHelloExporterLabel, context.count == 32, length == 32 else {
            throw ACPSecurityAdmissionError.authenticationFailed
        }
        return value
    }
}

private struct ExpectedCredentialVerifier: ACPCredentialSignatureVerifier {
    let digest: Data
    let signature: Data
    func verify(issuerKeyID: String, digest: Data, signature: Data) -> Bool {
        !issuerKeyID.isEmpty && digest == self.digest && signature == self.signature
    }
}

private struct FixtureAuthorityKey: ACPSigningKeyHandle {
    let keyID: ACPIdentityKeyID
    let digest: Data
    let signature: Data
    func sign(digest: Data) throws -> Data {
        guard digest == self.digest else { throw ACPSecurityErrorCode.credentialInvalid }
        return signature
    }
}

private final class MemoryCredentialBackend: ACPCredentialSlotBackend, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()
    func read(name: String) -> Data? { lock.withLock { values[name] } }
    func write(name: String, data: Data) { lock.withLock { values[name] = data } }
    func delete(name: String) { _ = lock.withLock { values.removeValue(forKey: name) } }
}

private extension Data {
    var hexM4: String { map { String(format: "%02x", $0) }.joined() }
    init?(hexM4: String) {
        guard hexM4.count.isMultiple(of: 2) else { return nil }
        var result = Data(), index = hexM4.startIndex
        while index < hexM4.endIndex {
            let next = hexM4.index(index, offsetBy: 2)
            guard let byte = UInt8(hexM4[index..<next], radix: 16) else { return nil }
            result.append(byte); index = next
        }
        self = result
    }
}
