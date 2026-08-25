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
