import CryptoKit
import Foundation
import XCTest
@testable import AuroraACP

final class ACPCredentialIssuanceTests: XCTestCase {
    func testAuthorizationIsBoundAndOneShot() throws {
        let facts = try makeFacts()
        let ceremonyKey = confirmedKey(facts.transcriptHash)
        let capabilities = try ACPIssuanceAuthorizationGate.authorize(
            facts: facts, confirmedKey: ceremonyKey,
            approvalMatchesCeremony: true, approvalSingleUse: true,
            cancelled: false, replayed: false,
            stillValid: { true })
        XCTAssertEqual(try capabilities.authorization.consume(
            now: Date(timeIntervalSince1970: 1_100)), facts)
        XCTAssertThrowsError(try capabilities.authorization.consume(
            now: Date(timeIntervalSince1970: 1_100)))
        XCTAssertThrowsError(try ACPIssuanceAuthorizationGate.authorize(
            facts: facts, confirmedKey: ceremonyKey,
            approvalMatchesCeremony: true,
            approvalSingleUse: true, cancelled: false, replayed: false,
            stillValid: { true }))
        XCTAssertThrowsError(try ACPIssuanceAuthorizationGate.authorize(
            facts: facts,
            confirmedKey: confirmedKey(Data(repeating: 0xff, count: 32)),
            approvalMatchesCeremony: true, approvalSingleUse: true,
            cancelled: false, replayed: false, stillValid: { true }))
        XCTAssertThrowsError(try ACPIssuanceAuthorizationGate.authorize(
            facts: facts, confirmedKey: confirmedKey(facts.transcriptHash),
            approvalMatchesCeremony: false, approvalSingleUse: true,
            cancelled: false, replayed: false,
            stillValid: { true }))
    }

    func testFailedReservationDoesNotConsumeAuthorization() async throws {
        let facts = try makeFacts()
        let authorization = try authorized(facts)
        let backend = MemoryIssuanceBackend()
        backend.failNextWrite = true
        let journal = try ACPIssuanceJournal(backend: backend)
        await XCTAssertThrowsErrorAsync {
            _ = try await journal.consumeAndReserve(
                authorization: authorization, now: Date(timeIntervalSince1970: 1_100),
                expectedDomain: facts.trustDomainID,
                expectedAuthorityKeyID: facts.authorityKeyID,
                random: FixedRandom(Data(repeating: 0xa5, count: 16)))
        }
        let committed = try await journal.consumeAndReserve(
            authorization: authorization, now: Date(timeIntervalSince1970: 1_100),
            expectedDomain: facts.trustDomainID,
            expectedAuthorityKeyID: facts.authorityKeyID,
            random: FixedRandom(Data(repeating: 0xa5, count: 16)))
        XCTAssertEqual(committed.facts, facts)
        XCTAssertEqual(committed.reservation.serial, Data(repeating: 0xa5, count: 16))
    }

    func testJournalReservesRandomSerialAndReturnsOnlyExactPackage() async throws {
        let backend = MemoryIssuanceBackend()
        let journal = try ACPIssuanceJournal(backend: backend)
        let facts = try makeFacts()
        let random = FixedRandom(Data(repeating: 0xa5, count: 16))
        let reserved = try await journal.reserve(
            authorizationID: facts.authorizationID, authorityKeyID: facts.authorityKeyID, random: random)
        XCTAssertEqual(reserved.serial, Data(repeating: 0xa5, count: 16))
        XCTAssertNil(reserved.existingPackage)
        let leaf = Data([0x30, 0x01, 0x00])
        let package = try ACPIssuedCredentialPackage(
            authorizationID: facts.authorizationID,
            leafDER: leaf, trustAnchorDER: Data([1]),
            credentialID: ACPCredentialIdentifiers.credentialID(for: leaf),
            identityKeyID: facts.identityKeyID, authorityKeyID: facts.authorityKeyID,
            trustDomainID: facts.trustDomainID, nodeID: facts.candidateNodeID,
            enrollmentID: facts.enrollmentID, attemptID: facts.attemptID,
            transcriptHash: facts.transcriptHash, serial: reserved.serial,
            notBefore: Date(timeIntervalSince1970: 1_000),
            expiresAt: Date(timeIntervalSince1970: 2_000),
            rotationDeadline: Date(timeIntervalSince1970: 1_900), replacesCredentialID: nil)
        try await journal.recordSigned(package, authorizationID: facts.authorizationID)
        let retry = try await journal.reserve(
            authorizationID: facts.authorizationID, authorityKeyID: facts.authorityKeyID,
            random: FixedRandom(Data(repeating: 0x5a, count: 16)))
        XCTAssertEqual(retry.existingPackage, package)
        let restored = try ACPIssuanceJournal(backend: backend)
        let afterRestart = try await restored.reserve(
            authorizationID: facts.authorizationID, authorityKeyID: facts.authorityKeyID,
            random: FixedRandom(Data(repeating: 0x11, count: 16)))
        XCTAssertEqual(afterRestart.existingPackage, package)
        let otherAuthority = ACPIdentityKeyID(
            rawValue: "sha256:" + String(repeating: "d", count: 64))!
        await XCTAssertThrowsErrorAsync {
            _ = try await restored.reserve(
                authorizationID: facts.authorizationID, authorityKeyID: otherAuthority,
                random: FixedRandom(Data(repeating: 0x11, count: 16)))
        }
    }

    func testInstallConfirmationIsSealedExactAndOneShot() throws {
        let facts = try makeFacts()
        let shared = Data(repeating: 0xa5, count: 32)
        let verifier = try ACPConfirmedSPAKE2PlusKey(
            secret: ACPSecretBytes(shared)!,
            transcriptHash: facts.transcriptHash).claimInstallVerifier(
                transcriptHash: facts.transcriptHash)
        let credential = "sha256:" + String(repeating: "c", count: 64)
        let values: [String: AnySendable] = [
            "attempt_id": .string(facts.attemptID.rawValue), "status": .string("installed"),
            "credential_id": .string(credential),
            "identity_key_id": .string(facts.identityKeyID.rawValue),
            "trust_domain_id": .string(facts.trustDomainID.rawValue),
            "storage_posture": .object([
                "class": .string("os_protected"), "hardware_backed": .bool(false),
                "private_key_exportable": .bool(false),
            ]),
            "proof_of_possession": .bytes(Data([1, 2, 3])),
        ]
        let key = ACPSecurityContext.deriveEnrollmentKeys(
            sharedKey: shared, transcriptHash: facts.transcriptHash)["candidate confirm"]!
        let confirmation = try ACPSecurityContext.installConfirmation(
            candidateConfirmKey: key, values: values)
        let evidence = try verifier.verify(values: values, confirmation: confirmation)
        XCTAssertEqual(evidence.attemptID, facts.attemptID)
        XCTAssertEqual(evidence.credentialID.rawValue, credential)
        XCTAssertThrowsError(try verifier.verify(values: values, confirmation: confirmation))

        let badVerifier = try ACPConfirmedSPAKE2PlusKey(
            secret: ACPSecretBytes(shared)!,
            transcriptHash: facts.transcriptHash).claimInstallVerifier(
                transcriptHash: facts.transcriptHash)
        XCTAssertThrowsError(try badVerifier.verify(
            values: values, confirmation: Data(repeating: 0, count: 32)))
        XCTAssertThrowsError(try badVerifier.verify(values: values, confirmation: confirmation))
    }

    func testRevocationPublisherFeedsExistingAuthoritativeVerifier() async throws {
        let facts = try makeFacts()
        let backend = MemoryIssuanceBackend()
        let signer = RecordingSigner(keyID: facts.authorityKeyID)
        let publisher = try ACPRevocationPublisher(
            domain: facts.trustDomainID, signer: signer, backend: backend)
        let credential = ACPCredentialID(rawValue: "sha256:" + String(repeating: "c", count: 64))!
        let issued = try await publisher.revoke(
            credentialID: credential, nodeID: facts.candidateNodeID, reason: "key_compromise",
            at: Date(timeIntervalSince1970: 1_000), nextUpdate: Date(timeIntervalSince1970: 2_000))
        var state = ACPRevocationState(trustDomainID: facts.trustDomainID, maximumEntries: 4096)
        try state.ingest(bodyRaw: issued.body, signature: issued.signature,
                         verifier: AcceptingVerifier(expectedKeyID: facts.authorityKeyID.rawValue))
        XCTAssertEqual(state.epoch, 1)
        XCTAssertEqual(state.entries[credential]?.nodeID, facts.candidateNodeID)

        let refreshed = try await publisher.current(
            issuedAt: Date(timeIntervalSince1970: 1_100),
            nextUpdate: Date(timeIntervalSince1970: 2_100))
        XCTAssertEqual(refreshed.epoch, 2)
        try state.ingest(bodyRaw: refreshed.body, signature: refreshed.signature,
                         verifier: AcceptingVerifier(expectedKeyID: facts.authorityKeyID.rawValue))
        XCTAssertEqual(state.epoch, 2)

        let restoredPublisher = try ACPRevocationPublisher(
            domain: facts.trustDomainID, signer: signer, backend: backend)
        let durable = try await restoredPublisher.latest(
            at: Date(timeIntervalSince1970: 1_200), maximumSnapshotAge: 500)
        XCTAssertEqual(durable, refreshed)
        await XCTAssertThrowsErrorAsync {
            _ = try await restoredPublisher.latest(
                at: Date(timeIntervalSince1970: 2_101), maximumSnapshotAge: 5_000)
        }

        await XCTAssertThrowsErrorAsync {
            _ = try await publisher.revoke(
                credentialID: credential, nodeID: facts.candidateNodeID, reason: "policy",
                at: Date(timeIntervalSince1970: 1_000),
                nextUpdate: Date(timeIntervalSince1970: 2_000))
        }
        let wrongDomain = ACPTrustDomainID(
            rawValue: "81000000-0000-4000-8000-000000000001")!
        XCTAssertThrowsError(try ACPRevocationPublisher(
            domain: wrongDomain, signer: signer, backend: backend))
    }

    private func makeFacts() throws -> ACPIssuanceCeremonyFacts {
        let spki = P256.Signing.PrivateKey().publicKey.derRepresentation
        return try .init(
            authorizationID: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            enrollmentID: ACPEnrollmentID(rawValue: "20000000-0000-4000-8000-000000000001")!,
            attemptID: ACPEnrollmentAttemptID(rawValue: "30000000-0000-4000-8000-000000000001")!,
            transcriptHash: Data(repeating: 1, count: 32),
            candidateNodeID: ACPSecurityNodeID(rawValue: "40000000-0000-4000-8000-000000000001")!,
            candidateInstanceID: UUID(uuidString: "50000000-0000-4000-8000-000000000001")!,
            commissionerNodeID: ACPSecurityNodeID(rawValue: "60000000-0000-4000-8000-000000000001")!,
            commissionerInstanceID: UUID(uuidString: "70000000-0000-4000-8000-000000000001")!,
            trustDomainID: ACPTrustDomainID(rawValue: "80000000-0000-4000-8000-000000000001")!,
            authorityKeyID: ACPIdentityKeyID(rawValue: "sha256:" + String(repeating: "a", count: 64))!,
            candidatePublicKeySPKI: spki,
            identityKeyID: ACPCredentialIdentifiers.identityKeyID(for: spki), requestedRole: "remote",
            permissionsDigest: "sha256:" + String(repeating: "b", count: 64),
            approvalID: UUID(uuidString: "90000000-0000-4000-8000-000000000001")!,
            approvalTime: Date(timeIntervalSince1970: 1_000),
            expiresAt: Date(timeIntervalSince1970: 1_200), cancellationGeneration: 7)
    }

    private func authorized(_ facts: ACPIssuanceCeremonyFacts) throws -> ACPIssuanceAuthorization {
        try ACPIssuanceAuthorizationGate.authorize(
            facts: facts, confirmedKey: confirmedKey(facts.transcriptHash),
            approvalMatchesCeremony: true, approvalSingleUse: true,
            cancelled: false, replayed: false,
            stillValid: { true }).authorization
    }

    private func confirmedKey(_ transcriptHash: Data) -> ACPConfirmedSPAKE2PlusKey {
        ACPConfirmedSPAKE2PlusKey(
            secret: ACPSecretBytes(Data(repeating: 0xa5, count: 32))!,
            transcriptHash: transcriptHash)
    }
}

private func XCTAssertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath, line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected error", file: file, line: line)
    } catch {}
}

private final class MemoryIssuanceBackend: ACPIssuanceJournalBackend, @unchecked Sendable {
    private let lock = NSLock(); private var data: Data?
    var failNextWrite = false
    func load() throws -> Data? { lock.lock(); defer { lock.unlock() }; return data }
    func replace(with data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        if failNextWrite { failNextWrite = false; throw ACPSecurityErrorCode.storageFailed }
        self.data = data
    }
}

private struct FixedRandom: ACPSecureRandomProvider {
    let value: Data
    init(_ value: Data) { self.value = value }
    func bytes(count: Int) throws -> ACPSecretBytes {
        guard count == value.count else { throw ACPSecurityErrorCode.resourceLimit }
        return ACPSecretBytes(value)!
    }
}

private struct RecordingSigner: ACPSigningKeyHandle {
    let keyID: ACPIdentityKeyID
    func sign(digest: Data) throws -> Data { Data(digest.prefix(16)) }
}

private struct AcceptingVerifier: ACPCredentialSignatureVerifier {
    let expectedKeyID: String
    func verify(issuerKeyID: String, digest: Data, signature: Data) -> Bool {
        issuerKeyID == expectedKeyID && !digest.isEmpty && !signature.isEmpty
    }
}
