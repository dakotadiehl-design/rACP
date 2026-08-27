import CryptoKit
import Foundation

package enum ACPCredentialIssuancePurpose: String, Codable, Sendable {
    case initial, renewal, keyRotation = "key_rotation"
}

package struct ACPIssuanceCeremonyFacts: Sendable, Equatable {
    package let authorizationID: UUID
    package let enrollmentID: ACPEnrollmentID
    package let attemptID: ACPEnrollmentAttemptID
    package let transcriptHash: Data
    package let candidateNodeID: ACPSecurityNodeID
    package let candidateInstanceID: UUID
    package let commissionerNodeID: ACPSecurityNodeID
    package let commissionerInstanceID: UUID
    package let trustDomainID: ACPTrustDomainID
    package let authorityKeyID: ACPIdentityKeyID
    package let candidatePublicKeySPKI: Data
    package let identityKeyID: ACPIdentityKeyID
    package let requestedRole: String
    package let permissionsDigest: String
    package let approvalID: UUID
    package let approvalTime: Date
    package let expiresAt: Date
    package let cancellationGeneration: UInt64
    package let purpose: ACPCredentialIssuancePurpose
    package let replacesCredentialID: ACPCredentialID?

    package init(
        authorizationID: UUID, enrollmentID: ACPEnrollmentID, attemptID: ACPEnrollmentAttemptID,
        transcriptHash: Data, candidateNodeID: ACPSecurityNodeID, candidateInstanceID: UUID,
        commissionerNodeID: ACPSecurityNodeID, commissionerInstanceID: UUID,
        trustDomainID: ACPTrustDomainID, authorityKeyID: ACPIdentityKeyID,
        candidatePublicKeySPKI: Data, identityKeyID: ACPIdentityKeyID,
        requestedRole: String, permissionsDigest: String, approvalID: UUID,
        approvalTime: Date, expiresAt: Date, cancellationGeneration: UInt64,
        purpose: ACPCredentialIssuancePurpose = .initial,
        replacesCredentialID: ACPCredentialID? = nil
    ) throws {
        guard transcriptHash.count == 32, candidatePublicKeySPKI.count == 91,
              (1...64).contains(requestedRole.utf8.count),
              permissionsDigest.range(of: #"^sha256:[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              approvalTime < expiresAt,
              (purpose == .initial) == (replacesCredentialID == nil)
        else { throw ACPSecurityErrorCode.credentialInvalid }
        self.authorizationID = authorizationID; self.enrollmentID = enrollmentID; self.attemptID = attemptID
        self.transcriptHash = transcriptHash; self.candidateNodeID = candidateNodeID
        self.candidateInstanceID = candidateInstanceID; self.commissionerNodeID = commissionerNodeID
        self.commissionerInstanceID = commissionerInstanceID; self.trustDomainID = trustDomainID
        self.authorityKeyID = authorityKeyID; self.candidatePublicKeySPKI = candidatePublicKeySPKI
        self.identityKeyID = identityKeyID; self.requestedRole = requestedRole
        self.permissionsDigest = permissionsDigest; self.approvalID = approvalID
        self.approvalTime = approvalTime; self.expiresAt = expiresAt
        self.cancellationGeneration = cancellationGeneration; self.purpose = purpose
        self.replacesCredentialID = replacesCredentialID
    }
}

/// One-shot evidence produced only by the enrollment authorization gate. It is
/// deliberately a non-Codable reference capability with no public initializer.
package final class ACPIssuanceAuthorization: @unchecked Sendable {
    package let facts: ACPIssuanceCeremonyFacts
    private let stillValid: @Sendable () -> Bool
    private let lock = NSLock()
    private var consumed = false

    package init(validated facts: ACPIssuanceCeremonyFacts,
                 stillValid: @escaping @Sendable () -> Bool) {
        self.facts = facts; self.stillValid = stillValid
    }

    package func consume(now: Date) throws -> ACPIssuanceCeremonyFacts {
        try lock.withIssuanceLock {
            guard !consumed else { throw ACPSecurityErrorCode.enrollmentReplayed }
            consumed = true
            guard now < facts.expiresAt, stillValid()
            else { throw ACPSecurityErrorCode.enrollmentExpired }
            return facts
        }
    }

    /// Keeps the capability unconsumed when the durable operation fails. The
    /// operation must make the authorization ID durable before returning.
    fileprivate func consumeCommitting<T>(
        now: Date, _ operation: (ACPIssuanceCeremonyFacts) throws -> T
    ) throws -> T {
        try lock.withIssuanceLock {
            guard !consumed else { throw ACPSecurityErrorCode.enrollmentReplayed }
            guard now < facts.expiresAt, stillValid()
            else { throw ACPSecurityErrorCode.enrollmentExpired }
            let result = try operation(facts)
            consumed = true
            return result
        }
    }
}

package enum ACPIssuanceAuthorizationGate {
    package static func authorize(
        facts: ACPIssuanceCeremonyFacts,
        cryptographyConfirmed: Bool,
        candidateIdentityBound: Bool,
        approvalMatchesCeremony: Bool,
        approvalUnexpired: Bool,
        approvalSingleUse: Bool,
        cancelled: Bool,
        replayed: Bool,
        publicKeyValid: Bool,
        trustDomainValid: Bool,
        stillValid: @escaping @Sendable () -> Bool
    ) throws -> ACPIssuanceAuthorization {
        guard cryptographyConfirmed, candidateIdentityBound, approvalMatchesCeremony,
              approvalUnexpired, approvalSingleUse, !cancelled, !replayed,
              publicKeyValid, trustDomainValid,
              ACPCredentialIdentifiers.identityKeyID(for: facts.candidatePublicKeySPKI) == facts.identityKeyID
        else { throw ACPSecurityErrorCode.authenticationFailed }
        return ACPIssuanceAuthorization(validated: facts, stillValid: stillValid)
    }
}

/// One-shot, non-serializable evidence that an exact installation result was
/// authenticated with the candidate-confirm key derived from a confirmed
/// SPAKE2+ exchange.
package final class ACPVerifiedEnrollmentInstallResult: @unchecked Sendable {
    package let attemptID: ACPEnrollmentAttemptID
    package let credentialID: ACPCredentialID
    package let identityKeyID: ACPIdentityKeyID
    package let trustDomainID: ACPTrustDomainID
    package let storagePosture: ACPStoragePosture
    package let proofOfPossession: Data

    fileprivate init(attemptID: ACPEnrollmentAttemptID, credentialID: ACPCredentialID,
                     identityKeyID: ACPIdentityKeyID, trustDomainID: ACPTrustDomainID,
                     storagePosture: ACPStoragePosture, proofOfPossession: Data) {
        self.attemptID = attemptID; self.credentialID = credentialID
        self.identityKeyID = identityKeyID; self.trustDomainID = trustDomainID
        self.storagePosture = storagePosture; self.proofOfPossession = proofOfPossession
    }
}

/// Consumes the confirmed PAKE key on its first verification attempt. A bad
/// confirmation is terminal, preventing retries from becoming an oracle.
package final class ACPEnrollmentInstallVerifier: @unchecked Sendable {
    private let confirmedKey: ACPConfirmedSPAKE2PlusKey
    private let transcriptHash: Data
    private let lock = NSLock()
    private var consumed = false

    package init(confirmedKey: ACPConfirmedSPAKE2PlusKey, transcriptHash: Data) throws {
        guard transcriptHash.count == 32 else { throw ACPSecurityErrorCode.transcriptMismatch }
        self.confirmedKey = confirmedKey; self.transcriptHash = transcriptHash
    }

    package func verify(
        values: [String: AnySendable], confirmation: Data
    ) throws -> ACPVerifiedEnrollmentInstallResult {
        try lock.withIssuanceLock {
            guard !consumed else { throw ACPSecurityErrorCode.enrollmentReplayed }
            consumed = true
            let sharedKey = confirmedKey.withUnsafeBytes { Data($0) }
            let keys = ACPSecurityContext.deriveEnrollmentKeys(
                sharedKey: sharedKey, transcriptHash: transcriptHash)
            guard let confirmationKey = keys["candidate confirm"],
                  let expected = try? ACPSecurityContext.installConfirmation(
                    candidateConfirmKey: confirmationKey, values: values),
                  ACPSecurityContext.channelBindingsEqual(expected, confirmation),
                  case .string(let attemptRaw) = values["attempt_id"],
                  let attemptID = ACPEnrollmentAttemptID(rawValue: attemptRaw),
                  case .string(let credentialRaw) = values["credential_id"],
                  let credentialID = ACPCredentialID(rawValue: credentialRaw),
                  case .string(let identityRaw) = values["identity_key_id"],
                  let identityKeyID = ACPIdentityKeyID(rawValue: identityRaw),
                  case .string(let domainRaw) = values["trust_domain_id"],
                  let trustDomainID = ACPTrustDomainID(rawValue: domainRaw),
                  case .object(let posture) = values["storage_posture"],
                  case .string(let classRaw) = posture["class"],
                  let storageClass = ACPStorageClass(rawValue: classRaw),
                  case .bool(let hardwareBacked) = posture["hardware_backed"],
                  case .bool(let privateKeyExportable) = posture["private_key_exportable"],
                  case .bytes(let proof) = values["proof_of_possession"]
            else { throw ACPSecurityErrorCode.keyConfirmationFailed }
            return .init(
                attemptID: attemptID, credentialID: credentialID, identityKeyID: identityKeyID,
                trustDomainID: trustDomainID,
                storagePosture: .init(storageClass: storageClass,
                                      hardwareBacked: hardwareBacked,
                                      privateKeyExportable: privateKeyExportable),
                proofOfPossession: proof)
        }
    }
}

package struct ACPIssuedCredentialPackage: Sendable, Equatable {
    package let authorizationID: UUID
    package let leafDER: Data
    package let trustAnchorDER: Data
    package let credentialID: ACPCredentialID
    package let identityKeyID: ACPIdentityKeyID
    package let authorityKeyID: ACPIdentityKeyID
    package let trustDomainID: ACPTrustDomainID
    package let nodeID: ACPSecurityNodeID
    package let enrollmentID: ACPEnrollmentID
    package let attemptID: ACPEnrollmentAttemptID
    package let transcriptHash: Data
    package let serial: Data
    package let notBefore: Date
    package let expiresAt: Date
    package let rotationDeadline: Date
    package let replacesCredentialID: ACPCredentialID?

    package init(
        authorizationID: UUID, leafDER: Data, trustAnchorDER: Data, credentialID: ACPCredentialID,
        identityKeyID: ACPIdentityKeyID, authorityKeyID: ACPIdentityKeyID,
        trustDomainID: ACPTrustDomainID, nodeID: ACPSecurityNodeID,
        enrollmentID: ACPEnrollmentID, attemptID: ACPEnrollmentAttemptID,
        transcriptHash: Data, serial: Data, notBefore: Date, expiresAt: Date,
        rotationDeadline: Date, replacesCredentialID: ACPCredentialID?
    ) throws {
        guard !leafDER.isEmpty, leafDER.count <= 8192, !trustAnchorDER.isEmpty,
              trustAnchorDER.count <= 8192, transcriptHash.count == 32,
              serial.count == 16, serial.contains(where: { $0 != 0 }),
              notBefore < expiresAt, rotationDeadline >= notBefore, rotationDeadline <= expiresAt,
              ACPCredentialIdentifiers.credentialID(for: leafDER) == credentialID
        else { throw ACPSecurityErrorCode.credentialInvalid }
        self.authorizationID = authorizationID; self.leafDER = leafDER; self.trustAnchorDER = trustAnchorDER
        self.credentialID = credentialID; self.identityKeyID = identityKeyID
        self.authorityKeyID = authorityKeyID; self.trustDomainID = trustDomainID
        self.nodeID = nodeID; self.enrollmentID = enrollmentID; self.attemptID = attemptID
        self.transcriptHash = transcriptHash; self.serial = serial; self.notBefore = notBefore
        self.expiresAt = expiresAt; self.rotationDeadline = rotationDeadline
        self.replacesCredentialID = replacesCredentialID
    }
}

package protocol ACPCredentialIssuing: Sendable {
    func issueCredential(authorization: ACPIssuanceAuthorization) async throws -> ACPIssuedCredentialPackage
}

package enum ACPCredentialIdentifiers {
    package static func credentialID(for bytes: Data) -> ACPCredentialID {
        ACPCredentialID(rawValue: digest(bytes))!
    }
    package static func identityKeyID(for canonicalSPKI: Data) -> ACPIdentityKeyID {
        ACPIdentityKeyID(rawValue: digest(canonicalSPKI))!
    }
    private static func digest(_ bytes: Data) -> String {
        "sha256:" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

package protocol ACPIssuanceJournalBackend: Sendable {
    func load() throws -> Data?
    func replace(with data: Data) throws
}

package struct ACPIssuanceReservation: Sendable, Equatable {
    package let authorizationID: UUID
    package let serial: Data
    package let existingPackage: ACPIssuedCredentialPackage?
}

package actor ACPIssuanceJournal {
    private struct Snapshot: Codable {
        var version = 1
        var entries: [Entry] = []
    }
    private struct Entry: Codable {
        enum State: String, Codable { case reserved, signed, delivered, installedReceiptVerified, closed, revoked }
        let authorizationID: UUID
        let authorityKeyID: String
        let serial: Data
        var state: State
        var package: StoredPackage?
    }
    private struct StoredPackage: Codable {
        let authorizationID: UUID
        let leafDER, trustAnchorDER, transcriptHash, serial: Data
        let credentialID, identityKeyID, authorityKeyID, trustDomainID, nodeID: String
        let enrollmentID, attemptID: String
        let notBefore, expiresAt, rotationDeadline: Date
        let replacesCredentialID: String?
    }

    private let backend: any ACPIssuanceJournalBackend
    private let maximumEntries: Int
    private var snapshot: Snapshot

    package init(backend: any ACPIssuanceJournalBackend, maximumEntries: Int = 16_384) throws {
        guard (1...1_000_000).contains(maximumEntries) else { throw ACPSecurityErrorCode.resourceLimit }
        self.backend = backend; self.maximumEntries = maximumEntries
        if let bytes = try backend.load() {
            guard let decoded = try? JSONDecoder().decode(Snapshot.self, from: bytes), decoded.version == 1,
                  decoded.entries.count <= maximumEntries,
                  Set(decoded.entries.map(\.authorizationID)).count == decoded.entries.count,
                  Set(decoded.entries.map { $0.authorityKeyID + ":" + $0.serial.hex }).count == decoded.entries.count,
                  try decoded.entries.allSatisfy({ try Self.validPersistedEntry($0) })
            else { throw ACPSecurityErrorCode.storageFailed }
            snapshot = decoded
        } else { snapshot = Snapshot() }
    }

    package func reserve(
        authorizationID: UUID, authorityKeyID: ACPIdentityKeyID,
        random: any ACPSecureRandomProvider
    ) throws -> ACPIssuanceReservation {
        try reserveSynchronously(authorizationID: authorizationID,
                                 authorityKeyID: authorityKeyID, random: random)
    }

    private func reserveSynchronously(
        authorizationID: UUID, authorityKeyID: ACPIdentityKeyID,
        random: any ACPSecureRandomProvider
    ) throws -> ACPIssuanceReservation {
        if let entry = snapshot.entries.first(where: { $0.authorizationID == authorizationID }) {
            guard entry.authorityKeyID == authorityKeyID.rawValue else {
                throw ACPSecurityErrorCode.trustDomainMismatch
            }
            guard entry.state != .revoked, entry.state != .closed else {
                throw ACPSecurityErrorCode.enrollmentReplayed
            }
            return .init(authorizationID: authorizationID, serial: entry.serial,
                         existingPackage: try entry.package.map(restore))
        }
        guard snapshot.entries.count < maximumEntries else { throw ACPSecurityErrorCode.resourceLimit }
        var serial = Data()
        for _ in 0..<16 {
            let secret = try random.bytes(count: 16)
            serial = secret.withUnsafeBytes { Data($0) }; secret.clear()
            guard serial.count == 16 else { throw ACPSecurityErrorCode.resourceLimit }
            if serial.contains(where: { $0 != 0 }) && !snapshot.entries.contains(where: {
                $0.authorityKeyID == authorityKeyID.rawValue && $0.serial == serial
            }) { break }
            serial.removeAll(keepingCapacity: false)
        }
        guard serial.count == 16 else { throw ACPSecurityErrorCode.storageFailed }
        let old = snapshot
        snapshot.entries.append(.init(authorizationID: authorizationID,
                                      authorityKeyID: authorityKeyID.rawValue,
                                      serial: serial, state: .reserved, package: nil))
        do { try persist() } catch { snapshot = old; throw error }
        return .init(authorizationID: authorizationID, serial: serial, existingPackage: nil)
    }

    /// Atomically validates/consumes an in-process authorization capability
    /// and durably reserves its authority-scoped serial. A persistence error
    /// leaves the capability available for an exact retry.
    package func consumeAndReserve(
        authorization: ACPIssuanceAuthorization, now: Date,
        expectedDomain: ACPTrustDomainID, expectedAuthorityKeyID: ACPIdentityKeyID,
        random: any ACPSecureRandomProvider
    ) throws -> (facts: ACPIssuanceCeremonyFacts, reservation: ACPIssuanceReservation) {
        try authorization.consumeCommitting(now: now) { facts in
            guard facts.trustDomainID == expectedDomain,
                  facts.authorityKeyID == expectedAuthorityKeyID else {
                throw ACPSecurityErrorCode.trustDomainMismatch
            }
            let reservation = try reserveSynchronously(
                authorizationID: facts.authorizationID,
                authorityKeyID: expectedAuthorityKeyID, random: random)
            return (facts, reservation)
        }
    }

    package func recordSigned(_ package: ACPIssuedCredentialPackage, authorizationID: UUID) throws {
        guard let index = snapshot.entries.firstIndex(where: { $0.authorizationID == authorizationID }),
              snapshot.entries[index].serial == package.serial,
              snapshot.entries[index].authorityKeyID == package.authorityKeyID.rawValue,
              package.authorizationID == authorizationID else { throw ACPSecurityErrorCode.storageFailed }
        if let existing = snapshot.entries[index].package {
            guard try restore(existing) == package else { throw ACPSecurityErrorCode.enrollmentReplayed }
            return
        }
        let old = snapshot
        snapshot.entries[index].package = store(package); snapshot.entries[index].state = .signed
        do { try persist() } catch { snapshot = old; throw error }
    }

    package func markDelivered(_ authorizationID: UUID) throws { try transition(authorizationID, to: .delivered) }
    package func markInstallReceiptVerified(_ authorizationID: UUID) throws {
        try transition(authorizationID, to: .installedReceiptVerified)
    }
    package func markRevoked(_ authorizationID: UUID) throws { try transition(authorizationID, to: .revoked) }

    private func transition(_ id: UUID, to state: Entry.State) throws {
        guard let index = snapshot.entries.firstIndex(where: { $0.authorizationID == id }),
              snapshot.entries[index].package != nil else { throw ACPSecurityErrorCode.storageFailed }
        let current = snapshot.entries[index].state
        if current == state || (current == .installedReceiptVerified && state == .delivered) { return }
        let legal = (current == .signed && state == .delivered)
            || (current == .delivered && state == .installedReceiptVerified)
            || (state == .revoked && current != .closed)
        guard legal else { throw ACPSecurityErrorCode.enrollmentReplayed }
        let old = snapshot; snapshot.entries[index].state = state
        do { try persist() } catch { snapshot = old; throw error }
    }
    private func persist() throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(snapshot)
        guard bytes.count <= 64 * 1_048_576 else { throw ACPSecurityErrorCode.resourceLimit }
        try backend.replace(with: bytes)
    }
    private func store(_ value: ACPIssuedCredentialPackage) -> StoredPackage {
        .init(authorizationID: value.authorizationID,
              leafDER: value.leafDER, trustAnchorDER: value.trustAnchorDER,
              transcriptHash: value.transcriptHash, serial: value.serial,
              credentialID: value.credentialID.rawValue, identityKeyID: value.identityKeyID.rawValue,
              authorityKeyID: value.authorityKeyID.rawValue, trustDomainID: value.trustDomainID.rawValue,
              nodeID: value.nodeID.rawValue, enrollmentID: value.enrollmentID.rawValue,
              attemptID: value.attemptID.rawValue, notBefore: value.notBefore,
              expiresAt: value.expiresAt, rotationDeadline: value.rotationDeadline,
              replacesCredentialID: value.replacesCredentialID?.rawValue)
    }
    private func restore(_ value: StoredPackage) throws -> ACPIssuedCredentialPackage {
        try Self.restoreStatic(value)
    }

    private static func validPersistedEntry(_ entry: Entry) throws -> Bool {
        guard ACPIdentityKeyID(rawValue: entry.authorityKeyID) != nil,
              entry.serial.count == 16, entry.serial.contains(where: { $0 != 0 }) else { return false }
        switch (entry.state, entry.package) {
        case (.reserved, nil): return true
        case (.reserved, .some), (_, nil): return false
        case (_, .some(let stored)):
            guard stored.authorizationID == entry.authorizationID,
                  stored.authorityKeyID == entry.authorityKeyID,
                  stored.serial == entry.serial else { return false }
            _ = try restoreStatic(stored)
            return true
        }
    }

    private static func restoreStatic(_ value: StoredPackage) throws -> ACPIssuedCredentialPackage {
        guard let credential = ACPCredentialID(rawValue: value.credentialID),
              let key = ACPIdentityKeyID(rawValue: value.identityKeyID),
              let authority = ACPIdentityKeyID(rawValue: value.authorityKeyID),
              let domain = ACPTrustDomainID(rawValue: value.trustDomainID),
              let node = ACPSecurityNodeID(rawValue: value.nodeID),
              let enrollment = ACPEnrollmentID(rawValue: value.enrollmentID),
              let attempt = ACPEnrollmentAttemptID(rawValue: value.attemptID)
        else { throw ACPSecurityErrorCode.storageFailed }
        let replacement = value.replacesCredentialID.flatMap(ACPCredentialID.init(rawValue:))
        guard value.replacesCredentialID == nil || replacement != nil else {
            throw ACPSecurityErrorCode.storageFailed
        }
        return try .init(authorizationID: value.authorizationID,
                         leafDER: value.leafDER, trustAnchorDER: value.trustAnchorDER,
                         credentialID: credential, identityKeyID: key, authorityKeyID: authority,
                         trustDomainID: domain, nodeID: node, enrollmentID: enrollment,
                         attemptID: attempt, transcriptHash: value.transcriptHash, serial: value.serial,
                         notBefore: value.notBefore, expiresAt: value.expiresAt,
                         rotationDeadline: value.rotationDeadline, replacesCredentialID: replacement)
    }
}

private extension NSLock {
    func withIssuanceLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }; return try body()
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
