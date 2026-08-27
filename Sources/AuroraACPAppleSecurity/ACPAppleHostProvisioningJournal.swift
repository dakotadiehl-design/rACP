import AuroraACP
import CryptoKit
import Foundation

package enum ACPAppleHostProvisioningPhase: String, Codable, Sendable {
    case reserved
    case authorityCommitted = "authority_committed"
    case identityActive = "identity_active"
    case committed
}

package struct ACPAppleHostProvisioningRecord: Codable, Sendable, Equatable {
    package static let currentSchemaVersion = 1

    package let schemaVersion: Int
    package let phase: ACPAppleHostProvisioningPhase
    package let nodeID: String
    package let authorizationID: UUID
    package let enrollmentID: String
    package let attemptID: String
    package let attemptGeneration: UInt64
    package let trustDomainID: String?
    package let authorityKeyID: String?
    package let anchorCredentialID: String?
    package let credentialID: String?
    package let identityKeyID: String?
    package var checksum: Data

    package init(
        phase: ACPAppleHostProvisioningPhase,
        nodeID: ACPSecurityNodeID,
        authorizationID: UUID = UUID(),
        enrollmentID: ACPEnrollmentID,
        attemptID: ACPEnrollmentAttemptID,
        attemptGeneration: UInt64 = 1,
        trustDomainID: ACPTrustDomainID? = nil,
        authorityKeyID: ACPIdentityKeyID? = nil,
        anchorCredentialID: ACPCredentialID? = nil,
        credentialID: ACPCredentialID? = nil,
        identityKeyID: ACPIdentityKeyID? = nil
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.phase = phase
        self.nodeID = nodeID.rawValue
        self.authorizationID = authorizationID
        self.enrollmentID = enrollmentID.rawValue
        self.attemptID = attemptID.rawValue
        self.attemptGeneration = attemptGeneration
        self.trustDomainID = trustDomainID?.rawValue
        self.authorityKeyID = authorityKeyID?.rawValue
        self.anchorCredentialID = anchorCredentialID?.rawValue
        self.credentialID = credentialID?.rawValue
        self.identityKeyID = identityKeyID?.rawValue
        checksum = Data()
    }
}

/// Durable lifecycle authority for one public Apple host namespace.
package final class ACPAppleHostProvisioningJournal: @unchecked Sendable {
    private let lock = NSLock()
    private let backend: ACPKeychainCredentialBackend
    private let account: String

    package init(service: String, account: String = "host-provisioning",
                 accessGroup: String? = nil) throws {
        guard (1...128).contains(service.utf8.count),
              (1...128).contains(account.utf8.count) else {
            throw ACPAppleHostProvisioningError.invalidConfiguration
        }
        backend = ACPKeychainCredentialBackend(service: service, accessGroup: accessGroup)
        self.account = account
    }

    package func loadOrReserve(nodeID: ACPSecurityNodeID) throws
        -> ACPAppleHostProvisioningRecord {
        try lock.withLock {
            if let existing = try loadLocked() {
                guard existing.nodeID == nodeID.rawValue else {
                    throw ACPAppleHostProvisioningError.corruptState
                }
                return existing
            }
            let record = ACPAppleHostProvisioningRecord(
                phase: .reserved, nodeID: nodeID,
                enrollmentID: Self.newEnrollmentID(), attemptID: Self.newAttemptID())
            let encoded = try encode(record)
            if try backend.createIfAbsent(name: account, data: encoded) { return try decode(encoded) }
            guard let winner = try loadLocked(), winner.nodeID == nodeID.rawValue else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            return winner
        }
    }

    package func advance(
        _ record: ACPAppleHostProvisioningRecord,
        to phase: ACPAppleHostProvisioningPhase,
        authority: ACPAppleTrustDomainAuthority? = nil,
        identity: ACPAppleLocalIdentityMetadata? = nil
    ) throws -> ACPAppleHostProvisioningRecord {
        try lock.withLock {
            guard let current = try loadLocked(), current == record,
                  Self.rank(phase) >= Self.rank(current.phase),
                  Self.rank(phase) <= Self.rank(current.phase) + 1 else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            let next = try Self.updated(current, phase: phase, authority: authority, identity: identity)
            try backend.write(name: account, data: try encode(next))
            return try loadLocked() ?? { throw ACPAppleHostProvisioningError.storageFailure }()
        }
    }

    package func rotateAttempt(_ record: ACPAppleHostProvisioningRecord) throws
        -> ACPAppleHostProvisioningRecord {
        try lock.withLock {
            guard let current = try loadLocked(), current == record,
                  current.phase == .authorityCommitted,
                  current.attemptGeneration < UInt64.max else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            guard let node = ACPSecurityNodeID(rawValue: current.nodeID),
                  let domainRaw = current.trustDomainID,
                  let domain = ACPTrustDomainID(rawValue: domainRaw),
                  let authorityRaw = current.authorityKeyID,
                  let authorityKey = ACPIdentityKeyID(rawValue: authorityRaw),
                  let anchorRaw = current.anchorCredentialID,
                  let anchor = ACPCredentialID(rawValue: anchorRaw) else {
                throw ACPAppleHostProvisioningError.corruptState
            }
            let next = ACPAppleHostProvisioningRecord(
                phase: .authorityCommitted, nodeID: node,
                enrollmentID: Self.newEnrollmentID(), attemptID: Self.newAttemptID(),
                attemptGeneration: current.attemptGeneration + 1,
                trustDomainID: domain, authorityKeyID: authorityKey,
                anchorCredentialID: anchor)
            try backend.write(name: account, data: try encode(next))
            return try loadLocked() ?? { throw ACPAppleHostProvisioningError.storageFailure }()
        }
    }

    package func load() throws -> ACPAppleHostProvisioningRecord? {
        try lock.withLock { try loadLocked() }
    }

    package func reset() throws {
        try lock.withLock { try backend.delete(name: account) }
    }

    private func loadLocked() throws -> ACPAppleHostProvisioningRecord? {
        guard let data = try backend.read(name: account) else { return nil }
        guard data.count <= 16_384 else { throw ACPAppleHostProvisioningError.corruptState }
        return try decode(data)
    }

    private func encode(_ value: ACPAppleHostProvisioningRecord) throws -> Data {
        var record = value
        record.checksum = Data()
        record.checksum = checksum(record)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        do { return try encoder.encode(record) }
        catch { throw ACPAppleHostProvisioningError.storageFailure }
    }

    private func decode(_ data: Data) throws -> ACPAppleHostProvisioningRecord {
        guard var record = try? JSONDecoder().decode(
            ACPAppleHostProvisioningRecord.self, from: data),
              record.schemaVersion == ACPAppleHostProvisioningRecord.currentSchemaVersion,
              Self.valid(record) else { throw ACPAppleHostProvisioningError.corruptState }
        let stored = record.checksum
        record.checksum = Data()
        guard stored == checksum(record) else { throw ACPAppleHostProvisioningError.corruptState }
        record.checksum = stored
        return record
    }

    private func checksum(_ record: ACPAppleHostProvisioningRecord) -> Data {
        var copy = record; copy.checksum = Data()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard let encoded = try? encoder.encode(copy) else { return Data() }
        return Data(SHA256.hash(data: Data("ACP Apple host provisioning v1".utf8) + encoded))
    }

    private static func updated(
        _ record: ACPAppleHostProvisioningRecord,
        phase: ACPAppleHostProvisioningPhase,
        authority: ACPAppleTrustDomainAuthority?,
        identity: ACPAppleLocalIdentityMetadata?
    ) throws -> ACPAppleHostProvisioningRecord {
        guard let node = ACPSecurityNodeID(rawValue: record.nodeID),
              let enrollment = ACPEnrollmentID(rawValue: record.enrollmentID),
              let attempt = ACPEnrollmentAttemptID(rawValue: record.attemptID) else {
            throw ACPAppleHostProvisioningError.corruptState
        }
        let domain = authority?.identity.trustDomainID
            ?? record.trustDomainID.flatMap(ACPTrustDomainID.init(rawValue:))
        let authorityKey = authority?.identity.authorityKeyID
            ?? record.authorityKeyID.flatMap(ACPIdentityKeyID.init(rawValue:))
        let anchor = authority?.identity.trustAnchorCredentialID
            ?? record.anchorCredentialID.flatMap(ACPCredentialID.init(rawValue:))
        let credential = identity.flatMap { ACPCredentialID(rawValue: $0.credentialID) }
            ?? record.credentialID.flatMap(ACPCredentialID.init(rawValue:))
        let identityKey = identity.flatMap { ACPIdentityKeyID(rawValue: $0.identityKeyID) }
            ?? record.identityKeyID.flatMap(ACPIdentityKeyID.init(rawValue:))
        return .init(
            phase: phase, nodeID: node, authorizationID: record.authorizationID,
            enrollmentID: enrollment, attemptID: attempt,
            attemptGeneration: record.attemptGeneration, trustDomainID: domain,
            authorityKeyID: authorityKey, anchorCredentialID: anchor,
            credentialID: credential, identityKeyID: identityKey)
    }

    private static func valid(_ record: ACPAppleHostProvisioningRecord) -> Bool {
        guard ACPSecurityNodeID(rawValue: record.nodeID) != nil,
              ACPEnrollmentID(rawValue: record.enrollmentID) != nil,
              ACPEnrollmentAttemptID(rawValue: record.attemptID) != nil,
              record.attemptGeneration > 0 else { return false }
        let authorityComplete = record.trustDomainID.flatMap(ACPTrustDomainID.init(rawValue:)) != nil
            && record.authorityKeyID.flatMap(ACPIdentityKeyID.init(rawValue:)) != nil
            && record.anchorCredentialID.flatMap(ACPCredentialID.init(rawValue:)) != nil
        let identityComplete = record.credentialID.flatMap(ACPCredentialID.init(rawValue:)) != nil
            && record.identityKeyID.flatMap(ACPIdentityKeyID.init(rawValue:)) != nil
        switch record.phase {
        case .reserved:
            return !authorityComplete && !identityComplete
        case .authorityCommitted:
            return authorityComplete && !identityComplete
        case .identityActive, .committed:
            return authorityComplete && identityComplete
        }
    }

    private static func rank(_ phase: ACPAppleHostProvisioningPhase) -> Int {
        switch phase {
        case .reserved: return 0
        case .authorityCommitted: return 1
        case .identityActive: return 2
        case .committed: return 3
        }
    }

    private static func newEnrollmentID() -> ACPEnrollmentID {
        ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!
    }

    private static func newAttemptID() -> ACPEnrollmentAttemptID {
        ACPEnrollmentAttemptID(rawValue: UUID().uuidString.lowercased())!
    }
}
