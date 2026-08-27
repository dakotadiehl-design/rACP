import CryptoKit
import Foundation

package struct ACPPublishedRevocationState: Sendable, Equatable {
    package let body: Data
    package let signature: Data
    package let epoch: UInt64
}

package actor ACPRevocationPublisher {
    private struct Snapshot: Codable {
        var version = 1
        let trustDomainID: String
        let issuerKeyID: String
        var epoch: UInt64 = 0
        var entries: [Entry] = []
        var previousSnapshotHash: String?
        var latestBody: Data?
        var latestSignature: Data?
        var latestIssuedAt: String?
        var latestNextUpdate: String?
    }
    private struct Entry: Codable, Equatable {
        let credentialID: String
        let nodeID: String
        let revokedAt: String
        let reason: String
        let replacementCredentialID: String?
    }

    private let domain: ACPTrustDomainID
    private let signer: any ACPSigningKeyHandle
    private let backend: any ACPIssuanceJournalBackend
    private let maximumEntries: Int
    private var snapshot: Snapshot

    package init(domain: ACPTrustDomainID, signer: any ACPSigningKeyHandle,
                 backend: any ACPIssuanceJournalBackend, maximumEntries: Int = 4096) throws {
        guard (1...4096).contains(maximumEntries) else { throw ACPSecurityErrorCode.resourceLimit }
        self.domain = domain; self.signer = signer; self.backend = backend
        self.maximumEntries = maximumEntries
        if let raw = try backend.load() {
            guard raw.count <= 8 * 1_048_576,
                  let value = try? JSONDecoder().decode(Snapshot.self, from: raw), value.version == 1,
                  value.trustDomainID == domain.rawValue,
                  value.issuerKeyID == signer.keyID.rawValue,
                  value.entries.count <= maximumEntries,
                  value.entries.map(\.credentialID) == value.entries.map(\.credentialID).sorted(),
                  Set(value.entries.map(\.credentialID)).count == value.entries.count,
                  value.entries.allSatisfy(Self.valid),
                  (value.previousSnapshotHash == nil
                    || ACPCredentialID(rawValue: value.previousSnapshotHash!) != nil),
                  value.entries.isEmpty || value.epoch > 0,
                  Self.validPublicationFields(value)
            else { throw ACPSecurityErrorCode.storageFailed }
            snapshot = value
        } else {
            snapshot = Snapshot(trustDomainID: domain.rawValue,
                                issuerKeyID: signer.keyID.rawValue)
        }
    }

    package func revoke(
        credentialID: ACPCredentialID, nodeID: ACPSecurityNodeID, reason: String,
        replacementCredentialID: ACPCredentialID? = nil, at date: Date,
        nextUpdate: Date
    ) throws -> ACPPublishedRevocationState {
        guard ["key_compromise", "superseded", "retired", "policy", "operator_request"].contains(reason),
              nextUpdate > date, replacementCredentialID != credentialID
        else { throw ACPSecurityErrorCode.credentialInvalid }
        let entry = Entry(credentialID: credentialID.rawValue, nodeID: nodeID.rawValue,
                          revokedAt: Self.timestamp(date), reason: reason,
                          replacementCredentialID: replacementCredentialID?.rawValue)
        if let existing = snapshot.entries.first(where: { $0.credentialID == credentialID.rawValue }) {
            guard existing == entry else { throw ACPSecurityErrorCode.credentialInvalid }
            return try advanceAndPublish(issuedAt: date, nextUpdate: nextUpdate)
        }
        guard snapshot.entries.count < maximumEntries else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        let old = snapshot
        snapshot.entries.append(entry)
        snapshot.entries.sort { $0.credentialID < $1.credentialID }
        do {
            return try advanceAndPublish(issuedAt: date, nextUpdate: nextUpdate)
        } catch { snapshot = old; throw error }
    }

    package func current(issuedAt: Date, nextUpdate: Date) throws -> ACPPublishedRevocationState {
        guard nextUpdate > issuedAt else { throw ACPSecurityErrorCode.credentialInvalid }
        return try advanceAndPublish(issuedAt: issuedAt, nextUpdate: nextUpdate)
    }

    package func latest(at now: Date, maximumSnapshotAge: TimeInterval) throws
        -> ACPPublishedRevocationState {
        guard (0...172_800).contains(maximumSnapshotAge),
              let body = snapshot.latestBody, let signature = snapshot.latestSignature,
              let issuedRaw = snapshot.latestIssuedAt, let nextRaw = snapshot.latestNextUpdate,
              let issued = ISO8601DateFormatter().date(from: issuedRaw),
              let next = ISO8601DateFormatter().date(from: nextRaw),
              now >= issued.addingTimeInterval(-120),
              now <= min(next, issued.addingTimeInterval(maximumSnapshotAge))
        else { throw ACPSecurityErrorCode.authenticationFailed }
        return .init(body: body, signature: signature, epoch: snapshot.epoch)
    }

    private func advanceAndPublish(
        issuedAt: Date, nextUpdate: Date
    ) throws -> ACPPublishedRevocationState {
        guard nextUpdate > issuedAt, snapshot.epoch < UInt64.max else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        let old = snapshot
        snapshot.epoch += 1
        do {
            let published = try publish(issuedAt: issuedAt, nextUpdate: nextUpdate)
            snapshot.previousSnapshotHash = ACPCredentialIdentifiers
                .credentialID(for: published.body).rawValue
            snapshot.latestBody = published.body
            snapshot.latestSignature = published.signature
            snapshot.latestIssuedAt = Self.timestamp(issuedAt)
            snapshot.latestNextUpdate = Self.timestamp(nextUpdate)
            try persist()
            return published
        } catch {
            snapshot = old
            throw error
        }
    }

    private func publish(issuedAt: Date, nextUpdate: Date) throws -> ACPPublishedRevocationState {
        let values: [AnySendable] = snapshot.entries.map { entry in
            var fields: [String: AnySendable] = [
                "credential_id": .string(entry.credentialID), "node_id": .string(entry.nodeID),
                "revoked_at": .string(entry.revokedAt), "reason": .string(entry.reason),
            ]
            if let replacement = entry.replacementCredentialID {
                fields["replacement_credential_id"] = .string(replacement)
            }
            return .object(fields)
        }
        var body: [String: AnySendable] = [
            "format": .string("acp-revocation-snapshot-v1"),
            "trust_domain_id": .string(domain.rawValue), "epoch": .uint(snapshot.epoch),
            "issued_at": .string(Self.timestamp(issuedAt)), "next_update": .string(Self.timestamp(nextUpdate)),
            "entries": .array(values), "issuer_key_id": .string(signer.keyID.rawValue),
        ]
        if let previous = snapshot.previousSnapshotHash { body["previous_snapshot_hash"] = .string(previous) }
        let encoded = try ACPEncoding.encodeValue(.plain(.object(body)))
        let digest = Data(SHA256.hash(data: Data("ACP revocation state v1".utf8) + encoded))
        let signature = try signer.sign(digest: digest)
        return .init(body: encoded, signature: signature, epoch: snapshot.epoch)
    }

    private func persist() throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(snapshot)
        guard encoded.count <= 8 * 1_048_576 else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        try backend.replace(with: encoded)
    }
    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private static func valid(_ entry: Entry) -> Bool {
        guard ACPCredentialID(rawValue: entry.credentialID) != nil,
              ACPSecurityNodeID(rawValue: entry.nodeID) != nil,
              ["key_compromise", "superseded", "retired", "policy", "operator_request"]
                .contains(entry.reason),
              let date = ISO8601DateFormatter().date(from: entry.revokedAt),
              timestamp(date) == entry.revokedAt else { return false }
        if let replacement = entry.replacementCredentialID {
            return ACPCredentialID(rawValue: replacement) != nil
                && replacement != entry.credentialID
        }
        return true
    }

    private static func validPublicationFields(_ value: Snapshot) -> Bool {
        if value.epoch == 0 {
            return value.latestBody == nil && value.latestSignature == nil
                && value.latestIssuedAt == nil && value.latestNextUpdate == nil
        }
        guard let body = value.latestBody, !body.isEmpty,
              let signature = value.latestSignature, !signature.isEmpty,
              let issuedRaw = value.latestIssuedAt,
              let nextRaw = value.latestNextUpdate,
              let issued = ISO8601DateFormatter().date(from: issuedRaw),
              let next = ISO8601DateFormatter().date(from: nextRaw),
              timestamp(issued) == issuedRaw, timestamp(next) == nextRaw,
              issued < next,
              value.previousSnapshotHash
                == ACPCredentialIdentifiers.credentialID(for: body).rawValue,
              case .object(let fields) = try? ACPEncoding.decodeValue(body),
              (try? ACPEncoding.encodeValue(.plain(.object(fields)))) == body,
              fields["format"] == .string("acp-revocation-snapshot-v1"),
              fields["trust_domain_id"] == .string(value.trustDomainID),
              fields["issuer_key_id"] == .string(value.issuerKeyID),
              unsigned(fields["epoch"]) == value.epoch,
              fields["issued_at"] == .string(issuedRaw),
              fields["next_update"] == .string(nextRaw),
              case .array(let encodedEntries) = fields["entries"],
              encodedEntries.count == value.entries.count
        else { return false }
        return zip(encodedEntries, value.entries).allSatisfy { encoded, entry in
            guard case .object(let item) = encoded,
                  item["credential_id"] == .string(entry.credentialID),
                  item["node_id"] == .string(entry.nodeID),
                  item["revoked_at"] == .string(entry.revokedAt),
                  item["reason"] == .string(entry.reason)
            else { return false }
            if let replacement = entry.replacementCredentialID {
                return item["replacement_credential_id"] == .string(replacement)
                    && item.count == 5
            }
            return item["replacement_credential_id"] == nil && item.count == 4
        }
    }

    private static func unsigned(_ value: AnySendable?) -> UInt64? {
        switch value {
        case .uint(let number): return number
        case .int(let number) where number >= 0: return UInt64(number)
        default: return nil
        }
    }
}
