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
            guard let value = try? JSONDecoder().decode(Snapshot.self, from: raw), value.version == 1,
                  value.trustDomainID == domain.rawValue,
                  value.issuerKeyID == signer.keyID.rawValue,
                  value.entries.count <= maximumEntries,
                  value.entries.map(\.credentialID) == value.entries.map(\.credentialID).sorted(),
                  Set(value.entries.map(\.credentialID)).count == value.entries.count,
                  value.entries.allSatisfy(Self.valid),
                  (value.previousSnapshotHash == nil
                    || ACPCredentialID(rawValue: value.previousSnapshotHash!) != nil),
                  value.entries.isEmpty || value.epoch > 0
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
        try backend.replace(with: encoder.encode(snapshot))
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
}
