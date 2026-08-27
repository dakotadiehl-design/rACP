import AuroraACP
import CryptoKit
import Foundation

package struct ACPAppleActiveCredential: Sendable {
    package let generation: UInt64
    package let identity: ACPAppleLocalIdentity
}

/// Owns the authoritative selector for real Keychain identities. Presence of a
/// certificate/key pair is never sufficient: only the checksummed active
/// record selects the identity returned after restart.
package actor ACPAppleCredentialLifecycleStore {
    private struct Selection: Codable, Equatable {
        let generation: UInt64
        let label: String
        let credentialID: String
        let identityKeyID: String
    }
    private struct Snapshot: Codable {
        var version = 1
        var active: Selection?
        var staged: Selection?
        var retiredLabels: [String] = []
        var checksum = Data()
    }

    private let identityStore: ACPAppleIdentityStore
    private let backend: ACPKeychainCredentialBackend
    private let account: String
    private let labelPrefix: String
    private let identity: ACPIdentity

    package init(
        identityStore: ACPAppleIdentityStore, identity: ACPIdentity,
        labelPrefix: String, service: String = "com.aurora.acp.identity-lifecycle",
        account: String = "active-credential", accessGroup: String? = nil
    ) throws {
        guard (1...80).contains(labelPrefix.utf8.count),
              (1...128).contains(account.utf8.count) else {
            throw ACPAppleSecurityError.resourceLimit
        }
        self.identityStore = identityStore; self.identity = identity
        self.labelPrefix = labelPrefix; self.account = account
        backend = ACPKeychainCredentialBackend(service: service, accessGroup: accessGroup)
    }

    package func stage(
        package: ACPIssuedCredentialPackage, pendingKey: ACPApplePendingCandidateKey,
        generation: UInt64
    ) async throws -> ACPAppleDurableInstallEvidence {
        var snapshot = try load()
        guard generation > 0, snapshot.staged == nil,
              snapshot.active.map({ generation > $0.generation }) ?? true else {
            throw ACPAppleSecurityError.duplicateIdentity
        }
        let selection = Selection(
            generation: generation, label: try label(generation),
            credentialID: package.credentialID.rawValue,
            identityKeyID: package.identityKeyID.rawValue)
        snapshot.staged = selection
        try save(snapshot)
        do {
            return try await identityStore.installIssuedCertificate(
                package, pendingKey: pendingKey, label: selection.label,
                identity: identity)
        } catch {
            snapshot = try load()
            if snapshot.staged == selection {
                snapshot.staged = nil
                try save(snapshot)
            }
            throw error
        }
    }

    package func activate(
        _ evidence: ACPAppleDurableInstallEvidence, generation: UInt64
    ) async throws -> ACPAppleActiveCredential {
        var snapshot = try load()
        guard let staged = snapshot.staged, staged.generation == generation,
              staged.credentialID == evidence.credentialID.rawValue,
              staged.identityKeyID == evidence.identityKeyID.rawValue,
              evidence.localIdentity.metadata.credentialID == staged.credentialID,
              evidence.localIdentity.metadata.identityKeyID == staged.identityKeyID else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        let durable = try await identityStore.load(label: staged.label, identity: identity)
        guard durable.metadata.credentialID == staged.credentialID,
              durable.metadata.identityKeyID == staged.identityKeyID else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        if let old = snapshot.active, old.label != staged.label {
            snapshot.retiredLabels.append(old.label)
        }
        guard snapshot.retiredLabels.count <= 2 else {
            throw ACPAppleSecurityError.resourceLimit
        }
        snapshot.active = staged; snapshot.staged = nil
        try save(snapshot) // authoritative credential commitment point
        // Retirement is post-commit maintenance. Failure leaves the bounded
        // retired-label journal intact for recovery; it cannot make a
        // successfully committed active identity appear to have failed.
        try? await cleanRetired()
        return .init(generation: generation, identity: durable)
    }

    package func recover() async throws -> ACPAppleActiveCredential? {
        try await recoverReportingDiscardedStaging().active
    }

    package func recoverReportingDiscardedStaging() async throws
        -> (active: ACPAppleActiveCredential?, discardedStaging: Bool) {
        var snapshot = try load()
        let discardedStaging = snapshot.staged != nil
        if let staged = snapshot.staged {
            try await identityStore.reset(label: staged.label)
            snapshot.staged = nil
            try save(snapshot)
        }
        // A locked or temporarily unavailable retired item must not hide the
        // independently validated authoritative active identity.
        try? await cleanRetired()
        snapshot = try load()
        guard let active = snapshot.active else { return (nil, discardedStaging) }
        let durable = try await identityStore.load(label: active.label, identity: identity)
        guard durable.metadata.credentialID == active.credentialID,
              durable.metadata.identityKeyID == active.identityKeyID else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        return (.init(generation: active.generation, identity: durable), discardedStaging)
    }

    package func reset() async throws {
        let snapshot = try load()
        if let staged = snapshot.staged { try await identityStore.reset(label: staged.label) }
        if let active = snapshot.active { try await identityStore.reset(label: active.label) }
        for label in snapshot.retiredLabels { try await identityStore.reset(label: label) }
        try backend.delete(name: account)
    }

    private func cleanRetired() async throws {
        var snapshot = try load()
        guard !snapshot.retiredLabels.isEmpty else { return }
        var remaining: [String] = []
        for label in snapshot.retiredLabels {
            do { try await identityStore.reset(label: label) }
            catch { remaining.append(label) }
        }
        guard remaining.count != snapshot.retiredLabels.count || remaining.isEmpty else {
            throw ACPAppleSecurityError.keychainFailure
        }
        snapshot.retiredLabels = remaining
        try save(snapshot)
    }

    private func load() throws -> Snapshot {
        guard let data = try backend.read(name: account) else {
            var empty = Snapshot(); empty.checksum = checksum(empty); return empty
        }
        guard data.count <= 16_384,
              var snapshot = try? JSONDecoder().decode(Snapshot.self, from: data),
              snapshot.version == 1, valid(snapshot) else {
            throw ACPAppleSecurityError.keychainFailure
        }
        let stored = snapshot.checksum; snapshot.checksum = Data()
        guard stored == checksum(snapshot) else { throw ACPAppleSecurityError.keychainFailure }
        snapshot.checksum = stored
        return snapshot
    }

    private func save(_ value: Snapshot) throws {
        var snapshot = value; snapshot.checksum = Data(); snapshot.checksum = checksum(snapshot)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(snapshot)
        guard data.count <= 16_384 else { throw ACPAppleSecurityError.resourceLimit }
        try backend.write(name: account, data: data)
    }

    private func checksum(_ value: Snapshot) -> Data {
        var copy = value; copy.checksum = Data()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard let encoded = try? encoder.encode(copy) else { return Data() }
        return Data(SHA256.hash(
            data: Data("ACP Apple credential selector v1".utf8) + encoded))
    }

    private func label(_ generation: UInt64) throws -> String {
        let value = "\(labelPrefix).generation-\(generation)"
        guard value.utf8.count <= 128 else { throw ACPAppleSecurityError.resourceLimit }
        return value
    }

    private func valid(_ snapshot: Snapshot) -> Bool {
        func validSelection(_ selection: Selection) -> Bool {
            selection.generation > 0
                && (try? label(selection.generation)) == selection.label
                && ACPCredentialID(rawValue: selection.credentialID) != nil
                && ACPIdentityKeyID(rawValue: selection.identityKeyID) != nil
        }
        guard snapshot.active.map(validSelection) ?? true,
              snapshot.staged.map(validSelection) ?? true,
              snapshot.retiredLabels.count <= 2,
              Set(snapshot.retiredLabels).count == snapshot.retiredLabels.count,
              snapshot.retiredLabels.allSatisfy({
                  $0.hasPrefix("\(labelPrefix).generation-") && $0.utf8.count <= 128
              }),
              snapshot.active.map({ !snapshot.retiredLabels.contains($0.label) }) ?? true,
              snapshot.staged.map({ !snapshot.retiredLabels.contains($0.label) }) ?? true
        else { return false }
        if let active = snapshot.active, let staged = snapshot.staged {
            return staged.generation > active.generation && staged.label != active.label
        }
        return true
    }
}
