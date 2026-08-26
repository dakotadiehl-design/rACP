import AuroraACP
import Foundation

public enum ACPApplePeerTrustState: String, Sendable, Codable { case trusted, revoked }

public struct ACPAppleTrustedPeer: Sendable, Equatable, Codable {
    public let nodeID: String
    public let credentialID: String
    public let identityKeyID: String
    public let displayName: String?
    public let state: ACPApplePeerTrustState
    public let lastSeen: Date?
    public let revokedAt: Date?

    package init(nodeID: String, credentialID: String, identityKeyID: String,
                 displayName: String?, state: ACPApplePeerTrustState,
                 lastSeen: Date?, revokedAt: Date?) {
        self.nodeID = nodeID; self.credentialID = credentialID
        self.identityKeyID = identityKeyID; self.displayName = displayName
        self.state = state; self.lastSeen = lastSeen; self.revokedAt = revokedAt
    }
}

public enum ACPAppleRevocationResult: String, Sendable {
    case revoked, alreadyRevoked, unknownCredential
}

/// Persistent, bounded, ACP-owned trust display and revocation state.
/// The single Keychain value is replaced atomically before success is exposed.
public final class ACPAppleTrustedPeerStore: ACPAppleRevocationChecking, @unchecked Sendable {
    private struct Snapshot: Codable { var version = 1; var peers: [ACPAppleTrustedPeer] = [] }
    private let lock = NSLock()
    private let backend: ACPKeychainCredentialBackend
    private let account: String
    private let maximumPeers: Int
    private var snapshot: Snapshot
    private var revocationObservers: [String: [UUID: @Sendable () -> Void]] = [:]
    private var revocationObserverCount = 0

    public init(service: String = "com.aurora.acp.trust", account: String,
                accessGroup: String? = nil, maximumPeers: Int = 1024) throws {
        guard (1...128).contains(account.utf8.count), (1...4096).contains(maximumPeers) else {
            throw ACPAppleSecurityError.trustStoreFailure
        }
        self.backend = ACPKeychainCredentialBackend(service: service, accessGroup: accessGroup)
        self.account = account; self.maximumPeers = maximumPeers
        if let data = try backend.read(name: account) {
            guard let decoded = try? JSONDecoder().decode(Snapshot.self, from: data),
                  decoded.version == 1, decoded.peers.count <= maximumPeers,
                  Set(decoded.peers.map(\.credentialID)).count == decoded.peers.count
            else { throw ACPAppleSecurityError.trustStoreFailure }
            snapshot = decoded
        } else { snapshot = Snapshot() }
    }

    public func trustedPeers() -> [ACPAppleTrustedPeer] {
        lock.withLock { snapshot.peers.sorted { $0.nodeID < $1.nodeID } }
    }

    public func isRevoked(_ credentialID: ACPCredentialID) -> Bool {
        lock.withLock {
            snapshot.peers.first { $0.credentialID == credentialID.rawValue }?.state == .revoked
        }
    }

    public func revoke(_ credentialID: ACPCredentialID, at date: Date = Date()) throws
        -> ACPAppleRevocationResult {
        let (result, callbacks): (ACPAppleRevocationResult, [@Sendable () -> Void]) = try lock.withLock {
            guard let index = snapshot.peers.firstIndex(where: { $0.credentialID == credentialID.rawValue })
            else { return (.unknownCredential, []) }
            guard snapshot.peers[index].state != .revoked else { return (.alreadyRevoked, []) }
            let old = snapshot
            let peer = snapshot.peers[index]
            snapshot.peers[index] = .init(
                nodeID: peer.nodeID, credentialID: peer.credentialID,
                identityKeyID: peer.identityKeyID, displayName: peer.displayName,
                state: .revoked, lastSeen: peer.lastSeen, revokedAt: date)
            do { try persist() } catch { snapshot = old; throw error }
            let callbacks = Array(revocationObservers.removeValue(
                forKey: credentialID.rawValue)?.values ?? [:].values)
            revocationObserverCount -= callbacks.count
            return (.revoked, callbacks)
        }
        callbacks.forEach { $0() }
        return result
    }

    /// Removes ACP trust-display and revocation state without touching cached
    /// show assets or local device identities.
    public func reset() throws {
        let callbacks: [@Sendable () -> Void] = try lock.withLock {
            do { try backend.delete(name: account) }
            catch { throw ACPAppleSecurityError.trustStoreFailure }
            snapshot = Snapshot()
            let callbacks = revocationObservers.values.flatMap { $0.values }
            revocationObservers.removeAll(keepingCapacity: false)
            revocationObserverCount = 0
            return callbacks
        }
        callbacks.forEach { $0() }
    }

    package func recordAuthenticated(_ certificate: ACPAppleVerifiedCertificate,
                                     displayName: String?, at date: Date = Date()) throws {
        try lock.withLock {
            let old = snapshot
            if let index = snapshot.peers.firstIndex(where: {
                $0.credentialID == certificate.credentialID.rawValue
            }) {
                guard snapshot.peers[index].state != .revoked else { throw ACPAppleSecurityError.revoked }
                let peer = snapshot.peers[index]
                snapshot.peers[index] = .init(
                    nodeID: certificate.nodeID.rawValue, credentialID: peer.credentialID,
                    identityKeyID: certificate.identityKeyID.rawValue,
                    displayName: displayName ?? peer.displayName, state: .trusted,
                    lastSeen: date, revokedAt: nil)
            } else {
                guard snapshot.peers.count < maximumPeers else { throw ACPAppleSecurityError.resourceLimit }
                snapshot.peers.append(.init(
                    nodeID: certificate.nodeID.rawValue,
                    credentialID: certificate.credentialID.rawValue,
                    identityKeyID: certificate.identityKeyID.rawValue,
                    displayName: displayName, state: .trusted, lastSeen: date, revokedAt: nil))
            }
            do { try persist() } catch { snapshot = old; throw error }
        }
    }

    package func observeRevocation(_ credentialID: ACPCredentialID,
                                   callback: @escaping @Sendable () -> Void) throws -> UUID {
        try lock.withLock {
            guard snapshot.peers.first(where: { $0.credentialID == credentialID.rawValue })?.state != .revoked
            else { throw ACPAppleSecurityError.revoked }
            guard revocationObserverCount < maximumPeers * 4 else {
                throw ACPAppleSecurityError.resourceLimit
            }
            let id = UUID()
            revocationObservers[credentialID.rawValue, default: [:]][id] = callback
            revocationObserverCount += 1
            return id
        }
    }

    package func removeRevocationObserver(_ id: UUID, credentialID: ACPCredentialID) {
        lock.withLock {
            guard revocationObservers[credentialID.rawValue]?.removeValue(forKey: id) != nil else { return }
            revocationObserverCount -= 1
            if revocationObservers[credentialID.rawValue]?.isEmpty == true {
                revocationObservers.removeValue(forKey: credentialID.rawValue)
            }
        }
    }

    private func persist() throws {
        guard let data = try? JSONEncoder().encode(snapshot), data.count <= 1_048_576 else {
            throw ACPAppleSecurityError.trustStoreFailure
        }
        do { try backend.write(name: account, data: data) }
        catch { throw ACPAppleSecurityError.trustStoreFailure }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }; return try body()
    }
}
