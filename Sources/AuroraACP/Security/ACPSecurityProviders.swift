import Foundation

public protocol ACPSecureRandomProvider: Sendable { func bytes(count: Int) throws -> ACPSecretBytes }
public protocol ACPSigningKeyHandle: Sendable {
    var keyID: ACPIdentityKeyID { get }
    func sign(digest: Data) throws -> Data
}
public protocol ACPCryptoProvider: Sendable {
    func sha256(_ value: Data) -> Data
    func hmacSHA256(key: ACPSecretBytes, value: Data) throws -> Data
}

/// Opaque proof that a SPAKE2+ provider completed peer confirmation before
/// releasing key material. Product code can carry this value but cannot
/// construct it or extract its secret.
public final class ACPConfirmedSPAKE2PlusKey: @unchecked Sendable {
    private let secret: ACPSecretBytes

    package init(secret: ACPSecretBytes) { self.secret = secret }

    package func withUnsafeBytes<T>(
        _ operation: (UnsafeRawBufferPointer) throws -> T
    ) rethrows -> T {
        try secret.withUnsafeBytes(operation)
    }
}

public protocol ACPSPAKE2PlusOperation: Sendable {
    func receive(peerShare: Data) throws -> Data
    /// Verifies the peer confirmation and atomically consumes the provider's
    /// shared secret. Implementations must become terminal on every return.
    func verifyAndConsumeKey(confirmation: Data) throws -> ACPConfirmedSPAKE2PlusKey
}
public protocol ACPAEADProvider: Sendable {
    func seal(key: ACPSecretBytes, plaintext: ACPSecretBytes, nonce: Data, associatedData: Data) throws -> Data
    func open(key: ACPSecretBytes, ciphertext: Data, nonce: Data, associatedData: Data) throws -> ACPSecretBytes
}
public protocol ACPIdentityKeyProvider: Sendable { func generate() throws -> any ACPSigningKeyHandle }
public protocol ACPCredentialValidator: Sendable {
    func validate(_ credential: Data, domain: ACPTrustDomainID, node: ACPSecurityNodeID) throws -> ACPTransportEvidence
}
public protocol ACPSecurityClock: Sendable {
    var monotonicNanoseconds: UInt64 { get }
    var utcTimestamp: String? { get }
    var trustState: ACPClockTrustState { get }
}
public protocol ACPSecureTimeCheckpoint: Sendable {
    func load() throws -> (timestamp: String, monotonicNanoseconds: UInt64)?
    func store(timestamp: String, monotonicNanoseconds: UInt64) throws
}
public protocol ACPIdentityStore: Sendable {
    func stage(credentialID: ACPCredentialID, credential: Data, key: any ACPSigningKeyHandle) throws
    func commit(credentialID: ACPCredentialID) throws
    func rollback() throws
}
public protocol ACPTrustDomainAuthority: Sendable { func issue(request: Data) throws -> Data }
public protocol ACPEnrollmentPolicy: Sendable { func approve(request: Data) throws -> Bool }
public protocol ACPAuthorizationPolicy: Sendable { func permissions(for principal: ACPAuthenticatedPrincipal) -> Set<String> }
public protocol ACPAuditSink: Sendable { func record(event: String, publicFields: [String: String]) }
public protocol ACPRevocationStore: Sendable {
    var epoch: UInt64 { get }
    func contains(_ credentialID: ACPCredentialID) -> Bool
}
