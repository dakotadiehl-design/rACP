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
public protocol ACPSPAKE2PlusOperation: Sendable {
    func receive(peerShare: Data) throws -> Data
    func verify(confirmation: Data) throws -> Bool
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
