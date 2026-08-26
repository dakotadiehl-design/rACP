import AuroraACP
import Foundation
import Security

public struct ACPAppleLocalIdentityMetadata: Sendable, Equatable {
    public let nodeID: String
    public let trustDomainID: String
    public let credentialID: String
    public let identityKeyID: String
}

/// Opaque Keychain identity capability. It exposes display metadata only;
/// private-key and `SecIdentity` references remain inside the Apple adapter.
public final class ACPAppleLocalIdentity: @unchecked Sendable {
    public let metadata: ACPAppleLocalIdentityMetadata
    package let networkIdentity: sec_identity_t
    package let certificateChain: [SecCertificate]
    package let acpIdentity: ACPIdentity

    package init(networkIdentity: sec_identity_t, certificateChain: [SecCertificate],
                 acpIdentity: ACPIdentity, verified: ACPAppleVerifiedCertificate) {
        self.networkIdentity = networkIdentity; self.certificateChain = certificateChain
        self.acpIdentity = acpIdentity
        metadata = .init(nodeID: verified.nodeID.rawValue,
                         trustDomainID: verified.trustDomainID.rawValue,
                         credentialID: verified.credentialID.rawValue,
                         identityKeyID: verified.identityKeyID.rawValue)
    }
}

public actor ACPAppleIdentityStore {
    private let anchors: [SecCertificate]
    private let trustDomainID: ACPTrustDomainID
    private let revocation: (any ACPAppleRevocationChecking)?

    public init(anchors: [SecCertificate], trustDomainID: ACPTrustDomainID,
                revocation: (any ACPAppleRevocationChecking)? = nil) {
        self.anchors = anchors; self.trustDomainID = trustDomainID; self.revocation = revocation
    }

    /// Loads a certificate/private-key pair by its Keychain label and verifies
    /// the complete ACP local certificate policy before returning a capability.
    public func load(label: String, identity: ACPIdentity) throws -> ACPAppleLocalIdentity {
        guard (1...128).contains(label.utf8.count),
              let expected = ACPSecurityNodeID(rawValue: identity.nodeID) else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw ACPAppleSecurityError.identityMissing }
        guard status == errSecSuccess, let secIdentity = result as! SecIdentity? else {
            throw ACPAppleSecurityError.keychainFailure
        }
        var certificate: SecCertificate?
        var privateKey: SecKey?
        guard SecIdentityCopyCertificate(secIdentity, &certificate) == errSecSuccess,
              SecIdentityCopyPrivateKey(secIdentity, &privateKey) == errSecSuccess,
              let certificate, privateKey != nil else { throw ACPAppleSecurityError.privateKeyUnavailable }
        let chain = [certificate] + anchors
        let verified = try ACPAppleCertificatePolicy.validate(
            chain: chain, anchors: anchors, expectedDomain: trustDomainID,
            expectedNode: expected, revocation: revocation
        )
        guard let network = sec_identity_create_with_certificates(secIdentity, chain as CFArray) else {
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
        return ACPAppleLocalIdentity(networkIdentity: network, certificateChain: chain,
                                     acpIdentity: identity, verified: verified)
    }

    /// Deletes only the selected ACP Keychain identity. Missing is idempotent.
    public func reset(label: String) throws {
        guard (1...128).contains(label.utf8.count) else { throw ACPAppleSecurityError.keychainFailure }
        let status = SecItemDelete([kSecClass as String: kSecClassIdentity,
                                    kSecAttrLabel as String: label] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ACPAppleSecurityError.keychainFailure
        }
    }
}
