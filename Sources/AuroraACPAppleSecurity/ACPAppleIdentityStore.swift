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
    private let references: ACPKeychainCredentialBackend

    public init(anchors: [SecCertificate], trustDomainID: ACPTrustDomainID,
                revocation: (any ACPAppleRevocationChecking)? = nil,
                referenceService: String = "com.aurora.acp.identity-reference") {
        self.anchors = anchors; self.trustDomainID = trustDomainID; self.revocation = revocation
        references = ACPKeychainCredentialBackend(service: referenceService)
    }

    /// Transactionally consumes an ACP-issued PKCS#12 package. This entry point
    /// is package-only: product code cannot install arbitrary credentials or
    /// receive the contained private key. Enrollment and qualification code in
    /// this package must verify the resulting durable identity with `load`.
    package func installIssuedPKCS12(_ packageData: Data, password: String,
                                     label: String, identity: ACPIdentity) throws
        -> ACPAppleLocalIdentity {
        guard !packageData.isEmpty, packageData.count <= 65_536,
              (1...128).contains(label.utf8.count) else {
            throw ACPAppleSecurityError.malformedIdentity
        }
        guard try references.read(name: label) == nil else {
            throw ACPAppleSecurityError.duplicateIdentity
        }
        var imported: CFArray?
        let status = SecPKCS12Import(
            packageData as CFData,
            [kSecImportExportPassphrase as String: password] as CFDictionary,
            &imported)
        guard status == errSecSuccess, let items = imported as? [[String: Any]],
              items.count == 1,
              let secIdentity = items[0][kSecImportItemIdentity as String] as! SecIdentity?,
              let chain = items[0][kSecImportItemCertChain as String] as? [SecCertificate],
              !chain.isEmpty else { throw ACPAppleSecurityError.malformedIdentity }
        var certificate: SecCertificate?
        var privateKey: SecKey?
        guard SecIdentityCopyCertificate(secIdentity, &certificate) == errSecSuccess,
              SecIdentityCopyPrivateKey(secIdentity, &privateKey) == errSecSuccess,
              let certificate, privateKey != nil,
              SecCertificateCopyData(certificate) as Data == SecCertificateCopyData(chain[0]) as Data,
              let expected = ACPSecurityNodeID(rawValue: identity.nodeID) else {
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
        _ = try ACPAppleCertificatePolicy.validate(
            chain: chain, anchors: anchors, expectedDomain: trustDomainID,
            expectedNode: expected, revocation: revocation)
        var persistent: CFTypeRef?
        let persistentStatus = SecItemCopyMatching([
            kSecValueRef as String: secIdentity, kSecReturnPersistentRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne] as CFDictionary, &persistent)
        guard persistentStatus == errSecSuccess, let persistentData = persistent as? Data else {
            throw ACPAppleSecurityError.keychainFailure
        }
        do {
            try references.write(name: label, data: persistentData)
            return try load(label: label, identity: identity)
        }
        catch {
            _ = SecItemDelete([kSecValuePersistentRef as String: persistentData] as CFDictionary)
            try? references.delete(name: label)
            throw error
        }
    }

    /// Loads a certificate/private-key pair by its Keychain label and verifies
    /// the complete ACP local certificate policy before returning a capability.
    public func load(label: String, identity: ACPIdentity) throws -> ACPAppleLocalIdentity {
        guard (1...128).contains(label.utf8.count),
              let expected = ACPSecurityNodeID(rawValue: identity.nodeID) else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        guard let persistent = try references.read(name: label) else {
            throw ACPAppleSecurityError.identityMissing
        }
        let query: [String: Any] = [
            kSecValuePersistentRef as String: persistent,
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
        guard let persistent = try references.read(name: label) else { return }
        let status = SecItemDelete([kSecValuePersistentRef as String: persistent] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ACPAppleSecurityError.keychainFailure
        }
        try references.delete(name: label)
    }
}
