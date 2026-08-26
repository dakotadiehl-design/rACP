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
              let certificate, let privateKey,
              SecCertificateCopyData(certificate) as Data == SecCertificateCopyData(chain[0]) as Data,
              let expected = ACPSecurityNodeID(rawValue: identity.nodeID) else {
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
        _ = try ACPAppleCertificatePolicy.validate(
            chain: chain, anchors: anchors, expectedDomain: trustDomainID,
            expectedNode: expected, revocation: revocation)
        // Persist the certificate and key references separately. A persistent
        // reference queried from a SecIdentity can resolve as its private key
        // on macOS; treating that object as SecIdentity causes a native crash.
        // SecIdentityCreate reconstructs only an opaque signing capability and
        // never exports private-key bytes.
        let locator = try ACPAppleIdentityLocator(
            certificate: persistentReference(to: certificate),
            privateKey: persistentReference(to: privateKey))
        let locatorData = try JSONEncoder().encode(locator)
        do {
            try references.write(name: label, data: locatorData)
            return try load(label: label, identity: identity)
        }
        catch {
            try? deletePersistent(locator.certificate)
            try? deletePersistent(locator.privateKey)
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
        guard let locatorData = try references.read(name: label) else {
            throw ACPAppleSecurityError.identityMissing
        }
        guard let locator = try? JSONDecoder().decode(ACPAppleIdentityLocator.self, from: locatorData),
              let certificate = try resolve(locator.certificate, typeID: SecCertificateGetTypeID()),
              let privateKey = try resolve(locator.privateKey, typeID: SecKeyGetTypeID()) else {
            throw ACPAppleSecurityError.identityMissing
        }
        let certificateRef = unsafeBitCast(certificate, to: SecCertificate.self)
        let keyRef = unsafeBitCast(privateKey, to: SecKey.self)
        guard let secIdentity = makeIdentity(certificate: certificateRef, privateKey: keyRef) else {
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
        let chain = [certificateRef] + anchors
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
        guard let locatorData = try references.read(name: label) else { return }
        guard let locator = try? JSONDecoder().decode(ACPAppleIdentityLocator.self, from: locatorData) else {
            throw ACPAppleSecurityError.keychainFailure
        }
        try deletePersistent(locator.certificate)
        try deletePersistent(locator.privateKey)
        try references.delete(name: label)
    }

    private func persistentReference(to value: CFTypeRef) throws -> Data {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecValueRef as String: value,
            kSecReturnPersistentRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw ACPAppleSecurityError.keychainFailure
        }
        return data
    }

    private func resolve(_ persistent: Data, typeID: CFTypeID) throws -> CFTypeRef? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecValuePersistentRef as String: persistent,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let result, CFGetTypeID(result) == typeID else {
            throw ACPAppleSecurityError.keychainFailure
        }
        return result
    }

    private func deletePersistent(_ persistent: Data) throws {
        let status = SecItemDelete([kSecValuePersistentRef as String: persistent] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ACPAppleSecurityError.keychainFailure
        }
    }

    private func makeIdentity(certificate: SecCertificate, privateKey: SecKey) -> SecIdentity? {
#if os(macOS)
        var identity: SecIdentity?
        guard SecIdentityCreateWithCertificate(nil, certificate, &identity) == errSecSuccess else {
            return nil
        }
        return identity
#else
        return SecIdentityCreate(nil, certificate, privateKey)
#endif
    }
}

private struct ACPAppleIdentityLocator: Codable {
    let certificate: Data
    let privateKey: Data
}
