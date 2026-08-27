import AuroraACP
import CryptoKit
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

/// Opaque pending candidate-key capability. Product code receives only public
/// enrollment material; the SecKey reference stays package-owned.
package final class ACPApplePendingCandidateKey: @unchecked Sendable {
    package let attemptID: ACPEnrollmentAttemptID
    package let publicKeySPKI: Data
    package let identityKeyID: ACPIdentityKeyID
    package let storagePosture: ACPStoragePosture
    fileprivate let privateKey: SecKey

    fileprivate init(attemptID: ACPEnrollmentAttemptID, publicKeySPKI: Data,
                     identityKeyID: ACPIdentityKeyID, storagePosture: ACPStoragePosture,
                     privateKey: SecKey) {
        self.attemptID = attemptID; self.publicKeySPKI = publicKeySPKI
        self.identityKeyID = identityKeyID; self.storagePosture = storagePosture
        self.privateKey = privateKey
    }
}

package final class ACPAppleDurableInstallEvidence: @unchecked Sendable {
    package let localIdentity: ACPAppleLocalIdentity
    package let attemptID: ACPEnrollmentAttemptID
    package let credentialID: ACPCredentialID
    package let identityKeyID: ACPIdentityKeyID
    package let trustDomainID: ACPTrustDomainID
    package let storagePosture: ACPStoragePosture
    package let proofOfPossession: Data

    fileprivate init(localIdentity: ACPAppleLocalIdentity, package: ACPIssuedCredentialPackage,
                     storagePosture: ACPStoragePosture, proofOfPossession: Data) {
        self.localIdentity = localIdentity; attemptID = package.attemptID
        credentialID = package.credentialID; identityKeyID = package.identityKeyID
        trustDomainID = package.trustDomainID; self.storagePosture = storagePosture
        self.proofOfPossession = proofOfPossession
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

    package func prepareCandidateKey(
        attemptID: ACPEnrollmentAttemptID, preferSecureEnclave: Bool = true,
        allowNonHardwareFallback: Bool = false,
        applicationTagPrefix: String = "com.aurora.acp.pending"
    ) throws -> ACPApplePendingCandidateKey {
        let tag = Data("\(applicationTagPrefix).\(attemptID.rawValue)".utf8)
        guard tag.count <= 128 else { throw ACPAppleSecurityError.resourceLimit }
        var existing: CFTypeRef?
        let existingStatus = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &existing)
        if existingStatus == errSecSuccess, let existing,
           CFGetTypeID(existing) == SecKeyGetTypeID() {
            let key = unsafeBitCast(existing, to: SecKey.self)
            let capability = try pendingCapability(attemptID: attemptID, key: key)
            guard !preferSecureEnclave || capability.storagePosture.hardwareBacked
                    || allowNonHardwareFallback else {
                throw ACPAppleSecurityError.privateKeyUnavailable
            }
            return capability
        }
        guard existingStatus == errSecItemNotFound else { throw ACPAppleSecurityError.keychainFailure }
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil)
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsExtractable as String: false,
        ]
        if let access { privateAttributes[kSecAttrAccessControl as String] = access }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        if preferSecureEnclave { attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
        var error: Unmanaged<CFError>?
        var key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        var hardwareBacked = preferSecureEnclave && key != nil
        if key == nil && preferSecureEnclave && allowNonHardwareFallback {
            _ = error?.takeRetainedValue(); error = nil
            attributes.removeValue(forKey: kSecAttrTokenID as String)
            key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
            hardwareBacked = false
        }
        guard let key
        else {
            _ = error?.takeRetainedValue()
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
        return try pendingCapability(attemptID: attemptID, key: key,
                                     knownHardwareBacked: hardwareBacked)
    }

    package func discardCandidateKey(_ pendingKey: ACPApplePendingCandidateKey) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: pendingKey.privateKey,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ACPAppleSecurityError.keychainFailure
        }
    }

    package func installIssuedCertificate(
        _ package: ACPIssuedCredentialPackage, pendingKey: ACPApplePendingCandidateKey,
        label: String, identity: ACPIdentity
    ) throws -> ACPAppleDurableInstallEvidence {
        guard (1...128).contains(label.utf8.count), !reservedReferenceName(label) else {
            throw ACPAppleSecurityError.localIdentityMismatch
        }
        let markerName = installMarkerName(package.attemptID)
        try recoverInterruptedInstall(markerName: markerName)
        guard package.attemptID == pendingKey.attemptID,
              package.identityKeyID == pendingKey.identityKeyID,
              package.trustDomainID == trustDomainID,
              package.nodeID.rawValue == identity.nodeID,
              try references.read(name: label) == nil,
              let leaf = SecCertificateCreateWithData(nil, package.leafDER as CFData),
              let packageAnchor = SecCertificateCreateWithData(nil, package.trustAnchorDER as CFData),
              anchors.contains(where: {
                  SecCertificateCopyData($0) as Data == SecCertificateCopyData(packageAnchor) as Data
              })
        else { throw ACPAppleSecurityError.localIdentityMismatch }
        _ = try ACPAppleCertificatePolicy.validate(
            chain: [leaf, packageAnchor], anchors: anchors, expectedDomain: trustDomainID,
            expectedNode: package.nodeID, revocation: revocation)
        let marker = ACPAppleInstallMarker(
            state: .staging, label: label, leafDER: package.leafDER)
        try references.write(name: markerName, data: try JSONEncoder().encode(marker))
        do {
            let certPersistent = try addCertificate(leaf, label: label)
            let locator = try ACPAppleIdentityLocator(
                certificate: certPersistent,
                privateKey: persistentReference(to: pendingKey.privateKey))
            try references.write(name: label, data: try JSONEncoder().encode(locator))
            let loaded = try load(label: label, identity: identity)
            guard loaded.metadata.credentialID == package.credentialID.rawValue,
                  loaded.metadata.identityKeyID == pendingKey.identityKeyID.rawValue
            else { throw ACPAppleSecurityError.localIdentityMismatch }
            let proof = try possessionProof(
                key: pendingKey.privateKey, transcriptHash: package.transcriptHash,
                credentialID: package.credentialID)
            guard verifyPossessionProof(proof, certificate: leaf, transcriptHash: package.transcriptHash,
                                        credentialID: package.credentialID)
            else { throw ACPAppleSecurityError.privateKeyUnavailable }
            try references.write(
                name: markerName,
                data: try JSONEncoder().encode(ACPAppleInstallMarker(
                    state: .committed, label: label, leafDER: package.leafDER)))
            try? references.delete(name: markerName)
            return .init(localIdentity: loaded, package: package,
                         storagePosture: pendingKey.storagePosture, proofOfPossession: proof)
        } catch {
            try? recoverInterruptedInstall(markerName: markerName)
            throw error
        }
    }

    /// Transactionally consumes an ACP-issued PKCS#12 package. This entry point
    /// is package-only: product code cannot install arbitrary credentials or
    /// receive the contained private key. Enrollment and qualification code in
    /// this package must verify the resulting durable identity with `load`.
    package func installIssuedPKCS12(_ packageData: Data, password: String,
                                     label: String, identity: ACPIdentity) throws
        -> ACPAppleLocalIdentity {
        guard !packageData.isEmpty, packageData.count <= 65_536,
              (1...128).contains(label.utf8.count), !reservedReferenceName(label) else {
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
        guard (1...128).contains(label.utf8.count), !reservedReferenceName(label),
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
        guard (1...128).contains(label.utf8.count), !reservedReferenceName(label)
        else { throw ACPAppleSecurityError.keychainFailure }
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

    private func addCertificate(_ certificate: SecCertificate, label: String) throws -> Data {
        var result: CFTypeRef?
        let status = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label,
            kSecReturnPersistentRef as String: true,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let persistent = result as? Data else {
            throw status == errSecDuplicateItem ? ACPAppleSecurityError.duplicateIdentity
                                                : ACPAppleSecurityError.keychainFailure
        }
        return persistent
    }

    private func installMarkerName(_ attemptID: ACPEnrollmentAttemptID) -> String {
        "com.aurora.acp.internal.pending-install.\(attemptID.rawValue)"
    }

    private func reservedReferenceName(_ name: String) -> Bool {
        name.hasPrefix("com.aurora.acp.internal.")
    }

    private func recoverInterruptedInstall(markerName: String) throws {
        guard let data = try references.read(name: markerName) else { return }
        guard let marker = try? JSONDecoder().decode(ACPAppleInstallMarker.self, from: data)
        else { throw ACPAppleSecurityError.keychainFailure }
        if marker.state == .staging {
            if let locatorData = try references.read(name: marker.label),
               let locator = try? JSONDecoder().decode(ACPAppleIdentityLocator.self,
                                                       from: locatorData) {
                try deletePersistent(locator.certificate)
                try references.delete(name: marker.label)
            } else {
                let status = SecItemDelete([
                    kSecClass as String: kSecClassCertificate,
                    kSecAttrLabel as String: marker.label,
                    kSecValueData as String: marker.leafDER,
                ] as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else {
                    throw ACPAppleSecurityError.keychainFailure
                }
            }
        }
        try references.delete(name: markerName)
    }

    private func pendingCapability(attemptID: ACPEnrollmentAttemptID, key: SecKey,
                                   knownHardwareBacked: Bool? = nil) throws -> ACPApplePendingCandidateKey {
        guard SecKeyCopyExternalRepresentation(key, nil) == nil,
              let publicKey = SecKeyCopyPublicKey(key),
              let x963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let spki = ACPAppleCredentialIssuer.canonicalSPKI(x963: x963)
        else { throw ACPAppleSecurityError.privateKeyUnavailable }
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        let hardware = knownHardwareBacked
            ?? (attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String)
        return .init(
            attemptID: attemptID, publicKeySPKI: spki,
            identityKeyID: ACPCredentialIdentifiers.identityKeyID(for: spki),
            storagePosture: .init(storageClass: hardware ? .hardwareBacked : .osProtected,
                                  hardwareBacked: hardware, privateKeyExportable: false),
            privateKey: key)
    }

    private func possessionProof(key: SecKey, transcriptHash: Data,
                                 credentialID: ACPCredentialID) throws -> Data {
        let digest = Data(SHA256.hash(data: Data("ACP enrollment install proof v1".utf8)
            + transcriptHash + Data(credentialID.rawValue.utf8)))
        for _ in 0..<16 {
            if let signature = SecKeyCreateSignature(
                key, .ecdsaSignatureDigestX962SHA256, digest as CFData, nil
            ) as Data?, ACPAppleCredentialIssuer.isLowSP256(signatureDER: Array(signature)) {
                return signature
            }
        }
        throw ACPAppleSecurityError.privateKeyUnavailable
    }

    private func verifyPossessionProof(_ signature: Data, certificate: SecCertificate,
                                       transcriptHash: Data, credentialID: ACPCredentialID) -> Bool {
        let digest = Data(SHA256.hash(data: Data("ACP enrollment install proof v1".utf8)
            + transcriptHash + Data(credentialID.rawValue.utf8)))
        guard let publicKey = SecCertificateCopyKey(certificate) else { return false }
        return SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256,
                                     digest as CFData, signature as CFData, nil)
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

private struct ACPAppleInstallMarker: Codable {
    enum State: String, Codable { case staging, committed }
    let state: State
    let label: String
    let leafDER: Data
}
