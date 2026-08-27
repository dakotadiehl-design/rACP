import AuroraACP
import CryptoKit
import Foundation
import SwiftASN1
import X509

package enum ACPAppleAuthorityBootstrapPhase: String, Codable, Sendable {
    case keyReserved = "key_reserved"
    case anchorGenerated = "anchor_generated"
    case metadataCommitted = "metadata_committed"
}

package struct ACPAppleAuthorityBootstrapRecord: Codable, Sendable, Equatable {
    package static let currentSchemaVersion = 1
    package let schemaVersion: Int
    package let phase: ACPAppleAuthorityBootstrapPhase
    package let trustDomainID: String
    package let authorityKeyID: String?
    package let anchorDER: Data?
    package let anchorCertificateID: String?
    package let custody: ACPAppleSigningKeyCustody?
    package let journalGeneration: UInt64
    package let revocationEpoch: UInt64

    package init(
        phase: ACPAppleAuthorityBootstrapPhase,
        trustDomainID: ACPTrustDomainID,
        authorityKeyID: ACPIdentityKeyID? = nil,
        anchorDER: Data? = nil,
        anchorCertificateID: ACPCredentialID? = nil,
        custody: ACPAppleSigningKeyCustody? = nil,
        journalGeneration: UInt64 = 0,
        revocationEpoch: UInt64 = 0
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.phase = phase
        self.trustDomainID = trustDomainID.rawValue
        self.authorityKeyID = authorityKeyID?.rawValue
        self.anchorDER = anchorDER
        self.anchorCertificateID = anchorCertificateID?.rawValue
        self.custody = custody
        self.journalGeneration = journalGeneration
        self.revocationEpoch = revocationEpoch
    }
}

package struct ACPAppleTrustDomainAuthority: @unchecked Sendable {
    package let identity: ACPTrustDomainAuthorityIdentity
    package let anchorDER: Data
    package let signingKey: ACPAppleProtectedSigningKey
    package let custody: ACPAppleSigningKeyCustody
}

/// Owns the recoverable pre-commit bootstrap and the committed authority
/// metadata. A committed or externally disclosed domain is never replaced by
/// this API; destructive new-domain creation belongs to an explicit reset API.
package actor ACPAppleTrustDomainAuthorityStore {
    private static let bootstrapLock = NSLock()
    private let keyStore: ACPAppleAuthorityKeyStore
    private let metadata: ACPKeychainCredentialBackend
    private let metadataAccount: String
    private let now: @Sendable () -> Date
    private let newDomainID: @Sendable () -> UUID

    package init(
        applicationTag: Data,
        metadataService: String = "com.aurora.acp.trust-domain-authority",
        metadataAccount: String = "authority-bootstrap-record",
        keyMetadataService: String = "com.aurora.acp.authority-key",
        accessGroup: String? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        newDomainID: @escaping @Sendable () -> UUID = { UUID() }
    ) throws {
        guard !metadataAccount.isEmpty, metadataAccount.utf8.count <= 128 else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        keyStore = try ACPAppleAuthorityKeyStore(
            applicationTag: applicationTag, metadataService: keyMetadataService,
            accessGroup: accessGroup)
        metadata = ACPKeychainCredentialBackend(service: metadataService, accessGroup: accessGroup)
        self.metadataAccount = metadataAccount
        self.now = now
        self.newDomainID = newDomainID
    }

    package func openOrCreate() throws -> ACPAppleTrustDomainAuthority {
        Self.bootstrapLock.lock(); defer { Self.bootstrapLock.unlock() }
        return try openOrCreateLocked()
    }

    private func openOrCreateLocked() throws -> ACPAppleTrustDomainAuthority {
        var record = try loadRecord()
        if record == nil {
            guard let domain = ACPTrustDomainID(
                rawValue: newDomainID().uuidString.lowercased()) else {
                throw ACPAppleSecureEnclaveOutcome.providerIntegrityFailure
            }
            let reserved = ACPAppleAuthorityBootstrapRecord(
                phase: .keyReserved, trustDomainID: domain)
            let encoded = try JSONEncoder().encode(reserved)
            if try metadata.createIfAbsent(name: metadataAccount, data: encoded) {
                record = reserved
            } else {
                // Another process won the reservation. Never overwrite its
                // domain; reopen and validate the winner instead.
                record = try loadRecord()
            }
        }
        guard var current = record,
              current.schemaVersion == ACPAppleAuthorityBootstrapRecord.currentSchemaVersion,
              let domain = ACPTrustDomainID(rawValue: current.trustDomainID)
        else { throw ACPAppleSecureEnclaveOutcome.corruptState }

        let key: ACPAppleProtectedSigningKey
        if current.phase == .keyReserved {
            key = try keyStore.openOrCreate(domainCorrelationID: domain.rawValue)
        } else {
            guard let expectedKeyIDRaw = current.authorityKeyID,
                  let expectedKeyID = ACPIdentityKeyID(rawValue: expectedKeyIDRaw),
                  let expectedCustody = current.custody else {
                throw ACPAppleSecureEnclaveOutcome.corruptState
            }
            key = try keyStore.openExisting(
                domainCorrelationID: domain.rawValue,
                expectedKeyID: expectedKeyID, expectedCustody: expectedCustody)
        }
        if current.phase == .keyReserved {
            let anchorDER = try makeAnchor(domain: domain, key: key)
            let anchorID = ACPCredentialIdentifiers.credentialID(for: anchorDER)
            current = ACPAppleAuthorityBootstrapRecord(
                phase: .anchorGenerated, trustDomainID: domain,
                authorityKeyID: key.keyID, anchorDER: anchorDER,
                anchorCertificateID: anchorID, custody: key.custody)
            try save(current)
        }

        guard let authorityKeyIDRaw = current.authorityKeyID,
              let authorityKeyID = ACPIdentityKeyID(rawValue: authorityKeyIDRaw),
              let anchorDER = current.anchorDER,
              let anchorIDRaw = current.anchorCertificateID,
              let anchorID = ACPCredentialID(rawValue: anchorIDRaw),
              let expectedCustody = current.custody,
              authorityKeyID == key.keyID,
              expectedCustody == key.custody,
              anchorID == ACPCredentialIdentifiers.credentialID(for: anchorDER)
        else { throw ACPAppleSecureEnclaveOutcome.identityMismatch }
        try validateAnchor(anchorDER, domain: domain, key: key)
        try key.proveOperational()

        if current.phase == .anchorGenerated {
            current = ACPAppleAuthorityBootstrapRecord(
                phase: .metadataCommitted, trustDomainID: domain,
                authorityKeyID: authorityKeyID, anchorDER: anchorDER,
                anchorCertificateID: anchorID, custody: expectedCustody,
                journalGeneration: current.journalGeneration,
                revocationEpoch: current.revocationEpoch)
            try save(current) // trust-domain commitment point
        }
        guard current.phase == .metadataCommitted else {
            throw ACPAppleSecureEnclaveOutcome.corruptState
        }
        return ACPAppleTrustDomainAuthority(
            identity: ACPTrustDomainAuthorityIdentity(
                trustDomainID: domain, authorityKeyID: authorityKeyID,
                trustAnchorCredentialID: anchorID),
            anchorDER: anchorDER, signingKey: key, custody: expectedCustody)
    }

    private func loadRecord() throws -> ACPAppleAuthorityBootstrapRecord? {
        guard let encoded = try metadata.read(name: metadataAccount) else { return nil }
        guard encoded.count <= 32_768 else {
            throw ACPAppleSecureEnclaveOutcome.corruptState
        }
        do { return try JSONDecoder().decode(ACPAppleAuthorityBootstrapRecord.self, from: encoded) }
        catch { throw ACPAppleSecureEnclaveOutcome.corruptState }
    }

    private func save(_ record: ACPAppleAuthorityBootstrapRecord) throws {
        try metadata.write(name: metadataAccount, data: try JSONEncoder().encode(record))
    }

    private func makeAnchor(
        domain: ACPTrustDomainID, key: ACPAppleProtectedSigningKey
    ) throws -> Data {
        let instant = now()
        let name = try DistinguishedName { OrganizationName("Aurora ACP Trust Domain Authority") }
        let ski = ArraySlice(SHA256.hash(
            data: Data(key.certificateKey.publicKey.subjectPublicKeyInfoBytes)).prefix(20))
        var serial = Data(count: 16)
        guard serial.withUnsafeMutableBytes({ SecRandomCopyBytes(
            kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else {
            throw ACPAppleSecureEnclaveOutcome.providerIntegrityFailure
        }
        serial[0] &= 0x7f
        if serial.allSatisfy({ $0 == 0 }) { serial[15] = 1 }
        for _ in 0..<16 {
            let certificate = try Certificate(
                version: .v3, serialNumber: .init(bytes: Array(serial)),
                publicKey: key.certificateKey.publicKey,
                notValidBefore: instant.addingTimeInterval(-120),
                notValidAfter: instant.addingTimeInterval(10 * 365 * 24 * 60 * 60),
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
                    Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                    SubjectKeyIdentifier(keyIdentifier: ski)
                }, issuerPrivateKey: key.certificateKey)
            if ACPAppleCredentialIssuer.isLowSP256(
                signatureDER: certificate.signature.rawRepresentation) {
                var serializer = DER.Serializer(); try serializer.serialize(certificate)
                return Data(serializer.serializedBytes)
            }
        }
        throw ACPAppleSecureEnclaveOutcome.providerIntegrityFailure
    }

    private func validateAnchor(
        _ anchorDER: Data, domain: ACPTrustDomainID,
        key: ACPAppleProtectedSigningKey
    ) throws {
        _ = domain // Domain correlation is persisted separately in v1.
        let anchor = try Certificate(derEncoded: Array(anchorDER))
        let evaluationTime = now()
        guard anchor.subject == anchor.issuer,
              anchor.publicKey.isValidSignature(anchor.signature, for: anchor),
              ACPAppleCredentialIssuer.isLowSP256(
                signatureDER: anchor.signature.rawRepresentation),
              let constraints = try anchor.extensions.basicConstraints,
              let usage = try anchor.extensions.keyUsage,
              anchor.notValidBefore <= evaluationTime,
              evaluationTime < anchor.notValidAfter,
              usage.keyCertSign, usage.cRLSign,
              !usage.digitalSignature, !usage.nonRepudiation,
              !usage.keyEncipherment, !usage.dataEncipherment,
              !usage.keyAgreement, !usage.encipherOnly, !usage.decipherOnly,
              try keyID(for: anchor.publicKey) == key.keyID,
              let ski = try anchor.extensions.subjectKeyIdentifier?.keyIdentifier,
              ski == ArraySlice(SHA256.hash(
                data: Data(anchor.publicKey.subjectPublicKeyInfoBytes)).prefix(20))
        else { throw ACPAppleSecurityError.invalidCertificate }
        guard case .isCertificateAuthority(let pathLength) = constraints,
              pathLength == 1 else { throw ACPAppleSecurityError.invalidCertificate }
    }

    private func keyID(for key: Certificate.PublicKey) throws -> ACPIdentityKeyID {
        var serializer = DER.Serializer(); try serializer.serialize(key)
        return ACPCredentialIdentifiers.identityKeyID(for: Data(serializer.serializedBytes))
    }
}
