import AuroraACP
import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

package struct ACPAppleSystemRandom: ACPSecureRandomProvider {
    package init() {}
    package func bytes(count: Int) throws -> ACPSecretBytes {
        guard (1...4096).contains(count) else { throw ACPSecurityErrorCode.resourceLimit }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess, let secret = ACPSecretBytes(data, label: "system random") else {
            throw ACPSecurityErrorCode.storageFailed
        }
        return secret
    }
}

package final class ACPAppleIssuanceJournalBackend: ACPIssuanceJournalBackend, @unchecked Sendable {
    private let backend: ACPKeychainCredentialBackend
    private let account: String
    package init(service: String = "com.aurora.acp.authority-journal", account: String,
                 accessGroup: String? = nil) {
        backend = ACPKeychainCredentialBackend(service: service, accessGroup: accessGroup)
        self.account = account
    }
    package func load() throws -> Data? { try backend.read(name: account) }
    package func replace(with data: Data) throws { try backend.write(name: account, data: data) }
}

package enum ACPAppleSigningKeyCustody: String, Codable, Sendable, Equatable {
    case secureEnclave = "secure_enclave_non_exportable"
    case keychain = "keychain_non_exportable"
}

/// Authority-service-only wrapper around a persistent, non-exportable P-256
/// SecKey. Exportable, ephemeral, file-backed, and unidentified keys are
/// rejected at construction.
package final class ACPAppleProtectedSigningKey: ACPSigningKeyHandle, @unchecked Sendable {
    package let keyID: ACPIdentityKeyID
    package let certificateKey: Certificate.PrivateKey
    package let custody: ACPAppleSigningKeyCustody
    private let key: SecKey

    package init(secKey: SecKey, expectedKeyID: ACPIdentityKeyID) throws {
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any],
              (attributes[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue == 256,
              (attributes[kSecAttrIsPermanent as String] as? NSNumber)?.boolValue == true,
              SecKeyCopyExternalRepresentation(secKey, nil) == nil,
              SecKeyIsAlgorithmSupported(secKey, .sign, .ecdsaSignatureMessageX962SHA256),
              let publicKey = SecKeyCopyPublicKey(secKey),
              let x963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let spki = ACPAppleCredentialIssuer.canonicalSPKI(x963: x963),
              ACPCredentialIdentifiers.identityKeyID(for: spki) == expectedKeyID
        else { throw ACPAppleSecurityError.privateKeyUnavailable }
        let token = attributes[kSecAttrTokenID as String] as? String
        custody = token == kSecAttrTokenIDSecureEnclave as String ? .secureEnclave : .keychain
        self.key = secKey; keyID = expectedKeyID
        certificateKey = try Certificate.PrivateKey(secKey)
    }

    package func proveOperational() throws {
        let message = Data("ACP authority operational proof v1".utf8)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
        ) as Data?, let publicKey = SecKeyCopyPublicKey(key),
              SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                                    message as CFData, signature as CFData, nil)
        else {
            _ = error?.takeRetainedValue()
            throw ACPAppleSecurityError.privateKeyUnavailable
        }
    }

    package func sign(digest: Data) throws -> Data {
        guard digest.count == 32 else { throw ACPSecurityErrorCode.credentialInvalid }
        for _ in 0..<16 {
            var error: Unmanaged<CFError>?
            if let signature = SecKeyCreateSignature(
                key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error
            ) as Data?, ACPAppleCredentialIssuer.isLowSP256(signatureDER: Array(signature)) {
                return signature
            }
            _ = error?.takeRetainedValue()
        }
        throw ACPAppleSecurityError.privateKeyUnavailable
    }
}

package actor ACPAppleCredentialIssuer: ACPCredentialIssuing {
    private let domain: ACPTrustDomainID
    private let authorityKeyID: ACPIdentityKeyID
    private let anchor: Certificate
    private let anchorDER: Data
    private let anchorSKI: ArraySlice<UInt8>
    private let signingKey: ACPAppleProtectedSigningKey
    private let journal: ACPIssuanceJournal
    private let random: any ACPSecureRandomProvider
    private let now: @Sendable () -> Date

    package init(
        domain: ACPTrustDomainID, authorityKeyID: ACPIdentityKeyID,
        anchorDER: Data, signingKey: ACPAppleProtectedSigningKey,
        journal: ACPIssuanceJournal, random: any ACPSecureRandomProvider = ACPAppleSystemRandom(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        let anchor = try Certificate(derEncoded: Array(anchorDER))
        guard anchor.subject == anchor.issuer,
              let ski = try anchor.extensions.subjectKeyIdentifier?.keyIdentifier, ski.count == 20,
              let constraints = try anchor.extensions.basicConstraints,
              anchor.publicKey.isValidSignature(anchor.signature, for: anchor),
              try Self.keyID(for: anchor.publicKey) == authorityKeyID,
              signingKey.keyID == authorityKeyID
        else { throw ACPAppleSecurityError.invalidCertificate }
        guard case .isCertificateAuthority(let maximumPathLength) = constraints,
              maximumPathLength.map({ $0 <= 1 }) ?? true else {
            throw ACPAppleSecurityError.invalidCertificate
        }
        self.domain = domain; self.authorityKeyID = authorityKeyID; self.anchor = anchor
        self.anchorDER = anchorDER; self.anchorSKI = ski; self.signingKey = signingKey
        self.journal = journal; self.random = random; self.now = now
    }

    package func issueCredential(
        authorization: ACPIssuanceAuthorization
    ) async throws -> ACPIssuedCredentialPackage {
        let issuanceTime = now()
        let consumed = try await journal.consumeAndReserve(
            authorization: authorization, now: issuanceTime,
            expectedDomain: domain, expectedAuthorityKeyID: authorityKeyID, random: random)
        let facts = consumed.facts
        guard facts.identityKeyID == ACPCredentialIdentifiers.identityKeyID(for: facts.candidatePublicKeySPKI),
              anchor.notValidBefore <= issuanceTime, issuanceTime < anchor.notValidAfter
        else { throw ACPSecurityErrorCode.trustDomainMismatch }
        let reservation = consumed.reservation
        if let existing = reservation.existingPackage { return existing }
        try signingKey.proveOperational()

        let publicKey = try Certificate.PublicKey(derEncoded: Array(facts.candidatePublicKeySPKI))
        guard try Self.keyID(for: publicKey) == facts.identityKeyID else {
            throw ACPSecurityErrorCode.identityMismatch
        }
        let notBefore = max(issuanceTime.addingTimeInterval(-120), anchor.notValidBefore)
        let policyExpiry = issuanceTime.addingTimeInterval(90 * 24 * 60 * 60)
        let expiresAt = min(policyExpiry, anchor.notValidAfter)
        guard expiresAt > issuanceTime else { throw ACPSecurityErrorCode.credentialExpired }
        let rotationDeadline = max(notBefore, expiresAt.addingTimeInterval(-14 * 24 * 60 * 60))
        let subject = try DistinguishedName { OrganizationName("Aurora ACP Node") }
        let san = "urn:aurora:acp:node:\(domain.rawValue):\(facts.candidateNodeID.rawValue)"
        let subjectSKI = ArraySlice(SHA256.hash(data: Data(publicKey.subjectPublicKeyInfoBytes)).prefix(20))
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.clientAuth, .serverAuth])
            SubjectAlternativeNames([.uniformResourceIdentifier(san)])
            SubjectKeyIdentifier(keyIdentifier: subjectSKI)
            AuthorityKeyIdentifier(keyIdentifier: anchorSKI)
        }
        var certificate: Certificate?
        for _ in 0..<16 {
            let candidate = try Certificate(
                version: .v3, serialNumber: .init(bytes: Array(reservation.serial)),
                publicKey: publicKey, notValidBefore: notBefore, notValidAfter: expiresAt,
                issuer: anchor.subject, subject: subject, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: extensions, issuerPrivateKey: signingKey.certificateKey)
            if Self.isLowSP256(signatureDER: candidate.signature.rawRepresentation) {
                certificate = candidate; break
            }
        }
        guard let certificate, anchor.publicKey.isValidSignature(certificate.signature, for: certificate) else {
            throw ACPAppleSecurityError.invalidCertificate
        }
        var serializer = DER.Serializer(); try serializer.serialize(certificate)
        let leafDER = Data(serializer.serializedBytes)
        let credentialID = ACPCredentialIdentifiers.credentialID(for: leafDER)
        let package = try ACPIssuedCredentialPackage(
            authorizationID: facts.authorizationID, leafDER: leafDER,
            trustAnchorDER: anchorDER, credentialID: credentialID,
            identityKeyID: facts.identityKeyID, authorityKeyID: authorityKeyID,
            trustDomainID: domain, nodeID: facts.candidateNodeID,
            enrollmentID: facts.enrollmentID, attemptID: facts.attemptID,
            transcriptHash: facts.transcriptHash, serial: reservation.serial,
            notBefore: notBefore, expiresAt: expiresAt, rotationDeadline: rotationDeadline,
            replacesCredentialID: facts.replacesCredentialID)

        guard let leaf = SecCertificateCreateWithData(nil, leafDER as CFData),
              let root = SecCertificateCreateWithData(nil, anchorDER as CFData)
        else { throw ACPAppleSecurityError.invalidCertificate }
        _ = try ACPAppleCertificatePolicy.validate(
            chain: [leaf, root], anchors: [root], expectedDomain: domain,
            expectedNode: facts.candidateNodeID, evaluationDate: issuanceTime)
        try await journal.recordSigned(package, authorizationID: facts.authorizationID)
        return package
    }

    package static func canonicalSPKI(x963: Data) -> Data? {
        guard x963.count == 65, x963.first == 0x04 else { return nil }
        return Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                     0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
                     0x01, 0x07, 0x03, 0x42, 0x00]) + x963
    }

    private static func keyID(for key: Certificate.PublicKey) throws -> ACPIdentityKeyID {
        var serializer = DER.Serializer(); try serializer.serialize(key)
        return ACPCredentialIdentifiers.identityKeyID(for: Data(serializer.serializedBytes))
    }

    package static func isLowSP256(signatureDER: [UInt8]) -> Bool {
        guard signatureDER.count >= 8, signatureDER[0] == 0x30,
              let first = integerRange(in: signatureDER, offset: 2),
              let second = integerRange(in: signatureDER, offset: first.upperBound),
              second.upperBound == signatureDER.count else { return false }
        var s = Array(signatureDER[second])
        while s.first == 0 && s.count > 1 { s.removeFirst() }
        let halfOrder: [UInt8] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ]
        return s.count < halfOrder.count || (s.count == halfOrder.count && s.lexicographicallyPrecedes(halfOrder)) || s == halfOrder
    }

    private static func integerRange(in bytes: [UInt8], offset: Int) -> Range<Int>? {
        guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else { return nil }
        let count = Int(bytes[offset + 1]); guard count > 0, offset + 2 + count <= bytes.count else { return nil }
        return (offset + 2)..<(offset + 2 + count)
    }
}
