import AuroraACP
import CryptoKit
import Foundation
import Security
import SwiftASN1
import XCTest
import X509
@testable import AuroraACPAppleSecurity

final class ACPAppleCredentialIssuerTests: XCTestCase {
    func testProtectedKeyIssuerCreatesFrozenLeafAndIsIdempotent() async throws {
        let tag = Data("com.aurora.acp.tests.ca.\(UUID().uuidString)".utf8)
        let key: SecKey
        do { key = try makeNonExtractableKey(tag: tag) }
        catch let error as NSError where error.code == Int(errSecMissingEntitlement) {
            throw XCTSkip("Secure Enclave authority test requires a signed target with Keychain entitlements")
        }
        defer { SecItemDelete([kSecClass as String: kSecClassKey,
                               kSecAttrApplicationTag as String: tag] as CFDictionary) }
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let x963 = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
        let spki = try XCTUnwrap(ACPAppleCredentialIssuer.canonicalSPKI(x963: x963))
        let authorityID = ACPCredentialIdentifiers.identityKeyID(for: spki)
        let rootDER = try makeRoot(key: key)
        let protectedKey = try ACPAppleProtectedSigningKey(secKey: key, expectedKeyID: authorityID)
        XCTAssertEqual(protectedKey.custody, .secureEnclave)
        let backend = AppleMemoryJournalBackend()
        let journal = try ACPIssuanceJournal(backend: backend)
        let domain = ACPTrustDomainID(rawValue: "40516273-8495-4a6b-8a3b-4c5d6e7f8091")!
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let issuer = try ACPAppleCredentialIssuer(
            domain: domain, authorityKeyID: authorityID, anchorDER: rootDER,
            signingKey: protectedKey, journal: journal,
            random: AppleFixedRandom(Data((1...16).map(UInt8.init))), now: { now })
        let candidate = P256.Signing.PrivateKey()
        let candidateSPKI = candidate.publicKey.derRepresentation
        let facts = try ACPIssuanceCeremonyFacts(
            authorizationID: UUID(), enrollmentID: ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!,
            attemptID: ACPEnrollmentAttemptID(rawValue: UUID().uuidString.lowercased())!,
            transcriptHash: Data(repeating: 7, count: 32),
            candidateNodeID: ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!,
            candidateInstanceID: UUID(), commissionerNodeID: ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!,
            commissionerInstanceID: UUID(), trustDomainID: domain, authorityKeyID: authorityID,
            candidatePublicKeySPKI: candidateSPKI,
            identityKeyID: ACPCredentialIdentifiers.identityKeyID(for: candidateSPKI),
            requestedRole: "remote", permissionsDigest: "sha256:" + String(repeating: "1", count: 64),
            approvalID: UUID(), approvalTime: now.addingTimeInterval(-1),
            expiresAt: now.addingTimeInterval(60), cancellationGeneration: 0)
        let first = try await issuer.issueCredential(authorization: authorized(facts))
        let retry = try await issuer.issueCredential(authorization: authorized(facts))
        XCTAssertEqual(first, retry)
        XCTAssertEqual(first.serial, Data((1...16).map(UInt8.init)))
        let leaf = try XCTUnwrap(SecCertificateCreateWithData(nil, first.leafDER as CFData))
        let root = try XCTUnwrap(SecCertificateCreateWithData(nil, rootDER as CFData))
        let verified = try ACPAppleCertificatePolicy.validate(
            chain: [leaf, root], anchors: [root], expectedDomain: domain,
            expectedNode: facts.candidateNodeID, evaluationDate: now)
        XCTAssertEqual(verified.credentialID, first.credentialID)
        XCTAssertEqual(verified.identityKeyID, facts.identityKeyID)
    }

    private func authorized(_ facts: ACPIssuanceCeremonyFacts) throws -> ACPIssuanceAuthorization {
        try ACPIssuanceAuthorizationGate.authorize(
            facts: facts, cryptographyConfirmed: true, candidateIdentityBound: true,
            approvalMatchesCeremony: true, approvalUnexpired: true, approvalSingleUse: true,
            cancelled: false, replayed: false, publicKeyValid: true, trustDomainValid: true,
            stillValid: { true })
    }

    private func makeNonExtractableKey(tag: Data) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil)!
        let key = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ] as CFDictionary, &error)
        if let key { return key }
        throw error!.takeRetainedValue() as Error
    }

    private func makeRoot(key: SecKey) throws -> Data {
        let privateKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { OrganizationName("Aurora ACP Test Authority") }
        let ski = ArraySlice(SHA256.hash(data: Data(privateKey.publicKey.subjectPublicKeyInfoBytes)).prefix(20))
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(bytes: Array(repeating: 0x44, count: 16)),
            publicKey: privateKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notValidAfter: Date(timeIntervalSince1970: 2_000_000_000),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(keyIdentifier: ski)
            }, issuerPrivateKey: privateKey)
        var serializer = DER.Serializer(); try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }
}

private final class AppleMemoryJournalBackend: ACPIssuanceJournalBackend, @unchecked Sendable {
    private let lock = NSLock(); private var data: Data?
    func load() throws -> Data? { lock.lock(); defer { lock.unlock() }; return data }
    func replace(with data: Data) throws { lock.lock(); defer { lock.unlock() }; self.data = data }
}

private struct AppleFixedRandom: ACPSecureRandomProvider {
    let value: Data
    init(_ value: Data) { self.value = value }
    func bytes(count: Int) throws -> ACPSecretBytes {
        guard count == value.count else { throw ACPSecurityErrorCode.resourceLimit }
        return ACPSecretBytes(value)!
    }
}
