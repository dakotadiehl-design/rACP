import AuroraACP
import CryptoKit
import Foundation
import Security

/// Sealed commissioner-side proof that the frozen install-result checks were
/// completed for one live attempt. No application-facing initializer exists.
package final class ACPAppleVerifiedInstallReceipt: @unchecked Sendable {
    package let authorizationID: UUID
    package let package: ACPIssuedCredentialPackage
    package let certificate: ACPAppleVerifiedCertificate

    fileprivate init(authorizationID: UUID, package: ACPIssuedCredentialPackage,
                     certificate: ACPAppleVerifiedCertificate) {
        self.authorizationID = authorizationID; self.package = package; self.certificate = certificate
    }
}

/// Narrow orchestration boundary. It carries issuer and installation
/// capabilities but has no signing key, SecKey, serial, SAN, validity, or EKU
/// input surface.
package actor ACPAppleEnrollmentCoordinator {
    private let issuer: any ACPCredentialIssuing
    private let journal: ACPIssuanceJournal
    private let trustStore: ACPAppleTrustedPeerStore
    private let anchors: [SecCertificate]
    private let domain: ACPTrustDomainID

    package init(issuer: any ACPCredentialIssuing, journal: ACPIssuanceJournal,
                 trustStore: ACPAppleTrustedPeerStore, anchors: [SecCertificate],
                 domain: ACPTrustDomainID) throws {
        guard anchors.count == 1 else { throw ACPSecurityErrorCode.credentialInvalid }
        self.issuer = issuer; self.journal = journal; self.trustStore = trustStore
        self.anchors = anchors; self.domain = domain
    }

    package func issue(
        authorization: ACPIssuanceAuthorization
    ) async throws -> ACPIssuedCredentialPackage {
        let package = try await issuer.issueCredential(authorization: authorization)
        guard package.trustDomainID == domain,
              SecCertificateCopyData(anchors[0]) as Data == package.trustAnchorDER
        else { throw ACPSecurityErrorCode.trustDomainMismatch }
        return package
    }

    /// Called only after the existing PAKE-confirmed approval envelope has
    /// accepted the exact package for transmission. Issuance alone is not
    /// recorded as delivery.
    package func markDelivered(package: ACPIssuedCredentialPackage) async throws {
        try await journal.markDelivered(package.authorizationID)
    }

    package func verifyInstallReceipt(
        package: ACPIssuedCredentialPackage,
        confirmation: ACPVerifiedEnrollmentInstallResult
    ) throws -> ACPAppleVerifiedInstallReceipt {
        guard confirmation.attemptID == package.attemptID,
              confirmation.credentialID == package.credentialID,
              confirmation.identityKeyID == package.identityKeyID,
              confirmation.trustDomainID == package.trustDomainID,
              package.trustDomainID == domain,
              SecCertificateCopyData(anchors[0]) as Data == package.trustAnchorDER,
              let leaf = SecCertificateCreateWithData(nil, package.leafDER as CFData),
              let publicKey = SecCertificateCopyKey(leaf),
              verifyInstallProof(confirmation.proofOfPossession, key: publicKey,
                                 transcriptHash: package.transcriptHash,
                                 credentialID: package.credentialID)
        else { throw ACPSecurityErrorCode.authenticationFailed }
        let certificate = try ACPAppleCertificatePolicy.validate(
            chain: [leaf, anchors[0]], anchors: anchors, expectedDomain: domain,
            expectedNode: package.nodeID, revocation: trustStore)
        return .init(authorizationID: package.authorizationID,
                     package: package, certificate: certificate)
    }

    package func commitTrust(_ receipt: ACPAppleVerifiedInstallReceipt,
                             displayName: String?) async throws {
        try trustStore.recordAuthenticated(receipt.certificate, displayName: displayName)
        try await journal.markInstallReceiptVerified(receipt.authorizationID)
    }

    private func verifyInstallProof(_ signature: Data, key: SecKey, transcriptHash: Data,
                                    credentialID: ACPCredentialID) -> Bool {
        let digest = Data(SHA256.hash(data: Data("ACP enrollment install proof v1".utf8)
            + transcriptHash + Data(credentialID.rawValue.utf8)))
        return ACPAppleCredentialIssuer.isLowSP256(signatureDER: Array(signature))
            && SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256,
                                     digest as CFData, signature as CFData, nil)
    }
}
