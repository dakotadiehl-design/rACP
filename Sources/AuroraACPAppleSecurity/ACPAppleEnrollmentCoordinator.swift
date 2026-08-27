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

    package init(authorizationID: UUID, package: ACPIssuedCredentialPackage,
                 certificate: ACPAppleVerifiedCertificate) {
        self.authorizationID = authorizationID; self.package = package; self.certificate = certificate
    }
}

/// Narrow orchestration boundary. It carries issuer and installation
/// capabilities but has no signing key, SecKey, serial, SAN, validity, or EKU
/// input surface.
package protocol ACPAppleEnrollmentCoordinating: Sendable {
    func issue(authorization: ACPIssuanceAuthorization) async throws
        -> ACPIssuedCredentialPackage
    func markDelivered(package: ACPIssuedCredentialPackage) async throws
    func verifyInstallReceipt(package: ACPIssuedCredentialPackage,
                              confirmation: ACPVerifiedEnrollmentInstallResult) async throws
        -> ACPAppleVerifiedInstallReceipt
    func commitTrust(_ receipt: ACPAppleVerifiedInstallReceipt,
                     displayName: String?) async throws
}

package actor ACPAppleEnrollmentCoordinator: ACPAppleEnrollmentCoordinating {
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
        try trustStore.recordPending(receipt.certificate, displayName: displayName)
        try await journal.markInstallReceiptVerified(receipt.authorizationID)
        try await journal.markTrusted(receipt.authorizationID)
        try trustStore.activatePending(receipt.package.credentialID)
    }

    /// Completes only journal-authorized pending trust after a process restart.
    /// It never reconstructs possession evidence or trusts a peer from portable
    /// package metadata alone.
    package func recoverCommittedTrust() async throws {
        for item in try await journal.trustRecoveryPackages() {
            guard trustStore.isPending(item.package.credentialID) else { continue }
            if !item.committed { try await journal.markTrusted(item.package.authorizationID) }
            try trustStore.activatePending(item.package.credentialID)
        }
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
