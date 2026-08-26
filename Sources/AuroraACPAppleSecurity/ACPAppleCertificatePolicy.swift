import AuroraACP
import CryptoKit
import Foundation
import Security

public struct ACPAppleVerifiedCertificate: Sendable, Equatable {
    public let trustDomainID: ACPTrustDomainID
    public let nodeID: ACPSecurityNodeID
    public let credentialID: ACPCredentialID
    public let identityKeyID: ACPIdentityKeyID
    public let leafDER: Data
}

public enum ACPAppleSecurityError: String, Error, Sendable {
    case invalidCertificate = "security.credential_invalid"
    case trustFailure = "security.authentication_failed"
    case revoked = "security.credential_revoked"
    case exporterFailure = "security.authentication_failed.exporter"
    case earlyData = "security.downgrade_forbidden"
    case providerUnavailable = "security.provider_unavailable"
}

public protocol ACPAppleRevocationChecking: Sendable {
    func isRevoked(_ credentialID: ACPCredentialID) -> Bool
}

public enum ACPAppleCertificatePolicy {
    public static func validate(
        chain: [SecCertificate],
        anchors: [SecCertificate],
        expectedDomain: ACPTrustDomainID,
        expectedNode: ACPSecurityNodeID? = nil,
        evaluationDate: Date = Date(),
        revocation: (any ACPAppleRevocationChecking)? = nil
    ) throws -> ACPAppleVerifiedCertificate {
        guard chain.count >= 2, !anchors.isEmpty,
              !anchors.contains(where: { SecCertificateCopyData($0) as Data == SecCertificateCopyData(chain[0]) as Data })
        else { throw ACPAppleSecurityError.invalidCertificate }
        try evaluate(chain: chain, anchors: anchors, date: evaluationDate, server: true)
        try evaluate(chain: chain, anchors: anchors, date: evaluationDate, server: false)

        let leaf = chain[0]
        let der = SecCertificateCopyData(leaf) as Data
        let values = try certificateValues(leaf)
        let expectedPrefix = "urn:aurora:acp:node:\(expectedDomain.rawValue):"
        let sanValues = flattenedStrings(values).filter { $0.hasPrefix("urn:aurora:acp:node:") }
        guard sanValues.count == 1, sanValues[0].hasPrefix(expectedPrefix),
              let node = ACPSecurityNodeID(rawValue: String(sanValues[0].dropFirst(expectedPrefix.count))),
              expectedNode.map({ $0 == node }) ?? true,
              hasExtension(values, oid: kSecOIDBasicConstraints as String),
              hasExtension(values, oid: kSecOIDSubjectKeyIdentifier as String),
              hasExtension(values, oid: kSecOIDAuthorityKeyIdentifier as String),
              hasExtension(values, oid: kSecOIDKeyUsage as String),
              hasExtension(values, oid: kSecOIDExtendedKeyUsage as String),
              let publicKey = SecCertificateCopyKey(leaf),
              let external = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let spki = p256SPKI(external),
              let credentialID = ACPCredentialID(rawValue: digestID(der)),
              let identityKeyID = ACPIdentityKeyID(rawValue: digestID(spki))
        else { throw ACPAppleSecurityError.invalidCertificate }
        if revocation?.isRevoked(credentialID) == true { throw ACPAppleSecurityError.revoked }
        return .init(
            trustDomainID: expectedDomain, nodeID: node, credentialID: credentialID,
            identityKeyID: identityKeyID, leafDER: der
        )
    }

    private static func evaluate(
        chain: [SecCertificate], anchors: [SecCertificate], date: Date, server: Bool
    ) throws {
        let policy = SecPolicyCreateSSL(server, nil)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil)
        else { throw ACPAppleSecurityError.trustFailure }
    }

    private static func certificateValues(_ certificate: SecCertificate) throws -> [String: Any] {
        let keys = [kSecOIDSubjectAltName, kSecOIDBasicConstraints, kSecOIDKeyUsage, kSecOIDExtendedKeyUsage,
                    kSecOIDSubjectKeyIdentifier, kSecOIDAuthorityKeyIdentifier] as CFArray
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(certificate, keys, &error) as? [String: Any]
        else {
            _ = error?.takeRetainedValue()
            throw ACPAppleSecurityError.invalidCertificate
        }
        return values
    }

    private static func flattenedStrings(_ value: Any) -> [String] {
        if let string = value as? String { return [string] }
        if let url = value as? URL { return [url.absoluteString] }
        if let array = value as? [Any] { return array.flatMap(flattenedStrings) }
        if let dictionary = value as? [String: Any] { return dictionary.values.flatMap(flattenedStrings) }
        if let array = value as? NSArray { return array.flatMap(flattenedStrings) }
        if let dictionary = value as? NSDictionary { return dictionary.allValues.flatMap(flattenedStrings) }
        return []
    }

    private static func hasExtension(_ values: [String: Any], oid: String) -> Bool {
        values[oid] != nil
    }

    private static func digestID(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func p256SPKI(_ x963: Data) -> Data? {
        // RFC 5480 id-ecPublicKey + prime256v1 SubjectPublicKeyInfo prefix.
        guard x963.count == 65, x963.first == 0x04 else { return nil }
        return Data([
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]) + x963
    }
}
