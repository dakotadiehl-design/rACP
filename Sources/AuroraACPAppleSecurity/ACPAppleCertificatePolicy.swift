import AuroraACP
import CryptoKit
import Foundation
import Security

package struct ACPAppleVerifiedCertificate: Sendable, Equatable {
    package let trustDomainID: ACPTrustDomainID
    package let nodeID: ACPSecurityNodeID
    package let credentialID: ACPCredentialID
    package let identityKeyID: ACPIdentityKeyID
    package let leafDER: Data

    package init(trustDomainID: ACPTrustDomainID, nodeID: ACPSecurityNodeID,
                 credentialID: ACPCredentialID, identityKeyID: ACPIdentityKeyID,
                 leafDER: Data) {
        self.trustDomainID = trustDomainID; self.nodeID = nodeID
        self.credentialID = credentialID; self.identityKeyID = identityKeyID
        self.leafDER = leafDER
    }
}

public enum ACPAppleSecurityError: String, Error, Sendable {
    case invalidCertificate = "security.credential_invalid"
    case trustFailure = "security.authentication_failed"
    case revoked = "security.credential_revoked"
    case exporterFailure = "security.authentication_failed.exporter"
    case earlyData = "security.downgrade_forbidden"
    case providerUnavailable = "security.provider_unavailable"
    case localIdentityMismatch = "security.local_identity_mismatch"
    case invalidHello = "security.invalid_hello"
    case listenerState = "security.listener_state"
    case timeout = "security.timeout"
    case identityMissing = "security.identity_missing"
    case privateKeyUnavailable = "security.private_key_unavailable"
    case keychainFailure = "security.keychain_failure"
    case trustStoreFailure = "security.trust_store_failure"
    case resourceLimit = "security.resource_limit"
    case malformedIdentity = "security.identity_malformed"
    case duplicateIdentity = "security.identity_duplicate"
    case tlsHandshake = "security.tls_handshake"
    case helloReceive = "security.hello_receive"
}

package protocol ACPAppleRevocationChecking: Sendable {
    func isRevoked(_ credentialID: ACPCredentialID) -> Bool
}

package enum ACPAppleCertificatePolicy {
    package static func validate(
        chain: [SecCertificate],
        anchors: [SecCertificate],
        expectedDomain: ACPTrustDomainID,
        expectedNode: ACPSecurityNodeID? = nil,
        evaluationDate: Date = Date(),
        revocation: (any ACPAppleRevocationChecking)? = nil
    ) throws -> ACPAppleVerifiedCertificate {
#if os(macOS)
        // TLS peers commonly omit the self-signed root, while Network.framework
        // may report the leaf or root more than once. Accept only copies of the
        // peer leaf and configured root; never accept an intermediate/other root.
        let leafDER = chain.first.map { SecCertificateCopyData($0) as Data }
        let anchorDER = anchors.first.map { SecCertificateCopyData($0) as Data }
        guard (1 ... 3).contains(chain.count), anchors.count == 1,
              leafDER != anchorDER,
              chain.dropFirst().allSatisfy({
                  let der = SecCertificateCopyData($0) as Data
                  return der == leafDER || der == anchorDER
              }),
              !anchors.contains(where: { SecCertificateCopyData($0) as Data == SecCertificateCopyData(chain[0]) as Data })
        else { throw ACPAppleSecurityError.invalidCertificate }
        let canonicalChain = [chain[0], anchors[0]]
        try evaluate(chain: canonicalChain, anchors: anchors, date: evaluationDate, server: true)
        try evaluate(chain: canonicalChain, anchors: anchors, date: evaluationDate, server: false)

        let leaf = chain[0]
        let der = SecCertificateCopyData(leaf) as Data
        let values = try certificateValues(leaf)
        let expectedPrefix = "urn:aurora:acp:node:\(expectedDomain.rawValue):"
        let sanValues = flattenedStrings(values).filter { $0.hasPrefix("urn:aurora:acp:node:") }
        guard sanValues.count == 1, sanValues[0].hasPrefix(expectedPrefix),
              let node = ACPSecurityNodeID(rawValue: String(sanValues[0].dropFirst(expectedPrefix.count))),
              expectedNode.map({ $0 == node }) ?? true,
              validBasicConstraints(values), validKeyUsage(values), validExtendedKeyUsage(values),
              validKeyIdentifier(values, oid: kSecOIDSubjectKeyIdentifier as String),
              validKeyIdentifier(values, oid: kSecOIDAuthorityKeyIdentifier as String),
              validSerial(values),
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
#else
        // SecCertificateCopyValues and the OID property API used for ACP's
        // strict extension audit are macOS-only. Fail closed until the
        // separately scoped iOS X.509 parser/policy milestone is implemented.
        _ = (chain, anchors, expectedDomain, expectedNode, evaluationDate, revocation)
        throw ACPAppleSecurityError.providerUnavailable
#endif
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
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil)
        else { throw ACPAppleSecurityError.trustFailure }
    }

#if os(macOS)
    private static func certificateValues(_ certificate: SecCertificate) throws -> [String: Any] {
        let keys = [kSecOIDSubjectAltName, kSecOIDBasicConstraints, kSecOIDKeyUsage, kSecOIDExtendedKeyUsage,
                    kSecOIDSubjectKeyIdentifier, kSecOIDAuthorityKeyIdentifier, kSecOIDX509V1SerialNumber] as CFArray
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

    private static func extensionValue(_ values: [String: Any], oid: String) -> Any? {
        (values[oid] as? [String: Any])?[kSecPropertyKeyValue as String]
    }

    private static func validBasicConstraints(_ values: [String: Any]) -> Bool {
        guard let entries = extensionValue(values, oid: kSecOIDBasicConstraints as String) as? [[String: Any]] else {
            return false
        }
        let pairs = Dictionary(uniqueKeysWithValues: entries.compactMap { entry -> (String, String)? in
            guard let label = entry[kSecPropertyKeyLabel as String] as? String,
                  let value = entry[kSecPropertyKeyValue as String] as? String else { return nil }
            return (label, value)
        })
        return pairs["Critical"] == "Yes" && pairs["Certificate Authority"] == "No"
    }

    private static func validKeyUsage(_ values: [String: Any]) -> Bool {
        guard let number = extensionValue(values, oid: kSecOIDKeyUsage as String) as? NSNumber else { return false }
        let bits = number.uint32Value
        return bits & 1 == 1 && bits & 0x7fff_fffe == 0
    }

    private static func validExtendedKeyUsage(_ values: [String: Any]) -> Bool {
        guard let usages = extensionValue(values, oid: kSecOIDExtendedKeyUsage as String) as? [Data] else {
            return false
        }
        return Set(usages) == Set([
            Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
            Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]),
        ])
    }

    private static func validKeyIdentifier(_ values: [String: Any], oid: String) -> Bool {
        guard let entries = extensionValue(values, oid: oid) as? [[String: Any]] else { return false }
        let identifiers = entries.compactMap { $0[kSecPropertyKeyValue as String] as? Data }
        return identifiers.count == 1 && identifiers[0].count == 20
    }

    private static func validSerial(_ values: [String: Any]) -> Bool {
        guard let text = extensionValue(values, oid: kSecOIDX509V1SerialNumber as String) as? String else {
            return false
        }
        let octets = text.split(separator: " ").compactMap { UInt8($0, radix: 16) }
        return octets.count == 16 && octets.contains(where: { $0 != 0 })
    }
#endif

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
