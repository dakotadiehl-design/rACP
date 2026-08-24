import CryptoKit
import Foundation

public enum ACPSecurityContextError: Error { case malformed }

public enum ACPSecurityContext {
    public static let enrollmentKeys = [
        "acp_version", "application", "attempt_id", "candidate_instance_id", "candidate_node_id",
        "commissioner_instance_id", "commissioner_node_id", "enrollment_id", "extension_version",
        "identity_algorithm", "identity_key_id", "purpose", "requested_permissions_digest",
        "requested_role", "suite", "trust_domain_id",
    ]

    public static func canonicalEnrollment(_ values: [String: String]) throws -> Data {
        guard Set(values.keys) == Set(enrollmentKeys) else { throw ACPSecurityContextError.malformed }
        return try ACPEncoding.encodeValue(.plain(.object(values.mapValues(AnySendable.string))))
    }

    public static func canonicalTranscript(_ items: [Data]) throws -> Data {
        guard items.count == 5, items.allSatisfy({ !$0.isEmpty }) else {
            throw ACPSecurityContextError.malformed
        }
        return try ACPEncoding.encodeValue(.plain(.array(items.map(AnySendable.bytes))))
    }

    public static func sha256(_ value: Data) -> Data { Data(SHA256.hash(data: value)) }
    public static func digestID(_ value: Data) -> String { "sha256:" + sha256(value).hex }

    public static func permissionDigest(_ permissions: [String: AnySendable]) throws -> String {
        digestID(try ACPEncoding.encodeValue(.plain(.object(permissions))))
    }

    public static func deriveEnrollmentKeys(sharedKey: Data, transcriptHash: Data) -> [String: Data] {
        let root = hmac(key: transcriptHash, data: sharedKey)
        let labels = ["candidate confirm", "commissioner confirm", "approval AEAD", "audit binding", "SAS"]
        return Dictionary(uniqueKeysWithValues: labels.map { label in
            let info = Data("ACP enrollment \(label) v1".utf8)
            return (label, hkdfExpand(key: root, info: info, length: 32))
        })
    }

    public static func base64URLEncode(_ value: Data) -> String {
        value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public static func base64URLDecode(_ text: String) throws -> Data {
        guard !text.isEmpty, !text.contains("=") else { throw ACPSecurityContextError.malformed }
        var normalized = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        guard let data = Data(base64Encoded: normalized), base64URLEncode(data) == text else {
            throw ACPSecurityContextError.malformed
        }
        return data
    }

    public static func channelBindingsEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == 32, right.count == 32 else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    private static func hmac(key: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    private static func hkdfExpand(key: Data, info: Data, length: Int) -> Data {
        var output = Data(), previous = Data()
        for counter in 1...((length + 31) / 32) {
            previous = hmac(key: key, data: previous + info + Data([UInt8(counter)]))
            output += previous
        }
        return output.prefix(length)
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
