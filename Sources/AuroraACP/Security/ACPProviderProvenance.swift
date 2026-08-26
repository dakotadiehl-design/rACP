import CryptoKit
import Foundation

public enum ACPProviderQualificationStatus: String, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case blocked = "BLOCKED"
    case notRun = "NOT_RUN"
}

public enum ACPProviderProvenanceError: String, Error, Sendable {
    case malformed = "security.provider_manifest_malformed"
    case unqualified = "security.provider_unqualified"
}

/// Validated diagnostic provenance for a provider build. Constructor opacity
/// and live-connection ownership remain the security boundary; this manifest
/// supplies the auditable qualification identity used by local policy.
public struct ACPProviderProvenance: Sendable, Equatable {
    public let adapterID: String
    public let sourceRevision: String
    public let providerName: String
    public let providerVersion: String
    public let targetTriple: String
    public let profiles: Set<String>
    public let keyStorageClasses: Set<String>
    public let qualificationStatus: ACPProviderQualificationStatus
    public let qualificationArtifactSHA256: String
    public let manifestDigest: String

    public init(jsonData: Data, requireQualified: Bool = true) throws {
        guard let root = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              Set(root.keys) == Set([
                  "schema_version", "adapter_id", "source_revision", "provider", "target_triple",
                  "profiles", "key_storage_classes", "qualification",
              ]),
              root["schema_version"] as? String == "1.0",
              let adapterID = root["adapter_id"] as? String, (1...128).contains(adapterID.count),
              let sourceRevision = root["source_revision"] as? String, Self.isHex(sourceRevision, count: 40),
              let targetTriple = root["target_triple"] as? String, !targetTriple.isEmpty,
              let provider = root["provider"] as? [String: Any], Set(provider.keys) == Set(["name", "version"]),
              let providerName = provider["name"] as? String, !providerName.isEmpty,
              let providerVersion = provider["version"] as? String, !providerVersion.isEmpty,
              let profileValues = root["profiles"] as? [String], !profileValues.isEmpty,
              Set(profileValues).count == profileValues.count,
              Set(profileValues).isSubset(of: ["full", "lightweight"]),
              let storageValues = root["key_storage_classes"] as? [String], !storageValues.isEmpty,
              Set(storageValues).count == storageValues.count,
              Set(storageValues).isSubset(of: ["secure_enclave", "tpm", "secure_element", "keychain", "encrypted_file"]),
              let qualification = root["qualification"] as? [String: Any],
              Set(qualification.keys) == Set(["status", "artifact_sha256"]),
              let statusText = qualification["status"] as? String,
              let status = ACPProviderQualificationStatus(rawValue: statusText),
              let artifact = qualification["artifact_sha256"] as? String, Self.isHex(artifact, count: 64)
        else { throw ACPProviderProvenanceError.malformed }
        if requireQualified, status != .pass { throw ACPProviderProvenanceError.unqualified }
        self.adapterID = adapterID
        self.sourceRevision = sourceRevision
        self.providerName = providerName
        self.providerVersion = providerVersion
        self.targetTriple = targetTriple
        self.profiles = Set(profileValues)
        self.keyStorageClasses = Set(storageValues)
        self.qualificationStatus = status
        self.qualificationArtifactSHA256 = artifact
        self.manifestDigest = "sha256:" + SHA256.hash(data: jsonData).map { String(format: "%02x", $0) }.joined()
    }

    private static func isHex(_ value: String, count: Int) -> Bool {
        value.count == count && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}
