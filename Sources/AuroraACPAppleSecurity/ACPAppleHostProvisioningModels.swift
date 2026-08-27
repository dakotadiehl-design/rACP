import AuroraACP
import Foundation

/// Presentation-safe lifecycle state for an ACP-managed Apple host.
public enum ACPAppleHostProvisioningState: String, Codable, Sendable, Equatable {
    case uninitialized
    case bootstrapping
    case ready
    case recoveryRequired = "recovery_required"
    case corrupt
    case resetRequired = "reset_required"
}

/// Sanitized failure categories suitable for application startup and UI.
public enum ACPAppleHostProvisioningError: String, Error, Codable, Sendable {
    case invalidConfiguration = "security.host.invalid_configuration"
    case providerUnqualified = "security.host.provider_unqualified"
    case authorityUnavailable = "security.host.authority_unavailable"
    case identityUnavailable = "security.host.identity_unavailable"
    case storageFailure = "security.host.storage_failure"
    case corruptState = "security.host.corrupt_state"
    case recoveryRequired = "security.host.recovery_required"
    case resetRequired = "security.host.reset_required"
}

/// One-use capability for an explicit destructive local security reset. The
/// initializer is intentionally not public; only the host that owns the state
/// can mint a valid plan.
public struct ACPAppleLocalSecurityResetPlan: Sendable, Equatable {
    public let resetID: UUID
    public let nodeID: ACPSecurityNodeID
    public let trustDomainID: ACPTrustDomainID
    public let consequences: [String]
    package let nonce: UUID

    package init(nodeID: ACPSecurityNodeID, trustDomainID: ACPTrustDomainID) {
        resetID = UUID(); nonce = UUID()
        self.nodeID = nodeID; self.trustDomainID = trustDomainID
        consequences = [
            "All locally trusted peers and revocations are removed.",
            "The local host identity and authority key are deleted.",
            "Pending enrollments are cancelled and cannot be resumed.",
            "Existing connections must be stopped before reset.",
        ]
    }
}

/// Safe status returned without exposing keys, certificates, or Keychain
/// references. Identifiers are present only after they have been validated.
public struct ACPAppleHostProvisioningStatus: Codable, Sendable, Equatable {
    public let state: ACPAppleHostProvisioningState
    public let nodeID: ACPSecurityNodeID
    public let trustDomainID: ACPTrustDomainID?
    public let credentialID: ACPCredentialID?
    public let identityKeyID: ACPIdentityKeyID?

    package init(
        state: ACPAppleHostProvisioningState,
        nodeID: ACPSecurityNodeID,
        trustDomainID: ACPTrustDomainID? = nil,
        credentialID: ACPCredentialID? = nil,
        identityKeyID: ACPIdentityKeyID? = nil
    ) {
        self.state = state
        self.nodeID = nodeID
        self.trustDomainID = trustDomainID
        self.credentialID = credentialID
        self.identityKeyID = identityKeyID
    }
}

public enum ACPAppleCredentialRenewalReadiness: String, Codable, Sendable, Equatable {
    case unsupported
}

/// Presentation-safe operational metadata for the installed local credential.
public struct ACPAppleHostOperationalStatus: Codable, Sendable, Equatable {
    public let credentialExpiresAt: Date
    public let credentialExpired: Bool
    public let renewalReadiness: ACPAppleCredentialRenewalReadiness

    package init(credentialExpiresAt: Date, now: Date) {
        self.credentialExpiresAt = credentialExpiresAt
        credentialExpired = credentialExpiresAt <= now
        renewalReadiness = .unsupported
    }
}

/// Application-supplied inputs for opening one ACP-owned Apple host security
/// graph. The namespace separates all ACP Keychain records belonging to the
/// host; it is not a display name or a security principal.
public struct ACPAppleHostConfiguration: Sendable {
    public let identity: ACPIdentity
    public let storageNamespace: String
    public let keychainAccessGroup: String?
    public let providerProvenance: ACPProviderProvenance
    public let preferSecureEnclave: Bool
    public let allowNonHardwareFallback: Bool

    public init(
        identity: ACPIdentity,
        storageNamespace: String,
        keychainAccessGroup: String? = nil,
        providerProvenance: ACPProviderProvenance,
        preferSecureEnclave: Bool = true,
        allowNonHardwareFallback: Bool = false
    ) throws {
        guard ACPSecurityNodeID(rawValue: identity.nodeID) != nil,
              UUID(uuidString: identity.instanceID)?.uuidString.lowercased() == identity.instanceID,
              (1...64).contains(identity.role.utf8.count),
              (1...128).contains(identity.name.utf8.count),
              Self.validNamespace(storageNamespace),
              keychainAccessGroup.map(Self.validAccessGroup) ?? true,
              providerProvenance.qualificationStatus == .pass,
              providerProvenance.profiles.contains(ACPSecurityProfile.full.rawValue),
              !providerProvenance.keyStorageClasses.isDisjoint(with: ["secure_enclave", "keychain"])
        else { throw ACPAppleHostProvisioningError.invalidConfiguration }

        self.identity = identity
        self.storageNamespace = storageNamespace
        self.keychainAccessGroup = keychainAccessGroup
        self.providerProvenance = providerProvenance
        self.preferSecureEnclave = preferSecureEnclave
        self.allowNonHardwareFallback = allowNonHardwareFallback
    }

    private static func validNamespace(_ value: String) -> Bool {
        guard (3...60).contains(value.utf8.count),
              value.first != ".", value.last != ".",
              !value.contains("..") else { return false }
        return value.utf8.allSatisfy {
            ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39)
                || $0 == 0x2d || $0 == 0x2e
        }
    }

    private static func validAccessGroup(_ value: String) -> Bool {
        guard (1...255).contains(value.utf8.count) else { return false }
        return value.utf8.allSatisfy {
            ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a)
                || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x2e
        }
    }
}
