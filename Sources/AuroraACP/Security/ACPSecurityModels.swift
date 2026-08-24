import Foundation

public protocol ACPStringIdentifier: RawRepresentable, Codable, Hashable, Sendable
where RawValue == String {}

private func validUUID(_ value: String) -> Bool {
    UUID(uuidString: value)?.uuidString.lowercased() == value
}

private func validSHA256ID(_ value: String) -> Bool {
    value.range(of: #"^sha256:[0-9a-f]{64}$"#, options: .regularExpression) != nil
}

public struct ACPTrustDomainID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validUUID(rawValue) else { return nil }; self.rawValue = rawValue }
}
public struct ACPSecurityNodeID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validUUID(rawValue) else { return nil }; self.rawValue = rawValue }
}
public struct ACPEnrollmentID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validUUID(rawValue) else { return nil }; self.rawValue = rawValue }
}
public struct ACPEnrollmentAttemptID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validUUID(rawValue) else { return nil }; self.rawValue = rawValue }
}
public struct ACPCredentialID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validSHA256ID(rawValue) else { return nil }; self.rawValue = rawValue }
}
public struct ACPIdentityKeyID: ACPStringIdentifier {
    public let rawValue: String
    public init?(rawValue: String) { guard validSHA256ID(rawValue) else { return nil }; self.rawValue = rawValue }
}

public enum ACPSecuritySuite: String, Codable, Sendable {
    case raw128 = "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1"
    case pbkdf2_100K = "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-PBKDF2-100K-v1"
}
public enum ACPSecurityProfile: String, Codable, Sendable {
    case full, lightweight
}
public enum ACPCredentialFormat: String, Codable, Sendable {
    case x509DER = "x509_der"
    case compactV1 = "acp-compact-credential-v1"
}
public enum ACPCredentialStatus: String, Codable, Sendable {
    case staged, active, expired, revoked, superseded, invalid, unknown
}
public enum ACPEnrollmentMethod: String, Codable, Sendable {
    case manualCode = "manual_code"
    case qr
    case provisioningFile = "provisioning_file"
}
public enum ACPEnrollmentState: String, Codable, Sendable {
    case closed, open
    case candidateSelected = "candidate_selected"
    case secretAcquired = "secret_acquired"
    case negotiating
    case keyConfirmed = "key_confirmed"
    case awaitingOperatorApproval = "awaiting_operator_approval"
    case issuingCredential = "issuing_credential"
    case awaitingInstallReceipt = "awaiting_install_receipt"
    case complete, cancelled, expired, locked
}
public enum ACPStorageClass: String, Codable, Sendable {
    case hardwareBacked = "hardware_backed"
    case osProtected = "os_protected"
    case encryptedFile = "encrypted_file"
    case protectedFlash = "protected_flash"
    case plainFile = "plain_file"
    case ephemeral
}
public struct ACPStoragePosture: Codable, Equatable, Sendable {
    public let storageClass: ACPStorageClass
    public let hardwareBacked: Bool
    public let privateKeyExportable: Bool
    enum CodingKeys: String, CodingKey {
        case storageClass = "class"
        case hardwareBacked = "hardware_backed"
        case privateKeyExportable = "private_key_exportable"
    }
}
public enum ACPClockTrustState: String, Codable, Sendable {
    case trustedWallClock = "trusted_wall_clock"
    case authenticatedCheckpoint = "authenticated_checkpoint"
    case commissionerBounded = "commissioner_bounded"
    case untrusted
}
public struct ACPSecurityCapabilityVersion: Codable, Equatable, Sendable {
    public let id: String
    public let version: String
    public init?(id: String, version: String) {
        guard !id.isEmpty, !version.isEmpty else { return nil }
        self.id = id; self.version = version
    }
}
public enum ACPSecurityErrorCode: String, Error, Codable, Sendable {
    case enrollmentClosed = "security.enrollment_closed"
    case enrollmentExpired = "security.enrollment_expired"
    case enrollmentLocked = "security.enrollment_locked"
    case enrollmentReplayed = "security.enrollment_replayed"
    case noCommonSuite = "security.no_common_suite"
    case authenticationFailed = "security.authentication_failed"
    case keyConfirmationFailed = "security.key_confirmation_failed"
    case transcriptMismatch = "security.transcript_mismatch"
    case identityMismatch = "security.identity_mismatch"
    case trustDomainMismatch = "security.trust_domain_mismatch"
    case credentialExpired = "security.credential_expired"
    case credentialRevoked = "security.credential_revoked"
    case credentialInvalid = "security.credential_invalid"
    case permissionDenied = "security.permission_denied"
    case downgradeForbidden = "security.downgrade_forbidden"
    case storageFailed = "security.storage_failed"
    case resourceLimit = "security.resource_limit"
    case clockUntrusted = "security.clock_untrusted"
}

public struct ACPDowngradePolicy: Equatable, Sendable {
    public let hardened: Bool
    public let allowTrustedLAN: Bool
    public static let hardenedProduction = Self(hardened: true, allowTrustedLAN: false)
    public static func migration(allowTrustedLAN: Bool) -> Self {
        Self(hardened: false, allowTrustedLAN: allowTrustedLAN)
    }
    public func permitsUnauthenticated(strongerAuthenticationAttempted: Bool) -> Bool {
        allowTrustedLAN && !hardened && !strongerAuthenticationAttempted
    }
}
