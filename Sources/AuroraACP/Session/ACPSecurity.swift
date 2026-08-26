import Foundation

public enum ACPAuthenticationMode: String, Codable, Sendable {
    case trustedLAN = "trusted_lan"
    case tls
    case auroraTrust = "aurora_trust"
    case enrollmentSPAKE2Plus = "enrollment_spake2plus"
}

public enum ACPPrincipalState: String, Codable, Sendable {
    case unauthenticated, authenticated, revoked, expired
    case identityConflict = "identity_conflict"
    case invalid
}

public enum ACPCredentialState: String, Codable, Sendable {
    case active, expired, revoked, invalid
}

public struct ACPTransportEvidence: Sendable, Equatable {
    public let mode: ACPAuthenticationMode
    public let profile: ACPSecurityProfile
    public let trustDomainID: String?
    public let nodeID: String?
    public let credentialID: String?
    public let identityKeyID: String?
    public let credentialFormat: String?
    public let channelBinding: String?
    public let roleConstraints: Set<String>
    public let credentialState: ACPCredentialState
    public let channelBindingVerified: Bool
    public let zeroRTTUsed: Bool
    public let resumptionUsed: Bool

    package init(
        mode: ACPAuthenticationMode, profile: ACPSecurityProfile = .full,
        trustDomainID: String? = nil, nodeID: String? = nil,
        credentialID: String? = nil, identityKeyID: String? = nil,
        credentialFormat: String? = nil, channelBinding: String? = nil,
        roleConstraints: Set<String> = [], credentialState: ACPCredentialState = .invalid,
        channelBindingVerified: Bool = false, zeroRTTUsed: Bool = false,
        resumptionUsed: Bool = false
    ) {
        self.mode = mode; self.profile = profile; self.trustDomainID = trustDomainID; self.nodeID = nodeID
        self.credentialID = credentialID; self.identityKeyID = identityKeyID
        self.credentialFormat = credentialFormat; self.channelBinding = channelBinding
        self.roleConstraints = roleConstraints
        self.credentialState = credentialState; self.channelBindingVerified = channelBindingVerified
        self.zeroRTTUsed = zeroRTTUsed; self.resumptionUsed = resumptionUsed
    }
}

public struct ACPAuthenticatedPrincipal: Sendable, Equatable {
    public let state: ACPPrincipalState
    public let mode: ACPAuthenticationMode
    public let profile: ACPSecurityProfile?
    public let trustDomainID: String?
    public let nodeID: String?
    public let credentialID: String?
    public let identityKeyID: String?
    public let credentialFormat: String?
    public let roleConstraints: Set<String>
}

public enum ACPSecurityAdmissionError: String, Error, Sendable {
    case credentialInvalid = "security.credential_invalid"
    case identityMismatch = "security.identity_mismatch"
    case trustDomainMismatch = "security.trust_domain_mismatch"
    case downgradeForbidden = "security.downgrade_forbidden"
    case authenticationFailed = "security.authentication_failed"
    case credentialExpired = "security.credential_expired"
    case credentialRevoked = "security.credential_revoked"
}

public enum ACPSecurityAdmission {
    public static func bindHello(
        claimedNodeID: String,
        auth: [String: String],
        evidence: ACPTransportEvidence?,
        hardened: Bool,
        securityCapabilities: [(id: String, version: String)] = []
    ) throws -> ACPAuthenticatedPrincipal {
        guard let value = auth["mode"], let mode = ACPAuthenticationMode(rawValue: value) else {
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard let evidence else {
            if mode == .trustedLAN && !hardened {
                return .init(state: .unauthenticated, mode: mode, profile: nil, trustDomainID: nil, nodeID: nil,
                             credentialID: nil, identityKeyID: nil, credentialFormat: nil, roleConstraints: [])
            }
            if hardened { throw ACPSecurityAdmissionError.downgradeForbidden }
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard mode == evidence.mode else { throw ACPSecurityAdmissionError.downgradeForbidden }
        guard mode == .auroraTrust else {
            if hardened { throw ACPSecurityAdmissionError.downgradeForbidden }
            return .init(state: .unauthenticated, mode: mode, profile: nil, trustDomainID: nil, nodeID: nil,
                         credentialID: nil, identityKeyID: nil, credentialFormat: nil, roleConstraints: [])
        }
        if evidence.zeroRTTUsed || evidence.resumptionUsed {
            throw ACPSecurityAdmissionError.downgradeForbidden
        }
        switch evidence.credentialState {
        case .active: break
        case .revoked: throw ACPSecurityAdmissionError.credentialRevoked
        case .expired: throw ACPSecurityAdmissionError.credentialExpired
        case .invalid: throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard evidence.channelBindingVerified else { throw ACPSecurityAdmissionError.authenticationFailed }
        guard Set(securityCapabilities.map(\.id)).count == securityCapabilities.count else {
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard securityCapabilities.contains(where: { $0.id == "aurora-trust" && $0.version == "1.0" }) else {
            throw ACPSecurityAdmissionError.downgradeForbidden
        }
        guard evidence.nodeID != nil, evidence.trustDomainID != nil, evidence.credentialID != nil,
              evidence.identityKeyID != nil, evidence.channelBinding != nil
        else { throw ACPSecurityAdmissionError.credentialInvalid }
        guard let domain = evidence.trustDomainID.flatMap(ACPTrustDomainID.init(rawValue:)),
              let node = evidence.nodeID.flatMap(ACPSecurityNodeID.init(rawValue:)),
              evidence.credentialID.flatMap(ACPCredentialID.init(rawValue:)) != nil,
              evidence.identityKeyID.flatMap(ACPIdentityKeyID.init(rawValue:)) != nil,
              domain.rawValue == evidence.trustDomainID, node.rawValue == evidence.nodeID,
              evidence.credentialFormat == (evidence.profile == .full ? "x509_der" : "acp-compact-credential-v1"),
              evidence.roleConstraints.count <= 16,
              evidence.roleConstraints.allSatisfy({ (1...64).contains($0.utf8.count) }),
              let bindingText = evidence.channelBinding,
              let binding = try? ACPSecurityContext.base64URLDecode(bindingText), binding.count == 32
        else { throw ACPSecurityAdmissionError.credentialInvalid }
        guard claimedNodeID == evidence.nodeID else { throw ACPSecurityAdmissionError.identityMismatch }
        guard auth["trust_domain_id"] == evidence.trustDomainID else { throw ACPSecurityAdmissionError.trustDomainMismatch }
        guard auth["credential_id"] == evidence.credentialID,
              auth["identity_key_id"] == evidence.identityKeyID,
              auth["channel_binding"] == evidence.channelBinding
        else { throw ACPSecurityAdmissionError.identityMismatch }
        return .init(state: .authenticated, mode: mode, profile: evidence.profile,
                     trustDomainID: evidence.trustDomainID,
                     nodeID: evidence.nodeID, credentialID: evidence.credentialID,
                     identityKeyID: evidence.identityKeyID, credentialFormat: evidence.credentialFormat,
                     roleConstraints: evidence.roleConstraints)
    }

    public static func effectivePermissions(
        credentialConstraints: Set<String>, localPolicy: Set<String>,
        capabilities: Set<String>, safetyPolicy: Set<String>
    ) -> Set<String> {
        credentialConstraints.intersection(localPolicy).intersection(capabilities).intersection(safetyPolicy)
    }
}
