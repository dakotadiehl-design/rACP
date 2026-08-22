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

public struct ACPTransportEvidence: Sendable, Equatable {
    public let mode: ACPAuthenticationMode
    public let trustDomainID: String?
    public let nodeID: String?
    public let credentialID: String?
    public let identityKeyID: String?
    public let credentialFormat: String?
    public let channelBinding: String?
    public let roleConstraints: Set<String>

    public init(
        mode: ACPAuthenticationMode, trustDomainID: String? = nil, nodeID: String? = nil,
        credentialID: String? = nil, identityKeyID: String? = nil,
        credentialFormat: String? = nil, channelBinding: String? = nil,
        roleConstraints: Set<String> = []
    ) {
        self.mode = mode; self.trustDomainID = trustDomainID; self.nodeID = nodeID
        self.credentialID = credentialID; self.identityKeyID = identityKeyID
        self.credentialFormat = credentialFormat; self.channelBinding = channelBinding
        self.roleConstraints = roleConstraints
    }
}

public struct ACPAuthenticatedPrincipal: Sendable, Equatable {
    public let state: ACPPrincipalState
    public let mode: ACPAuthenticationMode
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
}

public enum ACPSecurityAdmission {
    public static func bindHello(
        claimedNodeID: String,
        auth: [String: String],
        evidence: ACPTransportEvidence?,
        hardened: Bool
    ) throws -> ACPAuthenticatedPrincipal {
        guard let value = auth["mode"], let mode = ACPAuthenticationMode(rawValue: value) else {
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard let evidence else {
            if mode == .trustedLAN && !hardened {
                return .init(state: .unauthenticated, mode: mode, trustDomainID: nil, nodeID: nil,
                             credentialID: nil, identityKeyID: nil, credentialFormat: nil, roleConstraints: [])
            }
            if hardened { throw ACPSecurityAdmissionError.downgradeForbidden }
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        guard mode == evidence.mode else { throw ACPSecurityAdmissionError.downgradeForbidden }
        guard mode == .auroraTrust else {
            if hardened { throw ACPSecurityAdmissionError.downgradeForbidden }
            return .init(state: .unauthenticated, mode: mode, trustDomainID: nil, nodeID: nil,
                         credentialID: nil, identityKeyID: nil, credentialFormat: nil, roleConstraints: [])
        }
        guard claimedNodeID == evidence.nodeID else { throw ACPSecurityAdmissionError.identityMismatch }
        guard auth["trust_domain_id"] == evidence.trustDomainID else { throw ACPSecurityAdmissionError.trustDomainMismatch }
        guard auth["credential_id"] == evidence.credentialID,
              auth["identity_key_id"] == evidence.identityKeyID,
              auth["channel_binding"] == evidence.channelBinding
        else { throw ACPSecurityAdmissionError.identityMismatch }
        return .init(state: .authenticated, mode: mode, trustDomainID: evidence.trustDomainID,
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
