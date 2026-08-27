import Foundation

/// Portable authority identity metadata. This contains no signing capability
/// and does not imply that the authority and commissioner are co-located.
public struct ACPTrustDomainAuthorityIdentity: Codable, Sendable, Equatable {
    public let trustDomainID: ACPTrustDomainID
    public let authorityKeyID: ACPIdentityKeyID
    public let trustAnchorCredentialID: ACPCredentialID

    public init(trustDomainID: ACPTrustDomainID, authorityKeyID: ACPIdentityKeyID,
                trustAnchorCredentialID: ACPCredentialID) {
        self.trustDomainID = trustDomainID; self.authorityKeyID = authorityKeyID
        self.trustAnchorCredentialID = trustAnchorCredentialID
    }
    enum CodingKeys: String, CodingKey {
        case trustDomainID = "trust_domain_id"
        case authorityKeyID = "authority_key_id"
        case trustAnchorCredentialID = "trust_anchor_credential_id"
    }
}

/// Portable commissioner identity metadata. Authentication does not itself
/// authorize this node to commission enrollment or issue credentials.
public struct ACPCommissionerIdentity: Codable, Sendable, Equatable {
    public let nodeID: ACPSecurityNodeID
    public let instanceID: UUID
    public let credentialID: ACPCredentialID
    public let identityKeyID: ACPIdentityKeyID

    public init(nodeID: ACPSecurityNodeID, instanceID: UUID,
                credentialID: ACPCredentialID, identityKeyID: ACPIdentityKeyID) {
        self.nodeID = nodeID; self.instanceID = instanceID
        self.credentialID = credentialID; self.identityKeyID = identityKeyID
    }
    enum CodingKeys: String, CodingKey {
        case nodeID = "node_id"; case instanceID = "instance_id"
        case credentialID = "credential_id"; case identityKeyID = "identity_key_id"
    }
}

public enum ACPPortableIssuancePurpose: String, Codable, Sendable {
    case initial, renewal, keyRotation = "key_rotation"
}

/// Non-authoritative portable metadata for cross-language audit and fixture
/// comparison. Possession of this value is never issuance evidence.
public struct ACPPortableIssuanceMetadata: Codable, Sendable, Equatable {
    public let authorizationID: UUID
    public let enrollmentID: ACPEnrollmentID
    public let attemptID: ACPEnrollmentAttemptID
    public let trustDomainID: ACPTrustDomainID
    public let authorityKeyID: ACPIdentityKeyID
    public let commissionerNodeID: ACPSecurityNodeID
    public let candidateNodeID: ACPSecurityNodeID
    public let identityKeyID: ACPIdentityKeyID
    public let credentialID: ACPCredentialID
    public let purpose: ACPPortableIssuancePurpose
    public let replacesCredentialID: ACPCredentialID?

    public init(
        authorizationID: UUID, enrollmentID: ACPEnrollmentID,
        attemptID: ACPEnrollmentAttemptID, trustDomainID: ACPTrustDomainID,
        authorityKeyID: ACPIdentityKeyID, commissionerNodeID: ACPSecurityNodeID,
        candidateNodeID: ACPSecurityNodeID, identityKeyID: ACPIdentityKeyID,
        credentialID: ACPCredentialID, purpose: ACPPortableIssuancePurpose,
        replacesCredentialID: ACPCredentialID? = nil
    ) throws {
        guard (purpose == .initial) == (replacesCredentialID == nil)
        else { throw ACPSecurityErrorCode.credentialInvalid }
        self.authorizationID = authorizationID; self.enrollmentID = enrollmentID
        self.attemptID = attemptID; self.trustDomainID = trustDomainID
        self.authorityKeyID = authorityKeyID; self.commissionerNodeID = commissionerNodeID
        self.candidateNodeID = candidateNodeID; self.identityKeyID = identityKeyID
        self.credentialID = credentialID; self.purpose = purpose
        self.replacesCredentialID = replacesCredentialID
    }
    enum CodingKeys: String, CodingKey {
        case authorizationID = "authorization_id"; case enrollmentID = "enrollment_id"
        case attemptID = "attempt_id"; case trustDomainID = "trust_domain_id"
        case authorityKeyID = "authority_key_id"
        case commissionerNodeID = "commissioner_node_id"
        case candidateNodeID = "candidate_node_id"; case identityKeyID = "identity_key_id"
        case credentialID = "credential_id"; case purpose
        case replacesCredentialID = "replaces_credential_id"
    }
}

/// Portable revocation publication metadata, separate from the host's journal
/// and signing-provider reference.
public struct ACPPortableRevocationMetadata: Codable, Sendable, Equatable {
    public let trustDomainID: ACPTrustDomainID
    public let authorityKeyID: ACPIdentityKeyID
    public let epoch: UInt64
    public let snapshotID: ACPCredentialID
    public let previousSnapshotID: ACPCredentialID?

    public init(trustDomainID: ACPTrustDomainID, authorityKeyID: ACPIdentityKeyID,
                epoch: UInt64, snapshotID: ACPCredentialID,
                previousSnapshotID: ACPCredentialID? = nil) throws {
        guard epoch > 0 else { throw ACPSecurityErrorCode.credentialInvalid }
        self.trustDomainID = trustDomainID; self.authorityKeyID = authorityKeyID
        self.epoch = epoch; self.snapshotID = snapshotID
        self.previousSnapshotID = previousSnapshotID
    }
    enum CodingKeys: String, CodingKey {
        case trustDomainID = "trust_domain_id"; case authorityKeyID = "authority_key_id"
        case epoch; case snapshotID = "snapshot_id"
        case previousSnapshotID = "previous_snapshot_id"
    }
}
