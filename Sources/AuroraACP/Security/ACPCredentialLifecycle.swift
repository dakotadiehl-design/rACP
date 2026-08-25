import CryptoKit
import Foundation

public struct ACPX509ValidationEvidence: Sendable {
    public var derParsed, isolatedChain, signatureValid, sanWellFormed: Bool
    public var domainMatches, nodeMatches, ekuValid, kuValid, caConstraintsValid: Bool
    public var validityValid, revocationValid, credentialIDValid, identityKeyIDValid: Bool
    public var possessionValid, localPolicyValid, unknownCriticalExtensions: Bool

    public func requireValid() throws {
        guard derParsed, isolatedChain, signatureValid, sanWellFormed, domainMatches, nodeMatches,
              ekuValid, kuValid, caConstraintsValid, validityValid, revocationValid,
              credentialIDValid, identityKeyIDValid, possessionValid, localPolicyValid,
              !unknownCriticalExtensions
        else { throw ACPSecurityErrorCode.credentialInvalid }
    }
}

public protocol ACPCredentialSignatureVerifier: Sendable {
    func verify(issuerKeyID: String, digest: Data, signature: Data) -> Bool
}

public struct ACPTrustDomainIdentity: Sendable, Equatable {
    public let trustDomainID: ACPTrustDomainID
    public let authorityKeyID: ACPIdentityKeyID
    public init(trustDomainID: ACPTrustDomainID, authorityKeyID: ACPIdentityKeyID) {
        self.trustDomainID = trustDomainID; self.authorityKeyID = authorityKeyID
    }
}

public protocol ACPX509IssuanceProvider: Sendable {
    func issueNodeCertificate(domain: ACPTrustDomainID, node: ACPSecurityNodeID, publicKeySPKI: Data) throws -> Data
}

public struct ACPCredentialAuthority: Sendable {
    public let identity: ACPTrustDomainIdentity
    private let signingKey: any ACPSigningKeyHandle
    public init(identity: ACPTrustDomainIdentity, signingKey: any ACPSigningKeyHandle) throws {
        guard signingKey.keyID == identity.authorityKeyID else { throw ACPSecurityErrorCode.credentialInvalid }
        self.identity = identity; self.signingKey = signingKey
    }
    public static func restore(
        expected: ACPTrustDomainIdentity, restored: ACPTrustDomainIdentity,
        signingKey: any ACPSigningKeyHandle
    ) throws -> Self {
        guard expected == restored else { throw ACPSecurityErrorCode.trustDomainMismatch }
        return try .init(identity: restored, signingKey: signingKey)
    }
    public func issueCompact(body: [String: AnySendable]) throws -> Data {
        guard body["trust_domain_id"] == .string(identity.trustDomainID.rawValue),
              body["issuer_key_id"] == .string(identity.authorityKeyID.rawValue)
        else { throw ACPSecurityErrorCode.trustDomainMismatch }
        let bodyBytes = try ACPEncoding.encodeValue(.plain(.object(body)))
        let digest = Data(SHA256.hash(data: Data("ACP compact credential v1".utf8) + bodyBytes))
        let signature = try signingKey.sign(digest: digest)
        return try ACPEncoding.encodeValue(.plain(.object([
            "body": .object(body), "algorithm": .string("ecdsa_p256_sha256"), "signature": .bytes(signature),
        ])))
    }
    public func issueX509(
        provider: any ACPX509IssuanceProvider, node: ACPSecurityNodeID, publicKeySPKI: Data
    ) throws -> Data {
        try provider.issueNodeCertificate(domain: identity.trustDomainID, node: node, publicKeySPKI: publicKeySPKI)
    }
}

public struct ACPRenewalPlan: Sendable, Equatable {
    public let nodeID: ACPSecurityNodeID
    public let currentKeyID, nextKeyID: ACPIdentityKeyID
    public let rotation: Bool
    public static func create(
        nodeID: ACPSecurityNodeID, currentKeyID: ACPIdentityKeyID,
        rotation: Bool, requestedKeyID: ACPIdentityKeyID?
    ) throws -> Self {
        let next: ACPIdentityKeyID
        if rotation {
            guard let requestedKeyID, requestedKeyID != currentKeyID else { throw ACPSecurityErrorCode.credentialInvalid }
            next = requestedKeyID
        } else {
            guard requestedKeyID == nil else { throw ACPSecurityErrorCode.credentialInvalid }
            next = currentKeyID
        }
        return .init(nodeID: nodeID, currentKeyID: currentKeyID, nextKeyID: next, rotation: rotation)
    }
}

public struct ACPValidatedCompactCredential: Sendable, Equatable {
    public let credentialID: ACPCredentialID
    public let identityKeyID: ACPIdentityKeyID
    public let trustDomainID: ACPTrustDomainID
    public let nodeID: ACPSecurityNodeID
    public let publicKey: Data
    public let roles: [String]
}

public struct ACPCompactCredentialPolicy: Sendable {
    public let expectedDomain: ACPTrustDomainID
    public let expectedNode: ACPSecurityNodeID
    public let possessionValid: Bool
    public let allowedRoles: Set<String>
    public let maximumBytes: Int
    public let evaluationTime: Date
    public init(
        expectedDomain: ACPTrustDomainID, expectedNode: ACPSecurityNodeID,
        possessionValid: Bool, allowedRoles: Set<String>, maximumBytes: Int, evaluationTime: Date
    ) {
        self.expectedDomain = expectedDomain; self.expectedNode = expectedNode
        self.possessionValid = possessionValid; self.allowedRoles = allowedRoles
        self.maximumBytes = maximumBytes; self.evaluationTime = evaluationTime
    }
}

public func ACPValidateCompactCredential(
    _ raw: Data, verifier: any ACPCredentialSignatureVerifier,
    revoked: (ACPCredentialID) -> Bool, policy: ACPCompactCredentialPolicy
) throws -> ACPValidatedCompactCredential {
    guard !raw.isEmpty, raw.count <= policy.maximumBytes,
          case .object(let outer) = try ACPEncoding.decodeValue(raw),
          Set(outer.keys) == Set(["body", "algorithm", "signature"]),
          try ACPEncoding.encodeValue(.plain(.object(outer))) == raw,
          outer["algorithm"] == .string("ecdsa_p256_sha256"),
          case .object(let body) = outer["body"],
          case .bytes(let signature) = outer["signature"]
    else { throw ACPSecurityErrorCode.credentialInvalid }
    let required = Set([
        "format", "serial", "trust_domain_id", "node_id", "identity_algorithm",
        "identity_public_key", "role_constraints", "permission_policy_id", "issued_at",
        "not_before", "expires_at", "issuer_key_id", "extensions",
    ])
    guard Set(body.keys) == required,
          body["format"] == .string("acp-compact-credential-v1"),
          body["identity_algorithm"] == .string("ecdsa_p256_sha256"),
          body["trust_domain_id"] == .string(policy.expectedDomain.rawValue),
          body["node_id"] == .string(policy.expectedNode.rawValue),
          case .string(let issuer) = body["issuer_key_id"], ACPIdentityKeyID(rawValue: issuer) != nil,
          case .bytes(let publicKey) = body["identity_public_key"], !publicKey.isEmpty,
          case .array(let roleValues) = body["role_constraints"], roleValues.count <= 16,
          case .object(let extensions) = body["extensions"], extensions.count <= 64,
          case .string(let issuedText) = body["issued_at"],
          case .string(let notBeforeText) = body["not_before"],
          case .string(let expiresText) = body["expires_at"]
    else { throw ACPSecurityErrorCode.credentialInvalid }
    var roles: [String] = []
    for value in roleValues {
        guard case .string(let role) = value, policy.allowedRoles.contains(role),
              roles.last.map({ $0 < role }) ?? true
        else { throw ACPSecurityErrorCode.credentialInvalid }
        roles.append(role)
    }
    for extensionValue in extensions.values {
        guard case .object(let fields) = extensionValue,
              Set(fields.keys) == Set(["critical", "value"]),
              fields["critical"] != .bool(true), case .some(.bytes) = fields["value"]
        else { throw ACPSecurityErrorCode.credentialInvalid }
    }
    let formatter = ISO8601DateFormatter()
    guard let issuedAt = formatter.date(from: issuedText),
          let notBefore = formatter.date(from: notBeforeText),
          let expiresAt = formatter.date(from: expiresText),
          issuedAt <= policy.evaluationTime, notBefore <= policy.evaluationTime,
          policy.evaluationTime <= expiresAt, notBefore <= expiresAt
    else { throw ACPSecurityErrorCode.credentialExpired }
    let bodyBytes = try ACPEncoding.encodeValue(.plain(.object(body)))
    let digest = Data(SHA256.hash(data: Data("ACP compact credential v1".utf8) + bodyBytes))
    guard verifier.verify(issuerKeyID: issuer, digest: digest, signature: signature), policy.possessionValid,
          let credentialID = ACPCredentialID(rawValue: ACPSecurityContext.digestID(raw)),
          let identityKeyID = ACPIdentityKeyID(rawValue: ACPSecurityContext.digestID(publicKey)),
          !revoked(credentialID)
    else { throw ACPSecurityErrorCode.credentialInvalid }
    return .init(
        credentialID: credentialID, identityKeyID: identityKeyID,
        trustDomainID: policy.expectedDomain, nodeID: policy.expectedNode,
        publicKey: publicKey, roles: roles
    )
}

public struct ACPRevocationEntry: Sendable, Equatable {
    public let credentialID: ACPCredentialID
    public let nodeID: ACPSecurityNodeID
    public let revokedAt: String
    public let reason: String
}

public struct ACPRevocationState: Sendable {
    public let trustDomainID: ACPTrustDomainID
    public let maximumEntries: Int
    public private(set) var epoch: UInt64 = 0
    public private(set) var entries: [ACPCredentialID: ACPRevocationEntry] = [:]
    public private(set) var issuedAt: Date?
    public private(set) var nextUpdate: Date?
    public init(trustDomainID: ACPTrustDomainID, maximumEntries: Int) {
        self.trustDomainID = trustDomainID; self.maximumEntries = maximumEntries
    }
    public mutating func ingest(
        bodyRaw: Data, signature: Data, verifier: any ACPCredentialSignatureVerifier
    ) throws {
        guard case .object(let body) = try ACPEncoding.decodeValue(bodyRaw),
              try ACPEncoding.encodeValue(.plain(.object(body))) == bodyRaw,
              case .string(let format) = body["format"],
              ["acp-revocation-snapshot-v1", "acp-revocation-delta-v1"].contains(format),
              body["trust_domain_id"] == .string(trustDomainID.rawValue),
              case .int(let signedEpoch) = body["epoch"], signedEpoch >= 0,
              case .string(let issuer) = body["issuer_key_id"],
              case .array(let values) = body["entries"],
              case .string(let issuedText) = body["issued_at"],
              case .string(let nextText) = body["next_update"]
        else { throw ACPSecurityErrorCode.credentialInvalid }
        let formatter = ISO8601DateFormatter()
        guard let issued = formatter.date(from: issuedText), let next = formatter.date(from: nextText), next > issued
        else { throw ACPSecurityErrorCode.credentialInvalid }
        let required = Set(["format", "trust_domain_id", "epoch", "issued_at", "next_update", "issuer_key_id", "entries"])
        let allowed = required.union(["base_epoch", "previous_snapshot_hash"])
        guard required.isSubset(of: Set(body.keys)), Set(body.keys).isSubset(of: allowed),
              format == "acp-revocation-delta-v1" || body["base_epoch"] == nil
        else { throw ACPSecurityErrorCode.credentialInvalid }
        let nextEpoch = UInt64(signedEpoch)
        guard nextEpoch > epoch else { throw ACPSecurityErrorCode.authenticationFailed }
        if format == "acp-revocation-delta-v1" {
            guard case .int(let base) = body["base_epoch"], base >= 0,
                  UInt64(base) == epoch, nextEpoch == epoch + 1
            else { throw ACPSecurityErrorCode.authenticationFailed }
        }
        let prospective = format == "acp-revocation-snapshot-v1" ? values.count : values.count + entries.count
        guard values.count <= maximumEntries, prospective <= maximumEntries else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        let digest = Data(SHA256.hash(data: Data("ACP revocation state v1".utf8) + bodyRaw))
        guard verifier.verify(issuerKeyID: issuer, digest: digest, signature: signature) else {
            throw ACPSecurityErrorCode.credentialInvalid
        }
        var parsed: [ACPRevocationEntry] = [], previous = ""
        for value in values {
            guard case .object(let fields) = value,
                  Set(["credential_id", "node_id", "revoked_at", "reason"]).isSubset(of: Set(fields.keys)),
                  Set(fields.keys).isSubset(of: Set(["credential_id", "node_id", "revoked_at", "reason", "replacement_credential_id"])),
                  case .string(let credentialText) = fields["credential_id"], credentialText > previous,
                  let credentialID = ACPCredentialID(rawValue: credentialText),
                  case .string(let nodeText) = fields["node_id"],
                  let nodeID = ACPSecurityNodeID(rawValue: nodeText),
                  case .string(let revokedAt) = fields["revoked_at"],
                  case .string(let reason) = fields["reason"]
            else { throw ACPSecurityErrorCode.credentialInvalid }
            previous = credentialText
            parsed.append(.init(credentialID: credentialID, nodeID: nodeID, revokedAt: revokedAt, reason: reason))
        }
        if format == "acp-revocation-snapshot-v1" { entries.removeAll() }
        for entry in parsed { entries[entry.credentialID] = entry }
        epoch = nextEpoch
        issuedAt = issued
        nextUpdate = next
    }
    public func requireFresh(at now: Date, maximumSnapshotAge: TimeInterval) throws {
        guard maximumSnapshotAge >= 0, let issuedAt, let nextUpdate,
              now <= min(nextUpdate, issuedAt.addingTimeInterval(maximumSnapshotAge))
        else { throw ACPSecurityErrorCode.authenticationFailed }
    }
}

public enum ACPActiveSessionRevocationPolicy: Sendable, Equatable { case hardenedTerminate, explicitAuditedGrace }
public enum ACPRevocationSessionAction: Sendable, Equatable { case retain, terminate, auditedGrace }
public func ACPRevocationAction(
    revoked: Bool, policy: ACPActiveSessionRevocationPolicy = .hardenedTerminate
) -> ACPRevocationSessionAction {
    guard revoked else { return .retain }
    return policy == .hardenedTerminate ? .terminate : .auditedGrace
}

public struct ACPCredentialGeneration: Codable, Sendable, Equatable {
    public let generation: UInt64
    public let credentialID: String
    public let identityKeyID: String
    public let credential: Data
    public init(generation: UInt64, credentialID: ACPCredentialID, identityKeyID: ACPIdentityKeyID, credential: Data) {
        self.generation = generation; self.credentialID = credentialID.rawValue
        self.identityKeyID = identityKeyID.rawValue; self.credential = credential
    }
}

public protocol ACPCredentialSlotBackend: Sendable {
    func read(name: String) throws -> Data?
    func write(name: String, data: Data) throws
    func delete(name: String) throws
}

private struct ACPCredentialSlot: Codable {
    let value: ACPCredentialGeneration
    var committed: Bool
    var checksum: Data
}

public actor ACPTwoSlotIdentityStore {
    private let backend: any ACPCredentialSlotBackend
    public init(backend: any ACPCredentialSlotBackend) { self.backend = backend }

    public func stage(_ value: ACPCredentialGeneration) throws {
        guard !value.credential.isEmpty else { throw ACPSecurityErrorCode.storageFailed }
        let slot = ACPCredentialSlot(value: value, committed: false, checksum: checksum(value, false))
        try backend.write(name: name(value.generation), data: try encode(slot))
    }
    public func validateStaged(generation: UInt64, valid: Bool) throws {
        guard let slot = try load(generation), slot.value.generation == generation,
              !slot.committed, slot.checksum == checksum(slot.value, false), valid
        else { throw ACPSecurityErrorCode.storageFailed }
    }
    public func commit(generation: UInt64) throws {
        guard var slot = try load(generation), slot.value.generation == generation,
              slot.checksum == checksum(slot.value, slot.committed)
        else { throw ACPSecurityErrorCode.storageFailed }
        slot.committed = true; slot.checksum = checksum(slot.value, true)
        try backend.write(name: name(generation), data: try encode(slot))
        try backend.write(name: "active", data: Data("\(generation)\n".utf8))
    }
    public func recover() throws -> ACPCredentialGeneration? {
        [safeLoad(0), safeLoad(1)].compactMap { $0 }
            .filter { $0.committed && $0.checksum == checksum($0.value, true) }
            .max { $0.value.generation < $1.value.generation }?.value
    }
    public func resetTrust() throws {
        try backend.delete(name: "slot-0"); try backend.delete(name: "slot-1")
        try backend.delete(name: "active")
    }
    private func name(_ generation: UInt64) -> String { "slot-\(generation & 1)" }
    private func load(_ generation: UInt64) throws -> ACPCredentialSlot? {
        guard let raw = try backend.read(name: name(generation)) else { return nil }
        return try JSONDecoder().decode(ACPCredentialSlot.self, from: raw)
    }
    private func safeLoad(_ generation: UInt64) -> ACPCredentialSlot? {
        try? load(generation)
    }
    private func encode(_ slot: ACPCredentialSlot) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(slot)
    }
    private func checksum(_ value: ACPCredentialGeneration, _ committed: Bool) -> Data {
        var input = Data(); var generation = value.generation.bigEndian
        withUnsafeBytes(of: &generation) { input.append(contentsOf: $0) }
        input += Data(value.credentialID.utf8) + Data(value.identityKeyID.utf8) + value.credential
        input.append(committed ? 1 : 0)
        return Data(SHA256.hash(data: input))
    }
}

public enum ACPRotationPhase: Sendable { case idle, keyPrepared, credentialObtained, staged, possessionProved, active }
public actor ACPRotationCoordinator {
    public private(set) var phase: ACPRotationPhase = .idle
    private var pending: ACPCredentialGeneration?
    public func prepare(_ value: ACPCredentialGeneration, store: ACPTwoSlotIdentityStore) async throws {
        guard phase == .idle, try await store.recover() != nil else { throw ACPSecurityErrorCode.storageFailed }
        pending = value; phase = .keyPrepared
    }
    public func credentialObtained() throws { try advance(.keyPrepared, .credentialObtained) }
    public func stage(store: ACPTwoSlotIdentityStore, valid: Bool) async throws {
        guard phase == .credentialObtained, let pending else { throw ACPSecurityErrorCode.credentialInvalid }
        try await store.stage(pending); try await store.validateStaged(generation: pending.generation, valid: valid)
        phase = .staged
    }
    public func possessionProved(_ valid: Bool) throws {
        guard valid else { pending = nil; phase = .idle; throw ACPSecurityErrorCode.credentialInvalid }
        try advance(.staged, .possessionProved)
    }
    public func activate(store: ACPTwoSlotIdentityStore) async throws {
        guard phase == .possessionProved, let pending else { throw ACPSecurityErrorCode.credentialInvalid }
        try await store.commit(generation: pending.generation); phase = .active
    }
    private func advance(_ expected: ACPRotationPhase, _ target: ACPRotationPhase) throws {
        guard phase == expected else { throw ACPSecurityErrorCode.credentialInvalid }; phase = target
    }
}

public func ACPAcceptedTime(
    state: ACPClockTrustState, wall: Date?, checkpoint: Date?, commissioner: Date?, lastCheckpoint: Date?
) throws -> Date {
    let candidate: Date?
    switch state {
    case .trustedWallClock: candidate = wall
    case .authenticatedCheckpoint: candidate = checkpoint
    case .commissionerBounded: candidate = commissioner
    case .untrusted: candidate = nil
    }
    guard let candidate, lastCheckpoint.map({ candidate >= $0 }) ?? true else {
        throw ACPSecurityErrorCode.clockUntrusted
    }
    return candidate
}
