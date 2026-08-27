import AuroraACP
import Foundation

package enum ACPAppleCommissionerEnrollmentError: String, Error, Sendable, Equatable {
    case unexpectedMessage = "security.enrollment.unexpected_message"
    case malformedMessage = "security.enrollment.malformed_message"
    case bindingMismatch = "security.enrollment.binding_mismatch"
    case attemptInProgress = "security.enrollment.attempt_in_progress"
    case cryptographicFailure = "security.enrollment.cryptographic_failure"
}

package struct ACPAppleCommissionerEnrollmentSetup: Sendable {
    package let enrollmentID: ACPEnrollmentID
    package let attemptID: ACPEnrollmentAttemptID
    package let candidateNodeID: ACPSecurityNodeID
    package let suite: ACPSecuritySuite
    package let requestedRole: String
    package let requestedPermissionsDigest: String
    package let registrationRecord: ACPSecretBytes
    package let displayName: String?
    package let expiresAt: Date
    package let credentialExpiresAt: Date

    package init(enrollmentID: ACPEnrollmentID, attemptID: ACPEnrollmentAttemptID,
                 candidateNodeID: ACPSecurityNodeID, suite: ACPSecuritySuite,
                 requestedRole: String, requestedPermissionsDigest: String,
                 registrationRecord: ACPSecretBytes, displayName: String?, expiresAt: Date) throws {
        try self.init(
            enrollmentID: enrollmentID, attemptID: attemptID,
            candidateNodeID: candidateNodeID, suite: suite,
            requestedRole: requestedRole,
            requestedPermissionsDigest: requestedPermissionsDigest,
            registrationRecord: registrationRecord, displayName: displayName,
            expiresAt: expiresAt, credentialExpiresAt: expiresAt)
    }

    package init(enrollmentID: ACPEnrollmentID, attemptID: ACPEnrollmentAttemptID,
                 candidateNodeID: ACPSecurityNodeID, suite: ACPSecuritySuite,
                 requestedRole: String, requestedPermissionsDigest: String,
                 registrationRecord: ACPSecretBytes, displayName: String?,
                 expiresAt: Date, credentialExpiresAt: Date) throws {
        let registrationRecordCount = registrationRecord.withUnsafeBytes { $0.count }
        guard (1...64).contains(requestedRole.utf8.count), registrationRecordCount == 97,
              requestedPermissionsDigest == Self.emptyPermissionsDigest,
              displayName.map({ (1...128).contains($0.utf8.count) }) ?? true,
              expiresAt > Date(), credentialExpiresAt >= expiresAt else {
            throw ACPAppleCommissionerEnrollmentError.malformedMessage
        }
        self.enrollmentID = enrollmentID; self.attemptID = attemptID
        self.candidateNodeID = candidateNodeID; self.suite = suite
        self.requestedRole = requestedRole
        self.requestedPermissionsDigest = requestedPermissionsDigest
        self.registrationRecord = registrationRecord; self.displayName = displayName
        self.expiresAt = expiresAt
        self.credentialExpiresAt = credentialExpiresAt
    }

    private static let emptyPermissionsDigest =
        "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"
}

/// Commissioner-side protocol controller. It owns message binding, the PAKE
/// verifier, transcript construction, and transfer to the decision actor.
package actor ACPAppleCommissionerEnrollmentController {
    package var state: ACPCommissionerEnrollmentState { lifecycle.state }
    private let commissionerNodeID: ACPSecurityNodeID
    private let commissionerInstanceID: UUID
    private let trustDomainID: ACPTrustDomainID
    private let authorityKeyID: ACPIdentityKeyID
    private let decisions: ACPAppleEnrollmentDecisionService
    private let coordinator: any ACPAppleEnrollmentCoordinating
    private let approvalProtector: ACPOneShotApprovalProtector
    private let setup: ACPAppleCommissionerEnrollmentSetup
    private let validity = CommissionerCeremonyValidity()
    private var lifecycle: ACPCommissionerEnrollment
    private var beginMessageID: String?
    private var responseMessageID: String?
    private var confirmMessageID: String?
    private var challengeFacts: ChallengeFacts?
    private var verifier: ACPAppleSPAKE2PlusVerifier?
    private var issuedPackage: ACPIssuedCredentialPackage?
    private var installVerifier: ACPEnrollmentInstallVerifier?
    private var approvalMessageID: String?
    private var delivered = false

    package init(commissionerNodeID: ACPSecurityNodeID,
                 commissionerInstanceID: UUID, trustDomainID: ACPTrustDomainID,
                 authorityKeyID: ACPIdentityKeyID,
                 decisions: ACPAppleEnrollmentDecisionService,
                 coordinator: any ACPAppleEnrollmentCoordinating,
                 approvalProtector: ACPOneShotApprovalProtector = .init(
                    aead: ACPAppleAESGCM(), random: ACPAppleSystemRandom()),
                 setup: ACPAppleCommissionerEnrollmentSetup,
                 nowNanoseconds: UInt64) throws {
        self.commissionerNodeID = commissionerNodeID
        self.commissionerInstanceID = commissionerInstanceID
        self.trustDomainID = trustDomainID; self.authorityKeyID = authorityKeyID
        self.decisions = decisions; self.coordinator = coordinator
        self.approvalProtector = approvalProtector; self.setup = setup
        let interval = setup.expiresAt.timeIntervalSinceNow
        guard interval > 0, interval < Double(UInt64.max) / 1_000_000_000 else {
            throw ACPAppleCommissionerEnrollmentError.malformedMessage
        }
        let (deadline, overflow) = nowNanoseconds.addingReportingOverflow(
            UInt64(interval * 1_000_000_000))
        guard !overflow else { throw ACPAppleCommissionerEnrollmentError.malformedMessage }
        lifecycle = ACPCommissionerEnrollment(
            enrollmentID: setup.enrollmentID, attemptID: setup.attemptID,
            deadlineNanoseconds: deadline)
    }

    package func begin(now: UInt64, timestamp: Date = Date()) throws -> ACPEnvelope {
        guard beginMessageID == nil else {
            throw ACPAppleCommissionerEnrollmentError.attemptInProgress
        }
        try lifecycle.transition(from: .idle, to: .candidateSelected, now: now)
        try lifecycle.transition(from: .candidateSelected, to: .secretAcquired, now: now)
        let id = UUID().uuidString.lowercased(); beginMessageID = id
        return envelope(id: id, type: "security.enrollment.begin", correlationID: nil,
                        timestamp: timestamp, payload: [
            "enrollment_id": .string(setup.enrollmentID.rawValue),
            "attempt_id": .string(setup.attemptID.rawValue),
            "candidate_node_id": .string(setup.candidateNodeID.rawValue),
            "commissioner_node_id": .string(commissionerNodeID.rawValue),
            "commissioner_instance_id": .string(commissionerInstanceID.uuidString.lowercased()),
            "trust_domain_id": .string(trustDomainID.rawValue),
            "suite": .string(setup.suite.rawValue),
            "requested_role": .string(setup.requestedRole),
            "requested_permissions_digest": .string(setup.requestedPermissionsDigest),
        ])
    }

    package func receiveChallenge(_ request: ACPEnvelope, now: UInt64,
                                  timestamp: Date = Date()) throws -> ACPEnvelope {
        guard lifecycle.state == .secretAcquired,
              request.type == "security.enrollment.challenge",
              request.correlationID == beginMessageID else {
            throw ACPAppleCommissionerEnrollmentError.unexpectedMessage
        }
        let facts = try parseChallenge(request)
        var registrationRecord = setup.registrationRecord.withUnsafeBytes { Data($0) }
        defer {
            registrationRecord.resetBytes(in: registrationRecord.indices)
            setup.registrationRecord.clear()
        }
        let operation = try ACPAppleSPAKE2PlusVerifier(
            registrationRecord: registrationRecord,
            proverIdentity: Self.uuidBytes(setup.candidateNodeID.rawValue),
            verifierIdentity: Self.uuidBytes(commissionerNodeID.rawValue),
            context: try ACPSecurityContext.canonicalEnrollment(facts.context))
        let combined: Data
        do { combined = try operation.receive(peerShare: facts.shareP) }
        catch { lifecycle.fail(); throw ACPAppleCommissionerEnrollmentError.cryptographicFailure }
        guard combined.count == 97 else {
            lifecycle.fail(); throw ACPAppleCommissionerEnrollmentError.cryptographicFailure
        }
        try lifecycle.transition(from: .secretAcquired, to: .negotiating, now: now)
        challengeFacts = facts; verifier = operation
        let id = UUID().uuidString.lowercased(); responseMessageID = id
        return envelope(id: id, type: "security.enrollment.response",
                        correlationID: request.messageID, timestamp: timestamp, payload: [
            "attempt_id": .string(setup.attemptID.rawValue),
            "shareV": .bytes(Data(combined.prefix(65))),
            "confirmV": .bytes(Data(combined.dropFirst(65))),
        ])
    }

    package func receiveConfirm(_ request: ACPEnvelope, now: UInt64,
                                wallClock: Date = Date()) async throws {
        guard lifecycle.state == .negotiating,
              request.type == "security.enrollment.confirm",
              request.correlationID == responseMessageID,
              let facts = challengeFacts, let verifier,
              Self.string(request.payload, "attempt_id") == setup.attemptID.rawValue,
              case .bytes(let confirmation)? = request.payload["confirmP"],
              confirmation.count == 32 else {
            throw ACPAppleCommissionerEnrollmentError.unexpectedMessage
        }
        let key: ACPConfirmedSPAKE2PlusKey
        do { key = try verifier.verifyAndConsumeKey(confirmation: confirmation) }
        catch { lifecycle.fail(); throw ACPAppleCommissionerEnrollmentError.cryptographicFailure }
        try lifecycle.transition(from: .negotiating, to: .keyConfirmed, now: now)
        let ceremony = try ACPIssuanceCeremonyFacts(
            authorizationID: UUID(), enrollmentID: setup.enrollmentID,
            attemptID: setup.attemptID, transcriptHash: key.transcriptHash,
            candidateNodeID: setup.candidateNodeID,
            candidateInstanceID: facts.candidateInstanceID,
            commissionerNodeID: commissionerNodeID,
            commissionerInstanceID: commissionerInstanceID,
            trustDomainID: trustDomainID, authorityKeyID: authorityKeyID,
            candidatePublicKeySPKI: facts.identityPublicKey,
            identityKeyID: facts.identityKeyID, requestedRole: setup.requestedRole,
            permissionsDigest: setup.requestedPermissionsDigest,
            approvalID: UUID(), approvalTime: wallClock,
            expiresAt: setup.credentialExpiresAt, cancellationGeneration: 0)
        let summary = ACPAppleEnrollmentRequestSummary(
            requestID: setup.attemptID, candidateNodeID: setup.candidateNodeID,
            displayName: setup.displayName, requestedRole: setup.requestedRole,
            expiresAt: setup.expiresAt)
        try await decisions.submit(try ACPAppleValidatedEnrollmentRequest(
            summary: summary, facts: ceremony, confirmedKey: key), now: wallClock)
        try lifecycle.transition(from: .keyConfirmed,
                                 to: .awaitingOperatorApproval, now: now)
        confirmMessageID = request.messageID
        self.verifier = nil
    }

    package func awaitDecisionAndIssue(now: UInt64, wallClock: Date = Date(),
                                       timestamp: Date = Date()) async throws
        -> ACPEnrollmentRestrictedAction {
        guard lifecycle.state == .awaitingOperatorApproval,
              let confirmationMessageID = confirmMessageID else {
            throw ACPAppleCommissionerEnrollmentError.unexpectedMessage
        }
        let decision = try await waitForDecision(now: wallClock)
        switch decision {
        case .rejected, .cancelled:
            cancel()
            return .init(response: cancelEnvelope(
                correlationID: confirmationMessageID, timestamp: timestamp), terminal: true)
        case .approved(let approval):
            guard approval.request.facts.attemptID == setup.attemptID,
                  approval.request.facts.enrollmentID == setup.enrollmentID else {
                cancel(); throw ACPAppleCommissionerEnrollmentError.bindingMismatch
            }
            try lifecycle.transition(from: .awaitingOperatorApproval,
                                     to: .issuingCredential, now: now)
            let approvedFacts = try factsApprovedNow(
                approval.request.facts, at: Date())
            let capabilities = try ACPIssuanceAuthorizationGate.authorize(
                facts: approvedFacts,
                confirmedKey: approval.request.confirmedKey,
                approvalMatchesCeremony: true, approvalSingleUse: true,
                cancelled: false, replayed: false,
                stillValid: { [validity] in validity.isValid })
            let package = try await coordinator.issue(
                authorization: capabilities.authorization)
            let response = try await approvalEnvelope(
                package: package, request: approval.request,
                correlationID: confirmationMessageID, timestamp: timestamp)
            issuedPackage = package; installVerifier = capabilities.installVerifier
            approvalMessageID = response.messageID
            try lifecycle.transition(from: .issuingCredential,
                                     to: .awaitingInstallReceipt, now: now)
            return .init(response: response, didSend: { [weak self] in
                guard let self else { throw ACPEnrollmentRestrictedError.closed }
                try await self.markApprovalDelivered()
            })
        }
    }

    private func waitForDecision(now: Date) async throws
        -> ACPAppleEnrollmentTerminalDecision {
        let interval = setup.expiresAt.timeIntervalSince(now)
        guard interval > 0 else { throw ACPAppleEnrollmentDecisionError.expired }
        let decisions = self.decisions
        let requestID = setup.attemptID
        return try await withThrowingTaskGroup(
            of: ACPAppleEnrollmentTerminalDecision.self
        ) { group in
            group.addTask {
                try await decisions.awaitDecision(requestID: requestID, now: now)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                throw ACPAppleEnrollmentDecisionError.expired
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else {
                throw ACPAppleEnrollmentDecisionError.expired
            }
            return result
        }
    }

    private func factsApprovedNow(_ facts: ACPIssuanceCeremonyFacts, at date: Date) throws
        -> ACPIssuanceCeremonyFacts {
        try ACPIssuanceCeremonyFacts(
            authorizationID: facts.authorizationID,
            enrollmentID: facts.enrollmentID, attemptID: facts.attemptID,
            transcriptHash: facts.transcriptHash,
            candidateNodeID: facts.candidateNodeID,
            candidateInstanceID: facts.candidateInstanceID,
            commissionerNodeID: facts.commissionerNodeID,
            commissionerInstanceID: facts.commissionerInstanceID,
            trustDomainID: facts.trustDomainID, authorityKeyID: facts.authorityKeyID,
            candidatePublicKeySPKI: facts.candidatePublicKeySPKI,
            identityKeyID: facts.identityKeyID, requestedRole: facts.requestedRole,
            permissionsDigest: facts.permissionsDigest,
            approvalID: UUID(), approvalTime: date, expiresAt: facts.expiresAt,
            cancellationGeneration: facts.cancellationGeneration,
            purpose: facts.purpose, replacesCredentialID: facts.replacesCredentialID)
    }

    package func receiveInstallResult(_ request: ACPEnvelope, now: UInt64) async throws {
        guard lifecycle.state == .awaitingInstallReceipt, delivered,
              request.type == "security.enrollment.install_result",
              request.correlationID == approvalMessageID,
              let package = issuedPackage, let installVerifier,
              case .bytes(let confirmation)? = request.payload["confirmation"],
              confirmation.count == 32 else {
            throw ACPAppleCommissionerEnrollmentError.unexpectedMessage
        }
        var values = request.payload
        values.removeValue(forKey: "confirmation")
        let verified = try installVerifier.verify(
            values: values, confirmation: confirmation)
        let receipt = try await coordinator.verifyInstallReceipt(
            package: package, confirmation: verified)
        try await coordinator.commitTrust(receipt, displayName: setup.displayName)
        try lifecycle.completeVerifiedInstall(now: now, hmacValid: true, proofValid: true)
        validity.invalidate()
        self.installVerifier = nil
    }

    package func cancel() {
        lifecycle.cancel(); validity.invalidate()
        verifier = nil; challengeFacts = nil; installVerifier = nil
    }

    private func markApprovalDelivered() async throws {
        guard lifecycle.state == .awaitingInstallReceipt,
              !delivered, let package = issuedPackage else {
            throw ACPAppleCommissionerEnrollmentError.unexpectedMessage
        }
        try await coordinator.markDelivered(package: package)
        delivered = true
    }

    private func approvalEnvelope(
        package: ACPIssuedCredentialPackage,
        request: ACPAppleValidatedEnrollmentRequest,
        correlationID: String, timestamp: Date
    ) async throws -> ACPEnvelope {
        let facts = request.facts
        let plaintextValues: [String: AnySendable] = [
            "trust_domain_id": .string(package.trustDomainID.rawValue),
            "trust_domain_name": .string("Aurora ACP Trust Domain"),
            "credential": .bytes(package.leafDER),
            "credential_format": .string(ACPCredentialFormat.x509DER.rawValue),
            "authority_key_id": .string(package.authorityKeyID.rawValue),
            "trust_anchor": .bytes(package.trustAnchorDER),
            "role_constraints": .array([.string(facts.requestedRole)]),
            "policy_id": .string("acp.default.v1"), "policy_revision": .uint(1),
            "not_before": .string(Self.timestamp(package.notBefore)),
            "expires_at": .string(Self.timestamp(package.expiresAt)),
            "rotation_deadline": .string(Self.timestamp(package.rotationDeadline)),
            "commissioner_node_id": .string(commissionerNodeID.rawValue),
            "transcript_hash": .bytes(package.transcriptHash),
        ]
        let aadValues: [String: AnySendable] = [
            "message_type": .string("security.enrollment.approval"),
            "attempt_id": .string(setup.attemptID.rawValue),
            "enrollment_id": .string(setup.enrollmentID.rawValue),
            "candidate_node_id": .string(setup.candidateNodeID.rawValue),
            "commissioner_node_id": .string(commissionerNodeID.rawValue),
            "trust_domain_id": .string(trustDomainID.rawValue),
            "acp_version": .string(ACPModel.protocolVersion),
            "extension_version": .string("1.0"), "suite": .string(setup.suite.rawValue),
            "identity_algorithm": .string("ecdsa_p256_sha256"),
            "identity_key_id": .string(facts.identityKeyID.rawValue),
            "transcript_hash": .bytes(package.transcriptHash),
        ]
        var plaintextData = try ACPEncoding.encodeCanonicalValue(.object(plaintextValues))
        let aad = try ACPSecurityContext.canonicalApprovalAAD(aadValues)
        var approvalKeyData = request.confirmedKey.withUnsafeBytes {
            ACPSecurityContext.deriveEnrollmentKeys(
                sharedKey: Data($0), transcriptHash: package.transcriptHash)["approval AEAD"]!
        }
        guard let plaintext = ACPSecretBytes(plaintextData, label: "approval package"),
              let approvalKey = ACPSecretBytes(approvalKeyData, label: "approval key") else {
            throw ACPAppleCommissionerEnrollmentError.cryptographicFailure
        }
        defer {
            plaintext.clear(); approvalKey.clear()
            plaintextData.resetBytes(in: plaintextData.indices)
            approvalKeyData.resetBytes(in: approvalKeyData.indices)
        }
        let sealed = try await approvalProtector.seal(
            attemptID: setup.attemptID, key: approvalKey,
            plaintext: plaintext, associatedData: aad)
        return envelope(id: UUID().uuidString.lowercased(),
                        type: "security.enrollment.approval",
                        correlationID: correlationID, timestamp: timestamp, payload: [
            "attempt_id": .string(setup.attemptID.rawValue),
            "enrollment_id": .string(setup.enrollmentID.rawValue),
            "nonce": .bytes(sealed.nonce), "ciphertext": .bytes(sealed.ciphertext),
        ])
    }

    private func cancelEnvelope(correlationID: String, timestamp: Date) -> ACPEnvelope {
        envelope(id: UUID().uuidString.lowercased(), type: "security.enrollment.cancel",
                 correlationID: correlationID, timestamp: timestamp, payload: [
            "enrollment_id": .string(setup.enrollmentID.rawValue),
            "attempt_id": .string(setup.attemptID.rawValue), "reason": .string("denied"),
        ])
    }

    private func parseChallenge(_ request: ACPEnvelope) throws -> ChallengeFacts {
        let p = request.payload
        guard request.source.nodeID == setup.candidateNodeID.rawValue,
              request.destination?.nodeID == commissionerNodeID.rawValue,
              Self.string(p, "enrollment_id") == setup.enrollmentID.rawValue,
              Self.string(p, "attempt_id") == setup.attemptID.rawValue,
              Self.string(p, "candidate_node_id") == setup.candidateNodeID.rawValue,
              Self.string(p, "commissioner_node_id") == commissionerNodeID.rawValue,
              Self.string(p, "commissioner_instance_id")
                == commissionerInstanceID.uuidString.lowercased(),
              Self.string(p, "trust_domain_id") == trustDomainID.rawValue,
              Self.string(p, "suite") == setup.suite.rawValue,
              Self.string(p, "requested_role") == setup.requestedRole,
              Self.string(p, "requested_permissions_digest")
                == setup.requestedPermissionsDigest,
              Self.string(p, "identity_algorithm") == "ecdsa_p256_sha256",
              let instanceText = Self.string(p, "candidate_instance_id"),
              let candidateInstanceID = UUID(uuidString: instanceText),
              candidateInstanceID.uuidString.lowercased() == instanceText,
              let keyText = Self.string(p, "identity_key_id"),
              let identityKeyID = ACPIdentityKeyID(rawValue: keyText),
              case .bytes(let publicKey)? = p["identity_public_key"], publicKey.count == 91,
              ACPCredentialIdentifiers.identityKeyID(for: publicKey) == identityKeyID,
              case .bytes(let shareP)? = p["shareP"], shareP.count == 65 else {
            throw ACPAppleCommissionerEnrollmentError.bindingMismatch
        }
        let context = [
            "acp_version": ACPModel.protocolVersion,
            "application": "Aurora Communications Protocol",
            "attempt_id": setup.attemptID.rawValue,
            "candidate_instance_id": instanceText,
            "candidate_node_id": setup.candidateNodeID.rawValue,
            "commissioner_instance_id": commissionerInstanceID.uuidString.lowercased(),
            "commissioner_node_id": commissionerNodeID.rawValue,
            "enrollment_id": setup.enrollmentID.rawValue,
            "extension_version": "1.0", "identity_algorithm": "ecdsa_p256_sha256",
            "identity_key_id": identityKeyID.rawValue, "purpose": "security.enrollment",
            "requested_permissions_digest": setup.requestedPermissionsDigest,
            "requested_role": setup.requestedRole, "suite": setup.suite.rawValue,
            "trust_domain_id": trustDomainID.rawValue,
        ]
        return .init(candidateInstanceID: candidateInstanceID,
                     identityKeyID: identityKeyID, identityPublicKey: publicKey,
                     shareP: shareP, context: context)
    }

    private func envelope(id: String, type: String, correlationID: String?,
                          timestamp: Date, payload: [String: AnySendable]) -> ACPEnvelope {
        ACPEnvelope(acp: ACPModel.protocolVersion, messageID: id, type: type,
                    source: .init(nodeID: commissionerNodeID.rawValue),
                    destination: .init(nodeID: setup.candidateNodeID.rawValue),
                    timestampUTC: Self.timestamp(timestamp), correlationID: correlationID,
                    qos: .reliable, payload: payload)
    }
    private static func string(_ payload: [String: AnySendable], _ key: String) -> String? {
        guard case .string(let value)? = payload[key] else { return nil }; return value
    }
    private static func uuidBytes(_ value: String) -> Data {
        var uuid = UUID(uuidString: value)!.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }
    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

private struct ChallengeFacts: Sendable {
    let candidateInstanceID: UUID
    let identityKeyID: ACPIdentityKeyID
    let identityPublicKey: Data
    let shareP: Data
    let context: [String: String]
}

private final class CommissionerCeremonyValidity: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = true
    var isValid: Bool { lock.lock(); defer { lock.unlock() }; return valid }
    func invalidate() { lock.lock(); valid = false; lock.unlock() }
}
