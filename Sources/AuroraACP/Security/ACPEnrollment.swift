import Foundation

public enum ACPCandidateEnrollmentState: String, Sendable {
    case unenrolled, enrollmentOpen = "enrollment_open", negotiating, keyConfirmed = "key_confirmed"
    case awaitingApproval = "awaiting_approval", credentialStaged = "credential_staged", enrolled
    case cancelled, expired, locked, failed
}

public enum ACPCommissionerEnrollmentState: String, Sendable {
    case idle, candidateSelected = "candidate_selected", secretAcquired = "secret_acquired", negotiating
    case keyConfirmed = "key_confirmed", awaitingOperatorApproval = "awaiting_operator_approval"
    case issuingCredential = "issuing_credential", awaitingInstallReceipt = "awaiting_install_receipt"
    case complete, cancelled, expired, locked, failed
}

public struct ACPEnrollmentLimits: Equatable, Sendable {
    public let concurrentAttempts: Int
    public let attemptsPerEnrollment: Int
    public let attemptTimeoutNanoseconds: UInt64
    public let enrollmentWindowNanoseconds: UInt64
    public init(
        concurrentAttempts: Int, attemptsPerEnrollment: Int = 5,
        attemptTimeoutNanoseconds: UInt64 = 60_000_000_000,
        enrollmentWindowNanoseconds: UInt64 = 600_000_000_000
    ) {
        self.concurrentAttempts = concurrentAttempts
        self.attemptsPerEnrollment = attemptsPerEnrollment
        self.attemptTimeoutNanoseconds = attemptTimeoutNanoseconds
        self.enrollmentWindowNanoseconds = enrollmentWindowNanoseconds
    }
    public static func profile(_ profile: ACPSecurityProfile) -> Self {
        .init(concurrentAttempts: profile == .full ? 2 : 1)
    }
}

private struct ACPCandidateAttempt: Sendable {
    var state: ACPCandidateEnrollmentState = .negotiating
    let deadline: UInt64
    var peerShareProcessed = false
    var durableInstallVerified = false
}

public actor ACPCandidateEnrollment {
    public let enrollmentID: ACPEnrollmentID
    public private(set) var state: ACPCandidateEnrollmentState = .enrollmentOpen
    public private(set) var failedAttempts = 0
    public private(set) var consumedAttempts: Set<ACPEnrollmentAttemptID> = []
    private let suites: Set<ACPSecuritySuite>
    private let limits: ACPEnrollmentLimits
    private let openedAt: UInt64
    private let audit: (any ACPAuditSink)?
    private var attempts: [ACPEnrollmentAttemptID: ACPCandidateAttempt] = [:]

    public init(
        enrollmentID: ACPEnrollmentID, suites: Set<ACPSecuritySuite>, limits: ACPEnrollmentLimits,
        openedAtNanoseconds: UInt64, audit: (any ACPAuditSink)? = nil
    ) {
        self.enrollmentID = enrollmentID; self.suites = suites; self.limits = limits
        self.openedAt = openedAtNanoseconds
        self.audit = audit
    }

    public func begin(_ id: ACPEnrollmentAttemptID, suite: ACPSecuritySuite, now: UInt64) throws {
        try checkWindow(now)
        if state == .locked { throw ACPSecurityErrorCode.enrollmentLocked }
        guard state == .enrollmentOpen || state == .negotiating else { throw ACPSecurityErrorCode.enrollmentClosed }
        guard attempts[id] == nil, !consumedAttempts.contains(id) else { throw ACPSecurityErrorCode.enrollmentReplayed }
        guard suites.contains(suite) else { throw ACPSecurityErrorCode.noCommonSuite }
        guard attempts.count < limits.concurrentAttempts else { throw ACPSecurityErrorCode.resourceLimit }
        let (deadline, overflow) = now.addingReportingOverflow(limits.attemptTimeoutNanoseconds)
        guard !overflow, limits.concurrentAttempts > 0, limits.attemptsPerEnrollment > 0,
              limits.attemptTimeoutNanoseconds > 0, limits.enrollmentWindowNanoseconds > 0 else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        attempts[id] = .init(deadline: deadline); state = .negotiating
        record("security.enrollment.attempt_started", id)
    }

    public func verifyKeyConfirmation(
        _ id: ACPEnrollmentAttemptID, operation: inout any ACPSPAKE2PlusOperation,
        confirmation: Data, now: UInt64
    ) throws {
        let current = try active(id, expected: .negotiating, now: now)
        guard current.peerShareProcessed else {
            cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed
        }
        let verified: Bool
        do { verified = try operation.verify(confirmation: confirmation) }
        catch {
            cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed
        }
        guard verified else { cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed }
        var attempt = try active(id, expected: .negotiating, now: now)
        attempt.state = .keyConfirmed; attempts[id] = attempt
        record("security.enrollment.key_confirmed", id)
    }
    public func processPeerShare(
        _ id: ACPEnrollmentAttemptID, operation: inout any ACPSPAKE2PlusOperation,
        encodedShare: Data, now: UInt64
    ) throws -> Data {
        var attempt = try active(id, expected: .negotiating, now: now)
        guard !attempt.peerShareProcessed else {
            cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed
        }
        let response: Data
        do { response = try operation.receive(peerShare: encodedShare) }
        catch { cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed }
        guard !response.isEmpty else { cryptographicFailure(id); throw ACPSecurityErrorCode.authenticationFailed }
        attempt.peerShareProcessed = true; attempts[id] = attempt
        record("security.enrollment.peer_share_processed", id)
        return response
    }
    public func awaitApproval(_ id: ACPEnrollmentAttemptID, now: UInt64) throws {
        try transition(id, expected: .keyConfirmed, target: .awaitingApproval, now: now)
        record("security.enrollment.awaiting_approval", id)
    }
    public func credentialStaged(_ id: ACPEnrollmentAttemptID, now: UInt64) throws {
        try transition(id, expected: .awaitingApproval, target: .credentialStaged, now: now)
        record("security.enrollment.credential_staged", id)
    }
    public func durableInstallVerified(_ id: ACPEnrollmentAttemptID, now: UInt64) throws {
        var attempt = try active(id, expected: .credentialStaged, now: now)
        attempt.durableInstallVerified = true; attempts[id] = attempt
        record("security.enrollment.durable_install_verified", id)
    }
    public func complete(_ id: ACPEnrollmentAttemptID, now: UInt64) throws {
        let attempt = try active(id, expected: .credentialStaged, now: now)
        guard attempt.durableInstallVerified else { throw ACPSecurityErrorCode.storageFailed }
        consume(id); consumeAll(); state = .enrolled
        record("security.enrollment.enrolled", id)
    }
    public func cryptographicFailure(_ id: ACPEnrollmentAttemptID) {
        consume(id); failedAttempts += 1
        if failedAttempts >= limits.attemptsPerEnrollment { consumeAll(); state = .locked }
        else { state = attempts.isEmpty ? .enrollmentOpen : .negotiating }
        record("security.enrollment.cryptographic_failure", id)
    }
    public func cancel() { consumeAll(); state = .cancelled; record("security.enrollment.cancelled") }
    public func restart() { consumeAll(); if state != .enrolled && state != .locked { state = .failed }; record("security.enrollment.restart_invalidated") }

    private func transition(
        _ id: ACPEnrollmentAttemptID, expected: ACPCandidateEnrollmentState,
        target: ACPCandidateEnrollmentState, now: UInt64
    ) throws {
        var attempt = try active(id, expected: expected, now: now); attempt.state = target; attempts[id] = attempt
    }
    private func active(
        _ id: ACPEnrollmentAttemptID, expected: ACPCandidateEnrollmentState, now: UInt64
    ) throws -> ACPCandidateAttempt {
        try checkWindow(now)
        guard let attempt = attempts[id], !consumedAttempts.contains(id) else { throw ACPSecurityErrorCode.enrollmentReplayed }
        guard now < attempt.deadline else { consume(id); state = .expired; throw ACPSecurityErrorCode.enrollmentExpired }
        guard attempt.state == expected else { throw ACPSecurityErrorCode.authenticationFailed }
        return attempt
    }
    private func checkWindow(_ now: UInt64) throws {
        let (deadline, overflow) = openedAt.addingReportingOverflow(limits.enrollmentWindowNanoseconds)
        guard !overflow, now < deadline else {
            consumeAll(); state = .expired; throw ACPSecurityErrorCode.enrollmentExpired
        }
    }
    private func consume(_ id: ACPEnrollmentAttemptID) { attempts.removeValue(forKey: id); consumedAttempts.insert(id) }
    private func consumeAll() { consumedAttempts.formUnion(attempts.keys); attempts.removeAll(keepingCapacity: false) }
    private func record(_ event: String, _ id: ACPEnrollmentAttemptID? = nil) {
        var fields = ["enrollment_id": enrollmentID.rawValue, "state": state.rawValue]
        if let id { fields["attempt_id"] = id.rawValue }
        audit?.record(event: event, publicFields: fields)
    }
}

public struct ACPCommissionerEnrollment: Sendable {
    public let enrollmentID: ACPEnrollmentID
    public let attemptID: ACPEnrollmentAttemptID
    public let deadlineNanoseconds: UInt64
    public private(set) var state: ACPCommissionerEnrollmentState = .idle
    public private(set) var consumed = false
    private let audit: (any ACPAuditSink)?
    public init(enrollmentID: ACPEnrollmentID, attemptID: ACPEnrollmentAttemptID, deadlineNanoseconds: UInt64, audit: (any ACPAuditSink)? = nil) {
        self.enrollmentID = enrollmentID; self.attemptID = attemptID; self.deadlineNanoseconds = deadlineNanoseconds
        self.audit = audit
    }
    public mutating func transition(
        from expected: ACPCommissionerEnrollmentState, to target: ACPCommissionerEnrollmentState,
        now: UInt64
    ) throws {
        guard !consumed else { throw ACPSecurityErrorCode.enrollmentReplayed }
        guard now < deadlineNanoseconds else { consumed = true; state = .expired; throw ACPSecurityErrorCode.enrollmentExpired }
        guard state == expected else { throw ACPSecurityErrorCode.authenticationFailed }
        let legal: Bool
        switch (state, target) {
        case (.idle, .candidateSelected), (.candidateSelected, .secretAcquired),
             (.secretAcquired, .negotiating), (.negotiating, .keyConfirmed),
             (.keyConfirmed, .awaitingOperatorApproval),
             (.awaitingOperatorApproval, .issuingCredential),
             (.issuingCredential, .awaitingInstallReceipt),
             (.awaitingInstallReceipt, .complete): legal = true
        default: legal = false
        }
        guard legal else { throw ACPSecurityErrorCode.authenticationFailed }
        state = target
        record("security.enrollment.commissioner_transition")
    }
    public mutating func completeVerifiedInstall(now: UInt64, hmacValid: Bool, proofValid: Bool) throws {
        guard hmacValid, proofValid else { consumed = true; state = .failed; throw ACPSecurityErrorCode.authenticationFailed }
        try transition(from: .awaitingInstallReceipt, to: .complete, now: now); consumed = true
        record("security.enrollment.install_verified")
    }
    public mutating func cancel() { consumed = true; state = .cancelled; record("security.enrollment.cancelled") }
    public mutating func fail() { consumed = true; state = .failed; record("security.enrollment.failed") }
    private func record(_ event: String) {
        audit?.record(event: event, publicFields: ["enrollment_id": enrollmentID.rawValue, "attempt_id": attemptID.rawValue, "state": state.rawValue])
    }
}

public func ACPSelectEnrollmentSuite(
    preferred: [ACPSecuritySuite], supported: Set<ACPSecuritySuite>
) throws -> ACPSecuritySuite {
    guard let suite = preferred.first(where: supported.contains) else { throw ACPSecurityErrorCode.noCommonSuite }
    return suite
}

public actor ACPOneShotApprovalProtector {
    private let aead: any ACPAEADProvider
    private let random: any ACPSecureRandomProvider
    private var consumed: Set<ACPEnrollmentAttemptID> = []
    public init(aead: any ACPAEADProvider, random: any ACPSecureRandomProvider) {
        self.aead = aead; self.random = random
    }
    public func seal(
        attemptID: ACPEnrollmentAttemptID, key: ACPSecretBytes, plaintext: ACPSecretBytes,
        associatedData: Data
    ) throws -> (nonce: Data, ciphertext: Data) {
        guard !consumed.contains(attemptID) else { throw ACPSecurityErrorCode.enrollmentReplayed }
        consumed.insert(attemptID)
        let nonceSecret = try random.bytes(count: 12)
        let nonce = nonceSecret.withUnsafeBytes { Data($0) }
        guard nonce.count == 12 else { throw ACPSecurityErrorCode.resourceLimit }
        return (nonce, try aead.seal(key: key, plaintext: plaintext, nonce: nonce, associatedData: associatedData))
    }
}
