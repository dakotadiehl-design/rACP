import AuroraACP
import Foundation

public enum ACPAppleEnrollmentDecisionResult: String, Sendable, Equatable {
    case applied
    case alreadyApplied = "already_applied"
}

public enum ACPAppleEnrollmentDecisionError: String, Error, Sendable, Equatable {
    case unknownRequest = "security.enrollment.unknown_request"
    case invalidState = "security.enrollment.invalid_state"
    case expired = "security.enrollment.expired"
    case storageFailure = "security.enrollment.storage_failure"
}

public struct ACPAppleEnrollmentRequestSummary: Sendable, Equatable, Codable {
    public let requestID: ACPEnrollmentAttemptID
    public let candidateNodeID: ACPSecurityNodeID
    public let displayName: String?
    public let requestedRole: String
    public let expiresAt: Date

    package init(requestID: ACPEnrollmentAttemptID, candidateNodeID: ACPSecurityNodeID,
                 displayName: String?, requestedRole: String, expiresAt: Date) {
        self.requestID = requestID
        self.candidateNodeID = candidateNodeID
        self.displayName = displayName
        self.requestedRole = requestedRole
        self.expiresAt = expiresAt
    }
}

/// In-memory cryptographic capability paired with a presentation-safe request.
/// It cannot be initialized or recovered by an application.
package final class ACPAppleValidatedEnrollmentRequest: @unchecked Sendable {
    package let summary: ACPAppleEnrollmentRequestSummary
    package let facts: ACPIssuanceCeremonyFacts
    package let confirmedKey: ACPConfirmedSPAKE2PlusKey

    package init(summary: ACPAppleEnrollmentRequestSummary,
                 facts: ACPIssuanceCeremonyFacts,
                 confirmedKey: ACPConfirmedSPAKE2PlusKey) throws {
        guard summary.requestID == facts.attemptID,
              summary.candidateNodeID == facts.candidateNodeID,
              summary.requestedRole == facts.requestedRole,
              summary.expiresAt <= facts.expiresAt,
              confirmedKey.transcriptHash == facts.transcriptHash else {
            throw ACPSecurityErrorCode.transcriptMismatch
        }
        self.summary = summary
        self.facts = facts
        self.confirmedKey = confirmedKey
    }
}

package struct ACPAppleApprovedEnrollment: @unchecked Sendable {
    package let request: ACPAppleValidatedEnrollmentRequest
}

package enum ACPAppleEnrollmentTerminalDecision: @unchecked Sendable {
    case approved(ACPAppleApprovedEnrollment)
    case rejected
    case cancelled
}

/// Durable, race-safe human-decision boundary. Only sanitized summaries are
/// persisted. Confirmed PAKE keys remain memory-only, so pending or approved
/// requests are expired whenever this service is reopened.
package actor ACPAppleEnrollmentDecisionService {
    private enum State: String, Codable, Equatable { case pending, approved, rejected, cancelled, expired }
    private struct Entry: Codable, Equatable {
        let summary: ACPAppleEnrollmentRequestSummary
        var state: State
    }
    private struct Snapshot: Codable, Equatable { var version = 1; var entries: [Entry] = [] }

    private let backend: ACPKeychainCredentialBackend
    private let account: String
    private let maximumRequests: Int
    private var snapshot: Snapshot
    private var capabilities: [ACPEnrollmentAttemptID: ACPAppleValidatedEnrollmentRequest] = [:]
    private var consumedApprovals: Set<ACPEnrollmentAttemptID> = []
    private var waiters: [ACPEnrollmentAttemptID:
        (UUID, CheckedContinuation<Void, Error>)] = [:]
    private var observers: [UUID:
        AsyncStream<[ACPAppleEnrollmentRequestSummary]>.Continuation] = [:]

    package init(service: String, account: String = "enrollment-decisions",
                 accessGroup: String? = nil, maximumRequests: Int = 64) throws {
        guard (1...128).contains(service.utf8.count),
              (1...128).contains(account.utf8.count),
              (1...1024).contains(maximumRequests) else {
            throw ACPAppleEnrollmentDecisionError.storageFailure
        }
        backend = ACPKeychainCredentialBackend(service: service, accessGroup: accessGroup)
        self.account = account
        self.maximumRequests = maximumRequests
        if let data = try backend.read(name: account) {
            guard data.count <= 262_144,
                  let decoded = try? JSONDecoder().decode(Snapshot.self, from: data),
                  decoded.version == 1,
                  decoded.entries.count <= maximumRequests,
                  Set(decoded.entries.map(\.summary.requestID)).count == decoded.entries.count,
                  decoded.entries.allSatisfy(Self.valid) else {
                throw ACPAppleEnrollmentDecisionError.storageFailure
            }
            snapshot = decoded
            var recovered = snapshot
            for index in recovered.entries.indices where
                recovered.entries[index].state == .pending
                    || recovered.entries[index].state == .approved {
                recovered.entries[index].state = .expired
            }
            if recovered.entries != snapshot.entries {
                snapshot = recovered
                try Self.persist(snapshot, backend: backend, account: account)
            }
        } else {
            snapshot = Snapshot()
        }
    }

    package func pendingEnrollmentRequests(now: Date = Date()) throws
        -> [ACPAppleEnrollmentRequestSummary] {
        try expire(now: now)
        return snapshot.entries.filter { $0.state == .pending }.map(\.summary)
            .sorted { $0.expiresAt < $1.expiresAt }
    }

    package func updates() -> AsyncStream<[ACPAppleEnrollmentRequestSummary]> {
        let id = UUID()
        return AsyncStream { continuation in
            observers[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeObserver(id) }
            }
            if let pending = try? pendingEnrollmentRequests() {
                continuation.yield(pending)
            }
        }
    }

    package func reset() throws {
        try backend.delete(name: account)
        snapshot = Snapshot()
        capabilities.removeAll()
        consumedApprovals.removeAll()
        let suspended = waiters.values
        waiters.removeAll()
        suspended.forEach { $0.1.resume(throwing: CancellationError()) }
        publishUpdates()
    }

    package func approve(requestID: ACPEnrollmentAttemptID, now: Date = Date()) throws
        -> ACPAppleEnrollmentDecisionResult {
        try decide(requestID: requestID, target: .approved, now: now)
    }

    package func reject(requestID: ACPEnrollmentAttemptID, now: Date = Date()) throws
        -> ACPAppleEnrollmentDecisionResult {
        try decide(requestID: requestID, target: .rejected, now: now)
    }

    package func cancel(requestID: ACPEnrollmentAttemptID, now: Date = Date()) throws
        -> ACPAppleEnrollmentDecisionResult {
        try decide(requestID: requestID, target: .cancelled, now: now)
    }

    package func submit(_ request: ACPAppleValidatedEnrollmentRequest,
                        now: Date = Date()) throws {
        guard request.summary.expiresAt > now, Self.valid(summary: request.summary) else {
            throw ACPAppleEnrollmentDecisionError.expired
        }
        if let index = snapshot.entries.firstIndex(where: {
            $0.summary.requestID == request.summary.requestID
        }) {
            guard snapshot.entries[index].summary == request.summary,
                  snapshot.entries[index].state == .pending else {
                throw ACPAppleEnrollmentDecisionError.invalidState
            }
            capabilities[request.summary.requestID] = request
            return
        }
        guard snapshot.entries.count < maximumRequests else {
            throw ACPAppleEnrollmentDecisionError.storageFailure
        }
        let old = snapshot
        snapshot.entries.append(.init(summary: request.summary, state: .pending))
        capabilities[request.summary.requestID] = request
        do { try persist() }
        catch {
            snapshot = old
            capabilities.removeValue(forKey: request.summary.requestID)
            throw error
        }
        publishUpdates()
    }

    package func consumeApproved(requestID: ACPEnrollmentAttemptID, now: Date = Date()) throws
        -> ACPAppleApprovedEnrollment {
        try expire(now: now)
        guard !consumedApprovals.contains(requestID),
              let entry = snapshot.entries.first(where: { $0.summary.requestID == requestID }),
              entry.state == .approved,
              let request = capabilities.removeValue(forKey: requestID) else {
            throw ACPAppleEnrollmentDecisionError.invalidState
        }
        consumedApprovals.insert(requestID)
        return .init(request: request)
    }

    package func awaitDecision(requestID: ACPEnrollmentAttemptID,
                               now: Date = Date()) async throws
        -> ACPAppleEnrollmentTerminalDecision {
        try expire(now: now)
        guard let entry = snapshot.entries.first(where: {
            $0.summary.requestID == requestID
        }) else { throw ACPAppleEnrollmentDecisionError.unknownRequest }
        if entry.state != .pending { return try terminalDecision(entry, now: now) }
        guard waiters[requestID] == nil else {
            throw ACPAppleEnrollmentDecisionError.invalidState
        }
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiters[requestID] = (waiterID, continuation)
            }
        } onCancel: {
            Task { await self.cancelWaiter(requestID: requestID, id: waiterID) }
        }
        try expire(now: Date())
        guard let current = snapshot.entries.first(where: {
            $0.summary.requestID == requestID
        }) else { throw ACPAppleEnrollmentDecisionError.unknownRequest }
        return try terminalDecision(current, now: Date())
    }

    private func decide(requestID: ACPEnrollmentAttemptID, target: State, now: Date) throws
        -> ACPAppleEnrollmentDecisionResult {
        try expire(now: now)
        guard let index = snapshot.entries.firstIndex(where: {
            $0.summary.requestID == requestID
        }) else { throw ACPAppleEnrollmentDecisionError.unknownRequest }
        if snapshot.entries[index].state == target { return .alreadyApplied }
        guard snapshot.entries[index].state == .pending else {
            throw snapshot.entries[index].state == .expired
                ? ACPAppleEnrollmentDecisionError.expired
                : ACPAppleEnrollmentDecisionError.invalidState
        }
        let old = snapshot
        let oldCapability = capabilities[requestID]
        snapshot.entries[index].state = target
        if target != .approved { capabilities.removeValue(forKey: requestID) }
        do { try persist() }
        catch {
            snapshot = old
            if let oldCapability { capabilities[requestID] = oldCapability }
            throw error
        }
        resumeWaiter(requestID: requestID)
        publishUpdates()
        return .applied
    }

    private func expire(now: Date) throws {
        let old = snapshot
        let oldCapabilities = capabilities
        var changed = false
        for index in snapshot.entries.indices where
            (snapshot.entries[index].state == .pending
                || snapshot.entries[index].state == .approved)
                && snapshot.entries[index].summary.expiresAt <= now {
            capabilities.removeValue(forKey: snapshot.entries[index].summary.requestID)
            snapshot.entries[index].state = .expired
            changed = true
        }
        guard changed else { return }
        do { try persist() }
        catch {
            snapshot = old
            capabilities = oldCapabilities
            throw error
        }
        for entry in snapshot.entries where entry.state == .expired {
            resumeWaiter(requestID: entry.summary.requestID)
        }
        publishUpdates()
    }

    private func persist() throws {
        try Self.persist(snapshot, backend: backend, account: account)
    }

    private static func persist(_ snapshot: Snapshot,
                                backend: ACPKeychainCredentialBackend,
                                account: String) throws {
        guard let data = try? JSONEncoder().encode(snapshot), data.count <= 262_144 else {
            throw ACPAppleEnrollmentDecisionError.storageFailure
        }
        do { try backend.write(name: account, data: data) }
        catch { throw ACPAppleEnrollmentDecisionError.storageFailure }
    }

    private static func valid(_ entry: Entry) -> Bool { valid(summary: entry.summary) }

    private static func valid(summary: ACPAppleEnrollmentRequestSummary) -> Bool {
        (1...64).contains(summary.requestedRole.utf8.count)
            && (summary.displayName.map { (1...128).contains($0.utf8.count) } ?? true)
    }

    private func terminalDecision(_ entry: Entry, now: Date) throws
        -> ACPAppleEnrollmentTerminalDecision {
        switch entry.state {
        case .approved:
            return .approved(try consumeApproved(
                requestID: entry.summary.requestID, now: now))
        case .rejected: return .rejected
        case .cancelled: return .cancelled
        case .expired: throw ACPAppleEnrollmentDecisionError.expired
        case .pending: throw ACPAppleEnrollmentDecisionError.invalidState
        }
    }

    private func resumeWaiter(requestID: ACPEnrollmentAttemptID) {
        waiters.removeValue(forKey: requestID)?.1.resume()
    }

    private func cancelWaiter(requestID: ACPEnrollmentAttemptID, id: UUID) {
        guard waiters[requestID]?.0 == id else { return }
        waiters.removeValue(forKey: requestID)?.1.resume(throwing: CancellationError())
    }

    private func publishUpdates() {
        let pending = snapshot.entries.filter { $0.state == .pending }.map(\.summary)
            .sorted { $0.expiresAt < $1.expiresAt }
        observers.values.forEach { $0.yield(pending) }
    }

    private func removeObserver(_ id: UUID) {
        observers.removeValue(forKey: id)
    }
}

/// Ensures one in-process actor owns each durable decision snapshot. This
/// prevents two host handles for the same Keychain namespace from racing stale
/// copies of the same request state.
package actor ACPAppleEnrollmentDecisionServiceRegistry {
    package static let shared = ACPAppleEnrollmentDecisionServiceRegistry()

    private var services: [String: ACPAppleEnrollmentDecisionService] = [:]

    package func open(service: String, account: String = "enrollment-decisions",
                      accessGroup: String? = nil, maximumRequests: Int = 64) throws
        -> ACPAppleEnrollmentDecisionService {
        let key = [service, account, accessGroup ?? ""].joined(separator: "\u{1f}")
        if let existing = services[key] { return existing }
        let created = try ACPAppleEnrollmentDecisionService(
            service: service, account: account, accessGroup: accessGroup,
            maximumRequests: maximumRequests)
        services[key] = created
        return created
    }
}
