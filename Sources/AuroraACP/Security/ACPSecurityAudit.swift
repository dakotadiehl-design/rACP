import Foundation

public enum ACPSecurityOperationClass: String, Codable, Sendable {
    case securityAdministration = "security_administration"
    case trustLifecycle = "trust_issuance_revocation"
    case ordinaryControl = "ordinary_control"
    case safetyCriticalLiveControl = "safety_critical_live_control"
}

public struct ACPSecurityAuditEvent: Codable, Sendable, Equatable {
    public let timestamp: Date
    public let operationClass: ACPSecurityOperationClass
    public let operation: String
    public let outcome: String
    public let auditCorrelationID: String
    public let sessionID: String?
    public let nodeID: String?
    public let credentialID: String?
    public let targetScope: String?
    public let policyRevision: UInt64

    public init(
        timestamp: Date = Date(), operationClass: ACPSecurityOperationClass,
        operation: String, outcome: String, auditCorrelationID: String,
        sessionID: String?, nodeID: String?, credentialID: String?,
        targetScope: String?, policyRevision: UInt64
    ) throws {
        guard (1...128).contains(operation.utf8.count),
              (1...64).contains(outcome.utf8.count),
              (1...128).contains(auditCorrelationID.utf8.count),
              sessionID.map({ (1...128).contains($0.utf8.count) }) ?? true,
              nodeID.map({ (1...128).contains($0.utf8.count) }) ?? true,
              credentialID.map({ (1...128).contains($0.utf8.count) }) ?? true,
              targetScope.map({ (1...256).contains($0.utf8.count) }) ?? true
        else { throw ACPSecurityErrorCode.resourceLimit }
        self.timestamp = timestamp; self.operationClass = operationClass
        self.operation = operation; self.outcome = outcome
        self.auditCorrelationID = auditCorrelationID; self.sessionID = sessionID
        self.nodeID = nodeID; self.credentialID = credentialID
        self.targetScope = targetScope; self.policyRevision = policyRevision
    }
}

public protocol ACPSecurityAuditSink: Sendable {
    func record(_ event: ACPSecurityAuditEvent) throws
}

public struct ACPAuditFailurePolicy: Sendable, Equatable {
    public let ordinaryControlContinues: Bool
    public let safetyCriticalControlContinues: Bool

    public init(ordinaryControlContinues: Bool = true,
                safetyCriticalControlContinues: Bool = true) {
        self.ordinaryControlContinues = ordinaryControlContinues
        self.safetyCriticalControlContinues = safetyCriticalControlContinues
    }

    public func permitsOperationAfterAuditFailure(_ operationClass: ACPSecurityOperationClass) -> Bool {
        switch operationClass {
        case .securityAdministration, .trustLifecycle: return false
        case .ordinaryControl: return ordinaryControlContinues
        case .safetyCriticalLiveControl: return safetyCriticalControlContinues
        }
    }
}

/// A bounded local buffer suitable for surviving a temporarily unavailable
/// external audit sink. It stores identifiers and decisions, never secrets,
/// certificate bytes, PAKE material, private keys, or signing handles.
public final class ACPBoundedSecurityAuditLog: ACPSecurityAuditSink, @unchecked Sendable {
    private let lock = NSLock()
    private let maximumEvents: Int
    private var events: [ACPSecurityAuditEvent] = []

    public init(maximumEvents: Int = 4096) throws {
        guard (1...65_536).contains(maximumEvents) else {
            throw ACPSecurityErrorCode.resourceLimit
        }
        self.maximumEvents = maximumEvents
    }

    public func record(_ event: ACPSecurityAuditEvent) throws {
        try lock.withAuditLock {
            guard events.count < maximumEvents else { throw ACPSecurityErrorCode.resourceLimit }
            events.append(event)
        }
    }

    public func drain(maximum: Int) throws -> [ACPSecurityAuditEvent] {
        try lock.withAuditLock {
            guard (1...maximumEvents).contains(maximum) else {
                throw ACPSecurityErrorCode.resourceLimit
            }
            let count = min(maximum, events.count)
            let result = Array(events.prefix(count))
            events.removeFirst(count)
            return result
        }
    }

    public var count: Int { lock.withAuditLock { events.count } }
}

private extension NSLock {
    func withAuditLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }; return try body()
    }
}
