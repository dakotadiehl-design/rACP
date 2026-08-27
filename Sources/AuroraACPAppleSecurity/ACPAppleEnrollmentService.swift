import AuroraACP
import Foundation

public enum ACPAppleEnrollmentServiceError: String, Error, Sendable, Equatable {
    case invalidConfiguration = "security.enrollment.invalid_configuration"
    case invalidBootstrapSecret = "security.enrollment.invalid_bootstrap_secret"
    case notStarted = "security.enrollment.service_not_started"
    case alreadyStarted = "security.enrollment.service_already_started"
    case stopped = "security.enrollment.service_stopped"
    case resourceLimit = "security.enrollment.resource_limit"
    case timeout = "security.enrollment.timeout"
    case operationCancelled = "security.enrollment.operation_cancelled"
    case protocolViolation = "security.enrollment.protocol_violation"
    case approvalExpired = "security.enrollment.approval_expired"
    case credentialIssuanceFailed = "security.enrollment.credential_issuance_failed"
    case receiptOrTrustCommitFailed = "security.enrollment.receipt_or_trust_commit_failed"
    case failed = "security.enrollment.failed"
}

public struct ACPAppleEnrollmentServiceConfiguration: Sendable, Equatable {
    public let port: UInt16
    public let maximumConcurrentAttempts: Int
    public let maximumPendingConnections: Int
    public let maximumMessagesPerConnection: Int
    public let maximumMessageBytes: Int
    public let connectionTimeout: TimeInterval

    public init(port: UInt16 = 0, maximumConcurrentAttempts: Int = 2,
                maximumPendingConnections: Int = 8,
                maximumMessagesPerConnection: Int = 16,
                maximumMessageBytes: Int = 64 * 1024,
                connectionTimeout: TimeInterval = 60) throws {
        guard (1...8).contains(maximumConcurrentAttempts),
              (1...32).contains(maximumPendingConnections),
              (1...64).contains(maximumMessagesPerConnection),
              (1024...262_144).contains(maximumMessageBytes),
              connectionTimeout.isFinite, (1...600).contains(connectionTimeout) else {
            throw ACPAppleEnrollmentServiceError.invalidConfiguration
        }
        self.port = port; self.maximumConcurrentAttempts = maximumConcurrentAttempts
        self.maximumPendingConnections = maximumPendingConnections
        self.maximumMessagesPerConnection = maximumMessagesPerConnection
        self.maximumMessageBytes = maximumMessageBytes
        self.connectionTimeout = connectionTimeout
    }
}

public struct ACPAppleEnrollmentCandidate: Sendable {
    public let enrollmentID: ACPEnrollmentID
    public let nodeID: ACPSecurityNodeID
    public let displayName: String?
    public let requestedRole: String
    fileprivate let bootstrapSecret: ACPAppleEnrollmentBootstrapSecret

    public init(enrollmentID: ACPEnrollmentID, nodeID: ACPSecurityNodeID,
                displayName: String? = nil, requestedRole: String,
                bootstrapSecret: ACPAppleEnrollmentBootstrapSecret) throws {
        guard (1...64).contains(requestedRole.utf8.count),
              displayName.map({ (1...128).contains($0.utf8.count) }) ?? true else {
            throw ACPAppleEnrollmentServiceError.invalidConfiguration
        }
        self.enrollmentID = enrollmentID; self.nodeID = nodeID
        self.displayName = displayName; self.requestedRole = requestedRole
        self.bootstrapSecret = bootstrapSecret
    }
}

public struct ACPAppleEnrollmentServiceEndpoint: Sendable, Equatable {
    public let port: UInt16
    public let profile = "security.enrollment"
    public let authenticatedSessionAvailable = false
}

public enum ACPAppleEnrollmentServiceState: String, Sendable, Equatable {
    case initialized, listening, stopped
}

public struct ACPAppleEnrollmentServiceStatus: Sendable, Equatable {
    public let state: ACPAppleEnrollmentServiceState
    public let endpoint: ACPAppleEnrollmentServiceEndpoint?
    public let activeAttempts: Int
    public let pendingDecisions: Int
    public let lastError: ACPAppleEnrollmentServiceError?
}

public enum ACPAppleEnrollmentOutcome: String, Sendable, Equatable {
    case complete, cancelled
}

public actor ACPAppleEnrollmentService {
    private let configuration: ACPAppleEnrollmentServiceConfiguration
    private let listener: ACPAppleEnrollmentRestrictedListener
    private let commissionerNodeID: ACPSecurityNodeID
    private let commissionerInstanceID: UUID
    private let trustDomainID: ACPTrustDomainID
    private let authorityKeyID: ACPIdentityKeyID
    private let decisions: ACPAppleEnrollmentDecisionService
    private let coordinator: any ACPAppleEnrollmentCoordinating
    private var state: ACPAppleEnrollmentServiceState = .initialized
    private var activeAttempts: Set<ACPEnrollmentAttemptID> = []
    private var activeConnections: [ACPEnrollmentAttemptID:
        ACPEnrollmentRestrictedConnection] = [:]
    private var lastError: ACPAppleEnrollmentServiceError?
    private var observers: [UUID: AsyncStream<ACPAppleEnrollmentServiceStatus>.Continuation] = [:]
    private var decisionObserver: Task<Void, Never>?

    package init(configuration: ACPAppleEnrollmentServiceConfiguration,
                 commissionerNodeID: ACPSecurityNodeID,
                 commissionerInstanceID: UUID, trustDomainID: ACPTrustDomainID,
                 authorityKeyID: ACPIdentityKeyID,
                 decisions: ACPAppleEnrollmentDecisionService,
                 coordinator: any ACPAppleEnrollmentCoordinating) throws {
        self.configuration = configuration; self.commissionerNodeID = commissionerNodeID
        self.commissionerInstanceID = commissionerInstanceID
        self.trustDomainID = trustDomainID; self.authorityKeyID = authorityKeyID
        self.decisions = decisions; self.coordinator = coordinator
        listener = try ACPAppleEnrollmentRestrictedListener(
            port: configuration.port, localNodeID: commissionerNodeID,
            configuration: try .init(
                maximumPendingConnections: configuration.maximumPendingConnections,
                maximumMessagesPerConnection: configuration.maximumMessagesPerConnection,
                maximumMessageBytes: configuration.maximumMessageBytes,
                connectionTimeoutNanoseconds: Self.nanoseconds(configuration.connectionTimeout)))
    }

    public var endpoint: ACPAppleEnrollmentServiceEndpoint? {
        get async {
            guard state == .listening else { return nil }
            return .init(port: await listener.port)
        }
    }

    public func start() async throws -> ACPAppleEnrollmentServiceEndpoint {
        guard state == .initialized else {
            throw state == .stopped ? ACPAppleEnrollmentServiceError.stopped
                : ACPAppleEnrollmentServiceError.alreadyStarted
        }
        do {
            try await listener.start()
            state = .listening; lastError = nil
            let updates = await decisions.updates()
            decisionObserver = Task { [weak self] in
                for await _ in updates { await self?.decisionChanged() }
            }
            await publishStatus()
            return .init(port: await listener.port)
        } catch {
            state = .stopped; lastError = .failed
            await publishStatus(); throw ACPAppleEnrollmentServiceError.failed
        }
    }

    public func beginEnrollment(_ candidate: ACPAppleEnrollmentCandidate) async throws
        -> ACPAppleEnrollmentOutcome {
        guard state == .listening else {
            throw state == .stopped ? ACPAppleEnrollmentServiceError.stopped
                : ACPAppleEnrollmentServiceError.notStarted
        }
        guard activeAttempts.count < configuration.maximumConcurrentAttempts else {
            throw ACPAppleEnrollmentServiceError.resourceLimit
        }
        let attemptID = ACPEnrollmentAttemptID(rawValue: UUID().uuidString.lowercased())!
        activeAttempts.insert(attemptID); await publishStatus()
        defer { activeAttempts.remove(attemptID); Task { await self.publishStatus() } }
        var activeController: ACPAppleCommissionerEnrollmentController?
        do {
            let registration = try ACPAppleEnrollmentBootstrap.registrationRecord(
                secret: candidate.bootstrapSecret, enrollmentID: candidate.enrollmentID,
                candidateNodeID: candidate.nodeID,
                commissionerNodeID: commissionerNodeID)
            let setup = try ACPAppleCommissionerEnrollmentSetup(
                enrollmentID: candidate.enrollmentID, attemptID: attemptID,
                candidateNodeID: candidate.nodeID, suite: registration.suite,
                requestedRole: candidate.requestedRole,
                requestedPermissionsDigest: Self.emptyPermissionsDigest,
                registrationRecord: registration.record,
                displayName: candidate.displayName,
                expiresAt: Date().addingTimeInterval(600),
                credentialExpiresAt: Date().addingTimeInterval(3_600))
            let connection = try await listener.accept(
                timeoutNanoseconds: Self.nanoseconds(configuration.connectionTimeout))
            guard state == .listening else {
                await connection.close()
                throw ACPAppleEnrollmentServiceError.stopped
            }
            activeConnections[attemptID] = connection
            defer { activeConnections.removeValue(forKey: attemptID) }
            let now = DispatchTime.now().uptimeNanoseconds
            let controller = try ACPAppleCommissionerEnrollmentController(
                commissionerNodeID: commissionerNodeID,
                commissionerInstanceID: commissionerInstanceID,
                trustDomainID: trustDomainID, authorityKeyID: authorityKeyID,
                decisions: decisions, coordinator: coordinator,
                setup: setup, nowNanoseconds: now)
            activeController = controller
            let session = ACPAppleCommissionerEnrollmentSession(
                connection: connection, controller: controller)
            try await session.run()
            lastError = nil
            return await controller.state == .complete ? .complete : .cancelled
        } catch let error as ACPAppleEnrollmentServiceError {
            lastError = error; throw error
        } catch {
            let sanitized = await Self.sanitize(error, controller: activeController)
            lastError = sanitized; throw sanitized
        }
    }

    public func status() async throws -> ACPAppleEnrollmentServiceStatus {
        try await makeStatus()
    }

    public func statusUpdates() -> AsyncStream<ACPAppleEnrollmentServiceStatus> {
        let id = UUID()
        return AsyncStream { continuation in
            observers[id] = continuation
            continuation.onTermination = { _ in Task { await self.removeObserver(id) } }
            Task {
                if let status = try? await self.makeStatus() {
                    continuation.yield(status)
                }
            }
        }
    }

    public func shutdown() async {
        guard state != .stopped else { return }
        state = .stopped; await listener.shutdown()
        decisionObserver?.cancel(); decisionObserver = nil
        let connections = Array(activeConnections.values)
        activeConnections.removeAll()
        for connection in connections { await connection.close() }
        await publishStatus()
        observers.values.forEach { $0.finish() }; observers.removeAll()
    }

    package func decisionChanged() async { await publishStatus() }

    package func uses(_ candidate: ACPAppleEnrollmentServiceConfiguration) -> Bool {
        configuration == candidate
    }

    private func makeStatus() async throws -> ACPAppleEnrollmentServiceStatus {
        .init(state: state,
              endpoint: state == .listening ? .init(port: await listener.port) : nil,
              activeAttempts: activeAttempts.count,
              pendingDecisions: try await decisions.pendingEnrollmentRequests().count,
              lastError: lastError)
    }
    private func publishStatus() async {
        guard let value = try? await makeStatus() else { return }
        observers.values.forEach { $0.yield(value) }
    }
    private func removeObserver(_ id: UUID) { observers.removeValue(forKey: id) }
    private static func nanoseconds(_ interval: TimeInterval) -> UInt64 {
        UInt64(interval * 1_000_000_000)
    }
    private static func sanitize(
        _ error: Error, controller: ACPAppleCommissionerEnrollmentController?
    ) async -> ACPAppleEnrollmentServiceError {
        if error is CancellationError { return .operationCancelled }
        if let restricted = error as? ACPEnrollmentRestrictedError {
            switch restricted {
            case .timeout: return .timeout
            case .resourceLimit: return .resourceLimit
            case .closed: return .operationCancelled
            default: return .protocolViolation
            }
        }
        if error is ACPAppleCommissionerEnrollmentError {
            return .protocolViolation
        }
        if error as? ACPAppleEnrollmentDecisionError == .expired {
            return .approvalExpired
        }
        if let failure = error as? ACPAppleEnrollmentSessionFailure {
            switch failure {
            case .credentialIssuance: return .credentialIssuanceFailed
            case .receiptOrTrustCommit: return .receiptOrTrustCommitFailed
            }
        }
        if let controller {
            switch await controller.state {
            case .issuingCredential: return .credentialIssuanceFailed
            case .awaitingInstallReceipt: return .receiptOrTrustCommitFailed
            default: break
            }
        }
        return .failed
    }
    private static let emptyPermissionsDigest =
        "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"
}
