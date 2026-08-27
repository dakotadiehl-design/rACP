import AuroraACP
import Foundation
import Network

package struct ACPAppleEnrollmentRestrictedListenerConfiguration: Sendable {
    package let maximumPendingConnections: Int
    package let maximumMessagesPerConnection: Int
    package let maximumMessageBytes: Int
    package let connectionTimeoutNanoseconds: UInt64

    package init(maximumPendingConnections: Int = 8,
                 maximumMessagesPerConnection: Int = 16,
                 maximumMessageBytes: Int = 64 * 1024,
                 connectionTimeoutNanoseconds: UInt64 = 60_000_000_000) throws {
        guard (1...32).contains(maximumPendingConnections),
              (1...64).contains(maximumMessagesPerConnection),
              (1024...262_144).contains(maximumMessageBytes),
              connectionTimeoutNanoseconds > 0 else {
            throw ACPEnrollmentRestrictedError.invalidConfiguration
        }
        self.maximumPendingConnections = maximumPendingConnections
        self.maximumMessagesPerConnection = maximumMessagesPerConnection
        self.maximumMessageBytes = maximumMessageBytes
        self.connectionTimeoutNanoseconds = connectionTimeoutNanoseconds
    }
}

/// Package-owned raw enrollment listener. It creates only restricted
/// pre-session connections and has no authenticated-session conversion path.
package actor ACPAppleEnrollmentRestrictedListener {
    private let listener: NWListener
    private let localNodeID: ACPSecurityNodeID
    private let configuration: ACPAppleEnrollmentRestrictedListenerConfiguration
    private var pending: [NWConnection] = []
    private var waiters: [(UUID, CheckedContinuation<NWConnection, Error>)] = []
    private var started = false
    private var stopped = false

    package init(port: UInt16 = 0, localNodeID: ACPSecurityNodeID,
                 configuration: ACPAppleEnrollmentRestrictedListenerConfiguration) throws {
        guard let port = NWEndpoint.Port(rawValue: port) else {
            throw ACPEnrollmentRestrictedError.invalidConfiguration
        }
        listener = try NWListener(using: .tcp, on: port)
        self.localNodeID = localNodeID
        self.configuration = configuration
    }

    package var port: UInt16 { listener.port?.rawValue ?? 0 }

    package func start(timeoutNanoseconds: UInt64 = 10_000_000_000) async throws {
        guard !started, !stopped, timeoutNanoseconds > 0 else {
            throw ACPEnrollmentRestrictedError.closed
        }
        listener.newConnectionHandler = { connection in
            Task { await self.enqueue(connection) }
        }
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { continuation in
                        let gate = EnrollmentListenerCompletionGate()
                        self.listener.stateUpdateHandler = { state in
                            switch state {
                            case .ready: gate.run { continuation.resume() }
                            case .failed(let error):
                                gate.run { continuation.resume(throwing: error) }
                            case .cancelled:
                                gate.run { continuation.resume(
                                    throwing: ACPEnrollmentRestrictedError.closed) }
                            default: break
                            }
                        }
                        self.listener.start(queue: .global(qos: .userInitiated))
                    }
                } onCancel: {
                    self.listener.cancel()
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
                throw ACPEnrollmentRestrictedError.timeout
            }
            defer { group.cancelAll() }
            try await group.next()!
            }
            listener.stateUpdateHandler = nil
            started = true
        } catch {
            listener.stateUpdateHandler = nil
            listener.newConnectionHandler = nil
            stopped = true
            listener.cancel()
            pending.forEach { $0.cancel() }
            pending.removeAll(keepingCapacity: false)
            throw error
        }
    }

    package func accept(timeoutNanoseconds: UInt64 = 10_000_000_000) async throws
        -> ACPEnrollmentRestrictedConnection {
        guard started, !stopped, timeoutNanoseconds > 0 else {
            throw ACPEnrollmentRestrictedError.closed
        }
        let connection = try await nextConnection(timeoutNanoseconds: timeoutNanoseconds)
        do {
            let framed = try ACPFramedConnection(
                connection: connection,
                maximumFrameLength: configuration.maximumMessageBytes)
            try await framed.start(timeout: Double(timeoutNanoseconds) / 1_000_000_000)
            return try ACPEnrollmentRestrictedConnection(
                transport: framed, localNodeID: localNodeID,
                allowedInboundTypes: Self.commissionerInboundTypes,
                orderedInboundTypes: Self.commissionerInboundSequence,
                maximumMessages: configuration.maximumMessagesPerConnection,
                maximumMessageBytes: configuration.maximumMessageBytes,
                timeoutNanoseconds: configuration.connectionTimeoutNanoseconds)
        } catch {
            connection.cancel()
            throw error
        }
    }

    package func shutdown() {
        guard !stopped else { return }
        stopped = true
        listener.cancel()
        pending.forEach { $0.cancel() }
        pending.removeAll(keepingCapacity: false)
        let suspended = waiters
        waiters.removeAll(keepingCapacity: false)
        suspended.forEach { $0.1.resume(throwing: ACPEnrollmentRestrictedError.closed) }
    }

    private func enqueue(_ connection: NWConnection) {
        guard !stopped else { connection.cancel(); return }
        if !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            waiter.1.resume(returning: connection)
        } else if pending.count < configuration.maximumPendingConnections {
            pending.append(connection)
        } else {
            connection.cancel()
        }
    }

    private func nextConnection(timeoutNanoseconds: UInt64) async throws -> NWConnection {
        if !pending.isEmpty { return pending.removeFirst() }
        let id = UUID()
        return try await withThrowingTaskGroup(of: EnrollmentConnectionBox.self) { group in
            group.addTask {
                let connection = try await withTaskCancellationHandler(
                    operation: { try await self.waitForConnection(id: id) },
                    onCancel: { Task { await self.cancelWaiter(id: id) } })
                return EnrollmentConnectionBox(connection)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
                throw ACPEnrollmentRestrictedError.timeout
            }
            defer { group.cancelAll() }
            return try await group.next()!.connection
        }
    }

    private func waitForConnection(id: UUID) async throws -> NWConnection {
        try await withCheckedThrowingContinuation { continuation in
            guard !stopped else {
                continuation.resume(throwing: ACPEnrollmentRestrictedError.closed)
                return
            }
            waiters.append((id, continuation))
        }
    }

    private func cancelWaiter(id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.1.resume(throwing: ACPEnrollmentRestrictedError.timeout)
    }

    private static let commissionerInboundSequence = [
        "security.enrollment.challenge",
        "security.enrollment.confirm",
        "security.enrollment.install_result",
    ]
    private static let commissionerInboundTypes = Set(commissionerInboundSequence).union([
        "security.enrollment.cancel", "error.report",
    ])
}

private final class EnrollmentListenerCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    func run(_ operation: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        operation()
    }
}

private struct EnrollmentConnectionBox: @unchecked Sendable {
    let connection: NWConnection
    init(_ connection: NWConnection) { self.connection = connection }
}
