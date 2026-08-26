import Foundation
import Network

final class ResumeBox: @unchecked Sendable {
    private var done = false
    private let lock = NSLock()
    func resume(_ body: () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        if done { return }
        done = true
        body()
    }
}

public actor ACPFramedConnection: ACPTransport {
    package static let maximumFrameLength = 8 * 1024 * 1024

    package static func parseHeader(_ header: Data) throws -> (length: Int, text: Bool) {
        guard header.count == 5 else { throw ACPSessionError("malformed_envelope", "invalid frame header") }
        let length = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= maximumFrameLength else { throw ACPSessionError("invalid_range", "frame too large") }
        guard header[4] == 0 || header[4] == 1 else {
            throw ACPSessionError("malformed_envelope", "reserved frame flags")
        }
        return (Int(length), header[4] == 1)
    }
    private let connection: NWConnection
    private var started = false

    public init(connection: NWConnection) {
        self.connection = connection
    }

    public static func connect(host: String, port: UInt16, timeout: TimeInterval = 10) async throws -> ACPFramedConnection {
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        let framed = ACPFramedConnection(connection: conn)
        try await framed.start(timeout: timeout)
        return framed
    }

    public func start(timeout: TimeInterval = 10) async throws {
        if started { return }
        started = true
        let conn = connection
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    let box = ResumeBox()
                    conn.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            conn.stateUpdateHandler = nil
                            box.resume { cont.resume() }
                        case .failed(let err):
                            box.resume { cont.resume(throwing: err) }
                        case .cancelled:
                            box.resume { cont.resume(throwing: ACPSessionError("unavailable", "cancelled")) }
                        default:
                            break
                        }
                    }
                    conn.start(queue: .global())
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                conn.cancel()
                throw ACPSessionError("timeout", "connect timed out")
            }
            defer { group.cancelAll() }
            try await group.next()!
        }
    }

    public func send(_ data: Data, text: Bool) async throws {
        guard data.count <= Self.maximumFrameLength else {
            throw ACPSessionError("invalid_range", "frame too large")
        }
        var frame = Data()
        var length = UInt32(data.count).bigEndian
        frame.append(Data(bytes: &length, count: 4))
        frame.append(text ? 1 : 0)
        frame.append(data)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: frame, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    public func recv() async throws -> (Data, Bool) {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let header = try await self.receiveExact(5)
            let (length, text) = try Self.parseHeader(header)
            let payload = try await self.receiveExact(length)
            return (payload, text)
        } onCancel: {
            Task { await self.close() }
        }
    }

    public func close() async {
        connection.cancel()
    }

    private func receiveExact(_ count: Int) async throws -> Data {
        if count == 0 { return Data() }
        var collected = Data()
        while collected.count < count {
            let need = count - collected.count
            let chunk: Data = try await withCheckedThrowingContinuation { cont in
                connection.receive(minimumIncompleteLength: 1, maximumLength: need) { data, _, _, error in
                    if let error {
                        cont.resume(throwing: error)
                    } else if let data, !data.isEmpty {
                        cont.resume(returning: data)
                    } else {
                        cont.resume(throwing: ACPSessionError("unavailable", "eof"))
                    }
                }
            }
            collected.append(chunk)
        }
        return collected
    }
}

public actor ACPFramedListener {
    private let listener: NWListener
    private var pending: [NWConnection] = []
    private var waiter: CheckedContinuation<ACPFramedConnection, Error>?

    public init(port: UInt16) throws {
        listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
    }

    public var port: UInt16 {
        listener.port?.rawValue ?? 0
    }

    public func start(timeout: TimeInterval = 10) async throws {
        listener.newConnectionHandler = { conn in
            Task { await self.enqueue(conn) }
        }
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    self.listener.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            self.listener.stateUpdateHandler = nil
                            cont.resume()
                        case .failed(let err):
                            cont.resume(throwing: err)
                        default:
                            break
                        }
                    }
                    self.listener.start(queue: .global())
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw ACPSessionError("timeout", "listener start timed out")
            }
            defer { group.cancelAll() }
            try await group.next()!
        }
    }

    public func accept(timeout: TimeInterval = 10) async throws -> ACPFramedConnection {
        try await withThrowingTaskGroup(of: ACPFramedConnection.self) { group in
            group.addTask { try await self.waitForAccept() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw ACPSessionError("timeout", "accept timed out")
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private func waitForAccept() async throws -> ACPFramedConnection {
        if !pending.isEmpty {
            let conn = pending.removeFirst()
            return try await startFramed(conn)
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                waiter = cont
            }
        } onCancel: {
            Task { await self.failWaiter() }
        }
    }

    private func failWaiter() {
        if let waiter {
            self.waiter = nil
            waiter.resume(throwing: ACPSessionError("timeout", "accept cancelled"))
        }
    }

    public func cancel() {
        listener.cancel()
        if let waiter {
            self.waiter = nil
            waiter.resume(throwing: ACPSessionError("unavailable", "listener cancelled"))
        }
        pending.removeAll()
    }

    private func enqueue(_ conn: NWConnection) async {
        if let waiter {
            self.waiter = nil
            do {
                waiter.resume(returning: try await startFramed(conn))
            } catch {
                waiter.resume(throwing: error)
            }
        } else {
            pending.append(conn)
        }
    }

    private func startFramed(_ conn: NWConnection) async throws -> ACPFramedConnection {
        let framed = ACPFramedConnection(connection: conn)
        try await framed.start()
        return framed
    }
}
