import Foundation
import Network

/// Optional DNS-SD advertisement owned by an ACP WebSocket listener.
/// Tying publication to `NWListener` prevents the service registration from
/// drifting away from the socket during app lifecycle or interface changes.
public struct ACPBonjourAdvertisement: Sendable, Equatable {
    public var name: String
    public var type: String
    public var domain: String?
    public var txtRecord: [String: String]

    public init(
        name: String,
        type: String,
        domain: String? = "local.",
        txtRecord: [String: String] = [:]
    ) {
        self.name = name
        self.type = type
        self.domain = domain
        self.txtRecord = txtRecord
    }
}

/// Generic ACP WebSocket transport (RFC 6455 via Network.framework). Path default `/acp`.
public actor ACPWebSocketConnection: ACPTransport {
    private let connection: NWConnection
    private var started = false

    public init(connection: NWConnection) {
        self.connection = connection
    }

    public static func connect(host: String, port: UInt16, path: String = "/acp", timeout: TimeInterval = 10) async throws -> ACPWebSocketConnection {
        let ws = NWProtocolWebSocket.Options()
        ws.autoReplyPing = true
        let params = NWParameters.tcp
        params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)
        let pathPart = path.hasPrefix("/") ? path : "/\(path)"
        guard let url = URL(string: "ws://\(host):\(port)\(pathPart)") else {
            throw ACPSessionError("unavailable", "invalid websocket url")
        }
        // Network.framework completes the HTTP upgrade only for URL endpoints.
        let conn = NWConnection(to: .url(url), using: params)
        let transport = ACPWebSocketConnection(connection: conn)
        try await transport.start(timeout: timeout)
        return transport
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
                throw ACPSessionError("timeout", "websocket connect timed out")
            }
            defer { group.cancelAll() }
            try await group.next()!
        }
    }

    public func send(_ data: Data, text: Bool) async throws {
        let meta = NWProtocolWebSocket.Metadata(opcode: text ? .text : .binary)
        let context = NWConnection.ContentContext(identifier: "acp", metadata: [meta])
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, contentContext: context, isComplete: true, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    public func recv() async throws -> (Data, Bool) {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<(Data, Bool), Error>) in
            connection.receiveMessage { data, context, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                    return
                }
                let ws = context?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
                if ws?.opcode == .close {
                    cont.resume(throwing: ACPSessionError("unavailable", "websocket peer closed the connection"))
                    return
                }
                guard isComplete else {
                    cont.resume(throwing: ACPSessionError("unavailable", "incomplete websocket message"))
                    return
                }
                guard let data, !data.isEmpty else {
                    cont.resume(throwing: ACPSessionError("unavailable", "empty websocket message"))
                    return
                }
                let text = ws?.opcode == .text
                cont.resume(returning: (data, text))
            }
        }
    }

    public func close() async {
        connection.cancel()
    }
}

public actor ACPWebSocketListener {
    private let listener: NWListener
    private var waiters: [UUID: CheckedContinuation<ACPWebSocketConnection, Error>] = [:]
    private var waiterOrder: [UUID] = []
    private var pending: [ACPWebSocketConnection] = []
    private var stopped = false
    private var used = false

    public init(
        port: UInt16,
        loopbackOnly: Bool = false,
        bonjour: ACPBonjourAdvertisement? = nil
    ) throws {
        let ws = NWProtocolWebSocket.Options()
        ws.autoReplyPing = true
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.includePeerToPeer = false
        params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)
        let nwPort = NWEndpoint.Port(rawValue: port)!
        if loopbackOnly {
            // Bind 127.0.0.1 so "This Mac only" is a real local socket, not ACPLoopback.
            params.acceptLocalOnly = true
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: nwPort)
            listener = try NWListener(using: params)
        } else {
            listener = try NWListener(using: params, on: nwPort)
        }
        if let bonjour {
            let values = bonjour.txtRecord.mapValues { Data($0.utf8) }
            listener.service = NWListener.Service(
                name: bonjour.name,
                type: bonjour.type,
                domain: bonjour.domain,
                txtRecord: NetService.data(fromTXTRecord: values)
            )
        }
    }

    public var port: UInt16? {
        listener.port?.rawValue
    }

    public func start(timeout: TimeInterval = 10) async throws {
        guard timeout.isFinite, timeout > 0 else {
            throw ACPSessionError("invalid_range", "websocket listener timeout must be positive and finite")
        }
        guard !used else {
            throw ACPSessionError("conflict", "websocket listener instances are one-shot")
        }
        used = true
        stopped = false
        let listener = self.listener
        listener.newConnectionHandler = { conn in
            Task { await self.offer(ACPWebSocketConnection(connection: conn)) }
        }
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    let box = ResumeBox()
                    listener.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            listener.stateUpdateHandler = nil
                            box.resume { cont.resume() }
                        case .failed(let err):
                            box.resume { cont.resume(throwing: err) }
                        case .cancelled:
                            box.resume { cont.resume(throwing: ACPSessionError("unavailable", "listener cancelled")) }
                        default:
                            break
                        }
                    }
                    listener.start(queue: .global())
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: Self.nanoseconds(timeout))
                listener.cancel()
                throw ACPSessionError("timeout", "websocket listener start timed out")
            }
            defer { group.cancelAll() }
            try await group.next()!
        }
    }

    public func accept(timeout: TimeInterval? = 10) async throws -> ACPWebSocketConnection {
        if stopped { throw ACPSessionError("unavailable", "listener stopped") }
        if !pending.isEmpty { return pending.removeFirst() }
        if let timeout {
            guard timeout.isFinite, timeout > 0 else {
                throw ACPSessionError("invalid_range", "websocket accept timeout must be positive and finite")
            }
            let id = UUID()
            return try await withThrowingTaskGroup(of: ACPWebSocketConnection.self) { group in
                group.addTask {
                    try await self.waitForConnection(id: id)
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: Self.nanoseconds(timeout))
                    throw ACPSessionError("timeout", "websocket accept timed out")
                }
                defer { group.cancelAll() }
                return try await group.next()!
            }
        }
        return try await waitForConnection(id: UUID())
    }

    public func stop() async {
        used = true
        stopped = true
        listener.cancel()
        for waiter in waiters.values {
            waiter.resume(throwing: ACPSessionError("unavailable", "listener stopped"))
        }
        waiters.removeAll()
        waiterOrder.removeAll()
        let abandoned = pending
        pending.removeAll()
        for connection in abandoned { await connection.close() }
    }

    private func offer(_ conn: ACPWebSocketConnection) async {
        if stopped {
            await conn.close()
            return
        }
        do {
            try await conn.start(timeout: 10)
        } catch {
            await conn.close()
            return
        }
        if stopped {
            await conn.close()
            return
        }
        while let id = waiterOrder.first {
            waiterOrder.removeFirst()
            if let waiter = waiters.removeValue(forKey: id) {
                waiter.resume(returning: conn)
                return
            }
        }
        pending.append(conn)
    }

    private func waitForConnection(id: UUID) async throws -> ACPWebSocketConnection {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<ACPWebSocketConnection, Error>) in
                if stopped {
                    cont.resume(throwing: ACPSessionError("unavailable", "listener stopped"))
                } else if !pending.isEmpty {
                    cont.resume(returning: pending.removeFirst())
                } else {
                    waiters[id] = cont
                    waiterOrder.append(id)
                }
            }
        } onCancel: {
            Task { await self.cancelWaiter(id: id) }
        }
    }

    private func cancelWaiter(id: UUID) {
        waiterOrder.removeAll { $0 == id }
        waiters.removeValue(forKey: id)?.resume(throwing: CancellationError())
    }

    private static func nanoseconds(_ timeout: TimeInterval) -> UInt64 {
        let scaled = timeout * 1_000_000_000
        return UInt64(min(scaled, Double(UInt64.max)))
    }

}
