import Foundation
import Network

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
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!)
        let conn = NWConnection(to: endpoint, using: params)
        let transport = ACPWebSocketConnection(connection: conn)
        try await transport.start(timeout: timeout)
        _ = path
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
            connection.receiveMessage { data, context, _, error in
                if let error {
                    cont.resume(throwing: error)
                    return
                }
                let ws = context?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata
                let text = ws?.opcode == .text
                cont.resume(returning: (data ?? Data(), text))
            }
        }
    }

    public func close() async {
        connection.cancel()
    }
}

public actor ACPWebSocketListener {
    private let listener: NWListener
    private var waiters: [CheckedContinuation<ACPWebSocketConnection, Error>] = []
    private var pending: [ACPWebSocketConnection] = []

    public init(port: UInt16) throws {
        let ws = NWProtocolWebSocket.Options()
        ws.autoReplyPing = true
        let params = NWParameters.tcp
        params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)
        listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
    }

    public func start() async throws {
        let listener = self.listener
        listener.newConnectionHandler = { conn in
            Task { await self.offer(ACPWebSocketConnection(connection: conn)) }
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let box = ResumeBox()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    box.resume { cont.resume() }
                case .failed(let err):
                    box.resume { cont.resume(throwing: err) }
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    public func accept(timeout: TimeInterval = 10) async throws -> ACPWebSocketConnection {
        if !pending.isEmpty { return pending.removeFirst() }
        return try await withThrowingTaskGroup(of: ACPWebSocketConnection.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<ACPWebSocketConnection, Error>) in
                    Task { await self.enqueue(cont) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw ACPSessionError("timeout", "websocket accept timed out")
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    public func stop() {
        listener.cancel()
        for waiter in waiters {
            waiter.resume(throwing: ACPSessionError("unavailable", "listener stopped"))
        }
        waiters.removeAll()
    }

    private func offer(_ conn: ACPWebSocketConnection) async {
        do {
            try await conn.start(timeout: 10)
        } catch {
            await conn.close()
            return
        }
        if !waiters.isEmpty {
            waiters.removeFirst().resume(returning: conn)
        } else {
            pending.append(conn)
        }
    }

    private func enqueue(_ cont: CheckedContinuation<ACPWebSocketConnection, Error>) {
        if !pending.isEmpty {
            cont.resume(returning: pending.removeFirst())
        } else {
            waiters.append(cont)
        }
    }
}
