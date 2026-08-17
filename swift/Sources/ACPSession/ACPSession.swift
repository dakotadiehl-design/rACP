/// Full-profile ACP session engine: handshake, admission, sequencing, loopback.
import Foundation
import ACPModel
import ACPEncoding

public enum ACPSessionState: Sendable {
    case closed, connecting, helloSent, established, goodbyeSent, failed
}

public struct ACPSessionError: Error, Sendable {
    public var code: String
    public var message: String
    public init(_ code: String, _ message: String) {
        self.code = code
        self.message = message
    }
}

public struct ACPIdentity: Sendable {
    public var nodeID: String
    public var instanceID: String
    public var role: String
    public var name: String
    public init(nodeID: String = UUID().uuidString.lowercased(), instanceID: String = UUID().uuidString.lowercased(), role: String, name: String) {
        self.nodeID = nodeID
        self.instanceID = instanceID
        self.role = role
        self.name = name
    }
}

public actor ACPLoopback {
    private var peer: ACPLoopback?
    private var queue: [Data] = []
    private var waiters: [CheckedContinuation<Data, Error>] = []
    private var closed = false

    public init() {}

    public func attach(_ other: ACPLoopback) {
        peer = other
    }

    public func send(_ data: Data) async throws {
        guard !closed, let peer else { throw ACPSessionError("unavailable", "closed") }
        await peer.deliver(data)
    }

    func deliver(_ data: Data) {
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.resume(returning: data)
        } else {
            queue.append(data)
        }
    }

    public func recv() async throws -> Data {
        if closed { throw ACPSessionError("unavailable", "eof") }
        if !queue.isEmpty { return queue.removeFirst() }
        return try await withCheckedThrowingContinuation { cont in
            waiters.append(cont)
        }
    }

    public func close() {
        closed = true
        for w in waiters { w.resume(throwing: ACPSessionError("unavailable", "eof")) }
        waiters.removeAll()
    }
}

public actor ACPSession {
    public var state: ACPSessionState = .closed
    public var sessionID: String?
    public var sessionVersion: String = "1.2"
    public var encoding: String = "cbor"
    public var peer: ACPIdentity?
    public var allowPlaintext: Bool = true
    public let local: ACPIdentity
    public let isServer: Bool
    private let transport: ACPLoopback
    private var nextSequence: UInt64 = 0
    private var lastRx: UInt64?
    private var gapCount: UInt32 = 0
    private var inbox: [ACPEnvelope] = []
    private var encodings = ["cbor", "json"]

    public init(transport: ACPLoopback, local: ACPIdentity, isServer: Bool) {
        self.transport = transport
        self.local = local
        self.isServer = isServer
    }

    public func handshake() async throws -> ACPEnvelope {
        if !allowPlaintext { throw ACPSessionError("authentication", "trusted_lan requires allow_plaintext") }
        state = .connecting
        if isServer {
            let hello = try await waitType("session.hello")
            return try await acceptHello(hello)
        }
        let hello = makeHello()
        _ = try await transmit(hello, established: false)
        state = .helloSent
        let ack = try await waitType("session.hello_ack")
        try applyHelloAck(ack)
        return ack
    }

    public func goodbye() async {
        if state == .established {
            state = .goodbyeSent
            let env = ACPEnvelope(
                acp: "1.2",
                messageID: UUID().uuidString.lowercased(),
                type: "session.goodbye",
                source: ACPEndpoint(nodeID: local.nodeID),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .bestEffort,
                payload: ["reason": .string("shutdown")]
            )
            _ = try? await transmit(env, established: true)
        }
        state = .closed
        await transport.close()
    }

    public func pumpOnce() async throws -> ACPEnvelope? {
        let data = try await transport.recv()
        let env = try ACPEncoding.decodeCBOR(data)
        if let err = admit(env) {
            throw ACPSessionError(err, "inbound rejected \(env.type)")
        }
        if state == .established {
            try checkSequence(env)
        }
        if env.type == "session.goodbye" { state = .closed }
        inbox.append(env)
        return env
    }

    private func waitType(_ type: String) async throws -> ACPEnvelope {
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if let idx = inbox.firstIndex(where: { $0.type == type }) {
                return inbox.remove(at: idx)
            }
            if let env = try await pumpOnce(), env.type == type { return env }
        }
        throw ACPSessionError("timeout", "waiting for \(type)")
    }

    private func makeHello() -> ACPEnvelope {
        ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "session.hello",
            source: ACPEndpoint(nodeID: local.nodeID),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "node": .object([
                    "node_id": .string(local.nodeID),
                    "instance_id": .string(local.instanceID),
                    "role": .string(local.role),
                    "name": .string(local.name),
                ]),
                "protocol": .object(["min": .string("1.0"), "max": .string("1.2")]),
                "encodings": .array(encodings.map { .string($0) }),
                "profiles": .array([.string("core")]),
                "capabilities": .array([]),
                "auth": .object(["mode": .string("trusted_lan")]),
            ]
        )
    }

    private func acceptHello(_ hello: ACPEnvelope) async throws -> ACPEnvelope {
        guard case .object(let node) = hello.payload["node"],
              case .string(let nid) = node["node_id"],
              case .string(let iid) = node["instance_id"],
              case .string(let role) = node["role"],
              case .string(let name) = node["name"]
        else { throw ACPSessionError("authentication", "missing node") }
        if hello.source.nodeID != nid {
            throw ACPSessionError("authentication", "HELLO source mismatch")
        }
        peer = ACPIdentity(nodeID: nid, instanceID: iid, role: role, name: name)
        let sid = UUID().uuidString.lowercased()
        sessionID = sid
        sessionVersion = "1.2"
        encoding = "cbor"
        nextSequence = 0
        lastRx = nil
        gapCount = 0
        state = .established
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "session.hello_ack",
            source: ACPEndpoint(nodeID: local.nodeID),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "accepted": .bool(true),
                "protocol": .string("1.2"),
                "encoding": .string("cbor"),
                "session_id": .string(sid),
                "heartbeat_interval_ms": .int(1000),
                "node": .object([
                    "node_id": .string(local.nodeID),
                    "instance_id": .string(local.instanceID),
                    "role": .string(local.role),
                    "name": .string(local.name),
                ]),
                "peer_capabilities": .array([]),
                "limits": .object(["max_message_bytes": .int(1_048_576)]),
            ]
        )
        _ = try await transmit(ack, established: false)
        return ack
    }

    public func applyHelloAck(_ env: ACPEnvelope) throws {
        guard case .bool(true) = env.payload["accepted"] else {
            state = .failed
            throw ACPSessionError("unsupported_version", "rejected")
        }
        guard case .string(let s) = env.payload["session_id"], !s.isEmpty else {
            state = .failed
            throw ACPSessionError("malformed_envelope", "session_id")
        }
        guard case .object(let node) = env.payload["node"],
              case .string(let nid) = node["node_id"],
              case .string(let role) = node["role"],
              case .string(let name) = node["name"],
              case .string(let iid) = node["instance_id"]
        else {
            state = .failed
            throw ACPSessionError("authentication", "hello_ack missing node")
        }
        if env.source.nodeID != nid {
            throw ACPSessionError("authentication", "ACK source mismatch")
        }
        sessionID = s
        peer = ACPIdentity(nodeID: nid, instanceID: iid, role: role, name: name)
        if case .string(let proto) = env.payload["protocol"] { sessionVersion = proto }
        if case .string(let enc) = env.payload["encoding"] { encoding = enc }
        nextSequence = 0
        lastRx = nil
        gapCount = 0
        state = .established
    }

    public func assignSequence(_ env: ACPEnvelope) throws -> ACPEnvelope {
        guard state == .established, let sid = sessionID else {
            throw ACPSessionError("internal", "not established")
        }
        nextSequence += 1
        var copy = env
        copy.sessionID = sid
        copy.sequence = nextSequence
        return copy
    }

    private func admit(_ env: ACPEnvelope) -> String? {
        if state != .established {
            if env.type != "session.hello" && env.type != "session.hello_ack" && env.type != "error.report" {
                return "malformed_envelope"
            }
            return nil
        }
        if env.sessionID != sessionID { return "malformed_envelope" }
        if (env.sequence ?? 0) < 1 { return "malformed_envelope" }
        if let peer, env.source.nodeID != peer.nodeID { return "authentication" }
        if peer == nil { return "authentication" }
        return nil
    }

    private func checkSequence(_ env: ACPEnvelope) throws {
        let seq = env.sequence ?? 0
        switch lastRx {
        case nil where seq == 1:
            lastRx = 1
        case nil where seq > 2:
            state = .failed
            throw ACPSessionError("protocol.sequence_gap", "first sequence is not 1")
        case nil:
            lastRx = seq
            gapCount += 1
        case let last? where seq <= last:
            break
        case let last? where seq == last + 1:
            lastRx = seq
        default:
            gapCount += 1
            lastRx = seq
            if gapCount >= 2 {
                state = .failed
                throw ACPSessionError("protocol.sequence_gap", "sequence gap reset")
            }
        }
    }

    private func transmit(_ env: ACPEnvelope, established: Bool) async throws -> ACPEnvelope {
        var env = env
        if established {
            env = try assignSequence(env)
        }
        let data = try ACPEncoding.encodeCBOR(env)
        try await transport.send(data)
        return env
    }
}

public func acpLinkedTransports() async -> (ACPLoopback, ACPLoopback) {
    let a = ACPLoopback()
    let b = ACPLoopback()
    await a.attach(b)
    await b.attach(a)
    return (a, b)
}
