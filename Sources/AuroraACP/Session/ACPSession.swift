/// Full-profile ACP session engine: handshake, admission, sequencing.
import Foundation

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

public struct ACPCapability: Sendable {
    public var id: String
    public var version: String
    public init(id: String, version: String) {
        self.id = id
        self.version = version
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
    public var profiles: [String] = ["core"]
    public var encodings = ["cbor", "json"]
    public var protocolMin = "1.0"
    public var protocolMax = "1.2"
    public var capabilities: [ACPCapability] = ACPSession.defaultCapabilities
    public var negotiatedProfiles: [String] = []
    public var negotiatedCapabilities: [String] = []
    public var negotiatedVersions: [String: String] = [:]
    public var handshakeTimeout: TimeInterval = 5
    private let transport: any ACPTransport
    private var nextSequence: UInt64 = 0
    private var lastRx: UInt64?
    private var gapCount: UInt32 = 0
    private var inbox: [ACPEnvelope] = []

    public static let defaultCapabilities: [ACPCapability] = [
        ACPCapability(id: "health.heartbeat", version: "1.0"),
        ACPCapability(id: "prism.cue_control", version: "1.0"),
        ACPCapability(id: "bridge.blackout", version: "1.0"),
        ACPCapability(id: "bridge.config", version: "1.0"),
        ACPCapability(id: "resource.transfer", version: "1.2"),
        ACPCapability(id: "remote.profile", version: "1.0"),
        ACPCapability(id: "remote.control.invoke", version: "1.0"),
        ACPCapability(id: "remote.control.momentary", version: "1.0"),
    ]

    public init(transport: any ACPTransport, local: ACPIdentity, isServer: Bool) {
        self.transport = transport
        self.local = local
        self.isServer = isServer
    }

    public func setEncodings(_ value: [String]) { encodings = value }
    public func setProfiles(_ value: [String]) { profiles = value }
    public func setCapabilities(_ value: [ACPCapability]) { capabilities = value }
    public func setHandshakeTimeout(_ value: TimeInterval) { handshakeTimeout = value }
    public func setProtocolRange(min: String, max: String) {
        protocolMin = min
        protocolMax = max
    }

    public func handshake() async throws -> ACPEnvelope {
        do {
            if !allowPlaintext { throw ACPSessionError("authentication", "trusted_lan requires allow_plaintext") }
            state = .connecting
            if isServer {
                let hello = try await waitType("session.hello", timeout: handshakeTimeout)
                return try await acceptHello(hello)
            }
            let hello = makeHello()
            _ = try await transmit(hello, established: false)
            state = .helloSent
            let ack = try await waitType("session.hello_ack", timeout: handshakeTimeout)
            try applyHelloAck(ack)
            return ack
        } catch {
            await failClose(code: (error as? ACPSessionError)?.code ?? "timeout", message: "\(error)")
            throw error
        }
    }

    public func goodbye() async {
        if state == .established {
            state = .goodbyeSent
            let env = ACPEnvelope(
                acp: sessionVersion,
                messageID: UUID().uuidString.lowercased(),
                type: "session.goodbye",
                source: ACPEndpoint(nodeID: local.nodeID),
                timestampUTC: "2026-08-17T16:42:15.231Z",
                qos: .bestEffort,
                payload: ["reason": .string("shutdown")]
            )
            _ = try? await transmit(env, established: true)
        }
        if state != .failed { state = .closed }
        await transport.close()
    }

    public func pumpOnce(deadline: Date? = nil) async throws -> ACPEnvelope? {
        let remaining = deadline.map { $0.timeIntervalSinceNow } ?? handshakeTimeout
        let (data, text) = try await recvBounded(remaining)
        let env: ACPEnvelope
        do {
            env = text ? try ACPEncoding.decodeJSON(data) : try ACPEncoding.decodeCBOR(data)
        } catch {
            await failClose(code: "malformed_envelope", message: "\(error)")
            throw ACPSessionError("malformed_envelope", "\(error)")
        }
        if let err = admit(env) {
            let fatal = ["malformed_envelope", "authentication", "protocol.sequence_gap", "unsupported_message"]
            if fatal.contains(err) {
                await failClose(code: err, message: "inbound rejected \(env.type)")
                throw ACPSessionError(err, "inbound rejected \(env.type)")
            }
            return nil
        }
        if state == .established {
            do {
                try checkSequence(env)
            } catch {
                await failClose(
                    code: (error as? ACPSessionError)?.code ?? "protocol.sequence_gap",
                    message: "\(error)"
                )
                throw error
            }
        }
        if env.type == "session.goodbye" { state = .closed }
        inbox.append(env)
        return env
    }

    public func send(_ env: ACPEnvelope) async throws -> ACPEnvelope {
        try await transmit(env, established: state == .established)
    }

    public func request(_ env: ACPEnvelope, timeout: TimeInterval = 5) async throws -> ACPEnvelope {
        var env = env
        if env.correlationID == nil { env.correlationID = env.messageID }
        _ = try await send(env)
        let deadline = Date().addingTimeInterval(timeout)
        let corr = env.correlationID
        let expected = ACPRegistry.responseType(for: env.type)
        do {
            while Date() < deadline {
                if let idx = inbox.firstIndex(where: {
                    $0.correlationID == corr && ($0.type == expected || $0.type == "error.report")
                }) {
                    return inbox.remove(at: idx)
                }
                _ = try await pumpOnce(deadline: deadline)
            }
            throw ACPSessionError("timeout", "request timed out")
        } catch let err as ACPSessionError where err.code == "timeout" {
            await failClose(code: "timeout", message: err.message)
            throw err
        }
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

    private func waitType(_ type: String, timeout: TimeInterval) async throws -> ACPEnvelope {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let idx = inbox.firstIndex(where: { $0.type == type }) {
                return inbox.remove(at: idx)
            }
            if let env = try await pumpOnce(deadline: deadline), env.type == type { return env }
        }
        throw ACPSessionError("timeout", "waiting for \(type)")
    }

    private func recvBounded(_ seconds: TimeInterval) async throws -> (Data, Bool) {
        if seconds <= 0 { throw ACPSessionError("timeout", "recv timed out") }
        do {
            return try await withThrowingTaskGroup(of: (Data, Bool).self) { group in
                group.addTask { try await self.transport.recv() }
                group.addTask {
                    let ns = UInt64(max(seconds, 0.01) * 1_000_000_000)
                    try await Task.sleep(nanoseconds: ns)
                    throw ACPSessionError("timeout", "recv timed out")
                }
                defer { group.cancelAll() }
                return try await group.next()!
            }
        } catch let err as ACPSessionError where err.code == "timeout" {
            throw err
        }
    }

    private func failClose(code: String, message: String) async {
        state = .failed
        _ = code
        _ = message
        await transport.close()
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
                "protocol": .object(["min": .string(protocolMin), "max": .string(protocolMax)]),
                "encodings": .array(encodings.map { .string($0) }),
                "profiles": .array(profiles.map { .string($0) }),
                "capabilities": .array(capabilities.map {
                    .object(["id": .string($0.id), "version": .string($0.version)])
                }),
                "auth": .object(["mode": .string("trusted_lan")]),
            ]
        )
    }

    private func rejectHello(_ error: ACPSessionError) async {
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "session.hello_ack",
            source: ACPEndpoint(nodeID: local.nodeID),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "accepted": .bool(false),
                "protocol": .string(protocolMax),
                "encoding": .string(encodings.first ?? "cbor"),
                "session_id": .string(UUID().uuidString.lowercased()),
                "heartbeat_interval_ms": .int(1000),
                "node": .object([
                    "node_id": .string(local.nodeID),
                    "instance_id": .string(local.instanceID),
                    "role": .string(local.role),
                    "name": .string(local.name),
                ]),
                "peer_capabilities": .array([]),
                "limits": .object(["max_message_bytes": .int(1_048_576)]),
                "error": .object([
                    "code": .string(error.code),
                    "category": .string("protocol"),
                    "severity": .string("error"),
                    "message": .string(error.message),
                    "retryable": .bool(false),
                ]),
            ]
        )
        _ = try? await transmit(ack, established: false)
    }

    private func acceptHello(_ hello: ACPEnvelope) async throws -> ACPEnvelope {
        do {
            return try await acceptHelloValidated(hello)
        } catch let err as ACPSessionError {
            await rejectHello(err)
            throw err
        }
    }

    private func acceptHelloValidated(_ hello: ACPEnvelope) async throws -> ACPEnvelope {
        guard case .object(let node) = hello.payload["node"],
              case .string(let nid) = node["node_id"],
              case .string(let iid) = node["instance_id"],
              case .string(let role) = node["role"],
              case .string(let name) = node["name"]
        else { throw ACPSessionError("authentication", "missing node") }
        if hello.source.nodeID != nid {
            throw ACPSessionError("authentication", "HELLO source mismatch")
        }
        guard case .object(let proto) = hello.payload["protocol"],
              case .string(let pmin) = proto["min"],
              case .string(let pmax) = proto["max"]
        else { throw ACPSessionError("malformed_envelope", "missing protocol range") }
        let selected = try ACPNegotiate.selectVersion(
            clientMin: pmin, clientMax: pmax, serverMin: protocolMin, serverMax: protocolMax
        )
        let encoding = try ACPNegotiate.selectEncoding(client: strings(hello.payload["encodings"]), server: encodings)
        let negotiated = intersectCapabilities(hello)
        let negotiatedProfiles = intersectProfiles(hello)
        let sid = UUID().uuidString.lowercased()
        let ack = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "session.hello_ack",
            source: ACPEndpoint(nodeID: local.nodeID),
            timestampUTC: "2026-08-17T16:42:15.231Z",
            qos: .reliable,
            payload: [
                "accepted": .bool(true),
                "protocol": .string(selected),
                "encoding": .string(encoding),
                "session_id": .string(sid),
                "heartbeat_interval_ms": .int(1000),
                "node": .object([
                    "node_id": .string(local.nodeID),
                    "instance_id": .string(local.instanceID),
                    "role": .string(local.role),
                    "name": .string(local.name),
                ]),
                "peer_capabilities": .array(negotiated.map {
                    .object(["id": .string($0.id), "version": .string($0.version)])
                }),
                "profiles": .array(negotiatedProfiles.map { .string($0) }),
                "limits": .object(["max_message_bytes": .int(1_048_576)]),
            ]
        )
        _ = try await transmit(ack, established: false)
        peer = ACPIdentity(nodeID: nid, instanceID: iid, role: role, name: name)
        sessionID = sid
        sessionVersion = selected
        self.encoding = encoding
        negotiatedCapabilities = negotiated.map(\.id)
        negotiatedVersions = Dictionary(uniqueKeysWithValues: negotiated.map { ($0.id, $0.version) })
        self.negotiatedProfiles = negotiatedProfiles
        nextSequence = 0
        lastRx = nil
        gapCount = 0
        state = .established
        return ack
    }

    public func applyHelloAck(_ env: ACPEnvelope) throws {
        do {
            try applyHelloAckValidated(env)
        } catch {
            state = .failed
            throw error
        }
    }

    private func applyHelloAckValidated(_ env: ACPEnvelope) throws {
        guard case .bool(true) = env.payload["accepted"] else {
            throw ACPSessionError("unsupported_version", "rejected")
        }
        guard case .string(let s) = env.payload["session_id"], !s.isEmpty else {
            throw ACPSessionError("malformed_envelope", "session_id")
        }
        guard case .string(let proto) = env.payload["protocol"] else {
            throw ACPSessionError("malformed_envelope", "missing protocol")
        }
        guard ACPNegotiate.versionLeq(protocolMin, proto), ACPNegotiate.versionLeq(proto, protocolMax) else {
            throw ACPSessionError("malformed_envelope", "protocol outside offer")
        }
        guard case .string(let enc) = env.payload["encoding"] else {
            throw ACPSessionError("malformed_envelope", "missing encoding")
        }
        guard encodings.contains(enc) else {
            throw ACPSessionError("malformed_envelope", "encoding not offered")
        }
        let heartbeat: Int
        if case .int(let hb) = env.payload["heartbeat_interval_ms"] {
            heartbeat = Int(hb)
        } else if case .uint(let hb) = env.payload["heartbeat_interval_ms"] {
            heartbeat = Int(hb)
        } else {
            throw ACPSessionError("malformed_envelope", "missing heartbeat_interval_ms")
        }
        _ = try ACPNegotiate.validateHeartbeat(heartbeat)
        guard case .array = env.payload["peer_capabilities"] else {
            throw ACPSessionError("malformed_envelope", "missing peer_capabilities")
        }
        guard case .object(let limits) = env.payload["limits"] else {
            throw ACPSessionError("malformed_envelope", "missing limits")
        }
        let maxBytes: Int
        if case .int(let n) = limits["max_message_bytes"] { maxBytes = Int(n) }
        else if case .uint(let n) = limits["max_message_bytes"] { maxBytes = Int(n) }
        else { throw ACPSessionError("malformed_envelope", "missing max_message_bytes") }
        _ = try ACPNegotiate.validateMaxMessageBytes(maxBytes)
        guard case .object(let node) = env.payload["node"],
              case .string(let nid) = node["node_id"],
              case .string(let role) = node["role"],
              case .string(let name) = node["name"],
              case .string(let iid) = node["instance_id"]
        else {
            throw ACPSessionError("authentication", "hello_ack missing node")
        }
        if env.source.nodeID != nid {
            throw ACPSessionError("authentication", "ACK source mismatch")
        }
        if case .array(let offered) = env.payload["profiles"] {
            let names = offered.compactMap { if case .string(let s) = $0 { return s }; return nil }
            if names.contains(where: { !profiles.contains($0) }) {
                throw ACPSessionError("malformed_envelope", "ACK profile not offered")
            }
            negotiatedProfiles = profiles.filter { names.contains($0) }
        } else {
            throw ACPSessionError("malformed_envelope", "missing profiles")
        }
        sessionID = s
        peer = ACPIdentity(nodeID: nid, instanceID: iid, role: role, name: name)
        sessionVersion = proto
        encoding = enc
        let caps = capabilitiesFrom(env.payload["peer_capabilities"])
        negotiatedVersions = Dictionary(uniqueKeysWithValues: caps.map { ($0.id, $0.version) })
        negotiatedCapabilities = caps.map(\.id)
        nextSequence = 0
        lastRx = nil
        gapCount = 0
        state = .established
    }

    private func admit(_ env: ACPEnvelope) -> String? {
        let established = state == .established
        if !established {
            if isServer && env.type != "session.hello" && env.type != "error.report" {
                return "malformed_envelope"
            }
            var role = local.role
            if case .object(let node) = env.payload["node"], case .string(let r) = node["role"] {
                role = r
            }
            return ACPRegistry.allowed(
                type: env.type,
                senderRole: role,
                negotiated: [],
                handshakeComplete: false,
                qos: env.qos.rawValue,
                envelopeVersion: env.acp,
                negotiatedVersions: [:]
            )
        }
        if env.sessionID != sessionID { return "malformed_envelope" }
        if (env.sequence ?? 0) < 1 { return "malformed_envelope" }
        guard let peer else { return "authentication" }
        if env.source.nodeID != peer.nodeID { return "authentication" }
        return ACPRegistry.allowed(
            type: env.type,
            senderRole: peer.role,
            negotiated: negotiatedCapabilities,
            handshakeComplete: true,
            qos: env.qos.rawValue,
            envelopeVersion: env.acp,
            negotiatedVersions: negotiatedVersions
        )
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
            if let err = ACPRegistry.allowed(
                type: env.type,
                senderRole: local.role,
                negotiated: negotiatedCapabilities,
                handshakeComplete: true,
                qos: env.qos.rawValue,
                envelopeVersion: env.acp,
                negotiatedVersions: negotiatedVersions
            ) {
                throw ACPSessionError(err, "not allowed to send \(env.type)")
            }
            env = try assignSequence(env)
        }
        let data = encoding == "json" ? try ACPEncoding.encodeJSON(env) : try ACPEncoding.encodeCBOR(env)
        try await transport.send(data, text: encoding == "json")
        return env
    }

    private func strings(_ value: AnySendable?) -> [String] {
        guard case .array(let items) = value else { return [] }
        return items.compactMap { if case .string(let s) = $0 { return s }; return nil }
    }

    private func intersectProfiles(_ hello: ACPEnvelope) -> [String] {
        let offered = strings(hello.payload["profiles"])
        return profiles.filter { offered.contains($0) }
    }

    private func capabilitiesFrom(_ value: AnySendable?) -> [ACPCapability] {
        guard case .array(let items) = value else { return [] }
        return items.compactMap { item in
            guard case .object(let o) = item,
                  case .string(let id) = o["id"],
                  case .string(let ver) = o["version"] else { return nil }
            return ACPCapability(id: id, version: ver)
        }
    }

    private func intersectCapabilities(_ hello: ACPEnvelope) -> [ACPCapability] {
        let peer = capabilitiesFrom(hello.payload["capabilities"])
        var out: [ACPCapability] = []
        for cap in capabilities {
            guard let other = peer.first(where: { $0.id == cap.id }) else { continue }
            guard let lv = ACPNegotiate.parseVersion(cap.version),
                  let ov = ACPNegotiate.parseVersion(other.version),
                  lv.0 == ov.0 else { continue }
            out.append(ACPCapability(id: cap.id, version: lv <= ov ? cap.version : other.version))
        }
        return out
    }
}
