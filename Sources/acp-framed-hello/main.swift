import Foundation
import Darwin
import AuroraACP

let args = CommandLine.arguments
if args.count < 4 {
    fputs("usage: acp-framed-hello <client|server> <host> <port> [--json] [--remote] [--session] [--xfer]\n", stderr)
    exit(2)
}
let mode = args[1]
let host = args[2]
let port = UInt16(args[3]) ?? 0
let json = args.contains("--json")
let remote = args.contains("--remote")
let sessionSuite = args.contains("--session")
let xfer = args.contains("--xfer")

func configure(_ session: ACPSession) async {
    if json { await session.setEncodings(["json"]) }
    if remote { await session.setProfiles(["core", "remote", "aurora.remote.prism.v1"]) }
}

func env(
    type: String,
    source: String,
    dest: String?,
    payload: [String: AnySendable],
    corr: String?,
    qos: ACPQoS = .reliable
) -> ACPEnvelope {
    ACPEnvelope(
        acp: "1.2",
        messageID: UUID().uuidString.lowercased(),
        type: type,
        source: ACPEndpoint(nodeID: source),
        destination: dest.map { ACPEndpoint(nodeID: $0) },
        timestampUTC: "2026-08-17T16:42:15.231Z",
        correlationID: corr,
        qos: qos,
        payload: payload
    )
}

func string(_ value: AnySendable?) -> String {
    if case .string(let s) = value { return s }
    return ""
}

func serveEstablished(_ session: ACPSession) async {
    while true {
        do {
            guard let inbound = try await session.pumpOnce() else { continue }
            let src = await session.local.nodeID
            switch inbound.type {
            case "session.goodbye":
                return
            case "state.request":
                _ = try? await session.send(env(
                    type: "state.snapshot", source: src, dest: inbound.source.nodeID,
                    payload: ["resources": .array([])], corr: inbound.correlationID ?? inbound.messageID
                ))
            case "resource.offer":
                _ = try? await session.send(env(
                    type: "resource.accept", source: src, dest: inbound.source.nodeID,
                    payload: ["transfer_id": .string(string(inbound.payload["transfer_id"])), "max_chunk_bytes": .int(1024)],
                    corr: inbound.correlationID ?? inbound.messageID
                ))
            case "resource.complete":
                _ = try? await session.send(env(
                    type: "resource.transfer_result", source: src, dest: inbound.source.nodeID,
                    payload: ["transfer_id": .string(string(inbound.payload["transfer_id"])), "status": .string("verified")],
                    corr: inbound.correlationID ?? inbound.messageID
                ))
            case "resource.activate":
                _ = try? await session.send(env(
                    type: "resource.activation_result", source: src, dest: inbound.source.nodeID,
                    payload: ["transfer_id": .string(string(inbound.payload["transfer_id"])), "status": .string("applied")],
                    corr: inbound.correlationID ?? inbound.messageID
                ))
            case "remote.control.invoke":
                _ = try? await session.send(env(
                    type: "command.ack", source: src, dest: inbound.source.nodeID,
                    payload: ["status": .string("applied")],
                    corr: inbound.correlationID ?? inbound.messageID
                ))
            default:
                break
            }
        } catch {
            return
        }
    }
}

func runSessionClient(_ session: ACPSession, xfer: Bool) async throws {
    let dest = await session.peer?.nodeID
    let src = await session.local.nodeID
    _ = try await session.send(env(
        type: "health.heartbeat", source: src, dest: nil,
        payload: ["uptime_ms": .int(1), "status": .string("ok")],
        corr: nil, qos: .latest
    ))
    let snap = try await session.request(env(
        type: "state.request", source: src, dest: dest,
        payload: ["resources": .array([])], corr: nil
    ))
    guard snap.type == "state.snapshot" else { throw ACPSessionError("internal", "expected snapshot") }
    if xfer {
        let tid = "0193f8d8-4c4e-7d8b-a2ab-000000000070"
        let aid = "0193f8d8-4c4e-7d8b-a2ab-000000000071"
        let sha = String(repeating: "a", count: 64)
        let accept = try await session.request(env(
            type: "resource.offer", source: src, dest: dest,
            payload: [
                "transfer_id": .string(tid),
                "asset": .object([
                    "asset_id": .string(aid),
                    "asset_type": .string("lyric.chart"),
                    "revision": .int(1),
                    "sha256": .string(sha),
                    "size_bytes": .int(4),
                ]),
                "locator": .object(["mode": .string("chunked")]),
            ], corr: nil
        ))
        guard accept.type == "resource.accept" else { throw ACPSessionError("internal", "expected accept") }
        _ = try await session.send(env(
            type: "resource.chunk", source: src, dest: dest,
            payload: [
                "transfer_id": .string(tid),
                "offset": .int(0),
                "length": .int(4),
                "data": .bytes(Data([0x00, 0x01, 0xFF, 0xE0])),
            ], corr: nil
        ))
        let done = try await session.request(env(
            type: "resource.complete", source: src, dest: dest,
            payload: ["transfer_id": .string(tid)], corr: nil
        ))
        guard done.type == "resource.transfer_result" else { throw ACPSessionError("internal", "expected result") }
        let act = try await session.request(env(
            type: "resource.activate", source: src, dest: dest,
            payload: ["transfer_id": .string(tid), "idempotency_key": .string(tid)], corr: nil
        ))
        guard act.type == "resource.activation_result" else { throw ACPSessionError("internal", "expected activation") }
        let ack = try await session.request(env(
            type: "remote.control.invoke", source: src, dest: dest,
            payload: [
                "control_id": .string("cue_go"),
                "invocation_id": .string(tid),
                "interaction": .string("activate"),
                "idempotency_key": .string(tid),
            ], corr: nil
        ))
        guard ack.type == "command.ack" else { throw ACPSessionError("internal", "expected ack") }
    }
}

func run() async {
    do {
        if mode == "client" {
            let transport = try await ACPFramedConnection.connect(host: host, port: port)
            let role = remote ? "remote" : "conductor"
            let session = ACPSession(transport: transport, local: ACPIdentity(role: role, name: "sw-client"), isServer: false, allowPlaintext: true)
            await configure(session)
            _ = try await session.handshake()
            print("ok client \(await session.sessionID ?? "") \(await session.sessionVersion) \(await session.encoding)")
            fflush(stdout)
            if sessionSuite || xfer {
                try await runSessionClient(session, xfer: xfer)
            }
            await session.goodbye()
        } else if mode == "server" {
            let listener = try ACPFramedListener(port: port)
            try await listener.start()
            print("listening \(host):\(await listener.port)")
            fflush(stdout)
            let transport = try await listener.accept()
            let role = remote ? "conductor" : "bridge"
            let session = ACPSession(transport: transport, local: ACPIdentity(role: role, name: "sw-server"), isServer: true, allowPlaintext: true)
            await configure(session)
            _ = try await session.handshake()
            print("ok server \(await session.sessionID ?? "") \(await session.sessionVersion) \(await session.encoding)")
            fflush(stdout)
            if sessionSuite || xfer {
                await serveEstablished(session)
            } else {
                await session.goodbye()
            }
            await listener.cancel()
        } else {
            fputs("mode must be client or server\n", stderr)
            exit(2)
        }
    } catch {
        fputs("error \(error)\n", stderr)
        exit(1)
    }
}

await run()
