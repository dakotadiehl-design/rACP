import Foundation

public enum ACPCodecError: Error {
    case malformed(String)
}

public enum ACPEncoding {
    public static func encodeJSON(_ env: ACPEnvelope) throws -> Data {
        var env = env
        env.payload = try normalizeSecurityBytes(
            type: env.type, payload: env.payload, toCBOR: false)
        let obj = envelopeObject(env)
        return try JSONSerialization.data(withJSONObject: ns(obj), options: [.sortedKeys])
    }

    public static func decodeJSON(_ data: Data) throws -> ACPEnvelope {
        guard data.count <= 8 * 1024 * 1024 else { throw ACPCodecError.malformed("message too large") }
        let raw = try JSONSerialization.jsonObject(with: data)
        guard let dict = raw as? [String: Any] else {
            throw ACPCodecError.malformed("envelope")
        }
        try ACPSchema.validateEnvelopeObject(dict)
        var envelope = try envelope(from: fromNS(dict), securityBytesFromCBOR: false)
        envelope.payload = try normalizeSecurityBytes(
            type: envelope.type, payload: envelope.payload, toCBOR: true)
        return envelope
    }

    public static func encodeCBOR(_ env: ACPEnvelope) throws -> Data {
        var env = env
        env.payload = try normalizeChunk(type: env.type, payload: env.payload)
        env.payload = try normalizeSecurityBytes(type: env.type, payload: env.payload, toCBOR: true)
        return try encodeValue(cborReady(envelopeObject(env)))
    }

    public static func decodeCBOR(_ data: Data) throws -> ACPEnvelope {
        guard data.count <= 8 * 1024 * 1024 else { throw ACPCodecError.malformed("message too large") }
        let value = try decodeValue(data)
        let env = try envelope(from: value, securityBytesFromCBOR: false)
        var schemaEnvelope = env
        schemaEnvelope.payload = try normalizeSecurityBytes(
            type: env.type, payload: env.payload, toCBOR: false)
        guard let dict = ns(envelopeObject(schemaEnvelope)) as? [String: Any] else {
            throw ACPCodecError.malformed("envelope")
        }
        try ACPSchema.validateEnvelopeObject(dict)
        return env
    }

    static func envelopeObject(_ env: ACPEnvelope) -> AnySendable {
        var obj: [String: AnySendable] = [
            "acp": .string(env.acp),
            "message_id": .string(env.messageID),
            "type": .string(env.type),
            "source": endpointObject(env.source),
            "timestamp_utc": .string(env.timestampUTC),
            "qos": .string(env.qos.rawValue),
            "flags": .array(env.flags.sorted().map(AnySendable.string)),
            "payload": .object(env.payload),
        ]
        if let d = env.destination { obj["destination"] = endpointObject(d) }
        if let s = env.sessionID { obj["session_id"] = .string(s) }
        if let seq = env.sequence { obj["sequence"] = .uint(seq) }
        if let c = env.correlationID { obj["correlation_id"] = .string(c) }
        if let c = env.causationID { obj["causation_id"] = .string(c) }
        return .object(obj)
    }

    static func endpointObject(_ ep: ACPEndpoint) -> AnySendable {
        var o: [String: AnySendable] = ["node_id": .string(ep.nodeID)]
        if let c = ep.componentID { o["component_id"] = .string(c) }
        return .object(o)
    }

    static func envelope(from value: AnySendable, securityBytesFromCBOR: Bool) throws -> ACPEnvelope {
        guard case .object(let o) = value else { throw ACPCodecError.malformed("object") }
        func str(_ k: String) throws -> String {
            if case .string(let s) = o[k] { return s }
            throw ACPCodecError.malformed(k)
        }
        func ep(_ k: String) throws -> ACPEndpoint {
            guard case .object(let e) = o[k] else { throw ACPCodecError.malformed(k) }
            guard case .string(let id) = e["node_id"] else { throw ACPCodecError.malformed("node_id") }
            var comp: String?
            if case .string(let c) = e["component_id"] { comp = c }
            return ACPEndpoint(nodeID: id, componentID: comp)
        }
        var flags: [String] = []
        if case .array(let a) = o["flags"] {
            flags = a.compactMap { if case .string(let s) = $0 { return s }; return nil }
        }
        var seq: UInt64?
        if case .uint(let u) = o["sequence"] { seq = u }
        if case .int(let i) = o["sequence"], i >= 0 { seq = UInt64(i) }
        var dest: ACPEndpoint?
        if o["destination"] != nil { dest = try ep("destination") }
        var payload: [String: AnySendable] = [:]
        if case .object(let p) = o["payload"] { payload = p }
        let messageType = try str("type")
        payload = try normalizeChunk(type: messageType, payload: payload)
        if securityBytesFromCBOR {
            payload = try normalizeSecurityBytes(type: messageType, payload: payload, toCBOR: false)
        }
        return ACPEnvelope(
            acp: try str("acp"),
            messageID: try str("message_id"),
            type: try str("type"),
            source: try ep("source"),
            destination: dest,
            sessionID: { if case .string(let s) = o["session_id"] { return s }; return nil }(),
            sequence: seq,
            timestampUTC: try str("timestamp_utc"),
            correlationID: { if case .string(let s) = o["correlation_id"] { return s }; return nil }(),
            causationID: { if case .string(let s) = o["causation_id"] { return s }; return nil }(),
            qos: ACPQoS(rawValue: try str("qos")) ?? .reliable,
            flags: flags,
            payload: payload
        )
    }

    static func normalizeChunk(type: String, payload: [String: AnySendable]) throws -> [String: AnySendable] {
        guard type == "resource.chunk" else { return payload }
        var payload = payload
        guard let data = payload["data"] else { return payload }
        let bytes: Data
        switch data {
        case .string(let s):
            guard let decoded = Data(base64Encoded: s) else {
                throw ACPCodecError.malformed("invalid resource.chunk base64")
            }
            bytes = decoded
        case .bytes(let b):
            bytes = b
        default:
            throw ACPCodecError.malformed("resource.chunk data")
        }
        if case .uint(let n) = payload["length"], n != UInt64(bytes.count) {
            throw ACPCodecError.malformed("resource.chunk length does not match decoded bytes")
        }
        if case .int(let n) = payload["length"], n >= 0, UInt64(n) != UInt64(bytes.count) {
            throw ACPCodecError.malformed("resource.chunk length does not match decoded bytes")
        }
        payload["data"] = .bytes(bytes)
        return payload
    }

    static func normalizeSecurityBytes(
        type: String, payload: [String: AnySendable], toCBOR: Bool
    ) throws -> [String: AnySendable] {
        var payload = payload
        for path in ACPSecurityCatalog.binaryFields(messageType: type) {
            try transformSecurityPath(&payload, parts: path.split(separator: ".").map(String.init), toCBOR: toCBOR)
        }
        return payload
    }

    static func transformSecurityPath(
        _ object: inout [String: AnySendable], parts: [String], toCBOR: Bool
    ) throws {
        guard let first = parts.first, let value = object[first] else { return }
        if parts.count > 1 {
            guard case .object(var nested) = value else { throw ACPCodecError.malformed(first) }
            try transformSecurityPath(&nested, parts: Array(parts.dropFirst()), toCBOR: toCBOR)
            object[first] = .object(nested)
            return
        }
        if toCBOR {
            if case .bytes = value { return }
            guard case .string(let text) = value, !text.isEmpty, !text.contains("=") else {
                throw ACPCodecError.malformed("security bytes require unpadded base64url")
            }
            var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
            guard let data = Data(base64Encoded: standard), base64url(data) == text else {
                throw ACPCodecError.malformed("invalid security base64url")
            }
            object[first] = .bytes(data)
        } else {
            if case .string(let text) = value {
                guard !text.isEmpty, !text.contains("=") else {
                    throw ACPCodecError.malformed("security bytes require unpadded base64url")
                }
                var standard = text.replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
                standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
                guard let data = Data(base64Encoded: standard), base64url(data) == text else {
                    throw ACPCodecError.malformed("invalid security base64url")
                }
                return
            }
            guard case .bytes(let data) = value else {
                throw ACPCodecError.malformed("security field must be CBOR byte string")
            }
            object[first] = .string(base64url(data))
        }
    }

    static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
