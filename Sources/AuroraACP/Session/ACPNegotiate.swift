import Foundation

public enum ACPNegotiate {
    public static let heartbeatMinMs = 100
    public static let heartbeatMaxMs = 60_000
    public static let messageBytesMin = 256
    public static let messageBytesMax = 1_048_576

    public static func parseVersion(_ text: String) -> (Int, Int)? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, let major = Int(parts[0]), let minor = Int(parts[1]) else { return nil }
        return (major, minor)
    }

    public static func versionAtLeast(_ actual: String, _ required: String) -> Bool {
        guard let a = parseVersion(actual), let r = parseVersion(required) else { return false }
        if a.0 != r.0 { return a.0 > r.0 }
        return a.1 >= r.1
    }

    public static func versionLeq(_ actual: String, _ maximum: String) -> Bool {
        guard let a = parseVersion(actual), let m = parseVersion(maximum) else { return false }
        if a.0 != m.0 { return a.0 < m.0 }
        return a.1 <= m.1
    }

    public static func selectVersion(clientMin: String, clientMax: String, serverMin: String, serverMax: String) throws -> String {
        guard let cmin = parseVersion(clientMin), let cmax = parseVersion(clientMax),
              let smin = parseVersion(serverMin), let smax = parseVersion(serverMax),
              cmin.0 == smin.0, cmin.0 == cmax.0, smin.0 == smax.0, cmin <= cmax, smin <= smax
        else {
            throw ACPSessionError("unsupported_version", "protocol major mismatch or malformed range")
        }
        let lo = max(cmin.1, smin.1)
        let hi = min(cmax.1, smax.1)
        if lo > hi { throw ACPSessionError("unsupported_version", "empty protocol intersection") }
        return "\(cmin.0).\(hi)"
    }

    public static func selectEncoding(client: [String], server: [String]) throws -> String {
        for enc in ["cbor", "json"] where client.contains(enc) && server.contains(enc) {
            return enc
        }
        throw ACPSessionError("unsupported_version", "no common encoding")
    }

    public static func validateHeartbeat(_ ms: Int) throws -> Int {
        guard (heartbeatMinMs...heartbeatMaxMs).contains(ms) else {
            throw ACPSessionError("malformed_envelope", "heartbeat_interval_ms out of bounds")
        }
        return ms
    }

    public static func validateMaxMessageBytes(_ n: Int) throws -> Int {
        guard (messageBytesMin...messageBytesMax).contains(n) else {
            throw ACPSessionError("malformed_envelope", "max_message_bytes out of bounds")
        }
        return n
    }
}
