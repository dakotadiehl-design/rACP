import Foundation

public struct ACPRegistryRow: Sendable {
    public var type: String
    public var minProtocol: String
    public var requiredCapability: String?
    public var minCapabilityVersion: String?
    public var validSenders: [String]
    public var qosAllowed: [String]
    public var legalBeforeHandshake: Bool
    public var responseType: String?
    public var legalSessionStates: [String]
    public var authorizationPermission: String?
    public var rateLimitClass: String?
    public var sensitiveFieldPolicy: String?
}

public enum ACPRegistry {
    public static let rows: [String: ACPRegistryRow] = {
        let urls = [
            Bundle.module.url(forResource: "registry", withExtension: "json"),
            Bundle.module.url(forResource: "registry", withExtension: "json", subdirectory: "Session"),
            URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .appendingPathComponent("registry.json"),
        ]
        for url in urls.compactMap({ $0 }) {
            guard let data = try? Data(contentsOf: url),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let messages = obj["messages"] as? [[String: Any]]
            else { continue }
            var map: [String: ACPRegistryRow] = [:]
            for msg in messages {
                guard let typ = msg["type"] as? String else { continue }
                map[typ] = ACPRegistryRow(
                    type: typ,
                    minProtocol: msg["min_protocol"] as? String ?? "1.0",
                    requiredCapability: msg["required_capability"] as? String,
                    minCapabilityVersion: msg["min_capability_version"] as? String,
                    validSenders: msg["valid_senders"] as? [String] ?? [],
                    qosAllowed: msg["qos_allowed"] as? [String] ?? [],
                    legalBeforeHandshake: msg["legal_before_handshake"] as? Bool ?? false,
                    responseType: msg["response_type"] as? String,
                    legalSessionStates: msg["legal_session_states"] as? [String] ?? [],
                    authorizationPermission: msg["authorization_permission"] as? String,
                    rateLimitClass: msg["rate_limit_class"] as? String,
                    sensitiveFieldPolicy: msg["sensitive_field_policy"] as? String
                )
            }
            return map
        }
        return [:]
    }()

    public static func lookup(_ type: String) -> ACPRegistryRow? { rows[type] }

    public static func responseType(for type: String) -> String? { rows[type]?.responseType }

    public static func allowed(
        type: String,
        senderRole: String,
        negotiated: [String],
        handshakeComplete: Bool,
        qos: String?,
        envelopeVersion: String?,
        negotiatedVersions: [String: String],
        sessionState: String? = nil
    ) -> String? {
        guard let row = lookup(type) else {
            return handshakeComplete ? "unsupported_message" : "malformed_envelope"
        }
        if !handshakeComplete && !row.legalBeforeHandshake { return "malformed_envelope" }
        if !row.legalSessionStates.isEmpty {
            let actual = sessionState ?? (handshakeComplete ? "Established" : "PreHello")
            if !row.legalSessionStates.contains(actual) { return "security.permission_denied" }
        }
        if handshakeComplete {
            let ver = envelopeVersion ?? "1.2"
            if !ACPNegotiate.versionAtLeast(ver, row.minProtocol) { return "unsupported_message" }
        }
        if let cap = row.requiredCapability {
            if !negotiated.contains(cap) { return "capability_not_permitted" }
            if let minCap = row.minCapabilityVersion {
                guard let have = negotiatedVersions[cap], ACPNegotiate.versionAtLeast(have, minCap) else {
                    return "capability_not_permitted"
                }
            }
        }
        if !row.validSenders.contains(senderRole) { return "capability_not_permitted" }
        if let qos, !row.qosAllowed.contains(qos) { return "invalid_type" }
        return nil
    }
}

public func acpMinCapabilityAllowed(
    requiredCapability: String?,
    minCapabilityVersion: String?,
    negotiatedVersions: [String: String]
) -> String? {
    guard let cap = requiredCapability, let minCap = minCapabilityVersion else { return nil }
    guard let have = negotiatedVersions[cap], ACPNegotiate.versionAtLeast(have, minCap) else {
        return "capability_not_permitted"
    }
    return nil
}

public func acpVersionAtLeast(_ actual: String, _ required: String) -> Bool {
    ACPNegotiate.versionAtLeast(actual, required)
}
