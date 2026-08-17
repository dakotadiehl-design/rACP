import Foundation

public enum ACPModel {
    public static let protocolVersion = "1.2"
}

public enum ACPQoS: String, Sendable {
    case reliable
    case latest
    case bestEffort = "best_effort"
}

public struct ACPEndpoint: Sendable, Equatable {
    public var nodeID: String
    public var componentID: String?

    public init(nodeID: String, componentID: String? = nil) {
        self.nodeID = nodeID
        self.componentID = componentID
    }
}

public struct ACPEnvelope: Sendable, Equatable {
    public var acp: String
    public var messageID: String
    public var type: String
    public var source: ACPEndpoint
    public var destination: ACPEndpoint?
    public var sessionID: String?
    public var sequence: UInt64?
    public var timestampUTC: String
    public var correlationID: String?
    public var causationID: String?
    public var qos: ACPQoS
    public var flags: [String]
    public var payload: [String: AnySendable]

    public init(
        acp: String,
        messageID: String,
        type: String,
        source: ACPEndpoint,
        destination: ACPEndpoint? = nil,
        sessionID: String? = nil,
        sequence: UInt64? = nil,
        timestampUTC: String,
        correlationID: String? = nil,
        causationID: String? = nil,
        qos: ACPQoS,
        flags: [String] = [],
        payload: [String: AnySendable] = [:]
    ) {
        self.acp = acp
        self.messageID = messageID
        self.type = type
        self.source = source
        self.destination = destination
        self.sessionID = sessionID
        self.sequence = sequence
        self.timestampUTC = timestampUTC
        self.correlationID = correlationID
        self.causationID = causationID
        self.qos = qos
        self.flags = flags
        self.payload = payload
    }
}

/// JSON-like sendable value.
public enum AnySendable: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case uint(UInt64)
    case double(Double)
    case string(String)
    case bytes(Data)
    case array([AnySendable])
    case object([String: AnySendable])
}
