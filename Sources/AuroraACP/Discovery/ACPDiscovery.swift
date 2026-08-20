import Foundation

/// Portable ACP discovery identity. Discovery is informational and never authenticates.
public struct ACPDiscoveryEndpoint: Sendable, Equatable {
    public var nodeID: String
    public var instanceID: String
    public var role: String
    public var name: String
    public var endpointURL: String
    public var profiles: [String]
    public var encodings: [String]
    public var capabilitiesDigest: String
    public var securityMode: String

    public init(
        nodeID: String,
        instanceID: String,
        role: String,
        name: String,
        endpointURL: String,
        profiles: [String] = ["core"],
        encodings: [String] = ["cbor", "json"],
        capabilitiesDigest: String = "",
        securityMode: String = "trusted_lan"
    ) {
        self.nodeID = nodeID
        self.instanceID = instanceID
        self.role = role
        self.name = name
        self.endpointURL = endpointURL
        self.profiles = profiles
        self.encodings = encodings
        self.capabilitiesDigest = capabilitiesDigest
        self.securityMode = securityMode
    }

    /// Apple Bonjour TXT mapping of the same ACP advertisement semantics.
    /// TXT never carries credentials, PINs, or authorization grants.
    public var bonjourTXT: [String: String] {
        [
            "nid": nodeID,
            "iid": instanceID,
            "role": role,
            "name": name,
            "url": endpointURL,
            "enc": encodings.joined(separator: ","),
            "prf": profiles.joined(separator: ","),
            "sec": securityMode,
            "cap": capabilitiesDigest,
        ]
    }

    public static let bonjourServiceType = "_acp._tcp"

    public static func fromBonjourTXT(_ txt: [String: String]) -> ACPDiscoveryEndpoint? {
        guard let nodeID = txt["nid"], let url = txt["url"], !nodeID.isEmpty, !url.isEmpty else {
            return nil
        }
        return ACPDiscoveryEndpoint(
            nodeID: nodeID,
            instanceID: txt["iid"] ?? "",
            role: txt["role"] ?? "prism",
            name: txt["name"] ?? "",
            endpointURL: url,
            profiles: (txt["prf"] ?? "core").split(separator: ",").map(String.init),
            encodings: (txt["enc"] ?? "cbor").split(separator: ",").map(String.init),
            capabilitiesDigest: txt["cap"] ?? "",
            securityMode: txt["sec"] ?? "trusted_lan"
        )
    }
}
