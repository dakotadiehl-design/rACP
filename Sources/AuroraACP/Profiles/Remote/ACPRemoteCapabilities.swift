import Foundation

/// Capability presets drawn from `schema/constants.json` `remote.capabilities`
/// and `remote.feature_capabilities`. Do not use `ACPSession.defaultCapabilities`
/// for a production Remote client.
public enum ACPCapabilitySet {
    public static let remoteProtocolIDs: [String] = [
        "remote.profile",
        "remote.layout",
        "remote.control.invoke",
        "remote.control.momentary",
        "remote.control.state",
        "remote.navigation.song",
        "remote.navigation.section",
        "remote.navigation.cue",
        "remote.transport",
        "remote.busking",
        "remote.readiness",
        "remote.asset_sync",
        "remote.presentation",
    ]

    public static let remoteFeatureIDs: [String] = [
        "show.navigation",
        "song.selection",
        "song.loading",
        "cue.go",
        "cue.selection",
        "look.global",
        "remote.surfaces",
        "busk.controls",
        "control.momentary",
        "output.blackout",
        "output.blackout.engage",
        "output.blackout.clear",
        "output.grand_master",
        "state.live",
        "system.health",
    ]

    /// Capabilities a Prism Remote 1.0 client must see in the negotiated intersection
    /// before becoming ready. Feature IDs are required because Aurora Remote 1.0
    /// advertises and consumes them.
    public static let prismRemoteRequiredIDs: Set<String> = [
        "remote.profile",
        "remote.control.invoke",
        "remote.control.momentary",
        "remote.readiness",
        "remote.layout",
        "state.live",
        "system.health",
    ]

    public static var prismRemoteClient: [ACPCapability] {
        preset(ids: remoteProtocolIDs + remoteFeatureIDs + ["health.heartbeat", "resource.transfer", "command.status"])
    }

    public static var prismRemoteProvider: [ACPCapability] {
        prismRemoteClient
    }

    private static func preset(ids: [String]) -> [ACPCapability] {
        var seen = Set<String>()
        var out: [ACPCapability] = []
        for id in ids where seen.insert(id).inserted {
            let version = id == "resource.transfer" ? "1.2" : "1.0"
            out.append(ACPCapability(id: id, version: version))
        }
        return out
    }
}
