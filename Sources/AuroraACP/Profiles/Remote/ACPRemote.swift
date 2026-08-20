import Foundation

public enum ACPRemoteRole: String, Sendable {
    case viewer = "remote.viewer"
    case `operator` = "remote.operator"
    case busker = "remote.busker"
    case showNavigation = "remote.show_navigation"
    case admin = "remote.admin"
}

public enum ACPRemoteInteraction: String, Sendable {
    case activate
    case set
    case adjust
    case momentaryBegin = "momentary_begin"
    case momentaryEnd = "momentary_end"
    case momentaryCancel = "momentary_cancel"
}

public enum ACPRemoteReadiness: String, Sendable {
    case connecting, negotiating, syncingAssets = "syncing_assets", syncingState = "syncing_state"
    case ready, readyWithWarnings = "ready_with_warnings", degraded, blocked, disconnected
}

public struct ACPRemoteIdentity: Sendable, Equatable {
    public var nodeID: String
    public var instanceID: String
    public var deviceID: String
    public var remoteID: String
    public var deviceName: String
    public var platform: String
    public var appVersion: String
    public var participantID: String?

    public init(
        nodeID: String,
        instanceID: String,
        deviceID: String,
        remoteID: String,
        deviceName: String,
        platform: String,
        appVersion: String,
        participantID: String? = nil
    ) {
        self.nodeID = nodeID
        self.instanceID = instanceID
        self.deviceID = deviceID
        self.remoteID = remoteID
        self.deviceName = deviceName
        self.platform = platform
        self.appVersion = appVersion
        self.participantID = participantID
    }
}

public struct ACPRemoteControl: Sendable, Equatable {
    public var controlID: String
    public var label: String
    public var controlType: String
    public var permission: String
    public var action: String
    public var concurrency: String
    public var failsafe: String
    public var maxHoldMs: UInt64

    public init(
        controlID: String,
        label: String,
        controlType: String,
        permission: String,
        action: String,
        concurrency: String = "shared",
        failsafe: String = "release_on_disconnect",
        maxHoldMs: UInt64 = 10_000
    ) {
        self.controlID = controlID
        self.label = label
        self.controlType = controlType
        self.permission = permission
        self.action = action
        self.concurrency = concurrency
        self.failsafe = failsafe
        self.maxHoldMs = maxHoldMs
    }
}

public struct ACPRemoteLayout: Sendable, Equatable {
    public var layoutID: String
    public var revision: UInt64
    public var showID: String
    public var name: String
    public var controls: [ACPRemoteControl]

    public init(layoutID: String, revision: UInt64, showID: String, name: String, controls: [ACPRemoteControl]) {
        self.layoutID = layoutID
        self.revision = revision
        self.showID = showID
        self.name = name
        self.controls = controls
    }

    public func control(_ id: String) -> ACPRemoteControl? {
        controls.first { $0.controlID == id }
    }
}

public struct ACPRemoteViewState: Sendable, Equatable {
    public var readiness: ACPRemoteReadiness
    public var layout: ACPRemoteLayout?
    public var pending: [String]
    public var stale: Bool

    public init(
        readiness: ACPRemoteReadiness = .connecting,
        layout: ACPRemoteLayout? = nil,
        pending: [String] = [],
        stale: Bool = false
    ) {
        self.readiness = readiness
        self.layout = layout
        self.pending = pending
        self.stale = stale
    }
}
