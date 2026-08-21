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

public struct ACPRemoteProfileID: RawRepresentable, Sendable, Equatable, Hashable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let prismV1 = ACPRemoteProfileID(rawValue: "aurora.remote.prism.v1")
    public static let conductorV1 = ACPRemoteProfileID(rawValue: "aurora.remote.conductor.v1")
    public static let legacy = ACPRemoteProfileID(rawValue: "remote")

    public var isReserved: Bool { self == .conductorV1 }
}

public struct ACPRemotePermission: RawRepresentable, Sendable, Equatable, Hashable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let observe = ACPRemotePermission(rawValue: "observe")
    public static let songSelect = ACPRemotePermission(rawValue: "song.select")
    public static let songLoad = ACPRemotePermission(rawValue: "song.load")
    public static let cueExecute = ACPRemotePermission(rawValue: "cue.execute")
    public static let lookExecute = ACPRemotePermission(rawValue: "look.execute")
    public static let buskExecute = ACPRemotePermission(rawValue: "busk.execute")
    public static let outputGrandMaster = ACPRemotePermission(rawValue: "output.grand_master")
    public static let outputBlackout = ACPRemotePermission(rawValue: "output.blackout")
    public static let outputBlackoutEngage = ACPRemotePermission(rawValue: "output.blackout.engage")
    public static let outputBlackoutClear = ACPRemotePermission(rawValue: "output.blackout.clear")
    public static let remoteSurfaceUse = ACPRemotePermission(rawValue: "remote.surface.use")

    public static let known: [ACPRemotePermission] = [
        .observe, .songSelect, .songLoad, .cueExecute, .lookExecute, .buskExecute,
        .outputGrandMaster, .outputBlackout, .outputBlackoutEngage, .outputBlackoutClear,
        .remoteSurfaceUse,
    ]

    public var isKnown: Bool { Self.known.contains(self) }
}

public struct ACPRemoteControlType: RawRepresentable, Sendable, Equatable, Hashable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let button = ACPRemoteControlType(rawValue: "button")
    public static let momentary = ACPRemoteControlType(rawValue: "momentary")
    public static let momentaryButton = ACPRemoteControlType(rawValue: "momentary_button")
    public static let toggle = ACPRemoteControlType(rawValue: "toggle")
    public static let slider = ACPRemoteControlType(rawValue: "slider")
    public static let fader = ACPRemoteControlType(rawValue: "fader")
    public static let encoder = ACPRemoteControlType(rawValue: "encoder")
    public static let rotary = ACPRemoteControlType(rawValue: "rotary")
    public static let selector = ACPRemoteControlType(rawValue: "selector")
    public static let segmentedSelector = ACPRemoteControlType(rawValue: "segmented_selector")
    public static let xy = ACPRemoteControlType(rawValue: "xy")
    public static let xyPad = ACPRemoteControlType(rawValue: "xy_pad")
    public static let transport = ACPRemoteControlType(rawValue: "transport")
    public static let navigation = ACPRemoteControlType(rawValue: "navigation")
    public static let status = ACPRemoteControlType(rawValue: "status")
    public static let meter = ACPRemoteControlType(rawValue: "meter")
    public static let color = ACPRemoteControlType(rawValue: "color")
    public static let colorControl = ACPRemoteControlType(rawValue: "color_control")
    public static let presetTile = ACPRemoteControlType(rawValue: "preset_tile")
    public static let label = ACPRemoteControlType(rawValue: "label")
    public static let valueDisplay = ACPRemoteControlType(rawValue: "value_display")
    public static let statusIndicator = ACPRemoteControlType(rawValue: "status_indicator")
    public static let group = ACPRemoteControlType(rawValue: "group")
    public static let spacer = ACPRemoteControlType(rawValue: "spacer")

    public static let known: Set<String> = [
        "button", "momentary", "momentary_button", "toggle", "slider", "fader",
        "encoder", "rotary", "selector", "segmented_selector", "xy", "xy_pad",
        "transport", "navigation", "status", "meter", "color", "color_control",
        "preset_tile", "label", "value_display", "status_indicator", "group", "spacer",
    ]

    public var isKnown: Bool { Self.known.contains(rawValue) }
}

public struct ACPRemoteAction: RawRepresentable, Sendable, Equatable, Hashable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let cueGo = ACPRemoteAction(rawValue: "cue.go")
    public static let navGo = ACPRemoteAction(rawValue: "nav.go")
    public static let buskFogOutput = ACPRemoteAction(rawValue: "busk.fog.output")
    public static let buskWorkLights = ACPRemoteAction(rawValue: "busk.work_lights")
    public static let buskBlinder = ACPRemoteAction(rawValue: "busk.blinder")
    public static let bridgeBlackout = ACPRemoteAction(rawValue: "bridge.blackout")
    public static let outputBlackoutSet = ACPRemoteAction(rawValue: "output.blackout.set")
    public static let outputGrandMasterSet = ACPRemoteAction(rawValue: "output.grand_master.set")
    public static let transportPlay = ACPRemoteAction(rawValue: "transport.play")
    public static let transportStop = ACPRemoteAction(rawValue: "transport.stop")
    public static let navSongSelect = ACPRemoteAction(rawValue: "nav.song.select")
    public static let navSectionEnter = ACPRemoteAction(rawValue: "nav.section.enter")
    public static let showSongSelect = ACPRemoteAction(rawValue: "show.song.select")
    public static let showSongLoad = ACPRemoteAction(rawValue: "show.song.load")
    public static let showSongStop = ACPRemoteAction(rawValue: "show.song.stop")
    public static let showSongNext = ACPRemoteAction(rawValue: "show.song.next")
    public static let showSongPrevious = ACPRemoteAction(rawValue: "show.song.previous")
    public static let showSectionNext = ACPRemoteAction(rawValue: "show.section.next")
    public static let showSectionPrevious = ACPRemoteAction(rawValue: "show.section.previous")
    public static let showSectionRestart = ACPRemoteAction(rawValue: "show.section.restart")
    public static let showProgressionHold = ACPRemoteAction(rawValue: "show.progression.hold")
    public static let showFreePlayEnter = ACPRemoteAction(rawValue: "show.free_play.enter")
    public static let showFreePlayExit = ACPRemoteAction(rawValue: "show.free_play.exit")
    public static let lookRecall = ACPRemoteAction(rawValue: "look.recall")
    public static let lookPreview = ACPRemoteAction(rawValue: "look.preview")
    public static let lookTake = ACPRemoteAction(rawValue: "look.take")
    public static let lookPreviewCancel = ACPRemoteAction(rawValue: "look.preview.cancel")
    public static let effectsStop = ACPRemoteAction(rawValue: "effects.stop")

    public static let allowlist: [ACPRemoteAction] = [
        .cueGo, .navGo, .buskFogOutput, .buskWorkLights, .buskBlinder, .bridgeBlackout,
        .outputBlackoutSet, .outputGrandMasterSet, .transportPlay, .transportStop,
        .navSongSelect, .navSectionEnter, .showSongSelect, .showSongLoad, .showSongStop,
        .showSongNext, .showSongPrevious, .showSectionNext, .showSectionPrevious,
        .showSectionRestart, .showProgressionHold, .showFreePlayEnter, .showFreePlayExit,
        .lookRecall, .lookPreview, .lookTake, .lookPreviewCancel, .effectsStop,
    ]

    public var isAllowlisted: Bool { Self.allowlist.contains(self) }

    public var delivery: String {
        switch self {
        case .cueGo, .navGo, .lookTake, .showSectionNext, .showSectionPrevious, .showSectionRestart,
             .buskFogOutput, .buskBlinder:
            return "live_ephemeral"
        case .showSongSelect, .outputBlackoutSet, .outputGrandMasterSet, .buskWorkLights,
             .showProgressionHold, .bridgeBlackout, .navSongSelect:
            return "stateful"
        default:
            return "impulse"
        }
    }
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

public struct ACPRemoteBinding: Sendable, Equatable {
    public var target: String
    public var action: String
    public var parameters: [String: AnySendable]

    public init(target: String, action: String, parameters: [String: AnySendable] = [:]) {
        self.target = target
        self.action = action
        self.parameters = parameters
    }

    public static func from(_ object: [String: AnySendable]) -> ACPRemoteBinding? {
        guard let target = object.acpString("target"), let action = object.acpString("action") else {
            return nil
        }
        let parameters: [String: AnySendable]
        if case .object(let nested) = object["parameters"] {
            parameters = nested
        } else {
            parameters = [:]
        }
        return ACPRemoteBinding(target: target, action: action, parameters: parameters)
    }
}

public struct ACPRemoteSafety: Sendable, Equatable {
    public var safetyClass: String
    public var failsafe: String
    public var failsafeRequired: Bool
    public var maxHoldMs: UInt64
    public var heartbeatRequired: Bool
    public var confirm: String?

    public init(
        safetyClass: String = "normal",
        failsafe: String = "release_on_disconnect",
        failsafeRequired: Bool = false,
        maxHoldMs: UInt64 = 10_000,
        heartbeatRequired: Bool = false,
        confirm: String? = nil
    ) {
        self.safetyClass = safetyClass
        self.failsafe = failsafe
        self.failsafeRequired = failsafeRequired
        self.maxHoldMs = maxHoldMs
        self.heartbeatRequired = heartbeatRequired
        self.confirm = confirm
    }

    public static func from(_ object: [String: AnySendable]?) -> ACPRemoteSafety {
        guard let object else { return ACPRemoteSafety() }
        return ACPRemoteSafety(
            safetyClass: object.acpString("class") ?? "normal",
            failsafe: object.acpString("failsafe") ?? "release_on_disconnect",
            failsafeRequired: object.acpBool("failsafe_required") ?? false,
            maxHoldMs: object.acpUInt("max_hold_ms") ?? 10_000,
            heartbeatRequired: object.acpBool("heartbeat_required") ?? false,
            confirm: object.acpString("confirm")
        )
    }
}

public struct ACPRemoteCondition: Sendable, Equatable {
    public var predicate: String
    public var path: String?
    public var value: AnySendable?

    public init(predicate: String, path: String? = nil, value: AnySendable? = nil) {
        self.predicate = predicate
        self.path = path
        self.value = value
    }
}

public struct ACPRemoteControl: Sendable, Equatable {
    public var controlID: String
    public var label: String
    public var controlType: String
    public var permission: String
    public var binding: ACPRemoteBinding
    public var concurrency: String
    public var delivery: String?
    public var trafficClass: String?
    public var feedback: String?
    public var style: String?
    public var min: Double?
    public var max: Double?
    public var step: Double?
    public var units: String?
    public var availabilityBinding: String?
    public var safety: ACPRemoteSafety
    public var conditions: [ACPRemoteCondition]
    public var accessibilityLabel: String?
    public var accessibilityHint: String?

    public var action: String {
        get { binding.action }
        set { binding.action = newValue }
    }

    public var failsafe: String {
        get { safety.failsafe }
        set { safety.failsafe = newValue }
    }

    public var maxHoldMs: UInt64 {
        get { safety.maxHoldMs }
        set { safety.maxHoldMs = newValue }
    }

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
        self.init(
            controlID: controlID,
            label: label,
            controlType: controlType,
            permission: permission,
            binding: ACPRemoteBinding(target: "prism", action: action),
            concurrency: concurrency,
            safety: ACPRemoteSafety(failsafe: failsafe, maxHoldMs: maxHoldMs)
        )
    }

    public init(
        controlID: String,
        label: String,
        controlType: String,
        permission: String,
        binding: ACPRemoteBinding,
        concurrency: String = "shared",
        delivery: String? = nil,
        trafficClass: String? = nil,
        feedback: String? = nil,
        style: String? = nil,
        min: Double? = nil,
        max: Double? = nil,
        step: Double? = nil,
        units: String? = nil,
        availabilityBinding: String? = nil,
        safety: ACPRemoteSafety = ACPRemoteSafety(),
        conditions: [ACPRemoteCondition] = [],
        accessibilityLabel: String? = nil,
        accessibilityHint: String? = nil
    ) {
        self.controlID = controlID
        self.label = label
        self.controlType = controlType
        self.permission = permission
        self.binding = binding
        self.concurrency = concurrency
        self.delivery = delivery
        self.trafficClass = trafficClass
        self.feedback = feedback
        self.style = style
        self.min = min
        self.max = max
        self.step = step
        self.units = units
        self.availabilityBinding = availabilityBinding
        self.safety = safety
        self.conditions = conditions
        self.accessibilityLabel = accessibilityLabel
        self.accessibilityHint = accessibilityHint
    }

    public static func from(_ object: [String: AnySendable]) -> ACPRemoteControl? {
        guard
            let controlID = object.acpString("control_id"),
            let label = object.acpString("label"),
            let controlType = object.acpString("control_type"),
            case .object(let bindingObject) = object["binding"],
            let binding = ACPRemoteBinding.from(bindingObject)
        else {
            return nil
        }
        var conditions: [ACPRemoteCondition] = []
        if case .array(let items) = object["conditions"] {
            for item in items {
                guard case .object(let cond) = item, let predicate = cond.acpString("predicate") else { continue }
                conditions.append(ACPRemoteCondition(
                    predicate: predicate,
                    path: cond.acpString("path"),
                    value: cond["value"]
                ))
            }
        }
        let safetyObject: [String: AnySendable]?
        if case .object(let nested) = object["safety"] {
            safetyObject = nested
        } else {
            safetyObject = nil
        }
        return ACPRemoteControl(
            controlID: controlID,
            label: label,
            controlType: controlType,
            permission: object.acpString("permission") ?? "observe",
            binding: binding,
            concurrency: object.acpString("concurrency") ?? "shared",
            delivery: object.acpString("delivery"),
            trafficClass: object.acpString("traffic_class"),
            feedback: object.acpString("feedback"),
            style: object.acpString("style"),
            min: object.acpDouble("min"),
            max: object.acpDouble("max"),
            step: object.acpDouble("step"),
            units: object.acpString("units"),
            availabilityBinding: object.acpString("availability_binding"),
            safety: ACPRemoteSafety.from(safetyObject),
            conditions: conditions,
            accessibilityLabel: object.acpString("accessibility_label"),
            accessibilityHint: object.acpString("accessibility_hint")
        )
    }
}

public struct ACPRemoteGroup: Sendable, Equatable {
    public var groupID: String
    public var title: String?
    public var order: UInt64?
    public var controls: [String]

    public init(groupID: String, title: String? = nil, order: UInt64? = nil, controls: [String]) {
        self.groupID = groupID
        self.title = title
        self.order = order
        self.controls = controls
    }

    public static func from(_ object: [String: AnySendable]) -> ACPRemoteGroup? {
        guard let groupID = object.acpString("group_id") else { return nil }
        var ids: [String] = []
        if case .array(let items) = object["controls"] {
            ids = items.compactMap { if case .string(let s) = $0 { return s }; return nil }
        }
        return ACPRemoteGroup(
            groupID: groupID,
            title: object.acpString("title"),
            order: object.acpUInt("order"),
            controls: ids
        )
    }
}

public struct ACPRemotePage: Sendable, Equatable {
    public var pageID: String
    public var title: String
    public var order: UInt64?
    public var groups: [ACPRemoteGroup]

    public init(pageID: String, title: String, order: UInt64? = nil, groups: [ACPRemoteGroup]) {
        self.pageID = pageID
        self.title = title
        self.order = order
        self.groups = groups
    }

    public static func from(_ object: [String: AnySendable]) -> ACPRemotePage? {
        guard let pageID = object.acpString("page_id") else { return nil }
        var groups: [ACPRemoteGroup] = []
        if case .array(let items) = object["groups"] {
            groups = items.compactMap { item in
                guard case .object(let obj) = item else { return nil }
                return ACPRemoteGroup.from(obj)
            }
        }
        return ACPRemotePage(
            pageID: pageID,
            title: object.acpString("title") ?? "",
            order: object.acpUInt("order"),
            groups: groups
        )
    }
}

public struct ACPRemoteLayout: Sendable, Equatable {
    public var surfaceID: String
    public var revision: UInt64
    public var schemaVersion: String
    public var compatibleProfile: String?
    public var minClientSchema: String?
    public var maxClientSchema: String?
    public var sha256: String?
    public var showID: String
    public var showRevision: UInt64?
    public var name: String
    public var pages: [ACPRemotePage]
    public var controls: [ACPRemoteControl]

    /// Compatibility alias for `surfaceID`. Prefer surface terminology in new code.
    public var layoutID: String {
        get { surfaceID }
        set { surfaceID = newValue }
    }

    public init(layoutID: String, revision: UInt64, showID: String, name: String, controls: [ACPRemoteControl]) {
        self.init(
            surfaceID: layoutID,
            revision: revision,
            showID: showID,
            name: name,
            controls: controls
        )
    }

    public init(
        surfaceID: String,
        revision: UInt64,
        showID: String,
        name: String,
        controls: [ACPRemoteControl],
        schemaVersion: String = "1.0",
        compatibleProfile: String? = ACPRemoteProfileID.prismV1.rawValue,
        minClientSchema: String? = "1.0",
        maxClientSchema: String? = "1.0",
        sha256: String? = nil,
        showRevision: UInt64? = nil,
        pages: [ACPRemotePage] = []
    ) {
        self.surfaceID = surfaceID
        self.revision = revision
        self.schemaVersion = schemaVersion
        self.compatibleProfile = compatibleProfile
        self.minClientSchema = minClientSchema
        self.maxClientSchema = maxClientSchema
        self.sha256 = sha256
        self.showID = showID
        self.showRevision = showRevision
        self.name = name
        self.pages = pages
        self.controls = controls
    }

    public func control(_ id: String) -> ACPRemoteControl? {
        controls.first { $0.controlID == id }
    }

    public static func from(_ object: [String: AnySendable]) -> ACPRemoteLayout? {
        let surfaceID = object.acpString("surface_id") ?? object.acpString("layout_id")
        guard
            let surfaceID,
            let revision = object.acpUInt("revision"),
            let showID = object.acpString("show_id"),
            let name = object.acpString("name")
        else {
            return nil
        }
        var controls: [ACPRemoteControl] = []
        if case .array(let items) = object["controls"] {
            controls = items.compactMap { item in
                guard case .object(let obj) = item else { return nil }
                return ACPRemoteControl.from(obj)
            }
        }
        var pages: [ACPRemotePage] = []
        if case .array(let items) = object["pages"] {
            pages = items.compactMap { item in
                guard case .object(let obj) = item else { return nil }
                return ACPRemotePage.from(obj)
            }
        }
        return ACPRemoteLayout(
            surfaceID: surfaceID,
            revision: revision,
            showID: showID,
            name: name,
            controls: controls,
            schemaVersion: object.acpString("schema_version") ?? "1.0",
            compatibleProfile: object.acpString("compatible_profile"),
            minClientSchema: object.acpString("min_client_schema"),
            maxClientSchema: object.acpString("max_client_schema"),
            sha256: object.acpString("sha256"),
            showRevision: object.acpUInt("show_revision"),
            pages: pages
        )
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

extension Dictionary where Key == String, Value == AnySendable {
    fileprivate func acpString(_ key: String) -> String? {
        if case .string(let value) = self[key] { return value }
        return nil
    }

    fileprivate func acpBool(_ key: String) -> Bool? {
        if case .bool(let value) = self[key] { return value }
        return nil
    }

    fileprivate func acpUInt(_ key: String) -> UInt64? {
        switch self[key] {
        case .uint(let value): return value
        case .int(let value) where value >= 0: return UInt64(value)
        default: return nil
        }
    }

    fileprivate func acpDouble(_ key: String) -> Double? {
        switch self[key] {
        case .double(let value): return value
        case .int(let value): return Double(value)
        case .uint(let value): return Double(value)
        default: return nil
        }
    }
}
