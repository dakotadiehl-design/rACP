import Foundation

public struct ACPPrecondition: Sendable, Equatable {
    public var op: String
    public var field: String
    public var value: AnySendable
    public var resource: String?
    public var resourceField: String?

    public init(op: String, field: String, value: AnySendable, resource: String? = nil, resourceField: String? = nil) {
        self.op = op
        self.field = field
        self.value = value
        self.resource = resource
        self.resourceField = resourceField
    }
}

public enum ACPStateSyncError: Error, Equatable {
    case snapshotRequired(String)
    case preconditionFailed(String)
}

public enum ACPStateRevision {
    public static func snapshotPayload(
        authorityEpoch: UInt64,
        revision: UInt64,
        resources: [AnySendable]
    ) -> [String: AnySendable] {
        [
            "authority_epoch": .uint(authorityEpoch),
            "revision": .uint(revision),
            "resources": .array(resources),
        ]
    }

    public static func deltaPayload(
        authorityEpoch: UInt64,
        baseRevision: UInt64,
        revision: UInt64,
        changes: [AnySendable]
    ) -> [String: AnySendable] {
        [
            "authority_epoch": .uint(authorityEpoch),
            "base_revision": .uint(baseRevision),
            "revision": .uint(revision),
            "changes": .array(changes),
        ]
    }

    public static func applyDelta(
        localEpoch: UInt64,
        localRevision: UInt64,
        payload: [String: AnySendable]
    ) throws -> (UInt64, UInt64) {
        if payload["changes"] != nil, case .uint(let epoch) = payload["authority_epoch"] {
            let base = uint(payload["base_revision"])
            let revision = uint(payload["revision"])
            if epoch != localEpoch {
                throw ACPStateSyncError.snapshotRequired("authority_epoch mismatch")
            }
            if base != localRevision {
                throw ACPStateSyncError.snapshotRequired("base_revision mismatch")
            }
            if revision <= localRevision {
                throw ACPStateSyncError.snapshotRequired("delta revision did not advance")
            }
            return (epoch, revision)
        }
        return (localEpoch, localRevision &+ 1)
    }

    public static func evaluatePreconditions(
        _ preconditions: [ACPPrecondition],
        authorityEpoch: UInt64,
        revision: UInt64,
        showID: String? = nil,
        currentCueID: String? = nil,
        resources: [String: [String: AnySendable]] = [:]
    ) throws {
        for pred in preconditions {
            let actual: AnySendable
            switch pred.field {
            case "authority_epoch":
                actual = .uint(authorityEpoch)
            case "revision":
                actual = .uint(revision)
            case "show_id":
                actual = showID.map(AnySendable.string) ?? .null
            case "current_cue_id":
                actual = currentCueID.map(AnySendable.string) ?? .null
            case "resource_field":
                guard let resource = pred.resource, let field = pred.resourceField else {
                    throw ACPStateSyncError.preconditionFailed("resource_field precondition is incomplete")
                }
                actual = resources[resource]?[field] ?? .null
            default:
                throw ACPStateSyncError.preconditionFailed("unknown precondition field \(pred.field)")
            }
            switch pred.op {
            case "equals":
                if actual != pred.value {
                    throw ACPStateSyncError.preconditionFailed("\(pred.field) equals failed")
                }
            case "at_least":
                if uint(actual) < uint(pred.value) {
                    throw ACPStateSyncError.preconditionFailed("\(pred.field) at_least failed")
                }
            default:
                throw ACPStateSyncError.preconditionFailed("unknown precondition op \(pred.op)")
            }
        }
    }

    public static let neverCoalesceActions: Set<String> = [
        "performance.go", "performance.back", "cue.fire", "cue.go",
        "momentary.begin", "momentary.end", "blackoutOn", "blackoutOff",
    ]

    private static func uint(_ value: AnySendable?) -> UInt64 {
        switch value {
        case .uint(let u): return u
        case .int(let i) where i >= 0: return UInt64(i)
        default: return 0
        }
    }
}

public enum ACPTrafficClass: String, Sendable {
    case safety, interactive, state, background, telemetry
}

public struct ACPOutboundItem: Sendable {
    public var trafficClass: ACPTrafficClass
    public var coalescingKey: String?
    public var delivery: String
    public var action: String?
    public var payload: AnySendable

    public init(
        trafficClass: ACPTrafficClass,
        payload: AnySendable,
        coalescingKey: String? = nil,
        delivery: String = "in_order",
        action: String? = nil
    ) {
        self.trafficClass = trafficClass
        self.payload = payload
        self.coalescingKey = coalescingKey
        self.delivery = delivery
        self.action = action
    }
}

public struct ACPPriorityQueue: Sendable {
    public var capacities: [ACPTrafficClass: Int]
    private var queues: [ACPTrafficClass: [ACPOutboundItem]]
    private var coalesced: [String: ACPOutboundItem]

    public init(capacities: [ACPTrafficClass: Int] = [
        .safety: 32, .interactive: 64, .state: 128, .background: 16, .telemetry: 8,
    ]) {
        self.capacities = capacities
        self.queues = Dictionary(uniqueKeysWithValues: ACPTrafficClass.allCases.map { ($0, []) })
        self.coalesced = [:]
    }

    public mutating func push(_ item: ACPOutboundItem) -> Bool {
        var item = item
        if let action = item.action, ACPStateRevision.neverCoalesceActions.contains(action) {
            item.coalescingKey = nil
            item.delivery = "never_coalesce"
        }
        if item.delivery == "latest_value_wins", let key = item.coalescingKey {
            coalesced[key] = item
            return true
        }
        let cls = item.trafficClass
        let cap = capacities[cls] ?? 8
        var q = queues[cls] ?? []
        if q.count >= cap {
            return cls == .telemetry || cls == .background ? false : false
        }
        q.append(item)
        queues[cls] = q
        return true
    }

    public mutating func pop() -> ACPOutboundItem? {
        for cls in ACPTrafficClass.allCases {
            if cls == .state, let key = coalesced.keys.first {
                return coalesced.removeValue(forKey: key)
            }
            if var q = queues[cls], !q.isEmpty {
                let item = q.removeFirst()
                queues[cls] = q
                return item
            }
        }
        return nil
    }
}

extension ACPTrafficClass: CaseIterable {}
