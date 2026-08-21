import Foundation

/// Authoritative Remote state mirror. Command acknowledgements never write here.
public struct ACPRemoteStateStore: Sendable, Equatable {
    public private(set) var authorityEpoch: UInt64 = 0
    public private(set) var revision: UInt64 = 0
    public private(set) var stale = true
    public private(set) var needsSnapshot = true
    public private(set) var resources: [String: AnySendable] = [:]
    public private(set) var controls: [String: AnySendable] = [:]

    public static let namespaces: [String] = [
        "show.setlist",
        "show.selected_song",
        "show.current_song",
        "show.current_section",
        "show.next_section",
        "show.mode",
        "show.running",
        "show.progression",
        "look.catalog",
        "look.current",
        "look.preview",
        "output.grand_master",
        "output.blackout",
        "system.health",
    ]

    public init() {}

    public mutating func markInterrupted() {
        stale = true
        needsSnapshot = true
    }

    public func resource(_ name: String) -> AnySendable? {
        resources[name]
    }

    public var grandMaster: Double? { number(in: "output.grand_master") }
    public var blackout: Bool? { bool(in: "output.blackout") }
    public var currentSong: String? { stringField("show.current_song", "song_id") }
    public var selectedSong: String? { stringField("show.selected_song", "song_id") }
    public var currentSection: String? { stringField("show.current_section", "section_id") }
    public var nextSection: String? { stringField("show.next_section", "section_id") }
    public var showMode: String? { string(in: "show.mode") }
    public var running: Bool? { bool(in: "show.running") }

    public mutating func apply(_ envelope: ACPEnvelope) throws {
        switch envelope.type {
        case "state.snapshot":
            try applySnapshot(envelope.payload)
        case "state.delta":
            try applyDelta(envelope.payload)
        case "remote.control.snapshot":
            if case .array(let items) = envelope.payload["controls"] {
                for item in items {
                    guard case .object(let obj) = item, case .string(let id) = obj["control_id"] else { continue }
                    controls[id] = .object(obj)
                }
            }
            if let rev = uint(envelope.payload["snapshot_revision"]) {
                revision = max(revision, rev)
            }
            stale = false
        case "remote.control.state":
            if case .string(let id) = envelope.payload["control_id"] {
                controls[id] = .object(envelope.payload)
            }
        case "remote.presentation.state":
            resources["show.presentation"] = .object(envelope.payload)
        case "remote.navigation.state":
            resources["show.navigation"] = .object(envelope.payload)
        default:
            break
        }
    }

    public mutating func applySnapshot(_ payload: [String: AnySendable]) throws {
        if let epoch = uint(payload["authority_epoch"]), epoch < authorityEpoch, authorityEpoch != 0 {
            throw ACPStateSyncError.snapshotRequired("authority_epoch went backwards")
        }
        if let epoch = uint(payload["authority_epoch"]) {
            authorityEpoch = epoch
        }
        if let rev = uint(payload["revision"]) {
            revision = rev
        }
        var next: [String: AnySendable] = [:]
        if case .array(let items) = payload["resources"] {
            for item in items {
                guard case .object(let obj) = item, case .string(let name) = obj["resource"] else { continue }
                next[name] = obj["value"] ?? .object(obj)
            }
        }
        resources = next
        stale = false
        needsSnapshot = false
    }

    public mutating func applyDelta(_ payload: [String: AnySendable]) throws {
        if payload["changes"] != nil {
            if needsSnapshot {
                throw ACPStateSyncError.snapshotRequired("delta before snapshot")
            }
            let (epoch, rev): (UInt64, UInt64)
            do {
                (epoch, rev) = try ACPStateRevision.applyDelta(
                    localEpoch: authorityEpoch,
                    localRevision: revision,
                    payload: payload
                )
            } catch let error as ACPStateSyncError {
                needsSnapshot = true
                stale = true
                throw error
            }
            if epoch < authorityEpoch {
                needsSnapshot = true
                stale = true
                throw ACPStateSyncError.snapshotRequired("authority_epoch from a previous session")
            }
            if case .array(let changes) = payload["changes"] {
                for change in changes {
                    guard case .object(let obj) = change, case .string(let name) = obj["resource"] else { continue }
                    resources[name] = obj["value"] ?? .object(obj)
                }
            }
            authorityEpoch = epoch
            revision = rev
            stale = false
            return
        }
        if let epoch = uint(payload["authority_epoch"]) {
            if needsSnapshot {
                throw ACPStateSyncError.snapshotRequired("delta before snapshot")
            }
            if epoch != authorityEpoch {
                throw ACPStateSyncError.snapshotRequired("authority_epoch mismatch")
            }
        }
        if let incoming = uint(payload["revision"]), !needsSnapshot {
            if incoming < revision {
                throw ACPStateSyncError.snapshotRequired("stale state delta")
            }
            if incoming > revision + 1 {
                needsSnapshot = true
                stale = true
                throw ACPStateSyncError.snapshotRequired("revision gap")
            }
            revision = incoming
        }
        if case .string(let name) = payload["resource"] {
            resources[name] = payload["value"] ?? .object(payload)
            stale = false
        }
    }

    private func uint(_ value: AnySendable?) -> UInt64? {
        switch value {
        case .uint(let u): return u
        case .int(let i) where i >= 0: return UInt64(i)
        default: return nil
        }
    }

    private func number(in name: String) -> Double? {
        switch resource(name) {
        case .double(let d): return d
        case .int(let i): return Double(i)
        case .uint(let u): return Double(u)
        case .object(let obj):
            switch obj["value"] ?? obj["level"] {
            case .double(let d): return d
            case .int(let i): return Double(i)
            case .uint(let u): return Double(u)
            default: return nil
            }
        default: return nil
        }
    }

    private func bool(in name: String) -> Bool? {
        switch resource(name) {
        case .bool(let b): return b
        case .object(let obj):
            if case .bool(let b) = obj["value"] ?? obj["enabled"] { return b }
            return nil
        default: return nil
        }
    }

    private func string(in name: String) -> String? {
        switch resource(name) {
        case .string(let s): return s
        case .object(let obj):
            if case .string(let s) = obj["value"] ?? obj["mode"] { return s }
            return nil
        default: return nil
        }
    }

    private func stringField(_ name: String, _ field: String) -> String? {
        if case .string(let s) = resource(name) { return s }
        if case .object(let obj) = resource(name), case .string(let s) = obj[field] ?? obj["value"] {
            return s
        }
        return nil
    }
}
