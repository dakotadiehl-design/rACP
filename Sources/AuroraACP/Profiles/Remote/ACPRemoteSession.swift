import Foundation

public struct ACPRemoteHoldHandle: Sendable {
    public var controlID: String
    public var invocationID: String
    public var leaseID: String?
}

/// Non-production Remote Profile simulator.
/// A future production host may compose `ACPRemoteAuthorityCore` with
/// authenticated session, persistence, readiness, publication, and audit
/// facilities. This simulator accepts raw session ID strings and does not consume
/// validated ACP envelopes or authenticated transport principals. Not safe for
/// live show-control outputs.
public actor ACPRemoteAuthority {
    public var showID: String
    public var layoutID: String
    public var armed = true
    public var goCount: UInt64 = 0
    public var nowMs: UInt64 = 0
    private var permissions: [String: Set<String>] = [:]
    private var holds: [String: [String: (session: String, started: UInt64, maxHold: UInt64, lease: String)]] = [:]
    private var applied: [String: (fingerprint: String, status: String)] = [:]
    private var appliedOrder: [String] = []
    private let maxApplied = 1024
    private var controls: [String: ACPRemoteControl]

    public init(showID: String, layout: ACPRemoteLayout) {
        self.showID = showID
        self.layoutID = layout.layoutID
        self.controls = Dictionary(uniqueKeysWithValues: layout.controls.map { ($0.controlID, $0) })
    }

    public func authorize(identityID: String, roles: [String]) {
        permissions[identityID] = Set(roles)
        reconcile()
    }

    public func grant(sessionID: String, roles: [String]) {
        authorize(identityID: sessionID, roles: roles)
    }

    public func effectActive(_ controlID: String) -> Bool {
        !(holds[controlID] ?? [:]).isEmpty
    }

    public func invoke(
        sessionID: String,
        controlID: String,
        invocationID: String,
        interaction: ACPRemoteInteraction,
        showID: String? = nil,
        layoutID: String? = nil,
        leaseID: String? = nil
    ) -> (status: String, code: String?, leaseID: String?) {
        let key = "\(sessionID):\(invocationID):\(interaction.rawValue)"
        let fingerprint = "\(controlID)|\(interaction.rawValue)|\(showID ?? "")|\(layoutID ?? "")|\(leaseID ?? "")"
        if !armed { return ("rejected", "remote.control.not_armed", nil) }
        if let showID, showID != self.showID { return ("rejected", "remote.layout.stale", nil) }
        if let layoutID, layoutID != self.layoutID { return ("rejected", "remote.layout.stale", nil) }
        guard let control = controls[controlID] else { return ("rejected", "remote.control.unknown", nil) }
        let roles = permissions[sessionID] ?? []
        let needed = Self.actionPermission(control.action)
        if !roles.contains(needed) { return ("rejected", "remote.control.permission_denied", nil) }
        if let prev = applied[key] {
            if prev.fingerprint != fingerprint { return ("rejected", "conflict", nil) }
            return (prev.status, nil, holds[controlID]?[invocationID]?.lease)
        }
        func remember(_ status: String) {
            if applied.count >= maxApplied, let old = appliedOrder.first {
                appliedOrder.removeFirst()
                applied[old] = nil
            }
            applied[key] = (fingerprint, status)
            appliedOrder.append(key)
        }
        switch interaction {
        case .activate where control.action == "cue.go":
            goCount += 1
            remember("applied")
            return ("applied", nil, nil)
        case .momentaryBegin:
            var group = holds[controlID] ?? [:]
            if let existing = group[invocationID] {
                remember("duplicate")
                return ("duplicate", nil, existing.lease)
            }
            if control.concurrency == "exclusive", !group.isEmpty {
                return ("rejected", "remote.control.conflict", nil)
            }
            let lease = UUID().uuidString.lowercased()
            group[invocationID] = (sessionID, nowMs, control.maxHoldMs, lease)
            holds[controlID] = group
            remember("applied")
            return ("applied", nil, lease)
        case .momentaryEnd, .momentaryCancel:
            var group = holds[controlID] ?? [:]
            if let existing = group[invocationID], existing.session != sessionID {
                return ("rejected", "remote.control.permission_denied", nil)
            }
            if let existing = group[invocationID], existing.lease != leaseID {
                return ("rejected", "remote.momentary.unknown_invocation", nil)
            }
            if group.removeValue(forKey: invocationID) == nil {
                remember("duplicate")
                return ("duplicate", nil, nil)
            }
            holds[controlID] = group.isEmpty ? nil : group
            remember("applied")
            return ("applied", nil, nil)
        default:
            return ("rejected", "remote.control.invalid_interaction", nil)
        }
    }

    public func onSessionLost(_ sessionID: String) {
        for (cid, group) in holds {
            holds[cid] = group.filter { $0.value.session != sessionID }
        }
        holds = holds.filter { !$0.value.isEmpty }
        permissions[sessionID] = nil
    }

    public func tick(_ now: UInt64) {
        nowMs = now
        for (cid, group) in holds {
            holds[cid] = group.filter { now < $0.value.started + $0.value.maxHold }
        }
        holds = holds.filter { !$0.value.isEmpty }
    }

    private func reconcile() {
        for (cid, group) in holds {
            let needed = controls[cid].map { Self.actionPermission($0.action) } ?? "remote.admin"
            holds[cid] = group.filter { entry in
                permissions[entry.value.session]?.contains(needed) == true
            }
        }
        holds = holds.filter { !$0.value.isEmpty }
    }

    private static func actionPermission(_ action: String) -> String {
        if action.hasPrefix("busk.") { return "remote.busker" }
        if action == "bridge.blackout" { return "remote.admin" }
        return "remote.operator"
    }
}

public actor ACPRemoteSession {
    public static let maxLiveEphemeralAgeMs: UInt64 = 5_000

    public var viewState = ACPRemoteViewState()
    public let identity: ACPRemoteIdentity
    private let session: ACPSession
    public var values: [String: AnySendable] = [:]
    public var errors: [String: String] = [:]
    public var leases: [String: String] = [:]
    public private(set) var sentCount = 0
    private var sentInvokes: [String: ACPEnvelope] = [:]
    private var ephemeralPending: Set<String> = []

    public init(session: ACPSession, identity: ACPRemoteIdentity) {
        self.session = session
        self.identity = identity
    }

    public func prepare(layout: ACPRemoteLayout?) {
        viewState.layout = layout
        viewState.readiness = layout == nil ? .syncingAssets : .ready
    }

    public func invoke(
        controlID: String,
        interaction: ACPRemoteInteraction,
        invocationID: String? = nil,
        value: AnySendable? = nil,
        leaseID: String? = nil,
        wait: Bool = true
    ) async throws -> String {
        if viewState.stale || viewState.readiness != .ready {
            throw ACPSessionError("remote.session.not_ready", "remote is not interactive")
        }
        let id = invocationID ?? UUID().uuidString.lowercased()
        let resolvedLease = leaseID ?? leases[id]
        if interaction == .momentaryEnd || interaction == .momentaryCancel, resolvedLease == nil {
            throw ACPSessionError("invalid_type", "lease_id required")
        }
        let sentKey = "\(id):\(interaction.rawValue):\(resolvedLease ?? "")"
        if sentInvokes[sentKey] != nil {
            return id
        }
        let control = viewState.layout?.control(controlID)
        let live = Self.isLiveEphemeral(interaction: interaction, action: control?.action, delivery: control?.delivery)
        var payload: [String: AnySendable] = [
            "control_id": .string(controlID),
            "invocation_id": .string(id),
            "interaction": .string(interaction.rawValue),
            "idempotency_key": .string(id),
        ]
        if let layout = viewState.layout {
            payload["show_id"] = .string(layout.showID)
            payload["layout_id"] = .string(layout.layoutID)
            payload["layout_revision"] = .int(Int64(layout.revision))
        }
        if let value {
            payload["value"] = value
        }
        if let resolvedLease {
            payload["lease_id"] = .string(resolvedLease)
        }
        if live {
            let issued = Date()
            payload["delivery"] = .string("live_ephemeral")
            payload["issued_at"] = .string(Self.utcNow(issued))
            payload["expires_at"] = .string(Self.utcNow(issued.addingTimeInterval(Double(Self.maxLiveEphemeralAgeMs) / 1000)))
            payload["max_age_ms"] = .uint(Self.maxLiveEphemeralAgeMs)
        }
        let env = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "remote.control.invoke",
            source: ACPEndpoint(nodeID: identity.nodeID),
            timestampUTC: Self.utcNow(),
            correlationID: UUID().uuidString.lowercased(),
            qos: .reliable,
            payload: payload
        )
        sentInvokes[sentKey] = env
        if live {
            ephemeralPending.insert(id)
        }
        if !viewState.pending.contains(id) {
            viewState.pending.append(id)
        }
        sentCount += 1
        if wait {
            let ack = try await session.request(env)
            applyAcknowledgement(invocationID: id, ack: ack)
        } else {
            _ = try await session.send(env)
        }
        return id
    }

    public func refreshMomentary(_ handle: ACPRemoteHoldHandle) async throws {
        let lease = handle.leaseID ?? leases[handle.invocationID]
        guard let lease else {
            throw ACPSessionError("invalid_type", "lease_id required")
        }
        let payload: [String: AnySendable] = [
            "control_id": .string(handle.controlID),
            "invocation_id": .string(handle.invocationID),
            "lease_id": .string(lease),
        ]
        let env = ACPEnvelope(
            acp: "1.2",
            messageID: UUID().uuidString.lowercased(),
            type: "remote.momentary.refresh",
            source: ACPEndpoint(nodeID: identity.nodeID),
            timestampUTC: Self.utcNow(),
            qos: .reliable,
            payload: payload
        )
        sentCount += 1
        _ = try await session.send(env)
    }

    public func markDisconnected() {
        viewState.stale = true
        viewState.readiness = .disconnected
        viewState.pending.removeAll()
        ephemeralPending.removeAll()
        leases.removeAll()
    }

    public var pendingInvocationIDs: [String] { viewState.pending }

    public static func isLiveEphemeral(interaction: ACPRemoteInteraction, action: String?, delivery: String?) -> Bool {
        if delivery == "live_ephemeral" { return true }
        if interaction == .momentaryBegin || interaction == .momentaryEnd || interaction == .momentaryCancel {
            return true
        }
        if let action {
            return ACPRemoteAction(rawValue: action).delivery == "live_ephemeral"
        }
        return false
    }

    public func beginMomentary(controlID: String) async throws -> ACPRemoteHoldHandle {
        let id = try await invoke(controlID: controlID, interaction: .momentaryBegin)
        return ACPRemoteHoldHandle(controlID: controlID, invocationID: id, leaseID: leases[id])
    }

    public func end(_ handle: ACPRemoteHoldHandle) async throws {
        _ = try await invoke(
            controlID: handle.controlID,
            interaction: .momentaryEnd,
            invocationID: handle.invocationID,
            leaseID: handle.leaseID ?? leases[handle.invocationID]
        )
    }

    public func applyAcknowledgement(invocationID: String, ack: ACPEnvelope) {
        viewState.pending.removeAll { $0 == invocationID }
        if case .string(let status) = ack.payload["status"], status == "rejected" || status == "failed" {
            if case .object(let err) = ack.payload["error"], case .string(let code) = err["code"] {
                errors[invocationID] = code
            } else {
                errors[invocationID] = status
            }
            return
        }
        guard case .object(let result) = ack.payload["result"] else { return }
        if case .string(let lease) = result["lease_id"] {
            leases[invocationID] = lease
        }
        if case .bool(false) = result["active"] {
            leases[invocationID] = nil
        }
        // ACK is command disposition and lease tracking only.
        // Operational values come from ACPRemoteStateStore publications.
    }

    public func acknowledge(invocationID: String) {
        viewState.pending.removeAll { $0 == invocationID }
    }

    private static func utcNow(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter.string(from: date)
    }
}
