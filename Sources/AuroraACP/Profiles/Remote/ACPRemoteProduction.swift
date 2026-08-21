import Foundation

public struct ACPRemotePrincipal: Sendable, Equatable {
    public var nodeID: String
    public var instanceID: String
    public var sessionID: String
    public init(nodeID: String, instanceID: String, sessionID: String) {
        self.nodeID = nodeID
        self.instanceID = instanceID
        self.sessionID = sessionID
    }
}

public struct ACPRemoteRouterResult: Sendable, Equatable {
    public var ok: Bool
    public var physicalActive: Bool
    public var releasePending: Bool
    public init(ok: Bool, physicalActive: Bool = false, releasePending: Bool = false) {
        self.ok = ok
        self.physicalActive = physicalActive
        self.releasePending = releasePending
    }
}

public protocol ACPRemoteActionRouting: Sendable {
    func apply(action: String, controlID: String) async -> ACPRemoteRouterResult
    func begin(action: String, controlID: String) async -> ACPRemoteRouterResult
    func end(action: String, controlID: String) async -> ACPRemoteRouterResult
    func forceRelease(action: String, controlID: String) async -> ACPRemoteRouterResult
}

public protocol ACPRemotePolicyProviding: Sendable {
    func roles(for nodeID: String) -> [String]
}

public struct ACPRemoteStaticPolicy: ACPRemotePolicyProviding {
    public var rolesByNode: [String: [String]]
    public init(rolesByNode: [String: [String]] = [:]) {
        self.rolesByNode = rolesByNode
    }
    public func roles(for nodeID: String) -> [String] {
        rolesByNode[nodeID] ?? ["remote.viewer"]
    }
}

public struct ACPRemoteMemoryRouter: ACPRemoteActionRouting {
    public init() {}
    public func apply(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true)
    }
    public func begin(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: true)
    }
    public func end(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: false)
    }
    public func forceRelease(action: String, controlID: String) async -> ACPRemoteRouterResult {
        _ = action; _ = controlID
        return ACPRemoteRouterResult(ok: true, physicalActive: false)
    }
}

public struct ACPRemoteHoldState: Sendable, Equatable {
    public var controlID: String
    public var invocationID: String
    public var leaseID: String
    public var principalNodeID: String
    public var expiresAtMs: UInt64
    public var releasePending: Bool
    public var physicalActive: Bool
}

/// Remote authority safety core. Policy is keyed by an authenticated transport
/// node ID, never client-claimed roles. A production host must derive the
/// principal from an established authenticated session and provide the
/// surrounding readiness, persistence, publication, and audit facilities.
public actor ACPRemoteAuthorityCore {
    private struct HoldKey: Hashable, Sendable {
        var principalNodeID: String
        var invocationID: String
    }
    private struct AppliedRecord: Sendable {
        var fingerprint: String
        var status: String
        var leaseID: String?
    }
    public private(set) var showID: String
    public private(set) var layoutID: String
    public private(set) var armed: Bool
    private var controls: [String: ACPRemoteControl]
    private var policy: any ACPRemotePolicyProviding
    private var router: any ACPRemoteActionRouting
    private var applied: [String: AppliedRecord] = [:]
    private let maxApplied = 1_024
    private var holds: [HoldKey: ACPRemoteHoldState] = [:]
    private var holdTimers: [HoldKey: Task<Void, Never>] = [:]
    private var nowMs: UInt64 = 0
    private var failRelease = false

    public init(
        showID: String,
        layout: ACPRemoteLayout,
        policy: any ACPRemotePolicyProviding,
        router: any ACPRemoteActionRouting,
        armed: Bool = true
    ) {
        self.showID = showID
        self.layoutID = layout.layoutID
        self.controls = Dictionary(uniqueKeysWithValues: layout.controls.map { ($0.controlID, $0) })
        self.policy = policy
        self.router = router
        self.armed = armed
    }

    public func simulatePhysicalReleaseFailure(_ fail: Bool) {
        failRelease = fail
    }

    public func advanceTime(_ deltaMs: UInt64) async {
        nowMs += deltaMs
        await expireHolds()
    }

    public func invoke(
        principal: ACPRemotePrincipal,
        controlID: String,
        invocationID: String,
        interaction: ACPRemoteInteraction,
        claimedRoles: [String] = [],
        leaseID: String? = nil
    ) async -> (status: String, code: String?, leaseID: String?, hold: ACPRemoteHoldState?) {
        _ = claimedRoles
        let holdKey = HoldKey(principalNodeID: principal.nodeID.lowercased(), invocationID: invocationID.lowercased())
        let key = "\(principal.nodeID)|\(invocationID)|\(interaction.rawValue)"
        let fingerprint = "\(controlID)|\(interaction.rawValue)|\(leaseID ?? "")"
        if let prev = applied[key] {
            guard prev.fingerprint == fingerprint else {
                return ("conflict", "command_identity_conflict", nil, holds[holdKey])
            }
            return (prev.status, nil, prev.leaseID, holds[holdKey])
        }
        if !armed { return ("rejected", "remote.control.not_armed", nil, nil) }
        guard let control = controls[controlID] else { return ("rejected", "remote.control.unknown", nil, nil) }
        let roles = Set(policy.roles(for: principal.nodeID))
        if !roles.contains(control.permission) && !roles.contains("remote.admin") {
            return ("rejected", "remote.control.permission_denied", nil, nil)
        }
        switch interaction {
        case .activate, .set, .adjust:
            guard remember(key: key, fingerprint: fingerprint, status: "in_flight", leaseID: nil) else {
                return ("rejected", "unavailable", nil, nil)
            }
            let result = await router.apply(action: control.action, controlID: controlID)
            let status = result.ok ? "applied" : "rejected"
            _ = remember(key: key, fingerprint: fingerprint, status: status, leaseID: nil)
            return (status, result.ok ? nil : "unavailable", nil, nil)
        case .momentaryBegin:
            if let existing = holds[holdKey] {
                return ("conflict", "command_identity_conflict", existing.leaseID, existing)
            }
            guard remember(key: key, fingerprint: fingerprint, status: "in_flight", leaseID: nil) else {
                return ("rejected", "unavailable", nil, nil)
            }
            let result = await router.begin(action: control.action, controlID: controlID)
            guard result.ok else {
                _ = remember(key: key, fingerprint: fingerprint, status: "rejected", leaseID: nil)
                return ("rejected", "unavailable", nil, nil)
            }
            let lease = UUID().uuidString.lowercased()
            let hold = ACPRemoteHoldState(
                controlID: controlID,
                invocationID: invocationID,
                leaseID: lease,
                principalNodeID: principal.nodeID,
                expiresAtMs: nowMs + control.maxHoldMs,
                releasePending: false,
                physicalActive: result.physicalActive
            )
            holds[holdKey] = hold
            scheduleExpiry(for: holdKey, leaseID: lease, afterMs: control.maxHoldMs)
            _ = remember(key: key, fingerprint: fingerprint, status: "applied", leaseID: lease)
            return ("applied", nil, lease, hold)
        case .momentaryEnd, .momentaryCancel:
            guard let hold = holds[holdKey] else {
                return ("rejected", "remote.momentary.unknown_invocation", nil, nil)
            }
            guard let leaseID, leaseID == hold.leaseID else {
                return ("rejected", "remote.momentary.unknown_invocation", nil, hold)
            }
            guard remember(key: key, fingerprint: fingerprint, status: "in_flight", leaseID: hold.leaseID) else {
                return ("rejected", "unavailable", hold.leaseID, hold)
            }
            let result = await release(holdKey, reason: "end")
            _ = remember(key: key, fingerprint: fingerprint, status: result.status, leaseID: hold.leaseID)
            return result
        }
    }

    public func disconnect(nodeID: String) async {
        let keys = holds.keys.filter { $0.principalNodeID == nodeID.lowercased() }
        for key in keys {
            _ = await release(key, reason: "disconnect")
        }
    }

    public func hold(invocationID: String) -> ACPRemoteHoldState? {
        let matches = holds.values.filter { $0.invocationID.caseInsensitiveCompare(invocationID) == .orderedSame }
        return matches.count == 1 ? matches[0] : nil
    }

    public func hold(principalNodeID: String, invocationID: String) -> ACPRemoteHoldState? {
        holds[HoldKey(principalNodeID: principalNodeID.lowercased(), invocationID: invocationID.lowercased())]
    }

    /// Rejects new mutations and releases every active hold through the same
    /// fail-safe path used for disconnect and expiry.
    public func shutdown() async {
        armed = false
        let keys = Array(holds.keys)
        for key in keys { _ = await release(key, reason: "shutdown") }
        for task in holdTimers.values { task.cancel() }
        holdTimers.removeAll()
    }

    public func setArmed(_ newValue: Bool) async {
        armed = newValue
        if !newValue {
            let keys = Array(holds.keys)
            for key in keys { _ = await release(key, reason: "disarm") }
        }
    }

    @discardableResult
    public func replaceLayout(_ layout: ACPRemoteLayout, showID: String) async -> Bool {
        let keys = Array(holds.keys)
        for key in keys { _ = await release(key, reason: "layout_change") }
        guard holds.isEmpty else { return false }
        self.showID = showID
        layoutID = layout.layoutID
        controls = Dictionary(uniqueKeysWithValues: layout.controls.map { ($0.controlID, $0) })
        return true
    }

    public func replacePolicy(_ newPolicy: any ACPRemotePolicyProviding) async {
        let keys = Array(holds.keys)
        for key in keys { _ = await release(key, reason: "policy_change") }
        policy = newPolicy
    }

    public func helloRoles(principal: ACPRemotePrincipal, claimed: [String]) -> [String] {
        _ = claimed
        return policy.roles(for: principal.nodeID)
    }

    @discardableResult
    private func remember(key: String, fingerprint: String, status: String, leaseID: String?) -> Bool {
        if applied[key] == nil, applied.count >= maxApplied { return false }
        applied[key] = AppliedRecord(fingerprint: fingerprint, status: status, leaseID: leaseID)
        return true
    }

    private func expireHolds() async {
        let due = holds.filter { $0.value.expiresAtMs <= nowMs && !$0.value.releasePending }.map(\.key)
        for key in due {
            _ = await release(key, reason: "expiry")
        }
    }

    private func scheduleExpiry(for key: HoldKey, leaseID: String, afterMs: UInt64) {
        holdTimers[key]?.cancel()
        holdTimers[key] = Task { [weak self] in
            do {
                let product = afterMs.multipliedReportingOverflow(by: 1_000_000)
                try await Task.sleep(nanoseconds: product.overflow ? UInt64.max : product.partialValue)
            } catch {
                return
            }
            await self?.expire(key, leaseID: leaseID)
        }
    }

    private func expire(_ key: HoldKey, leaseID: String) async {
        guard let hold = holds[key], hold.leaseID == leaseID, !hold.releasePending else { return }
        _ = await release(key, reason: "expiry")
    }

    private func release(_ key: HoldKey, reason: String) async -> (status: String, code: String?, leaseID: String?, hold: ACPRemoteHoldState?) {
        guard var hold = holds[key], let control = controls[hold.controlID] else {
            return ("rejected", "remote.momentary.unknown_invocation", nil, nil)
        }
        let result: ACPRemoteRouterResult
        if failRelease {
            result = ACPRemoteRouterResult(ok: false, physicalActive: true, releasePending: true)
        } else if reason == "end" {
            result = await router.end(action: control.action, controlID: hold.controlID)
        } else {
            result = await router.forceRelease(action: control.action, controlID: hold.controlID)
        }
        hold.releasePending = result.releasePending || !result.ok
        hold.physicalActive = result.physicalActive || hold.releasePending
        holds[key] = hold
        if !hold.releasePending && !hold.physicalActive {
            holds.removeValue(forKey: key)
            holdTimers.removeValue(forKey: key)?.cancel()
        }
        return ("applied", hold.releasePending ? "remote.control.unconfirmed_release" : nil, hold.leaseID, hold)
    }
}

@available(*, deprecated, message: "This is a safety core, not a complete session-hosted production authority. Use ACPRemoteAuthorityCore and supply the required authenticated host facilities.")
public typealias ACPRemoteProductionAuthority = ACPRemoteAuthorityCore
