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

/// Production Remote authority. Policy is keyed by authenticated transport node ID, never client-claimed roles.
public actor ACPRemoteProductionAuthority {
    public var showID: String
    public var layoutID: String
    public var armed: Bool
    private var controls: [String: ACPRemoteControl]
    private var policy: any ACPRemotePolicyProviding
    private var router: any ACPRemoteActionRouting
    private var applied: [String: String] = [:]
    private var holds: [String: ACPRemoteHoldState] = [:]
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
        let key = "\(principal.nodeID)|\(invocationID)|\(interaction.rawValue)"
        if let prev = applied[key] {
            return (prev, nil, holds[invocationID]?.leaseID, holds[invocationID])
        }
        if !armed { return ("rejected", "remote.control.not_armed", nil, nil) }
        guard let control = controls[controlID] else { return ("rejected", "remote.control.unknown", nil, nil) }
        let roles = Set(policy.roles(for: principal.nodeID))
        if !roles.contains(control.permission) && !roles.contains("remote.admin") {
            return ("rejected", "remote.control.permission_denied", nil, nil)
        }
        switch interaction {
        case .activate, .set, .adjust:
            let result = await router.apply(action: control.action, controlID: controlID)
            let status = result.ok ? "applied" : "rejected"
            applied[key] = status
            return (status, result.ok ? nil : "unavailable", nil, nil)
        case .momentaryBegin:
            let result = await router.begin(action: control.action, controlID: controlID)
            guard result.ok else { return ("rejected", "unavailable", nil, nil) }
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
            holds[invocationID] = hold
            applied[key] = "applied"
            return ("applied", nil, lease, hold)
        case .momentaryEnd, .momentaryCancel:
            guard let hold = holds[invocationID] else {
                return ("rejected", "remote.momentary.unknown_invocation", nil, nil)
            }
            if let leaseID, leaseID != hold.leaseID {
                return ("rejected", "remote.momentary.unknown_invocation", nil, hold)
            }
            return await release(invocationID, reason: "end")
        }
    }

    public func disconnect(nodeID: String) async {
        for (id, hold) in holds where hold.principalNodeID == nodeID {
            _ = await release(id, reason: "disconnect")
        }
    }

    public func hold(invocationID: String) -> ACPRemoteHoldState? {
        holds[invocationID]
    }

    public func helloRoles(principal: ACPRemotePrincipal, claimed: [String]) -> [String] {
        _ = claimed
        return policy.roles(for: principal.nodeID)
    }

    private func expireHolds() async {
        let due = holds.filter { $0.value.expiresAtMs <= nowMs && !$0.value.releasePending }.map(\.key)
        for id in due {
            _ = await release(id, reason: "expiry")
        }
    }

    private func release(_ invocationID: String, reason: String) async -> (status: String, code: String?, leaseID: String?, hold: ACPRemoteHoldState?) {
        guard var hold = holds[invocationID], let control = controls[hold.controlID] else {
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
        holds[invocationID] = hold
        if !hold.releasePending && !hold.physicalActive {
            holds.removeValue(forKey: invocationID)
        }
        let status = hold.releasePending ? "applied" : "applied"
        return (status, hold.releasePending ? "remote.control.unconfirmed_release" : nil, hold.leaseID, hold)
    }
}
