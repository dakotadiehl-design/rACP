import Foundation

/// Production Remote client façade. Command results are disposition only;
/// operational truth comes from provider-published state (PR 4).
public actor ACPRemoteClient {
    public let session: ACPSession
    public let identity: ACPRemoteIdentity
    public let commands: ACPRemoteSession
    public private(set) var handshakeComplete = false
    public private(set) var ready = false
    public private(set) var state = ACPRemoteStateStore()
    public private(set) var activatedSurface: ACPRemoteLayout?
    public private(set) var skippedControlIDs: [String] = []
    public private(set) var lastSurfaceError: String?

    public init(session: ACPSession, identity: ACPRemoteIdentity) {
        self.session = session
        self.identity = identity
        self.commands = ACPRemoteSession(session: session, identity: identity)
    }

    public func configureSession() async {
        await session.setProfiles(["core", "remote", ACPRemoteProfileID.prismV1.rawValue])
        await session.setCapabilities(ACPCapabilitySet.prismRemoteClient)
    }

    public func handshake() async throws {
        await configureSession()
        _ = try await session.handshake()
        try await verifyNegotiated()
        handshakeComplete = true
    }

    public func verifyNegotiated() async throws {
        let profiles = await session.negotiatedProfiles
        guard profiles.contains(ACPRemoteProfileID.prismV1.rawValue) else {
            ready = false
            throw ACPSessionError("unsupported_version", "aurora.remote.prism.v1 was not negotiated")
        }
        let caps = Set(await session.negotiatedCapabilities)
        for id in ACPCapabilitySet.prismRemoteRequiredIDs where !caps.contains(id) {
            ready = false
            throw ACPSessionError("capability_not_permitted", "missing required capability \(id)")
        }
    }

    public func applyPublication(_ envelope: ACPEnvelope) throws {
        try state.apply(envelope)
        if !state.stale && !state.needsSnapshot && handshakeComplete {
            ready = true
        }
    }

    public func markInterrupted() async {
        state.markInterrupted()
        ready = false
        await commands.markDisconnected()
    }

    /// Resynchronize after reconnect. Never replays prior user commands.
    public func resyncFromSnapshot(_ envelope: ACPEnvelope) throws {
        try state.apply(envelope)
        if !state.stale && !state.needsSnapshot && handshakeComplete {
            ready = true
        }
    }

    /// Native Show/GO/Master/Blackout/monitoring do not depend on a dynamic surface.
    public var nativeControlsAvailable: Bool { handshakeComplete }

    public func activateSurface(_ object: [String: AnySendable]) throws {
        switch ACPRemoteSurfaceValidator.evaluate(object) {
        case .accepted(let layout, let skipped):
            activatedSurface = layout
            skippedControlIDs = skipped
            lastSurfaceError = nil
        case .rejected(let reason):
            lastSurfaceError = reason
            throw ACPSessionError("remote.layout.incompatible", reason)
        }
    }

    public func canInvoke(controlID: String) -> Bool {
        if skippedControlIDs.contains(controlID) { return false }
        if let control = activatedSurface?.control(controlID) {
            return ACPRemoteSurfaceValidator.isInvocable(control)
        }
        return false
    }

    public func nativeActionAvailable(_ action: ACPRemoteAction) -> Bool {
        nativeControlsAvailable && ACPRemoteSurfaceValidator.nativeActions.contains(action)
    }
}
