# Prism ACP Integration and Legacy Remote Replacement Plan

**Status:** Approved implementation plan  
**Date:** 2026-08-19  
**ACP baseline:** ACP 1.2 plus the Remote Profile amendments  
**Primary consumer:** Aurora Prism  
**Related documents:** `docs/ACP_SPEC.md`, `docs/REMOTE.md`, `docs/STATE_MACHINES.md`, `DesignDocs/ACP_Remote_Profile_Amendments.md`, and `Aurora_ACP_Remote_Profile_Implementation_Spec.md`

## 1. Purpose

This document defines how Prism will replace its private remote-control implementation with the Aurora Communications Protocol (ACP).

This is a total replacement, not an additive integration or compatibility layer. Prism will have one remote network stack, one security model, one state authority, and one semantic command path: ACP.

The most important architectural rule is permanent:

> ACP wraps Prism's semantic control and authoritative state architecture. ACP must never bypass that architecture or leak into the lighting engine.

ACP and Aurora Remote must not directly mutate fixtures, programmer internals, DMX, Art-Net, sACN, MIDI drivers, output drivers, or private Prism engine models.

## 2. Scope

This plan covers:

- Stabilizing ACP for use by Prism.
- Adding a dedicated `PrismACP` integration module.
- Replacing Prism's legacy TCP and HTTP remote services.
- Replacing legacy authentication, sessions, commands, snapshots, and browser assets.
- Publishing event-driven, revisioned Prism state over ACP.
- Routing approved ACP actions through Prism's existing `ControlActionRouter`.
- Adding replay safety, preconditions, availability, provenance, audit history, priority, backpressure, and momentary leases.
- Testing real LAN, Bonjour, WebSocket, reconnection, and shutdown behavior.
- Proving the legacy stack is absent in source and at runtime.

This plan does not authorize:

- A second lighting, cue, show, or programmer engine.
- Raw remote DMX or fixture mutation.
- Downloaded executable behavior.
- A Prism-specific private protocol carried inside ACP.
- Preservation of the legacy remote wire protocol.
- Automatic migration of legacy PINs or session tokens.

## 3. Existing Prism Remote Stack

The current Prism implementation is a complete parallel remote stack, not a small placeholder. It includes:

- A newline-delimited JSON TCP protocol on port `8742`.
- An HTTP server and bundled browser UI on port `8743`.
- Private hello, command, snapshot, acknowledgement, and ping messages.
- PIN authentication, bearer tokens, roles, rate limits, and session tracking.
- A flat `RemoteSnapshot` generated and broadcast on a 200 ms timer.
- A private `RemoteProtocolClient`.
- Settings, status, diagnostics, and tests coupled to the private stack.

The implementation currently resides primarily under Prism's `Sources/AuroraRemote` target and is integrated through `RemoteController` and `AppModel`.

Useful product behavior may be preserved only as semantic behavior. The protocol, message formats, sessions, roles, authentication model, implementation structure, polling system, ports, and browser assets are not preserved.

## 4. Target Architecture

```text
ACP client / Aurora Remote
        |
        v
Bonjour discovery + ACP WebSocket listener
        |
        v
ACP session, negotiation, admission, sequencing, and correlation
        |
        v
Authenticated principal + Prism authorization policy
        |
        v
PrismACP host boundary
        |
        v
PrismACPActionRouter adapter
        |
        v
Existing Prism ControlActionRouter
        |
        v
Prism lighting, cue, show, and output authorities
        |
        v
Authoritative Prism state events
        |
        v
PrismACPStatePublisher
        |
        v
ACP snapshots, deltas, acknowledgements, health, and audit outcomes
```

The following path is forbidden:

```text
ACP -> programmer internals / fixtures / output drivers / raw DMX
```

### 4.1 Responsibility boundaries

ACP owns:

- Wire encoding and schema validation.
- Protocol and profile negotiation.
- Session identity, sequencing, and correlation.
- Registry admission and capability negotiation.
- Resource transfer framing.
- Generic Remote Profile semantics.
- Generic lease, deduplication, readiness, and subscription behavior.

Prism owns:

- Enrollment and authorization policy.
- Command availability and safety interlocks.
- Semantic action execution.
- Cue, show, song, busking, programmer, output, and health truth.
- Physical effect application and release confirmation.
- Product-specific Remote surfaces and action bindings.
- Product diagnostics and user-facing management UI.

Aurora Remote owns:

- Native presentation.
- Local navigation and accessibility state.
- Operator intent.
- Cache presentation while disconnected or synchronizing.
- Disabling controls whenever authoritative readiness is absent.

## 5. Non-Negotiable Invariants

1. Prism has exactly one remote stack: ACP.
2. All ACP mutations ultimately traverse `ControlActionRouter`.
3. A successful socket write never means an action was applied.
4. A command acknowledgement communicates disposition; authoritative state communicates truth.
5. Discovery is informational only and never grants trust or authority.
6. Client-claimed identities, roles, and permissions are untrusted until bound by server-owned policy.
7. Unknown messages, actions, targets, permissions, and safety classes fail closed.
8. ACP-disabled Prism is network silent for ACP.
9. Remote disconnection never changes show execution unless an explicit safety lease requires release.
10. Failed physical release is never reported as inactive.
11. No legacy listener, route, codec, credential, or compatibility path remains after cutover.
12. Prism consumes a pinned and tagged ACP revision, never an arbitrary working directory state.

## 6. ACP Contract Work Required Before Prism Cutover

Some requirements affect the shared ACP wire contract and must be implemented in ACP before Prism depends on them.

### 6.1 General state-domain model

Define stable logical Prism resource domains from the start:

```text
prism.show
prism.song
prism.performance
prism.cue
prism.looks
prism.programmer
prism.busk
prism.output
prism.music
prism.health
```

The first Prism release is required to populate only:

```text
prism.show
prism.performance
prism.cue
prism.output
prism.health
```

Subscriptions, permissions, snapshots, and delta routing must nevertheless support the general domain model immediately. Internal Prism types must be projected into stable ACP data-transfer values and must never be serialized directly.

The existence of `prism.programmer` as a future state domain does not authorize arbitrary remote programmer mutation. Any future programmer command requires an explicitly designed, narrow semantic action.

### 6.2 Authority epoch and revision semantics

The state contract is:

```text
authority_epoch
    Changes when the semantic state universe is replaced, the authority
    changes, or continuity can no longer be guaranteed.

revision
    Increases monotonically within one authority epoch.
```

Every snapshot carries:

```text
authority_epoch
revision
resources
```

Every delta carries:

```text
authority_epoch
base_revision
revision
changes
```

A receiver must reject a delta and request a fresh authorized snapshot when:

```text
delta.authority_epoch != local.authority_epoch
```

or:

```text
delta.base_revision != local.revision
```

Examples:

- Loading a different show changes the epoch and starts a new revision sequence.
- Losing authority continuity changes the epoch.
- Cue advancement increments the revision within the current epoch.
- Blackout changes increment the revision within the current epoch.
- Set-list edits increment the revision unless they replace the state universe.

Revision assignment must occur at the authoritative semantic commit boundary, not when a network message is queued or transmitted.

### 6.3 Replay-safe command disposition

ACP's command path must support recovery after a lost acknowledgement. Add or formalize a command disposition query such as:

```text
command.status_request
command.status_report
```

The provider retains a bounded command ledger containing at least:

```text
command_id
idempotency_key
origin_node_id
origin_instance_id
origin_principal
origin_session_id
operation
received_at
disposition
result
resulting_epoch
resulting_revision
expires_at
```

Ledger identity must survive replacement sessions for the defined retention window and must not depend solely on `session_id`.

Once-only semantics apply to at least:

- GO and BACK.
- Explicit cue firing.
- Song loading or selection.
- Look activation where replay is not harmless.
- Busk commits.
- Other state transitions whose duplication has consequences.

After reconnect, a client queries disposition before deciding whether retransmission is safe.

### 6.4 Command preconditions

Mutation messages may carry typed preconditions, initially limited to stable predicates such as:

```text
authority_epoch equals X
revision equals X
revision at_least X
show_id equals X
current_cue_id equals X
resource field equals X
```

Prism evaluates preconditions atomically with command admission. A failed predicate produces a stable `precondition_failed` disposition without executing the action.

GO should normally include the epoch and current cue observed by the client. This prevents an unseen local GO followed by an unintended second advance from Remote.

Preconditions remain action-specific:

- GO: strongly recommended.
- Absolute continuous-value set: often latest-value-wins.
- Momentary END: lease identity is mandatory.
- Recovery or emergency operations: may have explicitly different policy.

### 6.5 Capability and availability

Capability and current availability are separate concepts.

```text
Capability:
    prism.performance.go is supported by this endpoint.

Availability:
    prism.performance.go is currently unavailable because no show is loaded.
```

Capabilities normally remain stable for a negotiated session. Availability is authoritative state and may change frequently.

Initial availability reason codes should include:

- `no_show_loaded`
- `not_armed`
- `output_offline`
- `permission_denied`
- `wrong_mode`
- `sync_required`
- `interlock_active`
- `resource_unavailable`

Remote should render from capability plus availability rather than probing Prism with commands expected to fail.

### 6.6 Lease-based momentary controls

Momentary behavior is a first-class semantic pattern:

```text
BEGIN
    activation_id
    requested_lease_ms

GRANT
    activation_id
    lease_id
    granted_lease_ms
    renew_before_ms

RENEW
    activation_id
    lease_id

END / CANCEL
    activation_id
    lease_id
```

The authority owns expiration and physical release. Disconnect, expiry, shutdown, authorization removal, surface removal, policy change, and authority restart all enter the same durable release transaction.

Failed release must remain explicitly unsafe:

```text
release_pending = true
physical_active = true or unknown
```

It must never be published as confirmed inactive.

ACP 1.2 may retain these messages in the Remote Profile while documenting the behavior as a reusable ACP pattern. A move into ACP core requires an explicit protocol-version decision.

### 6.7 Provenance and audit history

Every accepted mutation has normalized origin metadata:

```text
node_id
instance_id
session_id
principal_id
command_id
source_type
display_name
```

Initial source types are:

```text
local_ui
remote
conductor
midi
music_engine
automation
bridge
system
```

Origin must be attached at Prism's semantic command boundary so local UI, MIDI, music automation, Conductor, and ACP actions share one provenance model.

Prism maintains a bounded rolling audit history containing at least:

```text
timestamp
origin
operation
target
disposition
resulting_epoch
resulting_revision
safety_outcome
```

Audit history must not retain credentials or unnecessary personal information.

### 6.8 Priority, backpressure, and coalescing

ACP traffic is classified at the application layer:

| Class | Examples | Required behavior |
|---|---|---|
| Safety/performance | Blackout, GO, momentary END | Reserved capacity; never coalesced |
| Interactive | Look activation, button and set operations | Bounded latency |
| State | Cue and output deltas | Coalesce by resource only when semantically safe |
| Background | Surfaces, manifests, asset chunks | Pause under pressure |
| Telemetry | Metrics and diagnostics | Aggregate or drop first |

TCP/WebSocket ordering does not eliminate the need for prioritized production and bounded queues. Background traffic must not occupy all capacity ahead of a performance command.

Continuous values can declare:

```text
coalescing_key = "prism.output.master"
delivery = latest_value_wins
```

GO, BACK, cue fire, momentary BEGIN, and momentary END must never be coalesced.

### 6.9 Semantic Remote surfaces

Remote surfaces should primarily describe semantic controls:

```text
control_id
action
label
category
control_type
safety_class
availability_binding
permission
value_constraints
presentation_hint
```

Pages, grouping, ordering, and restrained presentation hints are allowed. Prism must not transmit executable behavior, private model types, or a pixel-perfect serialized copy of its desktop UI.

Native clients decide how controls are rendered for iPhone, iPad, Mac, or future form factors. Rich asset-driven custom surfaces remain optional rather than foundational.

## 7. ACP Stabilization and Release Gate

Prism must not point at whichever ACP files happen to exist in a developer checkout.

Before Prism consumes ACP:

1. Complete the shared contract changes required by this plan.
2. Commit the current ACP working tree.
3. Resolve or explicitly gate outstanding Swift session findings.
4. Run schema and registry validation.
5. Verify all frozen JSON and CBOR vectors.
6. Run Python, Rust, and Swift unit tests.
7. Run negative handshake, invalid-message, sequence, and authorization tests.
8. Run cross-language established-session interoperability.
9. Run live Remote Profile interoperability against the production reference authority.
10. Tag an immutable development release, such as `0.9.0-dev1`.
11. Pin Prism to that exact ACP revision.

The current Swift `ACPRemoteAuthority` is explicitly a non-production simulator. Prism must not expose it to live show control.

The preferred direction is to implement the generic production Swift Remote authority in ACP, conform it to the Python reference authority, and inject Prism adapters. Generic Remote behavior must not be rebuilt inside Prism.

## 8. Prism Module Design

Create a new Prism target named `PrismACP`. Do not reuse the name `AuroraRemote`; a new name makes stale imports and accidental compatibility easier to detect.

Recommended structure:

```text
PrismACP/
|-- PrismACPService.swift
|-- PrismACPConfiguration.swift
|-- PrismACPIdentityStore.swift
|-- PrismACPWebSocketListener.swift
|-- PrismACPDiscoveryService.swift
|-- PrismACPAuthorizationPolicy.swift
|-- PrismACPStateSource.swift
|-- PrismACPStatePublisher.swift
|-- PrismACPActionRouter.swift
|-- PrismACPAvailabilityProvider.swift
|-- PrismACPCommandLedger.swift
|-- PrismACPAuditStore.swift
|-- PrismACPRemoteAdapters.swift
`-- PrismACPDiagnostics.swift
```

`PrismACP` depends on the pinned ACP libraries and Prism's semantic contracts. It must not depend directly on output drivers, view implementations, or private lighting-engine representations.

### 8.1 Prism-provided Remote adapters

Prism supplies:

```text
PrismRemotePolicy
PrismRemoteSurfaceProvider
PrismRemoteActionRouter
PrismRemoteStateSource
PrismRemoteHoldPersistence
```

ACP supplies the generic session, Remote semantics, deduplication, readiness, transfer, subscription, lease scheduling, and release behavior.

## 9. Legacy Removal Ledger

The following legacy Prism sources are removed rather than adapted:

```text
Sources/AuroraRemote/AuroraRemote.swift
Sources/AuroraRemote/RemoteHost.swift
Sources/AuroraRemote/RemoteListenerState.swift
Sources/AuroraRemote/RemoteMessages.swift
Sources/AuroraRemote/RemoteProtocolClient.swift
Sources/AuroraRemote/RemoteSessionManager.swift
Sources/AuroraRemote/RemoteWebServer.swift
Sources/AuroraRemote/Resources/Web/index.html
```

The old `RemoteController` is removed and replaced by `PrismACPController`. Remove the legacy `AuroraRemote` package product and target after all consumers have moved.

Remove from `AppModel` and related controllers:

- `RemoteHost` and `RemoteWebServer` ownership.
- `RemoteSnapshot` construction.
- `RemoteShowAction` bridging.
- Snapshot-provider closures.
- The 200 ms snapshot timer.
- Legacy TCP and web port state.
- PIN generation and handling.
- Legacy listener status reconciliation.

Remove the legacy test suite rather than mechanically rewriting it around similarly named types:

```text
Tests/AuroraRemoteTests/RemoteHardeningTests.swift
Tests/AuroraRemoteTests/RemoteProtocolClientTests.swift
Tests/AuroraRemoteTests/RemoteProtocolTests.swift
Tests/AuroraRemoteTests/RemoteRequestIdRaceTests.swift
Tests/AuroraRemoteTests/RemoteSessionExpiryTests.swift
Tests/AuroraRemoteTests/RemoteWebServerTests.swift
```

Replace those tests with ACP contract, adapter, authorization, state, transport, interoperability, and safety tests.

### 9.1 Browser remote

Delete the bundled browser remote and private HTTP API.

If browser control returns later, it must be a separate ACP client that uses the same ACP protocol and security model as native Remote. Prism must not restore private `/api/hello`, `/api/command`, or `/api/snapshot` routes.

### 9.2 Legacy credentials

Delete legacy PINs, bearer tokens, and ephemeral sessions. They must not become ACP credentials.

On upgrade:

- Stop listening on ports `8742` and `8743`.
- Invalidate and delete legacy tokens.
- Do not import the old PIN into ACP enrollment.
- Preserve an old "remote enabled" preference only if ACP can enter a safe, non-controlling enrollment state.
- Otherwise require explicit ACP enablement.

An upgrade must never transform an old PIN-based installation into an openly controllable ACP endpoint.

## 10. Prism Integration Phases

Development may briefly contain old and new code on an isolated branch, but no released Prism build may expose both network stacks.

### Phase 0: ACP contract and release stabilization

Complete Section 6 and Section 7. Produce a pinned ACP development release suitable for Prism.

Exit criteria:

- ACP working tree is committed and tagged.
- Swift session implementation is fail-closed.
- Schema and registry validation are active at the application boundary.
- Required unit, negative, and interoperability tests pass.
- Prism can resolve an immutable ACP package version.

### Phase 1A: package and loopback foundation

Add the pinned ACP Swift products and create `PrismACP`.

Implement:

- Persistent Prism ACP `node_id`.
- Per-launch `instance_id`.
- ACP service lifecycle.
- Connection supervision.
- Authorization-policy boundary.
- State-source and state-publisher boundaries.
- Structured diagnostics.
- Loopback session tests.

No control capability is advertised.

Exit criteria:

- Prism can start and stop the ACP service deterministically.
- ACP failure cannot affect show execution.
- No ACP work runs on the real-time output path.
- Session and state flow pass through loopback transports.

### Phase 1B: read-only LAN WebSocket and discovery

Add the real ACP WebSocket listener and Bonjour discovery early, while the endpoint is read-only.

Initially support:

```text
HELLO
NEGOTIATE
SUBSCRIBE
STATE_SNAPSHOT
STATE_DELTA
HEARTBEAT
GOODBYE
```

Exercise:

- Real Wi-Fi latency and stalls.
- Interface changes.
- Sleep and wake.
- AP roaming where practical.
- Bonjour loss and reappearance.
- Socket cancellation.
- Backpressure and bounded queues.
- Reconnection and epoch recovery.

Exit criteria:

- A real client discovers and connects to Prism over the LAN.
- The client reconstructs Prism state from snapshot plus deltas.
- Gaps and epoch changes force resynchronization.
- No mutation capability is negotiable.

### Phase 2: event-driven state architecture

Replace the polling `RemoteSnapshot` architecture with event-driven state publication.

Initially populate:

- `prism.show`
- `prism.performance`
- `prism.cue`
- `prism.output`
- `prism.health`

Prism semantic state commits trigger revision assignment and publication. Subscription filtering, permissions, capability filtering, backpressure, and gap handling occur before fanout.

Exit criteria:

- No 200 ms remote snapshot timer remains.
- Identical state can be reconstructed from a snapshot followed by deltas.
- Forced gaps recover deterministically.
- State publication cannot block the lighting or output engine.

### Phase 3: narrow semantic control

Introduce actions in this order:

1. GO in non-live or test projects.
2. Explicit cue fire.
3. One non-momentary look or busking action.
4. Continuous controls with coalescing.
5. Production GO after ledger and precondition validation.

Every mutation follows:

```text
ACP admission
-> authentication and authorization
-> capability and availability
-> command precondition
-> PrismACPAction
-> ControlActionRouter
-> retained command disposition
-> authoritative state publication
```

Initial semantic mapping from useful legacy behavior may include:

| Legacy behavior | ACP semantic replacement |
|---|---|
| GO | `performance.go` |
| BACK | `performance.back` |
| STOP | `performance.stop` |
| Explicit cue fire | Semantic cue invocation |
| Song next/previous | Remote navigation request |
| Master intensity | Coalescible semantic value control |
| Blackout on/off | Safety-class semantic control |
| Programmer attribute | Unsupported until separately designed |

Semantic parity does not require wire or implementation compatibility.

### Phase 4: production Remote Profile authority

Implement and verify the generic production Swift Remote authority in ACP. Prism injects only its product adapters.

Required behavior includes:

- Authenticated `remote.hello`.
- Server-derived roles and permissions.
- Semantic surface and schema negotiation.
- Chunked asset transfer and activation.
- Layout and snapshot acknowledgement.
- Readiness gating.
- Subscription-filtered fanout.
- Command deduplication across replacement sessions.
- Action routing through the Prism adapter.
- Durable hold persistence and release.
- Reconnect and authority-epoch recovery.

### Phase 5: leased momentary controls

Begin with a harmless test momentary before enabling fog, blinders, strobe, bumps, or flash controls.

Required scenarios:

- BEGIN with a lost acknowledgement.
- Duplicate BEGIN.
- Renewal before deadline.
- END on all normal termination paths.
- Gesture cancellation.
- Page or control removal.
- Dirty disconnect.
- Lease expiry without inbound traffic.
- Prism shutdown.
- Authorization removal.
- Surface or policy replacement.
- Restart with a persisted active hold.
- Simulated physical release failure.

No safety-relevant momentary control ships until every release path is verified.

### Phase 6: safety-sensitive actions

Blackout receives an independent safety review. It must be:

- Idempotent.
- Acknowledged.
- Audited.
- Reflected in authoritative state.
- Persistent across reconnect.
- Protected against unintended clearing.
- Independent of multicast discovery.
- Available locally when ACP fails.

### Phase 7: legacy cutover and deletion

After approved semantic parity and ACP safety gates are complete:

1. Disable legacy listeners unconditionally.
2. Remove the entire `AuroraRemote` implementation and resources.
3. Replace `RemoteController` with `PrismACPController`.
4. Remove legacy settings and credentials.
5. Remove legacy tests and documentation claims.
6. Remove ports `8742` and `8743` from application code and configuration.
7. Remove all private HTTP routes and the bundled browser UI.
8. Run the source and runtime removal gates in Section 14.
9. Release Prism with ACP as its only remote implementation.

## 11. PrismACP Controller and Settings

`PrismACPController` is responsible for:

- Starting and stopping the ACP endpoint.
- Reporting actual listener, discovery, and session state.
- Managing enrollment and authorization policy.
- Exposing authenticated connected clients.
- Revoking one or all clients.
- Publishing ACP diagnostics.
- Coordinating safe lifecycle transitions.

It must not construct snapshots on a timer.

Replace the legacy settings surface:

```text
Remote enabled
PIN
TCP port
Web port
Bind policy
Viewer lock
Web URL
```

with:

```text
ACP remote access enabled
Endpoint identity
Discovery enabled
ACP WebSocket port
Network scope
Enrollment mode
Trusted or enrolled clients
Default permission policy
Revoke all clients
Connection and readiness status
```

## 12. Lifecycle Requirements

Lifecycle ordering is explicit because it affects security and momentary safety.

### 12.1 Startup

1. Load or create the stable ACP node identity.
2. Create the per-launch instance identity.
3. Load enrollment, authorization, and revocation policy.
4. Load command-ledger and hold-recovery state.
5. Reconcile and release any persisted unsafe holds.
6. Initialize authoritative state and authority epoch.
7. Create the listener in a non-advertised state.
8. Begin accepting only after policy and state sources are ready.
9. Start Bonjour discovery last.

Prism must not advertise an endpoint that is not ready to authenticate and synchronize clients safely.

### 12.2 Shutdown

1. Stop discovery first.
2. Stop accepting new sessions.
3. Mark the authority unavailable and reject new mutations.
4. Execute the durable release transaction for active momentaries.
5. Flush final safety outcomes and critical errors where possible.
6. Close active sessions.
7. Stop transfers and background publication.
8. Stop the listener.
9. Persist final command-ledger, audit, and hold state as required.

### 12.3 Disabled state

When ACP is disabled, Prism has:

- No ACP discovery advertisement.
- No ACP listener.
- No active ACP sessions.
- No resumable live-ephemeral commands.
- No active resource transfers.
- No renewable Remote leases.
- No background ACP network activity.

Persisted unsafe release records may remain for local recovery and warning presentation, but they must not imply an active network service.

## 13. Testing Strategy

### 13.1 Unit and contract tests

- Every ACP-to-Prism semantic action mapping.
- Every capability and availability rule.
- Epoch and revision transitions.
- Snapshot and delta reconstruction.
- Command ledger insertion, replay, expiry, and query.
- Preconditions and race rejection.
- Authorization and revocation.
- Priority queue capacity and ordering.
- Continuous-value coalescing.
- Momentary lease state machine.
- Audit and provenance generation.
- ACP schema, registry, and golden-vector compatibility.

### 13.2 Interoperability tests

- Python reference client to Prism Swift host.
- Swift Remote client to Prism Swift host.
- JSON and CBOR where negotiated.
- Real established-session application envelopes, not handshake-only tests.
- Resource transfer, activation, snapshot, delta, acknowledgement, and command-status recovery.

### 13.3 Network and lifecycle tests

- Real LAN discovery and connection.
- Wi-Fi interruption and recovery.
- Interface switching.
- Sleep and wake.
- Slow receiver and queue saturation.
- Resource transfer during a performance command.
- Dirty disconnect with active momentaries.
- Disable ACP with active clients.
- Prism shutdown with active momentaries.
- Authority restart and epoch replacement.

### 13.4 Safety tests

- Duplicate GO cannot advance twice.
- GO with a stale cue precondition is rejected.
- A lost ACK is resolved through command-status query.
- Expired live-ephemeral commands never replay.
- Momentary effects release after disconnect or expiry.
- Failed physical release stays unsafe and visible.
- Blackout is never cleared by reconnect.
- ACP failure cannot prevent local Prism control.

## 14. Final Removal Gate

Replacement is incomplete until both source and runtime checks pass.

### 14.1 Source gate

Active production code must contain no references to:

```text
AuroraRemote
RemoteHost
RemoteWebServer
RemoteSessionManager
RemoteProtocolClient
RemoteClientMessage
RemoteServerMessage
RemoteCodec
RemoteSnapshot
RemoteShowAction
remotePIN
8742
8743
/api/hello
/api/command
/api/snapshot
```

Historical documents may retain clearly identified historical references. Active architecture, product, setup, and testing documentation must describe ACP as Prism's only remote system.

### 14.2 Runtime gate

Launch Prism and verify:

- No listener exists on port `8742`.
- No listener exists on port `8743`.
- No legacy HTTP health, hello, command, or snapshot route responds.
- No bundled browser remote is served.
- Only the configured ACP endpoint is advertised.
- ACP disabled produces no ACP listener or discovery advertisement.
- Disabling ACP closes sessions and transfers and safely releases momentaries.
- No legacy credentials authorize an ACP session.

### 14.3 Architecture gate

Code review must prove:

- Every ACP mutation enters `ControlActionRouter` or an explicitly approved semantic authority at the same boundary.
- No ACP target depends directly on output drivers or UI view types.
- No independent Remote state can disagree with Prism authority.
- State revisions advance only from semantic commits.
- Generic Remote behavior remains in ACP rather than Prism.
- No compatibility shim preserves the private protocol.

## 15. Initial Delivery Milestone

The first delivery milestone is:

> Prism pinned to a tagged ACP development release, serving a real read-only ACP WebSocket endpoint over the LAN, with Bonjour discovery, heartbeat, domain subscriptions, and epoch/revision-correct snapshots and deltas for show, performance, cue, output, and health.

This milestone deliberately exercises real networking, state projection, lifecycle, backpressure, and diagnostics without allowing ACP to alter live output.

## 16. Completion Criteria

The integration is complete when:

- Prism ships one remote network stack: ACP.
- `PrismACP` is the only Prism remote integration module.
- The legacy TCP, HTTP, browser, codec, session, authentication, polling, and client code is deleted.
- Ports `8742` and `8743` are closed at runtime.
- Legacy credentials are deleted and cannot authorize ACP.
- Prism state is event-driven, domain-based, and epoch/revision correct.
- Approved actions use one semantic `ControlActionRouter` path.
- Once-only commands are recoverable and replay-safe.
- Preconditions prevent stale-view races.
- Capability and availability are separately published.
- Momentary effects are lease-based and fail safe.
- Actions retain provenance and appear in bounded audit history.
- Performance traffic is protected from background and telemetry pressure.
- Continuous values coalesce safely.
- Remote surfaces remain semantic and client-rendered.
- Real LAN, reconnect, lifecycle, interoperability, and safety tests pass.
- ACP disabled is network silent.
- Source, runtime, and architecture removal gates pass.

The resulting system preserves the Aurora family architecture: ACP transports authenticated semantic intent, Prism remains authoritative for execution and state, and future Conductor or Remote implementations can use the same generic protocol infrastructure without inheriting Prism's private implementation details.
