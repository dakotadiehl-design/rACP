# Prism ACP Remote Profile Live-Test Remediation

Status: implementation directive based on a live, non-destructive ACP Workbench audit on 2026-08-20.

## 1. Purpose

This document details the changes required in Prism to complete its ACP Remote/Prism profile integration. Prism must continue consuming the canonical `AuroraACP` Swift package for transport, framing, encoding, session negotiation, envelopes, validation, and shared protocol models. Prism must implement the product-specific production authority that connects those protocol facilities to its loaded document, authorization policy, semantic action router, and authoritative state.

The observed defects are primarily in Prism's use of the library, not in ACP session or codec behavior.

## 2. Live evidence

ACP Workbench connected to the running Prism process at:

```text
ws://127.0.0.1:27421/acp
```

No GO, blackout, busking, lighting, navigation, or momentary control was invoked.

### 2.1 Passed

- WebSocket upgrade and framing
- ACP 1.2 session handshake
- CBOR selection
- Session identity, session ID, and sequencing
- `core` profile negotiation
- `remote` and `aurora.remote.prism.v1` profile negotiation
- `state.request` handling
- Correlated `state.snapshot` response
- Graceful disconnect

These results demonstrate that the Swift ACP library is successfully carrying and decoding traffic for Prism.

### 2.2 Failed Remote synchronization

The Remote-profile attempt completed the ACP session handshake, then sent `remote.hello`. Prism sent no response, and Workbench timed out after five seconds.

Evidence:

```text
session.hello
<- session.hello_ack (accepted, ACP 1.2, CBOR,
   profiles: core, remote, aurora.remote.prism.v1)
remote.hello ->
[no remote.hello_ack]
[timeout]
```

Transcript:

```text
tools/acp-workbench/artifacts/prism-connection.jsonl
```

### 2.3 Passed core audit with incorrect product state

The core inspector successfully requested and received a snapshot. Prism published:

```text
prism.show:
  name: Untitled Show
  show_id: unidentified

prism.performance:
  engine_running: true
  master_intensity: 1.0
  blackout: false

prism.cue:
  current_cue_id: ""
  next_cue_id: ""

prism.output:
  status: "Output: Null only"

prism.health:
  status: ok

authority_epoch: 1
revision: 0
```

The open project was reported by the operator as:

```text
/Users/dakota/code/Aurora/smoketest files/HaywireFullRig.prism
```

Therefore, the ACP state bridge was alive but was not synchronized to the loaded Prism document.

Transcript:

```text
tools/acp-workbench/artifacts/prism-core-connection.jsonl
```

## 3. Confirmed Prism defects

### 3.1 `remote.hello` is silently ignored

File:

```text
/Users/dakota/code/Aurora/Sources/PrismACP/PrismACPService.swift
```

`PrismACPService.handle(_:session:)` currently handles:

- `state.request`
- `command.execute`
- `remote.control.invoke`

It has no `remote.hello` case. The empty `default` branch silently discards the message, producing the observed timeout.

Required fix:

1. Add a production Remote-session context owned by Prism and keyed by the authenticated ACP session ID.
2. Handle `remote.hello` only after ACP session establishment and successful negotiation of `aurora.remote.prism.v1`.
3. Treat all client identity, device, Remote ID, requested roles, and capabilities as untrusted claims.
4. Derive effective roles and permissions from Prism-owned policy bound to the authenticated ACP node/transport principal.
5. Return a correlated `remote.hello_ack` for both acceptance and rejection.
6. On acceptance, include the active show ID/revision and assigned surface ID/revision when available.
7. Publish `remote.permissions` and the initial server-computed readiness state.
8. Never silently ignore a known request. Return a correlated rejection/error for unsupported or invalid input.

Acceptance criteria:

- Workbench receives `remote.hello_ack` within the configured timeout.
- The response correlation ID matches the request message/correlation ID.
- Claimed `remote.admin` does not grant admin access unless Prism policy grants it.
- An unknown or unenrolled Remote receives a stable rejection rather than a timeout.

### 3.2 Capability advertisement is incomplete

`PrismACPService.sessionCapabilities()` currently filters out Remote control capabilities and conditionally adds only a small subset. During the live test, the intersection contained only:

```text
health.heartbeat 1.0
resource.transfer 1.2
remote.profile 1.0
```

Required fix:

- Advertise only capabilities that Prism truly implements, but include every implemented Remote capability needed by the chosen synchronization path.
- Do not negotiate `aurora.remote.prism.v1` while omitting all messages required to complete its minimum handshake, unless the profile explicitly supports a discovery-only subset.
- Keep observation capabilities independent from mutation permission. A view-only Remote should still be able to negotiate hello, permissions, surface, readiness, and authorized state.
- `advertiseControl == false` must disable or reject mutations without disabling Remote profile synchronization and monitoring.

Expected minimum implementation capabilities for the first usable Remote profile:

```text
remote.profile
remote.layout
remote.readiness
remote.control.state
remote.presentation
remote.asset_sync
resource.transfer
state.live
system.health
```

Add control/navigation capabilities only when their handlers and authoritative publications are implemented:

```text
remote.control.invoke
remote.control.momentary
remote.navigation.song
remote.navigation.section
remote.navigation.cue
remote.transport
remote.busking
show.navigation
song.selection
song.loading
cue.go
cue.selection
look.global
busk.controls
control.momentary
output.blackout
output.grand_master
```

Acceptance criteria:

- The capabilities in `session.hello_ack` match the actual handlers enabled for that session.
- View-only mode completes synchronization and rejects mutations explicitly.
- Control-enabled mode never advertises a capability whose request Prism silently ignores.

### 3.3 Loaded-document state is not reaching ACP

`PrismACPService.noteAuthoritativeState(_:)` and `lastState` exist, but the live snapshot remained at the placeholder `Untitled Show` / `unidentified`, revision 0.

Required fix:

1. Identify the Prism document/application state owner for the active `.prism` project.
2. On document open, close, replacement, and material state changes, construct a complete `PrismACPAuthoritativeState` and pass it to `noteAuthoritativeState(_:)`.
3. Ensure the initial loaded document is published if ACP is enabled after the document is already open.
4. Ensure the latest state is published if a document opens after ACP starts.
5. Advance the authority epoch on authority/document replacement according to ACP rules.
6. Advance revisions monotonically for each committed authoritative change.
7. Do not publish the requested command value optimistically. Publish only state read back from Prism's authoritative model after successful semantic application.

The initial snapshot should at minimum contain:

- Stable show/project ID and human-readable name
- Current and next song
- Current and next section/cue where defined
- Transport/progression state
- Current global look
- Master Dimmer value
- Blackout state
- Engine status
- Output/DMX health
- Important warnings

Acceptance criteria:

- With `HaywireFullRig.prism` open, `state.snapshot` identifies Haywire rather than `Untitled Show`.
- Closing or replacing the document changes epoch/state coherently.
- Current/next and output state agree with Prism's visible authoritative UI/model.
- Repeated snapshots without a state change do not fabricate revision advances.

### 3.4 Remote surface/layout synchronization is missing

Prism currently has no observed handlers for the Remote layout/surface workflow.

Required handlers and behavior:

- `remote.layout.request`
- `remote.layout.report`
- `resource.offer`
- `resource.accept` / `resource.reject`
- `resource.chunk`
- `resource.complete`
- `resource.activate`
- `resource.activation_result`

Prism should use the production chunked `aurora.remote.surface` asset flow by default. Inline layout bodies may be supported only as the negotiated compatibility path.

The surface must be generated from the active Prism project and authorization context. It must not grant permission; its `permission` fields only add UI constraints to server-owned policy.

The Haywire test surface should expose stable controls for the implemented subset of:

- Start/load/stop song
- Direct setlist selection
- Previous/next song
- GO
- Previous/next/restart section
- Hold/pause automatic progression
- Master Dimmer
- Explicit desired Blackout state
- Stop active effects
- Project Global Looks
- Enter/exit Free Play
- Project Busk controls
- Momentary fog, blinders, strobes, and similar effects

Acceptance criteria:

- Workbench receives and validates a complete surface.
- Surface hash and revision match the activated content.
- Cached identical surfaces are acknowledged without unnecessary transfer.
- Same-revision/different-content surfaces are rejected.
- Removed or changed momentary controls are safely released before activation.

### 3.5 Snapshot/readiness synchronization is missing

Sending layout and state is delivery, not acknowledgement. Prism must keep the Remote session non-interactive until the client acknowledges the exact delivered assets and snapshot.

Required fix:

1. After accepted `remote.hello`, set readiness to `syncing_assets` and/or `syncing_state`.
2. Deliver permissions, surface, presentation/navigation state, and control snapshot.
3. Track the layout revision/hash and snapshot revision delivered to each session.
4. Handle `remote.readiness` as the client's observation and acknowledgement.
5. Compute final readiness server-side.
6. Enter `ready` only when the client's acknowledged values match the delivered values and policy permits interaction.
7. On a revision gap, reconnect, authority epoch change, or surface mismatch, mark state stale and require fresh reconciliation.

Acceptance criteria:

- Workbench progresses through synchronization to `ready`.
- Incorrect layout hash/revision or snapshot revision does not become ready.
- A session gap forces resynchronization.
- Safety-sensitive controls stay disabled while stale or syncing.

### 3.6 Control invocation is not yet profile-complete

Prism has a limited `remote.control.invoke` handler with hard-coded control IDs. It accepts only `activate`, `set`, and `adjust`; momentary interactions are rejected. The requested product feature set requires more complete behavior.

Required fix:

- Resolve `control_id` against the active, versioned surface rather than a global hard-coded alias list alone.
- Verify authenticated session, accepted Remote hello, readiness, active surface revision/hash, show ID/revision, control availability, effective role/permission, safety prerequisites, and interaction validity.
- Route semantic actions through Prism's existing control architecture.
- Send terminal `command.ack` only after semantic application returns a disposition.
- Include the resulting snapshot revision in successful results when applicable.
- Publish the authoritative resulting state separately.
- Preserve idempotency for GO, song activation, blackout, toggles, and momentary operations.
- Enforce expiry for live-ephemeral GO/navigation requests.
- Return stable dispositions such as `unauthorized`, `unsupported`, `invalid_state`, `stale`, `expired`, `conflict`, `not_found`, and `rate_limited`.

Core invariant:

```text
Remote intent
  -> Prism admission and semantic application
  -> correlated command disposition
  -> Prism authoritative state publication
  -> Remote confirmed view update
```

A socket write or `command.ack` alone must never be treated as authoritative state.

### 3.7 Momentary controls and fail-safe behavior are incomplete

`PrismACPRemoteActionBridge.begin` currently returns success without demonstrated physical routing, and Prism's service rejects `momentary_begin` / `momentary_end` in its direct handler.

Required fix:

- Implement `momentary_begin`, exact-lease `momentary_end`, `momentary_cancel`, and `remote.momentary.refresh`.
- Bind every hold to authenticated session, node, invocation ID, control ID, lease ID, and surface/show revision.
- Require `max_hold_ms > 0` for failsafe-required controls.
- Own the expiry scheduler in Prism; it must not depend on inbound traffic.
- Release on normal END, cancellation, disconnect, lease expiry, policy/layout change, disarm, shutdown, and restart recovery.
- Publish confirmed inactive state only after the Prism/hardware release succeeds.
- If physical release fails, retain `physical_active` / `release_pending`, publish unverified unsafe state, and emit a critical error/health warning.
- Support concurrent holders without allowing one session's END to release another session's hold.

Acceptance criteria:

- Workbench momentary BEGIN/refresh/END scenario passes.
- Dirty disconnect results in authoritative release.
- Expiry occurs without further inbound messages.
- Failed release is never displayed as inactive.

### 3.8 Navigation, presentation, monitoring, and warnings are incomplete

Required Prism behavior:

- Handle authorized `remote.navigation.request` for browse, select, load, next, previous, and GO.
- Keep browsing/selection separate from live activation.
- Publish current/next song and section/cue through Remote navigation/presentation state or generic ACP state resources.
- Publish Master Dimmer, Blackout, current look, progression/transport state, output health, connection health, and important warnings.
- Mark state stale on disconnect/gaps and require reconciliation.
- Never advance Remote's current/next state locally merely because GO was sent or acknowledged.

## 4. Recommended Prism architecture

Do not grow the existing `switch` into a second protocol engine. Keep `ACPSession` as the session/transport authority and introduce a Prism-owned production Remote host with clear responsibilities:

```text
PrismACPService
  -> ACPSession (AuroraACP library)
  -> PrismRemoteSessionHost
       -> authenticated per-session context
       -> hello / permissions / readiness
       -> surface transfer
       -> subscriptions and fanout
       -> invocation and navigation dispatch
       -> momentary lease scheduler
  -> PrismACPActionRouter
       -> existing Prism semantic control paths
  -> PrismACPStateAdapter
       -> loaded document and live engine state
       -> authoritative snapshots/deltas
  -> PrismACPAuthorizationPolicy
       -> server-owned effective roles/permissions
```

The Swift package's `ACPRemoteAuthority` is documented as a non-production simulator. Do not quietly expose it as Prism's production authority. Reuse its shared models/interfaces where appropriate, but Prism must own durable safety, application routing, state adaptation, and policy.

## 5. Recommended implementation order

### Checkpoint 1: observation-only correctness

1. Fix loaded-document state propagation.
2. Add `remote.hello` / `remote.hello_ack`.
3. Add effective view-only permissions.
4. Add surface delivery.
5. Add state/control snapshot and readiness acknowledgement.
6. Keep all mutation capabilities disabled.

Exit test:

```bash
acp-workbench connect \
  --target ws://127.0.0.1:27421/acp \
  --profile remote-prism \
  --allow-plaintext \
  --duration 1 \
  --transcript prism-view-only.jsonl
```

Expected: `ready`, correct Haywire state, dynamic controls visible but disabled according to policy, no timeout.

### Checkpoint 2: discrete/value controls

1. Enable and advertise only implemented control capabilities.
2. Resolve controls through the active surface.
3. Route GO, song/show actions, looks, Master Dimmer, Blackout, stop-effects, Free Play, and Busk actions.
4. Publish authoritative results.
5. Add idempotency, expiry, authorization, and stale-state rejection.

Exit tests:

- GO disposition plus authoritative current/next publication
- Explicit Blackout set plus authoritative output state
- Master Dimmer set plus authoritative clamped/applied value
- Unauthorized and stale-state rejection
- Duplicate GO does not double-advance

### Checkpoint 3: momentary safety

1. Implement leases and monotonic scheduler.
2. Implement all release paths and durable recovery.
3. Publish unsafe/unverified state on failed release.
4. Run dirty-disconnect and expiry tests.

### Checkpoint 4: complete product feature matrix

Instantiate Workbench scenarios using the stable IDs published by `HaywireFullRig.prism` for all required Song & Show, Lighting, Busking, Monitoring, and Feedback features.

## 6. Required Prism tests

Add Prism-side unit/integration tests for:

- Remote hello accepted/rejected and correlated
- Client role claims never granting authorization
- Capability/handler parity
- Loaded-document snapshot correctness
- ACP enabled before and after document open
- Document replacement and authority epoch
- Inline and chunked surface synchronization
- Readiness revision/hash mismatch
- GO ACK plus authoritative state
- Duplicate and expired GO
- Song browse versus activation
- Explicit Blackout desired state
- Master Dimmer value/clamping
- Missing/disabled Global Look
- Free Play return context
- Unknown/removed Busk control
- Momentary END, cancel, dirty disconnect, expiry, layout removal, shutdown, and failed release
- Revision gap and reconnect reconciliation
- Warning appearance/clearance
- View-only session mutation rejection

Do not use successful socket writes as assertions of application success.

## 7. ACP library/registry follow-up

One issue should be evaluated in the ACP repository rather than worked around in Prism:

```text
remote.navigation.state valid_senders currently includes conductor and simulator,
but not prism.
```

If the intended profile allows Prism to publish `remote.navigation.state` directly, update the registry/schema-derived SDK data and regenerate/check vectors across Python, Swift, and Rust. If Conductor alone owns that message, Prism must publish the equivalent authoritative resources through generic `state.snapshot` / `state.delta` and the profile documentation should make that ownership explicit.

This registry question does not explain the observed `remote.hello` timeout or placeholder show state; those are confirmed Prism integration defects.

## 8. Definition of done

Prism's ACP Remote integration is ready for product-level testing when:

1. Workbench Remote profile reaches `ready` without timeout.
2. The surface and snapshots identify the actual loaded project.
3. Effective permissions come only from Prism-owned policy.
4. Every advertised capability has a working, tested handler.
5. Every stateful command has a correlated disposition and a separate authoritative state publication.
6. No Remote UI state is confirmed from transmission or ACK alone.
7. Momentary fail-safe release is authority-owned and tested on every termination path.
8. Disconnects, gaps, reconnects, and authority changes reconcile before controls re-enable.
9. Workbench smoke/conformance scenarios pass against Prism without modifying Workbench's protocol rules.
10. No production Prism adapter depends on the non-production Swift Remote simulator for safety or authority.

