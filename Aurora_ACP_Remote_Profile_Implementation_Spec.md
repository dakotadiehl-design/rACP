# Aurora Communications Protocol (ACP)
# Aurora Remote Profile Implementation Specification

Status: **Normative profile companion, reconciled 2026-08-27**
Current integration guidance: [`docs/integration/REMOTE.md`](docs/integration/REMOTE.md)

**Document Type:** Engineering Handoff / Protocol Profile Specification
**Profile Name:** Aurora Remote Profile
**Protocol Family:** Aurora Communications Protocol (ACP)
**Target ACP Baseline:** ACP v1.2+
**Recommended Protocol Revision After Adoption:** ACP v1.3
**Primary Implementations:** Python is the reference production Remote authority (`RemoteAuthority` + `RemoteHost`). Rust and Swift ship models plus **non-production simulators** only; they do not implement the Aurora Remote amendment engine.
**Status:** Implemented reference profile; Swift product adapter integration pending

---

## 1. Purpose

The Aurora Remote Profile defines how remote-control clients participate in the Aurora ecosystem through ACP.

Aurora Remote is intentionally **not** a second show engine, lighting engine, cue engine, or orchestration authority. It is a distributed control surface that exposes controls already owned by authoritative Aurora products such as Conductor and Prism.

The Remote Profile must allow a remote client to:

- Discover and connect to Aurora sessions.
- Identify itself and negotiate Remote-specific capabilities.
- Receive the currently active show, song, section, cue, and transport state.
- Receive a versioned remote-control layout defined by the show.
- Render controls appropriate to the current user/device/session.
- Invoke semantic Aurora controls.
- Support momentary controls such as fog, flash, bump, and push-to-enable behavior.
- Navigate songs and show structure when permitted.
- Execute Current / Next / GO style controls when permitted.
- Invoke busking controls exposed by Prism or Conductor.
- Receive immediate authoritative state feedback.
- Participate in show asset conformance.
- Survive transient network loss without producing unsafe control behavior.
- Clearly indicate stale, uncertain, disabled, disconnected, or degraded state.
- Never claim a command was applied merely because it was transmitted.
- Never become an alternate source of truth for show state.

The profile should be designed so the same ACP semantics can support Aurora Remote on iPad, future iPhone clients, macOS remote panels, browser-based remotes, purpose-built hardware panels, Stream Deck/control-surface bridges, simulators, and future Android clients.

---

## 2. Architectural Principle

The Remote Profile is based on one strict rule:

> **Aurora Remote expresses operator intent; authoritative Aurora products own state and execution.**

Remote should never directly manipulate DMX, Art-Net, MIDI, mixer protocols, fixture state, or other downstream hardware.

```text
Remote
   │
   │ remote.control.invoke
   ▼
Conductor or Prism
   │
   │ validate permissions
   │ resolve control binding
   │ route semantic action
   ▼
Existing control/action engine
   │
   ├── cue engine
   ├── programmer/busking engine
   ├── show progression
   ├── Bridge
   ├── mixer driver
   └── other Aurora subsystem
```

ACP must not create a parallel shortcut around the owning product's engine.

---

## 3. Remote Roles

A Remote client may operate in one or more negotiated roles:

```text
remote.viewer
remote.operator
remote.busker
remote.show_navigation
remote.admin
```

These roles are descriptive capability sets, not hard-coded user account types.

### 3.1 Viewer
May receive state and layout information but cannot invoke live controls.

### 3.2 Operator
May invoke explicitly exposed standard controls such as GO, Next, cue fire, start/stop, and scene selection.

### 3.3 Busker
May invoke controls intended for live improvisational operation such as fog burst, color bumps, intensity bumps, strobes, blinders, temporary effects, and fixture-group actions.

### 3.4 Show Navigation
May select songs, sections, or related show structures.

### 3.5 Admin
May perform Remote-specific configuration or synchronization actions. Remote admin rights must not automatically imply unrelated Conductor or Prism administration.

---

## 4. ACP Capability IDs

Minimum recommended capability identifiers:

```text
remote.profile
remote.layout
remote.control.invoke
remote.control.momentary
remote.control.state
remote.navigation.song
remote.navigation.section
remote.navigation.cue
remote.transport
remote.busking
remote.readiness
remote.asset_sync
remote.presentation
```

Optional future capabilities:

```text
remote.haptics
remote.multitouch
remote.hardware_surface
remote.local_macros
remote.voice_accessibility
remote.offline_cache
```

Each capability must have an independent capability version.

---

## 5. Remote Identity

Remote identity must distinguish ACP node identity, physical/logical device identity, Remote installation identity, optional participant/operator identity, and current process instance.

```json
{
  "node_id": "uuid",
  "instance_id": "uuid",
  "device_id": "uuid",
  "remote_id": "uuid",
  "participant_id": "uuid-or-null",
  "device_name": "FOH iPad",
  "platform": "ios",
  "app_version": "1.0.0"
}
```

`node_id` is stable ACP identity. `instance_id` changes every launch. `device_id` is a securely persisted app-generated device identity where platform policy permits. `participant_id` is optional and may identify a musician, technician, stage manager, or other operator role.

Do not assume every Remote is person-bound.

---

## 6. Remote Show Asset Model

Remote show configuration must use ACP's versioned asset system.

Recommended asset types:

```text
remote.layout
remote.control_set
remote.busking_page
remote.navigation_profile
remote.presentation_profile
remote.permission_profile
```

A show-layout change must not require an application update.

```json
{
  "asset_id": "uuid",
  "asset_type": "remote.layout",
  "revision": 8,
  "sha256": "...",
  "show_id": "...",
  "name": "Haywire FOH Remote"
}
```

Conductor must be able to report stale/missing Remote assets and synchronize the correct revision before ARM.

---

## 7. Remote Layout Philosophy

Remote layout describes **presentation and semantic binding**, not show-engine implementation.

A layout may define pages, groups, buttons, momentary buttons, toggles, sliders, encoders, selectors, XY pads, status indicators, cue widgets, song navigation, Current/Next/GO, busking controls, and read-only telemetry.

Each control references a stable `control_id`.

```json
{
  "control_id": "fog_burst",
  "label": "FOG",
  "control_type": "momentary",
  "binding": {
    "target": "prism",
    "action": "busk.fog.output",
    "parameters": {"value": 1.0}
  }
}
```

Remote need not understand the internal implementation of the bound action. The owning Aurora product resolves it.

---

## 8. Control Definitions

Recommended control types:

```text
button
momentary
toggle
slider
encoder
selector
xy
transport
navigation
status
meter
```

Each definition should support label, enabled/visible state, required permission, style hint, semantic binding, feedback policy, and safety metadata.

Presentation hints may include `normal`, `primary`, `secondary`, `warning`, `danger`, `success`, and `performance`. They are not authorization semantics.

---

## 9. Semantic Control Invocation

Primary message:

```text
remote.control.invoke
```

Example:

```json
{
  "control_id": "cue_go",
  "invocation_id": "uuid",
  "interaction": "activate",
  "value": null,
  "client_timestamp_utc": "2026-08-17T20:00:00Z"
}
```

The authority must verify session, control existence, active show/layout, current enabled state, permission, prerequisites, and binding before routing the semantic action through the owning control system.

Remote must not consider the operation successful until semantic ACP acknowledgement is received.

---

## 10. Momentary Control Semantics

Momentary controls are a first-class requirement.

Examples include fog-at-100%-while-held, blinder bumps, flashes, temporary strobe/effects, push-to-enable actions, and other controls where release is semantically meaningful.

Use explicit interactions:

```text
momentary_begin
momentary_end
momentary_cancel
```

Press:

```json
{
  "type": "remote.control.invoke",
  "payload": {
    "control_id": "fog_burst",
    "invocation_id": "uuid-123",
    "interaction": "momentary_begin",
    "value": 1.0
  }
}
```

Release uses the same `invocation_id` with `momentary_end`.

---

## 11. Momentary Fail-Safe Behavior

Momentary actions are unsafe if a network failure can leave them stuck ON.

All momentary bindings must declare a fail-safe policy.

```text
release_on_disconnect
release_on_timeout
hold_last_state
authority_defined
```

Default for live effects is `release_on_disconnect`.

```json
{
  "safety": {
    "failsafe": "release_on_disconnect",
    "max_hold_ms": 10000,
    "heartbeat_required": true
  }
}
```

The authoritative receiver must own the fail-safe timer. Remote-side release attempts are defense in depth only.

For fog/blinder/strobe-style controls:

- A disconnected Remote must not leave the effect active indefinitely.
- The receiver tracks which ACP session began the hold.
- Session loss releases actions configured for `release_on_disconnect`.
- `max_hold_ms` provides a second safety boundary.

---

## 12. Momentary Hold Leases

The protocol should leave room for optional momentary hold leases.

The authority may return a lease ID and expiration. The Remote refreshes the lease while the control remains physically held.

A simple first implementation may use reliable WebSocket session tracking plus periodic hold refresh and max-hold timeout, but the schema should permit explicit leases.

---

## 13. Toggle Controls

Never rely on blind inversion when authoritative state exists.

Bad:

```text
toggle_work_lights()
```

Preferred:

```text
set_work_lights(true)
```

Remote renders authoritative state and transmits desired state.

This prevents divergence after reconnect or missed state updates.

---

## 14. Slider and Continuous Controls

Slider definitions must declare min, max, step, units, update mode, nominal rate, max rate, and QoS.

Continuous updates should use latest-value coalescing.

Do not flood the reliable command queue with hundreds of slider updates per second.

A practical local UI rate is around 20-30 Hz unless the control requires otherwise.

---

## 15. Busking Profile

Remote busking controls must map only to explicitly exposed show controls.

Remote must not inspect Prism internals and synthesize arbitrary programmer mutations.

Examples:

```text
fog_burst
crowd_blinder
warm_wash
blue_stage
strobe_hit
solo_spot
chorus_bump
audience_chase
```

A control may bind to a Prism busking action, Conductor action, cue fire, palette recall, effect trigger, group intensity override, Bridge function, or another explicitly published Aurora semantic action.

The owning product decides what is safe to expose.

---

## 16. Busking Preview vs Live

Aurora supports staged/offline scene construction. Remote Profile should preserve the conceptual execution modes `live`, `preview`, and `staged` where such controls are eventually exposed.

For Remote v1, live invocation of preconfigured busking controls is sufficient. Do not prematurely build a full remote scene editor into ACP Remote Profile.

---

## 17. Current / Next / GO

Remote should subscribe to authoritative state resources such as:

```text
show.current
song.current
song.next
section.current
cue.current
cue.next
transport.state
```

GO is a semantic action. Remote must not locally advance Current/Next when GO is pressed. It waits for authoritative state deltas from Conductor/Prism.

---

## 18. Song Navigation

Remote may expose song selection, next, previous, start, and stop when permitted.

Browsing a song list must be separated from activation of the selected song. A user must be able to look ahead without changing the live show state.

Conductor is normally the preferred authority for show navigation.

---

## 19. Section Navigation

Where the show permits operator- or musician-driven progression, Remote may expose section enter/next/previous actions.

ACP should preserve initiator metadata so Conductor can show whether a transition came from Remote, MIDI, keyboard shortcut, Stream Deck, or another source.

---

## 20. Remote State Feedback

Every control should declare a feedback policy:

```text
none
ack_only
state
meter
progress
```

Remote must visually distinguish at least:

```text
idle
pending
applied
failed
disabled
stale
disconnected
```

Pending begins when an acknowledgement-required action is transmitted.

---

## 21. Remote Control State

Recommended message/resource payload:

```json
{
  "control_id": "work_lights",
  "revision": 55,
  "enabled": true,
  "available": true,
  "value": true,
  "confidence": "confirmed",
  "reason": null
}
```

Controls may become unavailable dynamically because a target is offline, the show is not armed, a subsystem is disabled, permission is missing, or another operational precondition is false.

Remote should disable the control and surface the reason appropriately.

---

## 22. Permissions

Remote authorization is server-authoritative.

A Remote must never grant itself capabilities because a layout contains a button.

The ACP session exposes the effective permission set. Every invocation is validated by the authority.

UI hiding/disabling is an operator-experience feature, not security.

---

## 23. Control Scoping

Controls should support explicit scope such as show, song, section, Prism project, fixture group, Bridge node, or global session.

Avoid ambiguous global controls.

---

## 24. Dangerous Controls

Controls such as blackout, stop-all, output disable, project reload, Bridge restart, and mixer mute-all should carry safety metadata.

Recommended classifications:

```text
normal
caution
dangerous
```

The layout may require interactions such as press-and-hold confirmation, but the authority still validates the action.

---

## 25. Layout Pages

Layouts should support device-independent pages and control groups.

Do not encode pixel-perfect iPad coordinates into the canonical asset.

Use relative layout hints, ordering, grouping, minimum touch-target hints, and capability/permission conditions. The Remote app adapts to screen size and orientation.

---

## 26. Conditional Visibility

A deliberately small conditional system may support predicates such as:

```text
equals
not_equals
exists
capability_present
permission_present
```

Do not embed a general scripting language into Remote layout assets.

Complex behavior belongs in the authoritative application.

---

## 27. Presentation Profile

Remote may present current show/song/cue, next song/cue, song progress, warnings, connection state, and selected health information.

Reuse normal ACP state/health resources wherever possible instead of duplicating state into Remote-specific messages.

---

## 28. Warning and Health Display

Conductor may publish an operator-focused warning feed for Remote.

Remote should not blindly mirror every low-level diagnostic event.

Warnings remain presentation state; acknowledging one should not silently suppress the underlying fault unless a separate operator-ack mechanism exists.

---

## 29. Reconnection Behavior

After reconnect:

1. Establish a fresh ACP session.
2. Perform HELLO/capability negotiation.
3. Renegotiate effective permissions.
4. Reconcile show manifest identity.
5. Verify required Remote assets.
6. Request fresh state snapshots.
7. Treat all momentary controls from the old session as released.
8. Become interactive only after readiness criteria are met.

Remote should visibly transition through states such as RECONNECTING, SYNCING, and READY.

Do not immediately enable live controls merely because the WebSocket reopened.

---

## 30. Stale UI Protection

Remote tracks ACP sequence/revision information.

A detected gap, reconnect, authority change, asset mismatch, or missed state revision triggers fresh snapshot reconciliation.

Safety-sensitive controls should remain disabled while state is stale.

---

## 31. Idempotency

Remote commands use ACP idempotency where appropriate, especially GO, cue fire, song activation, blackout, toggle-like state changes, and momentary begin/end.

Duplicate GO retries must never advance twice.

---

## 32. Momentary Idempotency

For one `invocation_id`:

```text
BEGIN first time  -> activate
BEGIN duplicate   -> return existing result
END first time    -> release
END duplicate     -> return already released
```

This behavior is normative for the Python reference authority. Rust and Swift simulators may exercise a subset for model/vector tests and are not amendment-conformant production engines.

---

## 33. Multiple Remote Clients

ACP must assume multiple Remote clients can coexist.

Possible concurrency modes:

```text
shared
exclusive
single_owner
authority_defined
```

For shared momentaries, recommended behavior is logical OR across valid holds: output remains active until all active invocation holds are released or expired.

The authority, not Remote, performs arbitration.

---

## 34. Control Arbitration

The authority resolves conflicting slider values, blackout/cue conflicts, show changes, and other concurrent actions using normal Aurora rules.

Rejected or conflicting actions return explicit structured errors rather than silently disappearing.

---

## 35. Authority Changes

Future redundant Conductor deployments may change active authority.

On authority change, Remote refreshes state, invalidates or resolves old pending commands, expires old momentary holds, and remains non-interactive until synchronized.

---

## 36. Remote Asset Conformance

Remote participates in ACP's SELECT -> PREPARE -> VERIFY -> ARM -> LIVE show lifecycle.

It reports installed layout/control-set/navigation-profile revisions and becomes show-ready only after required assets verify, permissions are known, state is current, and profile versions are compatible.

---

## 37. Offline Asset Cache

Remote should cache previously verified assets for fast startup and resilience.

Cached presence does not equal current show conformance. A cached layout may be rendered while synchronization occurs, but live controls remain disabled until the active manifest is verified.

---

## 38. State Ownership

Recommended ownership:

```text
Conductor:
    show identity
    show/song progression when authoritative
    Remote layout assignment
    Remote permissions
    readiness

Prism:
    lighting engine state
    cue state when authoritative
    busking/programmer state
    output health

Bridge:
    Bridge state
    blackout state
    output health

Remote:
    local presentation only
    selected page
    scroll positions
    local accessibility/haptic preferences
    transient touch state
```

Remote must never publish itself as authoritative for current show, cue, song, lighting, Bridge, or mixer state unless a future profile explicitly delegates that authority.

---

## 39. Local-Only Remote State

Keep UI-only data local, including visible page, scroll position, animation state, brightness preference, haptic preference, and accessibility settings.

Do not pollute ACP with unnecessary interface state.

---

## 40. Swift Implementation Requirements

Recommended modules/types:

```text
ACPRemoteProfile
ACPRemoteLayout
ACPRemoteSession
ACPRemoteState
ACPRemoteControls
ACPRemoteTesting
```

Use async/await, actors, Sendable value types, and immutable view-state snapshots.

Do not bind SwiftUI directly to network callbacks.

Recommended flow:

```text
ACP session actor
    ↓
Remote state coordinator
    ↓
immutable RemoteViewState
    ↓
SwiftUI
```

---

## 41. Swift Momentary Handling

The UI should send `momentary_begin` on touch-down and `momentary_end` on every termination path including touch-up, gesture cancellation, page dismissal, app backgrounding where appropriate, control removal, or session shutdown.

Authority-side fail-safe remains mandatory.

---

## 42. Python Implementation Requirements

Python Remote support is required for simulator, conformance tests, diagnostics, headless panels, and future hardware bridges.

Suggested CLI behaviors:

```bash
acp-sim remote discover
acp-sim remote connect <node>
acp-sim remote controls
acp-sim remote press fog_burst
acp-sim remote hold fog_burst --seconds 3
acp-sim remote go
acp-sim remote disconnect --dirty
```

`--dirty` disconnect is important for testing momentary fail-safe behavior.

---

## 43. Rust Implementation Requirements

Rust Remote models are mandatory even if no first-party Rust GUI is planned.

They enable hardware control surfaces, embedded endpoints, Bridge-hosted controls, and cross-language conformance testing.

The model layer must remain GUI-independent.

---

## 44. Wire Message Families

Recommended Remote-specific types:

```text
remote.hello
remote.hello_ack
remote.layout.request
remote.layout.report
remote.control.invoke
remote.control.state
remote.control.snapshot
remote.permissions
remote.permissions.changed
remote.readiness
remote.readiness.changed
remote.navigation.request
remote.navigation.state
remote.presentation.state
remote.momentary.refresh
remote.error
```

Reuse generic ACP command acknowledgements, state snapshots/deltas, asset transfer, health, and errors wherever possible.

---

## 45. Preferred Message Reuse

Prefer:

```text
remote.control.invoke
    +
command.ack
    +
state.delta
```

rather than inventing Remote-specific versions of ACP's existing acknowledgement lifecycle.

---

## 46. Example GO Flow

```text
Remote                           Conductor / Prism
   │
   │ remote.control.invoke: GO
   ├──────────────────────────────►
   │
   │ command.ack ACCEPTED
   ◄───────────────────────────────┤
   │
   │ command.ack APPLIED
   ◄───────────────────────────────┤
   │
   │ state.delta cue.current
   ◄───────────────────────────────┤
   │ state.delta cue.next
   ◄───────────────────────────────┤
```

Remote updates from authoritative deltas, not optimistic local cue advancement.

---

## 47. Example Fog Momentary Flow

```text
Remote                        Prism
  │
  │ BEGIN fog_burst / ID A
  ├───────────────────────────►
  │
  │ command.ack APPLIED
  ◄────────────────────────────
  │
  │ ... user holds ...
  │
  │ END fog_burst / ID A
  ├───────────────────────────►
  │
  │ command.ack APPLIED
  ◄────────────────────────────
```

Disconnect case:

```text
Remote                        Prism
  │
  │ BEGIN fog_burst / A
  ├───────────────────────────►
  │
  X network disappears
                               │
                               │ session timeout
                               │ release A
                               ▼
                           fog output off
```

This is a mandatory conformance test.

---

## 48. Multiple-Remote Hold Flow

For shared momentary controls, if Remote A and B both hold the same logical control, releasing A does not clear the output until B also releases or expires.

This prevents one client from unintentionally cancelling another operator's active hold.

---

## 49. Error Codes

Recommended Remote error namespace:

```text
remote.control.unknown
remote.control.disabled
remote.control.unavailable
remote.control.permission_denied
remote.control.conflict
remote.control.invalid_interaction
remote.control.invalid_value
remote.control.stale_state
remote.control.not_armed
remote.layout.missing
remote.layout.stale
remote.layout.invalid
remote.layout.incompatible
remote.session.not_ready
remote.session.authority_changed
remote.momentary.unknown_invocation
remote.momentary.expired
```

Use ACP's normal structured error model.

---

## 50. Wireshark Dissector Support

The ACP Wireshark dissector must expose Remote fields such as:

```text
acp.remote.id
acp.remote.device_id
acp.remote.participant_id
acp.remote.layout.id
acp.remote.layout.revision
acp.remote.control.id
acp.remote.control.type
acp.remote.control.interaction
acp.remote.control.invocation_id
acp.remote.control.value
acp.remote.permission
acp.remote.readiness
acp.remote.momentary.lease_id
acp.remote.momentary.expires_ms
```

Useful filters:

```text
acp.type == "remote.control.invoke"
acp.remote.control.id == "fog_burst"
acp.remote.control.interaction == "momentary_begin"
acp.remote.control.interaction == "momentary_end"
acp.remote.readiness != "ready"
acp.error.code == "remote.control.permission_denied"
```

Wireshark should make it easy to trace touch -> invocation -> ACCEPTED -> APPLIED -> state delta.

---

## 51. Security Requirements

Remote is a live control surface and must be treated accordingly.

Requirements:

- Authentication hooks exist.
- Effective permissions are server-authoritative.
- Layout metadata never grants access by itself.
- Unknown controls are rejected.
- Controls not present in the active show/control set are rejected.
- Cross-show stale invocations are rejected.
- No generic execute-string, shell, filesystem, or arbitrary RPC primitive.
- Session IDs, invocation IDs, idempotency keys, and show/layout context mitigate stale/replayed actions.

---

## 52. Show Boundary Protection

A layout from one show must never accidentally operate another show.

Invocations should carry or resolve against active `show_id`, `show_revision`, `layout_id`, and `layout_revision` context.

Stale show/layout invocations are rejected.

---

## 53. Layout Change During Show

When a new layout revision is published, Remote should stage and validate it while keeping the current valid layout active, then switch atomically when allowed.

Any momentary controls removed by the new layout must be released before activation completes.

A failed update leaves the prior valid layout intact.

---

## 54. Remote Readiness

Suggested readiness states:

```text
connecting
negotiating
syncing_assets
syncing_state
ready
ready_with_warnings
degraded
blocked
disconnected
```

Conductor should display Remote readiness in the show-conformance matrix.

---

## 55. Remote Health

Remote publishes normal ACP heartbeat telemetry.

Useful Remote components include network, session, layout, state_sync, and touch_input.

Optional capability-gated telemetry may include battery percentage and thermal state so Conductor can warn about a critical show-control device with low battery.

---

## 56. Latency Expectations

Remote should feel immediate on a healthy local show LAN.

Engineering targets, not wire guarantees:

```text
operator input -> ACCEPTED: typically < 50 ms
operator input -> APPLIED/state response: typically < 100 ms for simple controls
```

Metrics should be available for troubleshooting.

---

## 57. QoS

Recommended mapping:

```text
remote.control.invoke          reliable
command.ack                    reliable
state.delta durable state      reliable
slider intermediate updates    latest
meters                         latest
presentation telemetry         latest
verbose diagnostics            best_effort
momentary begin/end            reliable
```

Momentary begin/end must never be best effort.

---

## 58. Backpressure and Priority

Slider and meter traffic must never starve GO or momentary-end.

Recommended semantic priority:

```text
Priority 1: safety release, momentary_end, critical control/session lifecycle
Priority 2: GO, cue fire, song navigation, control invocations
Priority 3: durable state
Priority 4: slider latest-value updates
Priority 5: meters / telemetry
```

Use bounded queues in all SDKs.

---

## 59. Accessibility

Layouts should support accessibility labels and hints. Controls must have human-readable labels independent of iconography, and color must never be the sole state indication.

---

## 60. Haptics

Haptic hints may be provided, but haptics are never acknowledgement.

A success haptic should ideally occur only after semantic success is known.

---

## 61. Testing Requirements

Automated Remote tests must cover:

### Core Connection
- Discovery.
- HELLO negotiation.
- Capability negotiation.
- Permission negotiation.
- Show manifest reconciliation.
- Layout synchronization.
- State snapshot.

### Standard Controls
- Successful invoke.
- Rejected invoke.
- Unknown/disabled/unavailable control.
- Permission denied.
- Duplicate invocation.
- Idempotent retry.
- Ack timeout and late ack.

### Momentary
- Begin/end.
- Duplicate begin/end.
- Dirty disconnect while active.
- Timeout/max-hold expiration.
- Two Remotes holding one shared control.
- Exclusive conflict.
- Layout removed while active.
- Show changed while active.

### Navigation
- Browse without activation.
- Select song.
- Next/previous.
- GO.
- Duplicate GO retry.
- Stale cue state.

### Asset Conformance
- Correct/stale/missing layout.
- Hash mismatch.
- Failed transfer.
- Atomic activation.
- Rollback to prior valid layout.

### Reconnect
- Fresh instance ID.
- Fresh permissions.
- Fresh state snapshot.
- Old pending invocations invalidated.
- Momentaries released.
- Stale layout detected.

### Security
- Unauthorized control.
- Stale show/layout invocation.
- Forged permission metadata.
- Unknown action binding.
- Oversized/malformed layout.

---

## 62. Cross-Language Conformance

The **amendment-conformant production authority** is Python `RemoteHost` / `RemoteAuthority.handle`. Rust `RemoteAuthority` and Swift `ACPRemoteAuthority` are non-production simulators. Live Remote interoperability is proven against the Python authority.

Model/vector exercises may include:

```text
Swift Remote client ↔ Python reference authority
Python Remote client ↔ Python reference authority
Swift/Rust simulators ↔ golden vectors (not live amendment conformance)
```

Golden JSON and CBOR vectors must include layout, control invocation, momentary begin/end, readiness, permissions, control state, and errors.

---

## 63. Simulator Requirements

`acp-sim` should support Remote discovery, connection, status, layout inspection, control listing, invocation, momentary begin/end, GO, song selection, dirty disconnect, and reconnect.

The dirty-disconnect scenario is mandatory for fail-safe testing.

---

## 64. Product Adapter Requirements

### Conductor
Conductor should own Remote show assignment, layout assignment, permission resolution, show-level navigation, readiness display, warning presentation, and asset synchronization policy.

### Prism
Prism exposes explicitly permitted Remote actions such as GO, cue fire, busking controls, fog, blinders, strobe, blackout, or staged/live actions. All must route through existing Prism semantic control architecture.

### Bridge
Bridge may expose selected Remote controls such as blackout or test functions, preferably surfaced through Conductor rather than granting arbitrary administration.

### Lyric
Lyric is generally not controlled through Remote Profile except for intentionally exposed operator-level presentation actions. Do not couple Remote layout logic to Lyric chart-assignment semantics.

---

## 65. Avoid Protocol Duplication

Reuse ACP session, capabilities, command acknowledgements, state, health, config, asset transfer, show conformance, errors, and idempotency.

Remote Profile adds only Remote layout semantics, control semantics, momentary interaction semantics, permission/readiness semantics, and Remote-specific presentation behavior.

---

## 66. Recommended Schema Files

```text
schema/
  remote/
    remote_identity.schema.json
    remote_layout.schema.json
    remote_page.schema.json
    remote_control_definition.schema.json
    remote_control_invocation.schema.json
    remote_control_state.schema.json
    remote_permission_set.schema.json
    remote_readiness.schema.json
    remote_presentation.schema.json
```

Golden JSON/CBOR vectors should live under `vectors/remote/`.

---

## 67. Suggested Swift API

```swift
let remote = try await ACPRemoteSession.connect(to: conductor)
try await remote.prepare()
let layout = await remote.activeLayout
let result = try await remote.invoke(controlID: "go", interaction: .activate)
```

Momentary:

```swift
let handle = try await remote.beginMomentary(controlID: "fog_burst", value: 1.0)
try await handle.end()
```

The handle may attempt client-side cleanup on cancellation/deinit, but server-side fail-safe remains mandatory.

---

## 68. Suggested Python API

```python
remote = await ACPRemote.connect(peer)
await remote.prepare()
await remote.invoke("go")
hold = await remote.begin_momentary("fog_burst", value=1.0)
await hold.end()
```

---

## 69. Suggested Rust API

```rust
let mut remote = RemoteSession::connect(peer).await?;
remote.prepare().await?;
remote.invoke("go", Interaction::Activate, None).await?;
let hold = remote.begin_momentary("fog_burst", Some(Value::Float(1.0))).await?;
hold.end().await?;
```

---

## 70. Acceptance Criteria

The Remote Profile is complete when:

- Python exposes the reference production Remote authority. Rust and Swift expose equivalent wire models and non-production simulators.
- Remote layouts are versioned show assets.
- Remote can negotiate permissions, sync layout/state, and become READY.
- GO produces semantic acknowledgement and authoritative cue-state update.
- Duplicate GO retry never double-advances.
- Song navigation works without Remote becoming show authority.
- Busking controls route through existing Aurora semantic action paths.
- Momentary begin/end is idempotent.
- Momentary actions release when initiating sessions disappear.
- Max-hold safety is implemented where configured.
- Multiple Remotes coexist deterministically.
- Stale state disables unsafe controls until reconciliation.
- Show/layout mismatch blocks stale control invocation.
- Server-side permission enforcement is tested.
- Layout activation is atomic and rollback-safe.
- Wireshark exposes Remote lifecycle fields.
- Python simulator exercises all major behaviors.
- Swift↔Rust and Swift↔Python interoperability tests pass.
- No Remote path directly drives DMX, Art-Net, MIDI, or vendor device protocols.
- Remote remains a control surface, never a parallel show engine.

---

## 71. Implementation Order for Grok

1. Add Remote capability/profile constants.
2. Define Remote identity models.
3. Define layout/control schemas.
4. Add golden JSON/CBOR vectors.
5. Add Swift/Python/Rust model parity.
6. Implement permissions/readiness models.
7. Implement `remote.control.invoke`.
8. Reuse ACP `command.ack` and `state.*` for result/state.
9. Implement momentary begin/end.
10. Implement authoritative momentary fail-safe.
11. Implement Remote asset conformance.
12. Implement layout synchronization.
13. Implement reconnect/state reconciliation.
14. Implement navigation bindings.
15. Implement busking bindings.
16. Extend Wireshark dissector.
17. Extend Python simulator.
18. Add cross-language integration tests.
19. Add malformed-input/security tests.
20. Integrate Conductor/Prism adapters only after protocol-level tests pass.

---

## 72. Explicit Non-Goals

Do not turn Remote Profile into:

- A second Conductor.
- A second Prism.
- A generic scripting runtime.
- A DMX console.
- A remote shell.
- A device-driver interface.
- An arbitrary RPC mechanism.
- A place to duplicate Lyric chart logic.
- A place for business logic that belongs to Conductor.

Remote is a presentation and control surface.

---

## 73. Final Engineering Rule

When implementing Remote Profile, resolve ambiguity with this rule:

> **Remote sends intent. The authoritative Aurora product decides whether the action is permitted, applies it through its existing semantic control path, acknowledges the result, and publishes authoritative state back to Remote.**

For momentary controls:

> **The authority must always have enough information to release the action safely if the Remote disappears.**

These rules must remain true as Aurora Remote grows from an iPad control surface into future phones, hardware panels, Stream Deck bridges, or other control endpoints.
