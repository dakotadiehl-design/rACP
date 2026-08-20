# Aurora Communications Protocol (ACP)
## Remote Profile & App-Store-Safe Control Surface Amendments

**Status:** Implementation handoff / protocol amendment  
**Target:** Existing ACP specification and implementations  
**Primary consumers:** Aurora Prism, Aurora Remote  
**Future consumers:** Aurora Conductor and other ACP-capable Aurora products  
**Implementation teams:** Codex / Grok  
**Date:** 2026-08-17

---

## 1. Purpose

This document defines the changes and clarifications required in ACP to support **Aurora Remote** as a first-class ACP client while preserving clean expansion to **Aurora Conductor** later.

These changes are intentionally evolutionary. **Do not redesign ACP transport, framing, discovery, application-level acknowledgement, session identity, asset hashing, state synchronization, or version negotiation if those facilities already exist.** Extend the existing mechanisms with the Remote-specific semantics described here.

The central architectural rule is:

> **Aurora Remote is a generic Aurora control surface. Prism is its first provider/profile, not a hard-coded networking dependency.**

Remote must communicate in terms of ACP endpoints, capabilities, semantic actions, authoritative state, and declarative assets. The Remote UI must not depend on Prism implementation details or direct Prism data-model access.

---

## 2. Goals

ACP shall support the following Remote use cases:

1. Discover and connect to Prism now, and Conductor later.
2. Browse/select/load songs and navigate setlists.
3. Execute GO/cue actions with reliable application-level acknowledgement.
4. Recall project-defined global Looks independently of the active song.
5. Support ad-hoc/free-play operation for unplanned songs.
6. Expose project-defined Busk/Remote control surfaces.
7. Support momentary controls such as fog, blinders, or temporary overrides safely.
8. Publish current song, cue, next cue, output state, system health, and other live state.
9. Allow multiple Remote clients with differing permissions.
10. Cache and synchronize Remote surface assets using ACP's existing asset-conformance facilities.
11. Keep Remote surface definitions strictly declarative and non-executable.
12. Prevent stale live commands from being replayed after a disconnect/reconnect.
13. Ensure Remote displays authoritative provider state rather than optimistic assumptions.

---

## 3. Non-Goals

This amendment does **not** turn Remote into a remote copy of the Prism UI.

ACP Remote v1 does not need facilities for Remote to:

- Patch fixtures.
- Build fixture profiles.
- Edit cues.
- Create effects.
- Edit stage layouts.
- Modify MIDI mappings.
- Execute arbitrary scripts on Prism/Conductor.
- Download executable UI code.
- Stream or reproduce the Prism/Conductor desktop UI.

Those features can be considered independently in future protocol/profile revisions.

---

# 4. Remote ACP Profiles

ACP shall define product-independent Remote profile negotiation.

Initial profiles:

```text
aurora.remote.prism.v1
aurora.remote.conductor.v1    # reserved/future
```

Remote shall connect to an **ACP endpoint**, not to a hard-coded "Prism server" abstraction.

During session negotiation, the provider shall advertise supported Remote profiles and capabilities.

Example conceptual advertisement:

```text
profile: aurora.remote.prism.v1
capabilities:
  - show.navigation
  - song.selection
  - song.loading
  - cue.go
  - cue.selection
  - look.global
  - remote.surfaces
  - busk.controls
  - control.momentary
  - output.blackout
  - output.grand_master
  - state.live
  - system.health
```

The exact wire representation shall follow existing ACP conventions.

### 4.1 Capability Requirements

Capabilities shall be individually discoverable. Remote must not assume every Prism/Conductor implementation supports every operation.

A capability may optionally advertise:

- Capability version.
- Supported operations.
- Constraints/ranges.
- Required permission.
- Associated state namespaces.
- Associated asset types.

Remote shall hide, disable, or gracefully degrade controls whose capabilities are unavailable.

---

# 5. Declarative Remote Surface Definition

ACP shall add a first-class **Remote Surface Definition** facility.

A Remote Surface is configuration/data describing controls that a provider wishes Remote to render. It is **not executable code**.

Suggested conceptual model:

```text
RemoteSurface {
    surface_id
    revision
    schema_version
    title
    context
    pages[]
    metadata
}

RemotePage {
    page_id
    title
    layout
    controls[]
}

RemoteControl {
    control_id
    type
    label
    icon
    action_binding
    state_binding
    presentation
    constraints
    required_permission
}
```

Wire encoding should use ACP's existing structured payload format (for example JSON/CBOR if already defined by ACP). Do not invent a second serialization system solely for Remote.

## 5.1 Initial Control Vocabulary

Remote v1 should support a finite, versioned vocabulary such as:

```text
button
momentary_button
toggle
fader
rotary
segmented_selector
xy_pad
color_control
preset_tile
label
value_display
status_indicator
group
spacer
```

The final vocabulary may be adjusted during implementation, but it must remain **enumerated and schema-controlled**.

Unknown future control types shall fail gracefully. Remote should ignore/placeholder an unsupported control rather than fail the entire surface.

## 5.2 No Executable Payloads

ACP Remote surfaces SHALL NOT transport executable behavior.

Explicitly prohibited as Remote surface payloads:

```text
JavaScript
Lua
Swift
Python
WASM
shell commands
native binaries
plugins
bytecode
arbitrary executable expressions
HTML/JS mini-apps
```

Providers may transmit only declarative data understood by the installed Remote application.

Action bindings shall reference **semantic ACP action identifiers**, not arbitrary source code or host commands.

Example:

```text
control_id: fog_hold
control_type: momentary_button
label: Fog
binding: prism.busking.fog
```

Remote understands the control type and sends the defined ACP action. Prism owns the actual lighting behavior.

---

# 6. Remote Surfaces as ACP Assets

Integrate Remote Surface Definitions into the existing ACP asset/conformance system.

Add an asset type equivalent to:

```text
aurora.remote.surface
```

Each surface asset shall include, using existing ACP asset metadata conventions:

```text
asset_id
revision/hash
schema_version
compatible_profile
payload
```

Remote should be able to cache these assets locally.

On connection:

1. Provider publishes/reports the required surface revision/hash.
2. Remote compares it with its cached revision.
3. Matching asset requires no transfer.
4. Mismatch causes Remote to request the current asset.
5. Remote validates schema and hash before activation.

This must use the same asset-integrity philosophy already defined for Aurora family asset conformance.

---

# 7. Semantic Action Model

ACP Remote actions shall be semantic. Remote must not manipulate DMX channels or Prism internal objects directly.

Examples:

```text
show.song.select
show.song.load
show.free_play.enter
show.free_play.exit
cue.go
cue.select
look.recall
look.preview
look.take
look.preview.cancel
output.blackout.set
output.grand_master.set
busk.control.begin
busk.control.end
```

Prism interprets these actions according to the active project.

For example, Remote shall request:

```text
look.recall(id = slow_song)
```

rather than transmit fixture/channel values representing the Slow Song look.

This abstraction is mandatory for future Conductor compatibility.

---

# 8. Command Delivery Classes

ACP shall formally classify Remote commands by execution semantics.

At minimum, define the following classes.

## 8.1 Stateful

Commands whose requested value represents persistent/current state.

Examples:

```text
output.grand_master.set(0.70)
show.song.select(...)
output.blackout.set(true)
```

Retries may be permitted according to existing ACP idempotency rules.

Prefer explicit state-setting operations over ambiguous toggles. For example:

```text
blackout.set(true)
```

is preferable to:

```text
blackout.toggle()
```

because retries and synchronization are deterministic.

## 8.2 Impulse / Trigger

One-shot live operations.

Examples:

```text
cue.go
cue.fire
look.take
preset.trigger
```

These commands must carry unique command IDs and be protected against duplicate execution.

## 8.3 Momentary / Leased

Actions active only while the initiating control remains engaged.

Examples:

```text
fog hold
blinder hold
temporary strobe
momentary intensity override
```

These require explicit lease semantics as defined below.

---

# 9. Live-Ephemeral / Non-Replayable Commands

ACP shall define a delivery semantic for live commands that must **never be replayed after their useful moment has passed**.

Suggested semantic name:

```text
live_ephemeral
```

Examples include:

- GO.
- Cue trigger.
- Momentary begin/end.
- Look TAKE where timing is performance-sensitive.
- Other instantaneous busking actions.

A live-ephemeral command should support an expiration/deadline or maximum age where appropriate.

Conceptually:

```text
command_id: UUID
semantic: live_ephemeral
issued_at: ...
expires_at: ...
```

Rules:

1. Do not persist live-ephemeral commands for replay after reconnection.
2. Expired commands shall be rejected/not executed.
3. Duplicate command IDs shall not cause duplicate execution.
4. A reconnect establishes current authoritative state rather than replaying missed live actions.
5. ACK retransmission may occur where ACP requires it, but ACK retransmission must not imply command re-execution.

**Critical example:** If Remote sends GO, loses Wi-Fi, and reconnects five seconds later, the old GO must not fire on reconnect.

---

# 10. Momentary Control Lease Semantics

Momentary controls require a fail-safe protocol mechanism.

A simple press/release pair is insufficient because the client may disappear before sending RELEASE.

ACP shall implement leased momentary control.

Conceptual sequence:

```text
Remote -> Provider
CONTROL_BEGIN
  control_id = fog_hold
  command_id = ...
  lease_ms = 1500

Remote -> Provider
CONTROL_KEEPALIVE
  control_id = fog_hold
  lease_id = ...

Remote -> Provider
CONTROL_END
  control_id = fog_hold
  lease_id = ...
```

The exact message names should conform to existing ACP naming conventions.

## 10.1 Provider Requirements

The provider shall:

1. Allocate/acknowledge a lease on accepted BEGIN.
2. Activate the requested momentary behavior.
3. Require periodic renewal before lease expiration.
4. Deactivate automatically if the lease expires.
5. Deactivate immediately on valid END.
6. Deactivate leases when the controlling session is invalidated where possible.
7. Reject stale keepalives/end messages belonging to an obsolete lease.

## 10.2 Client Requirements

Remote shall:

1. Send BEGIN when the user engages the control.
2. Renew at a safe interval below the lease duration.
3. Send END immediately when the user releases/cancels the control.
4. Stop presenting the control as active if authoritative state reports release or connection is lost.
5. Never assume END was received merely because it was sent.

## 10.3 Safety

A provider must fail toward the inactive/safe state on lease expiration.

This is particularly important for:

- Fog.
- Blinders.
- Strobe overrides.
- Temporary full-intensity controls.
- Future special-effect controls.

The mechanism should remain generic rather than lighting-specific so Conductor and future Aurora products can use it.

---

# 11. Authoritative State Model

Remote shall treat ACP providers as authoritative for operational state.

**An ACK is not a state transition.**

Required conceptual sequence:

```text
Remote -> Prism: cue.go(command_id=X)
Prism  -> Remote: ACK(command_id=X, accepted)
Prism  -> Remote: STATE current_cue=chorus_2
Prism  -> Remote: STATE next_cue=guitar_solo
```

The Remote UI changes its authoritative current/next indication from the state publication, not simply from the ACK.

Add the following normative rule to the Remote profile:

> **Command acknowledgement confirms disposition/processing of the request. It does not constitute authoritative operational state. Remote clients SHALL derive displayed operational state from ACP state snapshots and publications.**

This rule applies to Prism and future Conductor providers.

---

# 12. Initial State Snapshot + Delta Subscription

Remote should not poll Prism repeatedly for live state.

Upon connection/profile activation:

1. Remote negotiates capabilities.
2. Remote requests/subscribes to required namespaces.
3. Provider sends an authoritative initial state snapshot.
4. Provider thereafter publishes state deltas/events.

Likely Prism Remote subscriptions include:

```text
show.current_song
show.selected_song
show.mode
show.current_cue
show.next_cue
show.setlist
output.blackout
output.grand_master
output.status
system.health
system.warnings
engine.status
network/output endpoint status
remote.control_state
```

Use existing ACP subscription/state mechanisms where possible.

Remote should be able to request a fresh snapshot after detecting a sequence gap, reconnect, or state-generation mismatch.

---

# 13. Song and Setlist Semantics

ACP Remote/Prism profile shall expose enough semantic information to maintain a persistent live setlist.

At minimum Remote needs:

```text
setlist_id
setlist_name
sections/sets
song_id
song_title
song_order
current_song_id
selected_song_id
song_status
```

Actions should distinguish selection from activation/loading:

```text
show.song.select(song_id)
show.song.load(song_id)
```

This allows the UI to preview/select a song without accidentally making it live.

The provider may expose a capability/configuration allowing single-action loading, but protocol semantics must preserve the distinction.

---

# 14. Global Looks

ACP shall support **Global Looks** as first-class Remote-visible semantic objects.

A Global Look is a provider/project-defined recallable lighting state that is not dependent upon a programmed song.

Examples:

```text
Slow Song
Country Warm
Rock
Ballad Blue
Full Stage
Guitar Solo
Vocal Spotlight
Crowd Wash
Between Songs
Full White
```

Remote does not need to know the fixture/DMX implementation of a Look.

Suggested metadata:

```text
look_id
name
category
icon
sort_order
is_quick_look
default_transition
remote_transition_override_allowed
required_permission
```

Suggested actions:

```text
look.recall
look.preview
look.take
look.preview.cancel
```

Transition/fade execution shall occur on the provider, not on Remote.

---

# 15. Free Play / Ad-Hoc Mode

The Remote profile shall support an explicit **Free Play** or equivalent ad-hoc show state.

Purpose: allow operation when performers play an unplanned song without destroying the planned setlist position.

Required behavior:

1. Entering Free Play preserves the planned setlist/current-position context.
2. Song-dependent automatic progression may be suspended according to Prism behavior.
3. Global Looks and Busk controls remain available.
4. Returning to the setlist restores/exposes the preserved planned position.

Suggested semantic actions:

```text
show.free_play.enter
show.free_play.exit
```

Suggested state:

```text
show.mode = programmed | free_play
show.return_song_id
show.return_position
```

The precise data model may follow Prism's existing show model, but ACP must expose the semantic distinction.

---

# 16. Remote Permissions

ACP shall support capability/action authorization per Remote session.

Do not require a sophisticated user-account system for v1, but ensure the protocol can express permissions now.

Suggested permission vocabulary:

```text
observe
song.select
song.load
cue.execute
look.execute
busk.execute
output.grand_master
output.blackout
remote.surface.use
```

A provider may grant different permissions to different connected Remotes.

Example future use:

```text
Primary iPad: full control
FOH iPad: show + busk
Musician phone: song navigation
Guest device: observe only
```

Permission denial shall produce an explicit ACP error/result rather than silent failure.

Conductor should eventually be able to act as the central authority for these permissions without requiring a Remote protocol redesign.

---

# 17. Connection Loss and Reconnection

The Remote profile shall define deterministic disconnect behavior.

On loss of connection:

- Remote immediately marks live control unavailable.
- Remote may continue displaying cached/last-known information, clearly identified as stale/disconnected.
- Remote shall not queue live-ephemeral actions for later execution.
- Provider momentary leases expire safely.
- Reconnection establishes a new/current session as required by ACP.
- Remote obtains/revalidates authoritative state before enabling live controls.
- Remote revalidates required asset revisions.

Do not infer that the show stopped because Remote disconnected. Prism/Conductor remains authoritative and autonomous.

---

# 18. Discovery Metadata

ACP discovery should remain generic across the Aurora family.

Prefer a family-wide service identity such as:

```text
_aurora-acp._tcp
```

with discovery/session metadata identifying the endpoint product and roles, for example:

```text
product = prism
role = lighting
protocol_version = 1
remote_profile = aurora.remote.prism.v1
```

Conductor can later advertise through the same ACP family discovery mechanism with its own product/role/profile information.

Do not hard-code Remote discovery solely around a Prism-specific service if the existing ACP discovery design can cleanly advertise generic Aurora endpoints.

For Apple-platform implementations, the networking/discovery layer should be compatible with native Bonjour/local-network discovery. This is an implementation constraint, not a change to ACP's higher-level semantics.

---

# 19. App-Store-Safe Remote Architecture Requirement

Although ACP is cross-product protocol infrastructure rather than an iOS-specific technology, the Remote profile shall deliberately support a native, declarative client architecture.

Add the following design constraint to the ACP Remote profile:

> **ACP Remote providers may supply semantic state, commands, metadata, assets, and declarative Remote Surface Definitions. They shall not require Remote clients to download or execute provider-supplied program code in order to expose Remote functionality.**

This keeps the protocol secure, portable, deterministic, and suitable for native App Store clients.

Remote itself owns the implementation of all UI/control behavior associated with the supported surface schema.

---

# 20. Conductor Forward Compatibility

All Remote additions must be implemented without assuming Prism is permanently the top-level authority.

Today:

```text
Aurora Remote
      |
     ACP
      |
    Prism
```

Future:

```text
Aurora Remote
      |
     ACP
      |
  Conductor
   /  |  \
Prism Lyric Bridge ...
```

Remote should be able to negotiate a Conductor profile and receive richer system-level state without replacing its ACP client core.

Therefore:

- Keep actions semantic.
- Keep permissions generic.
- Keep momentary leases generic.
- Keep state namespaces extensible.
- Keep Remote Surface assets provider-neutral.
- Avoid Prism implementation types in generic ACP Remote messages.
- Allow providers to aggregate/proxy capabilities where ACP architecture permits.

---

# 21. Error and Result Semantics

Remote commands should produce structured dispositions using ACP's existing error/result system.

Remote-relevant outcomes should distinguish at least:

```text
accepted
rejected
unauthorized
unsupported
invalid_state
stale
expired
conflict
not_found
rate_limited
```

Do not collapse these into generic failure where the distinction can help Remote present meaningful feedback.

A rejected command must never be represented to the user as successful merely because transport delivery succeeded.

---

# 22. Versioning and Compatibility

Remote Surface schemas and Remote profiles must be independently versionable within ACP's existing version negotiation framework.

Requirements:

1. Profile version is negotiated.
2. Surface schema version is declared in the asset.
3. Unknown optional fields are ignored when safe.
4. Unknown required semantics cause explicit incompatibility rather than undefined behavior.
5. Unsupported controls do not crash the client.
6. Providers should be able to expose a reduced compatible surface for older Remote versions where practical.

Do not tie the Remote app version directly to the Prism app version.

---

# 23. Security and Validation

All provider-supplied Remote data is untrusted input and shall be validated.

At minimum validate:

- Schema versions.
- Payload sizes.
- String lengths.
- Control counts/page counts.
- Numeric ranges.
- Asset hashes.
- Action identifiers.
- State-binding identifiers.
- Permission identifiers.
- Icon/asset references.
- Lease durations.
- Command expiration timestamps.

Reject malformed surfaces rather than attempting to interpret arbitrary content.

Remote surface definitions shall not be able to reference arbitrary local files, execute URLs as code, invoke shell commands, or escape the defined ACP action/state namespace.

---

# 24. Recommended Implementation Sequence

Implement these amendments in the following order so Prism and Remote development can proceed in parallel.

### Phase RACP-1: Profile and Capability Vocabulary

- Define `aurora.remote.prism.v1`.
- Reserve Conductor Remote profile namespace.
- Define initial Prism Remote capability IDs.
- Implement negotiation tests.

### Phase RACP-2: Semantic State and Commands

- Song/setlist state.
- Cue current/next state.
- Song select/load.
- GO.
- Global Look enumeration/recall.
- Free Play state/actions.
- Output blackout/grand-master state/actions.

### Phase RACP-3: Command Safety

- Delivery classes.
- Unique command IDs/idempotency clarification.
- `live_ephemeral` semantics.
- Expiration/staleness handling.
- Momentary leases.
- Disconnect cleanup.

### Phase RACP-4: Remote Surface Assets

- `aurora.remote.surface` asset type.
- Surface schema v1.
- Fixed control vocabulary.
- Asset synchronization/cache validation.
- Unknown-control compatibility behavior.

### Phase RACP-5: Permissions

- Session permission advertisement.
- Required-permission metadata.
- Explicit unauthorized responses.

### Phase RACP-6: Hardening

- Malformed payload tests.
- Reconnect tests.
- Duplicate GO tests.
- Expired-command tests.
- Lost-RELEASE/lease-expiration tests.
- Asset revision mismatch tests.
- Unsupported surface-schema tests.
- Multi-Remote concurrency tests.

---

# 25. Required Conformance Tests

The ACP test suite should add Remote-specific conformance coverage.

## 25.1 GO Is Executed Once

Send the same GO command ID repeatedly due to simulated retransmission.

**Pass:** provider executes GO exactly once and may retransmit the result/ACK without re-execution.

## 25.2 Old GO Is Not Replayed

Send GO, drop connection before normal completion, wait beyond command validity, reconnect.

**Pass:** stale GO is never executed as part of reconnection/recovery.

## 25.3 ACK Does Not Falsify State

Provider accepts a command but delays authoritative state publication.

**Pass:** Remote does not falsely display the requested state as authoritative solely because ACK was received.

## 25.4 Lost Momentary Release

Begin a fog momentary control, then simulate abrupt client/network loss without END.

**Pass:** provider automatically releases fog when the lease expires.

## 25.5 Stale Lease Messages

Create lease A, allow it to expire, create lease B, then deliver a delayed keepalive/end for lease A.

**Pass:** lease B is unaffected.

## 25.6 Surface Asset Hashing

Remote possesses revision A while provider requires revision B.

**Pass:** Remote fetches and validates B before using it.

## 25.7 Unsupported Control Type

Surface contains a control type introduced by a newer schema/client.

**Pass:** older compatible Remote degrades safely without crashing or executing undefined behavior.

## 25.8 Executable Payload Rejection

Attempt to place script/code payloads in a Remote Surface Definition.

**Pass:** schema validation rejects or treats them strictly as inert invalid data; no execution path exists.

## 25.9 Permission Denial

Observe-only Remote attempts GO.

**Pass:** provider explicitly rejects the action and show state does not change.

## 25.10 Free Play Round Trip

Enter Free Play from a programmed song, execute several Looks, then exit Free Play.

**Pass:** provider retains/restores the intended setlist continuation context.

## 25.11 Multi-Remote State Consistency

Remote A executes a Look while Remote B is connected.

**Pass:** both Remotes converge on the same provider-published authoritative state.

---

# 26. Implementation Guardrails

Codex/Grok should treat the following as hard requirements:

1. **Do not redesign ACP's existing transport/framing simply to implement Remote.**
2. **Do not couple generic Remote protocol code to Prism internal types.**
3. **Do not allow executable Remote surface payloads.**
4. **Do not let ACKs masquerade as authoritative state.**
5. **Do not replay stale live commands after reconnect.**
6. **Do not implement momentary controls without leases/fail-safe expiration.**
7. **Do not make Remote manipulate DMX/fixture channels directly.**
8. **Do not make Prism the permanent architectural authority; Conductor must be able to assume that role later.**
9. **Use the existing ACP asset-conformance machinery for Remote surfaces rather than inventing a parallel asset system.**
10. **Maintain heavy protocol comments/documentation around command lifetime, idempotency, leases, state authority, and failure behavior.**

---

# 27. Definition of Done

This ACP amendment is complete when:

- Remote can discover/connect to an ACP Prism endpoint.
- Remote negotiates `aurora.remote.prism.v1` and capabilities.
- Remote receives authoritative initial state and subscribed deltas.
- Songs/setlists can be browsed and selected/loaded semantically.
- GO is acknowledged, idempotent, live-ephemeral, and state-authoritative.
- Global Looks can be enumerated and recalled.
- Free Play can be entered/exited without losing setlist continuation.
- Project-defined declarative Remote surfaces synchronize as ACP assets.
- Momentary controls automatically fail inactive when their lease expires.
- Per-session permissions can be expressed and enforced.
- Disconnect/reconnect cannot replay stale live actions.
- Multiple Remotes converge on the same provider-published state.
- No downloaded executable code is required or permitted by the Remote profile.
- The same ACP client/profile architecture can later add Conductor without rewriting Remote's networking core.

---

## Final Architectural Principle

> **Remote sends intent. The ACP provider performs the operation. The provider publishes truth. Remote renders that truth.**

This rule should guide every implementation decision in the Remote profile.
