# ACP Swift Remote Client Readiness Amendments

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

## Purpose

This document defines the ACP-side changes required before beginning production implementation of **Aurora Remote** against the **Prism Remote profile**.

The goal is not to redesign ACP. The current ACP architecture is already suitable for Aurora Remote. These changes are intended to close the remaining gap between the current Swift implementation and the newer Remote-profile schemas, harden the client behavior for production use, and preserve a clean path to a future Conductor Remote profile.

Aurora Remote is intended for App Store distribution. Therefore, **all Remote surfaces and assets must remain strictly declarative and non-executable**. Prism or Conductor may describe controls, state bindings, labels, layout, ranges, safety metadata, icons, and semantic actions, but may never transmit code for Aurora Remote to execute.

---

## Architectural rule

**Remote sends intent. The ACP provider performs the operation. The provider publishes authoritative state. Remote renders that state.**

Consequences:

- ACK confirms command disposition only.
- ACK must never be treated as proof that Prism state changed.
- SwiftUI or other UI code must not derive operational truth directly from command responses.
- Prism remains authoritative for song state, section state, look state, master dimmer, blackout, and all other controlled state.
- Remote must be able to reconnect without replaying stale live actions.
- The Remote wire contract must remain product-neutral enough to support Conductor later.

---

# 1. Bring handwritten Swift Remote models into parity with current schemas

The current generated schema pack contains more Remote functionality than the handwritten Swift convenience models expose.

This should be corrected before substantial Aurora Remote application work begins.

## 1.1 `ACPRemoteControl`

Expand the Swift model so it can represent the current Remote control schema, including at minimum:

- `control_id`
- `label`
- `control_type`
- `permission`
- semantic binding:
  - provider-neutral `target`
  - semantic `action`
  - typed/declarative `parameters`
- `delivery`
- `traffic_class`
- `feedback`
- presentation/style metadata
- numeric constraints:
  - `min`
  - `max`
  - `step`
  - `units`
- `availability_binding`
- safety metadata:
  - safety class
  - failsafe requirement
  - maximum hold time
- conditions
- accessibility metadata:
  - accessibility label
  - accessibility hint

Do not introduce Prism-native object types into this model.

Bindings must remain semantic and provider-neutral.

Example:

```text
action = "output.grand_master.set"
parameters = { value: 0.75 }
```

not:

```text
set AuroraModel.fixtureUniverse[0].channel[37] = 191
```

## 1.2 Surface/layout model

Bring the Swift layout/surface model into parity with the current schema.

The production model should support at minimum:

- stable `surface_id`
- `revision`
- `schema_version`
- `compatible_profile`
- minimum supported client surface schema
- maximum supported client surface schema, if present
- `sha256`
- display name/title
- pages/groups
- controls
- optional project/show association
- compatibility metadata

The historical `layout_id` terminology may remain supported for compatibility, but the Swift production API should prefer **surface** terminology.

## 1.3 Typed Remote permission vocabulary

Expose typed Swift representations for the Remote permission vocabulary rather than requiring application code to scatter raw strings throughout the codebase.

Expected permissions include at least:

- observe
- song select
- song load/start
- cue/section execute
- look execute
- busk execute
- grand master control
- blackout control
- remote surface use

Roles and permissions remain separate concepts.

---

# 2. Add explicit Prism Remote profile constants and capability presets

The Swift ACP package should expose a production-safe Remote client configuration for Prism.

## 2.1 Profile constants

Provide typed/static constants for:

```text
aurora.remote.prism.v1
aurora.remote.conductor.v1
```

The Conductor profile is reserved for future use only.

Aurora Remote 1.0 should require negotiation of:

```text
aurora.remote.prism.v1
```

when connecting directly to Prism.

## 2.2 Capability preset

Do not rely on the generic `ACPSession.defaultCapabilities` for the production Remote app.

Add an explicit capability preset, conceptually similar to:

```swift
ACPCapabilitySet.prismRemoteClient
```

It should advertise all Remote 1.0 capabilities supported by the current implementation, including the relevant existing ACP Remote capabilities and feature capabilities for:

- profile negotiation
- Remote control invocation
- Remote state
- readiness
- navigation
- presentation
- momentary controls
- surfaces/layouts
- song selection/loading
- show navigation
- master dimmer
- blackout
- looks
- live state
- health/status

A corresponding provider-side preset may also be useful for Prism.

The exact names must use the existing registry and schema vocabulary rather than creating a parallel list.

---

# 3. Fix Swift schema validation for conditional JSON Schema rules

The Swift schema validator currently supports many common JSON Schema constructs but must also correctly enforce conditional rules used by the ACP Remote schemas.

Implement support for:

```text
if
then
else
```

at the validation layer.

This is important for Remote invocation rules such as requiring a lease identifier for:

```text
momentary_end
momentary_cancel
```

Runtime validation in higher-level Remote code may remain as defense in depth, but the schema validator must not silently ignore valid constraints defined by the source schema.

Add unit tests for:

- matching `if` followed by valid `then`
- matching `if` followed by invalid `then`
- non-matching `if`
- `else`, if used by ACP schemas
- Remote momentary end/cancel missing `lease_id`
- valid momentary end/cancel with `lease_id`

---

# 4. Enforce authoritative-state behavior in the Swift Remote client

The current Remote helper layer must not evolve into an optimistic-state client.

## Required behavior

When Remote sends:

```text
output.grand_master.set = 0.5
```

and receives:

```text
command.ack = accepted
```

the Remote application must not assume the master dimmer is now 50%.

The displayed value changes only when Prism publishes authoritative state such as:

```text
output.grand_master = 0.5
```

The same rule applies to:

- selected song
- loaded/current song
- current section
- next section
- song running/stopped state
- look state
- Free Play state
- blackout
- effects state
- master dimmer
- health/status values

## Implementation guidance

Refactor or constrain `ACPRemoteSession` so command results are used for:

- accepted/rejected disposition
- errors
- invocation tracking
- lease tracking
- retry/idempotency behavior

but not as the primary source of operational state.

Provide clean helpers for consuming:

- `state.snapshot`
- `state.delta`
- `remote.control.snapshot`
- `remote.presentation.state`
- `remote.navigation.state`

The future Aurora Remote state store should be able to consume these without parsing raw ACP envelopes in SwiftUI.

---

# 5. Add production-grade state synchronization helpers

The Swift ACP package should expose enough structure that Aurora Remote can maintain an authoritative local mirror of Prism state.

At minimum, support convenient consumption of state namespaces for:

```text
show.setlist
show.selected_song
show.current_song
show.current_section
show.next_section
show.mode
show.running
show.progression

look.catalog
look.current
look.preview

output.grand_master
output.blackout

system.health
```

Use existing ACP state snapshot/delta revision machinery.

Do not create a second Remote-specific state transport.

## Revision handling

The helper layer should:

- track authority epoch
- track revision
- reject stale deltas
- detect gaps
- request/resynchronize snapshots when needed
- avoid applying state from a previous authority/session epoch

This will be particularly important later when Conductor redundancy exists.

---

# 6. Preserve strict live-ephemeral command behavior

Verify the Swift Remote client fully honors existing delivery semantics.

Live actions such as:

- GO / advance
- section transition
- look take/trigger
- momentary begin/end
- blackout trigger operations, where applicable

must never be queued across a lost session.

On disconnect:

- unacknowledged live-ephemeral actions are discarded
- stale actions are not replayed after reconnect
- expired actions are rejected
- duplicate invocation IDs must not cause duplicate execution

Stateful controls such as master dimmer may use their defined reliable/stateful semantics, but the client should still resolve final truth from published state.

---

# 7. Harden momentary control behavior

Momentary controls are a first-class live-show safety concern.

Examples include:

- fog
- blinders
- strobes
- other hold-to-run actions

Verify Swift support for:

- begin
- refresh/keepalive
- end
- cancel
- lease identifier
- lease expiry
- provider-side maximum hold
- disconnect release
- stale lease message rejection

The app should never be capable of leaving a momentary action logically held merely because Wi-Fi disappeared.

Safety metadata supplied by a surface may describe provider-defined behavior such as:

```text
failsafe_required
max_hold_ms
```

Remote honors those limits but does not define device-specific safety logic itself.

---

# 8. App Store safety: Remote surfaces must be declarative only

This is a hard design requirement.

Aurora Remote may download or synchronize Remote surfaces, but those surfaces are **configuration data**, not executable programs.

## Allowed surface content

Examples:

- labels
- pages
- groups
- control types
- icons from an approved/known asset model
- control sizes
- control ranges
- units
- semantic action identifiers
- state bindings
- availability bindings
- permission requirements
- accessibility metadata
- styling/presentation metadata
- safety/failsafe metadata
- transition metadata
- declarative conditions supported by the installed app

## Forbidden content

Remote surfaces and ACP assets must not contain or cause execution of:

- Swift source
- Objective-C source
- JavaScript
- Lua
- Python
- shell scripts
- WebAssembly
- executable binaries
- dynamic libraries
- arbitrary HTML/JavaScript applications
- downloaded plugins
- arbitrary expressions evaluated as code
- command strings executed by the operating system
- code-generation payloads
- reflection-based arbitrary method invocation
- serialized closures/functions

No surface field may act as a disguised script container.

Fields such as the following should be rejected if encountered in a Remote surface payload unless they are explicitly part of a safe non-executable schema for another purpose:

```text
script
javascript
js
lua
python
wasm
html
shell
command
executable
plugin
binary
source
eval
expression
```

The exact blocklist is defense in depth only. The primary protection must be a strict allowlisted schema.

## Native control vocabulary

Aurora Remote itself contains the installed implementation of supported control types, for example:

- button
- momentary button
- toggle
- slider/fader
- encoder
- selector
- XY pad
- color control
- preset tile
- label
- value display
- status indicator
- group
- spacer

Prism merely declares:

```text
control_type = "slider"
action = "output.grand_master.set"
```

Aurora Remote decides how a slider behaves because the slider implementation shipped inside the App Store binary.

## Unknown control types

Unknown future control types must:

- fail closed for invocation
- not execute arbitrary fallback behavior
- be skipped or represented as unsupported
- not invalidate unrelated compatible controls unless the surface itself is structurally unsafe

This allows older App Store builds of Remote to coexist safely with newer Prism versions.

---

# 9. Surface schema compatibility must be explicit

Add or expose clear compatibility checks for Remote surfaces.

Before activating a downloaded surface, Remote must verify:

- hash
- declared schema version
- compatible ACP Remote profile
- minimum client surface schema
- maximum client surface schema, where defined
- supported control types
- binding validity
- safety constraints
- absence of forbidden executable content

If the surface is incompatible, Remote should reject that surface cleanly while keeping the ACP session alive and preserving unrelated native Remote functionality.

A bad Busk page must not take down the Show screen.

---

# 10. Binding validation must remain semantic and allowlisted

Remote surface action bindings must reference semantic ACP Remote actions only.

Examples:

```text
show.song.select
show.song.load
show.song.stop
show.section.next
show.section.previous
show.section.restart
cue.go
look.recall
look.preview
look.take
look.preview.cancel
show.free_play.enter
show.free_play.exit
output.grand_master.set
output.blackout.set
effects.stop
```

Not all of these need to exist immediately, but any added action must be formally registered/documented.

Bindings must not contain:

- Prism class names
- Swift selectors
- arbitrary key paths into Prism internals
- DMX channels
- fixture memory addresses
- arbitrary function names
- executable command strings

Provider adapters map semantic actions into Prism behavior.

---

# 11. Discovery service naming should be frozen before Remote ships

Review and formally choose the Bonjour service identifier used by ACP.

The Swift implementation currently uses a generic ACP service form.

The Remote design has also considered an Aurora-specific form such as:

```text
_aurora-acp._tcp
```

Resolve this once at the ACP specification level.

Do not ship Aurora Remote with one discovery name and later casually rename it.

If backward-compatible aliases are required, define them explicitly.

The chosen service must still represent ACP discovery rather than a Prism-specific transport.

---

# 12. Add a production Remote client abstraction

`ACPRemoteSession` is useful, but Aurora Remote will benefit from a clearer production client surface.

This may be implemented by evolving `ACPRemoteSession` or by adding a higher-level type.

Conceptual responsibilities:

```text
ACPRemoteClient
    - profile negotiation
    - negotiated capabilities
    - permissions
    - readiness
    - surface synchronization
    - command dispatch
    - invocation tracking
    - lease management
    - authoritative state synchronization
    - reconnect handling
    - error mapping
```

It should not contain Prism UI logic.

Aurora Remote should be able to place its own product layer above it:

```text
ACPRemoteClient
        ↓
PrismRemoteProvider
        ↓
PrismRemoteStore
        ↓
SwiftUI
```

Later:

```text
ACPRemoteClient
        ↓
ConductorRemoteProvider
        ↓
RemoteStore
        ↓
SwiftUI
```

No rewrite of the ACP client should be required.

---

# 13. Prism Remote 1.0 vocabulary coverage

Ensure the Swift models/registry can represent the intended initial Prism Remote functionality.

## Song/show control

- select song from setlist
- load/start song
- stop song
- previous song
- next song
- GO / advance
- next section
- previous section
- restart current section
- hold/pause progression

## Lighting control

- master dimmer
- blackout
- recall Global Look
- stop active effects

## Ad-hoc operation

- enter Free Play
- return to programmed setlist

## Monitoring

- current song
- selected song
- next song
- current section
- next section
- song running/stopped
- progression state
- current look
- master dimmer
- blackout
- Prism health
- ACP health
- DMX/output health
- warnings

Where exact semantic identifiers do not yet exist, add them through the existing registry/profile mechanism rather than inventing new message families.

---

# 14. Recommended implementation sequence

## ACP-SR1 — Swift model parity

- update Remote control model
- update Remote surface model
- typed permissions
- typed Prism/Conductor Remote profile identifiers
- compile/test generated schema integration

## ACP-SR2 — Schema validation hardening

- implement `if` / `then` / `else`
- add Remote conditional-validation tests
- verify executable-surface rejection

## ACP-SR3 — Capability and profile configuration

- add Prism Remote client capability preset
- verify profile negotiation
- verify missing required profile/capability failure behavior
- reserve Conductor without enabling it

## ACP-SR4 — Authoritative state client

- snapshot/delta helpers
- authority epoch/revision tracking
- stale/gap handling
- remove or isolate ACK-derived operational values

## ACP-SR5 — Remote surfaces

- surface asset compatibility
- SHA-256 verification
- schema compatibility
- unknown-control degradation
- strict declarative-only validation
- no executable payload path

## ACP-SR6 — Safety and reconnect testing

- live-ephemeral discard on disconnect
- duplicate invocation idempotency
- stale command expiry
- lease expiry
- stale lease rejection
- disconnect release
- surface incompatibility
- permission denial
- malformed payload behavior

---

# 15. Required conformance tests

At minimum add/retain tests covering:

1. Prism Remote profile negotiation succeeds.
2. Missing Prism Remote profile fails closed.
3. Required Remote capability unavailable is reported cleanly.
4. ACK accepted without state publication does not alter authoritative client state.
5. State delta updates authoritative client state.
6. Stale state delta is rejected.
7. Revision gap triggers resynchronization.
8. Duplicate GO does not execute twice.
9. Stale GO is not replayed after reconnect.
10. Momentary end without lease identifier fails validation.
11. Lost momentary release expires safely.
12. Stale lease messages cannot affect a newer lease.
13. Surface hash mismatch triggers re-fetch/revalidation.
14. Unknown control type does not execute.
15. Unknown control type does not break compatible controls.
16. Surface containing executable/script payload is rejected.
17. Surface with incompatible client schema is rejected cleanly.
18. Permission denial is explicit.
19. Multi-Remote clients converge on provider-published state.
20. Session reconnect cannot apply state from an old authority epoch.

---

# 16. Out of scope for this ACP pass

Do not implement in ACP:

- Prism UI
- Remote SwiftUI screens
- fixture patching
- fixture programming
- DMX channel-level controls
- cue editing
- effects editing
- MIDI mapping UI
- Prism-internal model renaming
- Conductor implementation
- executable Remote plugins
- downloaded scripting
- arbitrary web-app surfaces
- remote desktop/screen streaming

This pass exists only to make the Swift ACP package production-ready for Aurora Remote.

---

# 17. Definition of done

The ACP Swift package is ready for Aurora Remote development when:

- Aurora Remote can discover an ACP endpoint using the finalized Bonjour service.
- The client can negotiate `aurora.remote.prism.v1`.
- A production Prism Remote capability preset exists.
- Current Remote schemas are accurately represented by Swift models.
- Conditional schema rules are enforced.
- Remote surfaces are strictly declarative.
- No downloaded Remote asset can execute arbitrary code.
- Surface compatibility is checked before activation.
- Unknown controls fail safely.
- Commands and ACKs are separated from authoritative operational state.
- State snapshots/deltas maintain a correct local mirror with revision/epoch protection.
- Live-ephemeral commands are never replayed after reconnect.
- Momentary controls fail inactive on timeout/disconnect.
- Prism Remote 1.0 semantic actions and state can be represented without exposing DMX or Prism implementation details.
- Nothing in the implementation prevents adding `aurora.remote.conductor.v1` later.

---

## Final implementation principle

Aurora Remote must remain a **native App Store application whose behavior is shipped in the application binary**.

ACP may tell Remote:

> “Render a fader labeled Master and bind it to `output.grand_master.set`.”

ACP must never tell Remote:

> “Download and execute this code to create a new control.”

That boundary should be treated as both an App Store requirement and a security boundary for the Aurora ecosystem.
