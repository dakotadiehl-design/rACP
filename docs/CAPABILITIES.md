# Capability catalog

Status: **Normative generated-catalog companion**
Canonical source: `schema/constants.json`

Capability IDs are stable lowercase dotted strings. Versions evolve independently of ACP minor versions. A peer must not send capability-specific commands until the capability is in the negotiated intersection.

| ID | Min protocol | Meaning |
|---|---|---|
| `health.heartbeat` | 1.0 | Application heartbeat and health snapshot |
| `bridge.status` | 1.0 | Bridge network/uptime/output status |
| `bridge.blackout` | 1.0 | Scoped blackout command + authoritative state |
| `bridge.config` | 1.0 | Typed configuration get/set |
| `bridge.artnet_output` | 1.0 | Art-Net metadata (edge protocol remains Art-Net) |
| `bridge.dmx_output` | 1.0 | DMX port state |
| `prism.cue_control` | 1.0 | `cue.go` / `cue.fire` / `cue.stop` |
| `asset.conformance` | 1.2 | Show manifest, prepare/verify/arm |
| `resource.transfer` | 1.2 | Chunked (or stubbed HTTP) asset transfer |
| `lyric.assignment` | 1.2 | Participant/chart assignment |
| `authority` | 1.2 | `authority_node_id` / `authority_epoch` enforcement |
| `remote.profile` | 1.2 | Remote identity, permissions, session readiness |
| `remote.layout` | 1.2 | Versioned remote layout asset |
| `remote.control.invoke` | 1.2 | Semantic control invocation |
| `remote.control.momentary` | 1.2 | Momentary begin/end + fail-safe |
| `remote.control.state` | 1.2 | Per-control enabled/value feedback |
| `remote.navigation.song` | 1.2 | Browse vs activate song navigation |
| `remote.navigation.section` | 1.2 | Section enter/next/previous |
| `remote.navigation.cue` | 1.2 | Current/Next/GO presentation |
| `remote.transport` | 1.2 | Transport controls exposed to Remote |
| `remote.busking` | 1.2 | Explicitly published live busking actions |
| `remote.readiness` | 1.2 | Remote show-readiness reporting |
| `remote.asset_sync` | 1.2 | Remote layout/control-set conformance |
| `remote.presentation` | 1.2 | Operator-facing presentation state |
| `show.navigation` | 1.2 | Setlist / free-play / navigation feature |
| `song.selection` | 1.2 | Select a song without making it live |
| `song.loading` | 1.2 | Load/activate a song |
| `cue.go` | 1.2 | Feature flag for GO / cue fire |
| `look.global` | 1.2 | Global Look catalog and recall |
| `remote.surfaces` | 1.2 | Declarative Remote Surface assets |
| `busk.controls` | 1.2 | Published busk actions |
| `control.momentary` | 1.2 | Feature flag for leased momentary holds |
| `output.blackout` | 1.2 | Output blackout set |
| `output.grand_master` | 1.2 | Grand-master set |
| `command.status` | 1.2 | `command.status_request` / `command.status_report` recovery |
| `state.live` | 1.2 | Live show state namespaces |
| `system.health` | 1.2 | Health/warnings subscription |

`trusted_lan` sessions accept the intersection of advertised and accepted capabilities. Missing capability → `capability_not_permitted`. When a registry row has `min_capability_version`, an explicit negotiated version is required; absent, malformed, or below-minimum values also return `capability_not_permitted`.

Aurora Remote 1.0 must not use `ACPSession.defaultCapabilities`. Use `ACPCapabilitySet.prismRemoteClient`, which advertises the `remote.capabilities` and `remote.feature_capabilities` catalogs from `schema/constants.json`. After handshake, `ACPRemoteClient` fails closed if `aurora.remote.prism.v1` or a required Remote capability is missing from the intersection. `aurora.remote.conductor.v1` remains reserved.
