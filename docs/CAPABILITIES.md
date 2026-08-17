# Capability catalog

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

`trusted_lan` sessions accept the intersection of advertised and accepted capabilities. Missing capability → `capability_not_permitted`.
