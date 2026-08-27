# Error codes

Status: **Normative generated-catalog companion**
Canonical sources: `schema/constants.json` and `schema/registry.json`

Stable lowercase dotted codes. `error.report` and `command.ack.error` use this catalog.

| Code | Category | Retryable | Meaning |
|---|---|---|---|
| `unsupported_version` | protocol | false | Handshake ranges do not intersect |
| `unsupported_message` | protocol | false | Directed unknown required type |
| `malformed_envelope` | protocol | false | Missing required envelope fields or bad types |
| `protocol.sequence_gap` | protocol | true | Sequence gap on a live WebSocket (session fault) |
| `invalid_type` | validation | false | Payload failed schema / type checks |
| `invalid_range` | validation | false | Numeric or enum out of range |
| `capability_not_permitted` | authorization | false | Capability not in negotiated intersection |
| `not_found` | not_found | false | Unknown cue, song, resource, or transfer |
| `config.revision_conflict` | conflict | true | `expected_revision` does not match |
| `authority_conflict` | conflict | false | Non-owner publish or lower epoch |
| `unavailable` | unavailable | true | Subsystem offline |
| `timeout` | timeout | true | Waiter expired |
| `cancelled` | unavailable | false | Session goodbye / shutdown |
| `hash_mismatch` | validation | false | SHA-256 did not match staged bytes |
| `unsupported` | unavailable | false | Optional locator/mode not implemented |
| `internal` | internal | false | Unexpected implementation failure |
| `remote.control.unknown` | not_found | false | Control is not in the active layout |
| `remote.control.disabled` | authorization | false | Control exists but is disabled |
| `remote.control.unavailable` | unavailable | true | Target subsystem is offline |
| `remote.control.permission_denied` | authorization | false | Effective permission set does not allow the control |
| `remote.control.conflict` | conflict | true | Exclusive/single-owner hold already active |
| `remote.control.invalid_interaction` | validation | false | Interaction is not valid for the control type |
| `remote.control.invalid_value` | validation | false | Value type/range is not valid |
| `remote.control.stale_state` | conflict | true | Client state is stale; snapshot required |
| `remote.control.not_armed` | authorization | false | Show is not armed |
| `remote.layout.missing` | not_found | false | No layout assigned |
| `remote.layout.stale` | conflict | false | Show/layout identity does not match the active show |
| `remote.layout.invalid` | validation | false | Layout asset failed validation |
| `remote.layout.incompatible` | validation | false | Layout requires an unsupported profile version |
| `remote.session.not_ready` | unavailable | true | Remote is reconnecting/syncing |
| `remote.session.authority_changed` | conflict | true | Active authority changed |
| `remote.momentary.unknown_invocation` | not_found | false | No matching active hold |
| `remote.momentary.expired` | timeout | false | Max-hold or lease expired |
| `remote.command.expired` | timeout | false | Live-ephemeral command past expires_at / max_age |
| `remote.command.invalid_state` | conflict | false | Transition override forbidden or failsafe-required control cannot be leased |
| `remote.command.rate_limited` | unavailable | true | Provider refused the command due to rate |
| `remote.control.unconfirmed_release` | internal | true | Router did not confirm physical inactivity; hold remains unsafe |
| `reliable_queue_overflow` | unavailable | true | Reliable outbound queue full; message not sent |
| `command.precondition_failed` | conflict | false | Typed command precondition did not match authoritative state |
| `command.unknown` | not_found | false | Command-status query found no retained disposition |

## Remote stable outcomes

Every Remote `command.ack` rejection includes `details.disposition` from this closed set. Category and retryability below are the defaults; a specific code may override retryability (see the catalog above).

| Disposition | Category | Retryable | Typical codes |
|---|---|---|---|
| `unauthorized` | authorization | false | `authentication`, `remote.control.permission_denied`, `capability_not_permitted`, `remote.control.not_armed` |
| `unsupported` | validation | false | `unsupported` |
| `invalid_state` | conflict | false | `remote.command.invalid_state`, `remote.layout.invalid`, `hash_mismatch` |
| `stale` | validation | false | `remote.layout.stale` |
| `expired` | timeout | false | `remote.command.expired`, `remote.momentary.expired` |
| `conflict` | conflict | false | `conflict`, `remote.control.conflict` (conflict is retryable) |
| `not_found` | not_found | false | `remote.control.unknown`, `not_found` |
| `rate_limited` | unavailable | true | `remote.command.rate_limited` |
