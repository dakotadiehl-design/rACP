# Error codes

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
| `reliable_queue_overflow` | unavailable | true | Reliable outbound queue full; message not sent |
