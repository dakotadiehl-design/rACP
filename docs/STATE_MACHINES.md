# Session, sequence, acknowledgement, and idempotency

Golden vectors do **not** test these machines. TestKit suites do.

## Version negotiation

- Envelope `acp` is the message schema version for that message.
- `session.hello.protocol.{min,max}` advertises a range. `session.hello_ack.protocol` is the selected session version.
- min and max must share a major and min ≤ max. Selected = highest minor in the intersection of the two ranges.
- Empty intersection, malformed range, or unsupported major → `accepted: false`, `unsupported_version`.
- Do not emit a type whose registry `min_protocol` exceeds the session version.
- 1.2-only types also require their capability. Capabilities cannot smuggle a 1.2 type into a 1.0 session.

## Connection

```
Closed → Connecting → HelloSent → Established → GoodbyeSent → Closed
                 ↘ Failed
Established → Reconnecting → HelloSent   # fresh session_id; sequence restarts at 1
```

Only `session.hello`, `session.hello_ack`, handshake `error.report`, discovery types, and the Aurora Trust enrollment allowlist below are legal before Established. After Established, `session_id` and `sequence` are required.

Aurora Trust adds a restricted enrollment pre-session state:

```text
Connected → EnrollmentRestricted → EnrollmentComplete → Closed
                               ↘ Failed / Expired / Locked → Closed
```

Only `security.enrollment.status`, `security.enrollment.begin`, `security.enrollment.challenge`, `security.enrollment.response`, `security.enrollment.confirm`, `security.enrollment.approval`, `security.enrollment.install_result`, `security.enrollment.cancel`, and handshake `error.report` are legal in `EnrollmentRestricted`. This state has no ordinary ACP principal, negotiates only `security.enrollment`, cannot route Remote/control/resource messages, and cannot transition into an established control session. After successful enrollment both peers close it and establish a fresh authenticated connection.

Lightweight authentication adds a distinct pre-HELLO state after mutual RPK TLS:

```text
TLSAuthenticated → LightweightBinding → HelloSent/HelloReceived → Established
                                    ↘ Failed → Closed
```

Only `security.lightweight.finished` and handshake `error.report` are legal in `LightweightBinding`. HELLO is rejected until both finished messages verify. After both verify, `security.lightweight.finished` becomes illegal and ordinary HELLO proceeds. This state is not `EnrollmentRestricted` and cannot route any other ACP family.

`session.goodbye` fails pending waiters with `cancelled`, aborts transfers, then closes. It does not mutate peer safety state (including blackout).

## Sequencing and QoS

One sequence space per session per sender. Sequence is assigned **after** outbound QoS, at the moment the envelope is written to the socket. Coalesced `latest` drafts and dropped `best_effort` never consume a sequence. Reliable overflow is a fault: nothing is sent, no sequence is consumed.

A gap on a live WebSocket is an implementation/session fault (the transport is ordered and reliable). Emit `protocol.sequence_gap`, request `state.snapshot` for subscribed+owned resources, and reset the session on a second gap or a gap larger than 1.

`latest` coalesce key: `(type, payload.resource)` if present, else `(type, destination.node_id)`.

## Correlation

If the request omitted `correlation_id`, acks use `correlation_id = request.message_id`. Otherwise acks copy it. Derived events set `causation_id = request.message_id`.

Lifecycle: `accepted` is non-terminal unless no further ack is promised. `applied` / `completed` / `rejected` / `failed` / `duplicate` are terminal. Status moves forward only. First terminal ack completes the waiter. Late acks after timeout do not complete it a second time.

## Idempotency

Key: `payload.idempotency_key`. Scope: `(local_node_id, message_type, key)`. Retained for the session plus 60 s after close. Not persisted across reboot. Safety state (blackout, armed manifest) is persisted **state**, so a post-reboot retry applies the same desired state.

Cache hit → `command.ack` status `duplicate` with the prior terminal result.

Blackout last-write; reconnect does not clear unless `bridge.blackout.clear_on_disconnect` is true (default false).

## Resource transfer

```
Idle → Offered → Accepted → Receiving → Verified → Activating → Idle
              ↘ Rejected
                         ↘ Failed / Cancelled
                                          ↘ Failed (previous asset remains)
```

Chunks are `reliable` envelopes. Assemble by offset. SHA-256 over concatenated staged bytes. Activate is a separate message. Failed activation leaves the previous asset intact.
