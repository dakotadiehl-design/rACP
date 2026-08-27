# Reasonable ACP (rACP) v1

Status: normative core specification, 2026-08-27. The key words MUST, MUST NOT,
SHOULD, SHOULD NOT, and MAY describe protocol requirements.

## 1. Purpose and trust model

rACP carries bounded commands and authoritative state between show-control
applications and devices. It is intentionally small, observable, and independent of
its byte-stream transport.

The v1 TCP profile is plaintext. It provides **no confidentiality, peer
authentication, cryptographic integrity, or protection from a malicious host able to
reach the service**. Any reachable host can observe traffic and attempt operations.
Operators MUST protect it with appropriate isolated control networks, VLANs, ACLs,
firewalls, VPNs, physical controls, or equivalent architecture.

Capabilities describe functionality, never identity, permission, or authority. An
application MAY reject any otherwise valid command. Network input MUST enter the
application's normal command and safety path; rACP MUST NOT directly mutate arbitrary
application internals. An ACK says that a command handler accepted/completed the
request. It does not assert any state unless the application publishes that state.

## 2. Transport and encoding

rACP runs over an ordered, reliable byte stream. v1 defines TCP; a future TLS/TCP
profile wraps the same stream without changing any message or application semantic.

Each message is exactly one line: UTF-8 bytes followed by LF (`0A`). Senders MUST NOT
send CR. Receivers MAY accept CRLF by removing the single CR immediately before LF.
Empty lines are invalid. UTF-8 MUST be shortest-form valid Unicode and MUST NOT contain
NUL or unescaped C0 controls. JSON string escapes are ordinary printable bytes and are
not line breaks.

The maximum encoded line is 16,384 bytes excluding LF. A receiver MUST bound buffered
input. On an overlong unterminated line it MUST discard through the next LF and close
the connection; it MAY send `ERR 0 line_too_long` first if output is still safe. A
partial final line at EOF is discarded.

Tokens are separated by exactly one ASCII space. There is no leading or trailing
space. Verbs and identifiers are ASCII. Names (capabilities and state/command names)
match `[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*`, maximum 128 bytes. Peer types and peer IDs
match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Request IDs are decimal integers from 1 through
9,007,199,254,740,991 without a leading zero. `0` is reserved for errors not correlated
to a valid request.

Values are a single compact JSON value occupying the remainder of a `CMD` or `STATE`
line. All JSON types are allowed. JSON MUST be UTF-8, must not contain duplicate object
keys, and numbers MUST be finite IEEE-754 binary64 values or integers in the inclusive
range ±9,007,199,254,740,991. Encoders emit no insignificant whitespace, sort object
keys by Unicode scalar value, emit lowercase `true`, `false`, and `null`, and never
emit NaN or infinity. Receivers accept otherwise valid JSON whitespace inside the
value, but deterministic re-encoding uses the canonical rules above.

## 3. Connection establishment

Both peers send a HELLO block immediately after connection. No non-HELLO message may
be sent until both HELLO blocks are complete.

```text
RACP/1 HELLO
PEER <type> <id>
CAP <name>
CAP <name>
END
```

`RACP/1 HELLO` MUST be the first line. `PEER` MUST occur exactly once and before all
CAP lines. CAP occurs zero or more times in ascending byte order and MUST NOT repeat.
`END` terminates the block. Unknown HELLO fields are not permitted in v1. Each peer
MUST finish HELLO within 5 seconds of stream establishment.

A receiver that does not support the version sends
`ERR 0 unsupported_version` and closes. Any other invalid HELLO sends an appropriate
ERR with ID 0 where practical and closes. A peer becomes established only after it has
both sent and accepted HELLO. Capabilities are the peer's advertised supported
functionality; they are not intersected globally because direction matters.

## 4. Established messages

The complete v1 verb set is:

```text
CMD <id> <name>
CMD <id> <name> <json-value>
ACK <id>
ERR <id> <code>
STATE <name> <revision> <json-value>
SUB <id> <name>
UNSUB <id> <name>
PING <nonce>
PONG <nonce>
BYE
```

Error codes use the same grammar as names. Core codes are `malformed_message`,
`line_too_long`, `unsupported_version`, `handshake_required`,
`unsupported_capability`, `invalid_value`, `request_id_conflict`, `busy`,
`permission_denied`, `application_error`, and `heartbeat_timeout`. Applications MAY
define namespaced codes. Unknown error codes are handled as generic errors.

### 4.1 Commands, ACK, and ERR

`CMD` requests application behavior. The command name MUST be present in the receiving
peer's advertised capabilities or the receiver returns
`ERR <id> unsupported_capability`. A command without a value and a command with JSON
`null` are distinct. Exactly one terminal `ACK` or `ERR` is returned per new CMD.

Within one connection, request IDs MUST NOT be reused for different requests. A
receiver keeps a bounded ledger of at least the most recent 1,024 terminal requests.
An identical duplicate still present in the ledger returns the stored response without
re-running the handler. A conflicting reuse returns `ERR <id> request_id_conflict` and
does not invoke the handler. Evicted IDs are no longer protected; senders SHOULD use
monotonically increasing IDs and MUST NOT retry across a new connection unless the
application operation is independently idempotent.

Handlers MUST receive a validated semantic request and return either success or a
structured error code. They remain responsible for authorization, safety validation,
and authoritative state changes.

### 4.2 State and subscriptions

`SUB <id> <name>` requests future publications for exactly one state name. The
receiver returns ACK if it supports both `state.subscribe` and the named state
capability; otherwise it returns unsupported_capability. Subscription does not require
an immediate snapshot. `UNSUB` removes the exact subscription and is idempotent.

`STATE` contains a per-name unsigned revision from 0 through
9,007,199,254,740,991 and a JSON value. Revisions for a name MUST increase within a
connection. A receiver ignores duplicate or older revisions. State is authoritative;
it is not an ACK. A publisher MUST send STATE only for names the peer subscribed to,
unless an application profile explicitly defines unsolicited state.

Implementations MUST bound outbound queues. The default maximum is 256 messages.
Replaceable queued STATE for the same name SHOULD be coalesced to the newest revision.
If a non-replaceable message cannot be queued, the peer is considered slow and the
connection MUST close rather than grow memory without bound.

### 4.3 Heartbeat and close

`PING` and `PONG` nonces are request-ID-format decimal integers. A peer replies to PING
with the identical PONG as soon as practical. After 10 seconds without receiving any
message, a peer SHOULD send PING. If its PONG is not received within 5 seconds, it
closes the connection. Any received message demonstrates inbound liveness but does not
satisfy an outstanding PING unless it is the matching PONG.

`BYE` requests an orderly close. Its recipient stops accepting new commands, may flush
already queued terminal responses, and closes. EOF, reset, malformed input, timeout,
and queue exhaustion are unclean disconnects.

Applications choose reconnect policy. Clients SHOULD use capped exponential backoff
with jitter (suggested 0.25 seconds to 5 seconds), perform a new HELLO, recreate
subscriptions, and obtain fresh authoritative state. Connection-scoped request IDs,
subscriptions, ledgers, and state revision tracking do not survive reconnect. Safety
state such as blackout MUST NOT be cleared merely because a peer disconnects.

## 5. Malformed input and forward compatibility

Unknown established verbs receive `ERR 0 malformed_message`; the receiver MAY continue
only when framing and session state remain unambiguous. Invalid UTF-8, overlong lines,
invalid HELLO, control characters, or repeated malformed input require disconnect.
Implementations SHOULD close after three recoverable malformed established messages.
They MUST never dispatch malformed or partially validated input.

v1 HELLO is strict so peers cannot silently disagree about semantics. Extension work
uses a new protocol version or an explicitly negotiated capability. Receivers ignore
unknown application state names only if they did not subscribe to them; otherwise they
report diagnostics without terminating a healthy connection. Unknown JSON object keys
inside application-defined values are governed by that capability's application
profile, not by the rACP core.

## 6. Plain TCP profile and manual test

Servers listen on an application-configured TCP port; rACP reserves no fixed port.
Sockets SHOULD enable keepalive for dead-path assistance, but protocol heartbeat is
authoritative. Accept queues, connection counts, read/write buffers, and timeouts MUST
be bounded. Closing a session closes its stream exactly once.

A diagnostic exchange can be typed with `nc` (the server sends its HELLO as well):

```sh
nc 192.0.2.10 9000
RACP/1 HELLO
PEER diagnostic laptop
CAP state.subscribe
END
CMD 1 cue.go
SUB 2 cue.current
PING 3
BYE
```

This is safe only on a trusted/isolated network. It is also a deliberate reminder that
any reachable peer can attempt the same commands.
