# rACP Checkpoint 5: Cross-language consistency

## Decision

The rACP v1 release has Python and Swift implementations plus one language-neutral
wire contract. The Python implementation remains the reference oracle; the Swift 6
`ReasonableACP` product consumes the same canonical vectors and implements the strict
codec, session core, bounded byte-stream connection, and Network.framework TCP adapter.

`vectors/racp-v1/hello.txt` and `vectors/racp-v1/messages.txt` freeze canonical bytes.
Both suites parse and exactly re-encode every line. Each future implementation must
consume these files directly and add malformed, partial-frame, bounds, duplicate-ID,
version, heartbeat, and TCP reconnect tests equivalent to the reference suites.

## Recommended order

1. **Product integration**: Prism and Remote adapters should use `ReasonableACP`, route
   `Command` through their existing normal command and safety APIs, and publish only
   authoritative state.
2. **Rust**: implement a small `racp-core` crate without Tokio, then an optional
   `racp-tokio` adapter when Bridge has a concrete integration. Keep the core free of
   transport and application policy dependencies.
3. Extend the bidirectional matrix from golden-transcript conformance to live
   Python↔Swift TCP sessions, then Python↔Rust and Swift↔Rust sessions when Rust exists.

## Semantic checklist for every port

- UTF-8 and CRLF behavior matches the specification.
- The 16,384-byte limit is measured in encoded bytes, not characters.
- JSON rejects duplicate keys, non-finite numbers, and unsafe integers.
- HELLO fields, ordering, duplicates, and five-second deadline are strict.
- Capabilities mean supported functionality only and never grant authorization.
- No command reaches an application handler before complete validation.
- Identical duplicate commands replay the bounded stored response; conflicting ID reuse
  never invokes the handler.
- ACK is not converted into authoritative state.
- Output and ledgers are bounded; slow peers are disconnected.
- Heartbeat uses monotonic time and requires a matching PONG.
- TCP is only a byte-stream adapter; a future TLS stream changes no session behavior.

## Future integration requirements outside this repository

Application integrations must preserve product-specific authorization, blackout
persistence, lease/hold cleanup, idempotency, and authoritative state routing. They
must also place plain-TCP endpoints behind the intended show/control network boundary.
These are application integration tasks, not additions to the rACP core protocol.

## Checkpoint review

The golden files contain only normative v1 forms and no security credentials, encoding
negotiation, profiles, or generated schemas. Python and Swift now preserve the same
transport-independent semantic shape. Rust remains deferred until Bridge has a concrete
integration need.
