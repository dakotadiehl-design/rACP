# rACP Checkpoint 5: Cross-language consistency

## Decision

The initial rACP v1 release has one implementation, in Python, and one language-neutral
wire contract. Swift and Rust ports should follow concrete application needs rather
than being created only for language symmetry. This keeps lifecycle and parser review
focused while the protocol contract is still young.

This is a reduction in implementation scope, not in interoperability commitment.
`vectors/racp-v1/hello.txt` and `vectors/racp-v1/messages.txt` freeze canonical bytes.
The Python suite parses and exactly re-encodes every line. Each future implementation
must consume these files directly and add malformed, partial-frame, bounds, duplicate
ID, version, heartbeat, and TCP reconnect tests equivalent to the reference suite.

## Recommended order

1. **Swift**: implement the value types, line codec, and transport-independent session
   as a new `ReasonableACP` product. Add a Network.framework TCP byte-stream adapter.
   Prism and Remote adapters must route `Command` through their existing normal command
   and safety APIs and publish only authoritative state.
2. **Rust**: implement a small `racp-core` crate without Tokio, then an optional
   `racp-tokio` adapter when Bridge has a concrete integration. Keep the core free of
   transport and application policy dependencies.
3. Run a bidirectional matrix using the golden transcripts first, then Python↔Swift,
   Python↔Rust, and Swift↔Rust TCP sessions including fragmented writes and malformed
   peers.

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
negotiation, profiles, or generated schemas. The language recommendation preserves a
single transport-independent semantic shape. Deferring Swift and Rust avoids claiming
false cross-language confidence while still making exact conformance measurable.
