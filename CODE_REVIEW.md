# Aurora Communications Protocol — Tenth Deep Code Review

Review date: 2026-08-18

Normative target: ACP 1.2 plus `DesignDocs/ACP_Remote_Profile_Amendments.md`.

Path note (2026-08-19): Swift sources now live under `Sources/AuroraACP/` and `Sources/acp-framed-hello/`. Location citations below still refer to the pre-package `swift/` tree.

This report contains only the fixes still required after Grok's latest pass. The ninth-review findings were rechecked across the repository, all language gates were rerun, and live Python/Rust/Swift interoperability was exercised in CBOR and JSON.

## Outcome

The previous six findings are substantially resolved:

- All **91 registry messages now have shared JSON and canonical-CBOR vectors**.
- `resource.chunk` binary/base64 normalization interoperates across Python, Rust, and Swift.
- Rust and Swift expose transport abstractions and framed TCP peers.
- Python↔Rust and Python↔Swift HELLO sessions pass as client and server, with CBOR and JSON and the Aurora Remote profiles enabled.
- Rust and Swift use configurable profiles; Swift request matching is registry-driven.
- CI now runs the Python Remote WebSocket scenario and framed cross-language tests.

No P0 issue was found. The remaining release work is **two P1 defects and three P2 test/hardening gaps**. The framed cross-language result currently proves successful HELLO negotiation only; it does not prove cross-language ACP application traffic or Aurora Remote behavior.

## Required fixes

### P1-1. Swift session negotiation fails open

Locations: `swift/Sources/ACPSession/ACPSession.swift:193-238,241-275,362-370`.

The Swift server does not negotiate the client's protocol range; it always selects `1.2`. `selectEncoding()` returns the server's first encoding when there is no common encoding, so a HELLO offering only an unsupported encoding is accepted. On the client, `applyHelloAck()` permits missing `protocol` and `encoding`, accepts an out-of-range protocol or unoffered encoding, does not validate heartbeat or limits, and transitions to `established` anyway.

An incompatible or malicious peer can therefore create a session whose subsequent frames cannot be interpreted consistently. Rust already rejects these cases.

Required fix:

- Parse and validate the HELLO protocol range and select the highest mutually supported version; reject the handshake if there is no intersection.
- Make encoding selection throwing/failable and reject a HELLO with no common encoding.
- Require the ACK fields mandated by the session schema, including `protocol`, `encoding`, `heartbeat_interval_ms`, `peer_capabilities`, and `limits`.
- Verify that the selected protocol is inside the offered range, encoding was offered, profiles are a subset of those offered, heartbeat/limits are valid, and envelope/source identity is consistent before mutating state.
- On every failure path, leave the session in `failed` and close or make the transport unusable.
- Add negative Swift and cross-language tests for disjoint protocol ranges, no common encoding, missing ACK fields, unoffered ACK values, invalid heartbeat/limits, and source/node mismatch.

### P1-2. Swift's handshake and request timeouts do not bound I/O

Locations: `swift/Sources/ACPSession/ACPSession.swift:158-166,282-299`; `swift/Sources/ACPSession/ACPFramed.swift:19-37,53-86,103-130`.

`waitType()` and `request()` compare a deadline only before calling `pumpOnce()`. `pumpOnce()` awaits `transport.recv()` without a deadline. A peer that connects but sends no frame can suspend these APIs forever despite the advertised timeout. Listener startup and `accept()` have the same unbounded-wait characteristic.

Required fix:

- Race each blocking receive against the remaining deadline using structured concurrency, cancel the losing operation, and ensure cancellation reaches the transport read.
- Apply bounded waits to connect/start and listener accept in the framed peer, or expose caller-supplied deadlines.
- Set a deterministic session state on timeout and define whether the connection is closed or reusable.
- Add silent loopback and real-TCP tests proving elapsed time is bounded and no read task/continuation leaks.

### P2-1. Cross-language live tests stop after HELLO

Locations: `tests/interop/test_framed_cross.py:22-65,99-165`; `rust/acp-session/examples/framed_hello.rs`; `swift/Sources/acp-framed-hello/main.swift`.

Each foreign pairing negotiates a session and immediately sends `session.goodbye`. No established-session application envelope crosses a language boundary. The test does not exercise sequence handling, registry admission, request correlation, post-handshake encoding, payload decoding, or an Aurora Remote message. There is also no direct Rust↔Swift pairing.

Required fix:

- After HELLO, exchange and assert `health.heartbeat`, `state.request` → correlated `state.snapshot`, and `session.goodbye` in both directions and encodings.
- Add a Remote scenario that negotiates capabilities/profiles, transfers a binary `resource.chunk`, completes and activates the resource, performs a control invoke/result pair, and verifies state convergence.
- Add negative live cases for wrong session ID/source, sequence errors, unsupported message/capability, malformed payload/frame, connection loss, and request timeout.
- Add direct Rust-client↔Swift-server and Swift-client↔Rust-server runs, or explicitly track that missing edge in the support matrix.

### P2-2. Rust and Swift do not enforce payload schemas at the codec/session boundary

Locations: `python/src/acp/codec.py:72-97`; `rust/acp-codec/src/lib.rs`; `rust/acp-session/src/session.rs:652-746`; `swift/Sources/ACPEncoding/ACPEncoding.swift`; `swift/Sources/ACPSession/ACPSession.swift:144-155,313-324`.

Python validates the envelope and registry-selected payload schema during decode. Rust and Swift decode envelope fields but do not validate the per-message schema. Rust admission enforces registry role/capability/QoS rules, but a schema-invalid payload can enter the inbox. Swift admission enforces only handshake/session ID/sequence/source and omits registry sender, capability, QoS, minimum-protocol, and known-message rules.

Required fix:

- Generate or implement payload validators from the canonical schemas in Rust and Swift and invoke them before an envelope reaches application/session code.
- Add Swift registry admission equivalent to Rust/Python for known type, legal-before-handshake, sender role, negotiated capability/version, minimum protocol, and allowed QoS.
- Fail closed on unknown messages and malformed required fields with the ACP-defined error category.
- Add a shared invalid-message corpus covering every schema family and tests proving invalid envelopes never enter the inbox or mutate Remote state.

### P2-3. The framed CI harness is nondeterministic and may silently skip its target SDK

Locations: `tests/interop/test_framed_cross.py:150-158`; `.github/workflows/ci.yml:66-77,91-103`.

The harness auto-runs every compiler it finds. The Python/Rust job may also attempt Swift on Ubuntu, while the Python/Swift macOS job may also run Rust. If the intended toolchain is absent, the script can print a skip and exit successfully. Coverage therefore depends on runner contents.

Required fix:

- Add a required `--sdk rust|swift` argument and fail if the selected peer cannot be built or found.
- Pass `--sdk rust` in the Rust job and `--sdk swift` in the Swift job.
- Give every subprocess a total deadline, print captured output on failure, and terminate then wait for children in all cleanup paths.
- Split HELLO-only and full-session/Remote jobs so CI names accurately state the behavior proved.

## Verification completed

- Python: **130 passed**, 81.91% coverage; Ruff passed; mypy passed for 23 source files.
- Rust: **21 tests passed**; Clippy with `-D warnings` passed; rustfmt passed.
- Swift: **16 tests passed**.
- Registry/vector checks: **91 registry rows, 91 vectors**; frozen vectors passed.
- Python localhost WebSocket HELLO: passed.
- Python localhost Aurora Remote scenario: passed.
- Python↔Rust framed HELLO: passed as client/server using CBOR and JSON with Remote profiles.
- Python↔Swift framed HELLO: passed as client/server using CBOR and JSON with Remote profiles.
- `git diff --check`: passed before this report update.

## Release recommendation

The previous wire-format blocker is resolved, and the Python Remote implementation remains a credible reference. Do not yet describe Rust/Swift as production-complete live ACP or Aurora Remote implementations. Fix both P1 items before shipping the Swift session API, and complete P2-1/P2-2 before claiming full cross-language session or Remote interoperability.

---

## Phase 0A freeze addendum (2026-08-19)

Tag **`AuroraACP 1.0.0`** at `56c429b6002e6fd2008c5414e5d4032a15ccf5b0` (commit of the freeze; annotated tag object is distinct). Wire protocol remains **ACP 1.2**.

The tenth-review P1/P2 list above describes the pre-freeze tree. Rechecked against `Sources/AuroraACP/` and the 0A verification suite:

| Finding | 1.0.0 status | Evidence |
|---|---|---|
| P1-1 Swift negotiation fail-open | **Resolved** | `ACPNegotiate.selectVersion` / `selectEncoding` throw; `applyHelloAckValidated` requires ACK fields; `testRejectsDisjointProtocolAndEncoding`, `testApplyHelloAckRequiresFields` |
| P1-2 unbounded handshake I/O | **Resolved** | `recvBounded`; `testHandshakeTimeoutIsBounded`; `testFramedAcceptAndHandshakeTimeoutsAreBounded` |
| P2-1 HELLO-only interop | **Resolved** | `test_framed_cross.py --suite session\|remote\|negative`; `--sdk rust-swift --suite session` |
| P2-2 payload schema at Swift/Rust boundary | **Open (Phase 0B)** | Swift `admit` uses registry role/capability/QoS/protocol rules. Per-message payload schema validation is still Python-complete and not fully applied on Swift/Rust decode-before-inbox. |
| P2-3 CI SDK skip | **Resolved** | `--sdk rust\|swift\|rust-swift` is required; CI jobs pass `--sdk` and split hello vs session/remote/negative |

Re-run counts at freeze (not the tenth-review counts):

- Python: **131 passed**, 81.93% coverage; Ruff passed; mypy passed for 23 source files
- Rust: **22 tests passed**; Clippy `-D warnings` passed; rustfmt passed
- Swift: **22 tests passed**
- Registry/vectors: **91 / 91**
- Python WebSocket HELLO + Remote: passed
- Python↔Swift and Python↔Rust framed hello/session/remote/negative: passed
- Rust↔Swift framed session: passed
- External dummy package `import AuroraACP`: passed

Remaining work after this tag is **Phase 0B feature development**, not another package conversion: snapshot/delta epoch envelopes, `command.status_*`, command ledger, preconditions, availability vs capability, provenance, priority/coalescing, generic Swift WebSocket, portable discovery + Bonjour mapping, P2-2 schema admission, and a production Swift Remote authority (do not promote `ACPRemoteAuthority`).
