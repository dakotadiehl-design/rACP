# Aurora Communications Protocol — Second Deep Code Review

Review date: 2026-08-17

This is a fresh review of Grok's remediation pass across the full current tree. The directory still has no Git metadata, so this review is based on the snapshot rather than a trustworthy before/after diff.

## Outcome

The remediation is meaningful: transfer coverage, queue separation, negotiation intersections, WebSocket bounds, packaged Python data, finite-number checks, discovery bounds, and several CBOR checks improved. All current automated checks pass.

The repository is still not production-ready. Two high-impact session issues remain: clients do not know the authenticated peer's role and reject legitimate role-specific messages, and the supposed schema validator accepts schema-invalid payloads. Several security and lifecycle fixes are partial.

Severity: `P0` blocks safety-sensitive deployment, `P1` blocks general production deployment, and `P2` is required conformance/resilience work.

## Original 22 findings: remediation status

| Original finding | Status | Notes |
|---|---|---|
| 1. Inbound session validation | Partial | Central gate added; peer role, envelope version, destination kind/component, payload validation, and handshake binding remain. |
| 2. Authentication/secure transport | Partial | `wss`, certificate identity, and plaintext opt-in added; auth semantics and complete identity binding remain. |
| 3. Transfer ranges/coverage | Mostly fixed | Negative ranges, overlap, gaps, length, digest, and concurrency checked; aggregate memory, expiry, malformed base64, and invalid chunk sizes remain. |
| 4. Capability negotiation | Fixed in Python | Separate offers/intersection exist and outbound uses the intersection. |
| 5. Encoding negotiation | Mostly fixed | Empty intersections and invalid ACK selections rejected; negotiated max size is ignored. |
| 6. QoS queues/coalescing | Mostly fixed | Explicit queues/coalescing exist; writer failure reporting and lifecycle remain defective. |
| 7. Sequence-gap recovery | Mostly fixed | Single-gap recovery and larger/second-gap failure added; shutdown edge cases remain. |
| 8. Installed Python data | Fixed | Data packaged and CI includes an outside-tree wheel smoke test. |
| 9. WebSocket hardening | Partial | Limits/upgrade checks improved; HTTP over-read can lose frame bytes. |
| 10. Typed/schema validation | Not fixed | Added code is not a JSON Schema validator. |
| 11. CBOR conformance | Partial | Minimal integers/tags improved; Rust bounds and Swift integer/minimality defects remain. |
| 12. JSON profile | Fixed in Python only | Python finite-number and UTF-8 size checks improved. |
| 13. Waiter lifecycle | Mostly fixed | Cleanup/duplicate IDs added; response fallback and send failure behavior remain. |
| 14. Receive failure | Partial | Permanent errors fail; shutdown can cancel itself. |
| 15. Idempotency | Partial | Bounded TTL cache added; default ownership does not survive reconnect, body conflicts are unchecked, safety state is not persistent. |
| 16. Bridge/config validation | Partial | Atomic apply/blackout types improved; metadata remains hardcoded and persistence absent. |
| 17. Discovery validation | Mostly fixed | Receive bounds and defensive URL/field checks added. |
| 18. Rust/Swift session claims | Resolved by documentation | Correctly described as helpers, though helper state APIs remain unsafe. |
| 19. Registry/schema tooling | Not fixed | Schemas are still not compiled and vectors are not schema-validated. |
| 20. CI depth | Partial | Rust Clippy/wheel smoke added; no schema compiler, Python type/lint, fuzzing, coverage, or real cross-language live interop. |
| 21. Provenance/hygiene | Not fixed | No Git worktree; generated artifacts remain. |
| 22. Public API cleanup | Mostly fixed | `Offer` now has a real return type and dead/test-shaped code was removed. |

## Remaining required fixes

### P0-1. Client sessions reject legitimate role-specific peer messages

Locations: `python/src/acp/session.py:300-338`, `582-618`.

The server learns the client's `NodeIdentity` from HELLO. The client receives no peer identity/role in HELLO_ACK and sets `self.peer = None`; `_admit` substitutes sender role `tool`. Messages whose valid senders exclude `tool` are rejected. A focused Conductor↔Bridge probe produced:

```text
CLIENT_PEER None ADMIT_STATE_DELTA capability_not_permitted
```

Required fix:

- Make authenticated server identity and role available to the client through a protocol-defined ACK field or preconfigured transport/session identity.
- Never use an arbitrary fallback role for authorization.
- Require HELLO envelope source, payload node ID, and authenticated transport identity to match.
- Test every role pairing with role-specific inbound messages.

### P0-2. Runtime “schema validation” does not enforce schemas

Locations: `python/src/acp/validate.py:19-81`, `python/src/acp/codec.py:57-69`.

The code checks only a top-level `required` list and scrapes some property names. It does not implement `$ref`, composition, nested validation, types, enums, patterns/formats, bounds, arrays, or `additionalProperties`. A probe confirmed that `health.heartbeat.payload.uptime_ms = "not-an-integer"` decodes successfully.

Required fix:

- Use a JSON Schema 2020-12 validator with a local reference registry, or generated equivalent typed validators.
- Validate the complete envelope and selected payload before filtering unknown optional fields.
- Apply matching semantics in every SDK claiming typed decode, or label Rust/Swift as untyped wire codecs.
- Add negative fixtures for every constraint category and message family.

### P0-3. Safety/auth state remains memory-only across reconnect/restart

Locations: `python/src/acp/session.py:133-136`, `706-723`; `python/src/acp/idempotency.py`; `python/src/acp/bridge.py`.

Each Session creates its own cache by default. The bridge simulator makes a fresh Session per connection without a shared cache, so 60-second reconnect retention is absent in normal integration. `body_fingerprint` hashes the result, not the request, and lookup never checks conflicting request bodies. Blackout/config/live asset state is process memory, not reboot-persistent state.

Required fix:

- Make idempotency storage node-owned and inject one instance into replacement sessions.
- Fingerprint canonical request semantics and implement same-key/different-body behavior.
- Persist blackout, armed state, live asset metadata, and relevant config atomically; reload before commands.
- Test reconnect, process restart, conflict, TTL, and eviction through public APIs.

### P1-1. Inbound envelope admission remains incomplete

Locations: `python/src/acp/session.py:582-618`, `python/src/acp/registry.py:59-83`.

The gate only checks `env.acp <= session_version`, so an old-labeled envelope can carry a later message because registry gating uses session version rather than envelope schema version. It checks destination node ID but not component or registry `valid_destinations`. Handshake source/payload identity binding is incomplete.

Required fix:

- Require envelope version within the negotiated range and at least the message's `min_protocol`.
- Enforce registry destination kind/role and component targeting.
- Bind handshake source, payload identity, and transport identity.
- Centralize all state/direction/version/role/capability/QoS/destination policy.

### P1-2. Negotiated peer limits are ignored

Locations: `python/src/acp/session.py:313-334`, `523-531`; `python/src/acp/ws.py:104-123`.

HELLO_ACK `max_message_bytes` is parsed into `max_bytes` and discarded. Encoding uses the local limit and WebSocket has a separately initialized limit, so the sender can exceed the peer's advertised maximum.

Required fix: store the negotiated minimum, apply it before queueing/encoding and framing, negotiate other applicable limits, and add asymmetric-limit tests.

### P1-3. WebSocket header parsing can discard the first frame

Location: `python/src/acp/ws.py:30-39`, callers at `209` and `245`.

`_read_headers` reads chunks until finding the terminator and returns the whole chunk. If upgrade headers and the first WebSocket frame arrive in one TCP read, trailing frame bytes are discarded. Fast peers may legally send immediately.

Required fix:

- Use bounded `readuntil(b"\r\n\r\n")` or preserve over-read bytes for frame parsing.
- Close the client writer on every handshake-validation failure.
- Test upgrade plus first frame in a single socket write.

### P1-4. Reliable writer failures can look successful

Locations: `python/src/acp/session.py:477-521`.

On `_transmit` failure, the reliable future is resolved with `None`, then the session fails. A direct `await session.send(reliable)` can return normally although nothing was sent. The dynamic session-global callback is fragile.

Required fix: keep each future with its dequeued envelope, set the actual exception on failure, fail queued items exactly once, and test first/mid-queue failures.

### P1-5. Session shutdown can cancel itself

Locations: `python/src/acp/session.py:451-475`, calls from `546-578` and `682-684`.

When the receive loop calls `_fail` or handles remote goodbye, `_shutdown` cancels `_recv_task` even though it is the current task. Cancellation may fire at `transport.close`, interrupting cleanup. Cancelled tasks are not awaited.

Required fix: never cancel `asyncio.current_task()`, cancel/await other owned tasks, make shutdown idempotent, and test every local/remote/error shutdown path.

### P1-6. Transfer resource limits and malformed handling are incomplete

Locations: `python/src/acp/transfer.py:126-240`.

There is no aggregate byte budget or expiry. Zero/negative `max_chunk_bytes` is accepted. Base64 decoding is outside guarded validation and is permissive. Terminal records are not routinely purged.

Required fix: require positive bounded chunk size, strictly decode base64 inside the guard, track aggregate reserved/received/staged bytes, expire abandoned transfers, and purge terminal records.

### P1-7. Config metadata is hardcoded and incomplete

Locations: `python/src/acp/bridge.py:9-23`, `44-119`.

`SECRET_FIELDS` and `FIELD_TYPES` are small handwritten lists, not schema-derived. Unknown paths are accepted, including secret-like paths that may later be exposed. Because `bool` subclasses `int`, integer fields accept `True`.

Required fix: move secret/type/range/restart/known-path metadata into authoritative schema, generate validation, reject unknown paths unless explicitly extensible, use exact Boolean/integer semantics, and persist transactions.

### P2-1. CBOR cross-language DoS/conformance gaps remain

Locations: `rust/acp-codec/src/cbor.rs:147-245`; `swift/Sources/ACPEncoding/ACPCbor.swift:107-218`.

Rust lacks nesting and allocation/item bounds and needs checked length arithmetic. Swift's `ai == 27` path omits the preferred-encoding check and UInt64-to-Int64 conversions can trap on hostile input. Swift lengths/offset addition also require checked conversion. Rust/Swift erase tag 0 and cannot require it specifically at the timestamp.

Required fix: unify depth/item/byte/integer/minimality/checked-arithmetic rules, preserve/validate timestamp tagging, and run one shared malformed corpus in all SDKs.

### P2-2. Rust/Swift helper APIs permit invalid states

Locations: `rust/acp-session/src/lib.rs:43-74`; `swift/Sources/ACPSession/ACPSession.swift:23-40`.

Both establish without requiring a valid session ID and assign sequences while closed or without a session ID.

Required fix: validate all ACK selections/session ID, make sequence assignment fail unless established, and add negative transition tests.

### P2-3. Registry tooling still does not validate JSON Schemas

Location: `scripts/check_registry.py:36-94`.

New vector type/QoS and packaged-registry comparisons help, but schemas are not metaschema-compiled, `$ref`s are not resolved, registry metadata is not fully cross-checked, and vectors are not validated against schemas.

Required fix: compile all schemas with a local reference registry, schema-validate JSON and decoded CBOR vectors, cross-check duplicated metadata, and test deliberately invalid fixtures.

### P2-4. Tests/CI remain happy-path oriented

Location: `.github/workflows/ci.yml` and test directories.

Rust Clippy and wheel smoke were added, but Python lint/type checks, Rust format, Swift static checks, coverage thresholds, fuzz/property testing, dependency review, and a shared parser corpus are absent. “Interop” remains Python-to-Python. Only 8 of 75 message types have vectors.

Required fix: add these gates, parser/framing fuzzing, real Python↔Rust↔Swift interop, and representative positive/negative vectors for all families and safety messages.

### P2-5. Provenance/artifact hygiene remains unresolved

The directory is still not a Git worktree, preventing attribution and diff review. Generated Rust, Python, and scratch artifacts remain despite ignore rules.

Required fix: restore history or provide a patch against a known revision, remove generated output, and add a CI clean-worktree check.

## Verification performed

- Python: 34 tests passed.
- Registry: 75 messages reported OK.
- Golden vectors: 8 reported OK.
- Rust: 4 tests passed.
- Swift: 2 tests passed.
- Localhost WebSocket HELLO: passed.
- Focused schema probe: invalid string `uptime_ms` was incorrectly accepted.
- Focused role probe: legitimate Bridge `state.delta` was incorrectly rejected because client peer role was missing.

## Recommended order

1. Fix client peer identity/role and replace lightweight validation with real schema validation.
2. Complete session admission, negotiated limits, shutdown, and writer error behavior.
3. Make idempotency and safety state genuinely node-owned and persistent.
4. Fix WebSocket over-read and remaining transfer/config limits.
5. Unify CBOR hardening and helper state transitions across languages.
6. Compile schemas in CI, expand adversarial/cross-language tests, and restore clean Git provenance.

No production source files were modified during this review; only this report was updated.
