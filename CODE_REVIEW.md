# Aurora Communications Protocol — Remediation Report

Review/remediation date: 2026-08-20

Baseline: ACP 1.2, tagged Swift package `1.0.0` (`426f401`), current `main` (`1.1.0-dev.2`), Remote amendments, and the Prism integration/final implementation directives.

## Outcome

All actionable P0/P1 defects from the design-philosophy review have been fixed. The incomplete Swift Remote component has been deliberately reclassified as an authority **safety core**, not falsely completed as a production host. This preserves the original architecture: Python remains the reference production Remote authority; a future Swift production host must add authenticated session binding, readiness, persistence, publication, command recovery, backpressure, and audit around the core.

No known P0/P1 defect remains in the implemented scope. Aurora Trust remains a proposed design, explicitly marked as unimplemented; plaintext sessions are now denied by default.

## Implemented fixes

### Momentary safety and authority ownership

`Sources/AuroraACP/Profiles/Remote/ACPRemoteProduction.swift`

- Renamed the implementation to `ACPRemoteAuthorityCore`; retained the old production name only as a deprecated type alias with an explicit warning.
- Holds are keyed by authenticated node ID plus invocation ID, preventing cross-principal UUID collisions from overwriting active effects.
- END/CANCEL now requires the exact issued lease and resolves only the initiating principal's hold.
- BEGIN reserves command identity before awaiting the semantic router, preventing actor reentrancy from executing concurrent duplicates twice.
- Added autonomous lease timers; expiry no longer requires inbound traffic or a test clock advance.
- Disconnect, expiry, disarm, shutdown, layout replacement, and policy replacement use the common release path.
- Layout replacement fails closed while any release remains active/pending, so a new layout cannot orphan the old control binding.
- Failed release remains `release_pending` and `physical_active`; it is never reported confirmed inactive.
- The bounded replay table no longer evicts old identities and make them executable again; saturation rejects new work safely.

New tests cover two principals sharing an invocation ID, missing/wrong leases, autonomous expiry, concurrent duplicate execution, replacement-session body conflicts, disconnect, and failed physical release.

### Command ledger once-only semantics

`Sources/AuroraACP/Session/ACPCommandLedger.swift`

- Added an explicit unavailable reservation result for safe backpressure.
- Mutating reservations require a non-empty canonical semantic fingerprint.
- In-flight records are never evicted. If capacity contains only unresolved records, new reservations fail closed.
- Completion permits only defined terminal dispositions and cannot rewrite an already terminal record.
- Idempotency and command-ID conflicts compare operation, authenticated principal, and body fingerprint.

Tests cover capacity pressure, missing fingerprints, invalid transitions, duplicate reservations, and different-body reuse.

### Swift WebSocket lifecycle

`Sources/AuroraACP/Transport/ACPWebSocket.swift`

- Timeout/cancellation now removes and resumes the exact accept waiter instead of leaving an uncancellable checked continuation.
- A timed-out waiter cannot steal the next connection.
- Listener startup and accept validate positive finite deadlines and are bounded.
- Stop resumes all waiters and closes all pending connections.
- Listener instances are explicitly one-shot; restart is rejected deterministically.
- Connections offered after stop are closed.

Real loopback tests cover timeout bounds, post-timeout acceptance, data roundtrip, stop, and restart rejection.

### Trust boundary and authentication status

`Sources/AuroraACP/Session/ACPSession.swift`; `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`

- `ACPSession` now denies plaintext by default. Tests and interop fixtures opt in explicitly because they are development transports.
- The Aurora Trust document now states prominently that it is design-only and that `trusted_lan`/`allow_plaintext` do not authenticate a principal.
- Current Swift Remote code is no longer described as a complete production authority.
- The Phase 5 checkpoint was corrected: it proves selected safety-core behavior and does not authorize production deployment or legacy deletion.

Production Remote control must remain disabled until an authenticated transport principal, server-owned authorization, TLS/WSS or equivalent protected transport, revocation/offline policy, and conformance vectors are implemented.

### Forward-compatible catalogs

`schema/common/defs.schema.json` and packaged schema copies/packs

- Remote permissions and command dispositions are now forward-compatible non-empty strings with `x-known-values` catalogs rather than closed enums silently extended under the same wire version.
- Unknown permissions grant no authority; unknown dispositions are non-success and cannot confirm state.
- Added schema tests for extension permissions and unknown future statuses.
- Regenerated all canonical schema packs and verified packaged-schema parity.

### Workbench security and hygiene

`tools/acp-workbench/src/acp_workbench/transcript.py`; `.gitignore`

- Transcript redaction now covers complete nested `auth` objects and trust-sensitive credential, enrollment, PAKE, proof, private-key, secret, and token names/suffixes.
- Redaction is represented structurally as `{"$redacted": true}`, so it cannot be confused with a transmitted string.
- Added nested trust-material redaction tests.
- Repository hygiene now ignores Workbench live captures, Python caches/bytecode/egg-info, Ruff/pytest caches, and `.DS_Store`; an artifacts `.gitkeep` preserves the intended directory.

### Interop cleanup

`python/src/acp/session.py`

- Shutdown/writer failure explicitly observes exceptions placed on orphanable futures. Negative interop no longer emits “Future exception was never retrieved” warnings while preserving exceptions for active awaiters.

## Design philosophy status

The original non-negotiables remain intact:

- Intent and ACK remain separate from authoritative state.
- All effects route through an injected semantic router; ACP does not drive hardware or become a show engine.
- Client role claims do not grant permissions in the authority core.
- Discovery grants no trust.
- Unknown permissions/statuses fail safe while remaining forward compatible.
- Once-only commands are reserved before execution and cannot become replayable through in-flight eviction.
- Momentary release is authority-owned and independently scheduled.
- Blackout remains explicit, idempotent, state-reflected, and not cleared by reconnect.
- ACP retains no runtime Internet dependency.
- Prism is not made permanent architectural authority; the core is product-neutral.

## Final verification

- Swift: **44 passed**.
- Python: **137 passed**, 81.37% coverage; Ruff passed; mypy passed for 27 source files.
- Rust: **22 passed**; Clippy with `-D warnings` passed; rustfmt passed.
- ACP Workbench: **22 passed plus 3 subtests**; Ruff passed.
- Registry/schema/vector gates: **93 registry messages, 93 vectors**; frozen vectors and schema-pack drift checks passed.
- Python WebSocket HELLO and full Remote scenarios passed.
- Python↔Rust HELLO/session/Remote/negative suites passed in CBOR and JSON.
- Python↔Swift HELLO/session/Remote/negative suites passed in CBOR and JSON.
- Rust↔Swift direct session suite passed in CBOR and JSON.
- Negative interop completed without unhandled-future warnings.
- `git diff --check` passed.

## Release boundary

The codec/session SDKs and Workbench changes are test-clean. `ACPRemoteAuthorityCore` is suitable only as a safety primitive within a future production host. It must not be used by itself to claim production Swift Remote support or to enable live safety-sensitive output.

Implementing the full Aurora Trust protocol and full Swift production Remote host is new feature work, not silently completed by this remediation. Those capabilities require their own staged security, persistence, lifecycle, interoperability, and safety review before deployment.
