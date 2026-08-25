# Aurora Trust M3 Completion Report

Date: 2026-08-25
Starting commit: `ce89b8a` (`Aurora Trust M2 shared security models`)

## Result

M3 host-available software work is complete. Swift, Python, and Rust now provide bounded candidate and commissioner enrollment state machines keyed by `enrollment_id` and `attempt_id`. The ceremony requires a one-shot provider-backed SPAKE2+ peer-share step before bidirectional confirmation can advance, uses frozen approval and installation constructions, and cannot activate a credential before verified durable installation.

## Implemented

- Explicit candidate and commissioner states with internally enforced legal transitions.
- Suite intersection, monotonic enrollment/attempt deadlines, bounded concurrency, retry lockout, cancellation, restart invalidation, replay consumption, and overflow-safe limits.
- Provider-only SPAKE2+ exchange and confirmation verification. Missing, duplicate, empty, invalid, or provider-failed PAKE operations collapse to `security.authentication_failed` and consume the attempt.
- Frozen approval AAD, install-result canonicalization, installation HMAC, and proof-of-possession digest in all SDKs.
- Explicit-key AEAD provider boundary and one-shot approval-key/nonce use.
- Commissioner completion only after both installation confirmation and proof validate.
- Structured transition audit hooks limited to public enrollment IDs, attempt IDs, event names, and states; secret material is not included.
- Live Swift, Python, and Rust enrollment fixture executables exercised by the interoperability gate.

## Review findings fixed

1. Confirmation could initially be reached without a completed peer-share exchange. The exchange is now mandatory, provider-backed, one-shot, and fail-closed.
2. Commissioner callers could initially nominate an arbitrary target state. Every SDK now enforces the legal adjacency table internally.
3. Transition audit emission was absent. Narrow redacted audit hooks are now integrated.
4. Candidate state was initially too global for concurrent attempts. Attempt phase and durable-install evidence are stored per attempt.
5. The AEAD provider boundary initially omitted its key parameter. All SDK interfaces now require an explicit secret key.
6. Swift deadline arithmetic could overflow. Deadline construction is checked and fails closed.
7. Rust state fields could be forged by callers. State is private and exposed read-only.
8. Approval protection could risk reuse after partial failure. Attempt consumption occurs before randomness or AEAD invocation.

## Tests and evidence

The final corrected tree passed two complete gates consecutively:

- Registry: 109 messages.
- Standard vectors: 109 messages.
- Aurora Trust vectors: 17 vector sets / 31 hashed artifacts.
- Ruff: pass.
- Python mypy: 33 source modules, pass.
- Python pytest: 179 passed; coverage 82.53–82.56% (70% required).
- Rust workspace: 41 passed (codec 9, model 2, security 10, session 20); rustfmt and clippy pass.
- Swift: 89 passed.
- WebSocket HELLO and Remote interop: pass twice.
- Rust/Swift framed session JSON and CBOR: pass twice in both directions.
- Python/Rust and Python/Swift framed HELLO, session, Remote, and negative JSON/CBOR suites: pass twice in both directions.
- Live enrollment ceremony fixture: Python, Rust, and Swift all reached candidate `enrolled` and commissioner `complete`, twice.
- `git diff --check`: pass.

The enrollment-specific suites cover legal completion, illegal transitions, suite mismatch, missing and duplicate PAKE shares, invalid confirmation, replay, concurrency exhaustion, retry lockout, expiry, restart invalidation, deadline overflow, one-shot approval encryption, frozen byte parity, durable installation, and redacted audit output. Frozen transcript confirmation makes mutations to node ID, trust domain, role, permission digest, security version, and suite fail the provider confirmation boundary rather than creating SDK-specific validation paths.

## Provider and platform evidence

Production cryptography remains behind the narrow provider interfaces; deterministic providers are test-only. The existing M0 Botan 3.13.0 capability evidence remains the provider qualification source. macOS arm64 is host-qualified. Linux x86_64, Windows x86_64, physical iOS devices, and constrained hardware remain distinct platform/release qualification gates and are not represented as host PASS results here.

The cross-language enrollment fixture proves live state-machine and provider-boundary behavior across all three SDK processes. It does not replace independent provider/platform cryptographic qualification or the required external security review.

## Residual release gates

- Execute the common provider probe suite on unavailable Linux, Windows, physical iOS, and target constrained hardware.
- Retain the independent cryptographic/security review before show-critical release.
- M4 must supply the production credential authority, transactional identity store, issuance, renewal, rotation, and revocation implementations consumed by the M3 handoff boundaries.

No known host-software blocker remains for transition to M4.
