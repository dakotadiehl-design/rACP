# ACP Aurora Trust Final Internal Security Review

Date: 2026-08-26

## Scope and conclusion

This was an internal independent-style source and test review of the complete M0–M8 implementation, including frozen-profile artifacts, cross-language protocol boundaries, enrollment, credential lifecycle, authenticated transport, authorization, migration, operations, and hardening. It is not the independent external cryptographic/security review required for show-critical release.

No known Critical or High source finding remains open on the reviewed host implementation. M8 implementation evidence is suitable for an external review candidate. Production qualification remains deferred where physical hardware, additional operating systems, current online advisory data, or an independent reviewer are required.

## M7 findings resolved

1. **Synthetic security identifiers (High):** domain creation, enrollment completion, renewal, and rotation manufactured random identifiers without provider-backed keys or credentials. The CLI now requires canonical identifiers produced by the provider/issuance layer. Recovery now verifies an actual committed `JournaledIdentityStore` generation.
2. **Operational state not covered by audit integrity (High):** the audit chain covered events but not the resulting state. Every entry now binds the complete public state hash, and all mutations validate the chain and current state first.
3. **Unaudited forged state accepted (High):** a non-empty state with an empty audit was accepted. Only the exact empty version-2 state is now valid without audit entries.
4. **Concurrent lost updates (Medium):** independent CLI processes could overwrite each other. Transactions now use a restricted cross-platform file lock and atomic replacement.
5. **Unbounded audit growth (Medium):** audit storage could grow indefinitely. A declared bound now rejects safely with `security.resource_limit`; it does not evict security history.
6. **Filesystem substitution and permissions (Medium):** state reads and lock creation could follow links or accept overly broad permissions. Reads use no-follow where supported and require a regular owner-only file; roots, locks, temporary files, and final state are restricted.
7. **Revoked identity reactivation (High):** lifecycle paths could recover or modify revoked identity state. Revocation history is append-only, and recovery/renewal/rotation reject revoked identities.
8. **Malformed audit structures (Medium):** malformed entry shapes could escape as runtime exceptions. Schema and entry structure are now validated and fail closed.
9. **Reset without revocation (High):** reset previously marked a node unenrolled while leaving its credential absent from revocation state. Reset now requires an active node, revokes its credential, advances the revocation epoch, and cannot be used as a renewal path.
10. **Cross-node identifier collision (High):** enrollment and rotation could accept a credential or identity-key identifier already assigned elsewhere. Enrollment, renewal, and rotation now reject active or revoked credential reuse and identity-key collisions.
11. **Bootstrap-file substitution/exhaustion (Medium):** protected secret-file input followed filesystem links and had no explicit bound. It now requires an owner-only regular file, uses no-follow where supported, verifies ownership, and enforces a 4096-byte maximum.
12. **Unvalidated enrollment role (Medium):** direct library callers could supply an arbitrary role that followed the commissioner branch. The operational API now accepts only `candidate` and `commissioner`.

Version-1 operational state is deliberately rejected. It lacks full-state binding and cannot be upgraded without trusting unauthenticated content; operators must reconstruct it from provider-backed identity and credential evidence.

## Full M0–M8 findings resolved

1. **Compact credential contract drift (High):** language implementations disagreed on serial, permission-policy, role, and extension constraints, including accepting four times the frozen role/extension count. Swift, Python, and Rust now enforce the same types, byte lengths, ordering, and 16-entry limits.
2. **Incomplete revocation-entry validation (High):** signed revocation documents could exceed the profile message bound and carried unvalidated reasons and replacement credential identifiers. All implementations now enforce profile byte caps, the frozen reason vocabulary, canonical replacement IDs, and non-self replacement.
3. **Python identity-store filesystem substitution (High):** predictable temporary names and unrestricted reads permitted link substitution and unbounded credential/checkpoint reads. The store now uses unique restricted atomic files, no-follow regular-file reads, exact schemas, and frozen byte/generation bounds.
4. **Unvalidated authenticated transport evidence (High):** session binding trusted provider-returned identity strings and accepted non-frozen credential-format names. All SDKs now reconstruct canonical typed identifiers, require profile-specific formats, bound roles, and validate canonical 32-byte channel bindings before creating an authenticated principal.
5. **Security timestamp divergence (Medium):** Python and Rust rejected schema-valid fractional seconds, Rust accepted impossible dates and used lexical comparisons, and Swift accepted a broader ISO-8601 language than the frozen schema. The three implementations now accept only canonical UTC syntax with 1–9 optional fractional digits and validate dates before chronological comparison.
6. **Invalid enrollment runtime limits (Medium):** zero/negative time and count parameters could produce immediate expiry or nonsensical deadlines at direct API boundaries. Swift, Python, and Rust now reject invalid runtime limits fail closed.
7. **Non-canonical installation proof ID (Medium):** Python checked only the digest prefix and length. It now requires the same canonical lowercase SHA-256 identifier as Swift and Rust.

## M8 review and evidence

- Python Hypothesis tests cover canonical CBOR, base64url, extension criticality, revocation monotonicity, identifier parsing, authorization intersection, and Lightweight malformed input.
- Deterministic parser fuzz smoke covers compact CBOR/credentials, enrollment context, HELLO exporter context, base64url, X.509 evidence wrappers, and Lightweight framing.
- Rust exhaustively exercises malformed Lightweight input lengths and authorization combinations without panics.
- Swift exercises authorization combinations and concurrent policy replacement/authorization with a final fail-closed assertion.
- Existing suites cover enrollment replay/concurrency, transactional power-failure recovery, credential/revocation bounds, transport evidence, exporter mismatch, downgrade, malformed framing, session queues, identity mismatch, and redaction.
- CI adds explicit hardening and online dependency-advisory jobs. Frozen versions and license policy also have an offline reproducible check.

## Source-pattern audit

Security-adjacent source was searched for panic/unchecked operations, plaintext and downgrade switches, TODO/stub markers, secret/key logging, authentication and authorization bypasses, and provider substitutions. Reviewed `unwrap`/`expect` uses in Rust are test code or initialization invariants over embedded frozen data. `trusted_lan` remains discovery-compatible but cannot grant sensitive control, and hardened authentication failures do not downgrade. No production private-key debug/log path was found.

## Residual risks and release blockers

- The operational audit is tamper-evident against accidental or partial corruption, not a signed append-only transparency log. An attacker with full write control can rewrite state and its unkeyed hashes. Protect the host/storage and export audit records to an independently protected sink where non-repudiation is required.
- The Python operations CLI orchestrates public provider-produced identifiers; it is not a certificate authority or private-key provider.
- Online Rust/Python advisory results must pass in CI near release.
- Physical iOS/Secure Enclave, Pico-class Lightweight HIL, and every additionally claimed adapter remain separate qualification gates.
- The independent external review remains mandatory. This document must not be represented as that approval.

## Disposition

The corrected final-tree gate passed twice on the available macOS arm64 host: Python 234 tests, Rust 58 tests, Swift 104 tests, all registry/security vectors, deterministic fuzz smoke, dependency/license policy, Ruff, mypy, rustfmt, clippy, WebSocket interoperability, three-language enrollment, and every framed cross-SDK HELLO/session/Remote/negative combination.

Internal review: **PASS for external-review candidacy**. Show-critical production release: **DEFERRED** pending the explicit gates above.
