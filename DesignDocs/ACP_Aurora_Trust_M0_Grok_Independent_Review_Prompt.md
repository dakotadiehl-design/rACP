# ACP Aurora Trust M0 Independent Security Review Prompt

## Mission

Perform an **independent, adversarial GO / NO-GO security review** of Milestone 0 (Candidate Freeze 1) of the Aurora Communications Protocol (ACP) Aurora Trust security extension.

Codex produced the M0 review package. Do not defer to Codex's conclusions. Re-derive the important security conclusions independently and actively look for reasons Candidate Freeze 1 should **not** be frozen.

This is a **read-only review**. Do not modify ACP or any other Aurora repository during the initial review.

## Primary review material

Deeply inspect at minimum:

- `docs/SECURITY.md`
- `docs/ACP_SPEC.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md`
- `DesignDocs/ACP_Aurora_Trust_Conformance_Matrix.md`
- The approved Aurora Trust implementation plan/design documents
- Security-relevant schema, registry, constants, vectors, tests, transport/session code, discovery/HELLO handling, Remote Profile behavior, resource transfer, and identity handling
- Swift, Python, and Rust implementations wherever current ACP behavior constrains the security extension
- Dependency/build configuration relevant to candidate providers

Locate equivalent files if paths differ.

## Threat model

Assume an attacker can observe and inject LAN traffic, replay captures, spoof discovery, claim arbitrary node IDs/roles/capabilities, race legitimate nodes, reorder messages, reconnect repeatedly, send malformed CBOR/JSON, exhaust enrollment resources, interrupt credential writes, reboot during installation, present stale/revoked credentials, control a legitimate but unauthorized Aurora node, and attempt cross-domain/cross-protocol reuse.

Review the **composition**, not merely the strength of individual primitives.

## Required deep-review areas

### 1. SPAKE2+

Verify Candidate Freeze 1 against RFC 9383 and actual proposed-provider behavior.

Review exact ciphersuite, curve, hash, KDF, secret normalization, registration records, prover/verifier roles, point/scalar encoding, transcript/context construction, identity/domain/role/version binding, confirmation derivation/MACs/order, replay/reflection resistance, wrong-secret behavior, lockout, and side-channel-sensitive API usage.

Both required key confirmations must be successfully validated before enrollment is cryptographically complete.

Identify every ambiguity that could make Swift, Python, and Rust produce different bytes.

### 2. Transcript and context

Attempt substitution of:

- `node_id`
- `instance_id`
- role
- requested permissions
- trust domain
- ACP/security-profile version
- algorithm suite
- credential/key IDs
- enrollment IDs
- candidate/commissioner identity

Check Unicode normalization, canonical CBOR/JSON boundaries, absent vs null, Boolean vs number, endianness, string encoding, concatenation ambiguity, length framing, unknown fields, and optional fields.

The normative transcript must resolve to exact bytes.

### 3. Enrollment state machines

Attack candidate and commissioner flows using replay, reflection, duplicates, reordering, expiration, cancellation races, restart, concurrent attempts, ID substitution, address rebinding, wrong-secret retries, resource exhaustion, approval replay, installation-result replay, and premature credential installation.

Transient state must not be keyed merely by network address. Restart must invalidate transient ceremonies safely.

### 4. Protected approval

Review AEAD algorithm, key separation/derivation, nonce construction, associated data, replay protection, and binding to enrollment attempt, identities, requested authority, and issued credential. Attempt to transplant an approval ciphertext into another enrollment.

### 5. Persistent identity and storage

Review key generation/storage/handles, key IDs, credential IDs, node binding, proof of possession, transactional stage/verify/commit/rollback, read-back validation, and interrupted-write recovery.

No credential may become active without proof of possession of its corresponding private key.

### 6. X.509 Full Profile

Review CA/trust-domain model, SAN identity, EKU, Key Usage, Basic Constraints, critical extensions, validity, serials, issuance, chain validation, endpoint identity, role constraints, HELLO node-ID equality, revocation, and time handling.

Test mentally and against available code/vectors: valid cert/wrong node, wrong domain, wrong role, copied cert/no key, rotation overlap, revoked, future, and expired credentials.

### 7. TLS 1.3 and channel binding

Verify mutual TLS enforcement, peer-certificate evidence, validated identity extraction, TLS exporter/channel-binding labels and context, HELLO/session binding, reconnect/resumption behavior, and failure handling.

A successful TLS handshake alone must never become an authenticated ACP principal without the required validation.

### 8. Authentication vs authorization

Verify strict separation of:

`discovery → identity claim → authentication → capability negotiation → authorization → operational safety`

Try to gain permissions through role claims, capability advertisements, node IDs, participant identity, Remote layout metadata, HELLO fields, discovery TXT, or requested permissions.

Effective permissions should be derived from:

`authenticated identity ∩ credential constraints ∩ local policy ∩ negotiated capabilities ∩ operational safety policy`

Capability support must never grant authorization.

### 9. Device vs operator identity

Verify trusted cryptographic device/node identity is distinct from current participant/operator assignment.

Changing operator assignment should not require cryptographic reenrollment. Revoking device trust must not automatically destroy unrelated cached show assets. Trust lifecycle and asset lifecycle remain separate.

### 10. Downgrade resistance

Attempt downgrade to `trusted_lan` through discovery, HELLO, missing capabilities, unsupported suites, TLS/certificate failure, timeout, reconnect, legacy peers, and migration configuration.

Hardened mode must fail closed. Authentication failure must never silently continue insecurely.

### 11. Revocation

Review signatures, epochs, monotonicity, rollback/replay, missing deltas, offline behavior, active-session policy, propagation, recovery, and clock interaction. Replaying an older valid revocation state must not restore a revoked node.

### 12. Rotation and renewal

Attack every transition: new key generation, issuance, staging, verification, activation, overlap, and old-key retirement. Interrupted rotation must not produce no identity, conflicting identities, compromised rollback, or permanent lockout.

### 13. Authority recovery

Review backup/recovery against replacement CA under the same display name, split domains, cloned authority state, rollback, revocation-epoch loss, and unsafe recreation. Human-readable trust-domain names are not cryptographic identities.

### 14. Clock/time security

Review trusted/untrusted/monotonic time, rollback detection, certificate validity, enrollment deadlines, revocation epochs, offline operation, and constrained devices without reliable RTCs.

### 15. Lightweight Profile

Treat Lightweight as security-critical. Do not approve it merely because a provider advertises TLS 1.3/RPK constants.

Review peer authentication, confidentiality, integrity, replay resistance, RPK identity binding, transcript/enrollment binding, entropy, memory/message/storage bounds, reconnect/failure behavior, and clock assumptions. Flag custom unaudited cryptography.

### 16. Providers

For every proposed provider assess exact version, license, maintenance, build flags, platform support, Swift/Python/Rust integration, macOS/Linux/Windows/Raspberry Pi support as applicable, embedded relevance, SPAKE2+, exporter, X.509, RPK, and secure-storage behavior.

Distinguish **documented support** from **ACP-qualified support**.

### 17. Rust 1.75 MSRV

Audit the actual proposed dependency graph, including transitive dependencies and feature combinations. Report dependencies/features requiring newer Rust, compatible pins, and security/maintenance consequences.

### 18. Secret handling

Search source, tests, fixtures, CLI, logs, errors, debug output, Wireshark, PCAPs, and snapshots for leakage of pairing secrets, SPAKE material, private keys, AEAD/TLS/exporter material, credentials, or fields marked sensitive.

### 19. Resource exhaustion

Review bounds for concurrent enrollment, message/credential/certificate sizes, extensions, replay caches, revocation data, audit events, queues, pending state, and malformed inputs. Network input must not create unbounded allocations, especially on Lightweight.

### 20. Frozen ACP compatibility

Verify the extension remains additive to ACP 1.2 and does not silently change frozen envelope, discovery, HELLO, capability, Remote Profile, state, asset-conformance, resource-transfer, or interoperability semantics. Explicitly flag any security requirement that requires a normative frozen-protocol change.

## Test and evidence review

Do not merely run tests. Determine whether they prove the intended properties rather than self-consistency.

Run all available ACP regression validation without modifying code, including as applicable:

- Swift tests
- Python tests
- Rust tests/doc tests
- schema/registry checks
- generated-artifact freshness
- golden vectors
- JSON/CBOR interoperability
- WebSocket/framed interoperability
- `git diff --check`

Review coverage for wrong secret/node/domain/role, replay, reflection, downgrade, transcript mutation, malformed/expired/revoked/future credentials, interrupted installation/rotation, revocation rollback, authority recovery, resource exhaustion, and secret leakage.

Identify every place Swift, Python, and Rust could make different reasonable choices, including dates, Unicode, optional values, canonical CBOR, integer widths, signedness, base64url padding, map ordering, DER, transcript framing, error precedence, and timeout semantics.

## Findings severity

Use:

- **BLOCKER** — M0 must not freeze.
- **HIGH** — should block M0 until resolved.
- **MEDIUM** — must be addressed, but may not independently block freeze.
- **LOW** — hardening/clarity/diagnostics/maintainability.
- **INFORMATIONAL** — observation/future recommendation.

For every finding provide:

1. ID
2. Severity
3. File/section/line where possible
4. Description
5. Security consequence
6. Concrete attack/failure scenario
7. Recommended remediation
8. Whether remediation changes normative ACP behavior
9. Tests/vectors required

Explain actual failure modes. Do not merely call something "potentially insecure."

## Required final report

Present the complete review in your response first. **Do not modify files during this initial review.**

Structure it as:

1. Executive summary
2. Review scope
3. Material inspected
4. Tests executed/results
5. Provider assessment
6. SPAKE2+ assessment
7. Transcript/context assessment
8. Enrollment-state-machine assessment
9. Persistent identity assessment
10. X.509/mTLS assessment
11. Authentication/authorization assessment
12. Downgrade assessment
13. Revocation/rotation/recovery assessment
14. Lightweight assessment
15. Secret/resource-bound assessment
16. Cross-language assessment
17. Compatibility assessment
18. Findings table
19. Detailed findings
20. Required remediation
21. Remaining external/hardware evidence
22. Final decision

If later authorized, save the reviewed/final report as:

`DesignDocs/ACP_Aurora_Trust_M0_Independent_Review.md`

## Decision standard

Return exactly one of these decisions:

### GO

Only if no BLOCKER/HIGH findings remain, Candidate Freeze 1 is internally coherent, normative cryptographic behavior is precise enough for independent Swift/Python/Rust implementations, available provider evidence supports it, and available tests support the claims.

GO means Candidate Freeze 1 is sufficiently sound to continue Aurora engineering development. It is **not** a claim of formal professional cryptographic certification.

### CONDITIONAL GO

Use if no known architectural cryptographic flaw prevents proceeding but narrowly bounded external/hardware evidence or remediation remains. List every condition explicitly.

### NO-GO

Use if BLOCKER/HIGH findings remain, wire cryptography is ambiguous, provider assumptions materially threaten the design, authentication/authorization composition is unsafe, or downgrade/replay/identity problems remain.

## Pico hardware evidence

Never fabricate Pico qualification. If hardware is unavailable, explicitly preserve the outstanding tests for entropy source/quality, SPAKE2+ execution, RAM high-water mark, flash footprint, RPK transport, transactional credential storage, power-loss recovery, timing/performance, and bounded concurrency.

Desktop simulation does not satisfy these.

## Provider/license approval

You may technically assess and recommend providers and identify licenses. Do not claim project-owner licensing approval. Mark it as pending where applicable.

## Final instruction

Be adversarial. Passing tests and internally consistent documents are not enough. Try to break the design.

If you find a flaw, trace it to a concrete failure mode and remediation.

If you issue GO or CONDITIONAL GO, explain why the remaining uncertainty does not invalidate the cryptographic contract that Swift, Python, and Rust will implement in M1 and later milestones.
