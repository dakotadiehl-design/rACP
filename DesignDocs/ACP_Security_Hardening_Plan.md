# ACP Security Hardening Plan

Status: approved execution plan  
Scope: Swift production security path, with application-neutral semantics frozen for Rust and Python parity  
Amendments incorporated: `ACP_Security_Hardening_Plan_Recommended_Amendments.md` items 1–21

## 1. Governing rules

Security policy is frozen before the phase that implements it. Persisted metadata is never security evidence: every restart reloads and independently validates live key, credential, policy, and journal state. Commissioner authorization, authority signing, transport authentication, role claims, capabilities, and operation authorization remain separate gates.

All state machines are bounded. An unauthenticated peer cannot cause unbounded memory use, durable writes, retries, handshakes, audit growth, or journal growth. All stable identifiers, wire projections, clock rules, and errors remain portable across Swift, Rust, and Python.

## 2. Decisions frozen before implementation

### 2.1 Identifiers

- `trust_domain_id` is a generated canonical lowercase UUID and is not derived from an application, host, or display name.
- `authority_key_id` and `identity_key_id` are `sha256:` identifiers over canonical DER SPKI, as defined by the frozen ACP identifier functions.
- Trust-domain identity is `(trust_domain_id, authority_key_id)`.
- `credential_id` is the frozen SHA-256 identifier over exact credential bytes: exact DER for Full X.509 and deterministic CDE of the complete signed compact credential for Lightweight.
- `anchor_certificate_id` is a diagnostic SHA-256 identifier over exact anchor DER. It does not replace `authority_key_id` or confer authority.
- Every load recomputes identifiers from canonical artifacts and compares all persisted relationships. Persisted identifiers are correlation data, not proof.

### 2.2 Identifier lifetimes

- Node ID, trust-domain ID, identity-key ID, authority-key ID, and credential ID are durable cryptographic identity inputs.
- Enrollment ID and attempt ID bind one enrollment flow and its replay state; they survive restart only as long as the journaled flow remains live.
- Candidate and commissioner instance IDs bind one ceremony/session and aid correlation and replay resistance. They are not part of the durable credential identity tuple and do not grant permissions.

### 2.3 Revocation

Revoked credentials never establish future sessions. The frozen active-session policy is `hardened_terminate` unless the exact persisted value `explicit_audited_grace` was explicitly configured and audited. Missing, corrupt, or unknown values resolve to `hardened_terminate`. Phase 5 implements this contract; it does not choose it.

Offline state uses signed `issued_at` and required `next_update`. Acceptance ends at the earliest of `next_update` and `issued_at + maximum_snapshot_age`. Full defaults to a locally configured maximum no greater than 48 hours; Lightweight defaults to no greater than 24 hours. The existing two-minute authenticated wall-clock measurement tolerance applies, but never extends `next_update`. A node with the authority key may use only its newest valid durable local snapshot; authority ownership does not excuse malformed or rolled-back state. A disconnected peer whose snapshot ages out denies new production sessions and permits only discovery, locally authorized enrollment, and view-only diagnostics. Internet connectivity is never required.

### 2.4 TLS

ACP Full version 1 disables TLS resumption and 0-RTT. A future resumption mode requires a separately reviewed contract covering peer certificate identity, expiry, revocation, exporter binding, and policy revalidation.

### 2.5 Clocks

- Monotonic time controls in-process enrollment windows, attempt timeouts, retry delays, and authorization-decision consumption deadlines.
- Trusted or authenticated-checkpoint wall time controls certificate validity, durable authorization expiry, revocation timestamps, and snapshot freshness.
- Persisted checkpoints prevent wall-clock rollback beyond the frozen tolerance.
- A wall-clock change cannot resurrect an expired attempt, authorization, replay window, credential, or revocation snapshot.
- Untrusted wall time denies production control when validity cannot be established.

### 2.6 Authorization and audit

An authorization decision binds the authenticated session ID, principal/node, credential ID and generation, local-policy revision, role-assignment revision, negotiated-capability revision, operation type and target/scope, lifecycle/revocation generation, and one-shot creation/consumption state. It cannot move between sessions or operations. Long-running operations revalidate at their explicitly defined safety checkpoints.

Audit failure policy is operation-class-specific:

- security administration and trust/issuance/revocation operations fail closed when required durable audit evidence cannot be recorded;
- ordinary control operations follow explicit local availability policy without gaining authority;
- safety-critical live-show operations use their frozen safety policy and bounded local audit buffer, so audit-sink loss alone does not create a new hazard;
- no audit failure can add permissions, bypass authentication, or suppress a required denial.

### 2.7 Cross-cutting resource bounds

Before each feature is enabled, freeze and test limits for concurrent enrollments, issuance reservations, staged credentials, active credentials, revocation entries and bytes, audit queue, authorization decisions, TLS handshakes, unauthenticated connections, retry rates, per-peer failures, and journal growth. Existing Full/Lightweight protocol limits remain authoritative where already specified.

## 3. Phase 1 — Apple protected-key custody

Implement `ACPAppleAuthorityKeyStore` with this closed provider outcome taxonomy:

```text
Secure Enclave available and qualified       -> use Secure Enclave
unsupported platform                         -> Keychain fallback permitted
unsupported required signing operation       -> Keychain fallback permitted
every other failure                          -> FAIL CLOSED
```

Typed internal outcomes must distinguish unsupported platform/operation from access denial, locked storage, corruption, identity mismatch, duplicate state, entitlement failure, provider-integrity failure, and unexpected OS failure. Only the two unsupported outcomes permit fallback.

The durable custody record contains only key ID, expected custody mechanism, schema/creation version, expected canonical-SPKI ID, and authority/domain correlation data. A stored validation result is informational only and must not be consumed as authority.

Every load independently proves that the key exists, matches canonical SPKI and identifiers, is persistent P-256, supports the required operation, remains non-exportable to the provider's demonstrated extent, satisfies custody policy, and can produce a verified low-S signature. Exportable, ephemeral, file-backed, or unidentified keys are rejected. Diagnostics and qualification record the actual mechanism.

Exit: callers receive a freshly validated non-exportable capability or a stable fail-closed error; no weaker fallback exists.

## 4. Phase 2 — Authority bootstrap and recovery

Implement `ACPTrustDomainAuthorityStore` using:

```text
absent -> key_reserved -> anchor_generated -> metadata_committed -> active
```

Before trust-domain commitment, incomplete state is either automatically recoverable or safely discardable. The commitment point is the atomic durable publication of metadata binding the domain UUID, authority SPKI/key ID, anchor DER/ID, custody locator, and initial journal/revocation generations. Once committed or externally disclosed in protected approval, cleanup cannot replace the domain silently. Recovery must preserve it or require an explicit destructive new-domain operation and re-enrollment.

Every startup follows:

```text
stored metadata -> load protected key -> canonical SPKI -> recompute IDs
-> validate anchor DER/profile/self-signature -> prove possession
-> compare all persisted relationships -> ACTIVE or FAIL CLOSED
```

Classify each intermediate state as recoverable, pre-commit discardable, or operator-reset-required. Concurrent bootstraps cannot create competing committed domains. Missing or mismatched authority state never triggers automatic replacement.

Exit: create/open is idempotent and restart-safe; committed identity is never silently changed.

## 5. Phase 3 — Enrollment-to-issuance sealing

Commissioner authorization is not authority signing capability. Confirmed enrollment produces an opaque, sealed, one-shot `ACPIssuanceAuthorization`; the issuer independently requires it plus authority policy. A commissioner may operate without access to the signing key.

The authorization binds the durable identity inputs and the ceremony-only enrollment, attempt, transcript, commissioner/candidate instance, expiry, cancellation, requested-purpose, and replacement data according to Section 2.2. Production enrollment machinery is the sole producer; test constructors are excluded or gated from production.

The trust commitment sequence is:

```text
confirmed SPAKE2+ -> valid human approval -> sealed authorization
-> credential signed -> delivered -> transactional candidate install
-> durable reload -> certificate/policy validation -> possession proof
-> authenticated install confirmation -> journal commit -> TRUSTED
```

Signed, delivered, installed, possession-proven, and committed are distinct states. Final trusted-peer state cannot exist earlier than journal commit. Crash tests cover every edge. Shared secrets remain provider-owned and unavailable before confirmation.

Exit: only confirmed enrollment can cause issuance, and only exact durable installation plus possession and confirmation creates trust.

## 6. Phase 4 — Durable credential lifecycle

Initial installation, renewal, rotation, replacement, cancellation, recovery, and cleanup use a monotonic generation journal with explicit active slot, transaction/checksum integrity, credential ID, and state-machine phase. Timestamps never select authority, and a staged Keychain item never becomes active merely because it exists.

The previous active credential remains authoritative until the replacement is validated, durably reloaded, possession-proven, confirmed, and atomically promoted. Nonsequential generations, rollback, conflicting slots, stale reservations, and checksum failures fail closed. Cleanup is bounded and idempotent.

Fault injection covers every transition plus authority-key loss during renewal reservation, certificate generation, replacement, and revocation publication. Authority failure preserves the last valid node credential and cannot corrupt staged state.

Exit: restart always yields the explicitly committed credential or a deterministic recoverable pending state, never “newest certificate wins.”

## 7. Phase 5 — Revocation

Connect `ACPRevocationPublisher` to durable authority state with atomic monotonic epochs, canonical entries, previous-snapshot hash, timestamps, and signed snapshot. Validate issuer/domain, canonical form, bounds, time, strict low-S signature, chain, and rollback rules.

Implement the already-frozen active-session and offline-freshness policies from Section 2.3. Replacement metadata is informational: a replacement independently authenticates and receives permissions only through local policy. Revocation never transfers identity, authority, or authorization.

Exit: durable revocation rejects future sessions and applies identical frozen active-session behavior across language implementations.

## 8. Phase 6 — Transport and identity binding

Production connections originate only from authenticated transport providers. The gates are separate and ordered:

```text
TLS 1.3 mTLS validation -> authenticated transport capability
-> HELLO/exporter identity binding -> authenticated ACP peer
-> role/capability negotiation -> local authorization -> operation admission
```

The certificate proves node identity and trust-domain membership. HELLO role is an authenticated claim; local policy decides whether that node may use it. The certificate does not grant the role. Valid mTLS or HELLO never creates application permission.

Use isolated ACP anchors and disable public-Web-PKI, plaintext, CN, AIA/CRLDP/OCSP discovery, TLS resumption, and 0-RTT fallback. Bind exact node/domain/key/credential identity to HELLO and exporter evidence. Recheck lifecycle state at frozen policy points.

Exit: claims and callbacks cannot manufacture an authenticated or authorized session, and prohibited fallback cannot occur.

## 9. Phase 7 — Authorization hardening

Effective permission is the intersection of authenticated credential state, local peer policy, assigned role, negotiated capability, operation permission, safety policy, and current lifecycle state. Capabilities only restrict. Unknown roles, permissions, versions, targets, and critical fields deny.

Each operation consumes one authorization decision with all bindings in Section 2.6. Decisions are non-transferable and non-replayable. Policy, role, capability, revocation, and lifecycle races invalidate decisions according to frozen checkpoints. Audit follows the operation-class policy in Section 2.6 and is bounded and secret-redacted.

Exit: all sensitive operations traverse one fail-closed decision path; identity, claims, capabilities, audit failure, or races cannot independently confer permission.

## 10. Checkpoints

```text
Checkpoint A: Phases 1–2 -> protected custody and durable authority
Checkpoint B: Phases 3–4 -> sealed enrollment and crash-safe credentials
Checkpoint C: Phases 5–6 -> durable revocation and authenticated transport
Checkpoint D: Phase 7     -> centralized authorization and audit
```

Every checkpoint requires full affected-language tests, API-boundary and public-symbol fabrication audits, targeted restart/fault injection, secret/log redaction review, concurrency/race tests, resource-exhaustion and recovery tests, schema/fixture validation, `git diff --check`, focused code review, and updated qualification evidence. Checkpoints C and D also require a real authenticated client/server smoke test.

## 11. Definition of completion

At least one qualification path contains no mock for any security-critical transition and uses real production Apple custody, durable authority state, SPAKE2+, issuance, Keychain installation, full process termination/restart, TLS 1.3 mTLS, HELLO/exporter binding, authorization, and revocation publication/consumption.

The required two-process scenario is:

```text
fresh authority + candidate -> confirmed enrollment
-> issuance + durable installation -> terminate both -> restart
-> mTLS + HELLO + authorized operation
-> credential rotation/replacement -> restart
-> mTLS + authorized operation -> revocation -> reconnect rejected
```

Completion additionally requires frozen-policy active-session behavior, deterministic recovery at every persistent transition, no test-only cryptographic shortcut, no unexplained qualification skip, and recorded custody, policy, resource, clock, and failure evidence.

## 12. Amendment traceability

| Amendment | Incorporated in |
|---|---|
| 1. Persisted validation is non-authoritative | Phase 1 custody record and live-load proof |
| 2. Closed Secure Enclave fallback taxonomy | Phase 1 typed provider outcomes |
| 3. Identifier derivation before bootstrap | Frozen identifiers and Phase 2 load sequence |
| 4. Recovery versus destructive reset | Phase 2 commitment point and state classification |
| 5. Commissioner separate from signer | Phase 3 first invariant |
| 6. Instance-ID lifetime | Frozen identifier lifetimes |
| 7. Exact enrollment trust commitment | Phase 3 transition sequence |
| 8. Authoritative credential selector | Phase 4 generation/journal rule |
| 9. Authority loss during lifecycle | Phase 4 fault matrix |
| 10. Revocation policy frozen earlier | Frozen revocation policy; Phase 5 consumes it |
| 11. Offline freshness | Frozen revocation model |
| 12. Replacement is informational | Phase 5 replacement rule |
| 13. Certificate does not assert role | Phase 6 identity/role separation |
| 14. Explicit TLS resumption policy | Frozen TLS policy |
| 15. Separate transport and authorization gates | Phase 6 ordered gates |
| 16. Authorization-decision binding | Frozen authorization model and Phase 7 |
| 17. Audit policy by operation class | Frozen audit policy |
| 18. Cross-cutting resource limits | Governing rules and resource bounds |
| 19. Monotonic versus wall clock | Frozen clock policy |
| 20. Stronger checkpoint gates | Checkpoints |
| 21. Production-backed completion | Definition of completion |
