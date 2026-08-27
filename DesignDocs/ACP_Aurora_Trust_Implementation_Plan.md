# ACP Aurora Trust Implementation Plan

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Source design:** `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`
**Target:** ACP 1.2 additive security extension
**SDKs:** Swift, Python 3.11+, Rust 1.75+
**Profiles:** Full and Lightweight
**Planning rule:** Production Remote control remains disabled for unauthenticated principals until the enforcement gate in Milestone 7 passes.
**Approval status:** Approved for implementation planning, subject to the Milestone 0 cryptographic-profile freeze and milestone exit gates below.

## 1. Outcome

Deliver an interoperable Aurora Trust implementation that:

- securely enrolls headless or interactive nodes with SPAKE2+;
- issues and atomically stores persistent node credentials;
- authenticates Full-profile ACP sessions with mutual TLS 1.3;
- converts verified transport identity into an immutable principal;
- derives permissions from local policy rather than peer claims;
- supports renewal, rotation, revocation, reset, audit, and offline operation;
- preserves bounded-resource behavior for the Lightweight profile; and
- rejects silent downgrade to `trusted_lan` in hardened deployments.

The implementation is complete only when Swift, Python, and Rust pass identical vectors and live cross-language enrollment/authentication tests, and an independent security review has cleared the frozen cryptographic profile.

## 2. Delivery principles

1. Freeze the wire-level cryptographic contract before production cryptography is written.
2. Make schemas, registry metadata, deterministic vectors, and stable errors the shared source of truth.
3. Keep cryptography behind audited provider interfaces; do not implement curve arithmetic, TLS, or AEAD primitives in ACP.
4. Separate discovery, enrollment, authentication, authorization, and operational safety.
5. Keep private keys behind signing handles and install credentials transactionally.
6. Implement all security state machines with injected clocks, randomness, storage, and policy for deterministic testing.
7. Treat secret redaction, resource limits, crash recovery, and downgrade prevention as release requirements.
8. Keep trusted device identity independent from the current human, operator, or participant assignment.
9. Keep trust lifecycle independent from asset lifecycle; credential revocation must not implicitly delete cached layouts, show assets, or other conformance-managed data.

### 2.1 Identity and lifecycle invariants

- A persistent node keypair identifies an ACP device within a trust domain. Enrollment establishes that device identity; subsequent sessions prove possession of its private key rather than repeating enrollment.
- Operator and participant assignments are application state bound to an authenticated device for a defined scope or period. Reassigning an iPad or other node must not generate a new device identity or silently change its credential.
- Device authentication does not authenticate the current human operator. Where human identity matters, the product must establish it separately and include it as authorization/audit context rather than as a replacement for the device principal.
- Authorization decisions may use both the authenticated device principal and a separately verified operator/participant context, but neither context may be inferred from a peer's self-claim.
- Revoking, expiring, rotating, resetting, or replacing a device credential changes trust state only. Cached Remote layouts, show assets, and other content remain governed by their existing asset lifecycle and conformance rules.
- Asset deletion, cache invalidation, or quarantine after a security event must be an explicit product or incident-response policy action, not an implicit side effect of credential lifecycle code.

## 3. Workstreams and ownership boundaries

| Workstream | Primary repository areas | Deliverable |
|---|---|---|
| Protocol contract | `schema/`, `docs/`, `schema/registry.json`, `schema/constants.json` | Normative security profile, schemas, capabilities, errors, registry metadata |
| Shared fixtures | `vectors/security/`, `scripts/` | Synthetic deterministic vectors and validation/generation tooling |
| Swift SDK | `Sources/AuroraACP/Security/`, `Transport/`, `Session/`, Swift tests | Models, providers, enrollment, storage, mTLS principal integration, authorization |
| Python SDK | `python/src/acp/security/`, CLI, Python tests | Equivalent models and behavior, file storage, TLS adapter, operator CLI |
| Rust SDK | New security crates or existing model/session crates | Full and Lightweight models, typestate enrollment, bounded storage/transport adapters |
| Interoperability | `tests/interop/` | Cross-language enrollment and authenticated-session harnesses |
| Operations | inspector, simulator, Wireshark, docs | Enrollment/rotation/revocation tooling, audit verification, redacted diagnostics |

Assign one protocol/security owner to approve normative changes and one implementation owner per SDK. Security-sensitive pull requests require review from the protocol owner plus an SDK owner other than the author.

## 4. Milestones

### Milestone 0 — Security profile freeze

**Goal:** Remove every ambiguity listed in design section 33 before production cryptographic code is accepted.

Decide and document:

- exact SPAKE2+ parameters and audited provider/library for every supported platform;
- password normalization, registration-record handling, point encoding, transcript framing, and confirmation MAC format;
- protected-approval AEAD algorithm, nonce construction, associated data, and replay rules;
- mandatory identity suite after target validation;
- X.509 SAN, EKU, chain, validity, endpoint identity, and issuance rules;
- Lightweight secure transport and proof-of-possession construction;
- TLS exporter context and per-platform fallback/conformance policy;
- signed revocation snapshot/delta format and offline behavior;
- constrained-device secure-time and rollback policy;
- authority backup/recovery model; and
- SAS assets and mapping if SAS ships in version 1.

Implementation tasks:

- Add a normative `docs/SECURITY.md` linked from `docs/ACP_SPEC.md`.
- Record provider choices, versions, licenses, platform support, and known limitations.
- Build provider capability probes for CI and representative hardware.
- Obtain external review of the frozen profile and resolve blocking findings.

**Exit gate:** Normative byte formats and algorithms are review-approved; no item above remains an SDK-local choice.

### Milestone 1 — Protocol contract, schemas, registry, and vectors

**Goal:** Establish the language-neutral contract before SDK behavior diverges.

Implementation tasks:

- Add common definitions for auth modes, IDs, algorithms, suites, enrollment state/method, credential status/format, storage posture, and security errors.
- Create `schema/security/messages.schema.json` for the enrollment and credential lifecycle families.
- Extend HELLO/HELLO_ACK auth structures and discovery metadata without making discovery authoritative.
- Add all eight security capability identifiers and stable error codes.
- Extend registry rows with legal state, direction, QoS, correlation, capability, authorization permission, rate-limit class, response type, and sensitive-field policy.
- Add `x-acp-sensitive` and log-policy annotations, then make schema packing and registry generation preserve them.
- Define size/count limits for Full and Lightweight profiles.
- Create synthetic golden fixtures for success, wrong secret, expiry, replay, transcript tampering, role downgrade, malformed credentials, wrong node/domain, revocation, and rotation overlap.
- Extend registry/schema/vector check scripts and regenerate checked-in Swift/Python artifacts.

**Exit gate:** Schema validation, registry checks, artifact freshness checks, and vector manifest checks pass; security fixtures contain only clearly marked synthetic secrets.

### Milestone 2 — Shared models and security boundaries

**Goal:** Add compatible typed APIs without enabling production enrollment.

Implementation tasks in all SDKs:

- Implement typed IDs, algorithms, credentials, enrollment messages, security errors, storage posture, and immutable `AuthenticatedPrincipal`.
- Implement deterministic context/transcript serialization, hashes, HKDF labels, key IDs, credential IDs, and base64url/CBOR normalization.
- Define narrow crypto, signing-key, clock, identity-store, enrollment-policy, credential-validator, audit-sink, and authorization-policy interfaces.
- Add in-memory stores and deterministic providers visible only to tests.
- Ensure secret-bearing values cannot be casually serialized, logged, cloned, or debug-printed.
- Extend negotiation with security capabilities and an explicit downgrade policy; `trusted_lan` creates an unauthenticated principal only.

Language placement:

- Swift: add `Sources/AuroraACP/Security/` and `tests/AuroraACPTests/Security/`.
- Python: add `python/src/acp/security/` with frozen/slotted models.
- Rust: prefer separate model, crypto, session, and storage crates; keep networking/TLS out of `acp-model`.

**Exit gate:** All three SDKs produce identical context bytes, transcript hashes, derivation outputs, identifiers, and credential canonical bytes for fixed synthetic inputs.

### Milestone 3 — Enrollment state machines

**Goal:** Implement bounded candidate and commissioner ceremonies through durable installation receipt.

Implementation tasks:

- Implement explicit candidate and commissioner transitions, with state keyed by enrollment/attempt IDs rather than network address.
- Add suite intersection and bind ACP/security versions, identities, instances, domain, role, and permission digest into the transcript.
- Integrate audited SPAKE2+ providers and explicit bidirectional key confirmation.
- Encrypt approval with independently derived AEAD keys and fully specified associated data.
- Enforce monotonic deadlines, attempt limits, lockout, replay tracking, bounded concurrency, restart invalidation, and cancellation cleanup.
- Require operator/policy approval after key confirmation and before credential issuance.
- Authenticate installation result and require proof of possession of the new identity key.
- Emit stable, redacted audit events for every lifecycle transition.

Tests:

- exhaustive legal/illegal transition tests;
- expiry, duplicate, out-of-order, replay, reflection, cancellation, retry, and resource-exhaustion tests;
- wrong secret and every transcript-field mutation;
- logging tests that search captured output for fixtures and derived material; and
- live Swift/Python/Rust enrollment pairs in both supported roles.

**Exit gate:** Three-language vector parity and all mandated live enrollment pairs pass; no credential becomes active before durable verified commit.

### Milestone 4 — Credential authority, storage, and lifecycle

**Goal:** Establish persistent, recoverable identity and offline-valid credential management.

Implementation tasks:

- Implement trust-domain creation/import and authority-key abstraction without distributing the authority private key to nodes.
- Implement the frozen X.509 issuer/validator and deterministic compact credential issuer/validator.
- Validate format, signature/chain, domain, time, revocation, role constraints, proof of possession, HELLO node ID, and local policy in order.
- Implement atomic stage/verify/commit/rollback storage and read-back validation.
- Add Swift Keychain/platform adapter, Python restricted/journaled file store, and Rust two-slot embedded store; keep in-memory storage test-only.
- Implement renewal and two-phase key rotation with safe overlap.
- Implement signed revocation snapshot/delta ingestion, monotonic epochs, active-session policy, reset, and unenrollment.
- Implement clock trust states and rollback detection.

Tests:

- power loss/failure injection at every write boundary;
- malformed, expired, future, revoked, wrong-domain, wrong-node, wrong-key, and critical-extension credentials;
- rotation interruption at every phase; and
- authority restore/recovery without accidental trust-domain replacement.

**Exit gate:** Crash recovery always selects a complete valid generation or retains the previous valid identity; compromised/revoked credentials cannot establish new sessions.

### Milestone 5 — Authenticated transports and ACP session binding

**Goal:** Make a verified principal a prerequisite for authenticated ACP sessions.

Implementation tasks:

- Add TLS 1.3 mutual authentication adapters for Swift, Python, and Rust Full profiles.
- Configure local credential selection, trust-domain validation, SAN identity extraction, proof of possession, and certificate failure behavior.
- Change transport/session interfaces to return `AuthenticatedPrincipal`, not a TLS-success boolean.
- Extend HELLO auth fields and validate trust domain, credential/key IDs, security capabilities, and exact `node_id` equality.
- Implement the frozen TLS exporter/channel-binding construction where required.
- Prevent plaintext fallback after authentication failure.
- Complete and review the Lightweight authenticated transport, including confidentiality, integrity, replay protection, peer authentication, bounded parsing, and transcript binding.
- Update interop servers/clients to run authenticated WebSocket and Lightweight simulator sessions.

**Exit gate:** All Full-profile cross-language mTLS pairs pass; Lightweight-to-Full simulator interop passes; discovery or HELLO claims alone cannot create a principal.

### Milestone 6 — Authorization and profile integration

**Goal:** Enforce permissions derived only from authenticated identity and local policy.

Implementation tasks:

- Implement policy records and the intersection of credential role constraints, local policy, negotiated capabilities, and operational safety policy.
- Model device principal and operator/participant assignment as separate typed inputs. Assignment changes must not mutate the device identity or credential record.
- Define the effective-permission calculation as the intersection of authenticated device identity, credential constraints, local policy, negotiated ACP capabilities, operational safety policy, and—only where required—a separately authenticated operator context.
- Pass immutable principal plus authorization decision to security-sensitive handlers.
- Map every sensitive ACP and Remote operation to an explicit permission.
- Add policy revisioning, auditing, session revalidation behavior, and configured step-up requirements.
- Update Remote production gates so unauthenticated or insufficiently authorized principals cannot perform control operations.
- Keep production Remote sessions view-only during Observe, Enroll, and any mixed-mode deployment unless the control operation has an authenticated, authorized principal. A claimed `node_id` is never sufficient.
- Surface `untrusted`, `known domain`, `authenticated`, `identity conflict`, expiry, and storage posture distinctly in product adapters.
- Surface Conductor security states with stable operator-facing labels including `Authenticated`, `Trusted LAN`, `Revoked`, `Expired`, and `Identity Conflict`.
- Keep credential lifecycle handlers isolated from Remote layout/show-asset cache deletion and other asset lifecycle operations.

**Exit gate:** Role/capability self-claims never grant access; revocation/policy changes remove authorization according to the documented active-session rule; operator reassignment preserves device identity; credential lifecycle operations do not implicitly mutate asset state; all sensitive handlers have explicit permission tests.

### Milestone 7 — Operations, migration, and enforcement

**Goal:** Make security deployable and move production safely off `trusted_lan`.

Implementation tasks:

- Add Python/operator CLI commands for trust-domain creation, enrollment, node listing, rotation, revocation, and audit verification.
- Prefer interactive stdin or protected files for bootstrap secrets; redact normal and JSON output and warn about shell history.
- Add optional QR/text URI, signed enrollment package, and SAS UX.
- Extend inspector, simulator, discovery display, and Wireshark with opaque/redacted security fields.
- Document commissioning, offline operation, authority recovery, clock failure, revocation propagation, reset, and incident response.
- Run migration stages: Observe, Enroll, Prefer Authenticated, Enforce.
- Require an explicit configuration flag for legacy `trusted_lan`; make hardened production reject downgrade.

**Exit gate:** A clean offline deployment can enroll, authenticate, authorize, rotate, revoke, recover, and audit nodes; production Remote control fails closed without an authenticated authorized principal.

### Milestone 8 — Hardening and release

**Goal:** Demonstrate security, robustness, and platform readiness.

Implementation tasks:

- Add property tests and fuzz targets for enrollment, credentials, CBOR, base64url, extensions, and state events.
- Test declared allocation/message/concurrency bounds, especially for Lightweight.
- Run Swift concurrency/deadline tests, Python Hypothesis tests, Rust feature matrices and cross-builds, and embedded power-failure simulation.
- Test macOS/iOS, supported Linux Swift, Python on macOS/Linux/Windows, Rust on macOS/Linux/Windows/Raspberry Pi, and representative Pico-class hardware or HIL.
- Run LAN adversary tests: spoofing, MITM, replay, downgrade, identity collision, rate-limit bypass, and log/PCAP secret scanning.
- Commission an independent implementation and cryptographic review; resolve all critical/high findings and document accepted residual risk.
- Publish a conformance report mapping every design acceptance criterion to automated evidence or reviewed documentation.

**Exit gate:** Every design acceptance criterion is evidenced; CI and hardware matrices pass; independent review approves show-critical deployment.

## 5. Dependency and sequencing map

```text
M0 profile freeze
  -> M1 schema/registry/vectors
      -> M2 shared models/interfaces
          -> M3 enrollment
          -> M4 credentials/storage/lifecycle
              -> M5 authenticated transports
                  -> M6 authorization/product gates
                      -> M7 operations/enforcement
                          -> M8 hardening/release
```

Safe parallelism after M1:

- Swift, Python, and Rust model/provider work can proceed in parallel against the same vectors.
- Full-profile X.509/storage and Lightweight transport research can proceed in parallel, but Lightweight wire behavior cannot freeze independently.
- Operational UX can prototype against fake providers after M2, but cannot become a release dependency until M3–M6 contracts stabilize.

## 6. Pull-request slicing

Keep changes reviewable and reversible. A recommended sequence is:

1. Normative profile and provider decision record.
2. Common definitions, capabilities, and stable errors.
3. Security message schemas and registry metadata.
4. Vector format, synthetic fixtures, and artifact tooling.
5. Principal/models/transcript APIs in each SDK (one PR per SDK).
6. Deterministic provider and storage test doubles.
7. Production crypto-provider adapters (one provider/platform per PR).
8. Candidate and commissioner state machines (one SDK per PR).
9. Credential formats/validation and authority issuance.
10. Production storage adapters and crash recovery.
11. Renewal, rotation, revocation, and clock policy.
12. Full-profile mTLS transport adapters and HELLO binding.
13. Lightweight transport after its dedicated security review.
14. Authorization core and permission catalog.
15. Remote/profile product gates.
16. CLI, inspector, simulator, Wireshark, and migration controls.
17. Cross-language/hardware conformance and external-review remediation.

Each PR must include tests, regenerated artifacts where applicable, negative cases, stable error behavior, and an explicit statement about secret logging and downgrade behavior.

## 7. CI and evidence requirements

Add CI jobs for:

- schema, registry, generated-artifact, vector-manifest, and sensitive-annotation consistency;
- Swift, Python, and Rust security unit/property tests;
- cross-language deterministic vector equality;
- live pairwise enrollment and mTLS sessions;
- Rust feature combinations and representative embedded cross-builds;
- fuzz smoke runs and malformed-corpus regression;
- dependency/license/advisory scanning for selected providers;
- secret scanning of logs, JSON output, fixtures, and sample captures; and
- hardened-mode tests proving `trusted_lan` downgrade fails.

Maintain a machine-readable conformance matrix with rows for every acceptance criterion and links to test names, CI jobs, hardware results, or reviewed operational documents.

## 8. Primary risks and mitigations

| Risk | Mitigation |
|---|---|
| SPAKE2+ providers differ in profile or encoding | Freeze exact suite; require standard plus ACP vectors and pairwise live tests |
| Platform WebSocket APIs hide peer identity/exporters | Qualify APIs in M0; add a transport adapter that exposes required TLS state |
| Lightweight design becomes custom unaudited crypto | Separate profile review and wire freeze; reuse an audited secure transport/provider |
| Partial credential writes brick nodes | Transactional store, read-back validation, old-generation retention, exhaustive power-loss tests |
| Clockless nodes accept stale credentials | Explicit trusted-time state, monotonic checkpoints, bounded authenticated time, fail-closed production policy |
| Capability/role claims leak into authorization | Immutable verified principal and centralized policy intersection with handler-level tests |
| Device identity is conflated with operator assignment | Separate typed device principal and operator context; test reassignment without key/credential changes |
| Credential lifecycle accidentally deletes cached show data | Separate trust and asset services/stores; require explicit incident-response policy for asset invalidation |
| Secrets leak through tooling | Schema-driven redaction plus runtime enforcement and output/PCAP scanning |
| Migration silently preserves insecure access | Explicit legacy flag, visible security state, staged metrics, hardened no-downgrade test |
| SDK behavior drifts | Schema/registry contract, shared vectors, pairwise interop, conformance matrix |
| Authority loss or cloning splits trust | Documented backup/recovery identity checks; never recreate a domain under the same display name silently |

## 9. First executable backlog

Begin with these bounded issues:

1. Create and review the normative security-profile decision record covering the twelve freeze items.
2. Evaluate candidate SPAKE2+, P-256, X.509, AEAD, TLS-exporter, and secure-storage providers on every target.
3. Specify deterministic enrollment context/transcript bytes and publish initial synthetic vectors.
4. Add security common definitions, capability IDs, error constants, and sensitive-field annotations.
5. Add security message schemas and full registry metadata, then regenerate packed artifacts.
6. Add `AuthenticatedPrincipal` and explicit `trusted_lan` unauthenticated representation to each SDK.
7. Add transcript/key-derivation implementations backed only by test providers and prove three-language parity.
8. Establish the CI conformance matrix before production enrollment work begins.

Do not start production enrollment, credential issuance, or Lightweight transport implementation until Issues 1–3 are approved.

## 10. Definition of done

The release is done when the source design's section 32 checklist is fully satisfied, the conformance matrix points to passing evidence for every item, production Remote control requires an authenticated and authorized principal, device identity remains independent from operator/participant assignment, trust lifecycle remains independent from asset lifecycle, hardened deployments cannot downgrade, and an independent security review has approved the implementation for show-critical use.
