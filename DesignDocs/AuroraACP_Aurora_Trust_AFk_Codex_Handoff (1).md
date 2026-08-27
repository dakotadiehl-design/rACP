# AuroraACP Aurora Trust Remaining Security Implementation

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).
## AFK Codex Handoff Directive

**Repository:** `AuroraACP`  
**Target branch:** current working branch based on latest `main`  
**Primary objective:** Complete the remaining **software implementation** of the Aurora Trust security feature set, beginning from the current completed M1 contract and proceeding through M2–M8 as far as can be truthfully completed on the available host.

---

# 1. Mission

You are taking over the AuroraACP repository for an unattended implementation run.

The current Aurora Trust state is:

- M0 security-profile freeze: **conditionally closed**.
- M1 language-neutral protocol contract: **complete**.
- M2 development: **authorized**.
- The normative Aurora Trust 1.0 contract is frozen at the current ACP 1.2 / Candidate Freeze 2.1.1 contract.
- Current M1 evidence includes schema/registry/vectors, security constants, HELLO/HELLO_ACK security fields, principal-admission rules, downgrade protection, security metadata redaction, macOS arm64 provider probes, and iOS Simulator qualification.
- Physical-device and hardware/platform qualification is still a separate release gate.

Your job is to complete the remaining implementation described by:

- `DesignDocs/ACP_Aurora_Trust_Implementation_Plan.md`
- `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`
- `DesignDocs/ACP_Aurora_Trust_M1_Protocol_Contract.md`
- `DesignDocs/ACP_Aurora_Trust_M1_Completion_Report.md`
- `docs/SECURITY.md`
- `schema/common/defs.schema.json`
- `schema/security/messages.schema.json`
- `schema/session/messages.schema.json`
- `schema/constants.json`
- `schema/registry.json`
- `vectors/security/`

The intended work begins at **Milestone 2** and continues through **Milestone 8**.

This is not permission to redesign the frozen cryptographic protocol. Implement the existing contract.

---

# 2. Non-negotiable AFK operating rules

## 2.1 Do not wait for user input

This is an unattended run.

Do not stop merely because:

- a design choice is inconvenient,
- a test exposes missing implementation,
- a language needs additional internal abstractions,
- existing structure is awkward,
- one implementation needs to be brought into parity with another.

Use the frozen protocol documents and machine-readable contract as the source of truth.

If a genuine ambiguity exists, choose the most conservative fail-closed interpretation that:

1. does not change wire compatibility,
2. does not weaken authentication or authorization,
3. preserves cross-language parity,
4. preserves bounded-resource behavior,
5. can be justified from the normative design.

Record the choice in the milestone report.

## 2.2 Do not claim tests that were not run

Never convert unavailable evidence into PASS.

The following remain explicitly separate unless the actual hardware/platform is available during this run:

- iOS physical-device Full-profile qualification,
- Secure Enclave hardware qualification,
- macOS x86_64 qualification,
- Linux x86_64 qualification,
- Linux arm64 qualification,
- Windows x86_64 qualification,
- Raspberry Pi arm64 qualification,
- Pico-class Lightweight hardware-in-loop qualification,
- independent external cryptographic/security review.

Mark these as `NOT RUN`, `NOT AVAILABLE`, or `DEFERRED` as appropriate.

Simulation, cross-compilation, unit testing, or source review must not be described as hardware qualification.

## 2.3 No silent protocol changes

Do not casually edit frozen M0/M1 cryptographic bytes, constants, transcript construction, HKDF labels, X.509 policy, Lightweight binding, registry semantics, capability IDs, security error meanings, or vector contents.

If implementation reveals what appears to be a frozen-contract defect:

1. prove it with a failing test,
2. isolate the incompatibility,
3. determine whether the implementation or contract is wrong,
4. prefer fixing implementation,
5. if a normative change is truly unavoidable, make the smallest possible change,
6. update every language, vector, schema, registry entry, documentation section, and conformance reference affected,
7. document it as a deliberate contract correction.

Never silently regenerate frozen vectors to make tests pass.

## 2.4 Fail closed

Security failure must never become convenience fallback.

In hardened operation:

- authentication failure must not fall back to `trusted_lan`,
- discovery claims must never establish trust,
- HELLO claims must never establish trust,
- role claims must never grant authority,
- capabilities must never grant permissions by themselves,
- unilateral TLS must not become an authenticated principal,
- revoked credentials must not establish new authenticated sessions,
- expired or invalid credentials must not become authorized,
- untrusted clocks must follow frozen policy,
- failed release or persistence operations must not be reported as successful,
- malformed or unknown critical security fields must fail safely.

## 2.5 Preserve ACP architecture

Do not turn ACP into a product engine.

Maintain the existing boundaries:

- ACP carries semantic intent and state.
- Product adapters own product behavior.
- Discovery is not authority.
- Transport authentication creates evidence.
- Verified evidence creates an immutable device principal.
- Local policy grants permissions.
- Operational safety policy remains an additional gate.
- Device identity is separate from operator/participant assignment.
- Trust lifecycle is separate from show/layout/asset lifecycle.

Do not make Prism, Remote, Conductor, Bridge, or Lyric-specific assumptions part of the protocol core.

---

# 3. Mandatory execution pattern for every milestone

For **each milestone M2 through M8**, use the following loop.

## Phase A — Pre-implementation audit

Before coding the milestone:

1. Read the milestone requirements in the implementation plan.
2. Inspect all existing related Swift, Python, Rust, schema, test, tooling, and interop code.
3. Identify:
   - already-complete requirements,
   - partial implementations,
   - missing implementations,
   - inconsistent behavior between languages,
   - dangerous placeholders,
   - test gaps,
   - accidental future work already present.
4. Write a short milestone checklist in a temporary working note or final milestone report.

Do not duplicate functionality already implemented correctly.

## Phase B — Implement the milestone

Implement the complete milestone across every applicable SDK and tool.

Do not finish only Swift while leaving Python/Rust as stubs, or vice versa.

The target is behavioral parity.

## Phase C — Test the milestone

Run all milestone-specific tests plus the complete relevant regression suite.

Add negative tests before declaring success.

## Phase D — Security/code review

Immediately after implementation, perform a fresh review of the code just added and the directly affected existing code.

Review specifically for:

- trust-boundary violations,
- claimed identity being mistaken for authenticated identity,
- authorization from peer claims,
- downgrade paths,
- replay weaknesses,
- actor/concurrency races,
- TOCTOU behavior,
- non-atomic persistence,
- stale credential acceptance,
- revocation bypass,
- rotation mistakes,
- replay-table eviction bugs,
- resource-exhaustion behavior,
- unbounded maps/queues/messages,
- insecure randomness,
- secret logging,
- secret serialization/debug printing,
- private-key extraction,
- inappropriate copies of secret material,
- incorrect constant-time assumptions,
- network-input panics,
- `unwrap`/`expect` on attacker-controlled Rust paths,
- force unwraps or unsafe continuation handling in Swift,
- swallowed verification failures,
- overly broad exception handling in Python,
- confused-deputy authorization,
- operator/device identity conflation,
- credential/asset lifecycle coupling.

## Phase E — Fix every material review finding

Do not merely report findings.

Fix all P0, P1, and P2 findings that are within repository scope.

Add regression tests for each material defect discovered by review.

Then rerun the milestone suite.

## Phase F — Full regression gate

Before advancing:

- schema/registry validation must pass,
- frozen-vector verification must pass,
- Swift tests must pass,
- Python tests must pass,
- Python Ruff must pass,
- Python mypy must pass,
- Rust tests must pass,
- Rust doc tests must pass,
- Rust `cargo fmt --check` must pass,
- Rust Clippy with warnings denied must pass,
- interop suites relevant to the milestone must pass,
- `git diff --check` must pass,
- secret/redaction checks must pass.

If a regression fails, fix it before proceeding.

## Phase G — Milestone report and commit

At each successful milestone:

1. create/update a report under `DesignDocs/`,
2. record:
   - implemented requirements,
   - files/modules added or changed,
   - tests added,
   - review findings,
   - fixes made,
   - exact regression results,
   - deferred platform evidence,
   - known residual risks,
3. commit the milestone as a coherent commit.

Use commit messages similar to:

- `Aurora Trust M2 shared security models`
- `Aurora Trust M3 enrollment state machines`
- `Aurora Trust M4 credential lifecycle`
- `Aurora Trust M5 authenticated transports`
- `Aurora Trust M6 authorization enforcement`
- `Aurora Trust M7 operational security tooling`
- `Aurora Trust M8 hardening and conformance`

Do not squash the entire night into one giant commit.

---

# 4. Milestone 2 — Shared models and security boundaries

## Goal

Build the actual typed security foundation in Swift, Python, and Rust without yet pretending that enrollment is production-complete.

## Required implementation

### 4.1 Typed security identifiers and enums

Implement equivalent strongly typed representations for:

- trust-domain ID,
- node ID references where security-specific wrapping is needed,
- credential ID,
- identity key ID,
- enrollment ID,
- enrollment attempt ID,
- authentication mode,
- security suite,
- credential format,
- credential status,
- enrollment method,
- enrollment state,
- storage posture,
- clock trust state,
- security capability versions,
- stable security error codes.

Do not invent SDK-local spellings when canonical constants exist.

### 4.2 Authenticated principal

Implement an immutable `AuthenticatedPrincipal` concept across all SDKs.

It must contain only verified identity/security information.

It must clearly distinguish:

- unauthenticated trusted-LAN sessions,
- Full-profile authenticated sessions,
- Lightweight authenticated sessions.

It must not accept role/node/capability claims directly from unverified HELLO fields as proof.

### 4.3 Transport evidence

Implement narrow immutable transport-evidence types containing only evidence produced by a verified transport adapter.

Evidence should carry the frozen fields necessary to bind transport authentication to ACP HELLO, including:

- trust domain,
- node identity,
- credential ID,
- identity key ID,
- authentication profile/mode,
- channel binding/exporter evidence where applicable,
- validation result.

The session layer must not manufacture authenticated evidence.

### 4.4 Deterministic cryptographic context helpers

Implement the frozen language-neutral construction for:

- canonical enrollment context bytes,
- transcript framing,
- transcript hashes,
- HKDF labels,
- key IDs,
- credential IDs,
- base64url normalization,
- CBOR normalization,
- permission digest construction where specified,
- channel-binding comparison helpers.

All three SDKs must match the frozen security vectors bit-for-bit.

### 4.5 Provider interfaces

Create narrow interfaces/traits/protocols for:

- cryptographic provider,
- SPAKE2+ operation,
- AEAD operation,
- secure random provider,
- signing key handle,
- identity key generation,
- certificate/credential validation,
- clock,
- secure time checkpoint,
- identity store,
- trust-domain authority,
- enrollment policy,
- authorization policy,
- audit sink,
- revocation store.

Avoid giant “security manager” interfaces.

### 4.6 Test doubles

Add deterministic test-only providers for:

- randomness,
- clocks,
- in-memory identity storage,
- fake audit sink,
- deterministic crypto/vector fixtures.

Production code must not accidentally use deterministic providers.

### 4.7 Secret types and redaction

Secret-bearing values must not casually:

- implement printable/debug representations containing bytes,
- serialize to ordinary diagnostic JSON,
- appear in errors,
- appear in inspector output,
- appear in logs,
- appear in crash reports.

Add tests that actively search captured logs/output for fixture secrets and derived values.

### 4.8 Downgrade policy

Implement explicit downgrade policy objects.

`trusted_lan` must create an unauthenticated principal only.

Hardened mode must reject fallback after attempted stronger authentication fails.

## M2 exit gate

Do not proceed until:

- all three SDKs produce identical frozen bytes/hashes/IDs,
- public API shape is coherent,
- no secret values are casually printable,
- downgrade tests pass,
- M1 regressions remain green.

---

# 5. Milestone 3 — Enrollment state machines

## Goal

Implement the full candidate and commissioner enrollment ceremonies through durable installation receipt.

## 5.1 Explicit state machines

Implement separate candidate and commissioner state machines.

State must be keyed by:

- `enrollment_id`,
- `attempt_id`,

not merely by socket, IP, or connection identity.

Only legal transitions defined by the registry/state model are permitted.

Illegal transitions must return stable safe errors.

### Required behaviors

Implement:

- enrollment opening,
- attempt creation,
- suite negotiation/intersection,
- bootstrap-secret processing,
- SPAKE2+ exchange,
- transcript binding,
- bidirectional key confirmation,
- operator/policy approval,
- encrypted approval payload,
- identity key proof of possession,
- credential issuance handoff,
- installation receipt,
- cancellation,
- expiry,
- restart invalidation,
- lockout,
- retry control,
- bounded concurrency,
- replay detection.

## 5.2 SPAKE2+ provider integration

Use the frozen audited provider/profile.

Do not implement custom curve arithmetic.

Enforce:

- exact suite,
- exact normalization,
- exact point encoding,
- exact transcript construction,
- exact role mapping,
- exact confirmation construction.

### Negative tests

At minimum include:

- wrong bootstrap secret,
- altered node ID,
- altered trust domain,
- altered role,
- altered permission digest,
- altered security version,
- altered suite,
- duplicate PAKE messages,
- missing PAKE message,
- out-of-order PAKE messages,
- role reflection,
- confirmation reflection,
- invalid point/encoding,
- replayed attempt ID,
- replayed enrollment ID,
- randomness failure.

## 5.3 Approval encryption

Use the frozen AEAD construction.

Enforce:

- independent derived approval key,
- frozen nonce construction,
- frozen associated data,
- replay handling,
- decryption failure collapsing to safe external diagnostics.

Do not leak whether failure was transcript, confirmation, tag, or internal credential detail to a remote attacker where the contract requires collapsed diagnostics.

## 5.4 Resource limits

Honor the frozen Full/Lightweight limits in `schema/constants.json`.

Do not substitute old values from pre-freeze design text.

Bound:

- active enrollment windows,
- concurrent attempts,
- attempts per enrollment,
- PAKE state,
- message sizes,
- retained replay state,
- audit retention in constrained implementations.

## 5.5 Audit

Emit structured redacted audit events for every important transition.

Never log bootstrap secrets, PAKE inputs, derived keys, private keys, approval plaintext, or sensitive credential contents.

## M3 interoperability

Create live cross-language enrollment tests for all practical pairs:

- Swift ↔ Python,
- Swift ↔ Rust,
- Python ↔ Rust,

in each supported candidate/commissioner direction where the architecture permits.

At least one side must not merely replay vectors. Exercise live state machines.

## M3 exit gate

Do not proceed until:

- every legal transition is tested,
- illegal transitions are tested,
- replay and resource exhaustion are tested,
- three-language vector parity passes,
- live enrollment pairs pass,
- no credential becomes active before verified durable installation.

---

# 6. Milestone 4 — Credential authority, storage, renewal, rotation, revocation

## Goal

Create persistent, recoverable, offline-valid device identity.

## 6.1 Trust-domain authority

Implement authority abstractions for:

- trust-domain creation,
- trust-domain import,
- trust-domain recovery,
- authority identity validation,
- credential issuance,
- revocation publication.

Authority private keys must not be distributed to ordinary nodes.

Private keys must remain behind signing handles wherever the platform supports it.

## 6.2 Full-profile X.509 issuer and validator

Implement the exact frozen X.509 policy.

Validation must cover, in the correct fail-safe order:

- DER/parsing,
- chain to the isolated ACP trust domain,
- signature,
- SAN structure,
- exact trust-domain binding,
- exact node binding,
- EKU,
- KU,
- CA constraints,
- validity,
- revocation state/epoch,
- credential ID,
- identity key ID,
- proof of possession,
- local policy.

Do not rely on public WebPKI roots.

Do not treat CN as node identity where SAN is required.

Reject unknown critical extensions.

## 6.3 Compact credential implementation

Implement the frozen Lightweight compact credential format.

Requirements include:

- bounded CBOR parsing,
- canonical form,
- signature verification,
- exact trust-domain/node/key binding,
- validity/clock policy,
- revocation,
- unknown critical extension behavior,
- proof-of-possession.

## 6.4 Transactional credential stores

Implement production storage adapters.

### Swift

Implement Apple Keychain-backed storage for applicable Apple platforms.

Requirements:

- transactional staging,
- read-back validation,
- commit,
- rollback,
- old-generation retention until new generation is verified,
- stable handling of duplicate items,
- correct accessibility class,
- no private-key export merely for convenience.

Use Secure Enclave only if the design supports it cleanly. If hardware-backed implementation cannot be qualified on the available machine/device, keep the adapter capability-gated and report qualification as deferred.

### Python

Implement a restricted/journaled file store.

Requirements:

- restrictive file permissions,
- atomic replacement,
- fsync/durability where practical,
- journal or generation marker,
- corruption detection,
- crash recovery,
- rollback to last complete valid generation.

### Rust

Implement production host storage and the bounded/two-slot model required for constrained deployments.

For embedded-style storage:

- explicit generation numbers,
- integrity verification,
- power-failure-safe activation,
- previous-good retention.

## 6.5 Renewal

Implement credential renewal without unnecessary node-identity replacement.

Renewal must preserve the node identity unless rotation policy explicitly replaces the identity key.

## 6.6 Two-phase key rotation

Implement safe overlap:

1. prepare new key,
2. obtain new credential,
3. validate and stage,
4. prove possession,
5. activate,
6. retain old valid generation for recovery window,
7. retire old generation only after success.

Test interruption at every phase.

A failed rotation must never brick a node if a previous valid credential exists.

## 6.7 Revocation

Implement signed snapshot/delta ingestion.

Enforce:

- signature verification,
- trust-domain binding,
- monotonic epoch,
- rollback rejection,
- bounded storage,
- offline policy,
- reconnect behavior,
- active-session behavior exactly as documented.

A revoked credential must not establish a new authenticated session.

## 6.8 Clock trust and rollback

Implement explicit clock states and frozen policy for:

- trusted wall clock,
- authenticated secure-time checkpoint,
- commissioner-provided authenticated bounded time,
- no trusted time.

Unauthenticated discovery/HELLO time must never set trusted time.

Persist rollback-detection checkpoints where storage permits.

## 6.9 Reset and unenrollment

Implement credential reset/unenrollment as trust lifecycle operations only.

Do not delete show assets, layouts, cached Remote surfaces, or other product content as an implicit side effect.

## M4 failure-injection tests

Add failure injection at every persistence boundary:

- before write,
- partial write,
- after stage,
- before validation,
- after validation,
- before commit marker,
- after commit marker,
- during cleanup,
- during rotation activation.

## M4 exit gate

Crash recovery must always select:

- the previous complete valid identity, or
- the new complete valid identity,

never a partial identity.

---

# 7. Milestone 5 — Authenticated transports and session binding

## Goal

Make verified transport identity a prerequisite for authenticated ACP sessions.

## 7.1 Full-profile TLS 1.3 mutual authentication

Implement/complete production adapters for:

- Swift,
- Python,
- Rust.

The adapter must expose verified peer evidence to ACP rather than merely “TLS succeeded.”

Require:

- TLS 1.3,
- mutual authentication,
- ACP-isolated trust store/domain,
- exact peer certificate validation,
- local credential selection,
- peer SAN extraction,
- trust-domain/node/key/credential extraction,
- revocation handling,
- resumption policy,
- 0-RTT policy,
- channel/exporter binding.

## 7.2 Session API

Refactor transport/session integration so authenticated transports produce verified evidence / `AuthenticatedPrincipal`.

Do not pass booleans such as `isTLS = true` as proof of identity.

The session must compare frozen HELLO `aurora_trust` fields with verified transport evidence.

Mismatch must fail.

## 7.3 HELLO binding

Validate exact agreement for all frozen fields, including:

- node ID,
- trust domain,
- credential ID,
- identity key ID,
- security mode/profile,
- channel binding/exporter where required,
- negotiated security capability version.

A valid TLS connection with mismatched HELLO identity must not establish an authenticated session.

## 7.4 TLS exporter/channel binding

Implement the frozen exporter construction on every supported platform where required.

Add pairwise equality tests.

If a platform API cannot expose required exporter material, do not fake it.

Either:

- use the already-approved provider/adapter path, or
- mark the platform adapter unqualified.

## 7.5 No fallback

After authentication failure:

- do not retry plaintext automatically,
- do not convert the connection to `trusted_lan`,
- do not accept discovery identity as replacement evidence.

## 7.6 Lightweight authenticated transport

Complete the frozen Lightweight transport implementation.

It must provide:

- peer authentication,
- confidentiality,
- integrity,
- replay protection,
- transcript/session binding,
- bounded parsing,
- bounded state,
- deterministic failure behavior.

Do not invent new custom cryptography beyond the frozen reviewed profile.

## 7.7 Interop

Add live authenticated tests for:

- Swift Full ↔ Python Full,
- Swift Full ↔ Rust Full,
- Python Full ↔ Rust Full,
- Lightweight simulator ↔ Full-profile counterpart where defined,
- reconnect,
- resumption,
- revocation after prior success,
- identity mismatch,
- exporter mismatch,
- stripped security fields,
- downgrade attempt.

Run both JSON and CBOR framing paths where ACP supports both.

## M5 exit gate

All available Full-profile cross-language pairs must authenticate correctly.

No discovery or HELLO claim may create an authenticated principal without verified transport evidence.

---

# 8. Milestone 6 — Authorization and profile integration

## Goal

Ensure permissions come only from authenticated identity plus local authority policy and safety state.

## 8.1 Central permission calculation

Implement one clear effective-permission calculation.

Effective permission must be the intersection of:

- authenticated device identity,
- credential role/permission constraints,
- local authorization policy,
- negotiated ACP capabilities,
- operational safety policy,
- separately authenticated operator context only where explicitly required.

Peer role/capability claims never independently grant authority.

## 8.2 Device identity versus operator identity

Use separate types.

Changing the operator/participant assigned to a device:

- must not rotate the device key,
- must not replace the credential,
- must not change the node identity,
- must not rewrite trust-domain membership.

## 8.3 Sensitive operation catalog

Map every security-sensitive and Remote-sensitive operation to an explicit permission.

No “default allow because authenticated.”

Unknown permissions grant no authority.

## 8.4 Handler integration

Security-sensitive handlers must receive:

- immutable authenticated principal,
- authorization decision/context,
- policy revision,
- relevant safety context.

Do not let handlers reconstruct authority from message-body claims.

## 8.5 Policy revisioning and revalidation

Implement:

- policy revisions,
- audit correlation,
- active-session revalidation behavior,
- permission removal behavior,
- documented step-up requirements if present.

A policy change that removes permission must take effect according to the frozen active-session rule.

## 8.6 Remote production gate

Integrate Aurora Trust with the Remote production authority boundary.

The existing `ACPRemoteAuthorityCore` remains the safety primitive.

Build the production hosting/security layer around it so that safety-sensitive Remote control requires a properly authenticated and authorized principal.

During Observe/Enroll/mixed migration stages:

- unauthenticated sessions may be view-only only where policy explicitly permits,
- control operations must not become authorized from a claimed node ID,
- production control must fail closed without authenticated authorization.

Do not break:

- once-only command semantics,
- command ledger behavior,
- momentary lease ownership,
- autonomous release,
- blackout semantics,
- authoritative state rules.

## 8.7 Trust lifecycle isolation

Credential revoke/reset/expire/rotate must not implicitly delete or alter:

- Remote layouts,
- show assets,
- cached content,
- other product data.

Add explicit tests proving this isolation.

## M6 exit gate

Every sensitive handler must have tests proving:

- valid authenticated authorized principal succeeds,
- authenticated but unauthorized principal fails,
- unauthenticated claimed identity fails,
- revoked/expired principal fails as required,
- role/capability self-claims do not grant access,
- operator reassignment does not mutate device identity.

---

# 9. Milestone 7 — Operations, migration, and enforcement

## Goal

Make Aurora Trust practical to deploy and operate offline.

## 9.1 CLI

Extend the Python/operator CLI with commands for:

- trust-domain creation,
- trust-domain import,
- enrollment opening,
- candidate enrollment,
- commissioner enrollment,
- trusted-node listing,
- credential inspection,
- renewal,
- rotation,
- revocation,
- revocation-state inspection,
- reset/unenrollment,
- audit verification,
- security diagnostics.

Bootstrap secrets must be accepted via:

- interactive stdin, or
- protected file/input mechanisms.

Do not encourage passing secrets in command-line arguments.

Warn about shell history where relevant.

## 9.2 Output safety

Normal output and JSON output must redact secret-bearing data.

Add automated tests that scan CLI output for:

- bootstrap secrets,
- PAKE inputs,
- derived keys,
- private keys,
- approval plaintext,
- forbidden credential material.

## 9.3 Enrollment packaging

Implement the approved optional provisioning mechanisms where completely specified, such as:

- QR/text enrollment URI,
- signed enrollment package,
- SAS display/verification support.

Do not improvise visual/security semantics that are not frozen.

If a mechanism remains explicitly optional or underspecified, implement only the parts supported by the contract and document the residual.

## 9.4 Inspector / simulator / Workbench

Extend operational tooling to surface:

- security mode,
- enrollment state,
- trust-domain ID,
- credential ID,
- identity key ID,
- authentication state,
- revocation state,
- policy revision,
- public diagnostics.

Sensitive bytes must remain opaque/redacted.

## 9.5 Wireshark

Extend the dissector using schema-driven redaction policy.

Display only safe metadata.

PAKE bytes, ciphertext, confirmation material, and other secret-bearing fields should be represented only by safe opaque summaries such as length/hash where appropriate.

## 9.6 Migration controls

Implement explicit stages:

1. Observe
2. Enroll
3. Prefer Authenticated
4. Enforce

Requirements:

- `trusted_lan` must require explicit configuration,
- hardened production mode rejects downgrade,
- security state must be visible to adapters,
- authenticated endpoints are preferred when configured,
- sensitive capabilities require authentication,
- Enforce mode disables insecure production control.

## 9.7 Operational documentation

Document:

- commissioning,
- headless enrollment,
- offline operation,
- trust-domain backup,
- authority recovery,
- credential renewal,
- rotation,
- revocation propagation,
- clock failure,
- reset/unenrollment,
- device reassignment,
- incident response,
- lost/stolen node response,
- compromise response,
- migration from `trusted_lan`,
- how to verify audit history,
- which evidence is required before production qualification.

## M7 exit gate

A clean offline deployment using available host/simulator environments must be able to:

- create/import a trust domain,
- enroll a node,
- persist credentials,
- authenticate,
- authorize,
- renew,
- rotate,
- revoke,
- recover,
- audit.

Production Remote control must fail closed when the principal is not authenticated and authorized.

---

# 10. Milestone 8 — Hardening and release evidence

## Goal

Turn the implementation into a defensible security release candidate.

## 10.1 Property tests

Add property-based tests for:

- enrollment state transitions,
- credential encoding/decoding,
- CBOR canonicalization,
- base64url,
- extension handling,
- revocation epoch monotonicity,
- state-event parsing,
- identity/credential IDs,
- authorization intersection.

Use suitable ecosystems:

- Python Hypothesis,
- Rust proptest/quickcheck-equivalent if consistent with project policy,
- Swift property-style randomized tests where practical.

## 10.2 Fuzzing

Add fuzz targets or reproducible fuzz harnesses for attacker-controlled parsing:

- enrollment messages,
- credential parsing,
- compact CBOR,
- X.509 extension extraction wrapper boundaries,
- base64url,
- security HELLO fields,
- revocation snapshots/deltas,
- Lightweight frames.

No network-derived input should cause a process panic/crash.

## 10.3 Bounds tests

Prove declared limits:

- message size,
- credential size,
- concurrent attempts,
- replay state,
- pending handshakes,
- revocation entries,
- Lightweight parser state,
- session queues,
- audit queues where bounded.

When full, fail predictably and safely.

Do not evict unresolved security state in a way that makes previously rejected/replayed work executable.

## 10.4 Concurrency tests

Especially in Swift:

- actor reentrancy,
- cancellation,
- simultaneous enrollment attempts,
- simultaneous duplicate requests,
- rotation versus reconnect,
- revocation versus session establishment,
- policy update versus command execution,
- shutdown during pending security work.

In Rust:

- concurrent session/admission behavior,
- no deadlocks,
- no lock poisoning/panic from malformed input.

In Python:

- cancellation,
- future/task cleanup,
- no orphaned task warnings,
- no race-induced duplicate issuance.

## 10.5 Adversarial LAN tests

Add reproducible host-based adversary tests for:

- spoofed discovery,
- spoofed node ID,
- MITM attempt,
- replay,
- downgrade,
- identity collision,
- stripped Trust metadata,
- exporter mismatch,
- credential substitution,
- revocation rollback,
- rate-limit bypass attempts,
- malformed framing,
- log/PCAP secret scanning.

## 10.6 Dependency and license checks

Verify and document:

- exact provider versions,
- licenses,
- known advisory status available locally/through CI,
- feature flags,
- unsupported platform behavior.

Do not silently upgrade the frozen crypto provider/profile unless required and fully requalified.

## 10.7 CI

Add or complete CI jobs for:

- schema/registry drift,
- generated artifacts,
- frozen vectors,
- security vectors,
- Swift security tests,
- Python security tests,
- Rust security tests,
- interop enrollment,
- authenticated mTLS interop,
- Lightweight simulator interop,
- property tests,
- fuzz smoke runs,
- malformed corpus,
- feature matrices,
- dependency/license checks,
- secret scans,
- hardened downgrade tests.

Jobs requiring unavailable hardware should be clearly separate manual/release gates.

## 10.8 Machine-readable conformance matrix

Update/create the conformance matrix so every acceptance criterion points to evidence:

- unit test,
- property test,
- interop test,
- CI job,
- platform probe,
- hardware result,
- reviewed operational document.

Use explicit states:

- PASS
- FAIL
- NOT RUN
- DEFERRED
- NOT APPLICABLE

Never use ambiguous “mostly complete.”

## 10.9 Independent review preparation

Perform an internal independent-style review pass, but do not label it as the external review required by the design.

Create an external-review package containing:

- frozen contract references,
- architecture summary,
- threat model,
- provider versions,
- vector references,
- conformance matrix,
- known residual risks,
- platform qualification status,
- commands to reproduce tests.

The actual independent external cryptographic/security review remains a release gate.

---

# 11. Cross-language parity requirements

Swift, Python, and Rust are equal protocol citizens for the shared security contract.

Do not accept this state:

> Swift production-ready, Python partial, Rust TODO.

For shared features, require parity in:

- types,
- error semantics,
- transcript bytes,
- derivations,
- credential parsing,
- enrollment state behavior,
- revocation behavior,
- principal semantics,
- authorization semantics,
- downgrade policy,
- test vectors.

Platform-specific storage/transport adapters may differ internally but must expose equivalent semantic behavior.

---

# 12. Expected repository structure

Use the existing architecture where possible, but the implementation will likely require expansion similar to the following.

## Swift

Prefer under:

`Sources/AuroraACP/Security/`

Likely components:

- `ACPAuthenticatedPrincipal.swift`
- `ACPTransportEvidence.swift`
- `ACPSecurityModels.swift`
- `ACPSecurityProviders.swift`
- `ACPEnrollmentCandidate.swift`
- `ACPEnrollmentCommissioner.swift`
- `ACPEnrollmentTranscript.swift`
- `ACPCredential.swift`
- `ACPX509Credential.swift`
- `ACPCompactCredential.swift`
- `ACPIdentityStore.swift`
- `ACPKeychainIdentityStore.swift`
- `ACPRevocationStore.swift`
- `ACPSecureClock.swift`
- `ACPAuthorization.swift`
- `ACPAudit.swift`

Names may differ if existing conventions dictate better placement.

## Python

Prefer under:

`python/src/acp/security/`

Separate:

- models,
- providers,
- transcript,
- enrollment,
- credentials,
- storage,
- revocation,
- authorization,
- audit,
- TLS adapter.

## Rust

Keep model-only code free of networking.

Prefer clear crate/module separation for:

- model,
- crypto/provider adapter,
- enrollment,
- credential,
- storage,
- revocation,
- authorization,
- transport/session glue.

Do not pull Tokio/networking into a pure model crate merely for convenience.

---

# 13. Mandatory security review checklist after every milestone

Search manually and with tooling for the following classes of defects.

## Identity and authentication

- peer-supplied node ID used before verification,
- peer role used as authority,
- capability claim used as permission,
- unauthenticated session represented as authenticated,
- TLS success represented as identity success,
- missing HELLO/evidence equality check,
- wrong trust-domain comparison,
- ambiguous certificate identity extraction,
- resumption bypass,
- 0-RTT mutation path,
- downgrade/fallback.

## Enrollment

- unbound transcript field,
- role reflection,
- reuse of enrollment/attempt IDs,
- replay-state eviction,
- approval before key confirmation,
- credential issuance before approval,
- credential activation before proof of possession,
- restart preserving ephemeral PAKE state,
- unbounded attempts,
- timing based solely on wall-clock when monotonic timing is required.

## Credentials

- accepting wrong node/domain,
- accepting unknown critical extension,
- skipping proof of possession,
- accepting stale revocation epoch,
- rotation deleting last-good credential too early,
- partial writes,
- non-atomic activation,
- private-key export.

## Authorization

- default allow,
- wildcard permission expansion from unknown string,
- role-based implicit authority,
- operator identity replacing device identity,
- capability negotiation expanding authority,
- missing policy revision on long-lived sessions,
- handler reconstructing permissions.

## Logging

Search source and captured output for:

- `secret`,
- `password`,
- `bootstrap`,
- `pake`,
- `shared`,
- `private`,
- `token`,
- `approval`,
- raw credential bodies,
- key material.

Verify redaction structurally, not by hopeful string replacement.

## Resource exhaustion

- unbounded dictionaries/maps,
- unbounded queues,
- unbounded credential chains,
- unbounded CBOR collections,
- unbounded audit retention,
- in-flight entry eviction that re-enables replay,
- no deadline on handshake/enrollment,
- unchecked allocations from network length fields.

## Language-specific

### Swift

Review:

- force unwraps,
- unchecked continuations,
- actor reentrancy,
- cancellation leaks,
- non-Sendable shared mutable state,
- Keychain error handling,
- Data copies of secrets,
- accidental `CustomStringConvertible` leaks.

### Python

Review:

- broad `except Exception` around verification,
- ignored async task exceptions,
- mutable shared state,
- insecure tempfile usage,
- permissive file modes,
- logging of dataclasses containing secrets,
- timing/replay state based on non-monotonic clocks.

### Rust

Review:

- `unwrap()` / `expect()` reachable from network input,
- panic-prone indexing,
- integer overflow/length conversion,
- unbounded `Vec` allocation from untrusted length,
- secret types deriving `Debug`,
- unsafe code,
- lock/async misuse,
- verification results discarded with `let _ =`.

---

# 14. Full regression commands

Use repository-supported commands as the source of truth. At minimum preserve and run the existing gates:

```bash
python3 scripts/check_registry.py
python3 scripts/freeze_vectors.py

python3 -m ruff check --config python/pyproject.toml python scripts
(cd python && python3 -m mypy src/acp)
(cd python && python3 -m pytest tests --cov=acp --cov-fail-under=70)

cargo test --manifest-path rust/Cargo.toml
(cd rust && cargo fmt -- --check)
(cd rust && cargo clippy -- -D warnings)

swift test

python3 tests/interop/test_ws_hello.py
python3 tests/interop/test_ws_remote.py
```

Also run all current cross-language framed/session/negative suites and all new Trust/enrollment/mTLS/Lightweight suites added during this work.

Preserve exact Rust 1.75 compatibility where required by the project contract.

At each milestone, record the actual test counts observed.

---

# 15. Baseline evidence to preserve

Do not regress the current M1 accomplishments.

The current checked-in baseline reports that M1 passed:

- registry/schema for 109 messages,
- standard vectors for all 109 message types,
- 17 Aurora Trust security vector sets / 31 hashed artifacts,
- Python security regression,
- Swift security regression,
- Rust 1.75 security regression,
- JSON/CBOR WebSocket and framed interop,
- macOS arm64 Botan mandatory probes,
- iOS Simulator Full-profile qualification,
- X.509 negative policy matrix,
- authenticated-network negative suite,
- Keychain hosted tests,
- TLS 1.3 mutual authentication,
- peer evidence,
- TLS exporter equality,
- P-256 qualification,
- downgrade rejection,
- inspector/Wireshark redaction.

Treat those as regression requirements.

Do not rewrite the completion report to conceal a regression.

---

# 16. Important frozen security invariants

These are release-blocking invariants.

1. Discovery never grants trust.
2. HELLO never grants trust by itself.
3. Authentication and authorization are separate.
4. Authenticated device identity is immutable for the session.
5. Operator identity is separate from device identity.
6. Capabilities describe protocol ability, not authority.
7. Local policy owns permissions.
8. Safety policy can further reduce permissions.
9. `trusted_lan` is unauthenticated.
10. Hardened mode cannot silently downgrade.
11. Failed stronger authentication cannot fall back.
12. Private keys remain behind handles where practical.
13. Credential installation is transactional.
14. Rotation retains a recoverable previous generation until success.
15. Revocation epochs cannot move backward.
16. Clock rollback is detected where durable storage permits.
17. Secret-bearing values are never normal diagnostic data.
18. Lightweight parsing/state is bounded.
19. Security failure diagnostics do not become useful remote oracles.
20. Trust lifecycle never silently mutates show/layout/asset lifecycle.
21. Production Remote control requires authenticated authorization.
22. ACP still does not drive hardware directly.
23. No Internet dependency is introduced into protocol runtime.

---

# 17. Final whole-repository review

After M2–M8 implementation is complete, perform a clean review from the top, not merely a diff review.

Review:

- `Sources/AuroraACP/`
- `python/src/acp/`
- `rust/`
- `schema/`
- `vectors/security/`
- `tests/interop/`
- `tools/`
- `.github/workflows/`
- all Aurora Trust DesignDocs.

Search for:

```text
TODO
FIXME
HACK
XXX
stub
placeholder
not implemented
temporary
trusted_lan
allow_plaintext
insecure
skip
xfail
ignored
unwrap(
expect(
try!
fatalError(
preconditionFailure(
```

Interpret findings intelligently. Do not blindly delete legitimate comments.

For every security-relevant TODO/stub/skipped test:

- implement it, or
- prove it belongs only to an unavailable hardware/external-review gate and document that clearly.

Perform a second complete code review after fixes.

Then rerun the entire regression suite once more.

---

# 18. Final artifacts Codex must leave behind

Create the following documents under `DesignDocs/`:

1. `ACP_Aurora_Trust_M2_Completion_Report.md`
2. `ACP_Aurora_Trust_M3_Completion_Report.md`
3. `ACP_Aurora_Trust_M4_Completion_Report.md`
4. `ACP_Aurora_Trust_M5_Completion_Report.md`
5. `ACP_Aurora_Trust_M6_Completion_Report.md`
6. `ACP_Aurora_Trust_M7_Completion_Report.md`
7. `ACP_Aurora_Trust_M8_Completion_Report.md`
8. `ACP_Aurora_Trust_Final_Internal_Security_Review.md`
9. `ACP_Aurora_Trust_Final_Conformance_Report.md`
10. `ACP_Aurora_Trust_External_Review_Package.md`

Also update the machine-readable conformance matrix.

The final conformance report must separate:

### Software implementation status

What is implemented and passing on available environments.

### Platform qualification status

What platforms actually ran qualification.

### Hardware qualification status

What actual hardware ran.

### External review status

Whether an independent external reviewer has actually reviewed the final implementation.

---

# 19. Final completion states

At the end of the unattended run, choose exactly one honest overall state.

## `SOFTWARE IMPLEMENTATION COMPLETE`

Use only if M2–M8 software work is implemented and all host-available automated gates pass, while only genuine hardware/platform/external-review gates remain.

## `PARTIAL — BLOCKED BY SPECIFIC TECHNICAL ISSUE`

Use if a real implementation problem remains.

List exact failing test, subsystem, and likely cause.

Do not use vague wording.

## `QUALIFIED FOR AVAILABLE HOSTS ONLY`

May be used alongside software-complete status to describe actual tested platforms.

## Never say

- “production qualified everywhere” when hardware was not tested,
- “Secure Enclave passed” without a physical qualification,
- “Pi passed” from cross-compilation,
- “Pico passed” from simulation,
- “independent review passed” from your own review.

---

# 20. Git discipline

Before starting:

```bash
git status
git rev-parse HEAD
git log -10 --oneline
```

Record the starting commit in the M2 report.

Do not rewrite published history.

Prefer one coherent commit per milestone plus a final review/remediation commit if necessary.

At the end:

```bash
git status
git log --oneline --decorate -15
git diff HEAD^ --check
```

Leave the working tree clean unless a documented tool-generated artifact must remain uncommitted for a good reason.

Do not push unless repository/user policy already authorizes pushing from the current Codex environment.

---

# 21. Priority order if time or environment becomes constrained

Do not sacrifice security-critical core work for cosmetic tooling.

Priority:

1. M2 shared security model and evidence boundaries
2. M3 enrollment
3. M4 credentials/storage/revocation/rotation
4. M5 authenticated transport and session binding
5. M6 authorization and Remote production gate
6. M7 essential operational CLI/migration/documentation
7. M8 hardening/property/fuzz/CI
8. optional UX conveniences

If an unavailable platform blocks only a platform adapter, continue implementing and testing everything else.

---

# 22. Definition of done for this AFK run

The overnight implementation is successful when all of the following that can be executed without unavailable hardware/external reviewers are true:

- M2 through M8 software requirements are implemented.
- Swift, Python, and Rust security behavior is consistent.
- Enrollment works across languages.
- Credentials are persistent and crash-safe.
- Renewal and rotation are interruption-safe.
- Revocation is enforced.
- Full-profile mTLS creates verified principals.
- Lightweight authentication obeys the frozen profile.
- HELLO is bound to verified transport evidence.
- Authentication failure cannot downgrade.
- Authorization derives from local policy, not claims.
- Remote safety-sensitive control requires authenticated authorization.
- Secret redaction is tested.
- Resource bounds are tested.
- Property/adversarial/fuzz smoke coverage exists.
- CI reflects the security release gates.
- Every milestone received a post-implementation code/security review.
- Every material review finding was fixed and regression-tested.
- The final internal review is clean of unresolved P0/P1 issues.
- The conformance matrix accurately distinguishes PASS from DEFERRED/NOT RUN.
- Remaining blockers, if any, are limited to genuine unavailable hardware/platform/external-review gates or are explicitly documented technical failures.

The final objective is not to make the report look green.

The objective is to leave AuroraACP in a state where the remaining red/yellow items are **real qualification work**, not missing security implementation hidden behind paperwork.
