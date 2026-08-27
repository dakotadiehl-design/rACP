# ACP Aurora Trust M0 Closeout Directive for Codex

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).
## Scope: Close Remaining M0 Items 1–4 Only

**Repository:** AuroraCommunicationsProtocol  
**Milestone:** Aurora Trust M0 closeout  
**Normative baseline:** Candidate Freeze 2.1.1  
**Current review status:** Independent document-level GO; no remaining BLOCKER or HIGH findings  
**Important:** M1 remains closed until the M0 exit gate is explicitly satisfied.

---

# 1. Mission

Complete the remaining **non-hardware** M0 closeout work for Aurora Trust.

This directive covers exactly these four work items:

1. ACP security golden vectors.
2. Full-profile provider qualification probes.
3. Provider/license/security-update approval package.
4. Rust 1.75 MSRV qualification and reconciliation.

Do **not** begin M1.

Do **not** implement M1 production security models, enrollment state machines, credential lifecycle, authenticated transport, or product integration merely because some of the tooling created here resembles later implementation work.

The purpose of this work is to produce **M0 evidence** proving that Candidate Freeze 2.1.1 is precise, provider-compatible, reproducible, and buildable.

The Pico-class Lightweight HIL qualification remains intentionally deferred and must stay visibly open in the M0 conformance matrix.

---

# 2. Repository Boundary

Modify **only** the AuroraCommunicationsProtocol repository.

Do not modify:

- Prism
- Aurora Remote
- Lyric
- Conductor
- Bridge
- Any other Aurora-family repository
- External dependency source trees

Do not copy product code into ACP to work around this restriction.

---

# 3. Execution Discipline

Treat each of the four work items below as a gated sub-phase.

For each sub-phase:

1. Review Candidate Freeze 2.1.1 and the independent M0 review findings that led to the current freeze.
2. Implement the complete evidence/tooling requirement.
3. Add all tests needed to validate the work.
4. Run the sub-phase tests.
5. Run the complete existing ACP regression suite.
6. Perform a code/spec review of the changes.
7. Fix every issue found.
8. Run the sub-phase tests again.
9. Run the complete ACP regression suite again.
10. Only then continue to the next sub-phase.

Do not weaken, skip, disable, or rewrite existing tests merely to make the new work pass.

A passing test suite alone is not sufficient. The output must prove the intended interoperability/security property.

---

# 4. Work Item 1 — ACP Security Golden Vectors

## Goal

Create a checked-in, deterministic `vectors/security/` corpus that converts Candidate Freeze 2.1.1 from prose into exact machine-verifiable bytes.

These vectors are normative M0 evidence.

They must be suitable for consumption by future Swift, Python, and Rust implementations without each SDK generating its own expectations.

## Required vector categories

At minimum, add deterministic vectors for:

### Bootstrap secret representation

- Raw bootstrap secret bytes.
- Human-readable Crockford Base32 encoding.
- Human-readable decoding back to the exact raw bytes.
- Case handling.
- Hyphen/space handling if permitted by Freeze 2.1.1.
- Invalid alphabet rejection.
- Invalid length rejection.
- Invalid padding-bit rejection.
- Ambiguous-character rejection if the frozen profile rejects aliases.

Include secrets containing:

- `0x00`
- `0xff`
- high-bit bytes
- repeated bytes
- all-zero synthetic test input where safe for deterministic testing

The presence of `0x00` is mandatory to prove no C-string truncation path exists in the normative representation.

### Identity encodings

Pin exact bytes for:

- candidate `node_id`
- commissioner `node_id`
- candidate `instance_id`
- commissioner `instance_id`
- `trust_domain_id`
- `enrollment_id`
- `attempt_id`
- any other UUID participating in cryptographic input

Where Candidate Freeze 2.1.1 distinguishes textual UUID representation from RFC 4122 16-byte binary representation, the vectors must explicitly demonstrate both and identify which is used in each cryptographic construction.

### Registration/KDF inputs and outputs

Pin exact bytes for:

- password/bootstrap-secret octets
- `idProver`
- `idVerifier`
- registration salt
- KDF parameters
- KDF input framing
- KDF output
- `w0`
- `w1`
- `L`

The vectors must be independent of provider-default registration behavior.

Provider APIs may be used only if configured to reproduce the frozen ACP function exactly.

### RFC 9383 / SPAKE2+ values

Pin:

- selected suite identifier
- M/N constants as represented by ACP
- `shareP`
- `shareV`
- `confirmV`
- `confirmP`
- shared secret / `K_shared`
- exact lengths
- exact SEC1 point encoding

Where applicable, include RFC 9383 Appendix C compatibility/reference checks.

### ACP context

Create a complete example canonical context.

Check in:

- semantic JSON representation for readability
- canonical CBOR bytes
- hex representation
- SHA-256 if the freeze requires one

The context vector must pin every key, field type, key-ordering rule, absent/present rule, null rule, UUID representation, role, suite, trust domain, versions, instance IDs, identity-key binding, and permission digest.

No cryptographic context object may permit undefined extra fields.

### Requested-permission digest

Pin:

- exact permission object
- canonical encoding
- digest bytes

Include empty and non-empty permission sets, canonical ordering behavior, and mutation tests.

### Application transcript

Pin exact bytes for:

- transcript semantic structure
- canonical CBOR
- transcript hash

The vector must eliminate ambiguity around `shareP`, `shareV`, `confirmV`, `confirmP`, provider concatenation, and binary/text representation.

### Derived keys

Pin every ACP key derived from the shared secret/transcript, including all labels and output lengths defined by Freeze 2.1.1.

The vectors must prove the exact frozen HKDF construction and distinguish it from TLS HKDF-Expand-Label or other similar functions.

### Protected approval

Pin:

- approval plaintext semantic object
- canonical CBOR plaintext
- AAD semantic object
- canonical CBOR AAD
- AEAD key
- nonce
- ciphertext
- authentication tag
- final wire representation

Include negative mutations for wrong attempt ID, identities, transcript hash, credential ID, nonce/tag, and ciphertext transplant.

### Installation proof-of-possession

Pin:

- exact signed bytes
- identity key
- public key/SPKI
- signature format
- signature bytes
- verification result

If ECDSA is used, enforce the frozen DER/low-S rules.

### Identity key/SPKI/key ID

Pin:

- synthetic deterministic P-256 private key for tests only
- public point
- DER SubjectPublicKeyInfo
- `identity_key_id`
- any SHA-256 identifier derivation

Production APIs must not require raw private-key export.

### X.509 Full-profile vectors

Produce deterministic or reproducibly generated test artifacts sufficient to pin trust-domain/CA identity, leaf identity, SAN, EKUs, Key Usage, Basic Constraints, SKI, AKI, serial, validity, role constraints if applicable, credential ID, and wrong-node/domain/EKU cases.

If ECDSA certificate signatures are nondeterministic, separate deterministic TBSCertificate/profile vectors from fixed checked-in synthetic certificates used for validation.

### HELLO exporter/channel-binding inputs

Pin:

- exact closed HELLO semantic subset
- canonical CBOR bytes
- exporter label
- exporter context hash
- output length
- expected channel-binding bytes where a deterministic TLS fixture permits it

Include negative mutations for wrong node/domain/key IDs, changed security profile, absent-vs-null binding, and unknown fields.

### Compact credential vectors

If retained in Freeze 2.1.1, pin credential body, canonical CBOR, public-key encoding, critical-extension representation, signature input/signature, and credential ID.

Do not claim these vectors satisfy Pico HIL qualification.

### Revocation vectors

Pin snapshot/delta body, canonical CBOR, epoch, previous-hash behavior, timestamp representation, signature input/format/signature, and ID/hash.

Include negative fixtures for rollback, replay, wrong domain, bad signature, and revoked credentials.

### Negative vectors

Create structured negative vectors that mutate one property at a time, including wrong secret/node/domain/role/instance/key/permission digest/suite/version, malformed point, wrong/reflected confirmation, replayed approval, wrong AAD, malformed/revoked/future credentials, revocation rollback, malformed base encodings, and null/absent mismatches.

## File layout

Use a clear layout such as:

```text
vectors/security/
  manifest.json
  bootstrap/
  registration/
  spake2p/
  context/
  transcript/
  key_schedule/
  approval/
  installation/
  identity/
  x509/
  hello_binding/
  compact_credential/
  revocation/
  negative/
```

Follow stronger existing repository conventions if applicable.

## Vector manifest

Add a machine-readable manifest containing vector ID, category, freeze/profile version, source/reference, input/output files, provider-independence status, normative/diagnostic status, and expected pass/fail behavior.

## Validation tooling

Create or extend scripts so CI verifies manifest integrity, hashes, canonical CBOR, unique IDs, synthetic-secret markings, and artifact freshness.

## Exit criteria

Work Item 1 is complete only when the corpus is checked in, vector validation passes twice, full ACP regression passes twice, and a review finds no unresolved issue.

---

# 5. Work Item 2 — Full-Profile Provider Qualification Probes

## Goal

Create a repeatable provider qualification suite proving the selected Full-profile provider stack exposes every behavior Candidate Freeze 2.1.1 requires.

Do not merely check whether a library has functions with appropriate names.

## Provider target

Use the provider selection currently recommended by Candidate Freeze 2.1.1 / the M0 decision record.

If Botan 3.13.x remains selected:

- record exact tested version
- record build configuration/linkage mode
- use only supported/public APIs
- do not silently change providers

If a provider cannot satisfy a mandatory probe, report failure and leave M0 blocked.

## Required probes

At minimum test:

### SPAKE2+

- RFC 9383 reference behavior
- ACP registration vectors
- ACP shares/confirmations
- exact point encoding
- both confirmations mandatory
- no ACP use of any confirmation-skip API
- NUL-containing secret handling
- raw/prehashed ACP registration path where provider defaults differ

### Hash/HMAC/HKDF

- SHA-256
- HMAC-SHA256
- exact frozen HKDF behavior
- ACP key-schedule vectors

### AEAD

- frozen AEAD, including fixed-vector encrypt/decrypt
- AAD mismatch rejection
- tag mismatch rejection
- nonce rules

### P-256 signing

- production-style generation
- synthetic deterministic test import where needed
- sign/verify
- strict DER
- low-S if frozen
- malformed DER rejection
- wrong-key rejection

### X.509

- ACP-profile issue/parse/validate
- SAN URI
- trust-domain binding
- KU/EKU/Basic Constraints/SKI/AKI
- validity
- node/domain/EKU failures
- isolated ACP trust-store behavior
- ACP revocation behavior

### TLS 1.3 mutual authentication

Prove TLS 1.3-only behavior, mutual certificates, peer evidence availability, ACP identity extraction, trust-domain/node mismatch rejection, peer DER access where required, and no plaintext fallback.

### TLS exporter/channel binding

Prove the exact exporter label/context/length required by Freeze 2.1.1 and peer equality. A platform cannot be marked qualified if exporter evidence is unavailable.

### 0-RTT / resumption

Prove the frozen policy. If forbidden, prove rejection/disablement and that revoked clients cannot reconnect through cached tickets.

### Revocation

Test active/revoked credentials, older-snapshot replay, wrong domain, bad signature, and epoch behavior.

### Secret/error behavior

Qualification tooling must not leak bootstrap secrets, PAKE intermediates, private keys, session keys, approval keys, TLS secrets, or exporter secrets except clearly synthetic deterministic fixtures where absolutely necessary.

## Platform matrix

Build machine-readable results for all currently claimed Full-profile platforms.

Where available, include macOS arm64/x86_64, iOS, Linux x86_64/arm64/Pi-class, Windows x86_64, Python 3.11+ desktop targets, Swift Full-profile targets, and Rust Full-profile targets.

Unavailable platforms must be reported as `NOT_RUN` with exact reason and required follow-up. Never fabricate a pass.

## Probe result format

Use a stable machine-readable result schema that identifies platform, provider/version, freeze revision, individual result statuses, and overall qualification.

`qualified` must be false if any mandatory probe fails or remains unavailable.

## Tool placement

Prefer an ACP-local tool such as `tools/security-probe/`, separate from production SDK security implementation.

## Exit criteria

Complete when the suite exists, available platforms have been run, results are recorded, golden vectors are consumed where relevant, failures/NOT_RUN are explicit, and the review/regression loop passes.

M0 remains blocked if mandatory platforms are still unqualified.

---

# 6. Work Item 3 — Provider / License / Security-Update Approval Package

## Goal

Prepare the project-owner decision package for provider and maintenance approval.

## Required contents

For every production provider document:

- provider name
- exact version qualified
- version-family policy
- license
- source/reference
- distribution/attribution obligations
- linkage considerations where relevant
- supported Aurora targets
- ACP-used features
- unused/unsupported features
- advisory source
- release/update source
- maintenance status
- limitations
- fallback provider
- replacement consequences
- qualification required for upgrades

## Version policy

Prefer separating:

```text
Protocol profile:
    exact frozen ACP algorithms/bytes

Qualified provider:
    exact tested version(s)

Upgrade policy:
    newer compatible versions allowed only after
    vectors + provider probes + ACP regression pass
```

Do not assume a provider/version range is approved.

## Security-update policy

Define advisory monitoring, severity thresholds, mandatory/expedited update criteria, pre-release regression requirements, emergency upgrade process, and interoperability requalification requirements.

## Owner approval marker

Include a clearly separate block:

```text
PROJECT OWNER DECISION

Provider:
Version policy:
License approved: YES / NO
Distribution obligations accepted: YES / NO
Security-update policy approved: YES / NO
Date:
Approver:
Notes:
```

Codex may make a technical recommendation but must not fill owner approval unless explicitly supplied.

## Exit criteria

The package is complete when technical recommendation, licensing obligations, version/update policy, and owner-decision block are all ready. M0 remains blocked until explicit owner approval is supplied.

---

# 7. Work Item 4 — Rust 1.75 MSRV Qualification

## Goal

Prove that the actual production Rust dependency graph and intended Trust feature combinations build/test on Rust 1.75.0, or identify the exact reconciliation required.

Do not rely on top-level crate documentation alone.

## Required actions

### Exact toolchain

Test with exactly:

```text
rustc 1.75.0
cargo 1.75.0
```

Record both versions.

### Actual dependency graph

Use the real workspace and proposed Trust/provider dependencies.

Capture:

- `Cargo.lock`
- `cargo tree`
- feature graph
- transitive dependencies
- build dependencies
- platform-specific dependencies

### Feature matrix

Test all production combinations that may ship, including default, Full-profile security, provider/TLS/X.509 features, intended no-default-features combinations, and Linux/Pi combinations.

Do not qualify intentionally unsupported combinations.

### Required qualification commands

At minimum perform equivalents of:

```bash
cargo +1.75.0 check --workspace
cargo +1.75.0 test --workspace
```

plus every required production feature combination.

Use cross-target `cargo check` where the relevant target toolchain is available.

### Failure analysis

If any dependency needs newer Rust, report crate, resolved version, required MSRV, dependency path, responsible feature, newest safe 1.75-compatible version, consequences of pinning, and whether ACP should raise its MSRV.

Do not pin an obsolete or security-risk dependency merely to preserve 1.75.

### Decision rule

Prefer security and maintainability over preserving an arbitrary compiler floor.

Any MSRV increase must be an explicit documented project decision.

### Permanent CI gate

Add a permanent MSRV CI job so future dependency updates that break 1.75 fail until reconciled or the declared MSRV is intentionally changed.

## Exit criteria

Complete when the actual graph and feature matrix are captured/tested, transitive dependencies are accounted for, incompatibilities have a recommendation, permanent MSRV CI exists, and full ACP regression passes.

---

# 8. M0 Conformance Matrix

Update the M0 conformance matrix after each item.

Statuses must distinguish:

```text
PASS
FAIL
BLOCKED
NOT_RUN
OWNER_APPROVAL_REQUIRED
HARDWARE_REQUIRED
```

Never convert missing evidence to PASS.

Expected final state after this directive should resemble:

```text
Independent document review        PASS
Security golden vectors            PASS
Full-provider probes               PASS / explicit remaining platform BLOCKED
Provider/license package           PASS
Owner provider approval            OWNER_APPROVAL_REQUIRED until supplied
Rust MSRV                          PASS or explicit decision required
Pico Lightweight HIL               HARDWARE_REQUIRED
```

---

# 9. Final Regression

After all four work items, run the complete ACP suite from a clean state, including:

- Python
- Swift
- Rust/doc tests
- schema/registry checks
- artifact freshness
- all golden vectors
- new security-vector validation
- JSON/CBOR interoperability
- WebSocket/framed interoperability
- provider probes available on the current host
- Rust 1.75 MSRV job
- `git diff --check`

Perform a final code/spec review and inspect for unfinished Trust TODOs/FIXMEs/placeholders/stubs, skipped tests, insecure fallbacks, hard-coded secrets, secret leakage, and accidental `trusted_lan` downgrade behavior.

Fix all issues and rerun the entire suite.

---

# 10. Explicit Prohibitions

Do not:

- Begin M1.
- Implement production enrollment, credential lifecycle, or authenticated session machinery.
- Modify anything outside ACP.
- Fabricate Full-platform passes.
- Fabricate Pico HIL evidence.
- Fabricate project-owner approval.
- Silently change Freeze 2.1.1 to accommodate a provider.
- Use provider-specific registration semantics where ACP freezes its own bytes.
- Weaken tests.
- Skip negative vectors.
- Check in real secrets.
- Treat TLS success alone as ACP authentication.
- Reintroduce capability or role claims as authorization.

---

# 11. Final Deliverable

Produce an M0 closeout report covering:

### Golden vectors
- count
- categories
- normative/diagnostic status
- results
- gaps

### Provider probes
- provider/version
- platforms run
- platform results
- failures/NOT_RUN
- qualification conclusion

### Provider/license package
- recommendation
- version policy
- license/obligations
- security-update policy
- exact owner approval still required

### Rust MSRV
- rustc/cargo versions
- dependency graph
- feature matrix
- results
- pins or proposed MSRV change

### Regression
- Python/Swift/Rust test results
- vector results
- interoperability results
- provider-probe results
- MSRV result
- code-review findings/fixes
- second full regression result

### Remaining M0 blockers
List every remaining blocker explicitly.

The Pico-class HIL gate must remain open until physical evidence is later supplied.

---

# 12. Completion Rule

Do not claim M0 itself is complete merely because this directive is complete.

This directive closes the **non-hardware M0 evidence work for items 1–4**.

M0 may close only after all required evidence, owner approvals, platform qualifications, and the separately deferred Pico-class HIL gate satisfy Candidate Freeze 2.1.1.

Proceed with Work Item 1 first. Pass its review/regression gate before Work Item 2, then 3, then 4.
