# ACP Aurora Trust M0 Conditional Close / M1 Execution Directive for Codex

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

## Purpose

Conditionally close Aurora Trust Milestone 0 and begin Milestone 1.

M0 has produced sufficient protocol, provider, vector, and iOS Simulator evidence to proceed with shared protocol implementation.

The remaining iOS Simulator blockers are not M0 design defects. They depend on authenticated identity/revocation and authenticated-HELLO adapter functionality assigned to M1.

Therefore:

```text
M0 STATUS: CONDITIONALLY CLOSED
M1 STATUS: AUTHORIZED
```

This is a development authorization only.

It does **not** convert deferred platform or hardware qualification into PASS.

---

# 1. Repository Boundary

Modify only the **AuroraCommunicationsProtocol** repository.

Do not modify:

- Prism
- Aurora Remote
- Lyric
- Conductor
- Bridge
- Any other Aurora-family repository
- External dependency source trees

If a downstream product will eventually need changes, document them only.

---

# 2. Record the M0 Conditional Close

Update the M0 decision record, closeout report, and conformance matrix to reflect the following status accurately.

## Passed M0 evidence

Record as PASS where already evidenced:

- Candidate Freeze 2.1.1 independent review.
- No remaining BLOCKER or HIGH M0 design findings.
- Security golden vectors.
- Vector freshness validation.
- Botan 3.13.0 crypto profile.
- macOS arm64 provider adapter.
- iOS Simulator:
  - security vectors;
  - SPAKE2+;
  - SHA-256;
  - HMAC;
  - HKDF;
  - P-256;
  - TLS 1.3 mutual authentication;
  - peer-certificate evidence;
  - TLS exporter equality;
  - resumption/0-RTT policy;
  - Keychain functional qualification;
  - WebSocket qualification.
- Rust 1.75 MSRV.
- Project-owner provider/license/security-update approval.
- Existing ACP regression and interoperability suites.

## Deferred M0 evidence

Preserve these as NOT QUALIFIED / DEFERRED / NOT RUN as appropriate:

```text
iOS physical-device Full-profile qualification
Secure Enclave hardware qualification
macOS x86_64 provider qualification
Linux x86_64 provider qualification
Linux arm64 provider qualification
Windows x86_64 provider qualification
Raspberry Pi arm64 provider qualification
Pico-class Lightweight HIL
```

Do not convert any of these to PASS.

---

# 3. Move the Remaining iOS Simulator Cases into M1 Exit Criteria

The following two iOS Simulator qualification areas remain incomplete because the required production-intended adapters are M1 work:

1. Full ACP X.509 policy matrix.
2. Authenticated-network negative suite.

Record them explicitly as:

```text
M1-DEPENDENT QUALIFICATION
```

Do not mark them waived.

They become mandatory M1 exit criteria.

M1 must not close until the implemented identity/revocation/authenticated-HELLO path is used to rerun these iOS Simulator cases successfully.

Required M1 iOS cases include at minimum:

## X.509 policy matrix

- valid ACP chain;
- wrong trust domain;
- wrong node ID;
- wrong SAN;
- CN-only rejection;
- wrong EKU;
- wrong Key Usage;
- CA:TRUE leaf rejection;
- invalid chain;
- expired certificate;
- future certificate;
- malformed certificate;
- revoked credential;
- stale/rolled-back revocation state;
- wrong credential/key ID where applicable;
- isolated ACP trust-store behavior.

## Authenticated-network negative suite

- missing client credential;
- wrong CA;
- wrong trust domain;
- wrong node identity;
- claimed `mutual_tls` without transport evidence;
- stripped/missing Trust capability;
- attempted `trusted_lan` fallback;
- invalid HELLO channel binding;
- altered HELLO node ID after TLS authentication;
- exporter mismatch;
- revoked credential reconnect;
- 0-RTT rejection;
- session-resumption behavior according to Freeze 2.1.1.

Authentication failure must never silently downgrade.

---

# 4. Preserve Permanent Platform / Hardware Release Gates

Conditional M0 closure does not authorize production claims for unqualified platforms.

Maintain explicit release gates equivalent to:

```text
A platform may not claim ACP Trust production qualification
until its required provider/platform qualification suite passes.
```

Additionally:

```text
ACP Lightweight production release requires successful Pico-class HIL qualification.
```

And:

```text
iOS production release requires physical-device qualification
for all hardware-dependent security behavior used by ACP.
```

If Secure Enclave is used by the shipping iOS implementation, Secure Enclave qualification is mandatory before release.

These release gates must remain visible in the conformance matrix and release documentation.

---

# 5. Create the M0 Checkpoint

Before substantive M1 changes:

1. Run the complete M0 regression one final time.
2. Perform a final M0 review.
3. Fix any issue found.
4. Run the complete M0 regression again.
5. Create a clean repository checkpoint commit.

Use wording such as:

```text
Aurora Trust M0 conditional closeout
```

Do not call it `M0 complete`.

Do not include files outside ACP.

---

# 6. Begin Milestone 1

Proceed to:

# Milestone 1 — Protocol Contract, Schemas, Registry, and Vectors

Implement the **entire approved M1 scope** from the Aurora Trust implementation plan.

Do not skip features.

Do not implement scaffolding and call it complete.

Do not begin M2 until M1 passes its full exit gate.

---

# 7. M1 Required Scope

At minimum, implement every M1 requirement from the approved plan, including:

## Common security definitions

Add language-neutral definitions for:

- authentication modes;
- security profile/version;
- trust-domain identifiers;
- credential identifiers;
- key identifiers;
- enrollment identifiers;
- attempt identifiers;
- algorithm identifiers;
- suite identifiers;
- enrollment states;
- enrollment methods;
- credential status;
- credential format;
- storage posture;
- authenticated-principal state;
- security errors.

## Security message schemas

Add the full schema family required for:

- enrollment;
- credential lifecycle;
- security negotiation;
- revocation;
- rotation;
- renewal;
- reset/unenrollment;
- security state/events;
- authenticated session metadata.

All cryptographically relevant structures must follow Candidate Freeze 2.1.1 exactly.

No undefined extra fields may enter cryptographic transcript/AAD/signature structures.

## HELLO / HELLO_ACK extensions

Extend authentication structures to carry the frozen Trust fields.

Preserve backward-compatible ACP 1.2 behavior where allowed.

Hardened-mode behavior must remain fail-closed.

Discovery and HELLO claims remain untrusted until authenticated.

## Security capability IDs

Add all required Trust capability identifiers and versions.

Capabilities indicate support only.

Capabilities must never grant authorization.

## Stable security errors

Add all required stable security error codes.

Externally observable confirmation/transcript/tag failures must follow the frozen information-leakage policy.

Do not expose secret-sensitive distinctions.

## Registry metadata

Extend the registry for all security message types.

Each entry must define, where applicable:

- legal state;
- legal-before-handshake status;
- direction;
- QoS;
- correlation requirements;
- required capability;
- authorization permission;
- response type;
- rate-limit class;
- sensitive-field policy;
- profile applicability.

Enrollment legality before a normal Established session must be explicit.

Do not smuggle enrollment through ordinary `trusted_lan` show-control sessions.

## Sensitive-field annotations

Add and preserve the frozen sensitive-field annotations.

Schema generation, registry generation, packing, logging, inspection, and tooling must preserve them.

## Full / Lightweight limits

Add the frozen profile-specific size/count/resource limits.

These must be represented in the language-neutral contract.

Do not claim physical Lightweight enforcement is hardware-qualified yet.

## Golden-vector integration

M1 must consume the checked-in M0 security vectors as normative evidence.

Do not regenerate expected values independently inside individual SDKs.

Any M1 schema or serialization change that makes an existing security vector invalid must be treated as a protocol conflict and reviewed explicitly.

---

# 8. Cross-Language Contract

Swift, Python, and Rust must remain aligned.

Where M1 produces generated or shared artifacts, verify all three languages consume equivalent:

- identifiers;
- enums;
- message names;
- field names;
- field types;
- canonical encodings;
- error codes;
- capability IDs;
- limits;
- sensitivity annotations.

Do not allow SDK-local semantic choices where Candidate Freeze 2.1.1 is normative.

---

# 9. Authentication / Authorization Boundary

M1 must preserve this rule:

```text
discovery
→ claimed identity
→ cryptographic authentication
→ immutable AuthenticatedPrincipal
→ local authorization
→ operational safety policy
```

Peer claims do not create authority.

Specifically:

- `role` claims do not grant permission;
- capability advertisements do not grant permission;
- `node_id` claims do not prove identity;
- discovery TXT does not prove identity;
- `trusted_lan` produces an unauthenticated principal only;
- unilateral `tls` does not become an authenticated ACP principal in hardened mode;
- failed authentication must not fall back silently.

---

# 10. Enrollment-State Legality

M1 must explicitly encode the frozen pre-handshake enrollment behavior in:

- schemas;
- registry metadata;
- state-machine documentation;
- admission rules where M1 owns them.

The enrollment-only state must not expose ordinary show-control message families.

If the approved design uses a dedicated enrollment session/profile, implement the contract exactly as frozen.

Do not reuse an unauthenticated normal show-control session as an enrollment shortcut.

---

# 11. iOS Simulator M1-Dependent Qualification

As soon as M1 provides the required identity/revocation/authenticated-HELLO adapter functionality:

1. Integrate that path into the existing ACP-only iOS qualification host.
2. Run the complete X.509 policy matrix.
3. Run the authenticated-network negative suite.
4. Re-run every previously passing Simulator probe.
5. Record the new machine-readable iOS Simulator result.

M1 must not close while those Simulator-applicable M1-dependent cases remain `NOT_RUN`.

Expected final Simulator status for M1 completion:

```text
iOS Simulator Full-profile functional qualification: PASS
```

Physical-device and Secure Enclave statuses remain separate and deferred.

---

# 12. M1 Testing Requirements

Add all tests required by the approved implementation plan.

At minimum:

- schema validation;
- registry validation;
- security-vector consistency;
- generated-artifact freshness;
- security capability definitions;
- stable error definitions;
- sensitive-field annotation preservation;
- message legality/state checks;
- Full/Lightweight limit checks;
- malformed security messages;
- unknown fields;
- wrong field types;
- missing required fields;
- unsupported algorithms/suites;
- hardened-mode downgrade-policy representation;
- cross-language generated-artifact parity where applicable.

Do not delete or weaken existing tests.

---

# 13. M1 Code Review Gate

After first implementation:

Perform a thorough review for:

- schema ambiguity;
- differences from Candidate Freeze 2.1.1;
- cryptographic byte ambiguity;
- registry errors;
- state-machine inconsistencies;
- incorrect pre-handshake legality;
- missing sensitive annotations;
- role/capability authorization leakage;
- downgrade paths;
- unbounded fields;
- Full/Lightweight drift;
- SDK-local enums or identifiers;
- stale generated artifacts;
- golden-vector mismatches;
- accidental use of deferred hardware evidence as PASS;
- TODOs/FIXMEs/placeholders/stubs;
- disabled/skipped tests.

Fix every issue found.

---

# 14. M1 Regression Gate

After fixes, run:

- all M1-specific tests;
- Python suite;
- Swift suite;
- Rust suite/doc tests;
- security-vector validation/freshness;
- schema validation;
- registry validation;
- generated-artifact freshness;
- JSON interoperability;
- CBOR interoperability;
- WebSocket/framed interoperability;
- macOS arm64 provider probes;
- iOS Simulator qualification including new M1-dependent cases;
- Rust 1.75 qualification;
- `git diff --check`.

Then perform a second review.

Fix every issue found.

Run the entire suite again.

Only then may M1 be marked complete.

---

# 15. M1 Completion Report

Provide a detailed report containing:

## M0 transition

- confirmation of conditional M0 closure;
- checkpoint commit;
- deferred platform/hardware gates;
- confirmation that none were marked PASS.

## M1 implementation

- schemas added/changed;
- registry entries added/changed;
- capabilities;
- errors;
- limits;
- sensitive annotations;
- generated artifacts;
- state-machine changes;
- HELLO/auth changes.

## Cross-language status

- Swift
- Python
- Rust
- parity results

## iOS Simulator

- X.509 policy results;
- authenticated-network negative results;
- final Simulator status.

## Tests

- Python count/results;
- Swift count/results;
- Rust count/results;
- schema/registry results;
- vector results;
- interop results;
- provider probe results;
- Rust 1.75 results;
- first regression;
- code-review findings/fixes;
- final regression.

## Remaining deferred gates

Explicitly preserve:

- iOS physical-device qualification;
- Secure Enclave qualification if applicable;
- untested Full-profile platforms;
- Pico Lightweight HIL.

---

# 16. Decision at M1 Exit

Return exactly one:

```text
M1 COMPLETE — M2 AUTHORIZED
```

or

```text
M1 BLOCKED — M2 NOT AUTHORIZED
```

If blocked, list every unresolved item.

---

# 17. Final Rule

M0 is being conditionally closed because the remaining iOS Simulator gaps require M1 functionality and the remaining platform/hardware tests are release qualifications rather than blockers to defining the protocol contract.

Do not reinterpret this as permission to relax Aurora Trust.

Implement M1 completely, use Freeze 2.1.1 and the security vectors as the source of truth, close the M1-dependent iOS Simulator cases, perform the required review/regression cycles, and only then proceed to M2.
