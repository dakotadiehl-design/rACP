# ACP Aurora Trust Conditional M0 Close / M1 Transition Directive for Codex

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

## Purpose

Determine whether Aurora Trust Milestone 0 is eligible for a **conditional close** with only the Pico-class Lightweight HIL qualification deferred.

If, and only if, every non-hardware M0 gate is satisfied, record M0 as conditionally closed and proceed into M1.

Do not fabricate evidence, reinterpret missing non-hardware evidence as acceptable, or mark the Lightweight profile production-qualified.

## Repository Boundary

Modify only the **AuroraCommunicationsProtocol** repository.

Do not modify Prism, Aurora Remote, Lyric, Conductor, Bridge, any other Aurora-family repository, or external dependency source trees.

## Project-owner approval

Record this project-owner decision if it is not already captured:

> Botan is approved as the ACP Full-profile cryptographic provider subject to ACP qualification. The Simplified BSD licensing and associated distribution/attribution obligations are accepted. Botan 3.13.x is approved as the initial provider line. Compatible Botan 3.x updates may be adopted only after passing the complete ACP security-vector, provider-probe, interoperability, and regression gates. Major provider-version changes require renewed owner approval. Applicable critical/high security advisories affecting ACP-used functionality require expedited evaluation and qualification. Emergency updates do not waive ACP conformance/regression requirements. This approval does not cover or imply Pico/Lightweight production qualification, which remains deferred.

Do not broaden this approval.

## Re-evaluate the M0 gate

Before changing milestone status, verify independently that:

- Candidate Freeze 2.1.1 has independent document-level GO.
- No unresolved BLOCKER or HIGH findings remain.
- ACP security golden vectors pass.
- Vector freshness validation passes.
- Botan 3.13.0 crypto profile passes.
- All required Full-profile provider probes for the currently supported/shipping development target set are complete or explicitly resolved by documented project scope.
- macOS arm64 passes all mandatory provider probes.
- Provider/license/security-update policy has project-owner approval.
- Rust 1.75 MSRV qualification passes or has an explicitly approved reconciliation.
- Python tests pass.
- Swift tests pass.
- Rust tests/doc tests pass.
- JSON/CBOR interoperability passes.
- WebSocket/framed interoperability passes.
- Registry/schema/generated-artifact checks pass.
- `git diff --check` passes.
- No unresolved non-hardware M0 gate remains hidden behind `NOT_RUN`, `BLOCKED`, or similar status.

If any non-hardware requirement is not actually satisfied, **do not conditionally close M0 and do not begin M1**. Report the exact blocker instead.

## Pico / Lightweight HIL deferral

The only permitted deferred M0 gate is:

> **Pico-class Lightweight hardware-in-the-loop qualification**

Record it explicitly as:

```text
Pico-class Lightweight HIL: DEFERRED
Lightweight production qualification: NOT QUALIFIED
Lightweight release/conformance claim: BLOCKED
Reason: physical hardware testing deferred by project owner
```

Do not mark it PASS.

Preserve the future HIL checklist:

- entropy source and quality;
- SPAKE2+ execution;
- RAM high-water mark;
- flash footprint;
- TLS 1.3 Raw Public Key behavior;
- peer authentication;
- transactional credential storage;
- power-loss recovery;
- handshake timing/performance;
- bounded concurrency;
- malformed-input/resource-bound behavior.

Desktop/provider simulation does not replace physical HIL.

## Conditional M0 status

If all non-hardware gates are satisfied and Pico HIL is the only remaining item, update status to:

```text
M0 STATUS: CONDITIONALLY CLOSED

Full-profile protocol/specification status: QUALIFIED FOR M1 DEVELOPMENT
Full-profile production qualification: according to completed provider/platform evidence
Lightweight specification status: MAY PROCEED THROUGH SHARED M1 MODEL WORK
Lightweight production qualification: NOT QUALIFIED
Pico HIL: DEFERRED
```

Use equivalent repository terminology if formal milestone-state vocabulary already exists.

Document clearly:

> Conditional M0 closure authorizes M1 engineering work. It does not authorize production release, conformance claims, or deployment of the Lightweight/Pico profile.

## Preserve a permanent Lightweight release gate

Add/update conformance and release documentation so Pico HIL cannot be forgotten.

There must be an explicit release criterion equivalent to:

```text
ACP Lightweight production release requires successful Pico-class HIL qualification.
```

If the repository has a machine-readable conformance matrix, preserve this as a blocking condition for Lightweight production qualification.

Do not invent a compile-time constant unless the architecture naturally requires one. The requirement is the gate.

Future milestones must not automatically convert this deferred requirement to PASS.

## Final M0 regression before transition

Before beginning M1, perform one final clean-state M0 regression:

- security-vector validation/freshness;
- Python suite;
- Swift suite;
- Rust suite/doc tests;
- Rust 1.75 qualification;
- schema validation;
- registry validation;
- generated-artifact freshness;
- JSON interoperability;
- CBOR interoperability;
- WebSocket/framed interoperability;
- all provider probes available on the current host;
- `git diff --check`.

Then review M0 for:

- unresolved BLOCKER/HIGH findings;
- stale Freeze references;
- TODO/FIXME/placeholder security decisions;
- falsely marked provider/platform PASS states;
- missing owner approval;
- accidental claims that Lightweight is qualified;
- insecure downgrade language;
- secret leakage;
- incomplete conformance-matrix state.

Fix every issue found and rerun the complete M0 regression.

Only after a clean pass may M1 begin.

## Commit/checkpoint

If M0 closeout work remains uncommitted, create a clean checkpoint commit before substantive M1 implementation.

Use wording such as:

```text
Aurora Trust M0 conditional closeout
```

Do not call it `M0 complete`.

Do not include changes outside ACP.

## Begin M1 only after conditional close

If the criteria above pass, proceed immediately to:

**Milestone 1 — Protocol Contract, Schemas, Registry, and Vectors**

Follow the original strict execution contract.

For M1:

1. Re-read every M1 requirement and exit criterion.
2. Implement the entire milestone.
3. Do not skip features or substitute scaffolding.
4. Add all required security schemas, common definitions, registry metadata, capabilities, errors, sensitive-field annotations, limits, and generated artifacts.
5. Treat Candidate Freeze 2.1.1 and the checked-in security golden vectors as normative.
6. Keep Swift, Python, and Rust contract expectations aligned.
7. Preserve the deferred Pico HIL gate.
8. Do not claim hardware-specific Lightweight behavior is validated merely because shared schemas/models exist.

## M1 review/regression gate

After M1 implementation:

1. Run M1-specific validation.
2. Run the entire ACP regression suite.
3. Perform a thorough code/spec review.
4. Inspect specifically for schema ambiguity, registry inconsistency, cross-language divergence, missing sensitive-field annotations, malformed-input behavior, downgrade semantics, capability-vs-authorization confusion, Full/Lightweight drift, incorrect bounds, stale generated artifacts, vector mismatches, and accidental reliance on unqualified Pico behavior.
5. Fix every issue.
6. Run M1-specific validation again.
7. Run the entire ACP regression suite again.
8. Only then mark M1 complete and proceed to M2.

A passing test suite alone is not sufficient.

## Required transition report

Return a concise report containing:

### M0 final state

- Candidate Freeze revision
- independent review status
- golden-vector status
- provider qualification status
- macOS arm64 probe status
- other platform status
- provider/license owner approval status
- Rust MSRV status
- regression results
- Pico HIL status
- Lightweight production qualification status

### Decision

Return exactly one:

```text
M0 CONDITIONALLY CLOSED — M1 AUTHORIZED
```

or

```text
M0 REMAINS BLOCKED — M1 NOT AUTHORIZED
```

If blocked, list each unresolved non-hardware blocker.

### M1 start

If authorized, state that M1 has begun, identify the first implementation tranche, and confirm Pico HIL remains deferred.

## Non-negotiable rule

The project owner is deliberately deferring **only** the physical Pico-class Lightweight HIL qualification.

Do not turn this into a general waiver of M0 requirements.

Every other M0 requirement must actually be satisfied before M1 begins.

If that condition is met, conditionally close M0 and proceed to M1 under the existing strict milestone execution contract.
