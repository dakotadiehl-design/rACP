# ACP Aurora Trust M0 Closeout Report

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Date:** 2026-08-21  
**Normative baseline:** Candidate Freeze 2.1.1  
**Directive result:** Work Items 1–4 complete  
**Milestone result:** CONDITIONALLY CLOSED — M1 shared protocol development authorized; deferred platform/hardware gates remain unqualified

## 1. Security golden vectors — PASS

`vectors/security/manifest.json` indexes 17 deterministic vector sets and 31
hash-pinned artifacts. The corpus covers bootstrap encoding and rejection,
identities, ACP registration, ACP and RFC 9383 SPAKE2+, canonical context and
permissions, transcript, key schedule, protected approval, installation proof,
identity SPKI/key ID, X.509, HELLO channel binding, compact credentials,
revocation, and negative mutations. Fixtures containing private scalars and
bootstrap values are conspicuously synthetic test material.

`scripts/security_vectors.py` regenerates and validates the corpus independently
of production SDK implementations. CI regenerates it, validates every manifest
hash and semantic invariant, and rejects a dirty vector diff. Fixed certificates
pin reproducible validation artifacts while deterministic TBSCertificate hashes
avoid claiming deterministic ECDSA certificate issuance.

No vector-category gap required by the directive remains. Cross-language
consumption by future Trust implementations remains M1 work, not an M0 vector
defect.

## 2. Full-profile provider probes — PARTIAL PLATFORM QUALIFICATION

- Provider: Botan 3.13.0, Homebrew shared bottle, public APIs only.
- Provider crypto profile: PASS.
- macOS arm64 adapter: PASS.
- Mandatory current-host probes: 16 PASS, zero FAIL.
- macOS x86_64, iOS arm64, Linux x86_64, Linux arm64, Windows x86_64, and
  Raspberry Pi arm64: NOT_RUN with platform-specific reasons in the result.

The checked-in runner proves RFC 9383/ACP SPAKE2+, SHA/HMAC/HKDF, X.509 profile
and identity binding, KU/EKU/SKI/AKI, P-256 signing and strict DER/low-S adapter
behavior, AES-GCM negatives, TLS 1.3 mutual authentication, peer-certificate
evidence, exporter equality, disabled resumption/0-RTT, ACP revocation behavior,
and result redaction. The machine-readable evidence is
`tools/security-probe/results/macos-arm64-botan-3.13.0.json`.

Provider crypto capability and platform adapter capability are deliberately
separate. Overall `qualified` remains false; a macOS arm64 PASS does not qualify
another operating system or architecture.

## 3. Provider/license/security-update package — TECHNICAL PASS

The technical recommendation is exact Botan 3.13.0 for the Full profile only on
adapters that independently pass. There is no version-range approval or silent
provider fallback. Mbed TLS 4.2.0 remains a Lightweight research candidate and
is not qualified.

The approval package records Botan's BSD-2-Clause obligations, Mbed TLS's
Apache-2.0 OR GPL-2.0-or-later choice and recommended Apache path, distribution
requirements, advisory sources, severity deadlines, emergency response, and
mandatory requalification. Its owner-decision block is intentionally blank.
The project owner's bounded Botan Full-profile selection, license acceptance,
version policy, and security-update policy are recorded in the approval block.
The approval expressly does not qualify Pico/Lightweight or an untested adapter.

## 4. Rust 1.75 MSRV — PASS FOR CURRENT PRODUCTION GRAPH

- `rustc 1.75.0 (82e1608df 2023-12-21)`
- `cargo 1.75.0 (1d8b05cdd 2023-11-20)`
- Workspace check, test, all-targets check: PASS.
- Per-crate no-default-features checks: PASS.
- Unit tests: 25 PASS; doc tests PASS.

The original open `uuid = "1"` range resolved to `uuid 1.24.1` (Rust 1.85),
which selected edition-2024 `getrandom 0.4.3` (Rust 1.85) and could not be
parsed by Cargo 1.75. The manifest and lockfile now pin qualified `uuid 1.18.1`
and `getrandom 0.3.4`. UUID v4 behavior and ACP wire behavior are unchanged.
A permanent exact-toolchain CI job prevents recurrence.

The complete graph and feature analysis is in
`ACP_Aurora_Trust_M0_Rust_1.75_Qualification.md`. Full Trust, provider, TLS, and
X.509 Rust feature combinations are `NOT_RUN` because those production features
correctly do not exist while M1 is closed. They receive no advance qualification.

## 5. Regression and final review

After Work Item 4 and final review, two complete corrected passes produced the
same results:

| Check | Result per pass |
|---|---:|
| Registry / standard vectors | 93 messages / 93 vectors, PASS |
| Security vectors | 17 sets / 31 artifacts, PASS and fresh |
| Python lint / type checking | PASS / 27 source files PASS |
| Python tests | 142 PASS, 81.41% coverage |
| Rust 1.75 tests | 25 PASS plus doc tests |
| Swift tests | 75 PASS |
| Python WebSocket | HELLO and Remote PASS |
| Python/Rust framed | HELLO, session, Remote, negative; JSON/CBOR PASS |
| Python/Swift framed | HELLO, session, Remote, negative; JSON/CBOR PASS |
| Rust/Swift framed | session; JSON/CBOR PASS |
| Botan/macOS arm64 probes | 16 mandatory PASS |
| `git diff --check` | PASS |

Review found and fixed two execution defects: the initial TLS probe pump stopped
before draining the client-authentication flight, and the open UUID dependency
range invalidated the declared MSRV. The final audit found no skipped security
tests, live secrets, insecure fallback, silent `trusted_lan` downgrade, or M1
production implementation. Synthetic secrets/private scalars remain limited to
explicit test fixtures and ephemeral provider-probe inputs; result output is
redacted.

## 6. Remaining M0 blockers

1. `NOT_RUN`: every supported/shipping Full-profile adapter other than macOS arm64 must run
   and pass the same mandatory probe suite. No unsupported platform is implied
   qualified by the provider-level PASS.
2. `DEFERRED`: physical Pico-class Lightweight HIL is deferred by the project
   owner. Lightweight production qualification is `NOT QUALIFIED`, and its
   release/conformance claim remains `BLOCKED`. Future HIL must prove entropy
   source and quality, SPAKE2+ execution, RAM high-water mark, flash footprint,
   TLS 1.3 Raw Public Key behavior, peer authentication, transactional credential
   storage, power-loss recovery, handshake timing, bounded concurrency, and
   malformed-input/resource-bound behavior.

ACP Lightweight production release requires successful physical Pico-class HIL
qualification. Desktop/provider simulation and shared M1 models cannot satisfy
or automatically clear this permanent release gate.

Candidate Freeze 2.1.1 is frozen and independently reviewed, and closeout Work
Items 1–4 are complete. By project-owner directive, missing platform-specific
release evidence is deferred without being converted to PASS. The incomplete
iOS Simulator identity-policy and authenticated-network matrices are moved into
M1 as mandatory exit criteria because they require the M1 adapter. M0 is
conditionally closed for development and M1 is authorized; no production or
Lightweight conformance claim follows.
