# Aurora Trust Milestone 0 Decision and Qualification Record

**Date:** 2026-08-21
**Milestone:** M0 — Security profile freeze
**Status:** CONDITIONALLY CLOSED — shared Full-profile protocol development may proceed to M1; deferred platform and hardware evidence remains release-blocking on each affected target

## 1. Work completed

- Converted the twelve design-freeze questions into a single candidate normative profile in `docs/SECURITY.md`.
- Selected the RFC 9383 P-256/SHA-256/HKDF/HMAC ciphersuite and fixed ACP suite identity, secret normalization, context inputs, transcript hash, and application HKDF labels.
- Selected AES-256-GCM and fixed nonce/AAD behavior for protected approval.
- Fixed persistent identifier construction and a bounded X.509 v3 node profile.
- Fixed the TLS exporter label/context and prohibited hardened fallback when exporters are unavailable.
- Proposed a bounded Lightweight construction using TLS 1.3 mutual Raw Public Keys plus signed compact credentials.
- Fixed a signed deterministic-CBOR revocation snapshot/delta model, explicit offline policy, clock states, and authority-recovery identity rule.

Candidate Freeze 1 received independent NO-GO. Freeze 2 addressed its findings and received CONDITIONAL GO. Freeze 2.1 addressed the residuals and received CONDITIONAL GO in `ACP_Aurora_Trust_M0_Independent_Review_Freeze21.md` because its confirmation-key assignment introduced AT-M0-042. Freeze 2.1.1 closes AT-M0-042 through AT-M0-044 and received independent document-level GO in `ACP_Aurora_Trust_M0_Independent_Review_Freeze211.md`, with no BLOCKER or HIGH findings. That GO establishes internal profile coherence; it is not evidence that providers or target hardware can implement the profile safely.

## 2. Provider qualification findings

### 2.1 Desktop/shared provider candidate

Botan 3.13.0 is the leading shared-provider candidate because its maintained API advertises:

- RFC 9383 SPAKE2+ P-256/SHA-256 through a C FFI;
- SHA-256, HMAC, HKDF, AES-GCM, P-256 ECDSA;
- X.509 issuance/validation and TLS 1.3;
- C, C++, and Python APIs; and
- supported secure-memory, PKCS#11, TPM, system RNG, testing, and advisory mechanisms.

Qualification is incomplete:

- SPAKE2+ was newly delivered in the Botan 3.13 line and has no ACP-specific independent audit evidence.
- Swift and Rust would require reviewed bindings around the stable C FFI.
- TLS peer-evidence/exporter API behavior must be proven rather than inferred from feature lists.
- Packaging Botan in SwiftPM, Python wheels, Windows, Linux, and macOS has not been implemented or tested.
- Botan is not yet proven appropriate for Pico-class memory/flash limits.

### 2.2 Rejected or non-primary candidates

- The common Rust `spake2` crate implements balanced SPAKE2, explicitly not SPAKE2+, and documents lack of an independent audit. It is incompatible with the ACP suite.
- `pakery-spake2plus` implements RFC 9383 but is new, targets Rust 1.79 rather than the plan's stated Rust 1.75 floor, and has no independent audit evidence found. It cannot be the cross-language production provider without additional qualification.
- BoringSSL contains an RFC 9383 implementation, but it is internal API and BoringSSL explicitly does not promise third-party API/ABI stability. It is not selected as ACP's public provider.
- OpenSSL 3.5 documentation does not expose a public SPAKE2+ algorithm/API. The installed macOS `openssl` command is LibreSSL 3.3.6, so its presence is not qualification evidence.
- Apple CryptoKit documents P-256, hashing, key agreement, signatures, AEAD, and Secure Enclave support but no general RFC 9383 SPAKE2+ API. It remains useful behind ACP signing/storage interfaces, not as the complete enrollment provider.
- Matter/connectedhomeip contains deployed SPAKE2+ implementations across crypto PALs, including Mbed TLS, but adopting its entire build/runtime solely as an ACP primitive provider would require a separate dependency, footprint, stable-interface, and license assessment.

### 2.3 Lightweight provider candidate

Mbed TLS is the leading embedded transport candidate. Its maintained source identifies TLS 1.3 and RFC 7250 client/server Raw Public Key extension identifiers. Matter's Mbed TLS crypto PAL supplies SPAKE2+ P-256 operations.

Qualification is incomplete:

- Actual Raw Public Key negotiation/verification behavior must be proven on the selected maintained release and target configuration; header constants alone are insufficient.
- SPAKE2+ availability as a supported public Mbed TLS API was not established; Matter's adapter is not automatically an Mbed TLS public API.
- Pico-class flash, RAM, handshake-buffer, entropy, secure-storage, clock, and power-loss behavior require hardware/HIL validation.
- The proposed compact-credential preface binding requires independent protocol review.

## 3. Platform/API qualification matrix

| Target | SPAKE2+ | Identity/storage | TLS 1.3 mTLS | Exporter/peer evidence | Status |
|---|---|---|---|---|---|
| macOS Swift | Botan C FFI candidate | CryptoKit/Keychain candidate | provider adapter required | unproven | blocked |
| iOS Swift | packaging/ABI unproven | CryptoKit/Keychain candidate | App Store-compatible adapter unproven | unproven | blocked |
| Linux Swift | Botan C FFI candidate | protected file/PKCS#11 candidate | Botan/OpenSSL adapter evaluation required | unproven | blocked |
| Python macOS/Linux/Windows | Botan C/Python candidate | journaled file plus OS adapters | Botan or stdlib adapter evaluation required | unproven | blocked |
| Rust desktop/Pi | Botan C FFI candidate; pure-Rust candidates not qualified | file/TPM/PKCS#11 adapters | rustls/Botan evaluation required | unproven | blocked |
| Pico-class Rust/firmware | Matter/Mbed TLS research candidate | protected flash/two-slot design | Mbed TLS RPK candidate | unproven | blocked |
| Android adapter | no qualified choice | Android Keystore candidate | platform/provider adapter unproven | unproven | blocked |

## 4. M0 exit-criterion audit

| Criterion | Evidence | Result |
|---|---|---|
| Exact SPAKE2+ parameters | `docs/SECURITY.md` sections 2–4 | candidate specified |
| Password normalization/registration | `docs/SECURITY.md` section 3 | candidate specified |
| Transcript and confirmation format | `docs/SECURITY.md` sections 4–5 | candidate specified |
| Approval AEAD/nonce/AAD | `docs/SECURITY.md` section 6 | candidate specified |
| Mandatory identity suite | `docs/SECURITY.md` sections 2 and 8 | candidate specified |
| Full X.509 profile | `docs/SECURITY.md` section 8 | candidate specified |
| Lightweight transport/PoP | `docs/SECURITY.md` section 10 | candidate specified; review and hardware proof missing |
| TLS exporter policy | `docs/SECURITY.md` section 9 | candidate specified; API proof missing |
| Revocation/offline policy | `docs/SECURITY.md` section 11 | candidate specified |
| Secure-time policy | `docs/SECURITY.md` section 12 | candidate specified; hardware proof missing |
| Authority recovery | `docs/SECURITY.md` section 13 | candidate specified |
| SAS assets/mapping | Deferred from version 1; capability MUST NOT be advertised | closed by scope decision |
| Provider versions/licenses/platform support | Provider approval package and probe result | technical package complete; owner decision and remaining adapters open |
| Provider capability probes on representative targets | `tools/security-probe/` and machine-readable macOS arm64 result | Botan crypto profile and macOS arm64 PASS; remaining Full platforms NOT_RUN |
| Independent cryptographic/security review | `ACP_Aurora_Trust_M0_Independent_Review_Freeze211.md` | document-level GO; passed |
| Rust 1.75 production workspace | `ACP_Aurora_Trust_M0_Rust_1.75_Qualification.md` | PASS; exact toolchain and locked graph tested |

## 5. Blocking conditions

M0 cannot pass, and M1 MUST NOT begin under the approved execution contract, until all of the following occur:

1. Capability probes demonstrate RFC 9383 vector parity, P-256 signing, AES-GCM, TLS 1.3 mutual authentication, peer evidence, and exporter access on every supported/shipping Full target.
2. Every future production Trust/provider Rust feature combination is added to the MSRV matrix before it ships; the current production workspace is qualified on exact Rust 1.75.
3. A representative Pico-class target demonstrates CSPRNG readiness, RFC 9383 behavior, TLS 1.3 Raw Public Key mutual authentication, bounded memory/flash/time, and protected transactional storage—or the Lightweight profile is revised and reviewed.

## 6. Required follow-up evidence

- Signed or attributable independent review report with finding dispositions.
- Provider lockfile/version and SBOM/license record.
- Reproducible provider-probe outputs for macOS, iOS, Linux, Windows, Raspberry Pi, and the selected Pico-class target.
- RFC 9383 Appendix C results plus ACP Candidate Freeze vectors.
- TLS packet/test evidence for mutual identity, exporter equality, RPK proof of possession, and failure behavior.
- Resource report listing peak heap/stack, flash/code size, message bounds, and handshake time on Lightweight hardware.

## 7. Gate decision

**Decision: M0 is conditionally closed for development.** Candidate Freeze 2.1.1, security vectors, Botan's crypto profile, the macOS arm64 adapter, the Simulator-applicable provider/Keychain/WebSocket probes, bounded project-owner approval, and Rust 1.75 have evidence-backed PASS results. The remaining iOS Simulator X.509 policy and authenticated-network negative matrices are `M1-DEPENDENT QUALIFICATION` and mandatory M1 exit criteria. Untested Full platforms, physical iOS/Secure Enclave behavior, and Pico HIL remain explicitly unqualified release gates. This authorizes M1 engineering only, not production or conformance claims.

## 8. Regression and review evidence

Two complete available regression passes were run after the M0 documentation changes and after review remediation. Both final passes succeeded:

| Check | Result per pass |
|---|---:|
| Registry/generated-artifact validation | 93 messages, pass |
| Python tests | 142 passed |
| Python coverage | 81.41%, threshold 70% |
| Rust unit tests | 25 passed |
| Rust doc tests | pass |
| Swift tests | 75 passed |
| Python WebSocket interop | HELLO and Remote pass |
| Python/Rust framed interop | HELLO, session, Remote, negative; JSON and CBOR pass |
| Python/Swift framed interop | HELLO, session, Remote, negative; JSON and CBOR pass |
| Rust/Swift framed interop | session; JSON and CBOR pass |
| `git diff --check` | pass |

The initial sandboxed run could not bind localhost sockets and Swift could not write its compiler module cache. Those environment restrictions were rerun with explicit execution permission and passed; they are not product failures.

Review covered profile consistency, cross-language determinism requirements, downgrade behavior, secret handling, identity/assignment separation, trust/asset lifecycle separation, provider claims, Lightweight bounds, and unfinished-marker scans. One completeness defect was found and fixed: `docs/ACP_SPEC.md` did not link the new security profile as required by the implementation plan. No production code, schemas, registry rows, or vectors were changed because M1 is gated on M0 approval.

The working tree already contained unrelated user changes before this milestone. They were preserved and were not attributed to Aurora Trust M0.

### Candidate Freeze 2/2.1/2.1.1 remediation regression

After applying the independent NO-GO findings to Candidate Freeze 2, the complete available regression set passed again: registry 93 messages; Python 142 tests at 81.41% coverage; Rust 25 unit tests plus doc tests; Swift 75 tests; both Python WebSocket interop suites; Python/Rust and Python/Swift HELLO, session, Remote, and negative framed suites in JSON and CBOR; and Rust/Swift session interop in JSON and CBOR. These results prove preservation of existing ACP behavior only. They do not prove the new cryptographic profile, provider support, or Pico behavior.

After applying Candidate Freeze 2's CONDITIONAL GO findings to Freeze 2.1, the same complete available regression set passed with identical counts and coverage, including all WebSocket/framed interop suites and `git diff --check`. This remains compatibility evidence only; the required security vectors, provider probes, HIL, and independent GO confirmation are separate gates.

After applying the Freeze 2.1 review dispositions to Candidate Freeze 2.1.1, the complete available regression set passed again: registry validation covered 93 messages; Python reported 142 passing tests at 81.41% coverage; Rust reported 25 passing unit tests plus documentation tests; Swift reported 75 passing tests; and every WebSocket/framed interop suite passed, including Swift remote/negative and Rust-Swift session exchange in CBOR and JSON. `git diff --check` also passed. This is regression evidence, not a substitute for the outstanding M0 security gates.
