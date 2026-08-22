# ACP Aurora Trust Conformance Matrix

**Status:** Active evidence index
**Current gate:** M0 CONDITIONALLY CLOSED; M1 COMPLETE; M2 authorized for development. Platform/hardware release gates remain separate.

| Milestone | Requirement | Evidence | Status |
|---|---|---|---|
| M0 | Twelve wire/security choices resolved | `docs/SECURITY.md` Candidate Freeze 2.1.1 | independent document-level GO |
| M0 | Candidate Freeze 1 independent review | `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review.md` | NO-GO received |
| M0 | Independent-review finding dispositions | `DesignDocs/ACP_Aurora_Trust_M0_Review_Remediation.md` | AT-M0-001..044 closed; AT-M0-045..046 non-blocking follow-ups recorded |
| M0 | Candidate Freeze 2 independent re-review | `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review_Freeze2.md` | CONDITIONAL GO received |
| M0 | Candidate Freeze 2.1 independent confirmation | `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review_Freeze21.md` | CONDITIONAL GO received; AT-M0-042..044 remediated in 2.1.1 |
| M0 | Candidate Freeze 2.1.1 independent confirmation | `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review_Freeze211.md` | GO; no BLOCKER or HIGH findings |
| M0 | Audited providers selected per target | `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md` | blocked |
| M0 | Security golden vectors | `vectors/security/manifest.json`; `scripts/security_vectors.py` | PASS — 17 sets, 31 hash-pinned artifacts; deterministic generation and two regression gates |
| M0 | Botan 3.13.0 crypto-profile probes | `tools/security-probe/results/macos-arm64-botan-3.13.0.json` | PASS — provider capability separated from adapters |
| M0 | macOS arm64 Full adapter probes | same result artifact | PASS — mutual TLS 1.3, peer evidence, exporter equality, no resumption/tickets, X.509 and revocation |
| M0 | iOS Simulator M0-applicable functional qualification | initial/remediation results and reports | PASS — vectors/provider/TLS/exporter/P-256/Keychain/WebSocket; 76/76 package tests |
| M1 | iOS Simulator full ACP X.509 policy matrix | `tools/security-probe/results/ios-simulator-arm64-botan-3.13.0-m1.json` | PASS — 17 mandatory policy/negative cases |
| M1 | iOS Simulator authenticated-network negative suite | same result artifact | PASS — 13 mandatory fail-closed cases |
| M0 | iOS physical-device Full-profile qualification | none | DEFERRED / NOT_RUN — Simulator evidence is not device evidence |
| M0 | Secure Enclave hardware qualification | none | DEFERRED / NOT_RUN — physical device required |
| M0 | Other claimed Full-platform probes | same result artifact platform matrix | NOT_RUN — macOS x86_64, iOS, Linux x86_64/arm64, Windows x86_64, and Pi target unavailable |
| M0 | Provider/license/update approval package | `DesignDocs/ACP_Aurora_Trust_M0_Provider_Approval_Package.md` | PASS — technical package complete |
| M0 | Project-owner provider/license/update decision | approval block in package | PASS — bounded Botan Full-profile approval recorded; no Lightweight or untested-adapter approval implied |
| M0 | Rust 1.75 MSRV | `DesignDocs/ACP_Aurora_Trust_M0_Rust_1.75_Qualification.md`; locked workspace; permanent CI job | PASS — exact Rust/Cargo 1.75; 25 tests; `uuid` 1.18.1 compatibility pin |
| M0 | Future Trust/provider Rust feature graph | qualification report | NOT_RUN — production features correctly absent while M1 is closed |
| M0 | Pico-class Lightweight HIL | physical hardware testing deferred by project owner; future checklist retained in closeout report | DEFERRED — Lightweight production qualification NOT QUALIFIED; release/conformance claim BLOCKED |
| M0 | Independent security review | Freeze 2.1.1 confirmation | document-level gate passed |
| M0 | Existing ACP regression compatibility | M0 decision record section 8 | passed twice |
| M1 | Schema/registry/vectors | 109-message registry; 109 JSON/CBOR vectors; 17-set/31-artifact security corpus | PASS |
| M2 | Cross-language models/interfaces | not started; M0 gate enforced | pending |
| M3 | Enrollment and interop | not started; M0 gate enforced | pending |
| M4 | Credentials/storage/lifecycle | not started; M0 gate enforced | pending |
| M5 | Authenticated transports | not started; M0 gate enforced | pending |
| M6 | Authorization/profile gates | not started; M0 gate enforced | pending |
| M7 | Operations/migration | not started; M0 gate enforced | pending |
| M8 | Hardening/release | not started; M0 gate enforced | pending |

This file must be expanded with test names, CI run identifiers, hardware reports, and review artifacts as milestones proceed. A blank or narrative claim is not conformance evidence.

ACP Lightweight production release requires successful Pico-class HIL qualification. Deferred status must never be converted to PASS by completion of shared schemas, models, simulations, or later milestones.

A platform may not claim ACP Trust production qualification until its required provider/platform qualification suite passes. iOS production release requires physical-device qualification for every hardware-dependent behavior used by ACP; Secure Enclave use requires separate physical-device qualification.
