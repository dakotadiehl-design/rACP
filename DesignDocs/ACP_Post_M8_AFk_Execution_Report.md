# ACP post-M8 AFK execution report

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

Date: 2026-08-26  
Repository: AuroraCommunicationsProtocol  
Release verdict: **NO-GO**

## Executive result

The repository-local work strengthened the S9 evidence boundary, added explicit
three-SDK reserved-frame rejection coverage, established an Apple certificate
policy and API-feasibility spike, and produced read-only Prism, Aurora Remote,
and Bridge integration contracts. It did not produce a qualified shipping
provider-to-product path. AT-IA-001 therefore remains open and S16 release
authorization is prohibited.

## Milestone ledger

| Milestone | Status | Evidence / blocker |
|---|---|---|
| S9 | PARTIAL | Swift/Python/Rust evidence construction is sealed and the automated API-boundary check passes. The opaque connection capability is one-shot. A shipping adapter still must own HELLO/session admission end-to-end; focused exact-limit/offset/no-write tests and independent architecture review remain. |
| S10 | PARTIAL | Apple X.509 validation and TLS/exporter feasibility code exists and frozen certificate negatives pass. The public live factory is deliberately unavailable because bidirectional HELLO ownership, authenticated session construction, server qualification, Keychain lifecycle, real mTLS, and physical-iOS evidence are incomplete. |
| S11 | BLOCKED | Botan 3.13.0 capability probes pass on macOS arm64, but no shipping Rust native adapter/FFI or Linux execution environment exists in this repository run. Provider capability is not platform/product qualification. |
| S12 | BLOCKED / NOT SHIPPING | No Bridge firmware repository, selected embedded provider, board inventory, or HIL environment was available. Lightweight must remain unselectable in a release unless separately completed. |
| S13 | CONTRACTS ONLY | Read-only integration contracts were written for Prism, Aurora Remote, and Bridge. Prism and Remote were inspected but not modified; Bridge was unavailable. Product command paths remain unclosed. |
| S14 | BLOCKED | Exact-platform, physical-device, product-chain, HIL, signed-artifact, and two-clean-release-candidate evidence is missing. AT-IA-001 remains open. |
| S15 | BLOCKED | RustSec audit passed. The Python project constraint was raised to `cryptography >=50,<51` after the fresh host audit found applicable advisories through 49.0.0. No independent release review can begin before an S14 release candidate exists. |
| S16 | NO-GO | Mandatory S9–S15 evidence and security/product-owner signatures do not exist. |

## Evidence produced

- `scripts/check_security_api_boundary.py` rejects reopened Swift, Python, or
  Rust evidence-construction paths and rejects enabling the Rust testkit by
  default.
- Swift unit suite: 111 tests passed on the first complete run.
- Python unit suite: 240 tests passed on the first complete run.
- Rust workspace: 62 tests passed; Clippy passed.
- Swift/Rust/Python framed and enrollment/session interoperability matrix:
  PASS on the available macOS arm64 host.
- Security fuzz smoke: PASS, seed `0xA0C`, 2,000 iterations.
- Botan 3.13.0 provider probe: all 16 mandatory provider probes PASS on macOS
  arm64. Other platform adapters remain `NOT_RUN`; the aggregate qualification
  result remains false.
- `cargo audit --file Cargo.lock`: PASS against 1,226 refreshed RustSec
  advisories, 58 locked dependencies scanned.
- `pip-audit --local`: found advisories in host-installed `cryptography 43.0.3`
  and then 49.0.0, plus the host `pip` tool. ACP now requires
  `cryptography >=50,<51` for its
  optional vector tooling. With 50.0.1 installed, the 17-set/31-artifact vector
  gate and 40 focused security tests passed; the remaining audit findings are
  confined to host `pip 25.3`, which is not an ACP dependency. This report does
  not relabel a mutable host environment as a resolved release artifact.
- A second available-host regression/interoperability pass completed with 111
  Swift, 240 Python, and 62 Rust tests passing; Clippy/rustfmt, every framed and
  WebSocket interoperability suite, the API-boundary check, registry check, and
  the 2,000-iteration fuzz smoke also passed. This is not the two-clean-
  release-candidate gate required by S14/S15 because product/platform/HIL
  artifacts are absent and the working tree is not a frozen release candidate.

## Human/external input required

1. Approve the initial shipping target/product matrix, including whether
   Lightweight, Linux arm64/RPi, Windows, and macOS x86_64 are unsupported.
2. Provide writable product repositories and owners for Prism, Aurora Remote,
   and Bridge integration, or execute the supplied contracts there.
3. Provide physical iOS devices, Apple signing/entitlements, Keychain/Secure
   Enclave policy decisions, and a macOS/iOS server/client qualification host.
4. Provide Linux x86_64 and required arm64/RPi build/HIL workers, native Botan
   build provenance, and the approved storage posture (file, TPM, or secure
   element).
5. Select the embedded provider/boards and provide brownout, reset, entropy,
   malformed-traffic, and soak-test instrumentation if Lightweight will ship.
6. Assign CI/release owners for signed qualification artifacts, SBOMs tied to
   actual release artifacts, immutable hashes/tags, advisory dispositions, and
   the two clean release-candidate gates.
7. Commission an independent cryptography/security reviewer after S14, then
   supply security-owner and product-owner release signatures after all P0–P2
   findings are resolved.

Until those inputs are supplied and their gates pass, production Remote control
must remain view-only and hardened deployments must not fall back to
`trusted_lan`.
