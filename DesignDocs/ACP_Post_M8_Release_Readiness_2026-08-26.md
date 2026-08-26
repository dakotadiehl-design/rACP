# ACP post-M8 release readiness

Date: 2026-08-26

Baseline: `f877e91ab8f3ab0a19e1e9581bba87a400ce4365`

Verdict: **NO-GO for show-critical ecosystem release**

## Status

| Area | Status | Reason |
|---|---|---|
| S9 ACP-local evidence boundary | COMPLETE | Swift/Python/Rust construction and reuse paths are sealed; compiled release artifacts pass the fabrication-API audit; focused boundary regressions pass. Independent architecture review is still an S15 external gate. |
| S10 macOS arm64 Full adapter | PARTIAL / NOT QUALIFIED | Certificate and Network.framework capability work passes, but the live factory remains intentionally unavailable until it owns bidirectional HELLO, authenticated session construction, server/listener operation, local identity binding, cancellation, and real mTLS qualification. |
| S10 iOS Simulator | NOT_RUN | No end-to-end adapter exists to qualify. |
| Physical iOS / Secure Enclave | BLOCKED | Physical device, signing, entitlements, and key lifecycle evidence unavailable. |
| S11 Linux x86_64 | BLOCKED | No shipping Botan/native TLS adapter or exact Linux worker was available. |
| Linux arm64 / Raspberry Pi | BLOCKED | No exact hardware/provider/storage environment was available. |
| S12 Lightweight | DEFERRED / UNSUPPORTED | Swift and Rust production-profile selectors reject Lightweight until provider and HIL qualification. |
| S13 integration contracts | COMPLETE | ACP-owned Prism, Aurora Remote, and Bridge contracts remain current; product repositories were not modified. |
| S14 AT-IA-001, ACP side | OPEN | Required production adapters and exact-platform qualification do not exist. |
| S14 AT-IA-001, ecosystem | BLOCKED | Product integration and product qualification remain separate writable-repository jobs. |
| S15 advisories | PASS for resolved ACP dependency graphs | RustSec and isolated Python audits found no known vulnerabilities. Apple/Botan release-advisory disposition remains release-owner work. |
| S15 external review | BLOCKED | No independent review of a qualified release candidate exists. |
| S16 | NO-GO | Downstream, hardware, independent-review, and owner-signature gates remain open. |

## Evidence from this run

- Two unchanged-source host regression passes: Swift 116/116, Python 244/244, Rust 64/64; Clippy, rustfmt, Ruff, and mypy PASS.
- Two complete available-host interoperability passes: WebSocket HELLO/Remote; Python/Rust/Swift enrollment; Python↔Rust and Python↔Swift framed HELLO/session/Remote/negative CBOR+JSON; Rust↔Swift session CBOR+JSON.
- Twice: frozen vectors 17 sets/31 hashed artifacts, registry 109 messages, fuzz smoke seed `0xA0C` for 2,000 iterations.
- Compiled release API audit PASS for the Swift public symbol graph, Python wheel, and Rust release library.
- Fresh RustSec audit PASS (1,226 advisories, 58 locked dependencies). Isolated Python environment with `cryptography 50.0.1` and audit-tool `pip 26.2.1`: no known vulnerabilities.
- CycloneDX source-package SBOMs are under `qualification/sbom/`. They are not SBOMs for a qualified Apple/Botan shipping adapter because no such release artifact exists yet.

No frozen protocol byte, schema, transcript, algorithm, key schedule, credential encoding, revocation format, identifier, or channel-binding rule changed. No other Aurora-family repository was modified.

## Remaining gates

The Apple live connection-to-authenticated-session boundary, Apple server path, real Keychain identity lifecycle, physical iOS, native Botan/Linux adapter, Raspberry Pi/storage posture, product wiring, HIL, signed qualification artifacts, independent review, and security/product-owner authorization remain BLOCKED or NOT_RUN. Production Remote control must remain view-only and hardened operation must never fall back to `trusted_lan`.
