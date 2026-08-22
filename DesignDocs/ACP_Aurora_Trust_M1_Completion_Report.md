# ACP Aurora Trust M1 Completion Report

**Date:** 2026-08-21  
**M0 transition:** CONDITIONALLY CLOSED  
**M1 result:** COMPLETE — M2 development authorized

## M0 transition

M0 was conditionally closed at checkpoint `f9eabb2` (`Aurora Trust M0 conditional
closeout`) after two complete passing regression gates. No deferred platform or
hardware evidence was converted to PASS. Physical iOS, Secure Enclave, macOS
x86_64, Linux x86_64/arm64, Windows x86_64, Raspberry Pi arm64, and Pico-class
Lightweight HIL remain separate release gates.

## M1 contract

The language-neutral contract now contains closed common security definitions,
the complete enrollment and credential lifecycle family, signed revocation state,
reset/state events, Lightweight finished binding, Full/Lightweight profile limits,
stable errors, capability versions, and sensitive-field annotations. HELLO and
HELLO_ACK carry frozen Aurora Trust identity/channel-binding and authenticated-session
metadata. Cryptographically relevant maps reject unknown fields.

The registry contains 109 messages, including 16 Trust messages. Security rows
declare direction, QoS, response/correlation, capability version, authorization,
rate-limit class, sensitivity, terminal status, and explicit legal session states.
The `EnrollmentRestricted` and `LightweightBinding` states cannot route ordinary
show-control traffic.

The canonical constants and schema pack are packaged for Python and Swift and
consumed directly by Rust. All 109 message types have checked-in JSON and CBOR
vectors. The independent M0 security corpus remains unchanged and normative at
17 vector sets / 31 hashed artifacts.

Swift, Python, and Rust expose equivalent immutable transport-evidence/principal
admission, hardened downgrade rejection, identity/channel-binding comparison, and
permission intersection. Claimed roles, node IDs, and capabilities cannot create
authority. Device identity remains distinct from operator assignment, and credential
lifecycle remains distinct from asset lifecycle. The CLI inspector and Wireshark
surface only useful public security metadata and redact secret-bearing fields.

## iOS Simulator

The machine-readable result is
`tools/security-probe/results/ios-simulator-arm64-botan-3.13.0-m1.json`.

- X.509 policy: 17/17 mandatory PASS, covering valid isolated ACP chain, exact
  SAN/domain/node binding, CN-only, EKU, KU, CA leaf, invalid chain, expired/future,
  malformed DER, revocation/rollback, credential/key IDs, and isolated trust store.
- Authenticated network negatives: 13/13 mandatory PASS, covering missing/wrong
  identity evidence, stripped Trust/fallback, HELLO/exporter binding mutations,
  revoked reconnect, 0-RTT, and resumption policy.
- Previously passing SPAKE2+, TLS 1.3 mutual authentication, peer evidence,
  exporter equality, vectors, CryptoKit P-256, and hosted Keychain also pass.
- The spawn-only Keychain probe remains a non-applicable `errSecMissingEntitlement`
  result; the ACP-only hosted 2/2 Keychain suite is the authoritative PASS.

Final status: **iOS Simulator Full-profile functional qualification PASS**.
This is not physical-device or Secure Enclave evidence.

## Regression and review

The first complete M1 regression passed: registry/schema 109, standard vectors 109,
security vectors 17/31, Python 153, Swift 78, Rust 27 tests on exact Rust 1.75 plus
doc tests, JSON/CBOR WebSocket and framed Rust/Swift interoperability, macOS arm64
Botan 16 mandatory probes, Simulator qualification, and `git diff --check`.

Review found and fixed four material issues: provisional Full enrollment concurrency
was corrected from 8 to frozen 2; the initial HELLO/enrollment maps were aligned to
the exact Freeze 2.1.1 `aurora_trust` and PAKE field mapping; security constants were
made directly consumable in all three SDKs; and inspector/Wireshark redaction was
made explicit and tested. No TODO/FIXME/stub, skipped security test, silent downgrade,
unbounded cryptographic map, SDK-local Trust identifier, or platform qualification
overclaim remains in the M1 scope.

The final complete regression was then run with the same gates and passed:
Python 156, Swift 79, Rust 28 on exact Rust 1.75 plus doc tests, registry/schema 109,
standard vectors 109, security vectors 17/31, all listed interoperability suites,
macOS Botan 16 mandatory PASS, iOS Simulator 38 mandatory PASS, and
`git diff --check`. These remain reproducible from the checked-in contract,
vectors, and probe runner.

## Remaining release gates

- iOS physical-device Full-profile qualification: NOT RUN / DEFERRED.
- Secure Enclave qualification if used by shipping code: NOT RUN / DEFERRED.
- macOS x86_64, Linux x86_64/arm64, Windows x86_64, and Raspberry Pi arm64:
  NOT RUN / NOT QUALIFIED.
- Pico-class Lightweight HIL: NOT RUN / mandatory before Lightweight production release.

These gates do not block the completed shared M1 protocol contract, but they block
production qualification claims on their respective targets.
