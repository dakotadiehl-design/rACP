# ACP Aurora Trust M5 Implementation Report

Date: 2026-08-25
Starting commit: `301e55d` (`Fix M4 credential store crash recovery`)

## Result

The M5 shared transport-verification and session-binding implementation is complete, reviewed, and regression-clean. The M5 release/interop exit gate remains explicitly blocked for platform adapters that cannot expose the frozen TLS exporter; no fallback or inferred qualification is used.

## Implemented

- Swift, Python, and Rust Full-profile adapters consume provider handshake results and require TLS 1.3, mutual authentication, an isolated ACP trust store, exact peer certificate policy success, local credential selection, peer SAN extraction, active revocation state, disabled 0-RTT, disabled resumption, and a 32-byte exporter.
- All SDKs implement the frozen HELLO semantic projection and exporter context. Node/protocol/auth maps are closed, capability entries project to exactly `id` and `version`, array order is preserved, `auth.channel_binding` is excluded from its own context, and the shared frozen vector agrees byte-for-byte.
- Exporter output is compared in constant time with the HELLO channel binding before `TransportEvidence` is admitted.
- Python session integration now requires verified `TransportEvidence` for `aurora_trust`, binds the complete HELLO identity tuple and `aurora-trust` capability version, stores an immutable authenticated principal, and never treats a claimed node ID or discovery identity as authentication.
- Existing Swift and Rust admission paths continue to require verified evidence and compare node, domain, credential, key, binding, mode, and capability version exactly.
- Lightweight parsing enforces the 1..2048-byte credential preface and active compact-credential evidence. Finished verification is HMAC-SHA-256, constant-time, bounded, and tied to provider exporter material. No new cryptographic construction was introduced.
- Authentication failure, exporter mismatch, revocation, expiry, stripped fields, identity mismatch, 0-RTT, and resumption fail closed without plaintext or `trusted_lan` fallback.

## Review findings fixed

1. The initial HELLO projector preserved unknown fields inside capability entries. Every SDK now projects each entry to exactly `id` and `version` while retaining received order.
2. Python's legacy session path accepted a nonempty transport node-id string as sufficient for `aurora_trust`. It now requires typed verified transport evidence and calls the frozen HELLO admission boundary.
3. Local Python HELLO construction could diverge from the selected authentication mode. It now rejects absent or mismatched Aurora Trust auth material before transmission.
4. Lightweight Finished verification and strict preface bounds were made explicit in all SDKs.

## Verification

The complete regression/interoperability gate passed twice from the final tree:

| Gate | Run 1 | Run 2 |
|---|---:|---:|
| Registry | 109 messages | 109 messages |
| Frozen protocol vectors | 109 | 109 |
| Security vectors | 17 sets / 31 artifacts | 17 sets / 31 artifacts |
| Python | 209 passed / 82.71% coverage | 209 passed / 82.71% coverage |
| Rust | 50 passed; fmt/clippy clean | 50 passed; fmt/clippy clean |
| Swift | 97 passed | 97 passed |
| WebSocket HELLO and Remote | PASS | PASS |
| Rust-Swift framed session | PASS | PASS |
| Python-Rust framed hello/session/remote/negative | PASS | PASS |
| Python-Swift framed hello/session/remote/negative | PASS | PASS |
| Python/Rust/Swift enrollment | PASS | PASS |

The frozen HELLO exporter vector is independently consumed by Swift, Python, and Rust tests. Pairwise equality therefore has a single byte-exact oracle rather than SDK-specific expected values.

## Provider/platform qualification

The existing Botan 3.13.0 macOS arm64 evidence contains 16 mandatory PASS results, including TLS 1.3 mutual authentication, verified peer evidence, equal 32-byte exporters, no tickets/resumption/0-RTT, revocation integration, and redaction. `provider_crypto_qualified` and the `macos-arm64` adapter are true.

Python 3.14's standard `ssl` API on this host does not expose TLS exporter material. Native Swift Network/Security and Rust TLS adapters are not linked in this repository. Per the frozen rule, they remain unqualified rather than substituting a fabricated binding. The approved Botan adapter requires product-language bindings before live Swift Full ↔ Python Full, Swift Full ↔ Rust Full, and Python Full ↔ Rust Full sessions can be claimed.

## Exit gate

- PASS: no discovery or HELLO claim creates an authenticated principal without verified transport evidence.
- PASS: shared Full and Lightweight verification, HELLO binding, downgrade, revocation, and reconnect policy boundaries.
- BLOCKED: live product-language Full-profile pair qualification, pending production Botan/native adapter bindings with exporter access.

M6 must not interpret this platform-adapter blocker as permission to relax authentication or enable fallback.
