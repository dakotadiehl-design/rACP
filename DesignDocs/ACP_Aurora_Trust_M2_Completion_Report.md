# Aurora Trust M2 Completion Report

**Milestone:** M2 — Shared models and security boundaries

**Starting commit:** `f2c2429dae598b3965d4d5fe54d2dd6b2812f12a`

**Host:** macOS arm64

**Status:** Complete for host-available software requirements; M3 authorized

## Implemented requirements

- Added strongly typed trust-domain, security-node, enrollment, attempt, credential, and identity-key identifiers in Swift, Python, and Rust.
- Added canonical authentication/profile, suite, credential, enrollment, storage, clock, capability-version, and stable error models.
- Extended immutable principals and transport evidence with an explicit Full/Lightweight profile distinction. Trusted-LAN admission remains unauthenticated.
- Added deterministic canonical enrollment-context, transcript, SHA-256 ID, permission digest, RFC 5869 key schedule, base64url, and channel-binding helpers.
- Added narrow provider boundaries for cryptography, SPAKE2+, AEAD, randomness, signing handles, identity creation, validation, clocks/checkpoints, identity storage, authority, enrollment/authorization policy, audit, and revocation.
- Added opaque secret containers with redacted diagnostic output, no ordinary serialization, explicit scoped access, and best-effort memory clearing.
- Added explicit hardened/migration downgrade policies. A stronger-authentication failure cannot fall back to trusted LAN.
- Added deterministic randomness, clock, identity-store, audit, and vector fixtures exclusively in test targets/modules.
- Added the non-networking Rust `acp-security` crate and preserved Rust 1.75 compatibility.

## Tests added

- Swift frozen context/transcript/key-schedule/permission vectors, base64url rejection, secret redaction, and downgrade tests.
- Python byte-for-byte vector/ID parity, normalization mutations, binding comparison, secret serialization/log scanning, and downgrade tests.
- Rust frozen context/key-schedule/permission vectors, bounded deterministic-provider tests, secret type constraints, and downgrade tests.

## Security review and fixes

- Corrected an initial HKDF implementation to use the frozen exact `ACP enrollment <label> v1` UTF-8 info strings.
- Removed deterministic provider implementations from production Python code and placed all deterministic implementations in test-only modules/targets.
- Removed caller-provided labels from secret diagnostic representations so labels cannot become a secondary disclosure channel.
- Added explicit Full/Lightweight profile evidence rather than inferring authentication strength from a claimed HELLO role or capability.
- Preserved immutable evidence/principal data and kept unverified HELLO fields out of authenticated principal construction.
- Fixed repository-wide formatting/lint drift exposed by the mandatory gate and documented the existing registry admission argument exception rather than suppressing Clippy globally.

## Regression evidence

Two complete passes were executed after fixes.

| Gate | Pass 1 | Pass 2 |
|---|---:|---:|
| Registry | 109 messages PASS | 109 messages PASS |
| Frozen standard vectors | 109 PASS | 109 PASS |
| Ruff | PASS after blocker fix | PASS |
| mypy | 32 modules PASS | 32 modules PASS |
| Python | 171 PASS, 81.85% | 171 PASS, 81.89% |
| Swift | 82 PASS | 82 PASS |
| Rust workspace | 35 PASS | 35 PASS on Rust 1.75 |
| Rust fmt / Clippy `-D warnings` | PASS | PASS |
| WebSocket HELLO / Remote interop | PASS / PASS | PASS / PASS |
| Rust↔Swift framed hello/session/remote/negative, JSON+CBOR | PASS | PASS |
| `git diff --check` | PASS | PASS |

The Botan 3.13.0 provider baseline was also rerun twice: all 16 mandatory probes pass, `provider_crypto_qualified=true`, and the macOS arm64 adapter passes. The aggregate `qualified` value correctly remains false because unavailable Linux, Windows, macOS x86_64, physical iOS, and Raspberry Pi adapters remain `NOT_RUN`.

## Deferred platform evidence

- Linux arm64/x86_64, Windows x86_64, macOS x86_64, Raspberry Pi arm64, and physical iOS execution are unavailable on this host.
- iOS Simulator evidence remains the previously recorded M1 qualification; a simulator does not qualify a physical device or Secure Enclave.
- Pico-class hardware-in-the-loop remains required before Lightweight production qualification.
- These platform gaps do not block M3 host-available software development and are not represented as PASS.

## Residual risks

- Swift and Python can provide best-effort clearing but their runtimes may retain secret copies; production adapters must keep private keys behind non-exporting signing interfaces.
- Provider traits are intentionally interfaces at M2. Concrete enrollment, credential, transport, and storage behavior belongs to M3–M5 and must pass their own milestone gates.
- Independent release security review remains mandatory before show-critical release.

## Exit decision

The M2 exit gate is satisfied: all three SDKs match frozen context, transcript, hash, ID, permission, and key-schedule values; API boundaries are coherent; secret diagnostics are redacted; downgrade tests pass; and M1 regressions remain green. Proceed to M3.
