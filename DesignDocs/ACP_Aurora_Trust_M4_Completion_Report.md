# ACP Aurora Trust M4 Completion Report

Date: 2026-08-25

## Result

Milestone 4 is complete. The implementation provides credential authority boundaries, frozen Full-profile policy evidence validation, Lightweight compact credentials, transactional identity storage, renewal and rotation, signed revocation state, offline freshness, hardened active-session revocation decisions, secure-time rollback handling, and trust-only reset behavior.

## Implemented

- Swift, Python, and Rust share the frozen credential identifiers, deterministic-CBOR signature inputs, exact trust-domain/node/key bindings, validity checks, proof-of-possession requirements, and closed extension policy.
- Authority keys remain behind signing handles. Import/recovery validates the exact authority identity tuple, and renewal preserves node identity unless an explicit distinct key rotation is requested.
- The ordered X.509 validation boundary covers DER, isolated ACP chain, signature, SAN/domain/node bindings, EKU, KU, CA constraints, validity, revocation, credential and key IDs, possession, local policy, and unknown critical extensions.
- Swift uses a device-only Apple Keychain backend with update-or-add duplicate handling and a transactional checksummed two-slot store. Secure Enclave use remains capability-gated; no hardware-backed qualification is claimed from simulator/macOS testing.
- Python uses a mode-0700 journal directory and mode-0600 checksummed generation files with atomic replacement, file and directory fsync, recovery, previous-good retention, trust-only reset, and durable monotonic secure-time checkpoints.
- Rust provides restricted atomic host-file primitives and a checksummed bounded two-slot model with explicit generations, staged validation, power-failure-safe activation, previous-good recovery, and trust-only reset.
- Rotation follows prepare, credential acquisition, validation/staging, possession proof, activation, previous-good retention, and retirement. Failure injection covers every specified persistence boundary and always recovers either the old or new complete generation.
- Revocation accepts only canonical signed snapshots/deltas for the correct domain and increasing epoch. It rejects rollback, invalid delta bases, malformed/duplicate/unsorted entries, overflow, stale offline state, and revoked credentials on new sessions. Hardened active-session policy terminates by default; grace requires an explicit audited policy.
- Clock acceptance is limited to trusted wall time, authenticated checkpoints, or authenticated bounded commissioner time and rejects rollback or untrusted discovery/HELLO time.
- Reset and unenrollment mutate trust state only; show assets, layouts, and Remote caches are outside these adapters.

The production TLS transport wiring that consumes X.509 evidence and performs active-session teardown belongs to M5. M4 supplies the validated evidence and revocation decision boundaries and does not claim M5 transport completion.

## Review and remediation

The post-implementation review corrected:

- missing compact-credential validity enforcement in Swift and Rust;
- delta omission/closed-map rules and prospective revocation bounds;
- corrupt-generation recovery behavior;
- Rust host directory/file permissions;
- offline revocation freshness and the hardened active-session default;
- durable Python rollback-checkpoint persistence.

`git diff --check`, Ruff, mypy, Rust formatting, and clippy are clean.

## Verification

The complete regression/interoperability gate passed twice from the final tree:

| Gate | Run 1 | Run 2 |
|---|---:|---:|
| Registry | 109 messages | 109 messages |
| Frozen protocol vectors | 109 | 109 |
| Security vectors | 17 sets / 31 artifacts | 17 sets / 31 artifacts |
| Python | 196 passed / 82.71% coverage | 196 passed / 82.71% coverage |
| Rust | 47 passed; fmt/clippy clean | 47 passed; fmt/clippy clean |
| Swift | 94 passed | 94 passed |
| WebSocket HELLO and Remote | PASS | PASS |
| Rust-Swift framed session | PASS | PASS |
| Python-Rust framed hello/session/remote/negative | PASS | PASS |
| Python-Swift framed hello/session/remote/negative | PASS | PASS |
| Python/Rust/Swift enrollment | PASS | PASS |

## Exit gate

PASS. Recovery selects the previous complete valid identity or the new complete valid identity and never selects a staged, corrupt, or partial identity.
