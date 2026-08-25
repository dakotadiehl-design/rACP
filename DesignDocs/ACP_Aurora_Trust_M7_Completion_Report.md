# ACP Aurora Trust M7 Implementation Report

Date: 2026-08-25
Starting commit: `ccfff2e` (`Aurora Trust M6 authorization policy`)

## Result

M7 offline operations, migration enforcement, safe diagnostics, audit verification, and operator documentation are implemented. The existing M5 live product-language TLS exporter-adapter qualification blocker remains unchanged and is not hidden by M7 tooling.

## Implemented

- The `acp-security` Python CLI supports trust-domain create/import, enrollment open/candidate/commissioner flows, trusted-node list and inspection, renewal, rotation, revocation, revocation-state inspection, reset/unenrollment, recovery validation, audit verification, diagnostics, and migration status/change.
- Bootstrap input is accepted only through a hidden interactive prompt or an owner-only protected file. No secret command-line option exists.
- CLI normal/JSON output uses recursive security redaction. Tests scan for bootstrap, PAKE, derived/private key, approval, and credential material.
- Offline operational metadata is atomically replaced, fsynced, mode `0600`, and hash-chain audited. Tampered audit history blocks subsequent mutation.
- Revocation history is append-only. Revoked or unenrolled identities cannot be recovered, renewed, or rotated back into active status.
- Swift, Python, and Rust implement the four explicit migration stages. `trusted_lan` requires explicit enablement, never grants control, failed stronger authentication never falls back, and Enforce rejects unauthenticated connections.
- Migration decisions keep authentication and authorization separate; sensitive control requires both.
- Diagnostics expose only public security mode/state, trust-domain IDs, revocation epoch, policy revision, and migration state.
- Wireshark exposes safe revocation state and policy revision in addition to existing allowlisted public identifiers; secret-bearing payload fields remain undisclosed.
- The offline operations runbook covers commissioning, headless enrollment, backup/recovery, renewal/rotation/revocation, clock failure, reset, reassignment, incidents, lost/stolen nodes, compromise, migration, audit verification, and production evidence.

## Review findings fixed

1. M6 Remote hosts initially accepted stale caller-supplied policy snapshots. All SDK production boundaries now rebind to current policy-store permissions and revision per invocation.
2. Initial operational recovery and renewal paths could reactivate revoked identities. Revocation is now irreversible for the affected credential and retained in append-only operational history.
3. Initial migration logic treated authentication as authorization. It now requires an independent authorization result before sensitive control is permitted.
4. Conflicting trust-domain imports and duplicate commissioner node identities now fail closed.
5. Audit-chain tampering is now checked before every state-changing transaction, not only by the explicit verification command.

## Optional packaging

The frozen contract does not completely specify QR visual semantics or a signed portable enrollment-package format. M7 implements protected text/file bootstrap input and public domain-package import only, and deliberately does not invent the underspecified mechanisms.

## Verification

The complete final-tree gate passed twice:

| Gate | Run 1 | Run 2 |
|---|---:|---:|
| Registry | 109 messages | 109 messages |
| Frozen protocol vectors | 109 | 109 |
| Security vectors | 17 sets / 31 artifacts | 17 sets / 31 artifacts |
| Python | 217 passed / 82.48% coverage | 217 passed / 82.48% coverage |
| Python Ruff / mypy | PASS / 38 files | PASS / 38 files |
| Rust | 55 passed; fmt/clippy clean | 55 passed; fmt/clippy clean |
| Swift | 102 passed | 102 passed |
| WebSocket HELLO and Remote | PASS | PASS |
| Python/Rust/Swift enrollment | PASS | PASS |
| Python-Rust framed hello/session/remote/negative | PASS | PASS |
| Python-Swift framed hello/session/remote/negative | PASS | PASS |
| Rust-Swift framed session | PASS | PASS |

## Exit gate

PASS on available host/simulator environments: create/import domain metadata, enroll and persist node identity metadata, use the existing authenticated transport and authorization boundaries, renew, rotate, revoke, recover retained valid state, and verify audit history offline.

Production Remote remains fail-closed without a current authenticated and authorized principal. Platform qualification, hardware qualification, and final external review remain separate future evidence gates.
