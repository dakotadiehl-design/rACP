# ACP Aurora Trust M6 Implementation Report

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

Date: 2026-08-25
Starting commit: `8a91476` (`Fix M5 transport evidence binding`)

## Result

M6 authorization and production Remote gating are implemented across Swift, Python, and Rust. Authorization is fail-closed and derived locally from authenticated device identity, credential constraints, local policy, negotiated capability permissions, operational safety policy, and—only where explicitly required—an authenticated operator assignment.

## Implemented

- Immutable device and operator identity types keep cryptographic device trust separate from the current human assignment.
- A single authorization decision boundary in each SDK computes the permission intersection, records policy revision, safety state, audit correlation ID, effective permissions, and the immutable authenticated principal.
- Unknown operations and operations without an explicit permission mapping are denied.
- The canonical registry supplies message permissions; Remote control, macro, and navigation operations have explicit security-boundary mappings where the protocol registry intentionally carries no authorization permission.
- Authorization policy stores increment revisions on replacement and require session termination when revalidation removes a previously granted permission.
- Swift and Rust production Remote wrappers require `remote.control.invoke`, derive authority identity from the authenticated principal, and ignore client-claimed node/role authority. Unauthenticated viewing is disabled by default and only available through an explicit host option.
- Python exposes the same guarded handler boundary and explicit unauthenticated-view option.
- Credential/trust changes do not mutate or delete cached Remote layouts or show assets.

## Review findings fixed

1. Python's initial identity projection passed optional fields to a non-optional device identity after a runtime aggregate check. It now narrows every identity component explicitly and passes strict static analysis.
2. The first Rust implementation contained the shared authorization model but no canonical registry resolver or authenticated Remote integration. `acp-session` now resolves registry permissions through the shared boundary and exposes an authenticated Remote host keyed by verified device identity.
3. Swift policy revision increment could trap at `UInt64.max`. It now saturates, preserving fail-closed availability under pathological revision exhaustion.
4. Remote negative tests were tightened so unauthenticated denial is proven with the required Remote permission present in every non-identity input; the denial cannot be attributed to an accidentally missing permission.
5. A later full review found that Remote hosts trusted caller-supplied local-policy permissions and revisions. Swift, Python, and Rust hosts now rebind every invocation to the current policy store, so stale contexts cannot retain removed authority.

## Exit-gate evidence

The complete regression/interoperability gate passed twice from the final tree:

| Gate | Run 1 | Run 2 |
|---|---:|---:|
| Registry | 109 messages | 109 messages |
| Frozen protocol vectors | 109 | 109 |
| Security vectors | 17 sets / 31 artifacts | 17 sets / 31 artifacts |
| Python | 212 passed / 82.61% coverage | 212 passed / 82.58% coverage |
| Python Ruff / mypy | PASS / 36 files | PASS / 36 files |
| Rust | 54 passed; fmt/clippy clean | 54 passed; fmt/clippy clean |
| Swift | 101 passed | 101 passed |
| WebSocket HELLO and Remote | PASS | PASS |
| Rust-Swift framed session | PASS | PASS |
| Python-Rust framed hello/session/remote/negative | PASS | PASS |
| Python-Swift framed hello/session/remote/negative | PASS | PASS |
| Python/Rust/Swift enrollment | PASS | PASS |

M5's existing platform-adapter/exporter qualification blocker remains unchanged. M6 does not weaken authentication, authorize claimed identities, or introduce a downgrade path around that blocker.
