# Checkpoint — ACP Phase 0A: Freeze AuroraACP 1.0.0

**Date:** 2026-08-19  
**Status:** Review-satisfied  
**Repo:** `AuroraCommunicationsProtocol`  
**ACP tag:** `1.0.0`  
**ACP commit:** `426f40185b6b7510448c5e4229a7fb09b47f4cc3` (package conversion `56c429b6002e6fd2008c5414e5d4032a15ccf5b0`)  
**Prism commit:** unchanged (this phase does not modify Prism)

## Phase objective

Preserve the completed root Swift package and establish a reproducible library baseline **before** new ACP Prism/Remote feature work. No new messages, transports, discovery behavior, or Remote semantics were added in this checkpoint.

## Files changed

The freeze commit records the package conversion and the already-implemented protocol working tree (278 files). Documentation aligned in this checkpoint:

- `CHANGELOG.md` — 1.0.0 release notes; package vs wire version
- `README.md` — tagged baseline `1.0.0`
- `DesignDocs/ACP_Swift_Package_Migration_Report.md` — tag decision
- `CODE_REVIEW.md` — Phase 0A addendum mapping tenth-review findings to 1.0.0 evidence
- this file

Left untracked on purpose: `tools/acp-workbench/` (future workbench plan, not package conversion).

## Tests and commands run

| Command | Result |
|---|---|
| `swift build` | pass |
| `swift test` | **22 passed**, 0 failed, 0 skipped |
| `python3 scripts/check_registry.py` | `registry ok: 91 messages` |
| `python3 scripts/freeze_vectors.py` | `vectors ok: 91` |
| `python3 -m ruff check --config python/pyproject.toml python scripts` | pass |
| `python3 -m mypy src/acp` (from `python/`) | Success: no issues found in 23 source files |
| `python3 -m pytest tests --cov=acp --cov-fail-under=70` | **131 passed**, coverage **81.93%** |
| `cargo test --manifest-path rust/Cargo.toml` | **22 passed** (6+1+15) |
| `cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings` | pass |
| `cargo fmt -- --check` (in `rust/`) | pass |
| `python3 tests/interop/test_framed_cross.py --sdk swift --suite hello` | pass |
| `--sdk swift --suite session` | pass |
| `--sdk swift --suite remote` | pass |
| `--sdk swift --suite negative` | pass |
| `--sdk rust --suite hello` | pass |
| `--sdk rust --suite session` | pass |
| `--sdk rust-swift --suite session` | pass |
| `python3 tests/interop/test_ws_hello.py` | pass |
| `python3 tests/interop/test_ws_remote.py` | pass |
| Dummy Swift package `.package(path:)` `import AuroraACP` | pass (`IMPORT_OK`) |

No required gate was silently skipped. Rust, Python, and Swift toolchains were present.

## Review findings and remediation

### Review questions (Phase 0A scope)

1. Malformed input to Prism semantics — N/A (no Prism change). ACP decode still fail-closes unknown/invalid vectors in Swift tests.
2. ACK before commit — N/A (no Prism mutations).
3. Retry once-only — not yet (Phase 0B command ledger).
4. Epoch/revision — not yet (Phase 0B envelopes).
5–8. Disconnect/release/disable — no new listeners in this phase.
9. Generated drift — `check_registry.py` and `freeze_vectors.py` passed; schema pack copies are drift-checked.
10. Legacy remote — Prism unchanged.
11. ACP-to-engine shortcut — ACP sources still have no Prism/output imports.
12. Established-session tests — **yes**; hello/session/remote/negative interop all passed.

### Findings

- **P2 (docs):** `CODE_REVIEW.md` still claimed P1-1, P1-2, P2-1, and P2-3 were open. The freeze tree already contains fail-closed negotiation, bounded I/O, `--sdk` interop suites, and CI wiring. **Remediation:** Phase 0A addendum in `CODE_REVIEW.md` with evidence table. Remaining open item: **P2-2 payload schema validation on Swift/Rust decode**, assigned to Phase 0B.
- **P3:** `tools/acp-workbench/` exists as an untracked future plan. Deferred; not part of 1.0.0.

No P0 or P1 findings remain for this freeze.

## Remaining explicitly deferred items

All Phase 0B+ work:

- Snapshot/delta `authority_epoch` + `revision` envelopes
- `command.status_request` / `command.status_report` and generic command ledger
- Typed preconditions, availability vs capability, provenance, priority/coalescing
- Generic Swift WebSocket transport
- Portable discovery + Apple Bonjour mapping
- P2-2 per-message payload schema admission in Swift/Rust
- Production Swift Remote authority (do **not** promote `ACPRemoteAuthority`)

## Package version decision

**`1.0.0`** — the root `AuroraACP` product is the stable consumer import (`import AuroraACP`), dummy external packages compile, registry/vectors are frozen, and session fail-closed/bounded-I/O tests pass. This is a **library freeze**, not an ACP wire bump. Subsequent Prism/Remote features tag as `1.1.0-dev.1` (or successor).

## Statement

Phase 0A is **review-satisfied**. Proceed automatically to Phase 0B.
