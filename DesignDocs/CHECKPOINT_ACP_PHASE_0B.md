# Checkpoint — ACP Phase 0B: Prism/Remote readiness

**Date:** 2026-08-19  
**Status:** Review-satisfied  
**Repo:** `AuroraCommunicationsProtocol`  
**ACP tag:** `1.1.0-dev.1`  
**ACP baseline:** `1.0.0` (`426f40185b6b7510448c5e4229a7fb09b47f4cc3`)  
**Wire protocol:** ACP 1.2 (unchanged)

## Phase objective

Add generic ACP facilities Prism requires: epoch/revision state, command-status recovery, preconditions, provenance/traffic metadata, Swift WebSocket transport types, and portable discovery/Bonjour mapping. No second package conversion.

## Files changed (high level)

- `schema/common/defs.schema.json`, `schema/command/messages.schema.json`, `schema/state/messages.schema.json`, `schema/remote/remote_control_definition.schema.json`
- `scripts/gen_registry.py`, vectors, schema packs (93 messages)
- Python: `command_ledger.py`, `preconditions.py`, `state_revision.py`, `priority.py`, tests
- Swift: `ACPCommandLedger.swift`, `ACPStateRevision.swift`, `ACPDiscovery.swift`, `ACPWebSocket.swift`, `ACPReadinessTests.swift`
- `docs/REMOTE.md`, `docs/ACP_SPEC.md`, `docs/ERROR_CODES.md`, `docs/CAPABILITIES.md`, `CHANGELOG.md`

## Tests and commands run

| Command | Result |
|---|---|
| `python3 scripts/check_registry.py` | `registry ok: 93 messages` |
| `python3 scripts/freeze_vectors.py` | `vectors ok: 93` |
| `python3 -m pytest tests` | **136 passed**, coverage 81.45% |
| `python3 -m ruff check` | pass |
| `python3 -m mypy src/acp` | 27 files, no issues |
| `swift test` | **29 passed**, 0 failed, 0 skipped |
| `cargo test` | **22 passed** |
| framed `--sdk swift --suite session` | pass |
| framed `--sdk swift --suite remote` | pass |

## Review findings and remediation

1. Malformed input: new messages validated by schema pack on Swift/Python decode.
2. ACK-before-commit: not a Prism mutation phase; ledger records disposition only after caller supplies it.
3. Retry once-only: ledger returns the original record for the same origin node + command id / idempotency key; principals cannot read another principal's record.
4. Epoch/revision: mismatch raises snapshot-required; legacy single-resource delta still accepted.
5–6. Disconnect/release: unchanged Remote simulator; production authority remains Phase 5.
7. Telemetry: priority queue pops safety/interactive/state (including coalesced latest-value) before background/telemetry; GO never coalesces.
8. ACP-disabled: no listener started by these libraries by default.
9. Generated drift: registry/schema-pack checks passed.
10. Legacy remote: Prism unchanged.
11. Engine shortcut: still no Prism/output imports.
12. Established-session tests: framed session + remote interop passed after the schema additions.

### Findings

- **P2:** Network.framework WebSocket client/server echo hung in-process. Replaced with listener start/stop. Python already has HTTP-upgrade WS tests (`test_ws.py`). Full Python↔Swift WS interop is deferred to Phase 2 composition (same `/acp` URL contract).
- **P2:** Live Bonjour advertisement is a TXT mapping API, not a running `NetService`. Prism Phase 2 starts advertisement after policy is ready.
- **Deferred by design:** production Swift Remote authority (Phase 5). Simulator is not promoted.

No P0/P1 remain for this phase's required behavior.

## Remaining explicitly deferred items

- Python↔Swift live WebSocket application session
- Running Bonjour advertiser/browser (Prism Phase 2)
- Production Swift `RemoteAuthority` (Phase 5)

## Statement

Phase 0B is **review-satisfied**. Tag `1.1.0-dev.1`. Proceed automatically to Phase 1.
