# ACP Workbench Code Review

## Scope

Reviewed the engine, connection lifecycle, Remote/Prism profile, surface transfer, authoritative state model, scenario parser/runner, reports, transcripts, CLI, GUI controller, safety gates, packaging, and tests.

The Prism executable was not launched or contacted. Integration tests use linked in-process ACP transports and the repository's reference `RemoteAuthority` under a test Conductor identity.

## Findings fixed

- Bound the reference authority and ACP session to the same authenticated node identity.
- Required full layout/snapshot/readiness synchronization before declaring the Workbench connection ready.
- Added production-default chunked surface transfer and activation in addition to inline compatibility surfaces.
- Separated terminal command disposition from target-published authoritative state.
- Correlated ACK bookkeeping through the request message ID instead of relying on an optional result field.
- Prevented scenarios from matching an unrelated earlier command acknowledgement.
- Allowed authoritative publication before or after the ACK while still requiring it to occur after intent transmission.
- Populated individual confirmed control view state from initial control snapshots.
- Added best-effort momentary END on graceful shutdown while retaining authority-owned disconnect fail-safe behavior.
- Preserved failed connection state during failure cleanup.
- Added non-loopback and safety-sensitive GUI confirmations.
- Added typed GUI behavior for buttons, toggles, sliders/encoders, and timed momentaries.
- Added framed TCP and TLS/mTLS connection configuration.
- Removed the production Workbench dependency on ACP's test helper capability list.
- Made scenario top-level and per-step parsing reject unknown fields.
- Added stable CLI error mapping, direct decoded-envelope sending, reports, and scenario execution.
- Added transcript secret redaction and immediate flushing.

## Verification

- Ruff: clean for all Workbench source and tests.
- mypy: clean for all Workbench source.
- Workbench tests: 17 passed plus 3 subtests.
- Workbench core/scenario coverage: 80.35% (80% gate).
- Combined ACP Python and Workbench regression: 153 passed plus 3 subtests.
- ACP registry validation: 93 messages valid.
- Scenario validation: all bundled scenarios valid.
- Python bytecode compilation: clean.
- `git diff --check`: clean.

## Environment-limited checks

- PySide6 is not installed, so the GUI was statically checked and bytecode-compiled but not launched.
- PyYAML is not installed; bundled scenarios are JSON and were fully exercised. YAML produces an actionable optional-dependency error.
- The host Python lacks importable `setuptools`, so a wheel build could not start. The `pyproject.toml` uses the standard setuptools backend, and source execution/package metadata tests otherwise pass.

## Remaining product-dependent work

The Workbench mechanism supports every requested category through dynamically published Remote controls and generic ACP state/health resources. Project-specific scenarios for named Global Looks, stop-effects, restart-section, automatic-progression hold, and custom Busk controls require the stable IDs and surface published by Prism's dedicated test project. They should be added without changes to the engine.

No known release-blocking code defects remain within the tested headless scope.

