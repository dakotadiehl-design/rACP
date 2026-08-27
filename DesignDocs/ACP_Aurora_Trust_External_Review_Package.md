# ACP Aurora Trust External Review Package

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

Date prepared: 2026-08-26

## Reviewer mission

Assess the frozen Aurora Trust profile and its Swift, Python, and Rust implementation for cryptographic correctness, authentication/authorization separation, downgrade resistance, lifecycle safety, parser robustness, secret handling, and operational fitness. Report findings by severity and explicitly state whether show-critical deployment is approved.

This package is preparation only. No external review or approval is claimed.

## Normative inputs

- `docs/SECURITY.md` — frozen wire/security profile
- `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`
- `DesignDocs/ACP_Aurora_Trust_Implementation_Plan.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review_Freeze211.md`
- `vectors/security/manifest.json` and the hash-pinned corpus below it
- `registry/messages.yaml`, `schemas/`, and generated protocol vectors

## Architecture and trust boundaries

Pairing establishes a persistent device identity. Subsequent sessions authenticate proof of the corresponding private key. Device identity remains separate from human/operator assignment. Authentication creates a principal; it does not grant show control. Effective permissions are the exact intersection of credential constraints, local policy, advertised ACP capabilities, and operational safety policy.

Full profile uses the frozen Botan 3.13.0/provider and TLS 1.3/X.509/exporter contract. Lightweight is a distinct compact-credential and bounded framing profile. Private keys remain behind provider/storage interfaces. Credential installation and rotation are journaled transactions. Revocation and migration policy are enforced at live product boundaries.

## Threat model checklist

Review spoofed discovery/node IDs, hostile LAN MITM, replay, downgrade, identity collision, credential substitution, stripped metadata, exporter mismatch, revocation rollback, time failure, malformed messages, resource exhaustion, concurrent policy/lifecycle races, filesystem replacement, crash/power loss, log/PCAP disclosure, stolen devices, authority compromise, and recovery procedures.

## Provider and platform status

- Botan Full-profile crypto contract: 3.13.0 exact.
- macOS arm64 adapter: PASS in the recorded probe result.
- iOS Simulator functional/policy evidence: PASS where documented; this is not physical-device qualification.
- Physical iOS/Secure Enclave and Pico-class Lightweight HIL: DEFERRED.
- Unexecuted Linux/Windows/Pi and other adapter claims: NOT RUN.
- Exact Rust/Python dependencies and licenses: `scripts/check_security_dependencies.py`.
- Current vulnerability databases: CI-only `dependency-advisories` job; reviewer should require a fresh passing run.

## Evidence map

Use `DesignDocs/ACP_Aurora_Trust_Conformance_Matrix.json` as the machine-readable index and `DesignDocs/ACP_Aurora_Trust_Final_Internal_Security_Review.md` for internal findings and residual risk. M3–M7 completion reports provide milestone-specific evidence. Probe results live in `tools/security-probe/results/`.

## Reproduction commands

From the repository root:

```sh
python3 scripts/check_registry.py
python3 scripts/freeze_vectors.py
python3 scripts/security_vectors.py
python3 -m ruff check --config python/pyproject.toml python scripts
(cd python && python3 -m mypy src/acp && python3 -m pytest tests)
PYTHONPATH=python/src python3 scripts/security_fuzz_smoke.py
python3 scripts/check_security_dependencies.py
cargo test --manifest-path rust/Cargo.toml
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
(cd rust && cargo fmt -- --check)
swift test
python3 tests/interop/test_security_enrollment.py --sdk all
```

Run the remaining interop commands from `.github/workflows/ci.yml` and applicable platform/hardware probe instructions. Two clean complete runs are expected for release evidence.

## Required reviewer output

Provide scope and commit hash, reviewer identity and independence statement, environment/provider versions, reproduction results, findings with severity and exploit narrative, cross-language/profile discrepancies, residual-risk assessment, and an explicit `GO`, `CONDITIONAL GO`, or `NO-GO`. All Critical and High findings must be resolved and independently confirmed before show-critical release.
