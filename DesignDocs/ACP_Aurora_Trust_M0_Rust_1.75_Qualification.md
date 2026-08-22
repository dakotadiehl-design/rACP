# ACP Aurora Trust M0 Rust 1.75 Qualification

**Date:** 2026-08-21  
**Scope:** Existing ACP Rust workspace only  
**Result:** PASS for the current production graph; future M1 Trust/provider features are not yet present and are not qualified

## Toolchain

- `rustc 1.75.0 (82e1608df 2023-12-21)`
- `cargo 1.75.0 (1d8b05cdd 2023-11-20)`
- Workspace edition: Rust 2021
- Lockfile format: version 3

## Reconciliation

The unconstrained `uuid = "1"` dependency resolved to `uuid 1.24.1`. That
release declares Rust 1.85 and selects `getrandom 0.4.3`, which also declares
Rust 1.85 and uses edition 2024. Cargo 1.75 cannot parse the latter manifest.

Dependency path and responsible feature:

```text
acp-session 1.2.0
└── uuid 1.24.1 (feature: v4)
    └── getrandom 0.4.3 (feature: sys_rng)
```

The workspace now pins `uuid = "=1.18.1"`, the newest release directly tested
as compatible during this qualification. Its resolved `getrandom 0.3.4` graph
builds and tests on Rust 1.75. The pin preserves UUID v4 behavior and does not
change ACP wire semantics. It does mean UUID updates require an intentional
MSRV requalification instead of an automatic semver-compatible lock refresh.
No Rust MSRV increase is recommended at M0.

## Dependency and feature evidence

`rust/Cargo.lock` is the normative resolved graph. `cargo tree --locked` and
`cargo tree --locked -e features` were reviewed, including transitive, build,
and target-specific dependencies. The current workspace exposes no optional
Cargo features. Therefore the production feature matrix is:

| Combination | Result |
|---|---|
| Workspace default features | PASS |
| Workspace all targets | PASS |
| `acp-model` default/no-default-features | PASS |
| `acp-codec` default/no-default-features | PASS |
| `acp-session` default/no-default-features | PASS |
| Full/Trust/provider/TLS/X.509 feature combinations | NOT_RUN — no such production Rust features exist before M1 |
| Linux x86_64 native | NOT_RUN on macOS host; permanent CI runs Ubuntu x86_64 |
| Linux/Raspberry Pi arm64 cross-target | NOT_RUN — target/linker not installed and no production Trust adapter exists |

The `no-default-features` checks are meaningful as manifest/API drift guards,
but currently resolve identically because none of the three ACP crates defines
default or optional features.

## Commands and result

The following passed with the exact toolchain and locked graph:

```text
cargo +1.75.0 check --workspace --locked
cargo +1.75.0 test --workspace --locked
cargo +1.75.0 check --workspace --all-targets --locked
cargo +1.75.0 check -p acp-model --no-default-features --locked
cargo +1.75.0 check -p acp-codec --no-default-features --locked
cargo +1.75.0 check -p acp-session --no-default-features --locked
```

Unit result: 25 passed; documentation tests passed. A permanent `rust-msrv` CI
job repeats the exact-version workspace check, test, and all-targets check.

## Qualification boundary

This PASS proves the current ACP Rust workspace and dependency graph. It does
not pre-approve future Botan bindings, TLS/X.509 adapters, Lightweight support,
or any M1 security feature. Each added production feature combination must be
added to the MSRV matrix and CI before it can ship.
