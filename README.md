# Aurora Communications Protocol (ACP)

Language-neutral communications substrate for the Aurora family: Prism, Conductor, Lyric, Bridge, tools, and future nodes.

ACP carries Aurora-level intent, state, health, configuration, synchronization, and control. Art-Net, sACN, DMX, MIDI, OSC, and vendor APIs stay at the edges.

This repository is the **protocol foundation**. It is not a product adapter. Nothing here drives DMX, talks to a mixer, or replaces Prism’s engine.

Baseline: **ACP v1.2**. Spec: `Aurora_Communications_Protocol_Handoff_Spec_v1.2.pdf`.

## Non-negotiables

- Never infer that a command was applied because it was transmitted.
- Never mark device state `confirmed` from a successful socket write, MIDI send, or driver transmit.
- Safety-critical control never depends on multicast.
- Unknown optional fields are ignored on typed decode (not preserved through re-encode).
- Blackout is idempotent, acknowledged, logged, state-reflected, and not cleared by reconnect.
- The protocol runtime has no Internet dependency.

## Layout

```
schema/     JSON Schema, constants, message registry, semantic invariants
vectors/    Frozen golden JSON/CBOR (never silently rewritten)
docs/       Normative markdown (wire profile, state machines, catalogs)
swift/      SwiftPM package (Prism / Conductor / Apple Lyric)
python/     Reference models, codec, CLI, simulators
rust/       Bridge-oriented crates (acp-model has no Tokio)
tools/      acp-inspect, acp-sim, Wireshark dissector
tests/      Live cross-language interop
scripts/    Registry checks, vector freeze, dissector install
```

## Build

Requires Python 3.11+, a recent stable Rust toolchain, and Swift 5.9+ (macOS or a Swift-capable runner).

```bash
# Python
python3 -m pip install -e './python[dev]'
python3 -m ruff check --config python/pyproject.toml python scripts
(cd python && python3 -m mypy src/acp)
(cd python && python3 -m pytest tests --cov=acp --cov-fail-under=70)

# Rust
cargo test --manifest-path rust/Cargo.toml

# Swift
swift test --package-path swift

# Schema / registry (once PR1 lands)
python3 scripts/check_registry.py
```

CI may fetch toolchains and crates on a fresh runner. That is not a protocol Internet dependency.

## Adding a message

See [`docs/ADDING_A_MESSAGE.md`](docs/ADDING_A_MESSAGE.md). Short version: schema → registry row → golden vectors → decoder registration. Do not overload an existing type.

## What is here

| Layer | Python | Rust | Swift |
|---|---|---|---|
| Models | yes | `acp-model` | `ACPModel` |
| JSON + ACP-CDE-1.2 | reference encoder | bit-identical golden vectors | bit-identical golden vectors |
| Session | inbound authz, QoS scheduler, acks | Tokio engine (handshake, admit, sequence) | actor engine (handshake, admit, sequence) |
| Discovery framing | encode/decode + size limit | — | — |
| Bridge / config / blackout | yes | — | — |
| Resource transfer | chunk + SHA-256 + activate | — | — |
| Lyric assignment | resolver | — | — |
| CLI | `python3 -m acp inspect\|sim` | — | — |

- Schema + 75-type `schema/registry.json` + semantic invariants
- Frozen golden vectors in `vectors/` (one per message family plus core types)
- Shared malformed CBOR corpus in `vectors/malformed/`
- Localhost Python WebSocket HELLO: `python3 tests/interop/test_ws_hello.py` (cross-language live interop is follow-on)
- Wireshark Lua dissector: `tools/wireshark/`

Product adapters (Prism `ControlActionRouter`, Conductor UI, Lyric presentation, Bridge firmware I/O) are **not** in this repo.

## Tests

```bash
python3 scripts/check_registry.py
python3 scripts/freeze_vectors.py          # verify pinned CBOR
python3 -m ruff check --config python/pyproject.toml python scripts
(cd python && python3 -m mypy src/acp)
(cd python && python3 -m pytest tests --cov=acp --cov-fail-under=70)
python3 tests/interop/test_ws_hello.py     # Python loopback, not cross-language
cargo test --manifest-path rust/Cargo.toml
(cd rust && cargo fmt -- --check && cargo clippy -- -D warnings)
swift test --package-path swift
```
