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
Package.swift   SwiftPM manifest (product AuroraACP)
Sources/        AuroraACP library + acp-framed-hello interop fixture
schema/         JSON Schema, constants, message registry, semantic invariants
vectors/        Frozen golden JSON/CBOR (never silently rewritten)
docs/           Normative markdown (wire profile, state machines, catalogs)
python/         Reference models, codec, CLI, simulators
rust/           Bridge-oriented crates (acp-model has no Tokio)
tools/          acp-inspect, acp-sim, Wireshark dissector
tests/          Swift package tests + live cross-language interop
scripts/        Registry checks, vector freeze, dissector install
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
swift test

# Schema / registry
python3 scripts/check_registry.py
```

CI may fetch toolchains and crates on a fresh runner. That is not a protocol Internet dependency.

## Using AuroraACP

`AuroraACP` is the canonical Swift package for ACP. Prism, Remote, Conductor, and Lyric consume it as a dependency. They must not copy ACP protocol `.swift` files.

**Platforms:** macOS 13+, iOS 16+, Swift 5.9+.

**Import:**

```swift
import AuroraACP
```

### Local package (active development)

In Xcode: File → Add Package Dependencies → Add Local → select this repository root (the folder that contains `Package.swift`). Add the `AuroraACP` library product to the application target.

From another Swift package:

```swift
.package(path: "../AuroraCommunicationsProtocol")
```

then depend on `.product(name: "AuroraACP", package: "AuroraCommunicationsProtocol")`.

### Remote Git package (stable integration)

Add the ACP git repository URL and pin a semantic version tag. Do not pin release branches to a moving `main`.

```swift
.package(url: "https://example.com/AuroraCommunicationsProtocol.git", from: "1.0.0")
```

Replace the URL with the canonical ACP remote when tagging.

### Minimal usage

```swift
import AuroraACP

let (clientTransport, serverTransport) = await acpLinkedTransports()
let client = ACPSession(
    transport: clientTransport,
    local: ACPIdentity(role: "conductor", name: "example"),
    isServer: false
)
let server = ACPSession(
    transport: serverTransport,
    local: ACPIdentity(role: "bridge", name: "example"),
    isServer: true
)
async let serverAck = server.handshake()
_ = try await client.handshake()
_ = try await serverAck
await client.goodbye()
await server.goodbye()
```

### Build and test this package

```bash
swift build
swift test
```

### Versioning

Package version and wire-protocol version are different numbers:

- **AuroraACP 1.0.0** — Swift package release (semver). PATCH = compatible bug fix; MINOR = backward-compatible API addition; MAJOR = breaking public API or protocol compatibility change.
- **ACP 1.2** — version spoken on the network (`acp` field, HELLO negotiation). That remains authoritative for wire compatibility.

Tagged package baseline: **`1.0.0`**. That tag is a library/package freeze, not a wire-protocol bump.

## Adding a message

See [`docs/ADDING_A_MESSAGE.md`](docs/ADDING_A_MESSAGE.md). Short version: schema → registry row → golden vectors → decoder registration. Do not overload an existing type.

## What is here

| Layer | Python | Rust | Swift |
|---|---|---|---|
| Models | yes | `acp-model` | `AuroraACP` |
| JSON + ACP-CDE-1.2 | reference encoder | bit-identical golden vectors | bit-identical golden vectors |
| Session | inbound authz, QoS scheduler, acks | Tokio engine (handshake, admit, sequence) | actor engine (handshake, admit, sequence) |
| Discovery framing | encode/decode + size limit | — | — |
| Bridge / config / blackout | yes | — | — |
| Resource transfer | chunk + SHA-256 + activate | — | — |
| Lyric assignment | resolver | — | — |
| Remote Profile | session-hosted production authority | non-production simulator | non-production simulator |
| Live session transport | WebSocket + framed TCP | framed TCP + loopback | framed TCP + loopback |
| CLI | `python3 -m acp inspect\|sim\|remote` | — | — |

- Schema + 91-type `schema/registry.json` + semantic invariants
- Frozen golden vectors in `vectors/` (one JSON/CBOR pair per registry message)
- Shared malformed CBOR corpus in `vectors/malformed/`
- Localhost Python WebSocket HELLO: `python3 tests/interop/test_ws_hello.py`
- Localhost Python WebSocket Remote hello/sync/commands: `python3 tests/interop/test_ws_remote.py`
- Cross-language framed TCP: `python3 tests/interop/test_framed_cross.py --sdk rust|swift|rust-swift --suite hello|session|remote|negative`
- Coverage matrix: **codec** (all 91 golden vectors plus the invalid-message corpus), **session** (loopback plus framed TCP HELLO, heartbeat, correlated `state.request`/`state.snapshot`, goodbye), **Remote profile** (Python production host; Rust/Swift simulators exchange chunk/activate/invoke over an established session). Rust↔Swift framed session is covered by `--sdk rust-swift`.
- Wireshark Lua dissector: `tools/wireshark/`

Remote Profile (v1.2 profile, recommended future revision 1.3): see `docs/REMOTE.md` and `Aurora_ACP_Remote_Profile_Implementation_Spec.md`.

Product adapters (Prism `ControlActionRouter`, Conductor UI, Lyric presentation, Bridge firmware I/O) are **not** in this repo.

## Tests

```bash
python3 scripts/check_registry.py
python3 scripts/freeze_vectors.py          # verify pinned CBOR
python3 -m ruff check --config python/pyproject.toml python scripts
(cd python && python3 -m mypy src/acp)
(cd python && python3 -m pytest tests --cov=acp --cov-fail-under=70)
python3 tests/interop/test_ws_hello.py     # Python loopback handshake
python3 tests/interop/test_ws_remote.py    # Python loopback Remote hello/sync/commands
cargo test --manifest-path rust/Cargo.toml
(cd rust && cargo fmt -- --check && cargo clippy -- -D warnings)
swift test
```
