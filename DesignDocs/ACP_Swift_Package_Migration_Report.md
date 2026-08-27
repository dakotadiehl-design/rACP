# AuroraACP Swift Package Migration Report

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Date:** 2026-08-19
**Handoff:** `DesignDocs/ACP_Swift_Package_Grok_Handoff.md`
**Scope:** Packaging conversion only. ACP itself did not change.

```text
Same ACP
Same wire behavior
Same interoperability
Different packaging
```

## Resulting tree

```text
AuroraCommunicationsProtocol/
├── Package.swift
├── CHANGELOG.md
├── Sources/
│   ├── AuroraACP/
│   │   ├── Core/
│   │   ├── Codec/
│   │   ├── Transport/
│   │   ├── Session/
│   │   └── Profiles/Remote/
│   └── acp-framed-hello/
├── tests/
│   ├── AuroraACPTests/
│   └── interop/
├── python/
├── rust/
├── schema/
├── vectors/
└── docs/
```

`swift/` is gone. There is one Swift package, at the repository root.

**Test path casing:** this repo already had Python interop under `tests/`. macOS is case-insensitive, so a second `Tests/` directory cannot exist beside it. Package.swift therefore uses `path: "tests/AuroraACPTests"`. Linux CI resolves the same git path.

## Files moved

| From | To |
|---|---|
| `swift/Package.swift` | `Package.swift` (rewritten: one product `AuroraACP`) |
| `swift/Sources/ACPModel/ACPModel.swift` | `Sources/AuroraACP/Core/ACPModel.swift` |
| `swift/Sources/ACPModel/ACPRemote.swift` | `Sources/AuroraACP/Profiles/Remote/ACPRemote.swift` |
| `swift/Sources/ACPEncoding/*` | `Sources/AuroraACP/Codec/` |
| `swift/Sources/ACPSession/ACPSession.swift` | `Sources/AuroraACP/Session/ACPSession.swift` (transport types extracted) |
| `swift/Sources/ACPSession/ACPFramed.swift` | `Sources/AuroraACP/Transport/ACPFramed.swift` |
| `swift/Sources/ACPSession/ACPNegotiate.swift` | `Sources/AuroraACP/Session/ACPNegotiate.swift` |
| `swift/Sources/ACPSession/ACPRegistry.swift` | `Sources/AuroraACP/Session/ACPRegistry.swift` |
| `swift/Sources/ACPSession/registry.json` | `Sources/AuroraACP/Session/registry.json` |
| `swift/Sources/ACPSession/ACPRemoteSession.swift` | `Sources/AuroraACP/Profiles/Remote/ACPRemoteSession.swift` |
| `swift/Sources/acp-framed-hello/main.swift` | `Sources/acp-framed-hello/main.swift` |
| `swift/Tests/ACPModelTests/*` | `tests/AuroraACPTests/Core/` |
| `swift/Tests/ACPEncodingTests/*` | `tests/AuroraACPTests/Codec/` |
| `swift/Tests/ACPSessionTests/ACPSessionTests.swift` | `tests/AuroraACPTests/Session/` |
| `swift/Tests/ACPSessionTests/ACPRemoteTests.swift` | `tests/AuroraACPTests/Profiles/` |

New files (no protocol behavior):

- `Sources/AuroraACP/Transport/ACPTransport.swift` — `ACPTransport`, `ACPLoopback`, `acpLinkedTransports()` extracted unchanged from the session file
- `tests/AuroraACPTests/Fixtures/RepoRoot.swift` — locates `vectors/manifest.json` without a hard-coded walk depth

## Public API

Module name changed: `import ACPModel` / `ACPEncoding` / `ACPSession` → **`import AuroraACP`**.

Type names were not renamed. Existing `public` application-facing declarations remain `public`, including `applyHelloAck`, `acpMinCapabilityAllowed`, and `acpVersionAtLeast`.

Unambiguously internal (already non-public before the move; still non-public):

- `enum ACPSchema` (JSON Schema walker)
- `enum CborValue` and CBOR encode/decode helpers
- `private final class ResumeBox`

`ACPEncoding` public surface is still only `encodeJSON` / `decodeJSON` / `encodeCBOR` / `decodeCBOR` plus `ACPCodecError`.

No uncertain API was hidden.

## Application dependencies removed

None. Swift sources had no Prism, Remote, Conductor, or Lyric imports before or after.

## Behavior changes

None intended, none observed. Golden CBOR vectors still match bit-for-bit. Handshake, sequence, Remote simulator, and framed interop behavior is unchanged.

## Tooling

- `scripts/pack_schemas.py` writes `Sources/AuroraACP/Codec/schema_pack.json`
- `scripts/gen_registry.py` also writes `Sources/AuroraACP/Session/registry.json`
- `scripts/check_registry.py` drift-checks both the schema pack and the Swift registry copy
- `.github/workflows/ci.yml` runs `swift test` and `swift build --product acp-framed-hello` from the repo root
- `tests/interop/test_framed_cross.py` looks for `.build/debug/acp-framed-hello`

## Build and test results (2026-08-19, this checkout)

| Gate | Result |
|---|---|
| `swift build` | pass |
| `swift test` | 22 tests, 0 failures (golden vectors, invalid/malformed corpora, session, Remote) |
| `python3 scripts/check_registry.py` | `registry ok: 91 messages` |
| `python3 scripts/freeze_vectors.py` | `vectors ok: 91` |
| framed `--sdk swift --suite hello` | pass (Python↔Swift, CBOR+JSON) |
| framed `--sdk swift --suite session` | pass |
| framed `--sdk swift --suite remote` | pass |
| framed `--sdk swift --suite negative` | pass |
| framed `--sdk rust-swift --suite session` | pass |

Consumer import: `Sources/acp-framed-hello` builds with `import AuroraACP`. A throwaway Swift package depending on this checkout via `.package(path:)` also compiled `import AuroraACP` and printed `ACPModel.protocolVersion` (`1.2`).

## Recommended package tag

**`1.0.0`** — tagged in Phase 0A after the freeze verification suite in `DesignDocs/CHECKPOINT_ACP_PHASE_0A.md`.

That is the first supported Swift package product. The wire protocol remains **ACP 1.2**.

```text
AuroraACP 1.0.0        → Swift package version
ACP wire protocol 1.2  → version spoken on the network
```

Do not treat `1.0.0` as a protocol revision.

## Prism / consuming-app notes (not done in this conversion)

Stop here for human review of this repository. A later Prism (then Remote, Conductor, Lyric) pass should:

1. Add this checkout as a local Swift package, or the git URL plus a pinned tag.
2. Link the `AuroraACP` library product.
3. Replace copied ACP sources with `import AuroraACP`.
4. Keep application adapters (cue engine, UI, fixture store) in the application.
5. Delete duplicate ACP protocol `.swift` files only after the app builds and its ACP integration tests pass.

Never put Prism/Remote/Conductor/Lyric domain code into this package.

## Checkpoint

This conversion is complete as an independent package. No consuming application was modified.
