# Changelog

Package version (`AuroraACP` semver) is not the ACP wire-protocol version. Wire compatibility remains `acp: "1.2"` unless a release notes an explicit protocol revision.

## Unreleased

## 1.0.0 — 2026-08-19

Swift package conversion and frozen protocol baseline. This is **not** a wire-protocol bump; sessions still negotiate `acp: "1.2"`.

- Root `Package.swift` exposes library product `AuroraACP` (`import AuroraACP`).
- Collapsed `ACPModel`, `ACPEncoding`, and `ACPSession` into a single module.
- Swift sources live under `Sources/AuroraACP/`; tests under `tests/AuroraACPTests/`.
- `acp-framed-hello` remains an interop fixture executable and is not a production host.
- Schema pack and Swift `registry.json` are drift-checked against the canonical registry.
- Public `ACP*` type names are unchanged. Codec schema walker, CBOR internals, and framed `ResumeBox` stay internal.
- Python Remote Profile production authority, Swift/Rust Remote simulators, golden vectors (91), and framed/WebSocket interop from the working tree are included in this freeze.
