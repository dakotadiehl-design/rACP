# Changelog

Package version (`AuroraACP` semver) is not the ACP wire-protocol version. Wire compatibility remains `acp: "1.2"` unless a release notes an explicit protocol revision.

## Unreleased

## 1.1.0-dev.2 — 2026-08-19

Production Swift Remote Profile authority (`ACPRemoteProductionAuthority`):

- Server-derived roles from `ACPRemotePolicyProviding`; client-claimed roles are ignored.
- Authenticated principal is the transport node ID.
- Invoke dedup survives session replacement.
- Momentary BEGIN/END, disconnect release, timer expiry, and failed physical release (`release_pending` + `physical_active`).
- Injected `ACPRemoteActionRouting` adapters. The existing `ACPRemoteAuthority` simulator is unchanged and unused by Prism.

## 1.1.0-dev.1 — 2026-08-19

ACP Prism/Remote readiness on wire protocol **1.2** (not a protocol bump).

- `command.status_request` / `command.status_report` plus a bounded command ledger keyed by origin node + command identity.
- Snapshot payloads may carry `authority_epoch` + `revision`; deltas accept a revisioned envelope (`authority_epoch`, `base_revision`, `revision`, `changes`) while remaining compatible with the legacy single-resource delta.
- Typed command `preconditions`, provenance, traffic class, coalescing key, and delivery policy.
- Availability reason codes and semantic surface fields (`category`, `availability_binding`, `presentation_hint`).
- Generic Swift WebSocket listener/connection and portable discovery + Bonjour TXT mapping (`_acp._tcp`). Discovery still never authenticates.

## 1.0.0 — 2026-08-19

Swift package conversion and frozen protocol baseline. This is **not** a wire-protocol bump; sessions still negotiate `acp: "1.2"`.

- Root `Package.swift` exposes library product `AuroraACP` (`import AuroraACP`).
- Collapsed `ACPModel`, `ACPEncoding`, and `ACPSession` into a single module.
- Swift sources live under `Sources/AuroraACP/`; tests under `tests/AuroraACPTests/`.
- `acp-framed-hello` remains an interop fixture executable and is not a production host.
- Schema pack and Swift `registry.json` are drift-checked against the canonical registry.
- Public `ACP*` type names are unchanged. Codec schema walker, CBOR internals, and framed `ResumeBox` stay internal.
- Python Remote Profile production authority, Swift/Rust Remote simulators, golden vectors (91), and framed/WebSocket interop from the working tree are included in this freeze.
