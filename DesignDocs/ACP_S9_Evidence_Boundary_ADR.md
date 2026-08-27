# ADR: S9 authenticated-evidence construction boundary

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

Status: ACP-local implementation complete; independent architecture review remains BLOCKED and production adapters remain S10/S11/S12 work.

## Decision

Authenticated transport evidence and authenticated principals are library-owned values. Product code may inspect their public read-only views but cannot use a normal public constructor, struct literal, decoder, or arbitrary provider callback to create them.

- Swift evidence and Full TLS fact initializers have package-internal visibility. The eventual Apple adapter must live in the package-owned adapter target. Tests use `@testable` only.
- Rust evidence, principal, and Full TLS fields are crate-private. Public principal getters preserve read access. Cross-crate negative tests opt into the non-default `testkit` feature; release builds must reject that feature.
- Python constructors require module-owned provenance sentinels, and test construction is isolated under conspicuously named `unsafe_*_for_testing` helpers. This is defense against accidental fabrication, not a native security boundary. Python therefore remains excluded from production authenticated control as required by the closure plan.

The provider provenance manifest schema is diagnostic and release-policy input. It does not confer authority and cannot be converted into evidence.

## Compatibility and migration

The wire format, frozen transcripts, identifiers, credentials, revocation objects, and channel binding are unchanged. Source callers that formerly constructed evidence must move into a qualified package/crate-owned adapter. Test callers use test-target helpers. Product callers must receive an authenticated session/connection from those adapters once S10/S11/S12 supply them.

`trusted_lan` remains unauthenticated and cannot create an authenticated principal or satisfy hardened control authorization. There is no fallback from a failed Aurora Trust attempt.

## Remaining closure condition

S9 removes the former normal construction paths but does not close AT-IA-001. Closure still requires shipping opaque live-connection adapters, product wiring, exact-platform qualification, hardware evidence, and independent review through S10–S15.

The final ACP-local closeout additionally removes Python unsafe security factories from the wheel, denies pickle restoration of Python evidence/principals/TLS facts, makes Rust evidence non-cloneable and prevents downstream extraction from its connection, validates qualified provider manifests before Swift connection creation, and audits compiled Swift symbols, the Python wheel, and the Rust release library. Exact-limit, offset-buffer, reserved-flag, and outbound-no-partial-frame regressions are mandatory CI evidence. These facts close the repository-local S9 construction boundary; they do not qualify any provider or product.
