# S9 authenticated connection API migration

Product code must no longer construct handshake facts, transport evidence, or authenticated principals. Diagnostic certificate and discovery values belong in `ACPUnverifiedPeerObservation` and have no authorization meaning.

Swift products will receive `ACPAuthenticatedConnection` from a qualified ACP-owned provider target and consume it through the authenticated session initializer added with the completed adapter. The capability is non-Codable, owns one live transport/evidence pair, and is one-shot. Raw `ACPSession(transport:)` remains a trusted-LAN/testing path and defaults to plaintext denial.

Rust products will receive non-`Clone` `AuthenticatedConnection<T>` from an ACP-owned provider module. Its fields and provider constructor are crate-private; consumers have read-only identity/provenance access and consume the value into one session. The non-default `testkit` feature is for dependent-crate tests only and must be rejected by release CI.

Python records require module provenance and test helpers are explicitly unsafe, but Python reflection prevents a native security boundary. Python is reference tooling and must not terminate a production authenticated control channel.

The provider manifest digest is required diagnostic/release-policy provenance. A manifest never creates authority by itself; only the package/crate-owned provider path may mint the live capability.
