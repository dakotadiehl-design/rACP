# S13 Aurora Remote integration contract

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../../docs/README.md).

Inspection evidence: `/Users/dakota/code/AuroraRemote`, branch `main`, HEAD `538a33c467ea74147d46ee61c7b574299ac8fc1f`, clean at inspection. The repository was read-only.

## Current boundary

`AuroraRemote/ACP/PrismACPProvider.swift::connect` accepts a discovered `ws://` endpoint, creates `ACPWebSocketConnection`, then creates `ACPSession` with plaintext enabled whenever discovery TXT says `trusted_lan`. It compares the HELLO peer node ID to the discovery record, which is not cryptographic authentication. `RemoteIdentityStore` stores UUID strings as generic-password Keychain items; it does not own an identity key or credential. Command availability is inferred from server-returned Remote roles. `AppCoordinator` performs fresh reconnection and authoritative resynchronization but has no credential lifecycle or explicit authenticated/revoked/expired/conflict UI state.

## Required migration

1. Link the reviewed `AuroraACPAppleSecurity` product.
2. Replace raw WebSocket/session construction in `PrismACPProvider.connect` with the qualified ACP Apple client connection factory and authenticated-session initializer. Discovery remains an untrusted endpoint hint.
3. Replace `RemoteIdentityStore` UUID-only identity with provider-owned persistent P-256 key handles, installed credential metadata, trust-domain anchors, and transactional rotation. Never export raw private-key bytes.
4. Implement enrollment through the qualified ACP SPAKE2+ path. Device identity remains stable and separate from operator assignment.
5. Require a fresh authenticated connection for every reconnect; reject tickets, resumption, early data, wrong-channel exporters, and discovery identity substitution.
6. Derive command authority from authenticated identity, credential constraints, Prism policy, negotiated capabilities, safety policy, and authenticated operator assignment—not Remote role claims alone.
7. Add explicit UI states for authenticated, trusted-LAN/view-only, revoked, expired, identity conflict, locked key, and provider unavailable.
8. Revocation, expiry, key deletion, or reset removes control authority without deleting cached layouts or assets. Reinstall/restore behavior must not clone non-exportable identity.

Exact future files/symbols include `AuroraRemote/ACP/PrismACPProvider.swift` (`connect`, `RemoteIdentityStore`, command-role admission), `PrismDiscoveryService.swift`, `App/AppCoordinator.swift`, connection-state models and views, lifecycle/background handlers, `project.yml`, entitlements, and the Xcode project/package product references.

## Mandatory tests and completion

- Raw transports, discovery node IDs, claimed roles, and fabricated evidence cannot create control authority.
- Enrollment, persistent identity, rotation interruption, revoked/expired credentials, deleted/locked keys, reinstall/restore, and authority reset fail closed.
- Wrong root/domain/node/SAN, exporter mixup, resumption, 0-RTT, and provider absence fail before synchronization.
- Trusted LAN remains explicitly view-only.
- Fresh reconnect and authoritative resync preserve no stale command, lease, or authorization state.
- Credential lifecycle changes do not delete cached assets.
- iOS Simulator tests are recorded separately from physical-device Keychain/Secure Enclave tests.

Completion requires a separate Aurora-Remote-writable job with ACP read-only plus physical iOS qualification. Current status: `BLOCKED — product integration not yet performed`.
