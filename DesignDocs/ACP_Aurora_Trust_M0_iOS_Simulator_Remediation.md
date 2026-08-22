# ACP Aurora Trust M0 iOS Simulator Remediation

**Date:** 2026-08-21  
**Result:** FAIL — harness defects remediated; complete M1-bound identity-policy cases remain NOT_RUN

## Environment and host

Xcode 26.6 (17F113), Swift 6.3.3, Darwin 25.5.0 arm64, iOS 26.5
(23F77), iPhone 17 Pro Simulator arm64. Botan 3.13.0 was built statically for
`arm64-apple-ios16.0-simulator`. The ACP-only host is a minimal SwiftUI app plus
hosted XCTest bundle under `tools/security-probe/ios-host`; it has no product UI,
business logic, Aurora product dependency, or entitlement beyond its own
Keychain access group.

The original failed report/result and its 73/75 result are preserved unchanged.
The new machine result is
`tools/security-probe/results/ios-simulator-arm64-botan-3.13.0-remediation.json`.

## Keychain remediation — PASS

Root cause was confirmed: both `simctl spawn` and an unhosted SwiftPM XCTest
bundle lack an application identifier/Keychain entitlement context and return
`errSecMissingEntitlement` (-34018). The hosted target uses exactly one private
access group.

Two hosted tests pass: metadata create/read/delete, duplicate and not-found
behavior, deliberately wrong access-group rejection, permanent P-256 key
creation, opaque reference retrieval, signing/verification, and deletion. No
private-key representation or signature bytes are logged. Simulator software
Keychain evidence does not qualify Secure Enclave.

## WebSocket remediation — PASS

Both original failures timed out at `ACPWebSocketConnection.start` after the
listener reported ready and Network.framework reset the connection. A focused
test proved WebSocket self-loopback works when `acceptLocalOnly` is omitted.

Root cause was redundant listener confinement: combining
`params.acceptLocalOnly = true` with an explicit required `127.0.0.1` endpoint
causes Simulator WebSocket upgrades to reset. The required loopback endpoint is
already the binding/security boundary. Removing the redundant flag preserves
IPv4 loopback-only exposure and fixes the lifecycle race without weakening the
test or changing topology. The two original tests plus a focused regression now
pass; the full Simulator package suite is 76/76.

## Provider, X.509, and network evidence

Previously passing Simulator-native vectors, SPAKE2+, SHA/HMAC/HKDF, CryptoKit
P-256, Botan TLS 1.3 mutual authentication, peer chains, verified-certificate
evidence, equal 32-byte exporter, no-resumption/zero-ticket policy, and redaction
remain PASS.

The complete ACP X.509 policy matrix and authenticated-network negative matrix
remain NOT_RUN. Their required production-intended iOS identity/revocation and
HELLO-binding adapter does not exist before M1. Implementing it in M0 solely to
paint the qualification green would cross the milestone boundary. Existing
qualification TLS proves isolated-chain/provider capabilities, but is not
misrepresented as the future adapter's wrong-domain/node/SAN/EKU/revocation and
downgrade behavior.

## Review

Review found no product coupling, excessive entitlement, raw-key export, system
trust fallback, exporter workaround, downgrade path, disabled test, or
physical-device claim. The generated Xcode project is derived from checked-in
`project.yml` and contains only the qualification host and tests.

The first and post-review remediation runs both passed hosted Keychain 2/2 and
the full Simulator package 76/76. Two complete host regression gates also pass:
registry/vectors 93, security vectors 17 sets/31 artifacts, Python 142, Rust 25
plus doc tests on exact Rust 1.75, Swift/macOS 75, every JSON/CBOR WebSocket and
framed interop suite, macOS Botan's 16 mandatory probes, and `git diff --check`.

## Final status

```text
iOS Simulator Full-profile functional qualification: FAIL
iOS physical-device Full-profile qualification: NOT RUN / DEFERRED
Secure Enclave hardware qualification: NOT RUN / DEFERRED
```

The Simulator harness and transport failures are closed. The remaining
Simulator blockers are the complete ACP X.509 policy and authenticated-network
negative suites, which must run once the M1 production-intended adapter exists.
Other M0 blockers remain the untested Full platforms and deferred Pico HIL. M1
was not begun by this remediation.
