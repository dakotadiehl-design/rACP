# ACP Aurora Trust M0 iOS Simulator Qualification

**Date:** 2026-08-21  
**Freeze:** Candidate Freeze 2.1.1  
**Overall:** FAIL — useful Simulator evidence obtained, but mandatory adapter probes remain incomplete

## Environment

| Item | Value |
|---|---|
| Xcode | 26.6 (17F113) |
| Swift | 6.3.3 |
| Simulator runtime | iOS 26.5 (23F77) |
| Device | iPhone 17 Pro |
| Simulator architecture | arm64 |
| Host | Darwin 25.5.0 arm64 |
| Provider | Botan 3.13.0 |
| Provider target | `arm64-apple-ios16.0-simulator` |
| Linkage | static |
| Deployment target | iOS Simulator 16.0 |
| SDK | iPhoneSimulator 26.5 |

The provider was compiled from the exact Botan 3.13.0 source tarball. The
Homebrew macOS dylib was inspected and rejected for this purpose because its
Mach-O build platform is macOS, not iOS Simulator.

## Results

| Area | Result | Evidence / limitation |
|---|---|---|
| ACP package Simulator build | PASS | Swift package built as `arm64-apple-ios16.0-simulator` |
| Existing Simulator tests | FAIL | 73/75 passed; two Network.framework WebSocket loopback tests timed out/reset |
| Security-vector integrity | PASS | Simulator process verified Freeze 2.1.1 and all 31 manifest hashes |
| SPAKE2+ / SHA / HMAC / HKDF | PASS | RFC 9383 and ACP inputs; 65-byte shares, both confirmations, bad confirmation rejection |
| Botan TLS 1.3 mTLS | PASS | both peers active and certificate-verified |
| Peer evidence | PASS | peer chains and verified-certificate counts exposed on both sides |
| TLS exporter/channel binding primitive | PASS | equal 32-byte output using the frozen label/context fixture |
| Resumption / 0-RTT policy | PASS | no-op session manager and zero tickets |
| CryptoKit P-256 | PASS | generation, sign/verify, wrong-key rejection, point and DER shape |
| Keychain | FAIL | spawn-only executable receives `errSecMissingEntitlement` (-34018); an app/XCTest-hosted entitlement context is required |
| Full ACP X.509 identity policy | NOT_RUN | isolated chain was exercised, but the production SAN/domain/node/EKU/time/revocation adapter does not exist before M1 |
| Negative network identity cases | NOT_RUN | no production adapter for wrong CA/domain/node/expired/revoked cases before M1 |
| Bonjour Trust behavior | NOT_RUN | no app-hosted qualification target; discovery remains untrusted by contract |
| Secure Enclave | NOT_RUN / DEFERRED | physical-device-only evidence |

The machine-readable result is
`tools/security-probe/results/ios-simulator-arm64-botan-3.13.0.json`. It contains
only safe diagnostic facts and no bootstrap secret, PAKE scalar, private key,
shared secret, derived key, exporter bytes, or TLS secret material.

## Review findings

1. The installed Botan bottle was a macOS-only artifact. The qualification path
   now explicitly requires and records a genuine Simulator static build.
2. The existing package is broadly Simulator-compatible, but its two WebSocket
   loopback cases fail in the selected runtime and remain unresolved.
3. Direct `simctl spawn` is sufficient for provider and vector probes but does
   not supply an application Keychain entitlement context. This limitation is
   reported as FAIL, not converted to a Keychain PASS.
4. In-memory Botan TLS proves provider peer-evidence/exporter capability in a
   Simulator process. It does not prove the not-yet-implemented ACP transport
   adapter's complete identity policy or negative network behavior.

No macOS provider binary was relabeled, no Apple system trust fallback was
introduced, no exporter workaround was used, no M1 production scaffolding was
added, and no physical-device claim is made.

## Required status

```text
iOS Simulator Full-profile functional qualification: FAIL
iOS physical-device Full-profile qualification: NOT RUN / DEFERRED
Secure Enclave hardware qualification: NOT RUN / DEFERRED
```

## Remaining work

- Add an app/XCTest-hosted Simulator qualification target with Keychain
  entitlements and prove lifecycle persistence/deletion/access control.
- Resolve the two Simulator WebSocket failures.
- When the M1 adapter exists, execute complete ACP X.509 identity/revocation,
  TLS negative, HELLO-binding negative, downgrade, and Bonjour cases.
- Run the unchanged harness on physical iPhone/iPad hardware; separately qualify
  Secure Enclave behavior.

This FAIL does not regress the already-qualified Botan crypto profile or macOS
arm64 adapter. It keeps iOS Simulator and physical iOS qualification open and
does not authorize M1.

## Regression gate

The Simulator qualification ran twice around review. Both runs produced the
same provider result (7 PASS, 1 FAIL, 4 NOT_RUN) and the same package result
(73/75, with only the two named WebSocket cases failing).

Two complete host regression/interoperability passes then succeeded:

- registry and standard vectors: 93/93;
- security vectors: 17 sets and 31 fresh hash-pinned artifacts;
- Python: 142 tests at 81.37% coverage, lint and type checking pass;
- Rust 1.75: 25 tests plus documentation tests;
- Swift/macOS: 75 tests;
- Python WebSocket HELLO and Remote;
- Python/Rust and Python/Swift HELLO, session, Remote, and negative suites in
  JSON and CBOR;
- Rust/Swift session interoperability in JSON and CBOR;
- macOS arm64 Botan: 16 mandatory probes pass; and
- `git diff --check`.
