# ACP public bootstrap and enrollment implementation report

Date: 2026-08-27  
Repository boundary: AuroraCommunicationsProtocol only  
Starting revision: `d1620b344a732f69cd4bf8e4dd3106bdb6c002ea`  
Previous reviewed revision from the original gap analysis: `30f0670e30dcd9e9ebc2c2d24aea9d115043f3cb`  
Ending revision: the ACP-only commit containing this report; the pushed Git
revision is recorded in the task completion response.

The starting checkout matched the implementation-plan baseline and no sibling
Aurora repository was modified. The baseline changed from the older gap-analysis
revision because the supplied implementation plan explicitly froze the newer
`d1620b3` checkout.

## Delivered public boundary

- `ACPAppleHostFactory.openOrBootstrap` and opaque `ACPAppleHost` composition.
- Idempotent, namespace-bound trust-domain authority and local-host bootstrap,
  active-identity recovery, issuance-journal recovery, and fail-closed mismatch
  handling.
- Opaque Full-provider construction and verified Full TLS listener creation.
- `ACPAppleEnrollmentService`, bounded listener configuration, endpoint/status
  snapshots, and status event stream.
- `ACPAppleEnrollmentCandidate` and opaque, zeroizing RAW128/manual bootstrap
  secret factories. RAW128/HKDF and manual/PBKDF2 derivation remain internal.
- Sanitized pending-request snapshots plus approval, rejection, cancellation,
  and request-update streaming.
- Trusted-peer summaries, peer revocation, local credential expiry status, and
  explicit v1 renewal-unavailable status.
- One-use destructive reset planning/execution with fail-closed partial-reset
  state and no automatic replacement authority.

Issuer keys, identity keys, Keychain references, anchors, PAKE operations and
derived keys, verifier records, issuance authorization, journals, install
receipts, certificate construction, and trust mutation remain `package` or
private. The review removed formerly public low-level identity-store,
trusted-store construction/mutation, SPAKE2+, and raw verified-certificate
surfaces needed only by ACP internals.

## Implemented lifecycle

Bootstrap reserves a durable host attempt, opens or creates exactly one
non-exportable authority, validates and commits its anchor metadata, prepares a
candidate-owned non-exportable host key, issues and stages the host credential,
atomically selects it active, and commits the host journal. Reopen verifies the
same authority/domain/anchor/key/certificate graph. Concurrent opens in one
process converge on one cached host capability; a conflicting configuration for
the same namespace fails.

Enrollment runs only on the restricted pre-session TCP transport. The
commissioner sends `begin` and then accepts only the ordered
`challenge`/`confirm`/`install_result` sequence or terminal cancellation/error.
It binds the candidate SPKI and every ceremony context field, completes real
SPAKE2+, durably publishes a sanitized request, waits for one race-safe human
decision, seals authorization, issues and encrypts the credential package,
records delivery only after the frame is written, verifies the one-shot install
HMAC and proof of possession, journals pending trust, and activates the peer.
The connection then closes and cannot become an ordinary ACP principal; the
peer must reconnect using Full mTLS and HELLO/exporter binding.

Pending/approved requests are intentionally expired after process restart
because confirmed PAKE keys are memory-only. Pre-confirmation death restarts the
attempt. Delivered-without-receipt never creates trust. Journal-authorized
pending trust is recovered after interrupted activation. Approval/rejection/
cancellation is a durable compare-and-set; duplicate same decisions are
idempotent and competing decisions fail. Listener queues, active attempts,
frames, messages, and deadlines are bounded. Shutdown closes both queued and
active restricted connections.

Revocation persists before success is exposed and invokes registered active
session termination callbacks under the hardened policy. Reset shuts down
enrollment and removes decisions, trust/revocation state, local lifecycle and
identity records, issuance journal, host journal, then authority custody.

## Review findings fixed

- Connected the previously unit-only commissioner controller to a real public
  TCP service and host factory.
- Fixed JSON/CBOR security binary normalization: internal cryptographic fields
  now remain bytes while both wire encodings validate their frozen forms.
- Replaced the listener's single waiter with independent bounded waiters, so a
  second permitted attempt no longer fails as a closed listener.
- Added active-connection tracking so service shutdown cannot strand a live
  enrollment ceremony.
- Separated the 10-minute human-decision deadline from ACP's fixed one-hour
  issued-credential lifetime; callers cannot select certificate validity.
- Added exact frozen-vector RAW128 derivation and rejected malformed RAW128 and
  manual secrets before protocol use.
- Made bootstrap secrets opaque and zeroizing and removed public low-level PAKE
  and raw certificate-policy capabilities.
- Made host opening single-owner per namespace/configuration in process.
- Added decision/status streams, sanitized stage-specific errors, credential
  expiry gating, and explicit arm64 distribution enforcement.
- Made reset plans one-use under races and kept a partial reset unusable but
  explicitly retryable from the same host.

No public-path `TODO`, `FIXME`, placeholder, scaffold, `fatalError`, or
unimplemented branch remains. No P0–P2 review finding remains open in code.

## Qualification evidence

Toolchain:

- Apple Swift 6.3.3 (`swiftlang-6.3.3.1.3`, Clang 2100.1.1.101)
- Rust 1.97.1 / Cargo 1.97.1
- Python 3.14.2
- swift-certificates 1.19.4 (`449dbbec...`)
- swift-asn1 1.7.1 (`a9a5efd4...`)
- external consumer resolved swift-crypto 4.5.1 (`47d3869a...`)

Results:

- Swift: 180 tests passed, 0 failed, 2 unsigned-host custody tests skipped.
- Real restricted TCP enrollment success and resource-limit/shutdown tests pass.
- Existing real Keychain Full TLS 1.3 mTLS/exporter/HELLO all-up test passes.
- Debug and Release Swift package builds pass.
- Separate Release consumer package builds using ordinary imports only; no
  `@testable`, SPI, copied security code, or package-only access.
- Rust workspace: 65 tests passed plus doc tests; frozen/golden vectors pass.
- Python: 256 tests passed; coverage 82.66% (70% gate).
- SPAKE2 XCFramework policy test passes for `macos-arm64`, `ios-arm64`, and
  `ios-arm64-simulator` only.
- The unsigned authority qualification fails closed with
  `entitlementFailure`; its unique partial namespace was successfully reset.

## Platform decision and remaining external gate

Universal Intel macOS support is formally not part of the v1 support policy.
The native artifact is intentionally arm64-only; applications must not add an
insecure fallback. This closes the prior accidental-architecture ambiguity
without claiming an unavailable x86_64 build.

The repository implementation is complete, but production Prism readiness
still requires running the checked-in Apple qualification harness from a signed
application target with its production signing identity, Keychain access group,
and Secure Enclave entitlements. This environment cannot manufacture those
credentials. The observed entitlement failure is the required fail-closed
behavior, not a code fallback. Production qualification must record first-run
authority/identity custody, persistent reload, Secure Enclave or qualified
non-exportable Keychain classification, enrollment/rejection/cancellation,
restart, revocation/session termination, and deletion/corruption behavior under
`qualification/` before a product release gate is declared green.

Subject to that external signed-host gate, a normal Apple application can now
implement ACP first-run commissioning using supported public APIs only.
