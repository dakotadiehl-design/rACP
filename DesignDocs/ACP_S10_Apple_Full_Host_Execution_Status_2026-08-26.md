# ACP S10 Apple Full Host execution status

Date: 2026-08-26

Status: **APPLE TRANSPORT SCOPE PASS; S10 OVERALL BLOCKED; NOT QUALIFIED**

The production Apple transport, identity, trust, and revocation foundation is
implemented and has production-backed macOS arm64 evidence. The complete AFK
S10 success criteria cannot honestly pass because mandatory production
enrollment and cross-language provider paths do not exist in this repository.
No fallback, synthetic security assertion, or protocol change was introduced.

## Completed Apple production scope

- Network.framework owns TLS 1.3 client and listener connections, mandatory
  mutual authentication, isolated anchor validation, peer-chain extraction,
  same-connection exporter derivation, HELLO construction/verification, and
  connection shutdown.
- Security.framework enforces the frozen SAN/domain/node, KU/EKU, CA,
  validity, SKI/AKI, algorithm, credential-ID, key-ID, and revocation policy.
- ACP returns a one-shot opaque `ACPAuthenticatedConnection`; applications
  cannot choose the provider-sealed role or replace the certificate-derived
  local/peer node identity.
- Private keys remain opaque. Transactional PKCS#12 installation persists
  separate certificate and private-key references and verifies reconstructed
  identity usability. An invalid identity persistent-reference assumption that
  caused a native `SecIdentityCopyPrivateKey` crash was removed.
- Trust metadata and revocation are atomic Keychain values and are separate
  from device identity and cached assets.
- Each authenticated transport registers a bounded credential-specific
  revocation observer. Revocation or trust reset closes the live transport in
  accordance with the frozen hardened-termination policy.
- Timeout values are bounded, HELLO reads have deadlines, listener
  continuations have per-attempt cancellation ownership, and failed starts are
  terminal/fail-closed.

## Production-backed evidence

The multi-process harness performs:

```text
bootstrap identities -> exit
host + client start -> authenticate -> both exit
host + client restart -> reload -> authenticate -> both exit
revocation process -> exit
host restart + client reconnect -> both reject
cleanup qualification Keychain material
```

This passed repeatedly during development on macOS 26.5 arm64. The latest
checked artifact is
`qualification/macos-arm64-apple-network-framework-full-8c75913.json`.

Additional passing evidence on the same source line:

- Swift: 125 tests, including active-session revocation and malformed, stale,
  and wrong-class Keychain identity locators.
- Python: 244 tests, 82.5% coverage; Ruff and mypy pass.
- Rust: 64 tests; Clippy with warnings denied and rustfmt pass.
- registry: 109 messages; frozen security vectors: 17 sets / 31 artifacts.
- deterministic security fuzz smoke: 2,000 iterations.
- all WebSocket and framed Python/Rust/Swift HELLO, session, Remote, and
  malformed/negative interoperability suites.
- three-language enrollment state-machine fixture.
- Swift/Python/Rust compiled release API fabrication audit.
- current RustSec scan: no locked-crate finding; project-scoped `pip-audit`:
  no known dependency vulnerability. The host interpreter's unrelated pip
  25.3 has advisories and is not counted as an AuroraACP dependency PASS.

## Mandatory blockers

### Production enrollment provider

Swift contains frozen enrollment state machines and provider protocols, but it
contains no production `ACPSPAKE2PlusOperation`. SPAKE2+ exists only in the
Botan capability probe and deterministic test fixture. It also contains no
production ACP X.509 issuance provider. Security.framework validates and stores
credentials but is not a certificate authority.

Completing this path requires an approved shipping-provider/dependency design:

1. expose the frozen Botan 3.13.x SPAKE2+ profile to Swift through a reviewed
   narrow adapter, or approve and qualify another exact-profile provider; and
2. select the production certificate authority/issuer implementation and key
   custody boundary used by the commissioner.

Without those decisions, implementing an Apple enrollment coordinator would
either be a facade over test cryptography or homemade cryptography. Both are
explicitly forbidden. Human approval therefore cannot create trust in the
current Apple adapter; there is no production enrollment API that could make
that unsafe transition.

### Python and Rust to Apple production listener

The Python reference runtime's `SSLObject`/`SSLSocket` exposes no TLS exporter
API on the tested host. The Rust workspace has no TLS provider dependency or
production Full-profile adapter. Their existing interop fixtures are framed
protocol/reference tests, not authenticated Full-profile clients. Connecting
either to the Apple listener while preserving the frozen HELLO exporter proof
is therefore unsupported. Adding a fake exporter or weakening Apple policy is
not an acceptable substitute.

### Remaining negative and crash qualification

The real positive, restart, and persistent-revocation paths pass. Deterministic
OS-level Keychain access denial, locked-Keychain behavior, mid-Keychain-write
process kill, and deletion/update failure injection remain unqualified. Apple
does not expose deterministic injection for all of these through the shipping
API; a reviewed fault-injection boundary or external harness is required before
marking the original cases PASS.

## Internal security-review answers

1. Approval alone cannot establish trust: no Apple production enrollment API
   exists, and the core state machine requires durable-install verification.
2. Cancelled/expired/cross-ceremony approval replay is rejected by consumed
   attempt IDs and deadlines in the frozen core tests.
3. A crash after approval cannot create Apple trust through the implemented
   path because no trust write is exposed at approval.
4. Partial identity installation is not selected: the logical reference is
   written only after certificate/key persistence and policy verification;
   rollback removes both references on failure.
5. HELLO cannot override certificate identity; all identity fields and exporter
   context are compared before the opaque connection is returned.
6. Revocation survives process restart and rejects a new TLS connection.
7. Tickets/resumption are disabled and accepted early data is rejected.
8. Frozen active-session policy is enforced as `hardenedTerminate`; real
   revocation and trust reset close the registered live Apple transport.
9. Restart recovery uses only Keychain identity/trust data.
10. Product code cannot construct authenticated connections, transport
    evidence, or principals through compiled public APIs.
11. Storage failure has no plaintext, ephemeral, file-backed, trusted-LAN, or
    unauthenticated fallback.

No unresolved P0-P2 defect is known in the completed Apple transport scope.
The missing provider paths and fault-injection evidence are release blockers,
not green findings. Consequently final unchanged-source qualification Run 1
and Run 2 were not started, and **S10 APPLE FULL PROFILE — QUALIFIED / PASS** is
not claimed.
