# ACP Apple Full Host — Partial Implementation Report

Date: 2026-08-26

Status: **PARTIAL / NOT QUALIFIED / NOT PUSHED**

Starting commit: `1e04e4a2aabfbc0f0fce2b77613468505c61772c`

## Implemented in this worktree

- Added an Apple TLS 1.3 mutual-authentication listener API:
  `ACPAppleFullServerFactory.makeListener` and `ACPAppleFullServerListener`.
- Removed the caller-supplied authenticated HELLO from the Apple client API.
  ACP now constructs and transmits the client HELLO and its TLS exporter binding.
- The server receives, parses, validates, and exporter-verifies HELLO before it
  returns an `ACPAuthenticatedConnection`.
- Added one-shot `ACPAuthenticatedConnection.makeSession(local:)`. The provider
  seals the client/server role; application code cannot choose it.
- Added authenticated `ACPSession` sequencing. A server binds the claimed HELLO
  node/domain/credential/key/binding to provider evidence before establishing;
  a client binds the ACK node to the certificate-derived peer node.
- Added an opaque `ACPAppleLocalIdentity` and Keychain-backed
  `ACPAppleIdentityStore.load/reset` surface. The application sees metadata but
  does not receive a private key or `SecIdentity` reference.
- Listener endpoint metadata explicitly reports Full profile, Aurora Trust, and
  mandatory TLS.
- TLS tickets/resumption remain disabled and early data is rejected.
- Added positive authenticated-session and claimed-node mismatch tests.

## Evidence obtained

- Swift: 118 passed.
- Python: 244 passed (the first sandboxed run denied localhost bind; the
  unsandboxed rerun passed all tests).
- Rust: 64 passed.
- Ruff: PASS.
- mypy: PASS.
- Clippy with warnings denied: PASS.
- rustfmt check: PASS.
- compiled security evidence-boundary audit: PASS.
- `git diff --check`: PASS.

## Unmet mandatory completion gates

The milestone cannot be called complete or qualified from this worktree:

1. No real Keychain-backed client/server certificate identities have yet run
   through the new listener in an all-up macOS arm64 process.
2. Consequently, real Network.framework TLS 1.3 mTLS, peer-certificate
   extraction, exporter equality, reconnect, revocation rejection, and shutdown
   have not been demonstrated end to end for this new path.
3. The Apple enrollment approval/issuance/install orchestration API required by
   the prompt has not been implemented.
4. Safe trusted-peer enumeration, persistent last-seen metadata, revocation
   request/completion, and change observation have not been implemented.
5. The required Keychain negative matrix and listener/TLS/enrollment
   cancellation matrix have not been executed.
6. Python/Rust qualification clients have not connected to the Apple listener.
7. Interop, malformed-input, fuzz, SBOM/advisory, release-symbol, and the two
   unchanged-source final qualification passes have not been run for this
   milestone.
8. The required final internal security review cannot close until the missing
   production paths and real-platform tests exist.

Because these are security completion requirements, S10 remains unqualified.
No commit or push was made. No protocol semantics were weakened to claim PASS.
Only the AuroraACP repository was modified.
