# Aurora Trust M1 Protocol Contract

Status: normative ACP 1.2 Aurora Trust 1.0 contract (Candidate Freeze 2.1.1).

The canonical machine-readable sources are `schema/common/defs.schema.json`,
`schema/security/messages.schema.json`, `schema/session/messages.schema.json`,
`schema/constants.json`, and `schema/registry.json`. The checked-in M0 artifacts under
`vectors/security/` are normative cryptographic evidence and are not independently
recomputed by an SDK.

## Security boundary

The admission sequence is:

```text
discovery -> claimed identity -> verified transport evidence
          -> immutable AuthenticatedPrincipal -> local authorization -> safety policy
```

Discovery, `node_id`, role, capability, and HELLO authentication-mode fields are claims.
They cannot create a principal or grant permission. `trusted_lan` always produces an
unauthenticated principal. Unilateral TLS does not produce an authenticated principal in
hardened mode. Failed authentication never falls back to `trusted_lan`.

Effective permissions are the intersection of credential constraints, local policy,
negotiated capabilities, and operational safety policy. Device identity is independent
of the current operator/participant assignment. Credential revocation/reset is independent
of cached show/layout asset lifecycle.

## Session legality

- `PreHello`: only ordinary ACP handshake/discovery traffic declared pre-handshake is legal.
- `EnrollmentRestricted`: only the `security.enrollment.*` rows whose registry state includes
  `EnrollmentRestricted` are legal. Ordinary show-control families are forbidden.
- `Established`: ordinary ACP traffic is legal, but no authenticated authority is implied.
- `EstablishedAuthenticated`: verified Full mutual-TLS or Lightweight RPK evidence is bound to an
  `aurora_trust` HELLO identity and
  channel binding; authenticated Trust management messages are legal subject to their
  registry permission.

Enrollment attempt state is keyed by `enrollment_id` and `attempt_id`, has monotonic local
deadlines, and is bounded by the profile limits in `schema/constants.json`. A restart
invalidates ephemeral PAKE state. Credential installation/rotation is transactional: the
old complete identity or new complete identity remains usable, never a partial identity.

## Cryptographic structures and logging

Objects that contribute to the PAKE transcript, AAD, confirmation, signature, identity
binding, or revocation signature are closed schemas. Unknown fields are rejected. Binary
JSON values use unpadded base64url and CBOR uses byte strings. Fields annotated
`x-acp-sensitive: true` and `x-acp-log-policy: never` must be redacted by loggers,
inspectors, captures, and crash reporting. Node IDs, credential IDs, trust domains, suites,
and authentication state remain inspectable unless a stricter local policy applies.

Externally observable key-confirmation, transcript, and tag failures collapse to
`security.credential_invalid`; precise stable diagnostics are local-only and redacted.

## Release qualification boundary

This contract does not qualify physical iOS devices, Secure Enclave behavior, untested
desktop/server adapters, Raspberry Pi, or Pico-class hardware. Each adapter must pass its
platform suite before claiming production qualification. Lightweight production release
requires Pico-class HIL; iOS production release requires physical-device qualification for
all hardware-dependent behavior used by the shipping implementation.
