# Apple SPAKE2+ provider lifecycle review

Status: **Current provider contract; restricted Botan 3.13.0 wrapper implemented and boundary-audited.**

This review constrains the implemented ACP-owned Botan C ABI. Future ABI changes must not add any operation that is more permissive than this model.

## Chosen boundary

The provider operation has only two protocol-facing transitions:

1. `receive(peerShare:) -> response`
2. `verifyAndConsumeKey(confirmation:) -> ACPConfirmedSPAKE2PlusKey`

`ACPConfirmedSPAKE2PlusKey` is public only so it can appear in the public
protocol signature. Its initializer and secret accessor are package-scoped.
Downstream modules can carry the capability but cannot fabricate it or extract
its bytes. The enrollment actor stores it in private attempt state.

Verification and secret transfer are deliberately one atomic operation. There
is no `shared_secret`, `skip_confirmation`, Boolean confirmation result, or
generic provider-handle operation in the Swift interface.

## Required native states

| State | Allowed operation | Successor | Any failure |
|---|---|---|---|
| created | generate/process the first share for the fixed role | peer-processing | failed |
| peer-processing | complete the role-specific share exchange | confirmation-pending | failed |
| confirmation-pending | verify peer confirmation and move the secret into the opaque result | consumed | failed |
| consumed | destroy only | consumed | consumed |
| failed | destroy only | failed | failed |
| destroyed | none | destroyed | destroyed |

For the verifier flow used by candidate enrollment, processing the prover share
returns the fixed 97-byte `shareV || confirmV` response. Only a valid 32-byte
`confirmP` permits the wrapper to consume Botan's confirmed shared secret.

The prover flow must apply the equivalent rule: it may produce `confirmP` after
validating `shareV || confirmV`, but transfer of key material is part of that
successful confirmation-processing transition and is never a separate getter.

## Security arguments

- Premature exposure is structurally absent: neither Swift nor the native ABI
  has a pre-confirmation secret getter.
- Confirmation bypass is structurally absent: the only key-producing operation
  requires the peer confirmation input and performs verification internally.
- A Boolean cannot fabricate success: enrollment requires an opaque result
  whose initializer is package-owned.
- Reuse is absent: success consumes the native secret and makes the context
  terminal; failure also makes it terminal.
- Higher-level fabrication is absent: the result is not transport evidence, a
  principal, credential state, trusted-peer state, or authenticated connection.
- Destruction is not an alternate extraction path and must scrub retained
  scalar, serialized secret, and transient key buffers.

## ABI constraints established by this review

The native ABI may use role-specific create/share/confirm functions, but it
must not export a shared-secret getter. Its final confirmation call must accept
an exact 32-byte output buffer and atomically: verify confirmation, copy the
confirmed key, wipe the internal copy, and terminalize the handle. Zero-length,
undersized, oversized, overlapping, or null required buffers fail closed.

Test-only deterministic randomness must be compiled only into native test
executables and must never appear in the packaged header or product module.
