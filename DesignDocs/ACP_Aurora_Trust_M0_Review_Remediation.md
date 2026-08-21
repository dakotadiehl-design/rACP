# Aurora Trust M0 Independent-Review Remediation

**Review:** `ACP_Aurora_Trust_M0_Independent_Review.md`
**Reviewed candidate:** Candidate Freeze 1
**Remediated candidate:** `docs/SECURITY.md` Candidate Freeze 2.1
**Status:** Freeze 2 received CONDITIONAL GO; Freeze 2.1 addresses its residual findings and awaits independent confirmation

This record tracks disposition of the supplied NO-GO review. A documentation change is not proof that the construction is secure or supported on target hardware.

| Finding | Disposition carried into Candidate Freeze 2.1 |
|---|---|
| AT-M0-001 | Fixed uncompressed 65-byte SEC1 shares and RFC transcript point encoding. |
| AT-M0-002 | Defined binary-safe registration bytes, both identities, UUID order, salt, output split/reduction, and context exclusion from registration. |
| AT-M0-003 | Split high-entropy and numeric-code registration into distinct suite identifiers; provider defaults forbidden. |
| AT-M0-004 | Defined compact credential, preface framing, RPK matching, exporter context/key, finished message, and HMAC binding. Hardware proof remains required. |
| AT-M0-005 | Fixed challenge/response/confirm field mapping and candidate/commissioner key labels. |
| AT-M0-006 | Bound identity algorithm/key ID into context and AAD; challenge SPKI must hash to the bound ID. |
| AT-M0-007 | Required both instance IDs and binding fields on begin/challenge. |
| AT-M0-008 | Version 1 permission request is closed to empty-map only; requested values are not grants. |
| AT-M0-009 | Defined closed approval plaintext/AAD maps and field types. |
| AT-M0-010 | Defined low-S ECDSA installation proof and durable read-back requirement. |
| AT-M0-011 | Unified identity tuple/SPKI; Full v1 explicitly uses local-policy-only role narrowing. |
| AT-M0-012 | Fixed RFC 7093 SKI construction and AKI equality. |
| AT-M0-013 | Closed HELLO exporter semantic map; explicitly revised legacy Remote SAN behavior. |
| AT-M0-014 | Defined 26-character Crockford encoding, alphabet, padding bits, and rejection rules. |
| AT-M0-015 | Added restricted enrollment pre-session state and explicit allowlist to `STATE_MACHINES.md`. |
| AT-M0-016 | Made transport evidence/auth-mode equality, claim non-authority, and hardened downgrade rejection normative. SDK implementation remains M2/M5/M6 work. |
| AT-M0-017 | Fixed RFC 5869 Extract/Expand semantics and prohibited TLS Expand-Label. |
| AT-M0-018 | Explicitly prohibited `skip_confirmation`. |
| AT-M0-019 | Fixed revocation signature, timestamps, omission rules, epoch gaps, snapshot bounds, and hardened active-session behavior. |
| AT-M0-020 | Closed compact credential and extension maps; fixed SPKI/signature encoding. |
| AT-M0-021 | Fixed profile-specific size, nesting, collection, concurrency, and credential bounds. Codec implementation remains M1/M8 work. |
| AT-M0-022 | Added normative-profile precedence to the architecture design; removed v1 Ed25519 ambiguity, alternative transcript framing, stale identity tuple, and stale suite/key labels. SAS remains unadvertised. |
| AT-M0-023 | Accepted informational limitation; unchanged. |
| AT-M0-024 | Licenses remain pending project-owner approval. |
| AT-M0-025 | Disabled Full and Lightweight TLS resumption and 0-RTT in version 1. |
| AT-M0-026 | Defined `tls` and `trusted_lan` as unauthenticated and forbidden in hardened mode. |
| AT-M0-027 | Reduced Full enrollment concurrency to 2 and removed provider-default Argon2id from the ACP registration contract. |
| AT-M0-028 | Required isolated ACP trust stores and disabled Web-PKI/AIA/CRLDP/OCSP/DNS fallback. |
| AT-M0-029 | Required both EKUs, low-S, and RFC 7093 SHA-256 SKI. |
| AT-M0-030 | Unified confirmation/transcript/tag failures behind one external authentication error. |
| AT-M0-031 | Reduced backdating to two minutes, fixed total skew, required monotonic enrollment deadlines, and allowed only protected commissioner time to initialize a checkpoint. |

## Remaining evidence before GO

1. Independent confirmation must issue GO with no BLOCKER/HIGH findings against Candidate Freeze 2.1.
2. ACP golden vectors must prove registration, RFC shares, transcript, key schedule, AEAD, identifiers, credentials, revocation, and Lightweight finished binding.
3. Provider probes must pass on every supported Full platform.
4. Representative Pico-class HIL must prove the Lightweight provider, entropy, RPK, bounds, timing, and transactional storage.
5. Project owner must approve provider licenses and the ongoing security-update policy.

M1 remains closed until the M0 execution contract's exit gate is satisfied. Vector format/tooling may be reviewed as M0 evidence, but production schemas and SDK Trust behavior must not begin early.

## Freeze 2 CONDITIONAL GO dispositions

| Finding | Freeze 2.1 disposition |
|---|---|
| AT-M0-032 | Closed HELLO node/protocol/capability/auth projections and preserved received array ordering without sort/dedup/reconstruction. |
| AT-M0-033 | Added distinct `LightweightBinding` pre-HELLO state and allowlist. |
| AT-M0-034 | Fixed nested-map compact body, complete-object credential ID, canonical DER SPKIs, node/domain inputs, and mandatory equality checks. |
| AT-M0-035 | Required exactly one suite per enrollment ID and RAW128-only Lightweight advertisement. |
| AT-M0-036 | Fixed AAD message type literal to `security.enrollment.approval`. |
| AT-M0-037 | Defined credential ID ASCII as UTF-8 `sha256:` plus 64 lowercase hex digits. |
| AT-M0-038 | Fixed snapshot times to ACP-CDE tag 0. |
| AT-M0-039 | Replaced the stale 24-character display example with a 26-character example. |
| AT-M0-040 | Assigned candidate/commissioner confirmation keys to the install result and terminal receipt; prohibited ad hoc reuse. |
| AT-M0-041 | Required Lightweight to advertise RAW128 only. |
