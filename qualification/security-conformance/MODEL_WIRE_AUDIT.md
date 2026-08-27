# ACP Portable Authority Model and Wire Audit

Date: 2026-08-27  
Protocol: ACP 1.2 / Aurora Trust 1.0  
Result: PASS — no wire change required

## Frozen model mapping

| Portable model | Existing wire or signed representation | Result |
|---|---|---|
| Trust-domain authority identity | `trust_domain_id`, `authority_key_id`, PAKE-protected `trust_anchor` | Complete; provider reference remains host-private |
| Commissioner identity | commissioner node/instance IDs in enrollment transcript and approval AAD; commissioner credential in authenticated transport | Complete and distinct from authority identity |
| Issuance metadata | enrollment/attempt/transcript bindings plus protected approval credential metadata | Complete; metadata is not issuance evidence |
| Revocation metadata | signed `acp-revocation-snapshot-v1` body with trust domain, issuer key, epoch, and previous snapshot hash | Complete and authority-bound |

The portable JSON schema in `schemas/security/trust-domain-authority.schema.json` describes conformance and audit projections. It does not add a message or authorize these projections as security evidence.

## Boundary findings

- Swift portable and Apple host types keep `SecKey`, Keychain references, and signing handles off wire.
- Commissioner node identity and authority key identity remain separate throughout issuance facts.
- Certificates contain node/domain identity only; requested roles and permissions are not X.509 authorization grants.
- Rust's legacy raw `X509IssuanceProvider` and `CredentialAuthority.issue_x509` surface conflicted with the sealed issuer boundary and was removed in this milestone.
- Rust and Python still require full strict X.509 consumer implementations; the foundational tests currently validate canonical identifiers, exact artifact hashes, and portable model bindings.

## Stable conformance error categories

Negative fixtures use ACP error codes, never native library text. The initial registry is the `error_category` enum frozen in `vectors/security/conformance/manifest.schema.json`. Additions require fixture-schema review; changing the meaning of an existing category is breaking.
