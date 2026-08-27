# Apple security qualification

Status: **Current implementation guide**

Unit tests executed from an unsigned SwiftPM host cannot qualify production key custody. Qualification must run inside each signed Aurora application target with its production entitlements and bundle configuration.

## Custody decision

```text
Secure Enclave available + supported + qualified
        -> Secure Enclave non-exportable key
Secure Enclave unavailable/unsupported
        -> non-exportable Keychain-backed key
Neither secure custody path available
        -> FAIL CLOSED
```

Entitlement denial, access-control failure, persistence failure, malformed metadata, or inability to prove non-exportability is not “unsupported” and must not trigger fallback. No exportable software key, file-backed key, ephemeral key, or removable HSM is part of the v1 application setup.

## Required evidence

- Exact app, OS, architecture, provider version, source revision, signing identity, and entitlements.
- Persistent-reference reload after process restart.
- P-256 signing and public-SPKI agreement.
- Private-key external representation unavailable.
- Secure Enclave token classification when selected.
- Explicit Keychain non-exportability proof when fallback is selected.
- Authority and leaf-key loss behavior, reset behavior, and no silent replacement.
- Full TLS 1.3 mTLS/exporter all-up result.

Record results under `qualification/`; do not edit an older result to describe a newer artifact.

