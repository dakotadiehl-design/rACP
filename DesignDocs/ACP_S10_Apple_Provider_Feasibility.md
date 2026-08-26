# S10 Apple provider feasibility decision

Date: 2026-08-26

Status: API feasibility PASS; certificate-policy hardening PASS on available frozen fixtures; production adapter and platform qualification INCOMPLETE.

The installed Apple SDK exposes the frozen primitives in a single Network.framework TLS connection: TLS 1.3 min/max, required peer authentication, local `sec_identity_t`, custom verification, peer certificate-chain metadata, ticket and resumption disabling, early-data status, and `sec_protocol_metadata_create_secret_with_context`. The latter supports the frozen ACP exporter label, 32-byte semantic HELLO context, and length on the same connection. Therefore an Apple-supported provider path is feasible and is preferred over adding Botan to Apple products at this stage.

ACP now contains an `AuroraACPAppleSecurity` target with:

- isolated-anchor `SecTrust` evaluation for both client and server usages;
- exact ACP URI SAN extraction and trust-domain/node binding;
- exact leaf Basic Constraints CA=false/critical, digital-signature-only KU, both client/server EKUs, 128-bit nonzero serial shape, and 20-byte SKI/AKI validation;
- DER credential ID and P-256 SPKI identity-key ID derivation;
- current revocation callback;
- frozen-vector positive plus wrong-node/domain/anchor, expired, not-yet-valid, and revoked negatives;
- TLS client implementation scaffolding using one live `NWConnection` for validation and exporter acquisition.

The live factory is intentionally compile-time unavailable to product callers. The remaining blocker is architectural, not an SDK capability gap: ACP session establishment must own the precise outbound/inbound HELLO used for the exporter, support the server/listener direction, derive and bind both local and peer credential identities correctly, and consume the opaque connection exactly once. Real mTLS certificates/private keys, locked-Keychain behavior, iOS background behavior, and physical Secure Enclave qualification are also outstanding.

No macOS or iOS adapter PASS is claimed from the offline certificate tests or successful compilation.
