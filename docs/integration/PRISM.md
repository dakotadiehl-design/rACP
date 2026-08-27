# Prism ACP security integration

Status: **Current implementation guide — product integration pending**

Prism joins or creates an ACP trust domain and hosts authenticated Remote sessions. It must consume AuroraACP as a package; it must not copy protocol sources or reconstruct authenticated principals from node IDs.

## Required integration sequence

1. Link `AuroraACP` and `AuroraACPAppleSecurity` into the signed Prism target.
2. Bootstrap/open the trust-domain authority through `ACPAppleTrustDomainAuthorityStore`.
3. Accept only provider-created authenticated connections from the Apple Full server factory.
4. Create sessions from the authenticated connection capability; never enable plaintext for production control.
5. Resolve authorization from the authenticated device identity and Prism-owned policy.
6. Use `ACPAuthorizationPolicyStore.authorizeAndConsume` immediately before each privileged operation.
7. Route every accepted Remote action through Prism’s existing `ControlActionRouter` exactly once.
8. Register revocation/policy lifecycle handling and release momentary controls when authority is lost.
9. Keep trust reset separate from show/layout asset reset.

## Fail-closed requirements

Prism must not start its ACP control listener when its qualified provider, authority key, anchor, active credential, current revocation state, or required clock/checkpoint state cannot be opened safely. Missing authority key material never causes an automatic replacement key under the old trust-domain ID.

Discovery, HELLO node IDs, roles, layouts, and capabilities are claims. None grants permission. The authenticated certificate identity selects server-owned policy; capabilities only narrow protocol compatibility.

## Exit tests

- Signed-target Secure Enclave/non-exportable Keychain custody classification.
- Restart recovery without identity or trust-domain change.
- Wrong root/domain/node, revoked/expired credential, and HELLO-binding rejection.
- No plaintext or claimed-node route reaches `ControlActionRouter`.
- Policy/revocation races fail closed and active holds follow the frozen session policy.
- Remote all-up tests cover enrollment, reconnect, asset/state sync, GO, momentary release, revocation, and reset.

The historical inspection contract remains in `DesignDocs/Integration/ACP_S13_Prism_Integration_Contract.md`; this guide is the current integration entry point.

