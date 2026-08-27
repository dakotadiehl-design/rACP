# Prism ACP security integration

Status: **Current implementation guide — product integration pending**

Prism joins or creates an ACP trust domain and hosts authenticated Remote sessions. It must consume AuroraACP as a package; it must not copy protocol sources or reconstruct authenticated principals from node IDs.

## Required integration sequence

1. Link `AuroraACP` and `AuroraACPAppleSecurity` into the signed Prism target.
2. Bootstrap/open the ACP-owned host context through the public Apple host factory. The package-only authority store is not an application integration API.
3. Accept only provider-created authenticated connections from the Apple Full server factory.
4. Create sessions from the authenticated connection capability; never enable plaintext for production control.
5. Resolve authorization from the authenticated device identity and Prism-owned policy.
6. Use `ACPAuthorizationPolicyStore.authorizeAndConsume` immediately before each privileged operation.
7. Route every accepted Remote action through Prism’s existing `ControlActionRouter` exactly once.
8. Register revocation/policy lifecycle handling and release momentary controls when authority is lost.
9. Keep trust reset separate from show/layout asset reset.

The public startup composition is:

```swift
let host = try await ACPAppleHostFactory.openOrBootstrap(configuration: configuration)
let enrollment = try host.makeEnrollmentService(
    configuration: try ACPAppleEnrollmentServiceConfiguration())
let enrollmentEndpoint = try await enrollment.start()
let listener = try host.makeFullServerListener(port: 0)
```

`ACPAppleHostConfiguration` requires a stable node ID, a lowercase
application-unique Keychain namespace, and qualified Apple Full-provider
provenance. The factory returns only after authority, active identity, trust
store, and the host-provisioning journal agree. It fails closed instead of
creating replacement trust material when committed state is missing or
mismatched.

Enrollment UI reads `host.pendingEnrollmentRequests()` and may call only
`approveEnrollment`, `rejectEnrollment`, or `cancelEnrollment` with the opaque
request identifier. These decisions do not issue credentials or modify trust;
the package-owned restricted transport consumes an approval and completes the
sealed issuance, receipt-verification, and trust-commit sequence.

Prism advertises `enrollmentEndpoint.port` only as unauthenticated discovery
metadata. For a selected candidate it constructs `ACPAppleEnrollmentCandidate`
with the human-entered bootstrap code and awaits
`enrollment.beginEnrollment(_:)`. The call completes only after the restricted
connection closes following verified installation and durable trust activation.
Pending UI can subscribe to `host.enrollmentRequestUpdates()` without polling.
The candidate must then open a new Full-profile mTLS connection.

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
