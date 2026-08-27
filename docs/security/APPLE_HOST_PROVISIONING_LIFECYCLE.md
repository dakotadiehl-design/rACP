# Apple host provisioning lifecycle

Status: implemented public-boundary contract.

This document defines the application-facing security boundary for an Apple
Full-profile ACP host. It does not change the ACP wire protocol, trust model,
certificate policy, or enrollment cryptography.

## Ownership boundary

ACP owns trust-domain authority keys, host identity keys, certificates,
Keychain records, issuance journals, trusted-peer state, enrollment protocol
state, recovery, and authenticated transport. Host applications provide:

- stable local node identity and display metadata;
- a unique storage namespace and optional Keychain access group;
- qualified provider provenance;
- explicit human approval, rejection, or cancellation decisions.

Applications never receive authority or identity signing keys, persistent
Keychain references, PAKE-derived secrets, issuance authorizations, install
receipts, mutable trust records, or certificate-construction inputs.

Discovery remains unauthenticated metadata. It never creates an ACP principal
or authorizes application traffic.

## Public host states

`ACPAppleHostProvisioningState` is presentation-safe. A state is not proof that
the corresponding Keychain material is valid; the factory verifies all durable
material before returning a ready host.

| Public state | Meaning | Permitted startup action |
| --- | --- | --- |
| `uninitialized` | No committed authority or host provisioning record exists. | Begin bootstrap. |
| `bootstrapping` | A recoverable pre-commit operation is durable. | Resume the exact operation idempotently. |
| `ready` | Authority, active host identity, trust store, and provider provenance agree. | Construct authenticated listeners and enrollment service. |
| `recoveryRequired` | A committed operation needs deterministic reconciliation. | Recover; do not accept connections. |
| `corrupt` | Durable records are malformed, mismatched, or reference missing material. | Fail closed; do not create replacement material. |
| `resetRequired` | Recovery cannot preserve the committed trust domain safely. | Require a separately authorized destructive reset. |

## Bootstrap transaction

The host provisioning journal is the lifecycle authority. Merely finding a key,
certificate, authority record, or identity selector is insufficient to report
`ready`.

| Durable phase | Restart classification | Required behavior |
| --- | --- | --- |
| no record | retry idempotently | Reserve one bootstrap identifier and trust-domain creation attempt. |
| authority key reserved | resume safely | Open the same non-exportable key; never substitute another key for the domain. |
| anchor generated | resume safely | Validate the anchor, key identifier, custody, and self-signature before commitment. |
| authority committed | already committed | Missing or mismatched authority material is corrupt, not a new bootstrap. |
| host key prepared | resume safely | Reopen the exact pending key and verify its identity-key identifier. |
| host credential issued | retry idempotently | Reuse only the issuance journal package bound to the same authorization and key. |
| host identity staged | recover or abort staging | Reconcile the identity selector and provisioning journal; never infer activation from certificate presence. |
| host identity active | already committed | Reload and fully validate the selected identity. |
| trust store initialized | resume safely | Validate the domain-scoped store and finish the host commit. |
| host committed | already committed | Verify every component, then return `ready`. |

The linearization point for a usable host is the durable host-commit record
written after active-identity selection and trust-store initialization. Failure
before that point cannot enable a listener. Failure after that point is resolved
by reopening and verifying the committed graph.

Bootstrap is idempotent for one storage namespace and node ID. Concurrent calls
must converge on the same committed host or fail deterministically. A committed
trust domain is never silently replaced.

## Enrollment and restart rules

Enrollment connections are restricted protocol connections and never become
ordinary authenticated ACP sessions. On successful enrollment they close; the
new peer reconnects using mTLS and completes authenticated HELLO/exporter
binding.

| Enrollment point | Process restart behavior |
| --- | --- |
| Before SPAKE2+ confirmation | Discard transient secrets and start a new attempt. |
| Confirmed but not durably approved | Abort the attempt; do not persist PAKE-derived keys. |
| Awaiting human decision with safe request metadata | The request may be restored only if its cryptographic attempt remains independently valid; otherwise expire it. |
| Approved but not issued | Recover only from sealed, non-secret durable authorization evidence; otherwise abort. |
| Issued but not delivered | Follow the issuance journal's exact retry or abandonment result. |
| Delivered without valid install result | Never create pending or active trust. |
| Install result verified, activation interrupted | Recover only the journal-authorized pending trust record. |
| Trust activated, final response interrupted | Treat trust activation as committed and replay only the terminal result. |

Approval, rejection, and cancellation are single-use decisions. Their durable
compare-and-set is the decision linearization point. Cancellation wins only
before issuance/trust commitment crosses its documented commit point; after
commit, completion wins and must be reported after reconciliation.

The public decision API exposes only `ACPAppleEnrollmentRequestSummary` values
and request identifiers. Repeating the same decision is idempotent; a competing
decision fails with `invalidState`. The corresponding validated ceremony and
confirmed SPAKE2+ key remain package-owned, memory-only capabilities. Reopening
the decision service expires pending and approved records because those
transient capabilities are deliberately not persisted. A candidate must begin
a fresh ceremony after such a restart.

`enrollmentRequestUpdates()` emits sanitized durable pending-request snapshots.
`ACPAppleEnrollmentService.statusUpdates()` separately reports listener state,
bounded active-attempt count, pending-decision count, and sanitized last-error
category. Local credential expiry is available through `operationalStatus()`;
renewal is explicitly reported as unsupported in v1.

## Listener admission

The host may construct a Full-profile listener only when:

1. the host journal is committed;
2. authority key, anchor, domain metadata, and host certificate agree;
3. the active host key is present, non-exportable, and operational;
4. trusted-peer and revocation state opens successfully;
5. provider provenance is qualified for the Full profile; and
6. no recovery operation is outstanding.

The restricted enrollment endpoint accepts only the frozen enrollment
allowlist, applies bounded attempts/deadlines/message sizes, and closes after a
terminal outcome. Remote, control, state, resource, and ordinary session
traffic are rejected on that endpoint.

For the commissioner endpoint the direction is fixed by the frozen ceremony:
ACP sends `security.enrollment.begin`, then admits only candidate-originated
`challenge`, `confirm`, and `install_result` messages in that order. `cancel`
and `error.report` are terminal escape paths. The commissioner recomputes the
candidate identity-key identifier from the challenge SPKI and binds every
echoed context field before constructing its SPAKE2+ verifier. Only successful
candidate confirmation creates a sanitized pending human-decision request.

The transport boundary is implemented as a package-owned restricted connection
and Apple TCP listener exposed only through `ACPAppleEnrollmentService`.
Applications configure bounded concurrency, pending connections, frame/message
limits, and deadlines, then pass semantic candidate metadata plus either a
26-character Crockford RAW128 bootstrap code or an 8–12 digit manual code.
ACP derives the frozen verifier record internally and never returns it. Frames
are capped before decoding, every decoded
envelope must be pre-session and addressed to the local node, response types
must match the registry, and the connection closes synchronously after a
terminal message, timeout, denial, or resource-limit failure. This listener has
no conversion to `ACPAuthenticatedConnection` or `ACPSession`; the public host
exposes it only with the SPAKE2+/decision/issuance controller connected.

The connected commissioner session waits on the durable human-decision actor.
Approval is consumed exactly once, converted to sealed issuance capabilities,
and encrypted with the transcript-derived approval key. The issuance journal
records delivery only after the approval frame is successfully written. An
install result must then pass the one-shot candidate-confirm HMAC, exact package
binding, certificate proof-of-possession verification, and trust-domain policy
before pending trust is journaled and activated. Completion always closes the
restricted connection; the peer reconnects using fresh mTLS.

The application-facing provider configuration is opaque. Identity stores,
trusted-peer store construction/reset, decision actors, PAKE capabilities,
issuer objects, anchors, and mutable trust records are package-owned. Public
host operations expose only sanitized status, request summaries, decisions,
trusted-peer summaries, revocation, and construction of verified listeners.

## Reset boundary

Reset is not part of ordinary startup. `planLocalSecurityReset()` mints a
one-use plan describing affected authority, identity, trust, and enrollment
state. `executeLocalSecurityReset(_:)` accepts only the most recently minted
plan, shuts down enrollment, cancels pending decisions, and removes the
lifecycle selector/identity, issuance journal, trust state, host journal, and
authority custody in fail-closed order. The caller must perform platform-local
user authentication before execution. A reset host cannot create another
listener; creating a replacement domain requires a fresh factory open.

## Threat model for the public surface

The public boundary must fail closed against malicious or buggy application
code attempting duplicate bootstrap, concurrent approval/rejection, arbitrary
certificate fields, arbitrary trust insertion, receipt substitution, replayed
installation results, cross-domain state reuse, private-key export, namespace
aliasing, recovery rollback, listener startup during recovery, or use of an
enrollment connection as an authenticated application session.

Package-only issuer, journal, receipt, pending-key, coordinator, and trust
mutation capabilities remain sealed. Public compile qualification must use a
separate Swift package; another target in this package can access `package`
symbols and is not sufficient evidence.
