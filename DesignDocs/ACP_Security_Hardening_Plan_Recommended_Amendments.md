# Recommended Amendments to the ACP Security Hardening Plan

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

> **Disposition:** Incorporated into `ACP_Security_Hardening_Plan.md`. This
> document remains the review record; the consolidated plan is authoritative
> for execution.

## Review conclusion

The seven-phase plan is structurally strong and is a good basis for
completing the Swift production security path. The sequencing is
sensible:

1.  protected authority custody;
2.  durable trust-domain bootstrap;
3.  enrollment-to-issuance sealing;
4.  crash-safe credential lifecycle;
5.  revocation;
6.  authenticated transport binding;
7.  centralized authorization.

The following amendments are recommended before execution. They are
primarily clarifications of security ownership and qualification
requirements rather than a redesign of the plan.

------------------------------------------------------------------------

## 1. Phase 1: do not treat persisted `validation status` as authoritative

The proposed non-secret custody record may contain diagnostic
information, but a persisted `validation status` must never substitute
for validating the live key capability after restart.

### Recommended change

Replace:

> Persist a non-secret custody record containing key identifier, custody
> mechanism, creation version, validation status.

with a model in which the record contains only durable metadata such as:

-   key identifier;
-   expected custody mechanism;
-   creation/schema version;
-   expected public-key/SPKI identifier;
-   authority/domain correlation identifier where appropriate.

On every load, ACP must independently revalidate:

-   the key still exists;
-   it is the expected key;
-   it is P-256;
-   it has the expected public key/SPKI;
-   the private capability is usable for the required signing operation;
-   the key remains non-exportable to the extent the provider can prove;
-   the custody mechanism still satisfies policy.

Any stored validation result is informational only.

### Reason

Otherwise a stale metadata record could say "validated" after the
underlying Keychain/Secure Enclave state has changed.

------------------------------------------------------------------------

## 2. Phase 1: freeze the exact Secure Enclave fallback taxonomy

The plan correctly allows Keychain fallback only when Secure Enclave is
genuinely unavailable or unsupported. Make this an explicit closed set
of provider outcomes.

Conceptually:

``` text
Secure Enclave result
├── available + qualified       → use Secure Enclave
├── unsupported platform        → Keychain fallback permitted
├── unsupported required op     → Keychain fallback permitted
└── every other failure         → FAIL CLOSED
```

Failures such as access denial, locked storage, corruption, identity
mismatch, duplicate state, entitlement problems, unexpected OS errors,
or provider integrity failures must not trigger fallback.

The implementation should use typed internal failure categories rather
than string/error-code matching scattered through the application.

------------------------------------------------------------------------

## 3. Phase 2: freeze authority/domain identifier derivation before bootstrap implementation

Before implementing `ACPTrustDomainAuthorityStore`, explicitly freeze
how these values are derived and related:

-   trust-domain ID;
-   authority ID;
-   authority-key/SPKI ID;
-   anchor certificate ID;
-   credential IDs.

The bootstrap state machine must not invent platform-specific identifier
relationships.

The implementation should recompute identifiers from canonical portable
artifacts where the architecture requires that behavior, rather than
trusting persisted copies.

### Add to startup verification

On every authority load:

``` text
stored metadata
      ↓
load protected key
      ↓
derive canonical SPKI
      ↓
recompute key/authority/domain identifiers
      ↓
validate anchor DER/profile/self-signature
      ↓
prove possession
      ↓
compare every persisted relationship
      ↓
ACTIVE or FAIL CLOSED
```

------------------------------------------------------------------------

## 4. Phase 2: distinguish recoverable incomplete bootstrap from destructive reset

The
`absent → key reserved → anchor generated → metadata committed → active`
model is good, but every intermediate state should be classified as
either:

-   automatically recoverable;
-   safely discardable before trust-domain commitment;
-   requires explicit operator recovery/reset.

Do not allow "cleanup" code to silently cross the point at which a
trust-domain identity has become externally observable.

Define a clear **trust-domain commitment point** in Phase 2.

After that point, failure recovery must preserve that domain or require
an explicit destructive new-domain operation.

------------------------------------------------------------------------

## 5. Phase 3: keep commissioner authorization separate from authority signing

`ACPAppleEnrollmentCoordinator` should not infer issuance authority
merely because the local process hosts the trust-domain signing key.

Preserve:

``` text
commissioner authorization
        ≠
authority signing capability
```

The enrollment machinery should produce a sealed
`ACPIssuanceAuthorization`. The credential issuer should independently
require that sealed authorization plus its own authority policy before
signing.

A commissioner may conduct enrollment without possessing or directly
accessing the authority signing capability.

This keeps the implementation compatible with the application-neutral
authority model and future Conductor deployments.

------------------------------------------------------------------------

## 6. Phase 3: review whether instance IDs belong in durable issuance identity

The plan binds issuance authorization to commissioner and candidate
**node and instance IDs**.

Before freezing this, classify each identifier:

-   durable cryptographic identity;
-   enrollment-attempt correlation;
-   process/session instance metadata.

An ephemeral application/process instance ID should be useful for
replay/correlation protection but should not accidentally become part of
the durable credential identity unless the frozen security contract
explicitly requires it.

Document which bindings survive restart and which exist only to bind a
single ceremony.

------------------------------------------------------------------------

## 7. Phase 3: define the exact trust-commitment point

Make the trust transition explicit:

``` text
confirmed SPAKE2+
      ↓
valid human approval
      ↓
sealed issuance authorization
      ↓
credential issued
      ↓
candidate transactional install
      ↓
candidate durable reload
      ↓
certificate/policy validation
      ↓
possession proof
      ↓
authenticated install confirmation
      ↓
journal commit
      ↓
TRUSTED
```

No earlier step may produce final trusted-peer state.

Explicitly test crashes after each transition.

The commissioner must be able to distinguish:

-   credential signed;
-   credential delivered;
-   credential installed;
-   possession proven;
-   enrollment committed.

These are not interchangeable states.

------------------------------------------------------------------------

## 8. Phase 4: define the authoritative credential selector

The two-slot lifecycle is appropriate, but the plan should specify
exactly how ACP determines which credential is authoritative after
restart.

Do not rely only on timestamps or "newest certificate wins."

Prefer a durable generation/journal rule with:

-   monotonic generation;
-   explicit active slot;
-   transaction/checksum integrity;
-   credential ID;
-   state-machine phase.

A staged credential must never become active merely because it exists in
Keychain.

------------------------------------------------------------------------

## 9. Phase 4: include authority-key loss during lifecycle operations

Add fault cases where the trust-domain authority signing capability
becomes unavailable during:

-   renewal reservation;
-   certificate generation;
-   replacement;
-   revocation publication.

The expected result should preserve the last valid node credential and
fail the new lifecycle operation cleanly.

Authority failure must not corrupt candidate credential state.

------------------------------------------------------------------------

## 10. Phase 5: freeze active-session revocation policy in Phase 1

The plan currently states:

-   `hardened_terminate` by default;
-   `explicit_audited_grace` by persisted configuration.

This is security policy, not merely revocation implementation behavior.

Move the normative decision into **Phase 1 --- Freeze the security
contract** or explicitly reference an already-frozen contract.

Phase 5 should implement that frozen policy, not originate it.

If the policy is not already frozen, do not silently make
`hardened_terminate` normative during implementation.

------------------------------------------------------------------------

## 11. Phase 5: define offline revocation freshness precisely

"Bounded offline freshness" needs an exact model before implementation.

Freeze:

-   signed `issuedAt`;
-   optional/required `nextUpdate`;
-   maximum accepted age;
-   clock-skew allowance;
-   behavior when the local clock is untrusted;
-   behavior after restart;
-   whether locally authoritative nodes can always use their own newest
    durable state;
-   what a disconnected peer does when its last snapshot ages out.

The policy should explicitly balance fail-closed security with
show-network availability.

Do not make internet connectivity part of revocation correctness.

------------------------------------------------------------------------

## 12. Phase 5: separate revocation state from replacement metadata

The plan correctly says replacement relationships are informational.
Strengthen this:

A replacement credential must independently satisfy normal
authentication and authorization.

Never infer:

``` text
old credential permissions
        ↓
automatic inheritance
        ↓
replacement credential
```

unless local authorization policy explicitly maps the same node identity
to those permissions.

Certificate replacement must not become an authorization-transfer
mechanism.

------------------------------------------------------------------------

## 13. Phase 6: do not cryptographically bind certificate identity to application role as if the certificate asserted that role

The plan says to bind validated certificate identity to ACP Hello "node
and role claims."

Node identity should be cryptographically matched to the certificate.

Role claims are different. Certificates establish identity and
trust-domain membership only.

Recommended model:

``` text
certificate
    → proves node identity + trust domain

HELLO role claim
    → authenticated message claim

local authorization policy
    → determines whether that authenticated node
      may assume/use the claimed role
```

A role mismatch should fail authorization/session admission as defined
by policy, but the implementation must not imply that the X.509
credential itself grants the role.

This should align Phase 6 with Phase 7.

------------------------------------------------------------------------

## 14. Phase 6: freeze TLS resumption behavior rather than using "unqualified resumption"

Replace the phrase "unqualified resumption" with an explicit policy.

Define whether production ACP Full profile:

-   disables resumption entirely for v1; or
-   permits only a precisely qualified form that preserves certificate
    identity, revocation, exporter/channel binding, expiry, and policy
    revalidation.

Until that behavior is fully specified and tested, the safest v1
qualification posture is to disable resumption rather than leave a
vaguely conditional path.

0-RTT should remain prohibited.

------------------------------------------------------------------------

## 15. Phase 6: make transport admission and session authorization separate gates

Recommended sequence:

``` text
TLS/mTLS validation
      ↓
authenticated transport capability
      ↓
HELLO/exporter identity binding
      ↓
authenticated ACP peer
      ↓
role/capability negotiation
      ↓
local authorization
      ↓
operation admission
```

Do not let successful mTLS imply application authorization.

Likewise, a valid HELLO must not create permissions by itself.

------------------------------------------------------------------------

## 16. Phase 7: define authorization-decision lifetime and binding

"One authorization decision object per operation" is good. Freeze what
that decision is bound to:

-   authenticated session ID;
-   authenticated principal/node;
-   credential ID/generation;
-   local policy revision;
-   role assignment revision;
-   negotiated capability revision;
-   operation type;
-   operation target/scope where relevant;
-   lifecycle/revocation generation;
-   decision creation/consumption state.

Authorization decisions should be non-transferable between sessions and
non-replayable.

For long-running operations, define whether authorization is checked
only at admission or revalidated at explicit checkpoints.

------------------------------------------------------------------------

## 17. Phase 7: audit failure must have operation-class policy

The plan says audit failure must follow a frozen policy and cannot
silently grant access. Good, but avoid one universal rule.

Define at least:

-   security-administration operations;
-   trust/issuance/revocation operations;
-   ordinary control operations;
-   safety-critical live-show operations.

For security-administration operations, inability to produce required
audit evidence may reasonably fail closed.

For live-show control, blindly failing every operation because an audit
sink is unavailable could itself create an operational hazard.

Freeze the behavior per operation class.

Audit failure must never **grant additional authority**, but
availability policy should be deliberate.

------------------------------------------------------------------------

## 18. Add resource-exhaustion limits to every security state machine

The plan mentions bounds in several places, but make them a
cross-cutting requirement.

Freeze limits for:

-   concurrent enrollments;
-   issuance reservations;
-   staged credentials;
-   revocation entries;
-   snapshot size;
-   audit queue;
-   pending authorization decisions;
-   TLS handshakes;
-   unauthenticated connections;
-   retry rates;
-   per-peer failures;
-   journal growth.

Test exhaustion and recovery.

No unauthenticated peer should be able to force unbounded durable writes
or memory growth.

------------------------------------------------------------------------

## 19. Add explicit monotonic-clock vs wall-clock rules

Several phases depend on expiry, freshness, deadlines, certificate
validity, and replay windows.

Specify which decisions use:

-   monotonic process clock;
-   trusted/validated wall clock;
-   persisted wall-clock observations;
-   ACP clock-skew policy.

Use monotonic time for in-process deadlines where possible.

Certificate validity and durable revocation freshness necessarily
involve wall time and should use the frozen ACP clock policy.

A wall-clock jump must not resurrect expired enrollment authorization or
replay windows.

------------------------------------------------------------------------

## 20. Strengthen checkpoint gates

After each checkpoint, add:

-   targeted restart/fault-injection suite for the phases just
    completed;
-   secret/log redaction audit;
-   public API/symbol fabrication audit;
-   concurrency/race suite;
-   resource-limit tests.

For Checkpoints C and D, also run a minimal real authenticated
client/server smoke test rather than relying solely on unit tests.

------------------------------------------------------------------------

## 21. Strengthen the final definition of completion

Before declaring Phases 1--7 complete, require the two-process all-up
path to use:

-   real production Apple custody;
-   real durable authority state;
-   real SPAKE2+ provider;
-   real credential issuance;
-   real Keychain installation;
-   complete process termination/restart;
-   real TLS 1.3 mTLS;
-   real HELLO/exporter binding;
-   real authorization;
-   real revocation publication/consumption.

At least one qualification path should be free of mocks for all
security-critical transitions.

The required scenario should include:

``` text
fresh authority + fresh candidate
        ↓
confirmed enrollment
        ↓
issuance + durable installation
        ↓
terminate both processes
        ↓
restart
        ↓
mTLS + HELLO + authorized operation
        ↓
credential rotation/replacement
        ↓
restart
        ↓
mTLS + authorized operation
        ↓
revocation
        ↓
reconnect rejected
```

------------------------------------------------------------------------

# Recommended revised execution structure

The existing seven phases can remain intact.

Apply the amendments above, then execute through the existing
checkpoints:

``` text
Checkpoint A
Phase 1 + Phase 2
→ protected custody and durable authority

Checkpoint B
Phase 3 + Phase 4
→ sealed enrollment and crash-safe credentials

Checkpoint C
Phase 5 + Phase 6
→ durable revocation and authenticated transport

Checkpoint D
Phase 7
→ centralized authorization and audit
```

The principal change is that **security-policy decisions must be frozen
before the phase that implements them**.

In particular, freeze before implementation:

-   authority/domain identifier derivation;
-   trust-domain commitment point;
-   enrollment trust-commitment point;
-   active-session revocation policy;
-   offline revocation freshness;
-   TLS resumption policy;
-   authorization-decision lifetime;
-   audit-failure policy by operation class;
-   clock semantics;
-   resource limits.

# Overall assessment

The proposed plan is suitable for completing the Swift production
security path. No major architectural rewrite is recommended.

The most important amendments are:

1.  prevent persisted metadata from becoming security evidence;
2.  keep commissioner, authority, transport authentication, role claims,
    and authorization rigorously separate;
3.  freeze revocation, resumption, audit, clock, and offline behavior
    before implementing them;
4.  define crash/restart commitment points explicitly;
5.  make the final qualification path genuinely production-backed rather
    than mock-complete.

With these changes, the plan should provide a strong gate for moving ACP
from security construction into sustained Prism/Remote all-up
integration testing.
