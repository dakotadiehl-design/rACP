# Prism ACP Final AFK Implementation Directive

**Status:** Authoritative implementation directive  
**Date:** 2026-08-19  
**Execution model:** User AFK; continue autonomously through all phases  
**Repositories:** `AuroraCommunicationsProtocol` and `Aurora` (Prism)  
**Supersedes:** The implementation sequencing in `Prism_ACP_Integration_and_Legacy_Remote_Replacement_Plan.md` where corrected by `Prism_ACP_Integration_Plan_Recommended_Corrections.md`

## 1. Mission

Complete the replacement of Prism's legacy remote-control system with ACP.

The work is complete only when Prism has one remote network stack, one security model, one state authority, and one semantic mutation path:

```text
Remote / Conductor / other ACP client
                |
                v
               ACP
                |
                v
           AuroraACP
                |
                v
            PrismACP
                |
                v
      ControlActionRouter
                |
                v
      authoritative Prism state
                |
                v
       Prism lighting systems
```

ACP must never directly mutate fixtures, programmer internals, SwiftUI views, output drivers, Art-Net, sACN, or raw DMX.

This is a total replacement. Do not retain a compatibility listener, private protocol fallback, hidden legacy setting, old credential path, or bundled browser remote.

## 2. AFK Execution Contract

The user intends to be away while this work is performed. Do not pause after producing a plan, finishing a phase, encountering an ordinary test failure, or discovering review findings.

For every phase:

1. Inspect the current repository state and applicable instructions.
2. Implement the phase.
3. Run the phase-specific verification suite.
4. Perform a fresh code review of the complete phase diff.
5. Record every finding with severity and evidence.
6. Fix every blocking finding and all reasonably in-scope non-blocking findings.
7. Re-run affected tests and the full phase gate.
8. Re-review the remediation diff.
9. Repeat until the phase review is satisfied.
10. Record a checkpoint report.
11. Proceed immediately to the next phase without waiting for user confirmation.

An initial successful test run does not replace code review. A code review that finds no issue does not replace tests. Both are mandatory at every checkpoint.

### 2.1 Review satisfaction rule

A phase is review-satisfied only when:

- No P0 or P1 findings remain.
- No known correctness, security, state-consistency, concurrency, data-loss, or live-control safety defect remains.
- No test required by the phase is failing or silently skipped.
- Generated files and their canonical sources agree.
- Documentation and support-matrix claims match actual behavior.
- Any intentionally deferred P2/P3 item is outside the phase's required behavior, recorded with rationale, and does not weaken a later safety gate.

Do not waive a finding merely to advance the phase.

### 2.2 Conditions that do not justify stopping

Continue autonomously when:

- A build or test fails because of code written in this effort.
- A design needs a reasonable implementation choice already constrained by this directive.
- Generated files drift.
- A review finds defects.
- A local package must be rebuilt.
- A test harness needs improvement to prove the required behavior.
- A prerequisite inside either repository is incomplete but within scope.
- Documentation needs correction.
- A non-destructive refactor is required to preserve the architecture.

### 2.3 Genuine stop conditions

Stop only when meaningful progress requires one of the following:

- Credentials, signing identities, hardware, or external services unavailable to the implementation environment.
- A destructive or irreversible operation not already authorized by this directive.
- A product decision with materially different safety or user-visible outcomes that neither attached plan resolves.
- Repository corruption or an external dependency outage that cannot be worked around safely.
- A required filesystem or execution permission is denied after the normal approval mechanism has been attempted.

Before stopping, exhaust safe in-scope alternatives and leave a precise blocker report containing the failed command, evidence, work completed, and exact action needed from the user.

## 3. Current Repository Facts

Treat these as the starting baseline, but verify them before editing:

- The canonical Swift package is at the ACP repository root.
- The library product and import module are named `AuroraACP`.
- The executable product `acp-framed-hello` is an interoperability fixture only.
- The old `swift/` package tree has been consolidated into the root package.
- Prism's Xcode application target is internally named `Aurora`; its product is Prism.
- The ACP local package has been manually added to Prism's generated Xcode project.
- `AuroraACP` is linked to the `Aurora` application target.
- `acp-framed-hello` is not linked to the application.
- Prism's `project.yml` is the XcodeGen source of truth and must be updated to preserve the ACP dependency.
- Prism still contains the legacy `AuroraRemote` TCP/HTTP/PIN/browser stack.
- ACP wire protocol version and Swift package release version are independent version spaces.

Do not repeat the Swift package conversion. Do not split `AuroraACP` back into the old `ACPModel`, `ACPEncoding`, and `ACPSession` products.

## 4. Permanent Architecture Rules

### 4.1 One semantic command authority

Correct:

```text
ACP envelope
    -> AuroraACP validation/session authority
    -> PrismACP authorization and translation
    -> ControlActionRouter
    -> authoritative semantic commit
    -> ACP acknowledgement and state publication
```

Forbidden:

```text
ACP -> AuroraOutput
ACP -> fixture state
ACP -> programmer internals
ACP -> DMX
ACP -> SwiftUI view mutation
```

Local Prism UI, MIDI, music automation, future Conductor control, and ACP Remote should converge at the same semantic authority boundary.

### 4.2 Generic ACP versus Prism integration

`AuroraACP` owns:

- Encoding and schema validation.
- Registry admission.
- Negotiation, sessions, sequencing, and correlation.
- Generic WebSocket transport behavior.
- Generic discovery semantics and abstractions.
- Command identity, deduplication, and status-query semantics.
- Generic Remote Profile sessions, subscriptions, readiness, transfers, leases, and release scheduling.

`PrismACP` owns:

- Prism service lifecycle and configuration.
- Stable Prism identity storage.
- Product authorization and enrollment policy.
- Prism state projections.
- Semantic action translation into `ControlActionRouter`.
- Availability evaluation.
- Semantic execution-disposition persistence adapter.
- Prism audit integration and diagnostics.
- Prism Remote surfaces and product bindings.

Do not implement a second generic session, command-ledger, subscription, transfer, or lease engine in Prism.

### 4.3 State authority

A successful socket write never means an action was applied. An acknowledgement reports command disposition. Authoritative snapshot/delta state reports the resulting truth.

State publication is event-driven. Do not preserve the legacy 200 ms `RemoteSnapshot` polling model.

### 4.4 Discovery and trust

Discovery tells a client where an ACP endpoint may be found. It never authenticates Prism or authorizes the client.

Any Apple Bonjour mapping must expose the same ACP endpoint identity and semantics as normative ACP discovery. Do not invent a private Prism discovery or trust model. Keep Apple-specific Bonjour/Network.framework code platform-scoped so ACP discovery semantics remain portable.

### 4.5 ACP disabled

When ACP is disabled, Prism must have:

- No ACP discovery advertisement.
- No ACP listener.
- No active ACP sessions.
- No active transfers.
- No resumable live-ephemeral commands.
- No renewable Remote leases.
- No background ACP network traffic.

Persisted unsafe-release records may remain for local recovery and warnings, but they must not imply an active network service.

## 5. Mandatory Checkpoint Review Procedure

At the end of every phase, perform the following review independently of implementation reasoning.

### 5.1 Diff review

Inspect:

- The complete repository diff for the phase.
- Newly added and deleted files.
- Public APIs and concurrency annotations.
- Session and lifecycle state transitions.
- Error paths, cancellation paths, and shutdown paths.
- Authentication and authorization boundaries.
- Schema, registry, generated resources, and vectors.
- Tests for false positives, skips, and insufficient assertions.
- Documentation and support claims.
- Unrelated user changes to ensure they were preserved.

### 5.2 Required review categories

Classify findings as:

- **P0:** Immediate live-control, security, data-loss, or destructive failure.
- **P1:** Release blocker; correctness, protocol, concurrency, safety, or interoperability failure.
- **P2:** Important robustness, maintainability, or coverage issue that should be fixed in the current phase when in scope.
- **P3:** Minor cleanup or future improvement with no current correctness effect.

### 5.3 Review questions

Every checkpoint review must answer:

1. Can malformed or unauthorized input reach Prism semantics?
2. Can an acknowledgement claim success before Prism commits?
3. Can retries execute a once-only action twice?
4. Can state revisions skip, regress, or cross epochs incorrectly?
5. Can disconnect, cancellation, or shutdown leave an effect active?
6. Can a failed release be reported inactive?
7. Can telemetry or asset traffic delay performance traffic without bound?
8. Can the ACP-disabled state still open or advertise a socket?
9. Can generated project or schema files drift from their source of truth?
10. Can legacy remote behavior remain reachable?
11. Does the implementation create a direct ACP-to-engine/output shortcut?
12. Are tests proving established-session behavior rather than handshake-only success?

### 5.4 Checkpoint report

Create or update a checkpoint report for each phase containing:

- Phase objective.
- Files changed.
- Tests and commands run.
- Exact pass/fail/skip counts.
- Review findings and remediation.
- Remaining explicitly deferred items.
- ACP tag/commit and Prism commit used for the checkpoint.
- Statement that the phase is review-satisfied.

Do not claim completion without recorded evidence.

## 6. Phase 0A — Repair and Freeze the Existing AuroraACP Baseline

### Objective

Preserve the completed root Swift package and establish a reproducible baseline before new ACP feature work.

### Work

1. Inspect the ACP worktree, package manifest, generated resources, tests, and existing migration reports.
2. Do not repeat or redesign the package conversion.
3. Reconcile all package-conversion changes into a coherent commit-ready state.
4. Run the current package and interoperability suite from the repository root.
5. Decide the package tag from actual API/repository readiness:
   - Use `1.0.0` only if the repository-wide package API is ready for that stability commitment.
   - Otherwise use an appropriate prerelease such as `1.0.0-rc.1`.
6. Record the exact tag candidate and commit SHA.
7. Do not conflate the package version with ACP wire version `1.2`.

### Verification

At minimum:

```bash
swift build
swift test
python3 scripts/check_registry.py
python3 scripts/freeze_vectors.py
python3 tests/interop/test_framed_cross.py --sdk swift --suite hello
python3 tests/interop/test_framed_cross.py --sdk swift --suite session
python3 tests/interop/test_framed_cross.py --sdk swift --suite remote
python3 tests/interop/test_framed_cross.py --sdk swift --suite negative
```

Also run the repository's documented Python, Rust, lint, type-check, and cross-language gates applicable to the baseline.

If the environment lacks a required toolchain, do not count that gate as passing. Use an available runner or record a genuine external blocker.

### Review focus

- Root package contains all required resources.
- No production consumer depends on the deleted `swift/` tree.
- `import AuroraACP` works from an external dummy package.
- Registry and schema-pack copies cannot drift silently.
- README and package documentation match the actual layout.
- No tag is created from an incoherent or unverified worktree.

### Exit gate

- Baseline is reproducible and review-satisfied.
- Exact ACP commit is recorded.
- Package version decision is justified.
- Proceed automatically to Phase 0B.

## 7. Phase 0B — ACP Prism/Remote Readiness

### Objective

Implement the generic ACP facilities required by Prism without another package-layout rewrite.

### Required ACP capabilities

#### State consistency

Define:

```text
authority_epoch
    Changes when the semantic state universe is replaced, authority changes,
    or continuity cannot be guaranteed.

revision
    Monotonically increases within one authority epoch.
```

Snapshots carry:

```text
authority_epoch
revision
resources
```

Deltas carry:

```text
authority_epoch
base_revision
revision
changes
```

Epoch mismatch or base-revision mismatch requires a fresh authorized snapshot. Never guess through missing state.

#### Command recovery

Add or formalize:

```text
command.status_request
command.status_report
```

The generic command ledger must retain:

```text
command_id
idempotency_key
origin_node_id
origin_instance_id
origin_principal
origin_session_id
operation
received_at
disposition
result
resulting_epoch
resulting_revision
expires_at
```

Identity must survive replacement sessions for the retention window and must not rely solely on `session_id`.

#### Preconditions

Support typed predicates including:

```text
authority_epoch equals X
revision equals X
revision at_least X
show_id equals X
current_cue_id equals X
resource field equals X
```

Evaluate preconditions atomically with command admission. Failure returns `precondition_failed` and performs no action.

#### Capability and availability

Capability means the endpoint implements an action. Availability means the action may be used now. Publish availability as authoritative state with stable reasons such as:

```text
no_show_loaded
not_armed
output_offline
permission_denied
wrong_mode
sync_required
interlock_active
resource_unavailable
```

#### Provenance

Carry enough authenticated origin information for Prism to record:

```text
node_id
instance_id
session_id
principal_id
command_id
source_type
display_name
```

#### Priority and coalescing

Support application-layer traffic classes:

| Class | Examples | Behavior |
|---|---|---|
| Safety/performance | Blackout, GO, momentary END | Reserved capacity; never coalesced |
| Interactive | Look activation, set operations | Bounded latency |
| State | Cue/output deltas | Coalesce only when semantically safe |
| Background | Assets and manifests | Pause under pressure |
| Telemetry | Metrics and diagnostics | Aggregate or drop first |

Continuous values may use `latest_value_wins` with a stable coalescing key. GO, BACK, cue fire, BEGIN, and END must never be coalesced.

#### Semantic surfaces

Surface controls should describe semantic action, category, control type, safety class, availability binding, permission, constraints, and restrained presentation hints. Do not serialize Prism UI layout or executable behavior.

#### Transport and discovery

- Implement generic ACP WebSocket transport/session behavior in `AuroraACP`.
- Keep Apple listener lifecycle composition in Prism where product-specific.
- Define or document the Apple Bonjour mapping without creating private Prism discovery semantics.
- Keep ACP discovery portable.

#### Session hardening

- Negotiation fails closed.
- Handshake and requests have timeouts that actually bound I/O.
- Payload schemas are validated before application delivery.
- Registry admission enforces message, role, capability, QoS, and protocol rules.
- Established-session interop tests exchange real application envelopes.

### Verification

- Schema and registry generation/drift checks.
- Golden JSON/CBOR vectors for every new or modified message.
- Invalid-message corpus additions.
- Python reference tests.
- Swift tests.
- Rust tests where shared wire behavior changes.
- Negative negotiation, timeout, schema, sequence, and admission tests.
- Python-to-Swift and Rust-to-Swift established-session interop.
- WebSocket session tests beyond HELLO.

### Review focus

- No stylistic wire redesign unrelated to required functionality.
- Backward compatibility rules are explicit.
- Command status cannot leak results across principals.
- Preconditions are evaluated at the semantic execution boundary.
- Queue policy cannot starve performance messages.
- Discovery metadata never grants authorization.

### Exit gate

- ACP Prism/Remote readiness feature set is review-satisfied.
- New ACP prerelease/release tag and SHA are recorded as appropriate.
- Proceed automatically to Phase 1.

## 8. Phase 1 — Preserve Xcode Linkage and Establish PrismACP

### Objective

Make the existing ACP package dependency reproducible through XcodeGen and create the Prism integration boundary.

### 8.1 Repair the XcodeGen source of truth first

Prism's generated `.xcodeproj` currently contains the manually added ACP dependency, while `project.yml` may not. Fix `project.yml`; do not rely on hand-editing the generated project.

The authoritative configuration must represent the equivalent of:

```yaml
packages:
  AuroraPackage:
    path: .
  AuroraACPPackage:
    path: ../AuroraCommunicationsProtocol

targets:
  Aurora:
    dependencies:
      - package: AuroraACPPackage
        product: AuroraACP
```

Preserve all existing dependencies. Do not add `acp-framed-hello` to the application target.

Required regeneration test:

1. Build the current Prism project.
2. Update `project.yml`.
3. Regenerate `Aurora.xcodeproj` using the repository script.
4. Confirm `AuroraACP` remains linked to target `Aurora`.
5. Confirm `acp-framed-hello` is absent from app frameworks and dependencies.
6. Build Prism.
7. Regenerate a second time.
8. Confirm no unexpected diff on the second regeneration.
9. Build again.

### 8.2 Create `PrismACP`

Add a dedicated Prism library target/module. Suggested roles:

```text
PrismACPService
PrismACPConfiguration
PrismACPIdentityStore
PrismACPAuthorizationPolicy
PrismACPStateSource
PrismACPStatePublisher
PrismACPActionRouter
PrismACPAvailabilityProvider
PrismACPExecutionDispositionStore
PrismACPAuditStore
PrismACPRemoteAdapters
PrismACPDiagnostics
PrismACPController
```

Names may follow repository conventions, but the boundaries must remain.

Implement:

- Stable Prism ACP `node_id` storage.
- Per-launch `instance_id`.
- ACP lifecycle composition.
- Connection supervision.
- Authorization-policy boundary.
- State-source and state-publisher protocols.
- Structured diagnostics.
- Loopback session tests.

Do not advertise mutation capabilities.

### 8.3 Disable legacy startup

Stop starting the legacy TCP and HTTP listeners once the ACP integration lifecycle begins. During intermediate development builds, remote mutation may be temporarily unavailable. Do not silently fall back to the old protocol.

No released build may expose both remote stacks.

### Review focus

- XcodeGen is genuinely authoritative and reproducible.
- No duplicate package declaration exists across manual project state, `project.yml`, and package manifests.
- `acp-framed-hello` remains unlinked.
- `PrismACP` does not depend directly on output drivers or SwiftUI view types.
- Legacy listeners cannot start through another code path.
- ACP service failure cannot affect show execution.

### Exit gate

- Project regeneration is stable.
- `import AuroraACP` builds in Prism.
- `PrismACP` loopback foundation is review-satisfied.
- Legacy network startup is disabled.
- Proceed automatically to Phase 2.

## 9. Phase 2 — Read-Only ACP LAN

### Objective

Exercise real networking safely before exposing mutations.

Implement:

- ACP WebSocket listener using generic `AuroraACP` transport/session machinery.
- Apple Bonjour advertisement mapped to ACP endpoint identity and profiles.
- Session authentication/enrollment foundation.
- Read-only capability negotiation.
- Subscriptions.
- Heartbeat and goodbye.
- Network-silent disable.
- Correct startup and shutdown ordering.

Initially support only:

```text
HELLO
NEGOTIATE
SUBSCRIBE
STATE_SNAPSHOT
STATE_DELTA
HEARTBEAT
GOODBYE
```

Do not advertise live mutation capability.

Test:

- Real LAN discovery and connection.
- Wi-Fi latency and stalls.
- Interface changes.
- Sleep and wake.
- Bonjour loss and reappearance.
- Socket cancellation.
- Slow receivers and bounded queues.
- Reconnection and epoch resynchronization.
- ACP enable/disable transitions.

### Lifecycle order

Startup:

1. Load/create stable identity.
2. Create instance identity.
3. Load enrollment, authorization, and revocation policy.
4. Load command/hold recovery state.
5. Reconcile persisted unsafe holds.
6. Initialize authoritative state and epoch.
7. Create listener without advertisement.
8. Accept only after policy and state are ready.
9. Start discovery last.

Shutdown:

1. Stop discovery.
2. Stop accepting sessions.
3. Reject new mutations.
4. Release active momentaries through the durable release transaction.
5. Flush safety outcomes where possible.
6. Close sessions.
7. Stop transfers/publication.
8. Stop listener.
9. Persist required state.

### Review focus

- Discovery cannot race ahead of policy readiness.
- Disable is truly network silent.
- Cancellation bounds receive/send operations.
- Backpressure is finite.
- Network callbacks do not mutate UI or engine state directly.
- No mutation type is accidentally negotiated.

### Exit gate

- A real client can discover, connect, synchronize, disconnect, and reconnect.
- Read-only LAN phase is review-satisfied.
- Proceed automatically to Phase 3.

## 10. Phase 3 — Event-Driven Authoritative Prism State

### Objective

Replace the legacy polling snapshot with revisioned state domains.

Define the general namespace immediately:

```text
prism.show
prism.song
prism.performance
prism.cue
prism.looks
prism.programmer
prism.busk
prism.output
prism.music
prism.health
```

Initially populate:

```text
prism.show
prism.performance
prism.cue
prism.output
prism.health
```

Do not serialize private Prism domain objects. Use stable wire-safe projections.

On semantic commit:

```text
Prism truth changes
    -> projection changes
    -> revision advances
    -> subscription-filtered delta is queued
```

Do not advance revision merely because a message is transmitted.

Remove the live 200 ms `RemoteSnapshot` timer once ACP state publication replaces it. Do not delete the whole legacy module until the final deletion phase, but make the polling path unreachable.

### Verification

- Snapshot plus deltas reconstructs identical state.
- Revision never regresses or skips without an explicit resync condition.
- New show/authority continuity replacement changes epoch.
- Gap and epoch mismatch force an authorized snapshot.
- Subscription and permission filters are enforced.
- Slow clients cannot block Prism state commits or output.

### Review focus

- State events come from authoritative semantic boundaries.
- No independent Remote state can disagree with Prism.
- Threading and actor isolation are correct.
- Snapshot generation is consistent under concurrent state changes.
- Domain permissions do not leak unauthorized state.

### Exit gate

- Event-driven state is review-satisfied.
- Legacy polling is unreachable and no timer remains active.
- Proceed automatically to Phase 4.

## 11. Phase 4 — Narrow Semantic Mutations

### Objective

Introduce remote control gradually through the existing Prism semantic authority.

### Required mutation pipeline

```text
ACP admission
    -> authenticated principal
    -> authorization
    -> capability and availability
    -> command preconditions
    -> PrismACP semantic translation
    -> ControlActionRouter
    -> authoritative commit/rejection
    -> retained command disposition
    -> authoritative state delta
```

### Rollout order

1. GO in test/non-live contexts.
2. Explicit cue fire.
3. A safe non-momentary look/busk action if a real semantic action exists.
4. Master intensity with latest-value-wins coalescing.
5. Production GO after ledger and precondition validation.

Do not add blackout yet. Do not add raw programmer mutation.

Forbidden migration APIs include:

```text
setFixtureChannel(...)
setDMX(...)
setProgrammerAttribute(...)
```

### Command semantics

- Once-only commands are keyed by authenticated origin plus command identity.
- Lost acknowledgements are recovered through command-status query.
- Duplicate GO never advances twice.
- GO should include epoch and observed current cue preconditions.
- Preconditions are checked atomically with execution admission.
- Acknowledgement is emitted only after semantic disposition is known.
- Resulting epoch/revision is recorded where applicable.

### Provenance and audit

Extend the shared semantic boundary to capture:

```text
local_ui
remote
conductor
midi
music_engine
automation
bridge
system
```

Maintain a bounded audit history with timestamp, origin, operation, target, disposition, resulting epoch/revision, and safety outcome. Do not store credentials.

### Review focus

- No route around `ControlActionRouter`.
- No early success acknowledgement.
- Ledger cannot collide across principals or sessions.
- Retention and replacement-session recovery are bounded.
- Preconditions close local-versus-remote races.
- Master updates coalesce without reordering safety/performance commands.
- Audit metadata is trustworthy and privacy-conscious.

### Exit gate

- Narrow semantic control is review-satisfied.
- Production GO replay/precondition tests pass.
- Proceed automatically to Phase 5.

## 12. Phase 5 — Production Swift Remote Profile Authority

### Objective

Provide a production Remote Profile host without implementing generic Remote behavior inside Prism.

The existing Swift simulator must not be quietly promoted. Implement or complete an explicitly production-grade authority in `AuroraACP`, conforming to the Python reference behavior.

Required generic behavior:

- Authenticated `remote.hello`.
- Server-derived roles and permissions.
- Surface schema/version negotiation.
- Chunked surface asset transfer and activation.
- Layout and snapshot acknowledgement.
- Readiness gating.
- Subscription-filtered fanout.
- Deduplication across replacement sessions.
- Command-status recovery.
- Lease scheduling independent of inbound traffic.
- Durable hold release and restart recovery.
- Backpressure and gap recovery.

Prism injects only:

```text
PrismRemotePolicy
PrismRemoteSurfaceProvider
PrismRemoteActionRouter
PrismRemoteStateSource
PrismRemoteHoldPersistence
```

### Review focus

- Production entry point cannot call simulator-only APIs.
- Authenticated transport/session identity is the policy key.
- Client role claims cannot grant access.
- Surface metadata cannot grant permission.
- Readiness requires completed asset and state acknowledgement.
- Timer-originated lease events are published.
- Failed releases remain unsafe.
- Python reference and Swift authority outcomes agree.

### Exit gate

- Production Remote authority audit is review-satisfied.
- Live cross-language Remote interoperability passes.
- Proceed automatically to Phase 6.

## 13. Phase 6 — Leased Momentary Controls

### Objective

Prove the complete lease and release safety model before enabling safety-relevant effects.

Start with a harmless test momentary.

Protocol behavior:

```text
BEGIN
    activation_id
    requested_lease_ms

GRANT
    activation_id
    lease_id
    granted_lease_ms
    renew_before_ms

RENEW
    activation_id
    lease_id

END / CANCEL
    activation_id
    lease_id
```

Required tests:

- Normal END.
- Gesture cancellation.
- Lost BEGIN acknowledgement.
- Duplicate BEGIN.
- Renewal.
- Wrong lease rejection.
- Dirty disconnect.
- Lease expiry without inbound traffic.
- Page/control/surface removal.
- Authorization removal.
- Prism shutdown.
- Authority restart.
- Persisted hold recovery.
- Physical release failure.

If release fails, publish:

```text
release_pending = true
physical_active = true or unknown
```

Never publish confirmed inactive without physical confirmation.

### Review focus

- Every termination path enters the same durable release transaction.
- Timer scheduling uses monotonic deadlines appropriately.
- Restart recovery cannot resurrect a released hold.
- Layout/policy changes cannot silently orphan a hold.
- Shutdown does not cancel before durable release state is recorded.

### Exit gate

- Harmless leased momentary and every failure path are review-satisfied.
- Proceed automatically to Phase 7.

## 14. Phase 7 — Blackout and Safety-Sensitive Review

### Objective

Add blackout only after an independent safety review.

Prefer explicit commands:

```text
blackoutOn
blackoutOff
```

Do not use `toggleBlackout` as the remote semantic operation.

Required behavior:

- Commands are idempotent.
- Duplicate blackout does not oscillate state.
- Clearing blackout is separately authorized and audited.
- Reconnect never clears blackout.
- ACP failure never blocks local blackout.
- Discovery failure has no effect on blackout.
- State reports authoritative blackout truth.
- Blackout persists according to Prism safety policy.

Only after the blackout review is satisfied may fog, strobe, blinders, bump, flash, or similar controls be considered. Each safety class requires explicit authorization, availability, lease, release, and audit policy.

### Exit gate

- Independent blackout code review has no P0/P1 findings.
- Safety and retry tests pass.
- Proceed automatically to Phase 8.

## 15. Phase 8 — Delete Legacy AuroraRemote Completely

### Objective

Remove every element of Prism's private remote system.

Delete rather than adapt:

```text
Sources/AuroraRemote/AuroraRemote.swift
Sources/AuroraRemote/RemoteHost.swift
Sources/AuroraRemote/RemoteListenerState.swift
Sources/AuroraRemote/RemoteMessages.swift
Sources/AuroraRemote/RemoteProtocolClient.swift
Sources/AuroraRemote/RemoteSessionManager.swift
Sources/AuroraRemote/RemoteWebServer.swift
Sources/AuroraRemote/Resources/Web/index.html
```

Remove:

- The `AuroraRemote` library product and target.
- Old `RemoteController`.
- Legacy AppModel properties and composition.
- `RemoteSnapshot` and `RemoteShowAction`.
- PIN generation and storage.
- Bearer tokens and session credentials.
- TCP port `8742`.
- HTTP port `8743`.
- `/api/hello`, `/api/command`, and `/api/snapshot`.
- Bundled browser remote.
- Legacy listener status and settings.
- Legacy 200 ms polling.
- Legacy tests and diagnostics assumptions.

Replace old tests with ACP integration tests. Do not mechanically preserve old protocol types under new names.

Do not migrate legacy PINs or tokens into ACP enrollment. Preserve an old enabled preference only if it transitions to a safe, non-controlling ACP enrollment state; otherwise require explicit enablement.

If browser control returns in the future, it must be a separate ACP client using the same ACP protocol and security model.

### Source removal gate

Active production code must contain no references to:

```text
AuroraRemote
RemoteHost
RemoteWebServer
RemoteSessionManager
RemoteProtocolClient
RemoteClientMessage
RemoteServerMessage
RemoteCodec
RemoteSnapshot
RemoteShowAction
remotePIN
8742
8743
/api/hello
/api/command
/api/snapshot
```

Historical documents may retain clearly marked history. Active architecture, setup, and testing documentation must describe ACP as the only remote system.

### Runtime removal gate

Launch Prism and prove:

- Port `8742` is closed.
- Port `8743` is closed.
- No legacy HTTP route responds.
- No browser remote is served.
- Only the configured ACP endpoint is advertised.
- ACP disabled opens and advertises nothing.
- Disabling ACP closes sessions/transfers and safely releases holds.
- Legacy credentials cannot authorize ACP.

### Architecture removal gate

Prove:

- Every ACP mutation reaches the shared semantic authority.
- No `PrismACP` target depends directly on output drivers or view types.
- No parallel Remote state exists.
- Revisions advance only from authoritative commits.
- Generic Remote behavior remains in `AuroraACP`.
- No compatibility shim preserves the private protocol.

### Exit gate

- Source, runtime, architecture, interoperability, and safety reviews are satisfied.
- Proceed automatically to final whole-system review.

## 16. Final Whole-System Review

After all phases, perform a fresh review across both repositories rather than relying on phase-local conclusions.

### 16.1 Full validation

Run all applicable:

- ACP Python, Swift, and Rust tests.
- Schema, registry, generated-pack, and vector checks.
- Cross-language interoperability suites.
- Prism Swift package tests.
- Prism Xcode Debug and Release builds.
- PrismACP integration and lifecycle tests.
- Real LAN discovery/WebSocket tests.
- Removal-gate runtime probes.
- Safety, retry, precondition, lease, and blackout tests.

### 16.2 Final review scope

Review:

- Complete ACP diff from the frozen baseline.
- Complete Prism diff from before integration.
- Public API compatibility and Sendable/actor correctness.
- Security and identity binding.
- Command replay and status recovery.
- State epoch/revision correctness.
- Backpressure and queue behavior.
- Startup, disable, disconnect, and shutdown.
- Legacy deletion.
- Documentation and version claims.

Fix findings and repeat the relevant full gates until satisfied.

### 16.3 Completion criteria

Do not declare completion until all are true:

- Prism ships one remote stack: ACP.
- `PrismACP` is the sole product integration layer.
- `AuroraACP` is reproducibly linked through XcodeGen.
- `acp-framed-hello` is not linked into Prism.
- Legacy TCP, HTTP, browser, PIN, token, polling, codec, and client code is deleted.
- Ports `8742` and `8743` are closed at runtime.
- ACP disabled is network silent.
- State is event-driven, domain-based, and epoch/revision correct.
- Approved actions use the shared `ControlActionRouter` path.
- Once-only commands are replay-safe and reconnect-recoverable.
- Preconditions prevent stale-view races.
- Capability and availability are separate.
- Provenance and bounded audit history are present.
- Performance traffic is protected from background pressure.
- Continuous values coalesce safely.
- Momentary effects are lease-based and failure-safe.
- Blackout is explicit, idempotent, persistent, authorized, and audited.
- Remote surfaces remain semantic and native-client rendered.
- Real LAN, lifecycle, interoperability, and safety tests pass.
- Every phase and final review is recorded as satisfied with evidence.

## 17. Required Final Handoff

When all work is complete, provide one concise final handoff containing:

- ACP package tag and commit SHA used by Prism.
- Prism commit or working-tree checkpoint.
- High-level architecture implemented.
- Legacy components deleted.
- Tests run with exact results.
- Code-review rounds and remediated findings.
- Runtime proof that ports `8742` and `8743` are closed.
- Runtime proof that ACP disabled is network silent.
- Known non-blocking limitations, if any.
- Clear statement whether all completion criteria passed.

Do not finish with a proposed next phase. Complete the next safe in-scope phase automatically. Stop only after the whole directive is complete or a genuine stop condition in Section 2.3 is reached.
