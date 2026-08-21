# ACP Workbench Implementation Plan

## 1. Purpose

ACP Workbench is a cross-platform developer and conformance-testing application for the Aurora Communications Protocol. It simulates one Aurora family member while treating another member as a black-box system under test.

The first supported workflow is testing Prism's ACP Remote profile without requiring the production Remote or Conductor applications. The architecture must also support Prism, Conductor, Lyric, Bridge, and future Aurora roles without redesigning the core.

ACP Workbench has two equal front ends:

- A desktop GUI for interactive connection, control, inspection, and scenario execution.
- A headless CLI for local automation and CI test execution.

Both front ends use the same engine, profile implementations, scenario runner, assertions, and reporting code. Protocol behavior must never be implemented independently in the GUI or CLI.

## 2. Goals

- Connect to an ACP implementation over supported transports and complete a real ACP session handshake.
- Simulate configurable Aurora node identities and negotiated profiles.
- Send, receive, validate, inspect, and record ACP envelopes in JSON or CBOR.
- Provide profile-specific actions without coupling the application core to any product.
- Run deterministic, repeatable scenarios from the GUI or CLI.
- Generate human-readable, JSON, JSONL transcript, and JUnit XML output.
- Exercise success, failure, timing, reconnect, and malformed-input behavior.
- Reuse the repository's `aurora-acp` Python SDK as the protocol authority.
- Remain useful for manual development even before a complete conformance suite exists.

## 3. Non-goals

- Reimplementing ACP codecs, schemas, session negotiation, or profile authority logic.
- Sharing Prism product implementation code with the tester.
- Driving DMX, Art-Net, sACN, MIDI, OSC, or production hardware.
- Claiming full ACP conformance from a successful handshake or a small smoke suite.
- Replaying live-show commands without explicit safeguards and operator intent.
- Making PySide6 a dependency of headless or CI installations.

## 4. Architectural principles

### 4.1 Black-box testing

The target is observed only through its ACP connection and externally supplied configuration. Workbench may reuse the normative ACP SDK but must not import target product internals. This prevents a product bug from being duplicated in its tests.

### 4.2 Headless core

All long-running behavior lives in an asynchronous application engine. The GUI subscribes to engine events and submits commands; the CLI invokes the same commands and waits for results.

### 4.3 Profile plugins

Family-specific behavior is supplied by registered profile plugins. Adding a family member should add a plugin, scenarios, and presentation metadata rather than modify transport or session code.

### 4.4 Data-driven scenarios

Common test flows are expressed in version-controlled YAML. Python extensions are reserved for behavior that cannot be expressed clearly through standard steps and assertions.

### 4.5 Observable execution

Every connection transition, transmitted envelope, received envelope, validation result, assertion, timeout, and transport error becomes a timestamped engine event. GUI views, console output, reports, and transcripts derive from this event stream.

### 4.6 Safe defaults

Workbench defaults to loopback/plaintext development endpoints. Non-loopback targets, replay, hazardous profile actions, or scenarios tagged `live_show_unsafe` require an explicit command-line flag or GUI confirmation.

## 5. Proposed repository layout

```text
tools/acp-workbench/
├── IMPLEMENTATION_PLAN.md
├── README.md
├── pyproject.toml
├── src/acp_workbench/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── core/
│   │   ├── engine.py
│   │   ├── commands.py
│   │   ├── events.py
│   │   ├── connection.py
│   │   └── clock.py
│   ├── transports/
│   │   ├── base.py
│   │   ├── websocket.py
│   │   └── framed_tcp.py
│   ├── profiles/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── core.py
│   │   └── remote_prism.py
│   ├── scenarios/
│   │   ├── model.py
│   │   ├── loader.py
│   │   ├── runner.py
│   │   ├── steps.py
│   │   └── assertions.py
│   ├── recording/
│   │   ├── transcript.py
│   │   └── redaction.py
│   ├── reports/
│   │   ├── console.py
│   │   ├── json_report.py
│   │   └── junit.py
│   └── gui/
│       ├── application.py
│       ├── main_window.py
│       ├── models.py
│       ├── controllers.py
│       └── widgets/
├── scenarios/
│   ├── core/
│   └── remote-prism/
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

The existing `python/src/acp` package remains responsible for envelopes, JSON/CBOR encoding, validation, negotiation, WebSocket/framed transports, and session behavior. Workbench should promote missing reusable behavior into `acp` rather than copy it locally.

## 6. Core component design

### 6.1 Engine

`WorkbenchEngine` owns active connections, simulated node instances, scenario runs, and the event stream. Its public API is independent of GUI and command-line libraries.

Representative operations:

```python
await engine.connect(ConnectionRequest(...))
await engine.disconnect(connection_id, graceful=True)
await engine.send(connection_id, envelope)
await engine.invoke_action(connection_id, action_id, parameters)
result = await engine.run_scenario(connection_id, scenario, run_options)
async for event in engine.events():
    ...
```

The engine must support dependency injection for the clock, ID generator, and transport factory so automated tests can be deterministic.

### 6.2 Commands and events

Commands describe requested work. Events describe observed facts. They should be typed dataclasses and safe to serialize.

Initial event categories:

- Connection lifecycle and negotiated session details
- Envelope transmitted and received
- Decode and schema validation results
- Profile state changes
- Scenario and step lifecycle
- Assertion results
- Warnings, timeouts, and failures

Events receive a monotonically increasing sequence number in addition to a wall-clock timestamp. Reports must preserve event ordering even when timestamps match.

### 6.3 Connection lifecycle

The lifecycle is explicit:

```text
disconnected -> connecting -> transport_ready -> negotiating
             -> synchronizing -> ready -> closing -> disconnected
```

Any state may transition to `failed`. Profile plugins can define synchronization requirements but cannot bypass session negotiation.

One process may host multiple independent connections. The first GUI release may display one connection at a time, but the engine API must not assume a singleton.

### 6.4 Transport adapters

Transport adapters normalize connection establishment and diagnostics while delegating wire behavior to the ACP SDK.

Initial support:

1. WebSocket client, including `ws` development connections and `wss` credentials.
2. Framed TCP client for cross-language and low-level interoperability testing.
3. In-process linked transport for Workbench's own tests.

Later support:

- Discovery listener/browser
- Server/listen mode
- Packet capture metadata
- Transport interruption and corruption hooks

### 6.5 Profile plugin contract

A profile plugin describes how a simulated role interacts with a target role.

```python
class WorkbenchProfile(Protocol):
    metadata: ProfileMetadata

    def local_identity(self, config: ProfileConfig) -> Identity: ...
    def requested_profiles(self) -> list[str]: ...
    def requested_capabilities(self) -> list[str]: ...
    async def session_ready(self, context: ProfileContext) -> None: ...
    async def handle_envelope(self, context: ProfileContext, envelope: Envelope) -> None: ...
    def actions(self, state: ProfileState) -> Sequence[ActionDefinition]: ...
    async def invoke(self, context: ProfileContext, action: ActionInvocation) -> None: ...
    def scenario_extensions(self) -> Sequence[ScenarioStepFactory]: ...
```

`ProfileMetadata` includes a stable plugin ID, simulated roles, valid target roles, ACP profile identifiers, display name, and supported capability range.

Plugins are registered explicitly in the first release. Python package entry-point discovery may be added after the interface stabilizes.

### 6.6 Core profile

The core profile is available to every simulated node and covers:

- Session HELLO/HELLO_ACK
- Protocol and capability negotiation
- Heartbeat behavior
- State request/snapshot correlation
- Graceful goodbye
- Invalid envelope and unsupported-message behavior
- Timeout, reconnect, sequence, and duplicate handling

### 6.7 Remote-to-Prism profile

The first product profile simulates a Remote connected to Prism through `aurora.remote.prism.v1`.

Initial responsibilities:

- Send `remote.hello` after session establishment.
- Receive permissions, layout/surface transfer, readiness, and control snapshots.
- Complete asset and snapshot acknowledgement requirements.
- Expose controls from the received surface rather than hard-code a Prism layout.
- Invoke discrete, value, navigation, and momentary controls.
- Correlate terminal `command.ack` messages.
- Track snapshot revisions, deltas, leases, and readiness.
- End active momentary controls on normal shutdown.
- Support deliberate dirty disconnect and lease-expiry tests.

The production `RemoteClient` in the ACP SDK should be used or extended for Remote semantics. Workbench-specific UI state must remain outside that class.

## 7. Scenario system

### 7.1 File format

Scenarios use versioned YAML with strict parsing. Unknown fields are errors.

```yaml
schema_version: 1
id: remote-prism.go-authoritative-state
name: Remote GO is acknowledged and confirmed by authoritative state
simulate: remote
target: prism
profile: aurora.remote.prism.v1
tags: [smoke, remote, command]
timeout: 15s

steps:
  - connect: {}
  - wait_until:
      state: ready
      timeout: 10s
  - invoke:
      control_id: cue_go
  - expect:
      type: command.ack
      correlation: previous_invocation
      where:
        payload.status: applied
      timeout: 2s
  - expect_state_change:
      resources: [cue.current, cue.next]
      authority: target
      after: previous_invocation
      timeout: 2s
```

### 7.2 Standard steps

- `connect` and `disconnect`
- `wait_until`
- `send`
- `invoke`
- `expect`
- `expect_none`
- `expect_state_change`
- `sleep` using the injectable scenario clock
- `set_variable`
- `capture`
- `repeat`
- `parallel` for explicitly safe branches
- `interrupt_transport`
- `reconnect`
- `assert_state`

Values may reference scenario variables, captured envelope fields, and deterministic generated IDs. Expression support must be intentionally limited; arbitrary Python evaluation is forbidden.

### 7.3 Assertions

Assertions must produce structured results containing expected value, actual value, evidence event IDs, duration, and failure reason. Initial assertions cover:

- Message type and direction
- Correlation and invocation IDs
- JSON-path-like payload equality and existence
- Schema validity
- Ordering
- Count and absence within a time window
- Connection/profile state
- Maximum response duration
- Separation of command disposition from authoritative state confirmation
- Proof that displayed state originates from a target-published snapshot or delta

For stateful commands, scenarios may assert two separate outcomes:

1. **Disposition:** Prism accepted, applied, or rejected the requested intent through a correlated `command.ack`.
2. **Authoritative state:** Prism subsequently published the observable result through an ACP snapshot, delta, Remote control state, navigation state, presentation state, health message, or error/warning message.

An `applied` acknowledgement alone must not satisfy an authoritative-state assertion. The Workbench profile model may display an operation as pending after acknowledgement, but it must not update confirmed view state from the requested value. Confirmed state changes only when a qualifying target publication is received. Tests must also cover mismatched outcomes, missing publications, stale revisions, and publications received before or after the acknowledgement.

### 7.4 Failure behavior

A failed assertion fails the scenario but does not automatically abort cleanup. Each run has a guaranteed cleanup phase for graceful shutdown and active momentary release. `--fail-fast` controls whether later scenarios execute, not whether safety cleanup runs.

## 8. CLI design

Installable entry point:

```text
acp-workbench
```

Initial commands:

```bash
# Show registered roles, profiles, scenarios, and actions.
acp-workbench list profiles
acp-workbench list scenarios --profile remote-prism

# Connect interactively and stream decoded traffic.
acp-workbench connect \
  --target ws://127.0.0.1:27421/acp \
  --simulate remote \
  --profile remote-prism

# Send a JSON or CBOR envelope after establishing a session.
acp-workbench send \
  --target ws://127.0.0.1:27421/acp \
  --simulate remote \
  --file envelope.json

# Run one file or a registered suite.
acp-workbench test \
  --target ws://127.0.0.1:27421/acp \
  --suite prism \
  --report-junit artifacts/junit.xml \
  --report-json artifacts/results.json \
  --transcript artifacts/session.jsonl

# Validate scenario syntax without connecting.
acp-workbench validate scenarios/
```

Common flags include target URL, simulated identity, profile, encoding, global timeout, TLS material, deterministic seed, log level, transcript path, and the explicit live-show safety acknowledgement.

### 8.1 Exit codes

Exit codes form part of the automation contract:

| Code | Meaning |
|---:|---|
| 0 | All requested operations or tests passed |
| 1 | One or more protocol assertions failed |
| 2 | Invalid arguments, configuration, or scenario definition |
| 3 | Target connection or transport failure |
| 4 | Workbench internal error |
| 5 | Operation refused by a safety policy |

Signal interruption should produce a best-effort cleanup and the conventional shell signal exit status.

### 8.2 Configuration precedence

From highest to lowest priority:

1. CLI flags
2. Environment variables prefixed `ACP_WORKBENCH_`
3. Explicit configuration file
4. User configuration file
5. Built-in defaults

Secrets and private keys must not be placed in scenario files or transcripts.

## 9. GUI design

The GUI uses PySide6 and communicates with the asynchronous engine through a narrow controller layer. Qt widgets must not call ACP SDK operations directly.

Initial main-window areas:

- Connection editor and connection/session status
- Simulated role and profile selector
- Profile action panel generated from `ActionDefinition` metadata
- Bidirectional message timeline with filters
- Envelope detail view showing decoded data and validation results
- Scenario browser, runner, and structured results
- Profile state view for readiness, permissions, revisions, and leases
- Transcript export and report actions

GUI actions generate the same engine commands used by the CLI. Running a scenario in the GUI must yield the same assertions and report model as running it headlessly.

The message timeline must remain responsive under load by using a bounded presentation model. The engine and optional transcript writer retain authoritative history; the GUI may virtualize or discard old rendered rows.

## 10. Recording, replay, and reports

### 10.1 Transcript format

Use append-only JSON Lines. Each line contains transcript schema version, event sequence, timestamp, monotonic offset, connection ID, direction, encoding, message metadata, decoded envelope when available, validation outcome, and optional raw bytes encoded as base64.

Raw payload capture is configurable. Default transcripts should redact configured sensitive fields and TLS material. Redaction must be represented in the record so omitted data cannot be mistaken for transmitted data.

### 10.2 Replay

Replay is not part of the first vertical slice. When added, distinguish:

- Offline replay into the inspector and assertion engine.
- Live retransmission to a target.

Live retransmission requires explicit acknowledgement, refuses stale live-ephemeral commands by default, and never rewrites timestamps or IDs silently.

### 10.3 Reports

All reporters consume one `RunResult` model:

- Console summary for developers
- JSON report for programmatic analysis
- JUnit XML for CI systems
- JSONL transcript as execution evidence

Reports include Workbench version, ACP SDK version, scenario hashes, target configuration excluding secrets, negotiated protocol/profile details, timing, failures, and artifact paths.

## 11. Packaging and dependencies

ACP Workbench is a separate Python distribution in the monorepo and depends on the local `aurora-acp` package during development.

Suggested dependency groups:

```toml
[project]
requires-python = ">=3.11"
dependencies = [
    "aurora-acp==1.2.*",
    "PyYAML>=6.0",
]

[project.optional-dependencies]
gui = ["PySide6>=6.7"]
dev = [
    "pytest>=7.4",
    "pytest-asyncio>=0.23",
    "pytest-cov>=4.1",
    "ruff>=0.6",
    "mypy>=1.11",
]
```

If JUnit output can be generated safely with the Python standard library, avoid adding a reporting dependency.

Installation targets:

```bash
# CI/headless
python3 -m pip install -e './python[dev]' -e './tools/acp-workbench[dev]'

# Desktop development
python3 -m pip install -e './python[dev]' -e './tools/acp-workbench[gui,dev]'
```

Standalone application bundling for macOS and Windows should be evaluated only after the GUI behavior stabilizes.

## 12. Test strategy

### 12.1 Unit tests

- Configuration precedence and secret redaction
- Engine state transitions
- Command/event serialization
- Profile registry and metadata validation
- Scenario parsing and strict schema validation
- Variable capture and assertion semantics
- Exit-code mapping
- Report generation
- Transcript ordering and recovery from partial final records

### 12.2 Integration tests

- In-process linked transport using the ACP session implementation
- Python WebSocket handshake against a test server
- Framed TCP handshake
- Remote-to-Prism synchronization with a controlled fake authority
- Momentary begin/end, timeout, dirty disconnect, and reconnect
- Malformed and unsupported envelope handling
- CLI subprocess execution and artifact verification

### 12.3 Cross-language tests

Extend the repository's existing Rust/Swift framed interoperability fixtures to run selected core Workbench scenarios. These prove transport and session compatibility; profile-specific claims require profile-specific target fixtures.

### 12.4 GUI tests

- Controller tests without Qt widgets
- Qt model/view tests for filtering and bounded history
- Smoke test for launch, connect, scenario run, and clean shutdown
- Manual visual verification on macOS initially; Windows verification before distribution

### 12.5 Quality gates

- Ruff and mypy clean
- Unit and integration tests passing
- No GUI import during headless CLI startup
- At least 80% coverage for Workbench core and scenario packages
- Deterministic scenario-runner tests under a fake clock
- Clean cancellation without leaked tasks or active momentary controls

## 13. Implementation milestones

### Milestone 0: Decisions and protocol gaps

Deliverables:

- Confirm Prism's ACP endpoint, transport, TLS, authentication, and server/client orientation.
- Document the minimum Prism Remote handshake and synchronization sequence.
- Identify reusable SDK gaps revealed by the current placeholder `acp remote connect` command.
- Decide whether the existing `acp-sim` and `acp-inspect` entry points become compatibility wrappers or remain separate.

Exit criteria:

- A checked-in connection sequence and known-good manual Prism endpoint configuration.
- No unresolved architectural dependency between Workbench and Prism internals.

### Milestone 1: Headless engine and core CLI

Deliverables:

- Workbench package scaffold and CLI entry point.
- Typed commands/events, engine lifecycle, configuration, and structured logging.
- WebSocket connection using the ACP SDK.
- Generic simulated identity and core ACP profile.
- `list`, `connect`, `send`, and `validate` CLI commands.
- JSONL transcript writer.

Exit criteria:

- CLI connects to a controlled ACP server, completes HELLO negotiation, prints traffic, and exits cleanly.
- Headless installation imports no GUI dependency.

### Milestone 2: Scenario runner and reports

Deliverables:

- Strict YAML loader and versioned scenario model.
- Standard steps, variables, captures, timeouts, and assertions.
- Console, JSON, and JUnit reports.
- Stable exit-code contract.
- Core handshake, heartbeat, goodbye, and negative scenarios.

Exit criteria:

- The same scenario produces deterministic results locally and in CI.
- Assertion failures reference transcript evidence.

### Milestone 3: Remote-to-Prism vertical slice

Deliverables:

- `remote-prism` profile plugin.
- Remote hello and full readiness synchronization.
- Dynamic action definitions from the received Remote surface.
- Discrete GO invocation and correlated terminal acknowledgement.
- Authoritative cue/navigation state confirmation after GO; no optimistic local advancement.
- Initial Prism smoke suite.

Exit criteria:

- Workbench connects to Prism as a Remote, becomes ready, invokes GO, observes a correlated applied/rejected disposition, and—when applied—waits for Prism's authoritative cue/navigation publication before reporting the visible change as successful.
- The workflow runs from one non-interactive CLI command.

### Milestone 4: Desktop GUI

Deliverables:

- PySide6 application shell and async controller bridge.
- Connection/profile editor and status display.
- Message timeline and envelope inspector.
- Generated Remote control panel.
- Scenario browser, execution progress, results, and artifact export.

Exit criteria:

- The Milestone 3 workflow runs through the GUI without GUI-specific protocol code.
- The GUI and CLI produce equivalent `RunResult` data for the same scenario.

### Milestone 5: Remote conformance and resilience

Deliverables:

- Value and navigation actions.
- Momentary leases, refresh, END, forced disconnect, and expiry tests.
- Revision gaps, resynchronization, duplicate invocation, stale command, and malformed-input scenarios.
- Capability and permission matrix coverage.
- Safety tags and enforcement.

Exit criteria:

- Published coverage matrix maps Remote profile requirements to automated scenarios or documented manual tests.
- Cleanup is verified after every cancellation and failure path.

### Milestone 6: Additional Aurora family profiles

Implement profiles in the order required by product development. Each profile must provide metadata, actions, synchronization state, scenarios, fixtures, and coverage documentation.

Likely additions:

- Conductor-to-Prism
- Prism-to-Conductor
- Conductor-to-Lyric
- Conductor-to-Bridge
- Generic participant, state, health, configuration, asset, and resource-transfer suites

Exit criteria for each profile:

- No changes are required to core connection or scenario architecture.
- Profile scenarios run identically through GUI and CLI.

## 14. Initial Prism test catalog

The first useful suite should cover:

1. Successful ACP negotiation with the Remote/Prism profile.
2. Rejection of incompatible protocol or profile negotiation.
3. Remote hello admission and server-derived permissions.
4. Layout/surface transfer and integrity validation.
5. Snapshot delivery and readiness acknowledgement.
6. GO invocation with correct correlation, terminal acknowledgement, and authoritative current/next state publication.
7. Unsupported control rejection.
8. Unauthorized action rejection.
9. Duplicate invocation idempotency.
10. Expired live-ephemeral command rejection.
11. Momentary begin, refresh, and end.
12. Momentary release on dirty disconnect.
13. Snapshot revision gap and resynchronization.
14. Unknown optional-field tolerance.
15. Malformed or schema-invalid envelope rejection.
16. Graceful session goodbye and reconnect.

Every catalog entry must identify whether it is normative conformance, interoperability, resilience, or developer smoke coverage.

## 15. Prism/Remote feature coverage

The Prism suite must treat the following as an explicit product requirement matrix rather than relying only on generic control categories. A test is not considered covered until it has a checked-in scenario or a documented fixture-dependent manual test.

Prism remains authoritative in every row. Workbench sends operator intent, tracks the command disposition separately, and updates confirmed simulated-Remote state only from Prism-published ACP state.

### 15.1 Song and show control

| Feature | Workbench action | Required verification |
|---|---|---|
| Start/load song | Select a song where required, then request load/start | Correlated disposition followed by authoritative current-song, transport, and progression state |
| Stop song | Request stop | Authoritative stopped transport/progression state; no local optimistic stop |
| Select directly from setlist | Select a published setlist song ID | Selection/browsing state remains distinct from activation; current song changes only if Prism publishes it |
| Previous song | Send previous-song navigation intent | Authoritative current/next song publication and correct boundary behavior |
| Next song | Send next-song navigation intent | Authoritative current/next song publication and duplicate-request behavior |
| Advance / GO | Send live-ephemeral GO with idempotency and expiry metadata | Correlated ACK plus authoritative current/next cue or section changes; duplicate GO never advances twice |
| Next section | Send next-section navigation intent | Authoritative section/cue publication |
| Previous section | Send previous-section navigation intent | Authoritative section/cue publication and boundary behavior |
| Restart current section | Invoke the project-exposed restart-section semantic action | Authoritative section position/progress reset |
| Hold/pause automatic progression | Set the exposed hold/pause control to the desired state | Authoritative transport/progression hold state, including release/resume behavior |

The suite must test unavailable, unauthorized, invalid-state, stale, expired, and unsupported outcomes where applicable. Browsing a setlist must never itself alter the live current song.

### 15.2 Lighting control

| Feature | Workbench action | Required verification |
|---|---|---|
| Master Dimmer | Set the published grand-master slider/value control | Authoritative control value and confidence/revision; clamping or rejection outside the accepted range |
| Blackout | Send explicit desired blackout state, never blind toggle inversion | Authoritative blackout control/output state; reconnect must not clear blackout |
| Stop active effects | Invoke the published stop-effects semantic control | Authoritative active-effect/control state showing the resulting stop |
| Recall Global Looks | Invoke a dynamically published look control | Authoritative current-look/control-state publication matching the resolved Prism look |

The initial look fixture should include Slow Song, Rock, Country, Warm, Blue, Full Stage, Solo, and Crowd, while the Workbench UI and engine must discover look controls from Prism's surface rather than hard-code those names. Tests must cover missing looks, disabled looks, permission denial, and a Prism-side routing failure.

### 15.3 Ad-hoc and busking control

| Feature | Workbench action | Required verification |
|---|---|---|
| Enter Free Play | Invoke the published enter-Free-Play action | Authoritative mode plus preserved return context |
| Return to programmed setlist | Invoke exit/return action | Authoritative programmed mode and restored song/section/cue context |
| Project-defined Busk controls | Render and invoke controls dynamically from the active surface | Authoritative control state; unknown or removed controls are rejected/disabled |
| Momentary fog, blinders, strobes, and similar controls | BEGIN, lease refresh, END/cancel | Authoritative active/inactive state, lease identity, expiry, and fail-safe release behavior |

Momentary coverage includes touch release, cancellation, layout removal, graceful shutdown, dirty disconnect, lease expiry, duplicate messages, reconnect, concurrent holders, and failed physical release. A failed release must remain visibly unsafe/unverified rather than being presented as inactive.

### 15.4 Monitoring and feedback

The simulated Remote state model and GUI must expose, record, and test:

| Feedback | Expected ACP source |
|---|---|
| Current and next song | Authoritative navigation/presentation state or generic state snapshot/delta |
| Current and next section | Authoritative navigation/presentation state or generic state snapshot/delta |
| Current look | Published Remote control state or generic lighting state resource |
| Master Dimmer level | Published control state or authoritative output state resource |
| Blackout status | Published control state or authoritative output state resource |
| Song/progression state | Presentation/transport state and progress publications |
| Prism connection status | Workbench transport/session lifecycle plus Prism-published connection state when available |
| ACP connection and health | Session lifecycle, heartbeat, sequence/gap detection, and ACP health publications |
| DMX/output health | Generic ACP health/telemetry resources published by Prism or its authoritative output path |
| Important Prism warnings | Remote presentation warnings, `health.warning`, and relevant `error.report` publications |

Monitoring tests cover initial snapshot, incremental delta, unchanged value, out-of-order/stale revision, revision gap, reconnect, authority-epoch change, degraded confidence, warning appearance/clearance, and loss of subscription authorization. State becomes stale on disconnect or a detected gap and safety-sensitive actions remain disabled until reconciliation completes.

### 15.5 Authoritative-state conformance rule

This is a release-blocking invariant for the Remote-to-Prism profile:

> Remote sends intent. Prism decides, applies, acknowledges, and publishes authoritative state. Workbench must not treat the requested value or a successful socket write as state, and must not present an acknowledged command as a confirmed visible change until the corresponding Prism state publication arrives.

Each stateful feature scenario must therefore record and assert this sequence:

```text
intent sent -> pending -> command disposition -> authoritative publication -> confirmed view state
```

Allowed failure sequences include rejection, timeout, disconnect, and applied-without-state-publication. The last case is a test failure and leaves the simulated view state pending or stale; it must never synthesize the expected state locally.

The scenario report must retain separate timestamps and evidence references for intent, acknowledgement, authoritative publication, and confirmed view-state update. This permits latency reporting and makes false optimistic updates detectable.

## 16. Open decisions

Resolve these during Milestone 0 rather than embedding assumptions in the engine:

- Does Prism listen as the ACP session server, and on which development endpoint?
- Is the first Prism integration WebSocket-only or must framed TCP also be supported?
- What TLS and node enrollment mechanism will Prism require during development?
- Which Remote surface-transfer mode will Prism implement first?
- How will test-only Prism actions avoid affecting a real show or attached output hardware?
- Should test scenarios launch/stop Prism, or only connect to a separately managed process?
- Which existing `acp-sim` and `acp-inspect` command names must remain backward compatible?
- What is the canonical name: `ACP Workbench`, `acp-workbench`, or another product-facing name?

## 17. Definition of the first releasable version

Version 0.1 is complete when a developer can:

1. Install the headless package without PySide6.
2. Start Prism separately in an explicitly safe development configuration.
3. Run one CLI command that connects as a Remote, negotiates ACP 1.2 and `aurora.remote.prism.v1`, completes synchronization, invokes a configured GO control, verifies Prism's authoritative state publication separately from its acknowledgement, and writes JSON, JUnit, and transcript artifacts.
4. Launch the GUI, perform the same exchange interactively, inspect all envelopes, and run the same checked-in scenario.
5. Receive a nonzero documented exit code and actionable evidence when any protocol expectation fails.
6. Add a second profile plugin without modifying transport, engine, GUI connection management, or scenario-runner internals.
