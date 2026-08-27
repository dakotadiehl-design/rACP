# Aurora Remote Profile

Status: **Normative profile with current implementation notes**
Last reconciled: **2026-08-27**

Normative companion to `Aurora_ACP_Remote_Profile_Implementation_Spec.md`.

Remote expresses operator intent. Conductor/Prism own state and execution. Remote never drives DMX, Art-Net, MIDI, or vendor I/O.

## Profiles

Negotiate `aurora.remote.prism.v1` in `session.hello.profiles` (Conductor: reserved `aurora.remote.conductor.v1`). The registry family name remains `remote`. Swift exposes these as `ACPRemoteProfileID.prismV1` / `.conductorV1`.

Surfaces use a stable `surface_id`. `layout_id` remains a one-minor compatibility alias for the same UUID. Swift production APIs prefer `surfaceID`.

Before activation, Swift `ACPRemoteSurfaceValidator` checks SHA-256, client schema range, compatible profile, semantic allowlisted bindings, safety constraints, and rejects executable/script keys. Unknown control types are skipped, not executed. A rejected dynamic surface must not take down native song selection, GO, Master Dimmer, Blackout, or monitoring; the ACP session stays alive.

Remote permission identifiers (`observe`, `song.select`, `cue.execute`, …) are distinct from Remote roles (`remote.viewer`, `remote.operator`, …). Swift types them as `ACPRemotePermission` and `ACPRemoteRole`. Semantic Prism Remote 1.0 actions are allowlisted in `schema/constants.json` `remote.actions` and `ACPRemoteAction`.

## Discovery mapping

Discovery is informational and never authenticates or authorizes. Apple Bonjour service `_acp._tcp` advertises the same ACP endpoint identity as UDP multicast discovery: node id, instance id, WebSocket URL (default `ws://host:27421/acp`), encodings, profiles, and capability digest. TXT records must not include PINs, tokens, or permission grants. Clients still complete HELLO, session authentication, and server-side authorization after connecting.

## State and command recovery

Prism/Remote-ready authorities publish `state.snapshot` with `authority_epoch` + `revision` and `state.delta` with `authority_epoch` + `base_revision` + `revision` + `changes`. Epoch or base-revision mismatch requires a fresh snapshot. Lost acknowledgements are recovered with `command.status_request` / `command.status_report`. Typed `preconditions` fail closed as `precondition_failed` without executing the action.

## Capabilities

See `schema/constants.json` `remote.capabilities` and `remote.feature_capabilities`. Feature IDs (`look.global`, `song.loading`, `output.blackout`, …) are individually discoverable. Message registry rows still use `remote.*` capabilities.

## Messages

`remote.control.invoke` is the primary control path. Results reuse `command.ack` and `state.delta`.

Momentary begin/end are reliable. Fail-safe (`release_on_disconnect`, `max_hold_ms`) is owned by the authority.

## Roles

ACP node role `remote` is distinct from Remote capability roles (`remote.viewer`, `remote.operator`, `remote.busker`, `remote.show_navigation`, `remote.admin`). Layout metadata never grants access.

Wire policy:

- Permission identifiers and command dispositions are forward-compatible strings. Unknown permissions grant nothing; unknown dispositions are non-success and never confirm state. `schema/common/defs.schema.json` carries the known catalog as `x-known-values`, not a closed enum. New behavior is still gated by its negotiated feature/capability identifier.

- This is an ACP **1.2 profile extension**. New messages have `min_protocol` 1.2 and `min_capability_version` 1.0.
- Client `remote.hello` roles and device/Remote/participant IDs are untrusted claims. Effective roles come from server-side policy keyed by the authenticated transport/node principal only.
- If device, Remote, participant, or operator IDs affect admission, bind them through server-owned enrollment and reject mismatches. Never fall through from an unknown node to a client-provided identity key.
- The production Python entry point is `RemoteHost` wrapping `RemoteAuthority.handle(env, session)`. The host runs the lease-expiry scheduler, wakes an outbound publication flush on timer-originated events, drains subscription-filtered fanout into live sessions (with backpressure / gap tracking), and dispatches `resource.*` surface transfer plus `state.request`. Shutdown flushes safety outcomes before detaching sessions. `handle` derives session and peer from the established ACP Session and requires negotiated `remote.profile`, completed Remote hello, and authority-computed readiness. `handle_simulated` is a named simulator/test API only. Production defaults to the chunked `aurora.remote.surface` asset path; inline layout bodies are compatibility-only (`inline_surface` or negotiated `remote.surface.inline`). Confirmed lease expiry publishes inactive `remote.control.state`; failed release immediately publishes unverified control state plus a critical `error.report`.
- Hello-complete sessions start in `syncing_assets` / `syncing_state`. Sending `remote.layout.report` or `remote.control.snapshot` is delivery, not acknowledgement. The client must ack matching `layout_revision` + `layout_hash` and a delivered `snapshot_revision` via `remote.readiness`.
- A session that accepted a command is updated through the correlated `command.ack` (`snapshot_revision` in the result) and stays ready. Other sessions stay interactive unless they miss a delta (`mark_missed_delta`) and must resync.
- Required roles are independent predicates (operator, navigation, busker). Layout `permission` may only add a constraint, never replace action or safety constraints. Unknown actions/targets are rejected.
- Semantic apply/begin/refresh/end/force-release go through an injected `ActionRouter`. Protocol acknowledgement and snapshot revision advance only after a successful router result. `MemoryActionRouter` is the in-process default, not a Prism/Conductor adapter.
- `RemoteClient.request` / `invoke_wait` wait for the correlated terminal acknowledgement and update leases, values, and errors from it.
- Momentary end/cancel/refresh must present the exact issued lease and match the initiating session.
- Authority readiness is computed server-side. Client `remote.readiness` is an observation plus the explicit asset/snapshot ack contract.
- Same-revision layout updates are accepted only as identical replays after canonical-hash comparison.
- Unknown Remote types fail closed with `unsupported`. Client-to-authority handlers must stay in parity with the registry.
- Surfaces use a stable `surface_id` (`layout_id` is a one-minor alias). `schema_version` + `min_client_schema` / `max_client_schema` must intersect the client’s implemented range before activation.
- Free Play stores `return_context` (`return_song_id`, `return_position`, `return_cue_id`, `return_section_id`). Exit restores that context.
- Looks may carry `default_transition` and invoke-time `transition` (`transition_ms`, `transition_mode`, `transition_preset`). The provider executes the fade.
- `delivery: live_ephemeral` commands expire and are never replayed after reconnect. Navigation `kind=go` is live-ephemeral: it requires the same provider-bounded `issued_at` / `expires_at` / `max_age_ms` lifetime as control GO and is deduplicated by authenticated node plus command identity across replacement sessions. ACK is disposition only; displayed state comes from snapshots/deltas.
- Momentary leases expire on an authority scheduler that sleeps until the next monotonic deadline and does not wait for inbound traffic. BEGIN, refresh, END, disarm, layout/policy change, and shutdown reschedule the timer. Cancellation/shutdown runs a final durable release transaction.
- Restart recovery replays persisted holds through the same durable release transaction as disconnect/expiry. Failed physical releases stay unsafe (`release_pending`, `physical_active`) and are never reported inactive. Durable records include `expires_at_ms`, `release_pending`, `release_reason`, and `physical_active` (legacy records are migrated). Confirmed-inactive state is the only state that may be persisted empty.
- Layout activation is forward-only: a confirmed hardware release is never resurrected if a later release fails. Failed holds stay unsafe and the new layout is rejected.
- Fanout is filtered by each session's `state.request` subscriptions, authenticated permissions, and negotiated feature capabilities. A gap or authority-epoch change requires a fresh authorized snapshot before deltas resume.
- `RemoteClient` retransmits the original immutable invoke envelope for a given `invocation_id`, consumes publications, renews leases below deadline, sends END promptly, marks view/control state stale on disconnect or gaps, and cancels only live-ephemeral in-flight work. Ready requires a completed asset/snapshot sync.
- Remote action/transfer outcomes use the stable dispositions `unauthorized`, `unsupported`, `invalid_state`, `stale`, `expired`, `conflict`, `not_found`, and `rate_limited` (see `docs/ERROR_CODES.md`).
- Failsafe-required momentaries must be leasable (`max_hold_ms` > 0, not `hold_last_state`).
- Permissions (`observe`, `cue.execute`, `look.execute`, …) are advertised beside roles. Layout `permission` may name a role or a permission id.
- Legacy TLS identity metadata is the first `acp://<uuid>` SAN URI; it does not create an Aurora Trust principal. Aurora Trust 1.0 requires exactly one `urn:aurora:acp:node:<trust-domain-uuid>:<node-uuid>` SAN URI, an isolated ACP trust store, and equality with the verified HELLO trust domain and node ID. Common-name, DNS-ID, system-root, and legacy-SAN fallback are not used for authenticated control.
- Python `RemoteAuthority.handle` is the session-hosted **reference production engine** for this amendment. Rust `RemoteAuthority` and Swift `ACPRemoteAuthority` remain **non-production simulators** and do not implement the full Prism Remote profile. Shared JSON/CBOR vectors prove **codec compatibility**. Framed-TCP tests prove **session handshake, heartbeat, correlated state snapshot, and a chunk/activate/invoke exchange**. They do not prove live Aurora Remote production interoperability.
