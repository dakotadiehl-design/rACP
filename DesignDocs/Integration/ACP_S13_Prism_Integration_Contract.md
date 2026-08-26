# S13 Prism integration contract

Inspection evidence: `/Users/dakota/code/Aurora`, branch `main`, HEAD `c291e9bb034ac4d6e23345b833ca7db11edf6250`, clean at inspection. The repository was read-only.

## Current boundary

`Sources/PrismACP/PrismACPService.swift::serve` accepts a raw `ACPWebSocketConnection`, creates `ACPSession(... allowPlaintext: true)`, and establishes a principal from a claimed Remote node ID. `PrismACPController.apply` limits advertised mutation to loopback, but this is a migration safeguard rather than authentication. `remote.control.invoke` checks readiness and the local node-ID allowlist before `admit`, and `admit` eventually calls the installed host executor. The host executor is installed by `Sources/Aurora/Controllers/PrismACPController.swift` and reaches the shared `ControlActionRouter` path. Existing idempotency, readiness, surface, blackout-clear, and authoritative-state checks must be preserved.

## Required migration

1. Link both `AuroraACP` and `AuroraACPAppleSecurity` at a reviewed ACP release revision.
2. Replace the raw WebSocket listener and `ACPSession(transport:...allowPlaintext:true)` construction in `PrismACPService.acceptLoop/serve` with the qualified ACP Apple server connection factory and the authenticated-session initializer.
3. Treat discovery as an endpoint hint only. Advertise the qualified security profile and trust-domain identifier, never credentials.
4. Store the provider-produced `ACPAuthenticatedPrincipal` in each `PrismACPRemoteContext`. Delete node-ID-only principal construction and derive policy lookup keys from `ACPAuthorization.deviceIdentity`.
5. Make production mutation impossible for trusted-LAN sessions. Retain a separately typed view-only migration listener only if explicitly required.
6. Revalidate revocation and local policy on connection and epoch/policy changes. Terminate control sessions and release momentaries when authority is lost.
7. Extend the host-executor request so the `ControlActionRouter` boundary receives an authorization decision containing credential ID, authenticated node ID, policy revision, safety state, and audit correlation ID. Reject stale/missing decisions before dispatch.
8. Keep operator assignment separate from device identity and keep cached show/layout assets separate from credential reset.

Exact future files/symbols include `Sources/PrismACP/PrismACPService.swift` (`listener`, `acceptLoop`, `serve`, `handle`, `admit`, remote contexts), `PrismACPConfiguration.swift`, `PrismACPAuthorizationPolicy`, `PrismACPAction`, `Sources/Aurora/Controllers/PrismACPController.swift`, the host executor installation, and XcodeGen/package declarations in `Package.swift`, `project.yml`, and the generated project.

## Mandatory tests and completion

- Product code cannot construct evidence, a principal, or an authenticated session from a raw transport.
- Wrong root/domain/node/SAN, exporter mixup, revoked/expired credential, missing provider, resumption, and 0-RTT close before Remote readiness.
- Trusted LAN is view-only and cannot invoke any sensitive command.
- Every Remote mutation reaches `ControlActionRouter` exactly once with a current authorization decision; no ACP path reaches engine/output directly.
- Policy/revocation removal terminates authority and releases holds while assets remain cached.
- Existing readiness, stale-surface, idempotency, lease, blackout-clear, and authoritative-state suites remain green.
- macOS exact-target adapter and Prism integration qualification PASS.

Completion requires a separate Prism-writable job with ACP read-only, reviewed commits, and product qualification. Current status: `BLOCKED — product integration not yet performed`.
