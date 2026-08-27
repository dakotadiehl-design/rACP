# Checkpoint — ACP Phase 5 / 6 / 7 prototype (authority safety core, leases, blackout mapping)

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Date:** 2026-08-19  
**ACP tag:** `1.1.0-dev.2`

## Implemented

- `ACPRemoteAuthorityCore` (not a production host) keys policy on a caller-supplied authenticated node ID.
- Client-claimed roles cannot grant GO.
- Duplicate invocation IDs do not apply twice across session replacement.
- Momentary BEGIN grants a lease; expiry and disconnect enter the same release path.
- Simulated physical release failure remains `release_pending` and `physical_active`.
- Prism `PrismRemoteHostRouter` maps `cue.go` → `performance.go` and blackout set → `blackoutOn`.
- Prism admission maps `blackoutOn`/`blackoutOff` to explicit ShowAction keys (not toggle).

## Tests

ACP `swift test` — **33 passed** including 4 production-authority tests.

## Statement

This checkpoint proves selected safety-core behavior only. It does **not** satisfy
the Phase 4–7 production exit gates and does not authorize legacy deletion or
safety-sensitive deployment. A production host still requires authenticated
session binding, readiness, persistence/restart recovery, autonomous lease
scheduling, state publication, command recovery, backpressure, and audit.
