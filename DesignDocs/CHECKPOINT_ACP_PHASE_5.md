# Checkpoint — ACP Phase 5 / 6 / 7 (production authority, leases, blackout mapping)

**Date:** 2026-08-19  
**ACP tag:** `1.1.0-dev.2`

## Implemented

- `ACPRemoteProductionAuthority` (not the simulator) keys policy on authenticated node ID.
- Client-claimed roles cannot grant GO.
- Duplicate invocation IDs do not apply twice across session replacement.
- Momentary BEGIN grants a lease; expiry and disconnect enter the same release path.
- Simulated physical release failure remains `release_pending` and `physical_active`.
- Prism `PrismRemoteHostRouter` maps `cue.go` → `performance.go` and blackout set → `blackoutOn`.
- Prism admission maps `blackoutOn`/`blackoutOff` to explicit ShowAction keys (not toggle).

## Tests

ACP `swift test` — **33 passed** including 4 production-authority tests.

## Statement

Phases 5–7 core safety behavior is review-satisfied at the ACP/Prism adapter layer. Proceed to Phase 8 deletion.
