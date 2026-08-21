# Remote/Prism Feature Coverage

ACP Workbench discovers project-specific controls from Prism's published Remote surface. It does not hard-code production control IDs or look names. Checked-in scenarios use the IDs from the ACP reference fixture and can be copied for a Prism project fixture.

## Implemented mechanisms

| Area | Support |
|---|---|
| Song/show commands | `navigate` supports browse, select, load, next, previous, and GO; surface-defined start, stop, section, restart, and hold controls use `invoke` |
| Lighting | Surface-defined buttons, toggles, sliders, and encoders; explicit desired values for dimmer/blackout |
| Global Looks | Dynamically discovered look controls and selector/button invocation |
| Free Play and busking | Dynamically discovered actions; value and momentary interactions |
| Momentaries | BEGIN/END, lease capture, graceful-release cleanup, authority-owned dirty-disconnect fail-safe testing |
| Monitoring | Snapshot/delta, Remote control, navigation, presentation, warning/error, session, and health messages retained in the authoritative view and transcript |
| Surface sync | Inline compatibility mode and production chunked resource transfer/activation |
| Automation | Strict JSON/YAML scenarios, correlations, state assertions, timeouts, JSON/JUnit reports, JSONL transcripts, and stable exit codes |

## Checked-in executable scenarios

- GO disposition plus authoritative navigation/state publication
- Explicit blackout set plus authoritative `output.blackout` delta
- Momentary fog BEGIN/lease/END plus authoritative active/inactive publications

These are smoke/conformance seeds, not a claim that every Prism feature is already implemented. Project-dependent cases—named Global Looks, stop-effects, restart-section, automatic-progression hold, and project Busk controls—must be instantiated from the surface Prism publishes for the test project.

## Authoritative-state invariant

Command disposition and displayed state are separate. `command.ack` clears pending command bookkeeping but never mutates confirmed view state. Only target-published snapshots, deltas, Remote state, navigation/presentation state, health, warnings, and errors update the simulated Remote view.

The scenario runner correlates ACKs to the most recent intent and searches authoritative state from the intent boundary, allowing valid state publication either before or after the terminal ACK. Missing state publication remains a test failure.

