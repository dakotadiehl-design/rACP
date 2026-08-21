# Architecture

`WorkbenchEngine` is the sole application service. The CLI and GUI submit the same operations and consume the same typed event stream. The engine wraps the repository's `aurora-acp` SDK for wire/session behavior.

Profiles provide identity, capabilities, actions, synchronization, and publication handling. `remote-prism` is the first profile. Scenarios operate on the engine and produce a shared `RunResult`, consumed by console, JSON, and JUnit reporters.

Confirmed view state is publication-only. `command.ack` changes command disposition, not displayed state. The Remote profile delegates this invariant to ACP's `RemoteClient.apply_publication` and retains evidence event IDs for assertions.

The engine supports multiple connections by ID. GUI models are bounded views over the event stream; the JSONL transcript is the durable execution record.

