# ACP v1.2 — normative summary

Status: **Normative**
Current baseline: **ACP 1.2 / Aurora Trust extension 1.0**

This is the current overview. Machine-readable schemas, registries, and constants have the authority order defined in [README.md](README.md). Older handoff PDFs and `DesignDocs/` records are historical inputs, not competing specifications.

ACP is the Aurora-family control plane. It is not Art-Net, sACN, DMX, MIDI, or OSC.

- Canonical encoding: CBOR under [WIRE_ENCODING.md](WIRE_ENCODING.md). JSON is required for humans and debug.
- Reliable transport: WebSocket, one envelope per message.
- Discovery: framed UDP multicast, with an Apple Bonjour mapping (`_acp._tcp`) of the same endpoint identity. Never authentication. Never safety-critical.
- Commands distinguish delivery, acceptance, application, and observed confidence.
- One owner per state kind. State is reconstructable via snapshots.
- Unknown optional fields are ignored on typed decode.
- Safety actions (blackout) are explicit, scoped, acked, logged, and state-reflected.
- Aurora Trust is an additive ACP 1.2 security extension defined in [SECURITY.md](SECURITY.md). Its Full Apple implementation exists; signed product-target custody qualification remains required. Discovery and peer claims never establish authentication or authorization.

See [STATE_MACHINES.md](STATE_MACHINES.md), [CAPABILITIES.md](CAPABILITIES.md), [ERROR_CODES.md](ERROR_CODES.md), [REMOTE.md](REMOTE.md), and `schema/registry.json`.
