# ACP v1.2 — normative summary

Distilled from `Aurora_Communications_Protocol_Handoff_Spec_v1.2.pdf`. If this document and the PDF disagree on a frozen decision, update this file as a spec revision.

ACP is the Aurora-family control plane. It is not Art-Net, sACN, DMX, MIDI, or OSC.

- Canonical encoding: CBOR under [WIRE_ENCODING.md](WIRE_ENCODING.md). JSON is required for humans and debug.
- Reliable transport: WebSocket, one envelope per message.
- Discovery: framed UDP multicast. Never authentication. Never safety-critical.
- Commands distinguish delivery, acceptance, application, and observed confidence.
- One owner per state kind. State is reconstructable via snapshots.
- Unknown optional fields are ignored on typed decode.
- Safety actions (blackout) are explicit, scoped, acked, logged, and state-reflected.

See [STATE_MACHINES.md](STATE_MACHINES.md), [CAPABILITIES.md](CAPABILITIES.md), [ERROR_CODES.md](ERROR_CODES.md), and `schema/registry.json`.
