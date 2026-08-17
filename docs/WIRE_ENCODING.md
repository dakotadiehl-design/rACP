# ACP-CDE-1.2 wire encoding profile

This is a protocol rule, not a library default. Golden CBOR is produced by the Python reference encoder and consumed by every SDK.

## JSON

- RFC 8259
- Field names exactly as specified (snake_case)
- UUIDs: lowercase `8-4-4-4-12` hex
- Timestamps: RFC 3339 UTC, always `Z`, always millisecond precision (`2026-08-17T16:42:15.231Z`)
- Schema integers MUST be encoded without a fractional part
- `NaN` / `Infinity` are illegal

## CBOR

RFC 8949 Preferred Serialization plus Deterministic Encoding, with ACP restrictions:

| Rule | Requirement |
|---|---|
| Map keys | Text strings identical to JSON names. No integer keys in v1 |
| Key order | Bytewise lexicographic order of the **encoded** key bytes |
| Integers | Preferred (shortest) argument |
| Indefinite length | Forbidden; decoder rejects |
| Duplicate map keys | Forbidden; decoder rejects |
| Floats | Only on schema float fields; always IEEE-754 binary64; reject NaN/Inf |
| UUIDs | Text string (same as JSON). Tag 37 reserved |
| Timestamps | Tag 0 wrapping the same RFC 3339 millisecond UTC string. Tag 1 rejected |
| Byte strings | Only where the schema says binary (`resource.chunk` data) |
| Frames | One envelope per WebSocket message. Chunks are envelope payloads |

Unknown optional map keys on typed payloads are dropped, not re-encoded.

## Discovery datagram

```
[4 bytes ACP0][1 byte datagram_version][1 byte encoding][payload]
```

`encoding`: `0` = CBOR, `1` = JSON. Total ≤ 1200 bytes. v1 senders emit CBOR.
