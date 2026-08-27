# ACP Constants

Status: **Normative generated-catalog companion**

Single source of truth: [`schema/constants.json`](../schema/constants.json).

Every SDK copies or generates from that file. Product code must not hard-code multicast addresses, ports, magic bytes, or queue limits.

## Status

Discovery group, UDP port, and WebSocket port are **provisional** until a real-network collision check (Art-Net 6454, sACN 5568, mDNS 5353, typical console ports). Once a tagged ACP release ships them, they become deployment commitments.

## Quick reference

| Constant | Provisional value |
|---|---|
| Discovery multicast | `239.255.40.1` |
| Discovery UDP port | `27420` |
| WebSocket port | `27421` |
| WebSocket path | `/acp` |
| Discovery magic | `ACP0` (`41 43 50 30`) |
| Discovery datagram version | `1` |
| Preferred session encoding | CBOR |
| Legacy/default decoded auth mode | `trusted_lan` (unauthenticated; forbidden for hardened control) |
| Full-profile heartbeat | 1000 ms |
| Lightweight heartbeat | 5000 ms |
| Offline | 3 missed intervals; recover after 2 consecutive goods |
| Max discovery datagram | 1200 bytes |

## Discovery datagram

```
[4 bytes magic ACP0][1 byte datagram_version][1 byte encoding][payload]
```

- `encoding`: `0` = CBOR, `1` = JSON
- v1 senders emit CBOR
- Full-profile receivers accept CBOR and JSON if the datagram fits
- Lightweight senders and receivers are CBOR-only
- Discovery is never authentication
