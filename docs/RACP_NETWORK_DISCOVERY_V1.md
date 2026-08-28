# rACP Network Discovery Profile v1

This optional profile discovers rACP TCP services on a local network using multicast
DNS and DNS-Based Service Discovery. It does not change the rACP/1 wire protocol, and
an rACP implementation remains conforming without discovery support.

## DNS-SD records

An advertiser publishes `_racp._tcp` in the `local.` domain. Its service instance name
is a human-readable label and is not persistent identity. It is 1–63 UTF-8 bytes and
must not contain ASCII control characters. DNS-SD supplies the SRV port
and target hostname and the corresponding A and/or AAAA records.

The TXT record contains these required v1 keys:

| Key | Value |
| --- | --- |
| `v` | ASCII unsigned decimal profile version without leading zeros; v1 is `1` |
| `id` | The peer ID that the advertiser will send in rACP `HELLO` |
| `type` | The peer type that the advertiser will send in rACP `HELLO` |

Keys are ASCII and case-sensitive. Values for `id` and `type` use the rACP peer-token
grammar `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Required values cannot be empty. Duplicate
keys, malformed required values, or a non-decimal version make an advertisement
invalid. Unknown keys are ignored. Each DNS-SD TXT entry must fit its 255-byte wire
limit, and the complete TXT record must not exceed 512 bytes.

A v1 browser uses only advertisements containing valid `v`, `id`, and `type` values.
An unsupported version is not interpreted as v1. Missing discovery metadata never
invalidates an rACP connection established independently, such as through a static
host and port.

## Identity and trust

Discovery metadata is an untrusted routing and presentation hint. After connecting,
the rACP `HELLO` peer ID and peer type are authoritative for protocol association.
Applications must surface or reject a mismatch rather than silently associating the
connection with the advertisement.

Discovery metadata MUST NOT grant capabilities, authorization, trust, or identity
privileges. Capabilities remain in `HELLO`. Plain TCP rACP and its advertisements are
spoofable by any reachable local-network host.

## Result identity and interfaces

A browse-result identity consists of service instance, service type, domain, and its
interface scope. It remains stable across TXT changes for the life of that result but
is not persistent peer identity. Implementations retain all interfaces reported for a
result. Identically named services with contradictory records on different interfaces
must not be merged.

## Portability

Apple Network.framework, Linux Avahi, and embedded lwIP mDNS responders can publish
and browse this same profile. Static host/port configuration remains a first-class
fallback, particularly across VLANs where multicast DNS may be filtered.
