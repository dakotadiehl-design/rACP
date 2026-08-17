from __future__ import annotations

from .types import Capability, ProtocolRange, parse_version

ENCODING_PREFERENCE = ("cbor", "json")
HEARTBEAT_MIN_MS = 100
HEARTBEAT_MAX_MS = 60_000
MESSAGE_BYTES_MIN = 256
MESSAGE_BYTES_MAX = 1_048_576


class VersionError(ValueError):
    """Handshake version negotiation failed."""


def select_encoding(client: list[str], server: list[str]) -> str:
    client_set = set(client)
    server_set = set(server)
    for enc in ENCODING_PREFERENCE:
        if enc in client_set and enc in server_set:
            return enc
    raise VersionError("no common encoding")


def intersect_capabilities(local: list[Capability], peer: list[Capability]) -> list[Capability]:
    peer_map = {c.id: c.version for c in peer}
    out: list[Capability] = []
    for cap in local:
        if cap.id not in peer_map:
            continue
        other = peer_map[cap.id]
        try:
            lv, ov = parse_version(cap.version), parse_version(other)
        except ValueError:
            continue
        if lv[0] != ov[0]:
            continue
        chosen = cap.version if lv <= ov else other
        out.append(Capability(cap.id, chosen))
    return out


def validate_heartbeat(ms: int) -> int:
    if not HEARTBEAT_MIN_MS <= ms <= HEARTBEAT_MAX_MS:
        raise VersionError(f"heartbeat_interval_ms out of bounds: {ms}")
    return ms


def validate_max_message_bytes(n: int) -> int:
    if not MESSAGE_BYTES_MIN <= n <= MESSAGE_BYTES_MAX:
        raise VersionError(f"max_message_bytes out of bounds: {n}")
    return n


def version_leq(actual: str, maximum: str) -> bool:
    return parse_version(actual) <= parse_version(maximum)


def select_version(client: ProtocolRange, server: ProtocolRange) -> str:
    """Highest shared minor within the same major, or raise VersionError."""
    cmin, cmax = parse_version(client.min), parse_version(client.max)
    smin, smax = parse_version(server.min), parse_version(server.max)
    if cmin[0] != smin[0] or cmin[0] != cmax[0] or smin[0] != smax[0]:
        raise VersionError("protocol major mismatch or malformed range")
    lo = max(cmin[1], smin[1])
    hi = min(cmax[1], smax[1])
    if lo > hi:
        raise VersionError("empty protocol intersection")
    return f"{cmin[0]}.{hi}"


def version_at_least(actual: str, required: str) -> bool:
    a = parse_version(actual)
    r = parse_version(required)
    return a >= r
