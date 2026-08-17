from __future__ import annotations

import hashlib
import json
import socket
import struct
from dataclasses import dataclass
from urllib.parse import urlparse

from .cbor_cde import decode as cbor_decode
from .cbor_cde import encode as cbor_encode
from .constants import discovery as disc_const
from .types import NodeIdentity, ProtocolRange

ALLOWED_SECURITY = frozenset({"trusted_lan", "tls", "mutual_tls"})


MAGIC = b"ACP0"


def capabilities_digest(capability_ids: list[str]) -> str:
    blob = ",".join(sorted(capability_ids)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def encode_datagram(payload: dict, *, encoding: int = 0) -> bytes:
    body = cbor_encode(payload) if encoding == 0 else json.dumps(payload, separators=(",", ":")).encode()
    frame = MAGIC + bytes([disc_const()["datagram_version"], encoding]) + body
    if len(frame) > disc_const()["max_datagram_bytes"]:
        raise ValueError("discovery datagram exceeds 1200 bytes")
    return frame


def decode_datagram(frame: bytes) -> tuple[int, dict]:
    if len(frame) > disc_const()["max_datagram_bytes"]:
        raise ValueError("discovery datagram exceeds 1200 bytes")
    if len(frame) < 6 or frame[:4] != MAGIC:
        raise ValueError("not an ACP discovery datagram")
    version, encoding = frame[4], frame[5]
    if version != disc_const()["datagram_version"]:
        raise ValueError("unsupported discovery datagram version")
    body = frame[6:]
    if encoding == 0:
        payload = cbor_decode(body)
    elif encoding == 1:
        payload = json.loads(body.decode("utf-8"))
    else:
        raise ValueError("unknown discovery encoding")
    if not isinstance(payload, dict):
        raise ValueError("discovery payload must be a map")
    return encoding, payload


@dataclass(frozen=True)
class Advertisement:
    node: NodeIdentity
    protocol: ProtocolRange
    endpoint_url: str
    capabilities_digest: str
    security_mode: str = "trusted_lan"

    def payload(self) -> dict:
        return {
            "type": "discovery.advertisement",
            "node": self.node.to_dict(),
            "protocol": self.protocol.to_dict(),
            "endpoint_url": self.endpoint_url,
            "capabilities_digest": self.capabilities_digest,
            "security_mode": self.security_mode,
        }


class DiscoveryNode:
    def __init__(
        self,
        advert: Advertisement,
        *,
        group: str | None = None,
        port: int | None = None,
        ttl: int = 1,
    ) -> None:
        cfg = disc_const()
        self.advert = advert
        self.group = group or cfg["multicast_group"]
        self.port = port or int(cfg["udp_port"])
        self.ttl = ttl
        self._seen: dict[str, Advertisement] = {}
        self._sock: socket.socket | None = None

    def bind(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
        sock.bind(("", self.port))
        mreq = struct.pack("=4s4s", socket.inet_aton(self.group), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        sock.setblocking(False)
        self._sock = sock
        return sock

    def send_advertisement(self) -> None:
        assert self._sock is not None
        frame = encode_datagram(self.advert.payload(), encoding=0)
        self._sock.sendto(frame, (self.group, self.port))

    def send_query(self) -> None:
        assert self._sock is not None
        payload = {"type": "discovery.query", "requester": self.advert.node.to_dict()}
        self._sock.sendto(encode_datagram(payload, encoding=0), (self.group, self.port))

    def handle(self, data: bytes) -> Advertisement | None:
        try:
            _, payload = decode_datagram(data)
            if payload.get("type") == "discovery.query":
                return None
            if payload.get("type") != "discovery.advertisement":
                return None
            node = NodeIdentity.from_dict(payload["node"])
            url = str(payload["endpoint_url"])
            parsed = urlparse(url)
            if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
                return None
            mode = payload.get("security_mode", "trusted_lan")
            if mode not in ALLOWED_SECURITY:
                return None
            adv = Advertisement(
                node=node,
                protocol=ProtocolRange.from_dict(payload["protocol"]),
                endpoint_url=url,
                capabilities_digest=str(payload["capabilities_digest"]),
                security_mode=str(mode),
            )
        except (ValueError, KeyError, TypeError):
            return None
        prev = self._seen.get(node.node_id)
        self._seen[node.node_id] = adv
        if prev and prev.node.instance_id != node.instance_id:
            adv = adv  # restart detected by caller via instance_id
        return adv

    @property
    def seen(self) -> dict[str, Advertisement]:
        return dict(self._seen)
