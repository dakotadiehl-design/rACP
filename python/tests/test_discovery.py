import pytest

from acp.discovery import MAGIC, Advertisement, capabilities_digest, decode_datagram, encode_datagram
from acp.types import NodeIdentity, ProtocolRange, Role, new_uuid


def test_discovery_frame_roundtrip() -> None:
    node = NodeIdentity(new_uuid(), new_uuid(), Role.BRIDGE, "Stage Right")
    payload = Advertisement(
        node=node,
        protocol=ProtocolRange("1.0", "1.2"),
        endpoint_url="ws://127.0.0.1:27421/acp",
        capabilities_digest=capabilities_digest(["bridge.blackout", "health.heartbeat"]),
    ).payload()
    frame = encode_datagram(payload, encoding=0)
    assert frame.startswith(MAGIC)
    assert len(frame) <= 1200
    enc, again = decode_datagram(frame)
    assert enc == 0
    assert again["node"]["name"] == "Stage Right"


def test_discovery_rejects_oversize() -> None:
    with pytest.raises(ValueError):
        decode_datagram(b"ACP0\x01\x00" + b"x" * 1300)


def test_discovery_json_accepted() -> None:
    payload = {
        "type": "discovery.query",
        "requester": {
            "node_id": "0193f8d8-4c4e-7d8b-a2ab-000000000001",
            "instance_id": "0193f8d8-4c4e-7d8b-a2ab-000000000002",
            "role": "tool",
            "name": "t",
        },
    }
    frame = encode_datagram(payload, encoding=1)
    enc, again = decode_datagram(frame)
    assert enc == 1
    assert again["type"] == "discovery.query"
