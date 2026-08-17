import asyncio
import json

from acp.codec import CodecError, decode_json
from acp.envelope import make_envelope
from acp.testkit import connected_pair
from acp.types import Endpoint, QoS, Role


def test_schema_rejects_wrong_uptime_type() -> None:
    raw = {
        "acp": "1.2",
        "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000002",
        "type": "health.heartbeat",
        "source": {"node_id": "0193f8d8-4c4e-7d8b-a2ab-000000000001"},
        "timestamp_utc": "2026-08-17T16:42:15.231Z",
        "qos": "latest",
        "flags": [],
        "payload": {"uptime_ms": "not-an-integer", "status": "ok"},
    }
    try:
        decode_json(json.dumps(raw))
    except CodecError:
        return
    raise AssertionError("invalid uptime_ms was accepted")


def test_client_admits_bridge_state_delta() -> None:
    async def body() -> None:
        client, server = await connected_pair(Role.CONDUCTOR, Role.BRIDGE)
        assert client.peer is not None
        assert client.peer.role is Role.BRIDGE
        env = make_envelope(
            type="state.delta",
            source=server.source(),
            qos=QoS.LATEST,
            payload={
                "resource": "bridge.blackout",
                "revision": 1,
                "owner": server.source().to_dict(),
                "value": {"enabled": True},
                "confidence": "confirmed",
            },
        )
        env = env.with_session(client.session_id, 1)
        assert client._admit(env) is None
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())


def test_blackout_persists_across_instances(tmp_path) -> None:
    from acp.bridge import BridgeNode
    from acp.persist import NodeStore

    store = NodeStore(tmp_path)
    node = BridgeNode(source=Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-0000000000aa"), store=store)
    env = make_envelope(
        type="bridge.blackout",
        source=node.source,
        qos=QoS.RELIABLE,
        payload={"enabled": True, "scope": "all"},
        flags=frozenset({"ack_required"}),
    )
    node.handle(env)
    reloaded = BridgeNode(source=node.source, store=store)
    assert reloaded.blackout_enabled is True
    assert reloaded.blackout_scope == "all"
