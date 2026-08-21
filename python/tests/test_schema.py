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


def test_extension_permission_and_unknown_status_are_forward_compatible() -> None:
    permission = {
        "acp": "1.2",
        "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000002",
        "type": "remote.permissions",
        "source": {"node_id": "0193f8d8-4c4e-7d8b-a2ab-000000000001"},
        "timestamp_utc": "2026-08-17T16:42:15.231Z",
        "qos": "reliable",
        "flags": [],
        "payload": {"roles": [], "permissions": ["x.example.future.permission"], "revision": 1},
    }
    assert decode_json(json.dumps(permission)).payload["permissions"] == ["x.example.future.permission"]

    status = dict(permission)
    status["type"] = "command.status_report"
    status["payload"] = {
        "command_id": "0193f8d8-4c4e-7d8b-a2ab-000000000099",
        "origin_node_id": "0193f8d8-4c4e-7d8b-a2ab-000000000001",
        "origin_instance_id": "0193f8d8-4c4e-7d8b-a2ab-000000000003",
        "operation": "future.operation",
        "received_at": "2026-08-17T16:42:15.231Z",
        "disposition": "x.example.future_status",
        "result": {},
    }
    assert decode_json(json.dumps(status)).payload["disposition"] == "x.example.future_status"


def _invoke(*, interaction: str, lease_id: str | None = None) -> dict:
    payload = {
        "control_id": "fog_burst",
        "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
        "interaction": interaction,
        "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
    }
    if lease_id is not None:
        payload["lease_id"] = lease_id
    return {
        "acp": "1.2",
        "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000042",
        "type": "remote.control.invoke",
        "source": {"node_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"},
        "timestamp_utc": "2026-08-17T16:42:15.231Z",
        "qos": "reliable",
        "flags": [],
        "payload": payload,
    }


def test_momentary_end_requires_lease_id() -> None:
    decode_json(json.dumps(_invoke(
        interaction="momentary_end",
        lease_id="0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
    )))
    decode_json(json.dumps(_invoke(interaction="activate")))
    decode_json(json.dumps(_invoke(
        interaction="momentary_cancel",
        lease_id="0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
    )))
    try:
        decode_json(json.dumps(_invoke(interaction="momentary_end")))
    except CodecError:
        return
    raise AssertionError("momentary_end without lease_id was accepted")
