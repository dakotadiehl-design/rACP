from __future__ import annotations

import hashlib

from acp.assignment import AssignmentResolver, Chart
from acp.bridge import BridgeNode, ConfigStore, is_secret_path
from acp.envelope import make_envelope
from acp.health import HealthObserver
from acp.transfer import TransferAgent
from acp.types import Endpoint, HealthStatus, QoS, new_uuid

NODE = Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-0000000000aa")


def test_blackout_persist() -> None:
    bridge = BridgeNode(source=NODE)
    env = make_envelope(
        type="bridge.blackout",
        source=NODE,
        qos=QoS.RELIABLE,
        payload={"enabled": True, "scope": "all", "idempotency_key": new_uuid()},
        flags=frozenset({"ack_required"}),
    )
    out = bridge.handle(env)
    assert any(m.type == "command.ack" and m.payload["status"] == "applied" for m in out)
    assert bridge.blackout_enabled
    bridge.on_session_close()
    assert bridge.blackout_enabled is True
    bridge.clear_on_disconnect = True
    bridge.on_session_close()
    assert bridge.blackout_enabled is False


def test_config_revision_and_secrets() -> None:
    store = ConfigStore()
    store.apply(0, [{"path": "bridge.outputs.dmx.0.universe", "value": 1}])
    conflict = store.apply(0, [{"path": "bridge.outputs.dmx.0.universe", "value": 2}])
    assert conflict["error"]["code"] == "config.revision_conflict"
    store.apply(1, [{"path": "bridge.auth.password", "value": "s3cret"}])
    public = store.get_public("bridge.auth.password")
    assert public.get("configured") is True
    assert "s3cret" not in str(public)
    assert is_secret_path("bridge.auth.password")


def test_health_hysteresis() -> None:
    obs = HealthObserver()
    assert obs.status is HealthStatus.OFFLINE
    obs.on_heartbeat(HealthStatus.OK, "inst-a")
    assert obs.status is HealthStatus.OFFLINE  # need 2 goods
    obs.on_heartbeat(HealthStatus.OK, "inst-a")
    assert obs.status is HealthStatus.OK
    obs.on_tick_without_heartbeat()
    obs.on_tick_without_heartbeat()
    assert obs.status is HealthStatus.OK
    obs.on_tick_without_heartbeat()
    assert obs.status is HealthStatus.OFFLINE
    # restart instance
    obs.on_heartbeat(HealthStatus.OK, "inst-b")
    assert obs.status is HealthStatus.OFFLINE
    obs.on_heartbeat(HealthStatus.OK, "inst-b")
    assert obs.status is HealthStatus.OK


def test_assignment_not_from_song() -> None:
    resolver = AssignmentResolver()
    song = "song-1"
    p1, p2 = new_uuid(), new_uuid()
    c1 = Chart(new_uuid(), song, 1, "a" * 64, "nashville_number")
    c2 = Chart(new_uuid(), song, 1, "b" * 64, "chord_lyrics")
    resolver.catalog = [c1, c2]
    resolver.preferences[p1] = "nashville_number"
    resolver.explicit[(song, p2)] = c2
    chart, reason = resolver.resolve(song, p1)
    assert chart is c1 and reason == "performer_preference"
    chart, reason = resolver.resolve(song, p2)
    assert chart is c2 and reason == "explicit_assignment"
    assert not hasattr(resolver, "resolve_from_song")


def test_resource_transfer_hash_and_preserve() -> None:
    agent = TransferAgent(source=NODE)
    blob = b"chart-bytes-hello"
    prev = b"old-asset"
    asset_id = new_uuid()
    agent.live_assets[asset_id] = prev
    digest = hashlib.sha256(blob).hexdigest()
    tid = new_uuid()
    offer = make_envelope(
        type="resource.offer",
        source=NODE,
        qos=QoS.RELIABLE,
        payload={
            "transfer_id": tid,
            "asset": {
                "asset_id": asset_id,
                "asset_type": "lyric.chart",
                "revision": 2,
                "sha256": digest,
                "size_bytes": len(blob),
            },
            "locator": {"mode": "chunked"},
        },
    )
    assert agent.handle(offer)[0].type == "resource.accept"
    agent.handle(make_envelope(
        type="resource.chunk", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid, "offset": 0, "length": len(blob), "data": blob},
    ))
    result = agent.handle(make_envelope(
        type="resource.complete", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid},
    ))[0]
    assert result.payload["status"] == "verified"
    act = agent.handle(make_envelope(
        type="resource.activate", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid},
    ))[0]
    assert act.payload["status"] == "applied"
    assert agent.live_assets[asset_id] == blob

    # failed hash leaves previous
    tid2 = new_uuid()
    bad = make_envelope(
        type="resource.offer", source=NODE, qos=QoS.RELIABLE,
        payload={
            "transfer_id": tid2,
            "asset": {
                "asset_id": asset_id,
                "asset_type": "lyric.chart",
                "revision": 3,
                "sha256": "0" * 64,
                "size_bytes": 4,
            },
            "locator": {"mode": "chunked"},
        },
    )
    agent.handle(bad)
    agent.handle(make_envelope(
        type="resource.chunk", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid2, "offset": 0, "length": 4, "data": b"xxxx"},
    ))
    fail = agent.handle(make_envelope(
        type="resource.complete", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid2},
    ))[0]
    assert fail.payload["status"] == "failed"
    assert agent.live_assets[asset_id] == blob


def test_transfer_rejects_overlap_and_holes() -> None:
    agent = TransferAgent(source=NODE)
    asset_id = new_uuid()
    tid = new_uuid()
    agent.handle(make_envelope(
        type="resource.offer", source=NODE, qos=QoS.RELIABLE,
        payload={
            "transfer_id": tid,
            "asset": {
                "asset_id": asset_id, "asset_type": "lyric.chart", "revision": 1,
                "sha256": "0" * 64, "size_bytes": 8,
            },
            "locator": {"mode": "chunked"},
        },
    ))
    agent.handle(make_envelope(
        type="resource.chunk", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid, "offset": 0, "length": 4, "data": b"aaaa"},
    ))
    overlap = agent.handle(make_envelope(
        type="resource.chunk", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid, "offset": 2, "length": 4, "data": b"bbbb"},
    ))
    assert overlap and overlap[0].payload["status"] == "failed"
    tid2 = new_uuid()
    agent.handle(make_envelope(
        type="resource.offer", source=NODE, qos=QoS.RELIABLE,
        payload={
            "transfer_id": tid2,
            "asset": {
                "asset_id": asset_id, "asset_type": "lyric.chart", "revision": 1,
                "sha256": "0" * 64, "size_bytes": 8,
            },
            "locator": {"mode": "chunked"},
        },
    ))
    agent.handle(make_envelope(
        type="resource.chunk", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid2, "offset": 0, "length": 4, "data": b"aaaa"},
    ))
    hole = agent.handle(make_envelope(
        type="resource.complete", source=NODE, qos=QoS.RELIABLE,
        payload={"transfer_id": tid2},
    ))[0]
    assert hole.payload["code"] == "incomplete"


def test_config_atomic_no_partial() -> None:
    store = ConfigStore()
    store.apply(0, [{"path": "bridge.outputs.dmx.0.universe", "value": 1}])
    before = store.revision
    bad = store.apply(1, [
        {"path": "bridge.outputs.dmx.0.universe", "value": 2},
        {"path": "bridge.outputs.dmx.0.enabled", "value": "yes"},
    ])
    assert bad["status"] == "rejected"
    assert store.revision == before
    assert store.values["bridge.outputs.dmx.0.universe"] == 1
