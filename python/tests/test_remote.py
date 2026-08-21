from __future__ import annotations

import asyncio
import json
import time

import pytest

from acp.envelope import Envelope, make_envelope
from acp.persist import NodeStore
from acp.remote import (
    ACTION_DELIVERY,
    ACTION_FEATURE,
    ACTION_POLICY,
    EXECUTABLE_SURFACE_KEYS,
    PERMISSION_FOR_ACTION,
    ActionContext,
    ActionResult,
    Enrollment,
    MemoryActionRouter,
    RemoteAuthority,
    RemoteClient,
    RemoteHost,
    RemoteIdentity,
    layout_fingerprint,
    sample_layout,
)
from acp.session import Session, SessionError, SessionState
from acp.testkit import connected_pair, default_caps, identity, linked_transports
from acp.transfer import TransferState
from acp.types import Endpoint, NodeIdentity, Role, format_ts, new_uuid
from acp.validate import validate_message

SHOW = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
LAYOUT = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"
SRC = Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-0000000000b0")
SRC_B = Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-0000000000b1")
AUTH = Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-000000000001")
SID = "0193f8d8-4c4e-7d8b-a2ab-0000000000c0"
SID_B = "0193f8d8-4c4e-7d8b-a2ab-0000000000c1"
DEVICE = "0193f8d8-4c4e-7d8b-a2ab-0000000000d0"
REMOTE = "0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
PARTICIPANT = "0193f8d8-4c4e-7d8b-a2ab-0000000000d2"


def authority() -> RemoteAuthority:
    node = RemoteAuthority(source=AUTH, show_id=SHOW, use_manual_clock=True, inline_surface=True)
    node.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    node.authorize(SRC.node_id, ["remote.operator", "remote.busker", "remote.show_navigation", "remote.viewer"])
    node.bind_test_session(SID, SRC.node_id)
    return node


def run(
    auth: RemoteAuthority,
    env: Envelope,
    *,
    session_id: str = SID,
    client: RemoteClient | None = None,
) -> list[Envelope]:
    out = auth.handle_simulated(env, session_id=session_id)
    if client is not None and env.type == "remote.control.invoke" and out:
        client.record_result(str(env.payload["invocation_id"]), out[0])
    return out


def sync_session(auth: RemoteAuthority, session_id: str = SID, source: Endpoint = SRC) -> list[Envelope]:
    report = run(auth, make_envelope(type="remote.layout.request", source=source, payload={}), session_id=session_id)
    layout = next(m for m in report if m.type == "remote.layout.report").payload["layout"]
    snap = next(m for m in report if m.type == "remote.control.snapshot")
    ack = make_envelope(
        type="remote.readiness",
        source=source,
        payload={
            "state": "ready",
            "layout_revision": layout["revision"],
            "layout_hash": layout_fingerprint(layout),
            "snapshot_revision": snap.payload.get("snapshot_revision", auth.snapshot_revision),
        },
    )
    return run(auth, ack, session_id=session_id)


def hello_payload(node_id: str, *, device_id: str = DEVICE, remote_id: str = REMOTE, **extra: object) -> dict:
    remote = {
        "node_id": node_id,
        "instance_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b1",
        "device_id": device_id,
        "remote_id": remote_id,
        "device_name": "FOH",
        "platform": "ipados",
        "app_version": "1.0.0",
        **extra,
    }
    return {"remote": remote, "roles": ["remote.admin", "remote.busker"]}


def test_hello_does_not_self_grant() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    hello = make_envelope(
        type="remote.hello",
        source=SRC,
        payload={
            "remote": {
                "node_id": SRC.node_id,
                "instance_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b1",
                "device_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b2",
                "remote_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b3",
                "device_name": "FOH",
                "platform": "ipados",
                "app_version": "1.0.0",
            },
            "roles": ["remote.admin", "remote.busker"],
        },
    )
    out = run(auth, hello)
    ack = next(m for m in out if m.type == "remote.hello_ack")
    assert ack.payload["permissions"]["roles"] == []
    denied = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert denied[0].payload["error"]["code"] == "remote.control.permission_denied"


def test_layout_cannot_downgrade_fog_to_viewer() -> None:
    auth = authority()
    layout = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    layout["revision"] = 9
    for control in layout["controls"]:
        if control["control_id"] == "fog_burst":
            control["permission"] = "remote.viewer"
    ok, _ = auth.activate_layout(layout)
    assert ok is False
    auth.authorize(SRC.node_id, ["remote.viewer"])
    out = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).begin_momentary("fog_burst"))
    assert out[0].payload["error"]["code"] == "remote.control.permission_denied"


def test_cross_session_end_denied() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.busker"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    inv = "0193f8d8-4c4e-7d8b-a2ab-0000000000e0"
    a = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    b = RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT)
    run(auth, a.begin_momentary("fog_burst", invocation_id=inv), client=a)
    assert auth.effect_active("fog_burst")
    stolen = run(auth, b.end_momentary("fog_burst", inv, lease_id=a.leases[inv]), session_id=SID_B)
    assert stolen[0].payload["status"] == "rejected"
    assert stolen[0].payload["error"]["code"] == "remote.control.permission_denied"
    assert auth.effect_active("fog_burst")


def test_invoke_go_and_idempotent_retry() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    first = client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000d0")
    out = run(auth, first, client=client)
    assert out[0].payload["status"] == "applied"
    assert any(m.type == "state.delta" and m.payload["resource"] == "cue.current" for m in out)
    assert auth.go_count == 1
    retry = run(auth, first, client=client)
    assert retry[0].payload["status"] == "applied"
    assert auth.go_count == 1


def test_cross_session_idempotency_isolated() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    inv = "0193f8d8-4c4e-7d8b-a2ab-0000000000d5"
    a = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    b = RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT)
    run(auth, a.invoke("cue_go", invocation_id=inv), client=a)
    assert auth.go_count == 1
    other = run(auth, b.invoke("cue_go", invocation_id=inv), session_id=SID_B, client=b)
    assert other[0].payload["status"] == "applied"
    assert auth.go_count == 2


def test_permission_denied_and_unknown() -> None:
    auth = authority()
    auth.authorize(SRC.node_id, ["remote.viewer"])
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    denied = run(auth, client.invoke("cue_go"), client=client)
    assert denied[0].payload["status"] == "rejected"
    assert denied[0].payload["error"]["code"] == "remote.control.permission_denied"
    missing = run(auth, client.invoke("nope"), client=client)
    assert missing[0].payload["error"]["code"] == "remote.control.unknown"


def test_stale_show_and_layout_rejected() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id="0193f8d8-4c4e-7d8b-a2ab-000000000099", layout_id=LAYOUT)
    out = run(auth, client.invoke("cue_go"), client=client)
    assert out[0].payload["error"]["code"] == "remote.layout.stale"


def test_toggle_requires_desired_state() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    bad = run(auth, client.invoke("work_lights", "set", value="on"), client=client)
    assert bad[0].payload["error"]["code"] == "remote.control.invalid_value"
    ok = run(auth, client.invoke("work_lights", "set", value=True), client=client)
    assert ok[0].payload["status"] == "applied"
    assert auth.values["work_lights"] is True


def test_momentary_begin_end_and_duplicate() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    inv = "0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
    begin = client.begin_momentary("fog_burst", invocation_id=inv)
    out = run(auth, begin, client=client)
    assert out[0].payload["status"] == "applied"
    assert auth.effect_active("fog_burst")
    validate_message(out[1].to_dict())
    dup = run(auth, begin, client=client)
    assert dup[0].payload["status"] == "applied"
    end = client.end_momentary("fog_burst", inv)
    released = run(auth, end, client=client)
    assert released[0].payload["status"] == "applied"
    assert not auth.effect_active("fog_burst")
    again = run(auth, end, client=client)
    assert again[0].payload["status"] == "applied"


def test_dirty_disconnect_releases_hold() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    assert auth.effect_active("fog_burst")
    released = auth.on_session_lost(SID)
    assert "fog_burst" in released
    assert not auth.effect_active("fog_burst")


def test_revoke_and_disarm_release_holds() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    auth.authorize(SRC.node_id, ["remote.viewer"])
    assert not auth.effect_active("fog_burst")
    auth.authorize(SRC.node_id, ["remote.busker"])
    inv = "0193f8d8-4c4e-7d8b-a2ab-0000000000aa"
    run(auth, client.begin_momentary("fog_burst", invocation_id=inv), client=client)
    auth.disarm()
    assert not auth.effect_active("fog_burst")


def test_refresh_requires_permission_and_lease() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    begin = client.begin_momentary("fog_burst", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ab")
    ack = run(auth, begin, client=client)[0]
    lease = ack.payload["result"]["lease_id"]
    refresh = make_envelope(
        type="remote.momentary.refresh",
        source=SRC,
        payload={"control_id": "fog_burst", "invocation_id": begin.payload["invocation_id"], "lease_id": lease},
    )
    assert run(auth, refresh)[0].payload["status"] == "applied"
    auth.disarm()
    denied = run(auth, refresh)
    assert denied[0].payload["error"]["code"] == "remote.control.not_armed"


def test_max_hold_expires() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    expired = auth.tick(10_001)
    assert expired
    assert not auth.effect_active("fog_burst")


def test_shared_or_across_two_remotes() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.busker"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    a = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    b = RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT)
    inv_a = "0193f8d8-4c4e-7d8b-a2ab-0000000000e0"
    inv_b = "0193f8d8-4c4e-7d8b-a2ab-0000000000e1"
    run(auth, a.begin_momentary("fog_burst", invocation_id=inv_a), client=a)
    run(auth, b.begin_momentary("fog_burst", invocation_id=inv_b), session_id=SID_B, client=b)
    run(auth, a.end_momentary("fog_burst", inv_a), client=a)
    assert auth.effect_active("fog_burst")
    run(auth, b.end_momentary("fog_burst", inv_b), session_id=SID_B, client=b)
    assert not auth.effect_active("fog_burst")


def test_exclusive_conflict() -> None:
    auth = authority()
    fog = auth.control("fog_burst")
    assert fog is not None
    fog["concurrency"] = "exclusive"
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.busker"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    a = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    b = RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT)
    run(auth, a.begin_momentary("fog_burst", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000e2"), client=a)
    inv_b = "0193f8d8-4c4e-7d8b-a2ab-0000000000e3"
    conflict = run(auth, b.begin_momentary("fog_burst", invocation_id=inv_b), session_id=SID_B, client=b)
    assert conflict[0].payload["error"]["code"] == "remote.control.conflict"


def test_browse_is_session_local_and_requires_viewer() -> None:
    auth = authority()
    live = auth.song_id
    env = make_envelope(
        type="remote.navigation.request",
        source=SRC,
        payload={"kind": "browse", "song_id": "lookahead", "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000f0"},
    )
    out = run(auth, env)
    assert out[0].payload["status"] == "applied"
    assert auth.song_id == live
    assert auth.browsing[SID] == "lookahead"
    auth.authorize(SRC.node_id, [])
    denied = run(auth, env)
    assert denied[0].payload["error"]["code"] == "remote.control.permission_denied"


def test_previous_and_unknown_nav() -> None:
    auth = authority()
    prev = make_envelope(
        type="remote.navigation.request",
        source=SRC,
        payload={"kind": "previous", "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000f1"},
    )
    out = run(auth, prev)
    assert out[0].payload["status"] == "applied"
    assert auth.song_id == "closer"
    bad = make_envelope(
        type="remote.navigation.request",
        source=SRC,
        payload={"kind": "teleport", "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000f2"},
    )
    rejected = run(auth, bad)
    assert rejected[0].payload["error"]["code"] == "unsupported"


def test_layout_activation_releases_removed_and_rolls_back() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["controls"] = [c for c in nxt["controls"] if c["control_id"] != "fog_burst"]
    nxt["pages"][0]["groups"][0]["controls"] = ["cue_go", "work_lights"]
    ok, _ = auth.activate_layout(nxt)
    assert ok
    assert not auth.effect_active("fog_burst")
    broken = {"controls": [{"nope": True}]}
    ok, kept = auth.activate_layout(broken)
    assert ok is False
    assert kept["revision"] == 9
    assert auth.layout["revision"] == 9


def test_not_armed_blocks_invoke() -> None:
    auth = authority()
    auth.armed = False
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    out = run(auth, client.invoke("cue_go"), client=client)
    assert out[0].payload["error"]["code"] == "remote.control.not_armed"


def test_remote_identity_roundtrip() -> None:
    ident = RemoteIdentity(
        node_id=SRC.node_id,
        instance_id=new_uuid(),
        device_id=new_uuid(),
        remote_id=new_uuid(),
        device_name="FOH iPad",
        platform="ipados",
        app_version="1.0.0",
    )
    again = RemoteIdentity.from_dict(ident.to_dict())
    assert again.device_name == "FOH iPad"


def _established_session(
    *,
    peer_node: str = SRC.node_id,
    peer_role: Role = Role.REMOTE,
    session_id: str = SID,
    capabilities: dict[str, str] | None = None,
) -> Session:
    ta, _tb = linked_transports()
    session = Session(ta, identity(Role.CONDUCTOR), is_server=True, allow_plaintext=True)
    session.state = SessionState.ESTABLISHED
    session.session_id = session_id
    session.peer = NodeIdentity(
        node_id=peer_node,
        instance_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ee",
        role=peer_role,
        name="pad",
    )
    versions = capabilities if capabilities is not None else {
        "remote.profile": "1.0",
        "remote.control.invoke": "1.0",
        "remote.control.momentary": "1.0",
        "remote.layout": "1.0",
        "cue.go": "1.0",
        "look.global": "1.0",
        "song.selection": "1.0",
        "song.loading": "1.0",
        "show.navigation": "1.0",
        "busk.controls": "1.0",
        "output.blackout": "1.0",
        "output.grand_master": "1.0",
        "remote.surfaces": "1.0",
        "state.live": "1.0",
    }
    session.negotiated_capability_versions = dict(versions)
    session.negotiated_capabilities = set(versions)
    session.negotiated_profiles = {"remote", "aurora.remote.prism.v1"}
    return session


def test_session_context_rejects_wrong_peer() -> None:
    auth = authority()
    session = _established_session(peer_node="0193f8d8-4c4e-7d8b-a2ab-0000000000ff")
    env = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go")
    out = auth.handle(env, session)
    assert out[0].payload["error"]["code"] == "authentication"


def test_sample_layout_validates_as_report_payload() -> None:
    layout = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    data = {
        "acp": "1.2",
        "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000040",
        "type": "remote.layout.report",
        "source": {"node_id": AUTH.node_id},
        "destination": {"node_id": SRC.node_id},
        "session_id": SID,
        "sequence": 1,
        "timestamp_utc": "2026-08-17T16:42:15.231Z",
        "qos": "reliable",
        "flags": [],
        "payload": {"layout": layout},
    }
    validate_message(data)


def test_claimed_ids_cannot_impersonate_authorized_device() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    victim = "0193f8d8-4c4e-7d8b-a2ab-0000000000aa"
    auth.authorize(victim, ["remote.admin", "remote.operator"])
    auth.enroll(Enrollment(node_id=victim, device_id=DEVICE, remote_id=REMOTE, participant_id=PARTICIPANT))
    claims = [
        hello_payload(SRC.node_id, device_id=DEVICE, remote_id=new_uuid()),
        hello_payload(SRC.node_id, device_id=new_uuid(), remote_id=REMOTE),
        hello_payload(SRC.node_id, device_id=new_uuid(), remote_id=new_uuid(), participant_id=PARTICIPANT),
        hello_payload(SRC.node_id, device_id=DEVICE, remote_id=REMOTE, participant_id=PARTICIPANT),
    ]
    for payload in claims:
        env = make_envelope(type="remote.hello", source=SRC, payload=payload)
        out = run(auth, env)
        assert out[0].payload["error"]["code"] == "authentication"


def test_unknown_node_does_not_inherit_claimed_identity_policy() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.admin", "remote.operator"])
    env = make_envelope(
        type="remote.hello",
        source=SRC_B,
        payload=hello_payload(SRC_B.node_id, device_id=DEVICE, remote_id=REMOTE),
    )
    out = run(auth, env, session_id=SID_B)
    ack = next(m for m in out if m.type == "remote.hello_ack")
    assert ack.payload["permissions"]["roles"] == []
    denied = run(
        auth,
        RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"),
        session_id=SID_B,
    )
    assert denied[0].payload["error"]["code"] == "remote.control.permission_denied"


def test_enrollment_mismatch_rejects_authorized_node() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.enroll(
        Enrollment(node_id=SRC.node_id, device_id=DEVICE, remote_id=REMOTE),
        roles=["remote.operator"],
    )
    env = make_envelope(
        type="remote.hello",
        source=SRC,
        payload=hello_payload(SRC.node_id, device_id=new_uuid(), remote_id=REMOTE),
    )
    out = run(auth, env)
    assert out[0].payload["error"]["code"] == "authentication"


def test_invented_and_foreign_session_rejected() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator"])
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    invented = run(auth, client.invoke("cue_go"), session_id="0193f8d8-4c4e-7d8b-a2ab-000000000099")
    assert invented[0].payload["error"]["code"] == "authentication"
    auth.bind_test_session(SID, SRC.node_id)
    foreign = run(auth, RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert foreign[0].payload["error"]["code"] == "authentication"


def test_production_handle_requires_hello_and_ready_session() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator"])
    session = _established_session()
    env = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go")
    missing_hello = auth.handle(env, session)
    assert missing_hello[0].payload["error"]["code"] == "authentication"
    hello = make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id))
    ack = auth.handle(hello, session)
    assert any(m.type == "remote.hello_ack" for m in ack)
    assert auth.compute_readiness(SID) == "syncing_assets"
    too_soon = auth.handle(RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"), session)
    assert too_soon[0].payload["error"]["code"] == "remote.session.not_ready"
    report = auth.handle(make_envelope(type="remote.layout.request", source=SRC, payload={}), session)
    layout = next(m for m in report if m.type == "remote.layout.report").payload["layout"]
    snap = next(m for m in report if m.type == "remote.control.snapshot")
    assert auth.compute_readiness(SID) == "syncing_assets"
    ready = auth.handle(
        make_envelope(
            type="remote.readiness",
            source=SRC,
            payload={
                "state": "ready",
                "layout_revision": layout["revision"],
                "layout_hash": layout_fingerprint(layout),
                "snapshot_revision": snap.payload["snapshot_revision"],
            },
        ),
        session,
    )
    assert ready[0].payload["state"] == "ready"
    applied = auth.handle(RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"), session)
    assert applied[0].payload["status"] == "applied"
    closed = _established_session()
    closed.state = SessionState.CLOSED
    assert auth.handle(env, closed)[0].payload["error"]["code"] == "authentication"
    wrong_role = _established_session(peer_role=Role.CONDUCTOR)
    assert auth.handle(env, wrong_role)[0].payload["error"]["code"] == "authentication"
    no_cap = _established_session(capabilities={})
    assert auth.handle(env, no_cap)[0].payload["error"]["code"] == "capability_not_permitted"
    no_version = _established_session()
    no_version.negotiated_capability_versions = {}
    assert auth.handle(env, no_version)[0].payload["error"]["code"] == "capability_not_permitted"
    stale = _established_session(session_id="0193f8d8-4c4e-7d8b-a2ab-0000000000c9")
    assert auth.handle(env, stale)[0].payload["error"]["code"] == "authentication"


def test_client_cannot_promote_readiness() -> None:
    auth = authority()
    auth.authorize(SRC.node_id, [])
    assert auth.compute_readiness(SID) == "blocked"
    env = make_envelope(type="remote.readiness", source=SRC, payload={"state": "ready"})
    out = run(auth, env)
    assert out[0].payload["state"] == "blocked"
    auth.authorize(SRC.node_id, ["remote.operator", "remote.viewer"])
    assert auth.compute_readiness(SID) == "ready"
    auth.disarm()
    assert auth.compute_readiness(SID) == "blocked"
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    assert auth.activate_layout(nxt)[0]
    assert auth.compute_readiness(SID) == "syncing_assets"
    auth.on_session_lost(SID)
    assert auth.compute_readiness(SID) == "disconnected"


def test_end_and_refresh_require_issued_lease() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    inv = "0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
    begin = run(auth, client.begin_momentary("fog_burst", invocation_id=inv), client=client)
    lease = begin[0].payload["result"]["lease_id"]
    missing = run(auth, client.invoke("fog_burst", "momentary_end", invocation_id=inv))
    assert missing[0].payload["error"]["code"] == "remote.momentary.unknown_invocation"
    assert auth.effect_active("fog_burst")
    wrong = run(auth, client.end_momentary("fog_burst", inv, lease_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ee"))
    assert wrong[0].payload["error"]["code"] == "remote.momentary.unknown_invocation"
    refresh = make_envelope(
        type="remote.momentary.refresh",
        source=SRC,
        payload={"control_id": "fog_burst", "invocation_id": inv},
    )
    assert run(auth, refresh)[0].payload["error"]["code"] == "remote.momentary.unknown_invocation"
    ok = run(auth, client.end_momentary("fog_burst", inv, lease_id=lease), client=client)
    assert ok[0].payload["status"] == "applied"
    stale = run(auth, client.end_momentary("fog_burst", inv, lease_id=lease), client=client)
    assert stale[0].payload["status"] == "applied"


def test_same_revision_layout_mutation_rejected() -> None:
    auth = authority()
    changed = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    changed["controls"][0]["label"] = "CHANGED"
    ok, _ = auth.activate_layout(changed)
    assert ok is False
    assert auth.layout["controls"][0]["label"] == "GO"
    replay = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    assert auth.activate_layout(replay)[0] is True
    bad_hash = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    bad_hash["revision"] = 9
    bad_hash["sha256"] = "0" * 64
    assert auth.activate_layout(bad_hash)[0] is False
    assert auth.layout["revision"] == 8


def test_hello_starts_unsynced_and_own_command_stays_ready() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
    hello = make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id))
    run(auth, hello)
    assert auth.compute_readiness(SID) == "syncing_assets"
    sending = run(auth, make_envelope(type="remote.layout.request", source=SRC, payload={}))
    assert any(m.type == "remote.layout.report" for m in sending)
    assert auth.compute_readiness(SID) == "syncing_assets"
    sync_session(auth)
    assert auth.compute_readiness(SID) == "ready"
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    first = run(auth, client.invoke("cue_go"), client=client)
    assert first[0].payload["status"] == "applied"
    assert auth.compute_readiness(SID) == "ready"
    second = run(auth, client.invoke("work_lights", "set", value=True), client=client)
    assert second[0].payload["status"] == "applied"
    third = run(auth, client.invoke("cue_go"), client=client)
    assert third[0].payload["status"] == "applied"
    assert auth.go_count == 2
    assert auth.compute_readiness(SID) == "ready"


def test_prism_profile_required_on_production_handle() -> None:
    auth = authority()
    session = _established_session()
    session.negotiated_profiles = {"core"}
    hello = make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id))
    out = auth.handle(hello, session)
    assert out[0].payload["error"]["code"] == "capability_not_permitted"


def test_select_does_not_load_and_load_changes_live_song() -> None:
    auth = authority()
    live = auth.song_id
    select = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("song_select", value="encore"))
    assert select[0].payload["status"] == "applied"
    assert auth.selected_song_id == "encore"
    assert auth.song_id == live
    load = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("song_load", value="encore"))
    assert load[0].payload["status"] == "applied"
    assert auth.song_id == "encore"
    assert any(m.type == "state.delta" and m.payload["resource"] == "show.current_song" for m in load)


def test_free_play_preserves_cue_and_song_return_context() -> None:
    auth = authority()
    auth.cue_id = "verse"
    auth.next_cue_id = "chorus"
    enter = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("free_play_enter"))
    assert enter[0].payload["status"] == "applied"
    assert auth.mode == "free_play"
    assert auth.return_context["return_song_id"] == "haywire"
    assert auth.return_context["return_cue_id"] == "verse"
    run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="full_white"))
    assert auth.current_look_id == "full_white"
    auth.song_id = "closer"
    auth.cue_id = "bridge"
    exit_fp = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("free_play_exit"))
    assert exit_fp[0].payload["status"] == "applied"
    assert auth.mode == "programmed"
    assert auth.song_id == "haywire"
    assert auth.cue_id == "verse"


def test_look_transition_cut_versus_fade() -> None:
    auth = authority()
    fade = make_envelope(
        type="remote.control.invoke",
        source=SRC,
        payload={
            "control_id": "look_recall",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
            "interaction": "activate",
            "look_id": "slow_song",
            "transition": {"transition_mode": "fade", "transition_ms": 2500},
            "show_id": SHOW,
            "layout_id": LAYOUT,
            "layout_revision": 8,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
        },
    )
    out = run(auth, fade)
    assert out[0].payload["status"] == "applied"
    assert out[0].payload["result"]["transition"]["transition_ms"] == 2500
    cut = make_envelope(
        type="remote.control.invoke",
        source=SRC,
        payload={
            "control_id": "look_recall",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000ab",
            "interaction": "activate",
            "look_id": "full_white",
            "transition": {"transition_mode": "cut", "transition_ms": 0},
            "show_id": SHOW,
            "layout_id": LAYOUT,
            "layout_revision": 8,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000ab",
        },
    )
    out = run(auth, cut)
    assert out[0].payload["result"]["transition"]["transition_mode"] == "cut"
    delta = next(m for m in out if m.type == "state.delta")
    assert delta.payload["resource"] == "look.current"


def test_live_ephemeral_go_expires_and_is_not_replayed() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    env = client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ac")
    payload = dict(env.payload)
    payload["delivery"] = "live_ephemeral"
    payload["issued_at"] = "2020-01-01T00:00:00.000Z"
    payload["expires_at"] = "2020-01-01T00:00:01.000Z"
    stale = make_envelope(type="remote.control.invoke", source=SRC, payload=payload)
    out = run(auth, stale)
    assert out[0].payload["error"]["code"] == "remote.command.expired"
    assert auth.go_count == 0
    first = run(auth, client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ad"))
    assert first[0].payload["status"] == "applied"
    replay = run(auth, client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ad"))
    assert replay[0].payload["status"] == "applied"
    assert auth.go_count == 1
    auth.on_session_lost(SID)
    auth.bind_test_session("0193f8d8-4c4e-7d8b-a2ab-0000000000c9", SRC.node_id)
    late = make_envelope(type="remote.control.invoke", source=SRC, payload=payload)
    again = run(auth, late, session_id="0193f8d8-4c4e-7d8b-a2ab-0000000000c9")
    assert again[0].payload["error"]["code"] == "remote.command.expired"


def test_ack_does_not_update_authoritative_view() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    out = run(auth, client.invoke("cue_go"), client=client)
    client.record_result(str(out[0].payload.get("result", {}).get("control_id") or out[0].causation_id), out[0])
    assert "cue.current" not in client.view
    for msg in out:
        client.apply_publication(msg)
    assert client.view["cue.current"]["cue_id"] == auth.cue_id


def test_failsafe_required_rejects_unleasable_momentary() -> None:
    auth = authority()
    fog = auth.control("fog_burst")
    assert fog is not None
    fog["safety"] = {"class": "caution", "failsafe_required": True, "failsafe": "hold_last_state", "max_hold_ms": 0}
    out = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).begin_momentary("fog_burst"))
    assert out[0].payload["error"]["code"] == "remote.command.invalid_state"


def test_incompatible_surface_schema_keeps_prior() -> None:
    auth = authority()
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["min_client_schema"] = "9.0"
    nxt["max_client_schema"] = "9.0"
    ok, kept = auth.activate_layout(nxt)
    assert ok is False
    assert kept["revision"] == 8
    assert auth.layout["revision"] == 8


def test_unknown_control_type_does_not_fail_surface() -> None:
    auth = authority()
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["controls"] = list(nxt["controls"]) + [{
        "control_id": "future_pad",
        "label": "Future",
        "control_type": "hologram_well",
        "binding": {"target": "prism", "action": "cue.go"},
        "safety": {"class": "normal"},
    }]
    ok, _ = auth.activate_layout(nxt)
    assert ok is True
    denied = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT, layout_revision=9).invoke("future_pad"))
    assert denied[0].payload["error"]["code"] == "unsupported"


PRISM_REMOTE_1_0_ACTIONS = (
    "show.song.stop",
    "show.song.next",
    "show.song.previous",
    "show.section.next",
    "show.section.previous",
    "show.section.restart",
    "show.progression.hold",
    "effects.stop",
)


def test_prism_remote_1_0_actions_are_allowlisted() -> None:
    from acp.constants import load
    from acp.state_revision import NEVER_COALESCE_ACTIONS

    catalog = load()["remote"]
    for action in catalog["actions"]:
        assert action in ACTION_POLICY
        assert action in ACTION_FEATURE
        assert action in PERMISSION_FOR_ACTION
        assert ACTION_DELIVERY.get(action) in {"live_ephemeral", "impulse", "stateful"}
    for action in PRISM_REMOTE_1_0_ACTIONS:
        assert action in catalog["actions"]
    assert set(ACTION_POLICY) == set(catalog["actions"])
    assert set(ACTION_DELIVERY) == set(catalog["action_delivery"])
    assert ACTION_DELIVERY == catalog["action_delivery"]
    assert set(EXECUTABLE_SURFACE_KEYS) == set(catalog["executable_surface_keys"])
    assert "expression" in EXECUTABLE_SURFACE_KEYS
    assert set(NEVER_COALESCE_ACTIONS) == set(catalog["never_coalesce_actions"])
    assert "prism.internal.setChannel" not in ACTION_POLICY


def test_executable_surface_payload_rejected() -> None:
    auth = authority()
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["controls"][0]["script"] = "alert(1)"
    ok, _ = auth.activate_layout(nxt)
    assert ok is False


def test_expression_surface_payload_rejected() -> None:
    auth = authority()
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["controls"][0]["expression"] = "x+1"
    ok, _ = auth.activate_layout(nxt)
    assert ok is False


def test_prism_remote_1_0_namespaces_are_published() -> None:
    from acp.constants import load

    auth = authority()
    catalog = load()["remote"]["state_namespaces"]
    allowed = auth._authorized_namespaces(SRC.node_id, None)
    for ns in catalog:
        assert ns in allowed, ns
        assert auth._namespace_resource(ns) is not None, ns
    for ns in (
        "show.current_section",
        "show.next_section",
        "show.running",
        "show.progression",
        "look.catalog",
        "look.preview",
    ):
        assert ns in allowed
        item = auth._namespace_resource(ns)
        assert item is not None
        assert item["resource"] == ns


def test_observe_only_denied_go_and_look() -> None:
    auth = authority()
    auth.authorize(SRC.node_id, ["remote.viewer"])
    go = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert go[0].payload["error"]["code"] == "remote.control.permission_denied"
    look = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="slow_song"))
    assert look[0].payload["error"]["code"] == "remote.control.permission_denied"
    assert auth.go_count == 0
    assert auth.current_look_id is None


def test_conflicting_looks_last_commit_wins() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.viewer"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    a = make_envelope(
        type="remote.control.invoke",
        source=SRC,
        payload={
            "control_id": "look_recall",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b2",
            "interaction": "activate",
            "look_id": "blue_ballad",
            "show_id": SHOW,
            "layout_id": LAYOUT,
            "layout_revision": 8,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000b2",
        },
    )
    b = make_envelope(
        type="remote.control.invoke",
        source=SRC_B,
        payload={
            "control_id": "look_recall",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b3",
            "interaction": "activate",
            "look_id": "full_white",
            "show_id": SHOW,
            "layout_id": LAYOUT,
            "layout_revision": 8,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000b3",
        },
    )
    first = run(auth, a)
    second = run(auth, b, session_id=SID_B)
    assert first[0].payload["status"] == "applied"
    assert second[0].payload["status"] == "applied"
    assert auth.current_look_id == "full_white"
    assert auth.last_committed["extra"]["look_id"] == "full_white"


class _StickyRouter(MemoryActionRouter):
    def __init__(self) -> None:
        super().__init__(None)
        self.physical: dict[str, bool] = {}

    def begin(self, action: str, control: dict, ctx: ActionContext) -> ActionResult:
        del action, control
        self.physical[ctx.control_id] = True
        return ActionResult(ok=True)

    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action, control
        return ActionResult(ok=False, code="internal", message="hardware stuck", extra={"reason": ctx.reason})


def test_live_ephemeral_go_requires_lifetime_and_survives_reconnect() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    env = client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000c8")
    first = run(auth, env, client=client)
    assert first[0].payload["status"] == "applied"
    assert auth.go_count == 1
    auth.on_session_lost(SID)
    auth.bind_test_session(SID_B, SRC.node_id)
    replay = run(auth, env, session_id=SID_B, client=client)
    assert replay[0].payload["status"] == "applied"
    assert auth.go_count == 1
    stale = dict(env.payload)
    stale["issued_at"] = "2020-01-01T00:00:00.000Z"
    stale["expires_at"] = "2020-01-01T00:00:01.000Z"
    late = make_envelope(type="remote.control.invoke", source=SRC, payload=stale)
    expired = run(auth, late, session_id=SID_B)
    assert expired[0].payload["error"]["code"] == "remote.command.expired"
    assert expired[0].payload["error"]["details"]["disposition"] == "expired"
    assert auth.go_count == 1
    bare = make_envelope(
        type="remote.control.invoke",
        source=SRC,
        payload={
            "control_id": "cue_go",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000c7",
            "interaction": "activate",
            "show_id": SHOW,
            "layout_id": LAYOUT,
            "layout_revision": 8,
            "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000c7",
        },
    )
    missing = run(auth, bare, session_id=SID_B)
    assert missing[0].payload["error"]["code"] == "remote.command.expired"


def test_wall_clock_expires_hold_without_manual_tick() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, use_manual_clock=False)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
    auth.bind_test_session(SID, SRC.node_id)
    fog = auth.control("fog_burst")
    assert fog is not None
    fog["safety"]["max_hold_ms"] = 1
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    assert auth.effect_active("fog_burst")
    time.sleep(0.02)
    expired = auth.expire_due()
    assert expired
    assert not auth.effect_active("fog_burst")


def test_failed_force_release_keeps_physical_and_published_active() -> None:
    auth = authority()
    router = _StickyRouter()
    router.bind(auth)
    auth.router = router
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    assert auth.effect_active("fog_burst")
    assert router.physical["fog_burst"] is True
    released = auth.on_session_lost(SID)
    assert released == []
    assert auth.effect_active("fog_burst")
    assert router.physical["fog_burst"] is True
    assert auth.unsafe_releases
    assert any(item.get("status") == "release_pending" for item in auth.last_releases)


def test_feature_capabilities_fail_closed() -> None:
    auth = authority()
    auth._active_features = set()
    denied = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="slow_song"))
    assert denied[0].payload["error"]["code"] == "capability_not_permitted"
    auth._active_features = {"look.global"}
    ok = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="slow_song"))
    assert ok[0].payload["status"] == "applied"
    go = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert go[0].payload["error"]["code"] == "capability_not_permitted"


def test_grand_master_rejects_out_of_range() -> None:
    auth = authority()
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    bad = run(auth, client.invoke("grand_master", "set", value=2.5), client=client)
    assert bad[0].payload["error"]["code"] == "remote.control.invalid_value"
    nan = run(auth, client.invoke("grand_master", "set", value=float("nan")), client=client)
    assert nan[0].payload["error"]["code"] == "remote.control.invalid_value"
    ok = run(auth, client.invoke("grand_master", "set", value=0.7), client=client)
    assert ok[0].payload["status"] == "applied"


def test_nested_executable_surface_rejected() -> None:
    auth = authority()
    nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    nxt["revision"] = 9
    nxt["controls"][0]["binding"]["parameters"] = {"script": "rm -rf /"}
    assert auth.activate_layout(nxt)[0] is False


def test_cached_surface_hash_skips_body() -> None:
    auth = authority()
    digest = layout_fingerprint(auth.layout)
    env = make_envelope(
        type="remote.layout.request",
        source=SRC,
        payload={"show_id": SHOW, "layout_id": LAYOUT, "cached_sha256": digest},
    )
    out = run(auth, env)
    report = next(m for m in out if m.type == "remote.layout.report")
    assert report.payload.get("cached") is True
    assert "layout" not in report.payload


def test_fanout_look_to_peer_session() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.viewer"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    a = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    b = RemoteClient(SRC_B, show_id=SHOW, layout_id=LAYOUT)
    out = run(auth, a.invoke("look_recall", value="blue_ballad"), client=a)
    a.ingest(out)
    peer = auth.take_outbound(SID_B)
    assert peer
    b.ingest(peer)
    assert a.view["look.current"]["look_id"] == "blue_ballad"
    assert b.view["look.current"]["look_id"] == "blue_ballad"


def test_prism_authority_rejects_conductor_profile() -> None:
    auth = authority()
    session = _established_session()
    session.negotiated_profiles = {"aurora.remote.conductor.v1"}
    hello = make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id))
    out = auth.handle(hello, session)
    assert out[0].payload["error"]["code"] == "capability_not_permitted"


def test_hello_advertises_permissions() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator"])
    out = run(auth, make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id)))
    perms = next(m for m in out if m.type == "remote.permissions")
    assert "cue.execute" in perms.payload["permissions"]
    assert "observe" in perms.payload["permissions"]


def test_reconnect_requires_fresh_sync() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.viewer"])
    run(auth, make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id)))
    sync_session(auth)
    assert auth.compute_readiness(SID) == "ready"
    auth.on_session_lost(SID)
    assert auth.compute_readiness(SID) == "disconnected"
    run(auth, make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id)))
    assert auth.compute_readiness(SID) == "syncing_assets"
    sync_session(auth)
    assert auth.compute_readiness(SID) == "ready"


def test_peer_stays_ready_after_other_client_action() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.operator", "remote.viewer"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert auth.compute_readiness(SID) == "ready"
    assert auth.compute_readiness(SID_B) == "ready"
    auth.mark_missed_delta(SID_B)
    assert auth.compute_readiness(SID_B) == "syncing_state"
    sync_session(auth, SID_B, SRC_B)
    assert auth.compute_readiness(SID_B) == "ready"


def test_readiness_requires_layout_hash() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=True)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.viewer"])
    run(auth, make_envelope(type="remote.hello", source=SRC, payload=hello_payload(SRC.node_id)))
    run(auth, make_envelope(type="remote.layout.request", source=SRC, payload={}))
    wrong = make_envelope(
        type="remote.readiness",
        source=SRC,
        payload={"state": "ready", "layout_revision": 8, "layout_hash": "0" * 64, "snapshot_revision": 1},
    )
    out = run(auth, wrong)
    assert out[0].payload["state"] == "syncing_assets"


def test_enrollment_conflict_rolls_back_indexes() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    first = Enrollment(node_id=SRC.node_id, device_id=DEVICE, remote_id=REMOTE, participant_id=PARTICIPANT)
    auth.enroll(first, roles=["remote.operator"])
    other = Enrollment(
        node_id=SRC_B.node_id,
        device_id="0193f8d8-4c4e-7d8b-a2ab-0000000000d8",
        remote_id="0193f8d8-4c4e-7d8b-a2ab-0000000000d9",
    )
    auth.enroll(other)
    stolen = Enrollment(node_id=SRC.node_id, device_id=DEVICE, remote_id=other.remote_id)
    with pytest.raises(ValueError, match="remote_id already enrolled"):
        auth.enroll(stolen)
    assert auth.enrollment[SRC.node_id] == first
    assert auth._bound_device[DEVICE] == SRC.node_id
    assert auth._bound_remote[REMOTE] == SRC.node_id
    assert auth._bound_participant[PARTICIPANT] == SRC.node_id
    env = make_envelope(type="remote.hello", source=SRC_B, payload=hello_payload(SRC_B.node_id, remote_id=REMOTE))
    out = run(auth, env, session_id=SID_B)
    assert out[0].payload["error"]["code"] == "authentication"


def test_enrollment_multi_field_and_role_update_rollback() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW)
    original = Enrollment(node_id=SRC.node_id, device_id=DEVICE, remote_id=REMOTE, operator_id=PARTICIPANT)
    auth.enroll(original, roles=["remote.operator"])
    auth.enroll(Enrollment(node_id=SRC_B.node_id, participant_id="0193f8d8-4c4e-7d8b-a2ab-0000000000da"))
    conflict = Enrollment(
        node_id=SRC.node_id,
        device_id="0193f8d8-4c4e-7d8b-a2ab-0000000000db",
        remote_id=REMOTE,
        participant_id="0193f8d8-4c4e-7d8b-a2ab-0000000000da",
    )
    with pytest.raises(ValueError, match="participant_id"):
        auth.enroll(conflict, roles=["remote.admin"])
    assert auth.enrollment[SRC.node_id] == original
    assert auth._bound_device[DEVICE] == SRC.node_id
    assert "remote.operator" in auth.policy[SRC.node_id]
    assert "remote.admin" not in auth.policy[SRC.node_id]


class _RejectRouter(MemoryActionRouter):
    def apply(self, action: str, control: dict, ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        return ActionResult(ok=False, code="remote.control.unavailable", message="prism offline")


class _TimeoutRouter(MemoryActionRouter):
    def apply(self, action: str, control: dict, ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        return ActionResult(ok=False, status="timeout", code="timeout", message="router timeout", retryable=True)


class _BoomRouter(MemoryActionRouter):
    def apply(self, action: str, control: dict, ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        raise RuntimeError("router exploded")

    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action, control
        return ActionResult(ok=False, extra={"reason": ctx.reason})


def test_router_rejection_timeout_and_exception() -> None:
    auth = authority()
    auth.router = _RejectRouter(auth)
    denied = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert denied[0].payload["error"]["code"] == "remote.control.unavailable"
    assert auth.go_count == 0
    auth.router = _TimeoutRouter(auth)
    timed = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert timed[0].payload["error"]["code"] == "timeout"
    assert timed[0].payload["error"]["retryable"] is True
    auth.router = _BoomRouter(auth)
    boom = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert boom[0].payload["error"]["code"] == "internal"


def test_router_force_release_on_disconnect_and_recovery(tmp_path) -> None:
    store = NodeStore(tmp_path)
    auth = authority()
    auth.store = store
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    assert auth.effect_active("fog_burst")
    snapshot = auth.export_safety_state()
    assert snapshot["holds"]
    released = auth.on_session_lost(SID)
    assert "fog_burst" in released
    assert any(item["reason"] == "disconnect" for item in auth.last_releases)
    recovered = auth.recover_from_restart(snapshot)
    assert "fog_burst" in recovered
    assert any(item["reason"] == "process_recovery" for item in auth.last_releases)
    assert not auth.effect_active("fog_burst")


def test_unknown_remote_message_fails_closed() -> None:
    auth = authority()
    out = run(auth, make_envelope(type="remote.hello_ack", source=SRC, payload={"accepted": True}))
    assert out[0].payload["error"]["code"] == "unsupported"
    assert auth.inbound_handler_gaps() == set()


def test_independent_roles_do_not_imply_each_other() -> None:
    auth = authority()
    auth.authorize(SRC.node_id, ["remote.busker"])
    fog = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).begin_momentary("fog_burst"))
    assert fog[0].payload["error"]["code"] == "remote.control.permission_denied"
    auth.authorize(SRC.node_id, ["remote.show_navigation"])
    go = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert go[0].payload["error"]["code"] == "remote.control.permission_denied"
    nav = run(
        auth,
        make_envelope(
            type="remote.navigation.request",
            source=SRC,
            payload={"kind": "next", "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000f8"},
        ),
    )
    assert nav[0].payload["status"] == "applied"


def test_live_client_request_correlates_ack_and_lease() -> None:
    async def body() -> None:
        client_sess, server = await connected_pair(Role.REMOTE, Role.CONDUCTOR, default_caps())
        auth = RemoteAuthority(source=server.source(), show_id=SHOW, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(client_sess.local.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        remote = RemoteClient(
            client_sess.source(),
            show_id=SHOW,
            layout_id=LAYOUT,
            session=client_sess,
        )

        async def serve() -> None:
            async for env in server.subscribe():
                if env.type.startswith("remote."):
                    for reply in auth.handle(env, server):
                        await server.send(reply)

        task = asyncio.create_task(serve())
        try:
            hello = make_envelope(
                type="remote.hello",
                source=client_sess.source(),
                destination=Endpoint(node_id=client_sess.peer.node_id) if client_sess.peer else None,
                payload=hello_payload(client_sess.local.node_id),
            )
            ack = await remote.request(hello)
            assert ack.type == "remote.hello_ack"
            assert auth.compute_readiness(server.session_id or "") == "syncing_assets"
            report = await remote.request(remote.layout_request())
            layout = report.payload["layout"]
            await asyncio.sleep(0.05)
            snap_rev = auth.snapshot_revision
            ready = await remote.request(remote.readiness_ack(layout=layout, snapshot_revision=snap_rev))
            assert ready.payload["state"] == "ready"
            first = await remote.invoke_wait("cue_go")
            assert first.payload["status"] == "applied"
            second = await remote.invoke_wait("cue_go")
            assert second.payload["status"] == "applied"
            third = await remote.invoke_wait("work_lights", "set", value=True)
            assert third.payload["status"] == "applied"
            begin = await remote.begin_momentary_wait("fog_burst")
            inv = str(begin.payload["result"].get("control_id") and begin.causation_id or "")
            lease_inv = next(iter(remote.leases))
            assert remote.leases[lease_inv]
            ended = await remote.end_momentary_wait("fog_burst", lease_inv)
            assert ended.payload["status"] == "applied"
            assert lease_inv not in remote.leases
            del inv
        finally:
            task.cancel()
            await client_sess.goodbye()
            await server.goodbye()

    asyncio.run(body())


def _blinder_layout(revision: int = 9) -> dict:
    layout = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    layout["revision"] = revision
    layout["controls"] = list(layout["controls"]) + [{
        "control_id": "blinder",
        "label": "Blinders",
        "control_type": "momentary",
        "permission": "remote.busker",
        "style": "warning",
        "feedback": "state",
        "concurrency": "shared",
        "binding": {"target": "prism", "action": "busk.blinder"},
        "safety": {
            "class": "caution",
            "failsafe": "release_on_disconnect",
            "failsafe_required": True,
            "max_hold_ms": 10000,
            "heartbeat_required": True,
        },
    }]
    layout["pages"][0]["groups"][0]["controls"] = ["cue_go", "fog_burst", "work_lights", "blinder"]
    return layout


class _PartialReleaseRouter(MemoryActionRouter):
    def __init__(self, authority: RemoteAuthority | None = None) -> None:
        super().__init__(authority)
        self.attempts = 0
        self.released: list[str] = []
        self.failed: list[str] = []

    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action
        cid = str((control or {}).get("control_id") or ctx.control_id)
        self.attempts += 1
        if self.attempts >= 2:
            self.failed.append(cid)
            return ActionResult(ok=False, code="timeout", message="second hold stuck", retryable=True)
        self.released.append(cid)
        return ActionResult(ok=True, extra={"reason": ctx.reason or "forced"})


class _FlakyReleaseRouter(MemoryActionRouter):
    def __init__(self) -> None:
        super().__init__(None)
        self.fails_left = 2

    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action, control
        if self.fails_left > 0:
            self.fails_left -= 1
            return ActionResult(ok=False, code="timeout", message="still stuck", retryable=True)
        return ActionResult(ok=True, extra={"reason": ctx.reason or "forced"})


class _TimeoutReleaseRouter(MemoryActionRouter):
    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action, control
        return ActionResult(ok=False, status="timeout", code="timeout", message="release timeout", retryable=True)


class _BoomReleaseRouter(MemoryActionRouter):
    def force_release(self, action: str, control: dict | None, ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        raise RuntimeError("hardware exception")


class _FailingStore(NodeStore):
    def save(self, name: str, value: object) -> None:
        del name, value
        raise OSError("disk full")


def test_navigation_go_is_live_ephemeral_and_not_replayed() -> None:
    auth = authority()
    from datetime import UTC, datetime, timedelta

    issued = datetime.now(UTC)
    payload = {
        "kind": "go",
        "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
        "issued_at": format_ts(issued),
        "expires_at": format_ts(issued + timedelta(milliseconds=5000)),
        "max_age_ms": 5000,
        "delivery": "live_ephemeral",
    }
    env = make_envelope(type="remote.navigation.request", source=SRC, payload=payload)
    first = run(auth, env)
    assert first[0].payload["status"] == "applied"
    assert auth.go_count == 1
    auth.on_session_lost(SID)
    auth.bind_test_session(SID_B, SRC.node_id)
    replay = run(auth, env, session_id=SID_B)
    assert replay[0].payload["status"] == "applied"
    assert auth.go_count == 1
    stale = dict(payload)
    stale["issued_at"] = "2020-01-01T00:00:00.000Z"
    stale["expires_at"] = "2020-01-01T00:00:01.000Z"
    expired = run(auth, make_envelope(type="remote.navigation.request", source=SRC, payload=stale), session_id=SID_B)
    assert expired[0].payload["error"]["code"] == "remote.command.expired"
    assert expired[0].payload["error"]["details"]["disposition"] == "expired"
    assert auth.go_count == 1
    bare = run(
        auth,
        make_envelope(
            type="remote.navigation.request",
            source=SRC,
            payload={"kind": "go", "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000ab"},
        ),
        session_id=SID_B,
    )
    assert bare[0].payload["error"]["code"] == "remote.command.expired"
    assert auth.go_count == 1


def test_invoke_retransmits_immutable_envelope() -> None:
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    first = client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ad")
    time.sleep(0.002)
    replay = client.invoke("cue_go", invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000ad")
    assert replay is first
    assert replay.payload["interaction"] == "activate"
    assert replay.payload["issued_at"] == first.payload["issued_at"]
    auth = authority()
    auth.use_manual_clock = True
    auth.now_ms = 1
    out1 = run(auth, first)
    auth.now_ms = 5000
    out2 = run(auth, replay)
    assert out1[0].payload["status"] == "applied"
    assert out2[0].payload["status"] == "applied"
    assert auth.go_count == 1


def test_cancel_pending_ephemeral_preserves_stateful() -> None:
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    go = client.invoke("cue_go")
    lights = client.invoke("work_lights", "set", value=True)
    assert go.payload["invocation_id"] in client.pending
    assert lights.payload["invocation_id"] in client.pending
    client.cancel_pending_ephemeral()
    assert go.payload["invocation_id"] not in client.pending
    assert lights.payload["invocation_id"] in client.pending


def test_layout_change_does_not_resurrect_released_hold() -> None:
    auth = authority()
    assert auth.activate_layout(_blinder_layout(9))[0]
    auth.router = _PartialReleaseRouter(auth)
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT, layout_revision=9)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    run(auth, client.begin_momentary("blinder"), client=client)
    assert auth.effect_active("fog_burst")
    assert auth.effect_active("blinder")
    nxt = _blinder_layout(10)
    nxt["controls"] = [c for c in nxt["controls"] if c["control_id"] not in {"fog_burst", "blinder"}]
    nxt["pages"][0]["groups"][0]["controls"] = ["cue_go", "work_lights"]
    router = auth.router
    assert isinstance(router, _PartialReleaseRouter)
    ok, _ = auth.activate_layout(nxt)
    assert ok is False
    assert auth.layout["revision"] == 9
    assert router.released
    assert router.failed
    released_cid = router.released[0]
    failed_cid = router.failed[0]
    assert released_cid not in auth.holds
    assert not auth.effect_active(released_cid)
    assert auth.effect_active(failed_cid)
    hold = next(iter(auth.holds[failed_cid].values()))
    assert hold.release_pending is True
    assert any(item.get("control_id") == released_cid and item.get("router_ok") for item in auth.last_releases)
    assert any(
        item.get("control_id") == failed_cid and item.get("status") == "release_pending"
        for item in auth.last_releases
    )
    begin = run(auth, client.begin_momentary(failed_cid, invocation_id="0193f8d8-4c4e-7d8b-a2ab-0000000000f9"))
    assert begin[0].payload["error"]["code"] == "remote.control.conflict"


def test_recovery_retains_failed_release(tmp_path) -> None:
    store = NodeStore(tmp_path)
    auth = authority()
    auth.store = store
    client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
    run(auth, client.begin_momentary("fog_burst"), client=client)
    snapshot = auth.export_safety_state()
    assert "expires_at_ms" in snapshot["holds"][0]
    assert snapshot["version"] == 2
    auth.router = _StickyRouter()
    auth.router.bind(auth)
    recovered = auth.recover_from_restart(snapshot)
    assert recovered == []
    assert auth.effect_active("fog_burst")
    hold = next(iter(auth.holds["fog_burst"].values()))
    assert hold.release_pending is True
    assert hold.physical_active is True
    assert auth.health["engine"] == "critical"
    assert any(item.get("code") == "remote.control.unconfirmed_release" for item in auth._safety_events)
    persisted = store.load("remote_safety", {})
    assert persisted["holds"]
    assert persisted["holds"][0]["release_pending"] is True


def test_recovery_migrates_legacy_record_and_eventual_success(tmp_path) -> None:
    store = NodeStore(tmp_path)
    auth = authority()
    auth.store = store
    legacy = {
        "holds": [{
            "control_id": "fog_burst",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
            "session_id": SID,
            "node_id": SRC.node_id,
            "started_ms": 1,
            "max_hold_ms": 10000,
            "failsafe": "release_on_disconnect",
            "lease_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000ab",
            "value": 1.0,
        }],
    }
    router = _FlakyReleaseRouter()
    router.bind(auth)
    auth.router = router
    first = auth.recover_from_restart(legacy)
    assert first == []
    assert auth.effect_active("fog_burst")
    again = auth.retry_unsafe_releases()
    assert again == []
    done = auth.retry_unsafe_releases()
    assert "fog_burst" in done
    assert not auth.effect_active("fog_burst")


def test_recovery_timeout_exception_and_store_failure(tmp_path) -> None:
    auth = authority()
    snapshot = {
        "version": 2,
        "holds": [{
            "control_id": "fog_burst",
            "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
            "session_id": SID,
            "node_id": SRC.node_id,
            "started_ms": 1,
            "max_hold_ms": 10000,
            "failsafe": "release_on_disconnect",
            "lease_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000ab",
            "value": 1.0,
            "expires_at_ms": 10001,
            "release_pending": False,
            "release_reason": None,
            "physical_active": True,
        }],
    }
    auth.router = _TimeoutReleaseRouter(auth)
    assert auth.recover_from_restart(snapshot) == []
    assert auth.effect_active("fog_burst")
    auth2 = authority()
    auth2.router = _BoomReleaseRouter(auth2)
    assert auth2.recover_from_restart(snapshot) == []
    assert auth2.effect_active("fog_burst")
    auth3 = authority()
    auth3.store = _FailingStore(tmp_path)
    with pytest.raises(OSError, match="disk full"):
        auth3.recover_from_restart(snapshot)
    assert auth3._safety_events


def test_fanout_filters_subscriptions_and_capabilities() -> None:
    auth = authority()
    auth.authorize(SRC_B.node_id, ["remote.viewer"])
    auth.bind_test_session(SID_B, SRC_B.node_id)
    rec = auth.sessions[SID_B]
    rec["features"] = {"state.live", "show.navigation", "system.health"}
    rec["subscriptions"] = {"show.navigation", "system.health"}
    out = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="blue_ballad"))
    assert any(m.type == "state.delta" and m.payload["resource"] == "look.current" for m in out)
    peer = auth.take_outbound(SID_B)
    assert not any(m.type == "state.delta" and m.payload.get("resource") == "look.current" for m in peer)
    rec["features"] = {"look.global", "state.live"}
    rec["subscriptions"] = {"look.current"}
    rec["resync_required"] = False
    run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="full_white"))
    peer2 = auth.take_outbound(SID_B)
    assert any(m.type == "state.delta" and m.payload.get("resource") == "look.current" for m in peer2)
    rec["resync_required"] = True
    run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("look_recall", value="slow_song"))
    assert not any(
        m.type == "state.delta" and m.payload.get("resource") == "look.current"
        for m in auth.take_outbound(SID_B)
    )


def test_error_vocabulary_is_stable() -> None:
    auth = authority()
    denied = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("nope"))
    err = denied[0].payload["error"]
    assert err["details"]["disposition"] == "not_found"
    assert err["category"] == "not_found"
    auth.authorize(SRC.node_id, ["remote.viewer"])
    go = run(auth, RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT).invoke("cue_go"))
    assert go[0].payload["error"]["details"]["disposition"] == "unauthorized"
    assert go[0].payload["error"]["category"] == "authorization"


def test_scheduler_expires_and_shutdown_releases() -> None:
    async def body() -> None:
        auth = RemoteAuthority(source=AUTH, show_id=SHOW, use_manual_clock=False, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(SRC.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        auth.bind_test_session(SID, SRC.node_id)
        fog = auth.control("fog_burst")
        assert fog is not None
        fog["safety"]["max_hold_ms"] = 40
        client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
        run(auth, client.begin_momentary("fog_burst"), client=client)
        assert auth.effect_active("fog_burst")
        auth.start_scheduler()
        await asyncio.sleep(0.12)
        assert not auth.effect_active("fog_burst")
        retry_id = "0193f8d8-4c4e-7d8b-a2ab-0000000000ae"
        run(auth, client.begin_momentary("fog_burst", invocation_id=retry_id), client=client)
        assert auth.effect_active("fog_burst")
        await auth.stop_scheduler()
        assert not auth.effect_active("fog_burst")

    asyncio.run(body())


def test_scheduler_resumes_after_event_loop_stall() -> None:
    async def body() -> None:
        auth = RemoteAuthority(source=AUTH, show_id=SHOW, use_manual_clock=False, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(SRC.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        auth.bind_test_session(SID, SRC.node_id)
        fog = auth.control("fog_burst")
        assert fog is not None
        fog["safety"]["max_hold_ms"] = 30
        client = RemoteClient(SRC, show_id=SHOW, layout_id=LAYOUT)
        run(auth, client.begin_momentary("fog_burst"), client=client)
        auth.start_scheduler()
        end = time.monotonic() + 0.08
        while time.monotonic() < end:
            pass
        await asyncio.sleep(0.05)
        assert not auth.effect_active("fog_burst")
        await auth.stop_scheduler()

    asyncio.run(body())


async def _connected_remotes() -> tuple[Session, Session, Session, Session]:
    caps = default_caps()
    server_ident = identity(Role.CONDUCTOR, "auth")
    profiles = ["core", "remote", "aurora.remote.prism.v1"]
    pairs = []
    for name in ("a", "b"):
        ta, tb = linked_transports()
        client = Session(
            ta, identity(Role.REMOTE, name), is_server=False, allow_plaintext=True, profiles=profiles,
        )
        server = Session(
            tb, server_ident, is_server=True, allow_plaintext=True, profiles=profiles,
        )
        await server.start_receiver()
        await asyncio.gather(server.handshake(caps), client.handshake(caps))
        pairs.append((client, server))
    (client_a, server_a), (client_b, server_b) = pairs
    return client_a, server_a, client_b, server_b


def test_live_host_two_clients_converge_and_idle_expiry() -> None:
    async def body() -> None:
        client_a, server_a, client_b, server_b = await _connected_remotes()
        host_auth = RemoteAuthority(source=server_a.source(), show_id=SHOW, inline_surface=True)
        host_auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        host_auth.authorize(client_a.local.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        host_auth.authorize(client_b.local.node_id, ["remote.operator", "remote.viewer"])
        fog = host_auth.control("fog_burst")
        assert fog is not None
        fog["safety"]["max_hold_ms"] = 80
        host = RemoteHost(host_auth, inline_surface=True)
        await host.start()
        ta = asyncio.create_task(host.serve(server_a))
        tb = asyncio.create_task(host.serve(server_b))
        remote_a = RemoteClient(client_a.source(), show_id=SHOW, layout_id=LAYOUT, session=client_a)
        remote_b = RemoteClient(client_b.source(), show_id=SHOW, layout_id=LAYOUT, session=client_b)
        await remote_b.start_lifecycle()
        try:
            await remote_a.request(make_envelope(
                type="remote.hello",
                source=client_a.source(),
                destination=Endpoint(node_id=client_a.peer.node_id) if client_a.peer else None,
                payload=hello_payload(client_a.local.node_id),
            ))
            await remote_b.request(make_envelope(
                type="remote.hello",
                source=client_b.source(),
                destination=Endpoint(node_id=client_b.peer.node_id) if client_b.peer else None,
                payload=hello_payload(client_b.local.node_id, device_id=new_uuid(), remote_id=new_uuid()),
            ))
            report_a = await remote_a.request(remote_a.layout_request())
            report_b = await remote_b.request(remote_b.layout_request())
            await remote_a.request(remote_a.readiness_ack(
                layout=report_a.payload["layout"], snapshot_revision=host_auth.snapshot_revision,
            ))
            await remote_b.request(remote_b.readiness_ack(
                layout=report_b.payload["layout"], snapshot_revision=host_auth.snapshot_revision,
            ))
            await client_b.send(remote_b.state_request())
            await remote_a.invoke_wait("look_recall", value="blue_ballad")
            for _ in range(30):
                if remote_b.view.get("look.current", {}).get("look_id") == "blue_ballad":
                    break
                await asyncio.sleep(0.05)
            assert remote_b.view["look.current"]["look_id"] == "blue_ballad"
            await remote_a.begin_momentary_wait("fog_burst")
            assert host_auth.effect_active("fog_burst")
            await asyncio.sleep(0.25)
            assert not host_auth.effect_active("fog_burst")
            for _ in range(40):
                if remote_b.view.get("control.fog_burst", {}).get("value") is False:
                    break
                await asyncio.sleep(0.05)
            assert remote_b.view["control.fog_burst"]["value"] is False
        finally:
            await remote_b.stop_lifecycle()
            await host.close()
            ta.cancel()
            tb.cancel()
            await client_a.goodbye()
            await client_b.goodbye()

    asyncio.run(body())


def test_live_surface_transfer_and_cache_hit() -> None:
    async def body() -> None:
        client_sess, server = await connected_pair(Role.REMOTE, Role.CONDUCTOR, default_caps())
        auth = RemoteAuthority(source=server.source(), show_id=SHOW, inline_surface=False)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(client_sess.local.node_id, ["remote.operator", "remote.viewer"])
        host = RemoteHost(auth, inline_surface=False)
        await host.start()
        serve = asyncio.create_task(host.serve(server))
        remote = RemoteClient(client_sess.source(), show_id=SHOW, layout_id=LAYOUT, session=client_sess)
        try:
            await remote.request(make_envelope(
                type="remote.hello",
                source=client_sess.source(),
                destination=Endpoint(node_id=client_sess.peer.node_id) if client_sess.peer else None,
                payload=hello_payload(client_sess.local.node_id),
            ))
            report = await remote.request(remote.layout_request())
            assert "layout" not in report.payload
            assert report.payload.get("cached") is False
            await remote._wait_surface_transfer(timeout=3)
            assert remote.layout is not None
            assert layout_fingerprint(remote.layout) == layout_fingerprint(auth.layout)
            assert not auth._surface_offers
            meta = auth._live_surface_meta.get(server.session_id or "")
            assert meta and meta.get("sha256") == layout_fingerprint(auth.layout)
            await remote.request(remote.readiness_ack(
                layout=remote.layout, snapshot_revision=auth.snapshot_revision,
            ))
            cached = await remote.request(remote.layout_request())
            assert cached.payload.get("cached") is True
            assert "layout" not in cached.payload
        finally:
            await host.close()
            serve.cancel()
            await client_sess.goodbye()

    asyncio.run(body())


def test_surface_transfer_corruption_oversize_and_rollback() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=False)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.viewer"])
    auth.bind_test_session(SID, SRC.node_id)
    auth.sessions[SID]["inline_surface"] = False
    report = run(auth, make_envelope(type="remote.layout.request", source=SRC, payload={}))
    offer = next(m for m in report if m.type == "resource.offer")
    accept = make_envelope(
        type="resource.accept",
        source=SRC,
        payload={"transfer_id": offer.payload["transfer_id"], "max_chunk_bytes": 1024},
    )
    chunks = run(auth, accept)
    assert any(m.type == "resource.chunk" for m in chunks)
    assert chunks[-1].type == "resource.complete"
    bad = make_envelope(
        type="resource.activate",
        source=SRC,
        payload={"transfer_id": offer.payload["transfer_id"]},
    )
    # not verified yet
    failed = run(auth, bad)
    assert failed[0].payload["status"] == "failed"
    auth._surface_transfers[SID].state = TransferState.VERIFIED
    auth._surface_transfers[SID].staged = json.dumps(auth.layout, default=str).encode()
    ok = run(auth, bad)
    assert ok[0].payload["status"] == "applied"
    huge = dict(auth.layout)
    auth.layout = huge
    # force oversize by shrinking the limit locally
    from acp import remote as remote_mod
    previous = remote_mod.SURFACE_LIMITS["max_surface_bytes"]
    remote_mod.SURFACE_LIMITS["max_surface_bytes"] = 16
    try:
        denied = run(auth, make_envelope(type="remote.layout.request", source=SRC, payload={}))
        assert denied[0].payload["error"]["code"] == "remote.layout.invalid"
    finally:
        remote_mod.SURFACE_LIMITS["max_surface_bytes"] = previous


def test_state_request_sends_authorized_snapshot() -> None:
    auth = authority()
    req = make_envelope(type="state.request", source=SRC, payload={"resources": ["look.current", "cue.current"]})
    out = run(auth, req)
    snap = next(m for m in out if m.type == "state.snapshot")
    assert snap.correlation_id == req.message_id
    names = {item["resource"] for item in snap.payload["resources"]}
    assert names == {"look.current", "cue.current"}
    assert auth.sessions[SID]["subscriptions"] == {"look.current", "cue.current"}


def test_live_lease_renewal_over_multiple_periods() -> None:
    async def body() -> None:
        client_sess, server = await connected_pair(Role.REMOTE, Role.CONDUCTOR, default_caps())
        auth = RemoteAuthority(source=server.source(), show_id=SHOW, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(client_sess.local.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        fog = auth.control("fog_burst")
        assert fog is not None
        fog["safety"]["max_hold_ms"] = 150
        host = RemoteHost(auth, inline_surface=True)
        await host.start()
        serve = asyncio.create_task(host.serve(server))
        remote = RemoteClient(client_sess.source(), show_id=SHOW, layout_id=LAYOUT, session=client_sess)
        try:
            dest = Endpoint(node_id=client_sess.peer.node_id) if client_sess.peer else None
            await remote.request(make_envelope(
                type="remote.hello", source=client_sess.source(), destination=dest,
                payload=hello_payload(client_sess.local.node_id),
            ))
            report = await remote.request(remote.layout_request())
            await remote.request(remote.readiness_ack(
                layout=report.payload["layout"], snapshot_revision=auth.snapshot_revision,
            ))
            await remote.start_lifecycle()
            begin = await remote.begin_momentary_wait("fog_burst")
            assert begin.payload["status"] == "applied"
            assert auth.effect_active("fog_burst")
            await asyncio.sleep(0.55)
            router = auth.router
            assert router is not None
            assert getattr(router, "refresh_count", 0) >= 3
            assert auth.effect_active("fog_burst")
            if remote._renew_task is not None:
                remote._renew_task.cancel()
                try:
                    await remote._renew_task
                except asyncio.CancelledError:
                    pass
                remote._renew_task = None
            await asyncio.sleep(0.25)
            assert not auth.effect_active("fog_burst")
        finally:
            await remote.stop_lifecycle()
            await host.close()
            serve.cancel()
            await client_sess.goodbye()

    asyncio.run(body())


def test_live_idle_failed_release_alert_and_shutdown_flush() -> None:
    async def body() -> None:
        client_a, server_a, client_b, server_b = await _connected_remotes()
        auth = RemoteAuthority(source=server_a.source(), show_id=SHOW, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(client_a.local.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        auth.authorize(client_b.local.node_id, ["remote.operator", "remote.viewer"])
        fog = auth.control("fog_burst")
        assert fog is not None
        fog["safety"]["max_hold_ms"] = 80
        router = _StickyRouter()
        router.bind(auth)
        auth.router = router
        host = RemoteHost(auth, inline_surface=True)
        await host.start()
        ta = asyncio.create_task(host.serve(server_a))
        tb = asyncio.create_task(host.serve(server_b))
        remote_a = RemoteClient(client_a.source(), show_id=SHOW, layout_id=LAYOUT, session=client_a)
        remote_b = RemoteClient(client_b.source(), show_id=SHOW, layout_id=LAYOUT, session=client_b)
        await remote_b.start_lifecycle()
        try:
            await remote_a.request(make_envelope(
                type="remote.hello", source=client_a.source(),
                destination=Endpoint(node_id=client_a.peer.node_id) if client_a.peer else None,
                payload=hello_payload(client_a.local.node_id),
            ))
            await remote_b.request(make_envelope(
                type="remote.hello", source=client_b.source(),
                destination=Endpoint(node_id=client_b.peer.node_id) if client_b.peer else None,
                payload=hello_payload(client_b.local.node_id, device_id=new_uuid(), remote_id=new_uuid()),
            ))
            report_a = await remote_a.request(remote_a.layout_request())
            report_b = await remote_b.request(remote_b.layout_request())
            await remote_a.request(remote_a.readiness_ack(
                layout=report_a.payload["layout"], snapshot_revision=auth.snapshot_revision,
            ))
            await remote_b.request(remote_b.readiness_ack(
                layout=report_b.payload["layout"], snapshot_revision=auth.snapshot_revision,
            ))
            await client_b.send(remote_b.state_request())
            await remote_a.begin_momentary_wait("fog_burst")
            assert auth.effect_active("fog_burst")
            await asyncio.sleep(0.25)
            assert auth.effect_active("fog_burst")
            for _ in range(40):
                alert = remote_b.view.get("system.alert") or {}
                if alert.get("code") == "remote.control.unconfirmed_release":
                    break
                await asyncio.sleep(0.05)
            assert remote_b.view["system.alert"]["code"] == "remote.control.unconfirmed_release"
            assert remote_b.view.get("control.fog_burst", {}).get("confidence") == "unverified"
            await host.close()
            assert any(item.get("reason") == "shutdown" for item in auth.last_releases)
        finally:
            await remote_b.stop_lifecycle()
            ta.cancel()
            tb.cancel()
            await client_a.goodbye()
            await client_b.goodbye()

    asyncio.run(body())


def test_live_gap_recovery_uses_state_snapshot() -> None:
    async def body() -> None:
        client_sess, server = await connected_pair(Role.REMOTE, Role.CONDUCTOR, default_caps())
        auth = RemoteAuthority(source=server.source(), show_id=SHOW, inline_surface=True)
        auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
        auth.authorize(client_sess.local.node_id, ["remote.operator", "remote.viewer"])
        host = RemoteHost(auth, inline_surface=True)
        await host.start()
        serve = asyncio.create_task(host.serve(server))
        remote = RemoteClient(client_sess.source(), show_id=SHOW, layout_id=LAYOUT, session=client_sess)
        try:
            dest = Endpoint(node_id=client_sess.peer.node_id) if client_sess.peer else None
            hello = make_envelope(
                type="remote.hello", source=client_sess.source(), destination=dest,
                payload=hello_payload(client_sess.local.node_id),
            )
            await remote.sync_until_ready(hello, timeout=3)
            client_sess.gap_count = 1
            snap = await remote.request(remote.state_request(), timeout=2)
            assert snap.type == "state.snapshot"
            assert any(item.get("resource") == "cue.current" for item in snap.payload["resources"])
            await remote.sync_until_ready(hello, timeout=3)
            assert remote.ready or auth.compute_readiness(server.session_id or "") in {
                "ready", "ready_with_warnings", "syncing_assets", "syncing_state",
            }
        finally:
            await remote.stop_lifecycle()
            await host.close()
            serve.cancel()
            await client_sess.goodbye()

    asyncio.run(body())


def test_live_activation_reject_keeps_previous_layout() -> None:
    async def body() -> None:
        client_sess, server = await connected_pair(Role.REMOTE, Role.CONDUCTOR, default_caps())
        auth = RemoteAuthority(source=server.source(), show_id=SHOW, inline_surface=False)
        first = sample_layout(show_id=SHOW, layout_id=LAYOUT)
        auth.set_layout(first)
        auth.authorize(client_sess.local.node_id, ["remote.operator", "remote.viewer"])
        host = RemoteHost(auth, inline_surface=False)
        await host.start()
        serve = asyncio.create_task(host.serve(server))
        remote = RemoteClient(client_sess.source(), show_id=SHOW, layout_id=LAYOUT, session=client_sess)
        try:
            dest = Endpoint(node_id=client_sess.peer.node_id) if client_sess.peer else None
            await remote.request(make_envelope(
                type="remote.hello", source=client_sess.source(), destination=dest,
                payload=hello_payload(client_sess.local.node_id),
            ))
            await remote.request(remote.layout_request())
            await remote._wait_surface_transfer(timeout=3)
            kept = dict(remote.layout or {})
            assert kept
            nxt = sample_layout(show_id=SHOW, layout_id=LAYOUT)
            nxt["revision"] = 9
            nxt["controls"][0]["label"] = "GO2"
            assert auth.activate_layout(nxt)[0]
            auth.reject_activation = True
            remote.layout_hash = None
            await remote.request(remote.layout_request())
            with pytest.raises(SessionError):
                await remote._wait_surface_transfer(timeout=3)
            assert remote.layout == kept
            assert remote.layout["controls"][0]["label"] == "GO"
        finally:
            await remote.stop_lifecycle()
            await host.close()
            serve.cancel()
            await client_sess.goodbye()

    asyncio.run(body())


def test_repeated_transfer_and_disconnect_cleanup() -> None:
    auth = RemoteAuthority(source=AUTH, show_id=SHOW, inline_surface=False)
    auth.set_layout(sample_layout(show_id=SHOW, layout_id=LAYOUT))
    auth.authorize(SRC.node_id, ["remote.operator", "remote.viewer"])
    auth.bind_test_session(SID, SRC.node_id)
    auth.sessions[SID]["inline_surface"] = False
    first_tid = None
    for _ in range(3):
        report = run(auth, make_envelope(type="remote.layout.request", source=SRC, payload={}))
        offer = next(m for m in report if m.type == "resource.offer")
        first_tid = offer.payload["transfer_id"]
        chunks = run(auth, make_envelope(
            type="resource.accept", source=SRC,
            payload={"transfer_id": first_tid, "max_chunk_bytes": 4096},
        ))
        assert chunks[-1].type == "resource.complete"
        auth._surface_transfers[SID].state = TransferState.VERIFIED
        auth._surface_transfers[SID].staged = auth.surface_bytes()
        applied = run(auth, make_envelope(
            type="resource.activate", source=SRC, payload={"transfer_id": first_tid},
        ))
        assert applied[0].payload["status"] == "applied"
        assert first_tid not in auth._surface_offers
        xfer = auth._surface_transfers[SID]
        assert not xfer.parts
        assert xfer.staged is None
    assert len(auth._live_surface_meta) == 1
    auth.on_session_lost(SID)
    assert SID not in auth._surface_transfers
    assert SID not in auth._live_surface_meta
    assert not any(item.get("session_id") == SID for item in auth._surface_offers.values())
