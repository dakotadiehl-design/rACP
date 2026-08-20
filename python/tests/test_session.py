from __future__ import annotations

import asyncio

import pytest

from acp.codec import decode_cbor
from acp.envelope import make_envelope
from acp.negotiate import VersionError, intersect_capabilities, intersect_profiles, select_encoding, select_version
from acp.session import ReliableOverflow, Session, SessionError, make_ack
from acp.testkit import GateTransport, LoopbackTransport, connected_pair, default_caps, identity, linked_transports
from acp.types import Capability, CommandStatus, Endpoint, ProtocolRange, QoS, Role, new_uuid


def test_remote_profile_intersection() -> None:
    assert intersect_profiles(
        ["core", "remote", "aurora.remote.prism.v1"],
        ["core", "aurora.remote.prism.v1"],
    ) == ["core", "aurora.remote.prism.v1"]
    assert "aurora.remote.conductor.v1" not in intersect_profiles(
        ["aurora.remote.prism.v1"],
        ["aurora.remote.conductor.v1"],
    )


def test_version_select() -> None:
    assert select_version(ProtocolRange("1.0", "1.2"), ProtocolRange("1.0", "1.2")) == "1.2"
    assert select_version(ProtocolRange("1.0", "1.0"), ProtocolRange("1.0", "1.2")) == "1.0"
    with pytest.raises(VersionError):
        select_version(ProtocolRange("1.2", "1.2"), ProtocolRange("1.0", "1.0"))


def test_encoding_intersection() -> None:
    assert select_encoding(["json"], ["json", "cbor"]) == "json"
    with pytest.raises(VersionError):
        select_encoding(["cbor"], ["json"])


def test_capability_intersection_versions() -> None:
    local = [Capability("health.heartbeat", "1.2"), Capability("bridge.blackout", "1.0")]
    peer = [Capability("health.heartbeat", "1.0")]
    out = intersect_capabilities(local, peer)
    assert [c.id for c in out] == ["health.heartbeat"]
    assert out[0].version == "1.0"


def test_hello_loopback() -> None:
    async def body() -> None:
        client, server = await connected_pair()
        assert client.state.value == "established"
        assert server.state.value == "established"
        assert client.session_id == server.session_id
        assert client.session_version == "1.2"
        assert "prism.cue_control" in client.negotiated_capabilities
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())


def test_plaintext_requires_opt_in() -> None:
    async def body() -> None:
        ta, _ = linked_transports()
        session = Session(ta, identity(Role.CONDUCTOR), allow_plaintext=False)
        with pytest.raises(SessionError) as err:
            await session.handshake([])
        assert err.value.code == "authentication"

    asyncio.run(body())


def test_command_ack_correlation() -> None:
    async def body() -> None:
        client, server = await connected_pair(Role.CONDUCTOR, Role.PRISM)

        async def responder() -> None:
            async for env in server.subscribe():
                if env.type == "cue.go":
                    await server.send(make_ack(env, server.source(), CommandStatus.APPLIED))
                    return

        task = asyncio.create_task(responder())
        req = make_envelope(
            type="cue.go",
            source=client.source(),
            destination=server.source(),
            qos=QoS.RELIABLE,
            payload={"idempotency_key": new_uuid()},
            flags=frozenset({"ack_required"}),
        )
        ack = await client.request(req, timeout=2.0)
        assert ack.payload["status"] == "applied"
        assert ack.correlation_id == req.message_id
        await task
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())


def test_latest_coalesce_on_blocked_transport() -> None:
    async def body() -> None:
        client_t = GateTransport()
        server_t = LoopbackTransport()
        client_t.attach(server_t)
        client = Session(client_t, identity(Role.CONDUCTOR), allow_plaintext=True)
        server = Session(server_t, identity(Role.BRIDGE), is_server=True, allow_plaintext=True)
        await server.start_receiver()
        client_t.gate.set()
        await asyncio.gather(server.handshake(default_caps()), client.handshake(default_caps()))
        client_t.committed.clear()
        client_t.gate.clear()
        if client._writer_task:
            client._writer_task.cancel()
            client._writer_task = None
        start = client.next_sequence
        a = make_envelope(
            type="health.heartbeat",
            source=client.source(),
            qos=QoS.LATEST,
            payload={"resource": "health", "uptime_ms": 1, "status": "ok"},
        )
        b = make_envelope(
            type="health.heartbeat",
            source=client.source(),
            qos=QoS.LATEST,
            payload={"resource": "health", "uptime_ms": 2, "status": "ok"},
        )
        await client.send(a)
        await client.send(b)
        assert client.next_sequence == start
        assert len(client._latest_q) == 1
        client._writer_task = asyncio.create_task(client._writer_loop())
        client._work.set()
        client_t.gate.set()
        await asyncio.sleep(0.05)
        assert client.next_sequence == start + 1
        assert len(client_t.committed) == 1
        sent = decode_cbor(client_t.committed[0])
        assert sent.payload["uptime_ms"] == 2
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())


def test_reliable_overflow() -> None:
    async def body() -> None:
        ta, _tb = linked_transports()
        client = Session(ta, identity(Role.CONDUCTOR), is_server=False, allow_plaintext=True)
        client.profile = "lightweight"
        client.state = client.state.ESTABLISHED
        client.session_id = new_uuid()
        client.negotiated_capabilities = {"prism.cue_control"}
        client.negotiated_capability_versions = {"prism.cue_control": "1.0"}
        for _ in range(client.limits["outbound_reliable_queue"]):
            client._reliable_q.append((make_envelope(
                type="cue.go",
                source=client.source(),
                qos=QoS.RELIABLE,
                payload={"idempotency_key": new_uuid()},
            ), asyncio.get_running_loop().create_future()))
        env = make_envelope(
            type="cue.go",
            source=client.source(),
            qos=QoS.RELIABLE,
            payload={"idempotency_key": new_uuid()},
        )
        with pytest.raises(ReliableOverflow):
            await client.send(env)

    asyncio.run(body())


def test_rejects_impersonated_source() -> None:
    async def body() -> None:
        client, server = await connected_pair()
        spoof = make_envelope(
            type="health.heartbeat",
            source=Endpoint(node_id=new_uuid()),
            qos=QoS.LATEST,
            payload={"uptime_ms": 1, "status": "ok"},
        )
        spoof = spoof.with_session(server.session_id, 99)
        # inject as if it arrived on the server socket from the wrong node
        error = server._admit(spoof)
        assert error == "authentication"
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())


def test_rejects_unknown_type_when_established() -> None:
    async def body() -> None:
        client, server = await connected_pair()
        env = make_envelope(
            type="x.evil.shell",
            source=client.source(),
            qos=QoS.RELIABLE,
            payload={},
        )
        env = env.with_session(server.session_id, 2)
        # rewrite type after construction
        object.__setattr__(env, "type", "x.evil.shell")
        assert server._admit(env) == "unsupported_message"
        await client.goodbye()
        await server.goodbye()

    asyncio.run(body())
