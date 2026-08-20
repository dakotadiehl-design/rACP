"""Python framed-TCP session handshake, request correlation, goodbye, and loss."""

from __future__ import annotations

import asyncio

from acp.codec import encode_cbor
from acp.envelope import make_envelope
from acp.framed import connect_framed, serve_framed
from acp.session import Session, SessionState
from acp.testkit import default_caps, identity
from acp.types import Endpoint, QoS, Role, new_uuid

REMOTE_PROFILES = ["core", "remote", "aurora.remote.prism.v1"]


async def _framed_hello_cbor_and_json() -> None:
    await _framed_hello_once(["cbor", "json"])
    await _framed_hello_once(["json"])


async def _framed_hello_once(encodings: list[str]) -> None:
    done = asyncio.Event()
    server_ident = identity(Role.BRIDGE, "framed-bridge")
    holder: dict = {}

    async def on_client(transport) -> None:
        server = Session(
            transport, server_ident, is_server=True, allow_plaintext=True, encodings=encodings,
            profiles=REMOTE_PROFILES,
        )
        await server.handshake(default_caps())
        assert server.state == SessionState.ESTABLISHED
        holder["server"] = server
        done.set()
        await server.goodbye()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        transport = await connect_framed("127.0.0.1", port)
        client = Session(
            transport,
            identity(Role.CONDUCTOR, "framed-cond"),
            is_server=False,
            allow_plaintext=True,
            encodings=encodings,
            profiles=REMOTE_PROFILES,
        )
        await client.handshake(default_caps())
        assert client.state == SessionState.ESTABLISHED
        assert client.session_id
        assert client.session_version == "1.2"
        assert client.encoding in encodings
        assert client.peer is not None
        assert client.peer.node_id == server_ident.node_id
        assert client.peer.role == Role.BRIDGE
        assert "aurora.remote.prism.v1" in client.negotiated_profiles
        assert "health.heartbeat" in client.negotiated_capabilities
        assert "remote.profile" in client.negotiated_capabilities
        await asyncio.wait_for(done.wait(), timeout=2)
        server = holder["server"]
        assert server.peer is not None
        assert server.peer.node_id == client.local.node_id
        await client.goodbye()


async def _framed_request_correlation_and_goodbye() -> None:
    got = asyncio.Event()
    server_ident = identity(Role.CONDUCTOR, "req-server")

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake(default_caps())
        async for env in server.subscribe():
            if env.type == "state.request":
                await server.send(make_envelope(
                    type="state.snapshot",
                    source=server.source(),
                    destination=Endpoint(node_id=env.source.node_id),
                    payload={"resources": []},
                    correlation_id=env.correlation_id or env.message_id,
                ))
                got.set()
                break
        await server.goodbye()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        client = Session(
            await connect_framed("127.0.0.1", port),
            identity(Role.REMOTE, "req-client"),
            is_server=False,
            allow_plaintext=True,
        )
        await client.handshake(default_caps())
        dest = Endpoint(node_id=client.peer.node_id) if client.peer else None
        ack = await client.request(make_envelope(
            type="state.request",
            source=client.source(),
            destination=dest,
            payload={"resources": []},
        ), timeout=2)
        assert ack.type == "state.snapshot"
        assert ack.correlation_id == ack.correlation_id
        await asyncio.wait_for(got.wait(), timeout=2)
        await client.goodbye()


async def _framed_connection_loss() -> None:
    server_ident = identity(Role.BRIDGE, "loss-bridge")

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake(default_caps())
        await transport.close()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        client = Session(
            await connect_framed("127.0.0.1", port),
            identity(Role.CONDUCTOR, "loss-client"),
            is_server=False,
            allow_plaintext=True,
        )
        await client.handshake(default_caps())
        try:
            await asyncio.wait_for(client.subscribe().__anext__(), timeout=2)
        except Exception:
            pass
        deadline = asyncio.get_running_loop().time() + 2
        while client.state == SessionState.ESTABLISHED and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        assert client.state in {SessionState.FAILED, SessionState.CLOSED}


async def _framed_identity_binding() -> None:
    failed = asyncio.Event()
    server_ident = identity(Role.BRIDGE, "id-bridge")

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake(default_caps())
        async for _env in server.subscribe():
            if server.state in {SessionState.FAILED, SessionState.CLOSED}:
                break
        if server.state == SessionState.FAILED:
            failed.set()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        client = Session(
            await connect_framed("127.0.0.1", port),
            identity(Role.CONDUCTOR, "id-client"),
            is_server=False,
            allow_plaintext=True,
        )
        await client.handshake(default_caps())
        spoof = make_envelope(
            type="health.heartbeat",
            source=Endpoint(node_id=new_uuid()),
            qos=QoS.LATEST,
            payload={"uptime_ms": 1, "status": "ok"},
        ).with_session(client.session_id, 99)
        await client.transport.send(encode_cbor(spoof), text=False)
        await asyncio.wait_for(failed.wait(), timeout=2)
        await client.goodbye()


async def _framed_sequence_gap() -> None:
    failed = asyncio.Event()
    server_ident = identity(Role.BRIDGE, "gap-bridge")

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake(default_caps())
        try:
            async for _env in server.subscribe():
                if server.state == SessionState.FAILED:
                    break
        finally:
            if server.state == SessionState.FAILED:
                failed.set()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        client = Session(
            await connect_framed("127.0.0.1", port),
            identity(Role.CONDUCTOR, "gap-client"),
            is_server=False,
            allow_plaintext=True,
        )
        await client.handshake(default_caps())
        def heartbeat(seq: int):
            return make_envelope(
                type="health.heartbeat",
                source=client.source(),
                qos=QoS.LATEST,
                payload={"uptime_ms": 1, "status": "ok"},
            ).with_session(client.session_id, seq)

        await client.transport.send(encode_cbor(heartbeat(2)), text=False)
        await client.transport.send(encode_cbor(heartbeat(5)), text=False)
        await asyncio.wait_for(failed.wait(), timeout=2)
        await client.goodbye()


async def _framed_malformed_frames() -> None:
    done = asyncio.Event()
    server_ident = identity(Role.BRIDGE, "bad-bridge")
    holder: dict = {}

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake(default_caps())
        holder["server"] = server
        await asyncio.sleep(0.2)
        done.set()
        await server.goodbye()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port = srv.sockets[0].getsockname()[1]
        client = Session(
            await connect_framed("127.0.0.1", port),
            identity(Role.CONDUCTOR, "bad-client"),
            is_server=False,
            allow_plaintext=True,
        )
        await client.handshake(default_caps())
        await client.transport.send(b"\xff\x00not-cbor", text=False)
        await client.transport.send(b"{not json", text=True)
        await asyncio.wait_for(done.wait(), timeout=2)
        server = holder["server"]
        assert server.counters.decode_errors >= 2
        assert server.state in {SessionState.ESTABLISHED, SessionState.GOODBYE_SENT, SessionState.CLOSED}
        await client.goodbye()


def test_framed_python_suite() -> None:
    asyncio.run(_framed_hello_cbor_and_json())
    asyncio.run(_framed_request_correlation_and_goodbye())
    asyncio.run(_framed_connection_loss())
    asyncio.run(_framed_identity_binding())
    asyncio.run(_framed_sequence_gap())
    asyncio.run(_framed_malformed_frames())
