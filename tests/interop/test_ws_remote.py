"""Live localhost WebSocket Remote hello, sync, transfer, fanout, and idle expiry."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python" / "src"))

from acp.envelope import make_envelope
from acp.remote import RemoteAuthority, RemoteClient, RemoteHost, layout_fingerprint, sample_layout
from acp.session import Session
from acp.testkit import default_caps, identity
from acp.types import Endpoint, Role, new_uuid
from acp.ws import connect_ws, serve_ws

SHOW = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
LAYOUT = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"


def hello_payload(node_id: str, **ids: str) -> dict:
    return {
        "remote": {
            "node_id": node_id,
            "instance_id": ids.get("instance_id") or "0193f8d8-4c4e-7d8b-a2ab-0000000000b1",
            "device_id": ids.get("device_id") or "0193f8d8-4c4e-7d8b-a2ab-0000000000d0",
            "remote_id": ids.get("remote_id") or "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
            "device_name": "FOH",
            "platform": "ipados",
            "app_version": "1.0.0",
        },
        "roles": ["remote.operator"],
    }


async def _open_client(url: str, name: str) -> tuple[Session, RemoteClient]:
    transport = await connect_ws(url, allow_plaintext=True)
    client = Session(
        transport,
        identity(Role.REMOTE, name),
        is_server=False,
        allow_plaintext=True,
        profiles=["core", "remote", "aurora.remote.prism.v1"],
    )
    await client.handshake(default_caps())
    remote = RemoteClient(client.source(), show_id=SHOW, layout_id=LAYOUT, session=client)
    return client, remote


async def main() -> None:
    server_ident = identity(Role.CONDUCTOR, "interop-auth")
    show_layout = sample_layout(show_id=SHOW, layout_id=LAYOUT)
    caps = default_caps()
    auth = RemoteAuthority(source=Endpoint(node_id=server_ident.node_id), show_id=SHOW, inline_surface=False)
    auth.set_layout(show_layout)
    fog = auth.control("fog_burst")
    assert fog is not None
    fog["safety"]["max_hold_ms"] = 120
    host = RemoteHost(auth, inline_surface=False)
    await host.start()

    async def on_client(transport) -> None:
        server = Session(
            transport,
            server_ident,
            is_server=True,
            allow_plaintext=True,
            profiles=["core", "remote", "aurora.remote.prism.v1"],
        )
        await server.handshake(caps)
        assert server.peer is not None
        auth.authorize(server.peer.node_id, ["remote.operator", "remote.busker", "remote.viewer"])
        await host.serve(server)

    srv = await serve_ws("127.0.0.1", 27432, on_client, allow_plaintext=True)
    async with srv:
        client_a, remote_a = await _open_client("ws://127.0.0.1:27432/acp", "interop-pad-a")
        client_b, remote_b = await _open_client("ws://127.0.0.1:27432/acp", "interop-pad-b")
        dest_a = Endpoint(node_id=client_a.peer.node_id) if client_a.peer else None
        dest_b = Endpoint(node_id=client_b.peer.node_id) if client_b.peer else None
        await remote_b.start_lifecycle()
        await remote_a.request(make_envelope(
            type="remote.hello", source=client_a.source(), destination=dest_a,
            payload=hello_payload(client_a.local.node_id),
        ))
        await remote_b.request(make_envelope(
            type="remote.hello", source=client_b.source(), destination=dest_b,
            payload=hello_payload(
                client_b.local.node_id, instance_id=new_uuid(), device_id=new_uuid(), remote_id=new_uuid(),
            ),
        ))
        report = await remote_a.request(remote_a.layout_request())
        assert "layout" not in report.payload
        await remote_a._wait_surface_transfer(timeout=3)
        assert remote_a.layout is not None
        await remote_a.request(remote_a.readiness_ack(
            layout=remote_a.layout, snapshot_revision=auth.snapshot_revision,
        ))
        report_b = await remote_b.request(remote_b.layout_request())
        if not report_b.payload.get("layout"):
            await remote_b._wait_surface_transfer(timeout=3)
        await remote_b.request(remote_b.readiness_ack(
            layout=remote_b.layout, snapshot_revision=auth.snapshot_revision,
        ))
        await client_b.send(remote_b.state_request())

        await remote_a.invoke_wait("cue_go")
        await remote_a.invoke_wait("cue_go")
        nav = remote_a.navigate("go")
        nav_ack = await remote_a.request(nav)
        assert nav_ack.payload["status"] == "applied"
        go_after_nav = auth.go_count
        await remote_a.invoke_wait("look_recall", value="blue_ballad")
        for _ in range(40):
            if remote_b.view.get("look.current", {}).get("look_id") == "blue_ballad":
                break
            await asyncio.sleep(0.05)
        assert remote_b.view["look.current"]["look_id"] == "blue_ballad"

        await remote_a.begin_momentary_wait("fog_burst")
        assert auth.effect_active("fog_burst")
        await asyncio.sleep(0.25)
        assert not auth.effect_active("fog_burst")

        saved_local = client_a.local
        await client_a.goodbye()
        transport_a2 = await connect_ws("ws://127.0.0.1:27432/acp", allow_plaintext=True)
        client_a2 = Session(
            transport_a2,
            saved_local,
            is_server=False,
            allow_plaintext=True,
            profiles=["core", "remote", "aurora.remote.prism.v1"],
        )
        await client_a2.handshake(caps)
        remote_a2 = RemoteClient(client_a2.source(), show_id=SHOW, layout_id=LAYOUT, session=client_a2)
        dest_a2 = Endpoint(node_id=client_a2.peer.node_id) if client_a2.peer else None
        await remote_a2.request(make_envelope(
            type="remote.hello", source=client_a2.source(), destination=dest_a2,
            payload=hello_payload(client_a2.local.node_id),
        ))
        report2 = await remote_a2.request(remote_a2.layout_request())
        if not report2.payload.get("layout"):
            await remote_a2._wait_surface_transfer(timeout=3)
        await remote_a2.request(remote_a2.readiness_ack(
            layout=remote_a2.layout, snapshot_revision=auth.snapshot_revision,
        ))
        replay = await remote_a2.request(nav)
        assert replay.payload.get("status") in {"applied", "rejected"}
        assert auth.go_count == go_after_nav

        await remote_b.stop_lifecycle()
        await client_a2.goodbye()
        await client_b.goodbye()
        await host.close()
    print("interop remote ok", client_a2.session_id, layout_fingerprint(remote_a.layout or {}))


if __name__ == "__main__":
    asyncio.run(main())
