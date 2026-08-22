from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .bridge import BridgeNode
from .codec import decode_cbor, decode_json
from .remote import RemoteAuthority, RemoteClient, sample_layout
from .session import Session
from .testkit import identity
from .types import Endpoint, Role
from .ws import connect_ws, serve_ws

_SECURITY_REDACT_KEYS = frozenset({
    "bootstrap_secret", "manual_code", "shareP", "shareV", "confirmP", "confirmV",
    "pake_message", "candidate_confirmation", "commissioner_confirmation", "channel_binding",
    "binding", "ciphertext", "tag", "credential", "trust_anchor", "identity_public_key",
    "public_key", "signature", "proof_of_possession", "possession_proof", "confirmation",
    "private_key", "key_material",
})


def redact_security(value, key: str = ""):
    if key in _SECURITY_REDACT_KEYS:
        return "<redacted>"
    if isinstance(value, dict):
        return {name: redact_security(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_security(item) for item in value]
    return value


def inspect(path: Path) -> int:
    raw = path.read_bytes()
    if raw[:1] in (b"{", b"["):
        env = decode_json(raw)
    else:
        env = decode_cbor(raw)
    print(json.dumps(redact_security(env.to_dict()), indent=2))
    return 0


async def _sim_bridge(listen: str) -> None:
    host, port_s = listen.rsplit(":", 1)
    port = int(port_s)
    node = identity(Role.BRIDGE, "sim-bridge")
    bridge = BridgeNode(source=Endpoint(node_id=node.node_id))

    async def on_client(transport) -> None:
        session = Session(transport, node, is_server=True, profiles=["core", "bridge"], allow_plaintext=True)
        await session.handshake([])
        async for env in session.subscribe():
            for reply in bridge.handle(env, session):
                await session.send(reply)

    server = await serve_ws(host, port, on_client, allow_plaintext=True)
    async with server:
        await server.serve_forever()


async def _sim_conductor(connect: str) -> None:
    transport = await connect_ws(connect, allow_plaintext=True)
    session = Session(transport, identity(Role.CONDUCTOR, "sim-conductor"), is_server=False, allow_plaintext=True)
    await session.handshake([])
    print("handshake ok", session.session_id, session.session_version)
    await session.goodbye()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acp")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_ins = sub.add_parser("inspect")
    p_ins.add_argument("path")
    p_sim = sub.add_parser("sim")
    p_sim.add_argument("role", choices=["bridge", "conductor", "prism", "lyric", "remote"])
    p_remote = sub.add_parser("remote")
    rsub = p_remote.add_subparsers(dest="remote_cmd", required=True)
    rsub.add_parser("discover")
    r_conn = rsub.add_parser("connect")
    r_conn.add_argument("node")
    rsub.add_parser("controls")
    r_press = rsub.add_parser("press")
    r_press.add_argument("control_id")
    r_hold = rsub.add_parser("hold")
    r_hold.add_argument("control_id")
    r_hold.add_argument("--seconds", type=float, default=1.0)
    rsub.add_parser("go")
    r_disc = rsub.add_parser("disconnect")
    r_disc.add_argument("--dirty", action="store_true")
    p_sim.add_argument("--listen", default="127.0.0.1:27421")
    p_sim.add_argument("--connect")
    p_sim.add_argument(
        "--i-understand-this-is-not-a-live-show",
        action="store_true",
        dest="force_replay",
    )
    args = parser.parse_args(argv)
    if args.cmd == "inspect":
        return inspect(Path(args.path))
    if args.cmd == "sim":
        if args.role == "bridge":
            asyncio.run(_sim_bridge(args.listen))
            return 0
        if args.role == "conductor":
            if not args.connect:
                print("--connect is required for conductor sim", file=sys.stderr)
                return 2
            asyncio.run(_sim_conductor(args.connect))
            return 0
        if args.role == "remote":
            return _remote_demo(dirty=False)
        print("role not implemented in this build", file=sys.stderr)
        return 2
    if args.cmd == "remote":
        return _remote_cli(args)
    return 2


def _remote_cli(args: argparse.Namespace) -> int:
    if args.remote_cmd == "discover":
        print("discovery multicast 239.255.40.1:27420 (ACP0)")
        return 0
    if args.remote_cmd == "connect":
        print(f"would connect to {args.node} over ws://…/acp")
        return 0
    if args.remote_cmd == "controls":
        show = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
        layout_id = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"
        layout = sample_layout(show_id=show, layout_id=layout_id)
        for control in layout["controls"]:
            print(control["control_id"], control["control_type"], control["binding"]["action"])
        return 0
    dirty = bool(getattr(args, "dirty", False)) or args.remote_cmd == "disconnect"
    if args.remote_cmd == "hold":
        return _remote_demo(hold=args.control_id, seconds=args.seconds, dirty=dirty)
    if args.remote_cmd == "press":
        return _remote_demo(press=args.control_id, dirty=dirty)
    if args.remote_cmd == "go":
        return _remote_demo(press="cue_go", dirty=dirty)
    return _remote_demo(dirty=dirty)


def _remote_demo(
    *,
    press: str | None = None,
    hold: str | None = None,
    seconds: float = 0.0,
    dirty: bool = False,
) -> int:
    show = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
    layout_id = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"
    auth = RemoteAuthority(source=Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-000000000001"), show_id=show)
    auth.set_layout(sample_layout(show_id=show, layout_id=layout_id))
    sid = "0193f8d8-4c4e-7d8b-a2ab-0000000000c0"
    client_node = "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"
    auth.authorize(client_node, ["remote.operator", "remote.busker"])
    auth.bind_test_session(sid, client_node)
    client = RemoteClient(Endpoint(node_id=client_node), show_id=show, layout_id=layout_id)
    if press:
        for msg in auth.handle_simulated(client.invoke(press), session_id=sid):
            print(msg.type, msg.payload.get("status") or msg.payload.get("resource"))
    if hold:
        begin = client.begin_momentary(hold)
        inv = str(begin.payload["invocation_id"])
        for msg in auth.handle_simulated(begin, session_id=sid):
            client.record_result(inv, msg)
            print(msg.type, msg.payload.get("status"), "active", auth.effect_active(hold))
        if dirty:
            auth.on_session_lost(sid)
            print("dirty disconnect released", hold, "active", auth.effect_active(hold))
            return 0
        auth.tick(int(seconds * 1000) + 1)
        if seconds * 1000 >= 10000:
            print("max-hold expired", "active", auth.effect_active(hold))
        else:
            for msg in auth.handle_simulated(client.end_momentary(hold, inv), session_id=sid):
                print(msg.type, msg.payload.get("status"), "active", auth.effect_active(hold))
        return 0
    if dirty:
        begin = client.begin_momentary("fog_burst")
        auth.handle_simulated(begin, session_id=sid)
        released = auth.on_session_lost(sid)
        print("dirty disconnect released", released)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
