from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .bridge import BridgeNode
from .codec import decode_cbor, decode_json
from .session import Session
from .testkit import identity
from .types import Endpoint, Role
from .ws import connect_ws, serve_ws


def inspect(path: Path) -> int:
    raw = path.read_bytes()
    if raw[:1] in (b"{", b"["):
        env = decode_json(raw)
    else:
        env = decode_cbor(raw)
    print(json.dumps(env.to_dict(), indent=2))
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
    p_sim.add_argument("role", choices=["bridge", "conductor", "prism", "lyric"])
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
        print("role not implemented in this build", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
