"""Live localhost WebSocket HELLO between two Python sessions."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python" / "src"))

from acp.session import Session
from acp.testkit import identity
from acp.types import Role
from acp.ws import connect_ws, serve_ws


async def main() -> None:
    server_ident = identity(Role.BRIDGE, "interop-bridge")
    done = asyncio.Event()

    async def on_client(transport) -> None:
        server = Session(transport, server_ident, is_server=True, allow_plaintext=True)
        await server.handshake([])
        assert server.state.value == "established"
        done.set()
        await server.goodbye()

    srv = await serve_ws("127.0.0.1", 27431, on_client, allow_plaintext=True)
    async with srv:
        transport = await connect_ws("ws://127.0.0.1:27431/acp", allow_plaintext=True)
        client = Session(transport, identity(Role.CONDUCTOR, "interop-cond"), is_server=False, allow_plaintext=True)
        await client.handshake([])
        assert client.state.value == "established"
        await asyncio.wait_for(done.wait(), timeout=2)
        await client.goodbye()
    print("interop hello ok", client.session_id, client.session_version)


if __name__ == "__main__":
    asyncio.run(main())
