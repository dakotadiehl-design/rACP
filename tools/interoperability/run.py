#!/usr/bin/env python3
"""Real-TCP Swift↔Python rACP interoperability harness."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from racp import Command, Hello, Session, State  # noqa: E402
from racp.transport import AsyncioStream, Connection  # noqa: E402


async def swift_client_to_python() -> None:
    applied: list[Command] = []
    sessions: list[Session] = []

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = Session(
            Hello("device", "python-server", ("cue.current", "cue.go", "cue.null", "state.subscribe")),
            lambda command: applied.append(command) or None,
        )
        sessions.append(session)
        connection = Connection(AsyncioStream(reader, writer), session)
        run = asyncio.create_task(connection.run())
        async with asyncio.timeout(5):
            while "cue.current" not in session.subscriptions:
                await asyncio.sleep(0.001)
        await connection.send(State("cue.current", 3, "ready"))
        await run

    server = await asyncio.start_server(client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    process = await asyncio.create_subprocess_exec(
        "swift", "run", "RACPInteropPeer", "client", "127.0.0.1", str(port),
        cwd=ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
    server.close()
    await server.wait_closed()
    if process.returncode or b"SWIFT_CLIENT_OK" not in stdout:
        raise RuntimeError(f"Swift client failed:\n{stdout.decode()}\n{stderr.decode()}")
    assert any(command.name == "cue.go" and not command.has_value for command in applied)
    assert any(command.name == "cue.null" and command.has_value and command.value is None for command in applied)
    assert len([command for command in applied if command.request_id == 99]) == 1


async def read_hello(reader: asyncio.StreamReader) -> list[str]:
    lines: list[str] = []
    while not lines or lines[-1] != "END":
        lines.append((await asyncio.wait_for(reader.readline(), 5)).decode().rstrip("\r\n"))
    return lines


async def python_client_to_swift() -> None:
    process = await asyncio.create_subprocess_exec(
        "swift", "run", "RACPInteropPeer", "server", "0", cwd=ROOT,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdout is not None
    while True:
        line = await asyncio.wait_for(process.stdout.readline(), 30)
        if line.startswith(b"PORT "):
            port = int(line.split()[1])
            break
        if not line:
            stderr = await process.stderr.read() if process.stderr else b""
            raise RuntimeError(f"Swift server exited early: {stderr.decode()}")

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await read_hello(reader)
    writer.write(
        b"RACP/1 HELLO\nPEER remote python-client\nCAP cue.current\nCAP cue.go\n"
        b"CAP cue.null\nCAP state.subscribe\nEND\n"
        b"CMD 1 cue.go\nCMD 2 cue.null null\nSUB 3 cue.current\n"
        b'CMD 5 cue.go {"label":"A  B",  "a":1}\n'
        b"CMD 99 cue.go\nCMD 99 cue.go\nCMD 99 cue.null null\nPING 7\n"
    )
    await writer.drain()
    received: list[str] = []
    async with asyncio.timeout(5):
        while not any(line.startswith("STATE cue.current 3 ") for line in received):
            received.append((await reader.readline()).decode().rstrip("\r\n"))
    assert "ACK 1" in received and "ACK 2" in received and "ACK 3" in received and "ACK 5" in received
    assert received.count("ACK 99") >= 2
    assert "ERR 99 request_id_conflict" in received and "PONG 7" in received
    writer.write(b"UNSUB 4 cue.current\nBYE\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
    if process.returncode or b"SWIFT_SERVER_OK 4" not in stdout:
        raise RuntimeError(f"Swift server failed:\n{stdout.decode()}\n{stderr.decode()}")


async def main() -> None:
    await swift_client_to_python()
    await python_client_to_swift()
    print("Swift↔Python interoperability passed")


if __name__ == "__main__":
    asyncio.run(main())
