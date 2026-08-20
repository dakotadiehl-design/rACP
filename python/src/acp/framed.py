"""Length-prefixed TCP framing for cross-language session tests.

Frame: 4-byte big-endian payload length, 1-byte flags (bit 0 = text/JSON), payload.
"""

from __future__ import annotations

import asyncio
import struct

from .session import Transport

MAX_FRAME = 8 * 1024 * 1024


class FramedTransport(Transport):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._closed = False
        self.peer_identity: str | None = None

    async def send(self, data: bytes, *, text: bool) -> None:
        if len(data) > MAX_FRAME:
            raise ConnectionError("frame exceeds maximum")
        self.writer.write(struct.pack("!IB", len(data), 1 if text else 0) + data)
        await self.writer.drain()

    async def recv(self) -> tuple[bytes, bool]:
        header = await self.reader.readexactly(5)
        length, flags = struct.unpack("!IB", header)
        if length > MAX_FRAME:
            raise ConnectionError("frame exceeds maximum")
        payload = await self.reader.readexactly(length)
        return payload, bool(flags & 1)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def connect_framed(host: str, port: int) -> FramedTransport:
    reader, writer = await asyncio.open_connection(host, port)
    return FramedTransport(reader, writer)


async def serve_framed(host: str, port: int, handler) -> asyncio.AbstractServer:
    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        transport = FramedTransport(reader, writer)
        try:
            await handler(transport)
        finally:
            await transport.close()

    return await asyncio.start_server(_client, host, port)
