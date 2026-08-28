"""Observable asyncio rACP client used by integration scenarios."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from racp import (
    Ack,
    Bye,
    Command,
    Error,
    Hello,
    LineDecoder,
    Ping,
    Pong,
    State,
    Subscribe,
    Unsubscribe,
    encode_message,
    parse_message,
)
from racp.protocol import Message

from .model import TranscriptEntry


class PeerClosed(ConnectionError):
    pass


class RACPClient:
    def __init__(self, host: str, port: int, hello: Hello, timeout: float, transcript: list[TranscriptEntry]) -> None:
        self.host = host
        self.port = port
        self.hello = hello
        self.timeout = timeout
        self.transcript = transcript
        self.peer: Hello | None = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.decoder = LineDecoder()
        self.pending: list[object] = []
        self.started = time.monotonic()
        self.next_id = 1

    async def connect(self) -> Hello:
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)
        for line in self.hello.lines():
            await self.send_line(line)
        lines: list[str] = []
        while not lines or lines[-1] != "END":
            lines.append(await self.read_line())
        # Reuse the reference session to validate strict HELLO grammar.
        from racp import Session

        session = Session(self.hello)
        for line in lines:
            session.receive_line(line)
        assert session.peer is not None
        self.peer = session.peer
        return self.peer

    async def close(self, orderly: bool = True) -> None:
        if self.writer is None:
            return
        if orderly and not self.writer.is_closing():
            try:
                await self.send(Bye())
            except (ConnectionError, OSError):
                pass
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), self.timeout)
        except (ConnectionError, OSError, TimeoutError):
            pass
        self.reader = None
        self.writer = None

    async def send_line(self, line: str) -> None:
        if self.writer is None:
            raise RuntimeError("not connected")
        self._record("send", line)
        self.writer.write(line.encode("utf-8") + b"\n")
        await asyncio.wait_for(self.writer.drain(), self.timeout)

    async def send_bytes(self, data: bytes, display: str) -> None:
        if self.writer is None:
            raise RuntimeError("not connected")
        self._record("send", display)
        self.writer.write(data)
        await asyncio.wait_for(self.writer.drain(), self.timeout)

    async def send(self, message: object) -> None:
        await self.send_line(encode_message(message))  # type: ignore[arg-type]

    async def read_line(self) -> str:
        if self.reader is None:
            raise RuntimeError("not connected")
        raw = await asyncio.wait_for(self.reader.readline(), self.timeout)
        if not raw:
            raise PeerClosed("peer closed the connection")
        lines = self.decoder.feed(raw)
        if len(lines) != 1:
            raise RuntimeError("reader returned an incomplete rACP line")
        self._record("recv", lines[0])
        return lines[0]

    async def receive(self) -> Message:
        while True:
            message = parse_message(await self.read_line())
            if isinstance(message, Ping):
                await self.send(Pong(message.nonce))
                continue
            return message

    async def expect(self, predicate: Callable[[Message], bool], description: str) -> Message:
        for index, message in enumerate(self.pending):
            if predicate(message):  # type: ignore[arg-type]
                return self.pending.pop(index)  # type: ignore[return-value]
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"timed out waiting for {description}")
            try:
                async with asyncio.timeout(remaining):
                    message = await self.receive()
            except TimeoutError as exc:
                raise AssertionError(f"timed out waiting for {description}") from exc
            if predicate(message):
                return message
            self.pending.append(message)

    async def request(self, message: Command | Subscribe | Unsubscribe) -> Ack | Error:
        request_id = message.request_id
        await self.send(message)
        response = await self.expect(
            lambda item: isinstance(item, (Ack, Error)) and item.request_id == request_id,
            f"terminal response for request {request_id}",
        )
        assert isinstance(response, (Ack, Error))
        return response

    def allocate_id(self) -> int:
        value = self.next_id
        self.next_id += 1
        return value

    def _record(self, direction: str, line: str) -> None:
        self.transcript.append(TranscriptEntry(time.monotonic() - self.started, direction, line))


def terminal_name(message: Ack | Error) -> str:
    return "ack" if isinstance(message, Ack) else message.code


def is_state(name: str) -> Callable[[Message], bool]:
    return lambda message: isinstance(message, State) and message.name == name
