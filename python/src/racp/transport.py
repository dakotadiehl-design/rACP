"""Bounded plain-TCP transport for the transport-independent rACP session."""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Protocol

from .protocol import Error, LineDecoder, Message, ProtocolError
from .session import Session, SessionClosed, SessionState

READ_CHUNK_BYTES = 4096
DEFAULT_OUTPUT_MESSAGES = 256
HELLO_TIMEOUT_SECONDS = 5.0
WRITE_TIMEOUT_SECONDS = 5.0


class ByteStream(Protocol):
    async def read(self, maximum: int) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...


class AsyncioStream:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def read(self, maximum: int) -> bytes:
        return await self.reader.read(maximum)

    def write(self, data: bytes) -> None:
        self.writer.write(data)

    async def drain(self) -> None:
        await self.writer.drain()

    def close(self) -> None:
        self.writer.close()

    async def wait_closed(self) -> None:
        await self.writer.wait_closed()


@dataclass(frozen=True)
class ReconnectPolicy:
    initial: float = 0.25
    maximum: float = 5.0
    multiplier: float = 2.0
    jitter: float = 0.2

    def delays(self, *, random_value: Callable[[], float] = random.random) -> AsyncIterator[float]:
        async def generate() -> AsyncIterator[float]:
            delay = self.initial
            while True:
                spread = delay * self.jitter
                yield max(0.0, delay - spread + 2 * spread * random_value())
                delay = min(self.maximum, delay * self.multiplier)

        if self.initial <= 0 or self.maximum < self.initial or self.multiplier < 1 or not 0 <= self.jitter <= 1:
            raise ValueError("invalid reconnect policy")
        return generate()


class Connection:
    def __init__(
        self,
        stream: ByteStream,
        session: Session,
        *,
        output_messages: int = DEFAULT_OUTPUT_MESSAGES,
        hello_timeout: float = HELLO_TIMEOUT_SECONDS,
        write_timeout: float = WRITE_TIMEOUT_SECONDS,
    ) -> None:
        if output_messages < 1 or hello_timeout <= 0 or write_timeout <= 0:
            raise ValueError("transport bounds and timeouts must be positive")
        self.stream = stream
        self.session = session
        self.hello_timeout = hello_timeout
        self.write_timeout = write_timeout
        self.output: asyncio.Queue[bytes | None] = asyncio.Queue(output_messages)
        self.decoder = LineDecoder()
        self.closed = asyncio.Event()
        self.close_reason: str | None = None
        self._next_nonce = 1
        self._closing = False

    async def send(self, *messages: Message) -> None:
        if self._closing:
            raise SessionClosed(self.close_reason or "closing")
        data = Session.encode(list(messages))
        if self.output.full():
            await self.close("output_queue_full")
            raise SessionClosed("output_queue_full")
        self.output.put_nowait(data)

    async def run(self) -> None:
        writer = asyncio.create_task(self._write_loop())
        heartbeat = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._enqueue_raw(self.session.hello_bytes())
            async with asyncio.timeout(self.hello_timeout):
                await self._read_until_established()
            await self._read_established()
        except TimeoutError:
            self.close_reason = "handshake_timeout"
            await self._try_error("handshake_required")
        except ProtocolError as exc:
            self.close_reason = exc.code
            await self._try_error(exc.code)
        except SessionClosed as exc:
            self.close_reason = str(exc)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            self.close_reason = "connection_lost"
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            await self._stop_writer(writer)
            await self.close(self.close_reason or "eof")

    async def close(self, reason: str = "closed") -> None:
        if self._closing:
            await self.closed.wait()
            return
        self._closing = True
        self.close_reason = self.close_reason or reason
        self.session.state = SessionState.CLOSED
        self.stream.close()
        with contextlib.suppress(ConnectionError, OSError):
            await self.stream.wait_closed()
        self.closed.set()

    async def _read_until_established(self) -> None:
        while self.session.state is SessionState.HELLO:
            if not await self._read_once():
                raise ConnectionError("EOF during HELLO")

    async def _read_established(self) -> None:
        while self.session.state is SessionState.ESTABLISHED:
            if not await self._read_once():
                return
        if self.session.state is SessionState.CLOSING:
            self.close_reason = "peer_bye"

    async def _read_once(self) -> bool:
        data = await self.stream.read(READ_CHUNK_BYTES)
        if not data:
            self.decoder.eof()
            return False
        for line in self.decoder.feed(data):
            responses = self.session.receive_line(line)
            if responses:
                await self.send(*responses)
        return True

    async def _write_loop(self) -> None:
        while True:
            data = await self.output.get()
            try:
                if data is None:
                    return
                self.stream.write(data)
                async with asyncio.timeout(self.write_timeout):
                    await self.stream.drain()
            finally:
                self.output.task_done()

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                messages = self.session.heartbeat(self._next_nonce)
            except SessionClosed:
                self.close_reason = "heartbeat_timeout"
                self.stream.close()
                return
            if messages:
                self._next_nonce = self._next_nonce + 1 if self._next_nonce < 9_007_199_254_740_991 else 1
                await self.send(*messages)

    async def _enqueue_raw(self, data: bytes) -> None:
        if self.output.full():
            raise SessionClosed("output_queue_full")
        self.output.put_nowait(data)

    async def _try_error(self, code: str) -> None:
        if not self._closing and not self.output.full():
            await self._enqueue_raw(Session.encode([Error(0, code)]))

    async def _stop_writer(self, task: asyncio.Task[None]) -> None:
        if not task.done():
            with contextlib.suppress(asyncio.QueueFull):
                self.output.put_nowait(None)
            try:
                async with asyncio.timeout(self.write_timeout):
                    await task
            except TimeoutError:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        elif task.exception() is not None:
            self.close_reason = "write_failed"


async def connect_tcp(host: str, port: int, session: Session, **options: object) -> Connection:
    reader, writer = await asyncio.open_connection(host, port)
    return Connection(AsyncioStream(reader, writer), session, **options)  # type: ignore[arg-type]


async def serve_tcp(host: str, port: int, session_factory: Callable[[], Session], **options: object) -> asyncio.Server:
    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = Connection(AsyncioStream(reader, writer), session_factory(), **options)  # type: ignore[arg-type]
        await connection.run()

    return await asyncio.start_server(client, host, port, limit=READ_CHUNK_BYTES)
