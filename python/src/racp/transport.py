"""Bounded plain-TCP transport for the transport-independent rACP session."""

from __future__ import annotations

import asyncio
import contextlib
import random
import socket
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Protocol

from .protocol import Error, LineDecoder, Message, ProtocolError, State
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
        allow_unsolicited_state: bool = False,
    ) -> None:
        if output_messages < 1 or hello_timeout <= 0 or write_timeout <= 0:
            raise ValueError("transport bounds and timeouts must be positive")
        self.stream = stream
        self.session = session
        self.hello_timeout = hello_timeout
        self.write_timeout = write_timeout
        self.allow_unsolicited_state = allow_unsolicited_state
        self.output: asyncio.Queue[bytes | None] = asyncio.Queue(output_messages)
        self.decoder = LineDecoder()
        self.closed = asyncio.Event()
        self.close_reason: str | None = None
        self._next_nonce = 1
        self._closing = False
        self._published_revisions: dict[str, int] = {}

    async def send(self, *messages: Message) -> None:
        if self._closing:
            raise SessionClosed(self.close_reason or "closing")
        if self.session.state is not SessionState.ESTABLISHED:
            raise ProtocolError("handshake_required")
        pending_revisions = dict(self._published_revisions)
        for message in messages:
            if isinstance(message, State):
                if not self.allow_unsolicited_state and message.name not in self.session.subscriptions:
                    raise ProtocolError("unsupported_capability")
                if message.revision <= pending_revisions.get(message.name, -1):
                    raise ProtocolError("invalid_value")
                pending_revisions[message.name] = message.revision
        encoded = [Session.encode([message]) for message in messages]
        if len(encoded) > self.output.maxsize - self.output.qsize():
            await self.close("output_queue_full")
            raise SessionClosed("output_queue_full")
        for data in encoded:
            self.output.put_nowait(data)
        self._published_revisions = pending_revisions

    async def run(self) -> None:
        writer = asyncio.create_task(self._write_loop())
        heartbeat = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._enqueue_raw(self.session.hello_bytes())
            await self._flush_output()
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
        with contextlib.suppress(ConnectionError, OSError, TimeoutError):
            async with asyncio.timeout(self.write_timeout):
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
        try:
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
        except (ConnectionError, OSError, TimeoutError):
            await self.close("write_failed")
            raise

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                messages = self.session.heartbeat(self._next_nonce)
            except SessionClosed:
                await self.close("heartbeat_timeout")
                return
            if messages:
                self._next_nonce = self._next_nonce + 1 if self._next_nonce < 9_007_199_254_740_991 else 1
                try:
                    await self.send(*messages)
                except SessionClosed:
                    return

    async def _enqueue_raw(self, data: bytes) -> None:
        if self.output.full():
            raise SessionClosed("output_queue_full")
        self.output.put_nowait(data)

    async def _try_error(self, code: str) -> None:
        if not self._closing and not self.output.full():
            await self._enqueue_raw(Session.encode([Error(0, code)]))

    async def _stop_writer(self, task: asyncio.Task[None]) -> None:
        if not task.done():
            try:
                async with asyncio.timeout(self.write_timeout):
                    await self.output.join()
            except TimeoutError:
                self.close_reason = self.close_reason or "write_timeout"
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError, OSError, TimeoutError):
                await task
        if not task.cancelled() and task.done() and task.exception() is not None:
            self.close_reason = "write_failed"

    async def _flush_output(self) -> None:
        async with asyncio.timeout(self.write_timeout):
            await self.output.join()
        if self._closing:
            raise SessionClosed(self.close_reason or "closing")


def _enable_keepalive(writer: asyncio.StreamWriter) -> None:
    stream_socket = writer.get_extra_info("socket")
    if stream_socket is not None:
        with contextlib.suppress(OSError):
            stream_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


async def connect_tcp(
    host: str, port: int, session: Session, *, keepalive: bool = True, **options: object
) -> Connection:
    reader, writer = await asyncio.open_connection(host, port)
    if keepalive:
        _enable_keepalive(writer)
    return Connection(AsyncioStream(reader, writer), session, **options)  # type: ignore[arg-type]


async def serve_tcp(
    host: str,
    port: int,
    session_factory: Callable[[], Session],
    *,
    max_connections: int = 64,
    backlog: int = 100,
    keepalive: bool = True,
    **options: object,
) -> asyncio.Server:
    if max_connections < 1 or backlog < 1:
        raise ValueError("server bounds must be positive")
    connections = asyncio.Semaphore(max_connections)

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if connections.locked():
            writer.close()
            await writer.wait_closed()
            return
        await connections.acquire()
        try:
            if keepalive:
                _enable_keepalive(writer)
            try:
                session = session_factory()
            except Exception:
                writer.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.wait_closed()
                raise
            await Connection(AsyncioStream(reader, writer), session, **options).run()  # type: ignore[arg-type]
        finally:
            connections.release()

    return await asyncio.start_server(client, host, port, limit=READ_CHUNK_BYTES, backlog=backlog)
