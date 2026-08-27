import asyncio

import pytest

from racp import (
    Ack,
    Command,
    Connection,
    Hello,
    ProtocolError,
    ReconnectPolicy,
    Session,
    SessionClosed,
    SessionState,
    State,
    Subscribe,
    connect_tcp,
    serve_tcp,
)


class MemoryStream:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = reads
        self.writes: list[bytes] = []
        self.is_closed = False

    async def read(self, _maximum: int) -> bytes:
        await asyncio.sleep(0)
        return self.reads.pop(0) if self.reads else b""

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.is_closed = True

    async def wait_closed(self) -> None:
        pass


def test_memory_stream_handshake_command_and_clean_close() -> None:
    async def body() -> None:
        peer = b"RACP/1 HELLO\nPEER remote desk\nCAP cue.go\nEND\nCMD 1 cue.go\nBYE\n"
        stream = MemoryStream([peer[:7], peer[7:33], peer[33:]])
        connection = Connection(stream, Session(Hello("device", "prism", ("cue.go",))))
        await connection.run()
        output = b"".join(stream.writes)
        assert output.startswith(b"RACP/1 HELLO\nPEER device prism\nCAP cue.go\nEND\n")
        assert b"ACK 1\n" in output
        assert stream.is_closed and connection.close_reason == "peer_bye"

    asyncio.run(body())


def test_handshake_timeout_is_bounded() -> None:
    class WaitingStream(MemoryStream):
        async def read(self, _maximum: int) -> bytes:
            await asyncio.sleep(10)
            return b""

    async def body() -> None:
        stream = WaitingStream([])
        connection = Connection(stream, Session(Hello("device", "x")), hello_timeout=0.01)
        await connection.run()
        assert connection.close_reason == "handshake_timeout"
        assert b"ERR 0 handshake_required\n" in b"".join(stream.writes)

    asyncio.run(body())


def test_output_queue_is_bounded() -> None:
    async def body() -> None:
        session = Session(Hello("device", "x"))
        session.state = SessionState.ESTABLISHED
        connection = Connection(MemoryStream([]), session, output_messages=1)
        await connection.send(Ack(1))
        with pytest.raises(SessionClosed, match="output_queue_full"):
            await connection.send(Ack(2))
        assert connection.closed.is_set()

    asyncio.run(body())


def test_output_queue_counts_each_message_in_a_batch() -> None:
    async def body() -> None:
        session = Session(Hello("device", "x"))
        session.state = SessionState.ESTABLISHED
        connection = Connection(MemoryStream([]), session, output_messages=2)
        with pytest.raises(SessionClosed, match="output_queue_full"):
            await connection.send(Ack(1), Ack(2), Ack(3))
        assert connection.output.empty()

    asyncio.run(body())


def test_send_requires_handshake_and_state_subscription() -> None:
    async def body() -> None:
        session = Session(Hello("device", "x", ("cue.current", "state.subscribe")))
        connection = Connection(MemoryStream([]), session)
        with pytest.raises(ProtocolError, match="handshake_required"):
            await connection.send(Ack(1))
        session.state = SessionState.ESTABLISHED
        with pytest.raises(ProtocolError, match="unsupported_capability"):
            await connection.send(State("cue.current", 1, "A"))
        assert session.receive(Subscribe(1, "cue.current")) == [Ack(1)]
        await connection.send(State("cue.current", 1, "A"))
        with pytest.raises(ProtocolError, match="invalid_value"):
            await connection.send(State("cue.current", 1, "B"))
        await connection.send(State("cue.current", 2, "B"))

    asyncio.run(body())


def test_full_queue_does_not_deadlock_shutdown() -> None:
    class BlockedStream(MemoryStream):
        async def drain(self) -> None:
            await asyncio.Event().wait()

    async def body() -> None:
        session = Session(Hello("device", "x"))
        session.state = SessionState.ESTABLISHED
        connection = Connection(BlockedStream([]), session, output_messages=1, write_timeout=0.01)
        writer = asyncio.create_task(connection._write_loop())
        await connection.send(Ack(1))
        await asyncio.sleep(0)
        await connection.send(Ack(2))
        await connection._stop_writer(writer)
        assert writer.done()

    asyncio.run(body())


def test_reconnect_backoff_is_capped() -> None:
    async def body() -> None:
        iterator = ReconnectPolicy(initial=0.25, maximum=1, jitter=0).delays()
        assert [await anext(iterator) for _ in range(5)] == [0.25, 0.5, 1.0, 1.0, 1.0]

    asyncio.run(body())


def test_tcp_loopback_interoperability() -> None:
    async def body() -> None:
        applied: list[Command] = []
        server = await serve_tcp(
            "127.0.0.1",
            0,
            lambda: Session(Hello("device", "prism", ("cue.go",)), lambda command: applied.append(command) or None),
        )
        port = server.sockets[0].getsockname()[1]
        client_session = Session(Hello("remote", "desk", ("cue.go",)))
        connection = await connect_tcp("127.0.0.1", port, client_session)
        task = asyncio.create_task(connection.run())
        try:
            async with asyncio.timeout(1):
                while client_session.state.value != "established":
                    await asyncio.sleep(0.001)
            await connection.send(Command(1, "cue.go"))
            async with asyncio.timeout(1):
                while not applied:
                    await asyncio.sleep(0.001)
            assert applied == [Command(1, "cue.go")]
        finally:
            await connection.close("test_complete")
            await task
            server.close()
            await server.wait_closed()

    asyncio.run(body())
