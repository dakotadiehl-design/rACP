from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from acp.envelope import Envelope
from acp.framed import connect_framed
from acp.session import Session
from acp.ws import connect_ws

from .models import ConnectionConfig, ConnectionState, WorkbenchEvent, utc_now_text
from .profiles import Profile, create_profile
from .transcript import TranscriptWriter

TransportFactory = Callable[[ConnectionConfig], Any]


@dataclass(slots=True)
class WorkbenchConnection:
    id: str
    config: ConnectionConfig
    profile: Profile
    state: ConnectionState = ConnectionState.DISCONNECTED
    session: Session | None = None
    receive_task: asyncio.Task[None] | None = None
    engine: WorkbenchEngine | None = field(default=None, repr=False)

    async def send(self, envelope: Envelope) -> Envelope | None:
        if self.session is None:
            raise RuntimeError("connection has no session")
        if self.engine is None:
            raise RuntimeError("connection is detached from engine")
        await self.engine.emit("envelope.out", self.id, {"envelope": envelope.to_dict()})
        return await self.session.send(envelope)

    async def request(self, envelope: Envelope, timeout: float) -> Envelope:
        if self.session is None:
            raise RuntimeError("connection has no session")
        if self.engine is None:
            raise RuntimeError("connection is detached from engine")
        await self.engine.emit("envelope.out", self.id, {"envelope": envelope.to_dict(), "request": True})
        response = await self.session.request(envelope, timeout=timeout)
        return response


class WorkbenchEngine:
    def __init__(
        self,
        *,
        transport_factory: TransportFactory | None = None,
        transcript: TranscriptWriter | None = None,
    ) -> None:
        self.connections: dict[str, WorkbenchConnection] = {}
        self.history: list[WorkbenchEvent] = []
        self._condition = asyncio.Condition()
        self._sequence = 0
        self._started = time.monotonic()
        self._transport_factory = transport_factory or self._default_transport
        self._transcript = transcript

    async def _default_transport(self, config: ConnectionConfig):
        parsed = urlparse(config.target)
        if parsed.scheme in {"tcp", "acp+tcp"}:
            if not config.allow_plaintext:
                raise ConnectionError("framed TCP requires explicit allow_plaintext")
            if not parsed.hostname or not parsed.port:
                raise ConnectionError("framed TCP target requires host and port")
            return await connect_framed(parsed.hostname, parsed.port)
        ssl_context = None
        if parsed.scheme == "wss":
            ssl_context = ssl.create_default_context(cafile=config.ca_file)
            if config.cert_file:
                ssl_context.load_cert_chain(config.cert_file, config.key_file)
        return await connect_ws(
            config.target,
            ssl_context=ssl_context,
            allow_plaintext=config.allow_plaintext,
        )

    async def emit(self, kind: str, connection_id: str | None, data: dict[str, Any] | None = None) -> WorkbenchEvent:
        async with self._condition:
            self._sequence += 1
            event = WorkbenchEvent(
                sequence=self._sequence,
                kind=kind,
                connection_id=connection_id,
                monotonic_s=time.monotonic() - self._started,
                timestamp_utc=utc_now_text(),
                data=data or {},
            )
            self.history.append(event)
            if self._transcript:
                self._transcript.write(event)
            self._condition.notify_all()
            return event

    async def connect(self, config: ConnectionConfig, *, connection_id: str = "default") -> WorkbenchConnection:
        if connection_id in self.connections:
            raise ValueError(f"connection {connection_id!r} already exists")
        profile = create_profile(config.profile, config)
        conn = WorkbenchConnection(connection_id, config, profile, engine=self)
        self.connections[connection_id] = conn
        try:
            conn.state = ConnectionState.CONNECTING
            await self.emit("connection.state", connection_id, {"state": conn.state.value, "target": config.target})
            transport = await self._transport_factory(config)
            conn.session = Session(
                transport,
                profile.node,
                is_server=False,
                allow_plaintext=config.allow_plaintext,
                profiles=profile.session_profiles(),
            )
            conn.state = ConnectionState.NEGOTIATING
            await self.emit("connection.state", connection_id, {"state": conn.state.value})
            ack = await conn.session.handshake(profile.capabilities())
            await self.emit("session.established", connection_id, {
                "session_id": conn.session.session_id,
                "protocol": conn.session.session_version,
                "encoding": conn.session.encoding,
                "profiles": sorted(conn.session.negotiated_profiles),
                "hello_ack": ack.to_dict(),
            })
            conn.receive_task = asyncio.create_task(self._receive(conn), name=f"workbench-recv-{connection_id}")
            conn.state = ConnectionState.SYNCHRONIZING
            await self.emit("connection.state", connection_id, {"state": conn.state.value})
            await profile.synchronize(conn)
            conn.state = ConnectionState.READY
            await self.emit("connection.state", connection_id, {"state": conn.state.value})
            return conn
        except Exception as exc:
            conn.state = ConnectionState.FAILED
            await self.emit("connection.failed", connection_id, {"error": str(exc), "type": type(exc).__name__})
            await self.disconnect(connection_id, graceful=False, remove=False)
            raise

    async def _receive(self, connection: WorkbenchConnection) -> None:
        assert connection.session is not None
        try:
            async for envelope in connection.session.subscribe():
                await self.emit("envelope.in", connection.id, {"envelope": envelope.to_dict()})
                if envelope.type.startswith("resource."):
                    await connection.profile.handle_resource(connection, envelope)
                else:
                    connection.profile.handle(envelope)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.emit("connection.receive_error", connection.id, {"error": str(exc)})
        finally:
            if connection.state not in {ConnectionState.CLOSING, ConnectionState.DISCONNECTED}:
                connection.state = ConnectionState.FAILED
                await self.emit("connection.state", connection.id, {"state": connection.state.value})

    async def disconnect(self, connection_id: str, *, graceful: bool = True, remove: bool = True) -> None:
        conn = self.connections.get(connection_id)
        if conn is None:
            return
        was_failed = conn.state is ConnectionState.FAILED
        if not was_failed:
            conn.state = ConnectionState.CLOSING
            await self.emit("connection.state", connection_id, {"state": conn.state.value})
        if conn.session:
            if graceful:
                await conn.profile.prepare_disconnect(conn)
                await conn.session.goodbye("workbench disconnect")
            else:
                await conn.session._shutdown("cancelled", "workbench disconnect")
        if conn.receive_task and conn.receive_task is not asyncio.current_task():
            conn.receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await conn.receive_task
        if not was_failed:
            conn.state = ConnectionState.DISCONNECTED
            await self.emit("connection.state", connection_id, {"state": conn.state.value})
        if remove:
            self.connections.pop(connection_id, None)

    async def close(self) -> None:
        for connection_id in list(self.connections):
            await self.disconnect(connection_id)
        if self._transcript:
            self._transcript.close()

    async def invoke(self, connection_id: str, action: str, value: Any = None, **parameters: Any) -> Envelope:
        conn = self.connections[connection_id]
        envelope = conn.profile.envelope_for_action(action, value, **parameters)
        await conn.send(envelope)
        await self.emit("action.pending", connection_id, {
            "action": action,
            "invocation_id": envelope.payload.get("invocation_id"),
            "message_id": envelope.message_id,
        })
        return envelope

    async def navigate(self, connection_id: str, kind: str, *, song_id: str | None = None) -> Envelope:
        conn = self.connections[connection_id]
        envelope = conn.profile.navigation(kind, song_id=song_id)
        await conn.send(envelope)
        return envelope

    async def momentary(self, connection_id: str, action: str, *, value: Any = 1.0, duration: float = 1.0) -> None:
        begin = await self.invoke(connection_id, action, value, interaction="momentary_begin")
        ack = await self.wait_for(
            lambda event: event.connection_id == connection_id
            and event.kind == "envelope.in"
            and event.data["envelope"].get("type") == "command.ack"
            and event.data["envelope"].get("correlation_id") == begin.message_id,
            timeout=self.connections[connection_id].config.timeout,
        )
        if ack.data["envelope"]["payload"].get("status") not in {"applied", "duplicate"}:
            return
        invocation_id = str(begin.payload["invocation_id"])
        lease_id = (ack.data["envelope"]["payload"].get("result") or {}).get("lease_id")
        try:
            await asyncio.sleep(max(0.0, duration))
        finally:
            await self.invoke(
                connection_id,
                action,
                interaction="momentary_end",
                invocation_id=invocation_id,
                lease_id=lease_id,
            )

    async def wait_for(
        self,
        predicate: Callable[[WorkbenchEvent], bool],
        *,
        after_sequence: int = 0,
        timeout: float = 5.0,
    ) -> WorkbenchEvent:
        deadline = asyncio.get_running_loop().time() + timeout
        async with self._condition:
            while True:
                for event in self.history:
                    if event.sequence > after_sequence and predicate(event):
                        return event
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for Workbench event")
                await asyncio.wait_for(self._condition.wait(), timeout=remaining)
