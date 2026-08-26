"""In-process transports and deterministic helpers."""

from __future__ import annotations

import asyncio
from dataclasses import fields
from datetime import UTC, datetime
from typing import Any, cast

from .session import Session, Transport
from .types import Capability, NodeIdentity, Role, new_uuid


def unsafe_transport_evidence_for_testing(**values: object):
    """Construct sealed evidence in tests; never use this in a product adapter."""
    from .security import _verified_transport_evidence

    return _verified_transport_evidence(**values)


def unsafe_authenticated_principal_for_testing(**values: object):
    """Construct a sealed principal for authorization unit tests only."""
    from .security import _admitted_principal

    return _admitted_principal(**values)


def unsafe_full_tls_handshake_for_testing(**values: object):
    """Construct sealed TLS facts for deterministic transport unit tests only."""
    from .security_transport import _verified_full_tls_handshake

    return _verified_full_tls_handshake(**values)


def unsafe_replace_security_value_for_testing(value: object, **changes: object):
    """Copy a sealed security value with mutations for negative-path tests."""
    from .security import TransportEvidence
    from .security_transport import FullTLSHandshake

    values = {field.name: getattr(value, field.name) for field in fields(cast(Any, value))} | changes
    if isinstance(value, TransportEvidence):
        return unsafe_transport_evidence_for_testing(**values)
    if isinstance(value, FullTLSHandshake):
        return unsafe_full_tls_handshake_for_testing(**values)
    raise TypeError("unsupported sealed security value")


class LoopbackTransport(Transport):
    def __init__(self) -> None:
        self.peer: LoopbackTransport | None = None
        self._queue: asyncio.Queue[tuple[bytes, bool]] = asyncio.Queue()
        self.closed = False
        self.peer_identity: str | None = None

    def attach(self, peer: LoopbackTransport) -> None:
        self.peer = peer
        peer.peer = self

    async def send(self, data: bytes, *, text: bool) -> None:
        if self.closed or self.peer is None or self.peer.closed:
            raise ConnectionError("transport closed")
        await self.peer._queue.put((data, text))

    async def recv(self) -> tuple[bytes, bool]:
        while not self.closed:
            try:
                return await asyncio.wait_for(self._queue.get(), timeout=0.05)
            except TimeoutError:
                if self.closed:
                    raise ConnectionError("transport closed") from None
        raise ConnectionError("transport closed")

    async def close(self) -> None:
        self.closed = True


class GateTransport(LoopbackTransport):
    """Blocks sends until `gate` is set. Records committed frames."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = asyncio.Event()
        self.committed: list[bytes] = []

    async def send(self, data: bytes, *, text: bool) -> None:
        await self.gate.wait()
        self.committed.append(data)
        await super().send(data, text=text)


def linked_transports() -> tuple[LoopbackTransport, LoopbackTransport]:
    a, b = LoopbackTransport(), LoopbackTransport()
    a.attach(b)
    return a, b


def identity(role: Role, name: str | None = None) -> NodeIdentity:
    return NodeIdentity(
        node_id=new_uuid(),
        instance_id=new_uuid(),
        role=role,
        name=name or role.value,
        product_version="1.2.0",
    )


def default_caps() -> list[Capability]:
    return [
        Capability("health.heartbeat", "1.0"),
        Capability("prism.cue_control", "1.0"),
        Capability("bridge.blackout", "1.0"),
        Capability("bridge.config", "1.0"),
        Capability("asset.conformance", "1.2"),
        Capability("resource.transfer", "1.2"),
        Capability("lyric.assignment", "1.2"),
        Capability("remote.profile", "1.0"),
        Capability("remote.layout", "1.0"),
        Capability("remote.control.invoke", "1.0"),
        Capability("remote.control.momentary", "1.0"),
        Capability("remote.control.state", "1.0"),
        Capability("remote.presentation", "1.0"),
        Capability("remote.navigation.song", "1.0"),
        Capability("remote.readiness", "1.0"),
        Capability("show.navigation", "1.0"),
        Capability("song.selection", "1.0"),
        Capability("song.loading", "1.0"),
        Capability("cue.go", "1.0"),
        Capability("look.global", "1.0"),
        Capability("remote.surfaces", "1.0"),
        Capability("busk.controls", "1.0"),
        Capability("control.momentary", "1.0"),
        Capability("output.blackout", "1.0"),
        Capability("output.grand_master", "1.0"),
        Capability("state.live", "1.0"),
        Capability("system.health", "1.0"),
    ]


async def connected_pair(
    left_role: Role = Role.CONDUCTOR,
    right_role: Role = Role.BRIDGE,
    capabilities: list | None = None,
) -> tuple[Session, Session]:
    caps = capabilities or default_caps()
    ta, tb = linked_transports()
    client = Session(
        ta,
        identity(left_role),
        is_server=False,
        allow_plaintext=True,
        profiles=["core", "remote", "aurora.remote.prism.v1"],
    )
    server = Session(
        tb,
        identity(right_role),
        is_server=True,
        allow_plaintext=True,
        profiles=["core", "remote", "aurora.remote.prism.v1"],
    )
    await server.start_receiver()

    async def run() -> None:
        await asyncio.gather(
            server.handshake(caps),
            client.handshake(caps),
        )

    await run()
    return client, server


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 8, 17, 16, 42, 15, 231000, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now
