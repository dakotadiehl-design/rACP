"""Capability-aware Prism integration scenarios."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from racp import Ack, Command, Error, Hello, Ping, Pong, State, Subscribe, Unsubscribe

from .client import PeerClosed, RACPClient, is_state, terminal_name
from .config import CommandCase, HarnessConfig, SubscriptionCase
from .model import RunReport, ScenarioResult, Status

Scenario = Callable[[], Awaitable[str | None]]


class HarnessRunner:
    def __init__(self, config: HarnessConfig, *, allow_state_changes: bool = False, probe_only: bool = False) -> None:
        self.config = config
        self.allow_state_changes = allow_state_changes
        self.probe_only = probe_only
        self.report = RunReport(target=f"{config.host}:{config.port}", metadata=config.metadata)
        self.client: RACPClient | None = None

    async def run(self) -> RunReport:
        await self._scenario("handshake", self._handshake)
        if self.client is None:
            return self.report
        await self._scenario("required capabilities", self._required_capabilities)
        await self._scenario("ping/pong", self._ping)
        if not self.probe_only:
            await self._scenario("unsupported command", self._unsupported_command)
            for command_case in self.config.commands:
                await self._command_case(command_case)
            for subscription_case in self.config.subscriptions:
                await self._subscription_case(subscription_case)
            await self._scenario("orderly close", self._orderly_close)
            await self._scenario("reconnect", self._reconnect)
            if self.config.malformed_tests:
                await self._malformed_scenarios()
        else:
            await self.client.close()
        return self.report

    async def _scenario(self, name: str, operation: Scenario, skip: str | None = None) -> None:
        if skip is not None:
            self.report.results.append(ScenarioResult(name, Status.SKIP, skip))
            return
        started = time.monotonic()
        try:
            detail = await operation()
        except Exception as exc:
            self.report.results.append(
                ScenarioResult(name, Status.FAIL, f"{type(exc).__name__}: {exc}", time.monotonic() - started)
            )
        else:
            self.report.results.append(ScenarioResult(name, Status.PASS, detail or "", time.monotonic() - started))

    def _new_client(self) -> RACPClient:
        return RACPClient(
            self.config.host,
            self.config.port,
            Hello(self.config.peer_type, self.config.peer_id),
            self.config.timeout,
            self.report.transcripts,
        )

    async def _handshake(self) -> str:
        client = self._new_client()
        peer = await client.connect()
        if self.config.expected_peer_type is not None and peer.peer_type != self.config.expected_peer_type:
            raise AssertionError(f"peer type {peer.peer_type!r}, expected {self.config.expected_peer_type!r}")
        if self.config.expected_peer_id is not None and peer.peer_id != self.config.expected_peer_id:
            raise AssertionError(f"peer ID {peer.peer_id!r}, expected {self.config.expected_peer_id!r}")
        self.client = client
        self.report.peer = {"type": peer.peer_type, "id": peer.peer_id, "capabilities": list(peer.capabilities)}
        return f"{peer.peer_type} {peer.peer_id}; {len(peer.capabilities)} capabilities"

    async def _required_capabilities(self) -> str:
        assert self.client is not None and self.client.peer is not None
        missing = sorted(set(self.config.required_capabilities) - set(self.client.peer.capabilities))
        if missing:
            raise AssertionError(f"missing: {', '.join(missing)}")
        return f"{len(self.config.required_capabilities)} required"

    async def _ping(self) -> str | None:
        assert self.client is not None
        nonce = 9_001
        await self.client.send(Ping(nonce))
        await self.client.expect(lambda item: isinstance(item, Pong) and item.nonce == nonce, f"PONG {nonce}")
        return None

    async def _unsupported_command(self) -> str | None:
        assert self.client is not None and self.client.peer is not None
        name = "harness.unsupported"
        if name in self.client.peer.capabilities:
            raise AssertionError(f"reserved test capability {name!r} is unexpectedly advertised")
        response = await self.client.request(Command(self.client.allocate_id(), name))
        if not isinstance(response, Error) or response.code != "unsupported_capability":
            raise AssertionError(f"received {terminal_name(response)}, expected unsupported_capability")
        return None

    async def _command_case(self, case: CommandCase) -> None:
        skip = "requires --allow-state-changes" if case.state_changing and not self.allow_state_changes else None
        if self.client is not None and self.client.peer is not None and case.name not in self.client.peer.capabilities:
            skip = f"Prism does not advertise {case.name}"
        await self._scenario(f"command {case.name}", lambda: self._run_command(case), skip)

    async def _run_command(self, case: CommandCase) -> str:
        assert self.client is not None
        request_id = self.client.allocate_id()
        command = Command(request_id, case.name, case.value, case.has_value)
        first = await self.client.request(command)
        if terminal_name(first) != case.expected:
            raise AssertionError(f"received {terminal_name(first)}, expected {case.expected}")
        duplicate = await self.client.request(command)
        if duplicate != first:
            raise AssertionError(f"duplicate response changed from {first!r} to {duplicate!r}")
        conflicting = Command(request_id, case.name, None, not case.has_value)
        conflict = await self.client.request(conflicting)
        if not isinstance(conflict, Error) or conflict.code != "request_id_conflict":
            raise AssertionError(f"conflicting ID received {terminal_name(conflict)}")
        return "terminal response replayed; conflicting ID rejected"

    async def _subscription_case(self, case: SubscriptionCase) -> None:
        assert self.client is not None and self.client.peer is not None
        missing = [cap for cap in ("state.subscribe", case.name) if cap not in self.client.peer.capabilities]
        skip = f"Prism does not advertise {', '.join(missing)}" if missing else None
        await self._scenario(f"subscription {case.name}", lambda: self._run_subscription(case), skip)

    async def _run_subscription(self, case: SubscriptionCase) -> str:
        assert self.client is not None
        response = await self.client.request(Subscribe(self.client.allocate_id(), case.name))
        if not isinstance(response, Ack):
            raise AssertionError(f"SUB received {terminal_name(response)}")
        detail = "accepted"
        if case.expect_initial:
            state = await self.client.expect(is_state(case.name), f"initial STATE {case.name}")
            assert isinstance(state, State)
            detail = f"initial revision {state.revision}"
        response = await self.client.request(Unsubscribe(self.client.allocate_id(), case.name))
        if not isinstance(response, Ack):
            raise AssertionError(f"UNSUB received {terminal_name(response)}")
        return detail

    async def _orderly_close(self) -> str | None:
        assert self.client is not None
        await self.client.close(orderly=True)
        self.client = None
        return None

    async def _reconnect(self) -> str:
        client = self._new_client()
        try:
            peer = await client.connect()
            if self.report.peer is not None:
                expected = (self.report.peer["type"], self.report.peer["id"])
                if (peer.peer_type, peer.peer_id) != expected:
                    raise AssertionError("peer identity changed after reconnect")
        finally:
            await client.close()
        return "fresh HELLO completed"

    async def _malformed_scenarios(self) -> None:
        await self._scenario(
            "CRLF input", lambda: self._raw_established(b"PING 8123\r\n", "PONG 8123", "PING 8123\\r\\n")
        )
        await self._scenario(
            "unknown verb", lambda: self._raw_established(b"WAT 1\n", "ERR 0 malformed_message", "WAT 1")
        )
        await self._scenario("invalid HELLO", self._invalid_hello)
        await self._scenario("overlong line", self._overlong_line)

    async def _raw_established(self, payload: bytes, expected: str, display: str) -> str | None:
        client = self._new_client()
        try:
            await client.connect()
            await client.send_bytes(payload, display)
            line = await client.read_line()
            if line != expected:
                raise AssertionError(f"received {line!r}, expected {expected!r}")
        finally:
            await client.close(orderly=False)
        return None

    async def _invalid_hello(self) -> str | None:
        client = self._new_client()
        client.reader, client.writer = await asyncio.wait_for(
            asyncio.open_connection(self.config.host, self.config.port), self.config.timeout
        )
        try:
            # Read Prism's HELLO first so transcript failures remain diagnosable.
            lines: list[str] = []
            while not lines or lines[-1] != "END":
                lines.append(await client.read_line())
            await client.send_bytes(b"RACP/2 HELLO\nPEER diagnostic bad-version\nEND\n", "RACP/2 HELLO ...")
            line = await client.read_line()
            if line != "ERR 0 unsupported_version":
                raise AssertionError(f"received {line!r}")
        finally:
            await client.close(orderly=False)
        return None

    async def _overlong_line(self) -> str:
        client = self._new_client()
        try:
            await client.connect()
            await client.send_bytes(b"X" * 16_385 + b"\n", "<16,385-byte overlong line>")
            try:
                line = await client.read_line()
            except PeerClosed:
                return "connection closed"
            if line != "ERR 0 line_too_long":
                raise AssertionError(f"received {line!r}")
            try:
                await client.read_line()
            except PeerClosed:
                return "ERR then connection closed"
            raise AssertionError("connection remained open after overlong line")
        finally:
            await client.close(orderly=False)
