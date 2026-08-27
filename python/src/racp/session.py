"""Transport-independent rACP v1 session semantics."""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .protocol import (
    MAX_LINE_BYTES,
    Ack,
    Bye,
    Command,
    Error,
    Message,
    Ping,
    Pong,
    ProtocolError,
    State,
    Subscribe,
    Unsubscribe,
    encode_message,
    parse_message,
)

PEER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
CAP_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")


@dataclass(frozen=True)
class Hello:
    peer_type: str
    peer_id: str
    capabilities: tuple[str, ...] = ()

    def lines(self) -> list[str]:
        _validate_peer(self.peer_type)
        _validate_peer(self.peer_id)
        caps = tuple(sorted(self.capabilities))
        if caps != self.capabilities or len(set(caps)) != len(caps):
            raise ValueError("capabilities must be sorted and unique")
        for cap in caps:
            _validate_cap(cap)
        return ["RACP/1 HELLO", f"PEER {self.peer_type} {self.peer_id}", *(f"CAP {cap}" for cap in caps), "END"]


class SessionState(Enum):
    HELLO = "hello"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


class SessionClosed(RuntimeError):
    pass


CommandHandler = Callable[[Command], str | None]


def _validate_peer(value: str) -> None:
    if not PEER_RE.fullmatch(value):
        raise ValueError("invalid peer token")


def _validate_cap(value: str) -> None:
    if len(value) > 128 or not CAP_RE.fullmatch(value):
        raise ValueError("invalid capability")


class Session:
    def __init__(
        self,
        local: Hello,
        handler: CommandHandler | None = None,
        *,
        ledger_size: int = 1024,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        if ledger_size < 1:
            raise ValueError("ledger_size must be positive")
        local.lines()
        self.local = local
        self.peer: Hello | None = None
        self.state = SessionState.HELLO
        self.handler = handler or (lambda _command: None)
        self.ledger_size = ledger_size
        self._ledger: OrderedDict[int, tuple[Command, Ack | Error]] = OrderedDict()
        self._hello_lines: list[str] = []
        self.subscriptions: set[str] = set()
        self.state_revisions: dict[str, int] = {}
        self.malformed_count = 0
        self.now = now
        self.last_received = now()
        self.outstanding_ping: tuple[int, float] | None = None

    def hello_bytes(self) -> bytes:
        return ("\n".join(self.local.lines()) + "\n").encode()

    def receive_line(self, line: str) -> list[Message]:
        if self.state in (SessionState.CLOSING, SessionState.CLOSED):
            raise SessionClosed(self.state.value)
        self.last_received = self.now()
        if self.state is SessionState.HELLO:
            self._hello_lines.append(line)
            if len(self._hello_lines) > 1027:
                raise ProtocolError("malformed_message", fatal=True)
            if line == "END":
                self.peer = _parse_hello(self._hello_lines)
                self._hello_lines.clear()
                self.state = SessionState.ESTABLISHED
            return []
        try:
            message = parse_message(line)
        except ProtocolError as exc:
            self.malformed_count += 1
            if self.malformed_count >= 3:
                exc.fatal = True
            raise
        return self.receive(message)

    def receive(self, message: Message) -> list[Message]:
        if self.state is not SessionState.ESTABLISHED:
            raise ProtocolError("handshake_required", fatal=True)
        if isinstance(message, Ping):
            return [Pong(message.nonce)]
        if isinstance(message, Pong):
            if self.outstanding_ping and self.outstanding_ping[0] == message.nonce:
                self.outstanding_ping = None
            return []
        if isinstance(message, Bye):
            self.state = SessionState.CLOSING
            return []
        if isinstance(message, Command):
            return [self._command(message)]
        if isinstance(message, Subscribe):
            return [self._subscribe(message)]
        if isinstance(message, Unsubscribe):
            self.subscriptions.discard(message.name)
            return [Ack(message.request_id)]
        if isinstance(message, State):
            previous = self.state_revisions.get(message.name, -1)
            if message.revision > previous:
                self.state_revisions[message.name] = message.revision
            return []
        return []

    def _command(self, command: Command) -> Ack | Error:
        previous = self._ledger.get(command.request_id)
        if previous is not None:
            return previous[1] if previous[0] == command else Error(command.request_id, "request_id_conflict")
        assert self.peer is not None
        if command.name not in self.local.capabilities:
            response: Ack | Error = Error(command.request_id, "unsupported_capability")
        else:
            try:
                code = self.handler(command)
                if code:
                    try:
                        _validate_cap(code)
                    except ValueError:
                        code = "application_error"
                response = Error(command.request_id, code) if code else Ack(command.request_id)
            except Exception:
                response = Error(command.request_id, "application_error")
        self._ledger[command.request_id] = (command, response)
        while len(self._ledger) > self.ledger_size:
            self._ledger.popitem(last=False)
        return response

    def _subscribe(self, message: Subscribe) -> Ack | Error:
        if "state.subscribe" not in self.local.capabilities or message.name not in self.local.capabilities:
            return Error(message.request_id, "unsupported_capability")
        self.subscriptions.add(message.name)
        return Ack(message.request_id)

    def heartbeat(self, nonce: int) -> list[Message]:
        current = self.now()
        if self.outstanding_ping is not None:
            if current - self.outstanding_ping[1] >= 5:
                self.state = SessionState.CLOSED
                raise SessionClosed("heartbeat_timeout")
            return []
        if current - self.last_received >= 10:
            self.outstanding_ping = (nonce, current)
            return [Ping(nonce)]
        return []

    @staticmethod
    def encode(messages: list[Message]) -> bytes:
        output = bytearray()
        for message in messages:
            line = encode_message(message).encode("utf-8")
            if len(line) > MAX_LINE_BYTES:
                raise ProtocolError("line_too_long", fatal=True)
            output.extend(line)
            output.append(0x0A)
        return bytes(output)


def _parse_hello(lines: list[str]) -> Hello:
    if len(lines) < 3 or lines[0] != "RACP/1 HELLO" or lines[-1] != "END":
        code = "unsupported_version" if lines and lines[0].startswith("RACP/") else "malformed_message"
        raise ProtocolError(code, fatal=True)
    peer_parts = lines[1].split(" ")
    if len(peer_parts) != 3 or peer_parts[0] != "PEER":
        raise ProtocolError("malformed_message", fatal=True)
    try:
        _validate_peer(peer_parts[1])
        _validate_peer(peer_parts[2])
    except ValueError as exc:
        raise ProtocolError("malformed_message", fatal=True) from exc
    caps: list[str] = []
    for line in lines[2:-1]:
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] != "CAP":
            raise ProtocolError("malformed_message", fatal=True)
        try:
            _validate_cap(parts[1])
        except ValueError as exc:
            raise ProtocolError("malformed_message", fatal=True) from exc
        caps.append(parts[1])
    if caps != sorted(set(caps)):
        raise ProtocolError("malformed_message", fatal=True)
    return Hello(peer_parts[1], peer_parts[2], tuple(caps))
