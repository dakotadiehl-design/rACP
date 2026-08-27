"""Strict rACP v1 line grammar and bounded incremental framing."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, TypeAlias

MAX_LINE_BYTES = 16_384
MAX_SAFE_INTEGER = 9_007_199_254_740_991
NAME_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")
ID_RE = re.compile(r"[1-9][0-9]{0,15}\Z")
NONCE_RE = ID_RE


class ProtocolError(ValueError):
    def __init__(self, code: str, *, fatal: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.fatal = fatal


@dataclass(frozen=True)
class Command:
    request_id: int
    name: str
    value: Any = None
    has_value: bool = False


@dataclass(frozen=True)
class Ack:
    request_id: int


@dataclass(frozen=True)
class Error:
    request_id: int
    code: str


@dataclass(frozen=True)
class State:
    name: str
    revision: int
    value: Any


@dataclass(frozen=True)
class Subscribe:
    request_id: int
    name: str


@dataclass(frozen=True)
class Unsubscribe:
    request_id: int
    name: str


@dataclass(frozen=True)
class Ping:
    nonce: int


@dataclass(frozen=True)
class Pong:
    nonce: int


@dataclass(frozen=True)
class Bye:
    pass


Message: TypeAlias = Command | Ack | Error | State | Subscribe | Unsubscribe | Ping | Pong | Bye


def _request_id(token: str, *, allow_zero: bool = False) -> int:
    if allow_zero and token == "0":
        return 0
    if not ID_RE.fullmatch(token):
        raise ProtocolError("malformed_message")
    value = int(token)
    if value > MAX_SAFE_INTEGER:
        raise ProtocolError("malformed_message")
    return value


def _name(token: str) -> str:
    if len(token.encode("ascii", "ignore")) != len(token) or len(token) > 128 or not NAME_RE.fullmatch(token):
        raise ProtocolError("malformed_message")
    return token


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("invalid_value")
        result[key] = value
    return result


def _validate_value(value: Any) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ProtocolError("invalid_value")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ProtocolError("invalid_value")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProtocolError("invalid_value")
        return
    if isinstance(value, list):
        for item in value:
            _validate_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("invalid_value")
            _validate_value(key)
            _validate_value(item)
        return
    raise ProtocolError("invalid_value")


def decode_value(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ProtocolError("invalid_value")),
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ProtocolError("invalid_value") from exc
    _validate_value(value)
    return value


def encode_value(value: Any) -> str:
    _validate_value(value)
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid_value") from exc


def parse_message(line: str) -> Message:
    if not line or line.startswith(" ") or line.endswith(" "):
        raise ProtocolError("malformed_message")
    if any(ord(char) < 0x20 for char in line):
        raise ProtocolError("malformed_message", fatal=True)
    head = line.split(" ", 3)
    verb = head[0]
    if verb == "CMD" and len(head) in (3, 4):
        has_value = len(head) == 4
        return Command(
            _request_id(head[1]),
            _name(head[2]),
            decode_value(head[3]) if has_value else None,
            has_value,
        )
    if verb == "ACK" and len(head) == 2:
        return Ack(_request_id(head[1]))
    if verb == "ERR" and len(head) == 3:
        return Error(_request_id(head[1], allow_zero=True), _name(head[2]))
    if verb == "STATE" and len(head) == 4:
        revision = _request_id(head[2], allow_zero=True)
        return State(_name(head[1]), revision, decode_value(head[3]))
    if verb == "SUB" and len(head) == 3:
        return Subscribe(_request_id(head[1]), _name(head[2]))
    if verb == "UNSUB" and len(head) == 3:
        return Unsubscribe(_request_id(head[1]), _name(head[2]))
    if verb == "PING" and len(head) == 2:
        return Ping(_request_id(head[1]))
    if verb == "PONG" and len(head) == 2:
        return Pong(_request_id(head[1]))
    if verb == "BYE" and len(head) == 1:
        return Bye()
    raise ProtocolError("malformed_message")


def encode_message(message: Message) -> str:
    if isinstance(message, Command):
        base = f"CMD {_request_id(str(message.request_id))} {_name(message.name)}"
        return f"{base} {encode_value(message.value)}" if message.has_value else base
    if isinstance(message, Ack):
        return f"ACK {_request_id(str(message.request_id))}"
    if isinstance(message, Error):
        return f"ERR {_request_id(str(message.request_id), allow_zero=True)} {_name(message.code)}"
    if isinstance(message, State):
        revision = _request_id(str(message.revision), allow_zero=True)
        return f"STATE {_name(message.name)} {revision} {encode_value(message.value)}"
    if isinstance(message, Subscribe):
        return f"SUB {_request_id(str(message.request_id))} {_name(message.name)}"
    if isinstance(message, Unsubscribe):
        return f"UNSUB {_request_id(str(message.request_id))} {_name(message.name)}"
    if isinstance(message, Ping):
        return f"PING {_request_id(str(message.nonce))}"
    if isinstance(message, Pong):
        return f"PONG {_request_id(str(message.nonce))}"
    if isinstance(message, Bye):
        return "BYE"
    raise TypeError(f"unsupported message: {type(message)!r}")


class LineDecoder:
    """Incremental line decoder that never buffers more than one maximum line."""

    def __init__(self, maximum: int = MAX_LINE_BYTES) -> None:
        if maximum < 1:
            raise ValueError("maximum must be positive")
        self.maximum = maximum
        self._buffer = bytearray()
        self._discarding = False

    def feed(self, data: bytes) -> list[str]:
        lines: list[str] = []
        for byte in data:
            if self._discarding:
                if byte == 0x0A:
                    self._discarding = False
                continue
            if byte == 0x0A:
                raw = bytes(self._buffer)
                self._buffer.clear()
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                try:
                    line = raw.decode("utf-8", "strict")
                except UnicodeDecodeError as exc:
                    raise ProtocolError("malformed_message", fatal=True) from exc
                if not line:
                    raise ProtocolError("malformed_message")
                lines.append(line)
            else:
                self._buffer.append(byte)
                # A maximum-length line may have one additional CR as part of
                # an accepted CRLF terminator. Any other additional byte is an
                # overlong line.
                overlong = len(self._buffer) > self.maximum
                possible_crlf = len(self._buffer) == self.maximum + 1 and byte == 0x0D
                if overlong and not possible_crlf:
                    self._buffer.clear()
                    self._discarding = True
                    raise ProtocolError("line_too_long", fatal=True)
        return lines

    def eof(self) -> None:
        self._buffer.clear()
        self._discarding = False
