"""Bounded RFC 6455 WebSocket transport (stdlib only)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct
from urllib.parse import urlparse

from .constants import limits as profile_limits
from .session import Transport
from .types import UUID_RE

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEADER_BYTES = 8192
MAX_CONTROL_PAYLOAD = 125


def _accept_key(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _header_has_token(value: str, token: str) -> bool:
    return token.lower() in [part.strip().lower() for part in value.split(",")]


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    try:
        header = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError as exc:
        raise ConnectionError("http headers too large") from exc
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("eof during http upgrade") from exc
    if len(header) > MAX_HEADER_BYTES:
        raise ConnectionError("http headers too large")
    return header


async def _read_frame(
    reader: asyncio.StreamReader,
    *,
    expect_mask: bool,
    max_payload: int,
) -> tuple[int, bytes, bool]:
    header = await reader.readexactly(2)
    fin = (header[0] & 0x80) != 0
    rsv = header[0] & 0x70
    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    length = header[1] & 0x7F
    if rsv:
        raise ConnectionError("rsv bits must be zero")
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
        if length < 126:
            raise ConnectionError("non-minimal length")
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
        if length < 65536:
            raise ConnectionError("non-minimal length")
    if opcode in {0x8, 0x9, 0xA}:
        if not fin or length > MAX_CONTROL_PAYLOAD:
            raise ConnectionError("invalid control frame")
    elif opcode not in {0x1, 0x2}:
        raise ConnectionError("unsupported opcode")
    if not fin:
        raise ConnectionError("fragmentation is not supported")
    if length > max_payload:
        raise ConnectionError("frame exceeds ACP maximum")
    if expect_mask and not masked:
        raise ConnectionError("client frames must be masked")
    if (not expect_mask) and masked:
        raise ConnectionError("server frames must not be masked")
    mask = await reader.readexactly(4) if masked else b""
    raw = await reader.readexactly(length)
    if masked:
        raw = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
    return opcode, raw, fin


def _write_frame(opcode: int, payload: bytes, *, mask: bool) -> bytes:
    header = bytearray()
    header.append(0x80 | opcode)
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))
    if mask:
        key = os.urandom(4)
        header.extend(key)
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + payload


class WsTransport(Transport):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        client: bool,
        max_payload: int | None = None,
        peer_identity: str | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.client = client
        self.max_payload = max_payload or profile_limits()["max_message_bytes"] + 32
        self.peer_identity = peer_identity
        self._closed = False

    async def send(self, data: bytes, *, text: bool) -> None:
        if len(data) > self.max_payload:
            raise ConnectionError("payload exceeds ACP maximum")
        opcode = 0x1 if text else 0x2
        self.writer.write(_write_frame(opcode, data, mask=self.client))
        await self.writer.drain()

    async def recv(self) -> tuple[bytes, bool]:
        while True:
            opcode, payload, _ = await _read_frame(
                self.reader, expect_mask=self.client is False, max_payload=self.max_payload
            )
            if opcode == 0x8:
                self._closed = True
                raise ConnectionError("ws closed")
            if opcode == 0x9:
                self.writer.write(_write_frame(0xA, payload, mask=self.client))
                await self.writer.drain()
                continue
            if opcode == 0xA:
                continue
            return payload, opcode == 0x1

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(_write_frame(0x8, b"", mask=self.client))
            await self.writer.drain()
        except Exception:  # noqa: BLE001
            pass
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _tls_identity(ssl_object: ssl.SSLObject | None) -> str | None:
    if ssl_object is None:
        return None
    cert = ssl_object.getpeercert()
    if not cert:
        return None
    sans = cert.get("subjectAltName") or ()
    if isinstance(sans, (list, tuple)):
        for item in sans:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            type_, value = item
            if type_ != "URI" or not isinstance(value, str) or not value.startswith("acp://"):
                continue
            node = value.split("acp://", 1)[1].rstrip("/").split("/")[-1].lower()
            if UUID_RE.match(node):
                return node
    return None


async def connect_ws(
    url: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    allow_plaintext: bool = False,
) -> WsTransport:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    scheme = (parsed.scheme or "ws").lower()
    if scheme == "wss":
        ctx = ssl_context or ssl.create_default_context()
        port = parsed.port or 443
        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    elif scheme == "ws":
        if not allow_plaintext:
            raise ConnectionError("plaintext ws requires allow_plaintext=True")
        port = parsed.port or 80
        reader, writer = await asyncio.open_connection(host, port)
    else:
        raise ConnectionError(f"unsupported url scheme {scheme}")
    path = parsed.path or "/"
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    writer.write(req.encode("ascii"))
    await writer.drain()
    try:
        header = await _read_headers(reader)
        lines = header.decode("iso-8859-1").split("\r\n")
        status = lines[0]
        parts = status.split()
        if len(parts) < 2 or parts[0] != "HTTP/1.1" or parts[1] != "101":
            raise ConnectionError(f"websocket handshake failed: {status!r}")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        if headers.get("upgrade", "").lower() != "websocket":
            raise ConnectionError("missing Upgrade: websocket")
        if not _header_has_token(headers.get("connection", ""), "upgrade"):
            raise ConnectionError("missing Connection: Upgrade")
        if headers.get("sec-websocket-accept") != _accept_key(key):
            raise ConnectionError("invalid Sec-WebSocket-Accept")
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        raise
    identity = _tls_identity(writer.get_extra_info("ssl_object"))
    return WsTransport(reader, writer, client=True, peer_identity=identity)


async def serve_ws(
    host: str,
    port: int,
    handler,
    *,
    ssl_context: ssl.SSLContext | None = None,
    allow_plaintext: bool = False,
    path: str = "/acp",
) -> asyncio.AbstractServer:
    if ssl_context is None and not allow_plaintext:
        raise ConnectionError("plaintext server requires allow_plaintext=True")

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            header = await _read_headers(reader)
            lines = header.decode("iso-8859-1").split("\r\n")
            request = lines[0].split()
            if len(request) < 3 or request[0] != "GET" or request[2] != "HTTP/1.1":
                raise ConnectionError("invalid request line")
            if request[1] != path:
                raise ConnectionError("wrong path")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()
            if headers.get("upgrade", "").lower() != "websocket":
                raise ConnectionError("missing upgrade")
            if not _header_has_token(headers.get("connection", ""), "upgrade"):
                raise ConnectionError("missing connection upgrade")
            if headers.get("sec-websocket-version") != "13":
                raise ConnectionError("unsupported websocket version")
            key = headers.get("sec-websocket-key")
            if not key:
                raise ConnectionError("missing key")
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {_accept_key(key)}\r\n"
                "\r\n"
            )
            writer.write(resp.encode("ascii"))
            await writer.drain()
            identity = _tls_identity(writer.get_extra_info("ssl_object"))
            transport = WsTransport(reader, writer, client=False, peer_identity=identity)
            await handler(transport)
        except Exception:  # noqa: BLE001
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                return

    return await asyncio.start_server(_client, host, port, ssl=ssl_context)
