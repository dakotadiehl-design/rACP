from __future__ import annotations

import asyncio

from acp.types import UUID_RE
from acp.ws import _tls_identity, connect_ws


def test_tls_identity_requires_acp_san_uuid() -> None:
    class FakeSSL:
        def __init__(self, cert):
            self._cert = cert

        def getpeercert(self):
            return self._cert

    nid = "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"
    cert = {
        "subjectAltName": (("DNS", "bridge.local"), ("URI", f"acp://{nid}")),
        "subject": ((("commonName", "should-not-win"),),),
    }
    assert _tls_identity(FakeSSL(cert)) == nid
    cn_only = {"subject": ((("commonName", nid),),)}
    assert _tls_identity(FakeSSL(cn_only)) is None
    bad = {"subjectAltName": (("URI", "acp://not-a-uuid"),)}
    assert _tls_identity(FakeSSL(bad)) is None
    assert UUID_RE.match(nid)


def test_connect_ws_closes_on_bad_handshake() -> None:
    async def body() -> None:
        server = await asyncio.start_server(
            lambda r, w: asyncio.create_task(_bad_upgrade(r, w)),
            "127.0.0.1",
            0,
        )
        host, port = server.sockets[0].getsockname()[:2]
        try:
            try:
                await connect_ws(f"ws://{host}:{port}/acp", allow_plaintext=True)
                raise AssertionError("expected handshake failure")
            except ConnectionError:
                pass
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(body())


async def _bad_upgrade(_reader, writer) -> None:
    await _reader.readuntil(b"\r\n\r\n")
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive\r\n\r\n")
    await writer.drain()
    writer.close()
