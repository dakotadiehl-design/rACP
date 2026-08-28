"""Disposable reference-backed Prism stand-in for testing the harness itself."""

from __future__ import annotations

from racp import Command, Hello, Session, serve_tcp


class FakePrism:
    def __init__(self) -> None:
        self.commands: list[Command] = []
        self.server = None
        self.port = 0

    async def start(self) -> None:
        self.server = await serve_tcp(
            "127.0.0.1",
            0,
            lambda: Session(
                Hello("device", "fake-prism", ("cue.go",)),
                lambda command: self.commands.append(command) or None,
            ),
            hello_timeout=0.5,
            write_timeout=0.5,
        )
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()

