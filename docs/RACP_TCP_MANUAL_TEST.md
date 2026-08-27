# Manual rACP TCP test

The Python reference exposes `serve_tcp()` and `connect_tcp()` around the same
transport-independent `Session`. The following starts a minimal endpoint without
installing dependencies:

```sh
cd python
PYTHONPATH=src python3 -c '
import asyncio
from racp import Hello, Session, serve_tcp

async def main():
    server = await serve_tcp(
        "127.0.0.1", 9000,
        lambda: Session(
            Hello("device", "demo", ("cue.go",)),
            lambda command: print("accepted", command, flush=True) or None,
        ),
    )
    async with server:
        await server.serve_forever()

asyncio.run(main())
'
```

In a second terminal:

```sh
nc 127.0.0.1 9000
```

The server immediately prints its HELLO. Enter:

```text
RACP/1 HELLO
PEER diagnostic laptop
CAP cue.go
END
CMD 1 cue.go
PING 2
BYE
```

The expected terminal responses include `ACK 1` and `PONG 2`. Use a disposable
test endpoint: plain TCP rACP authenticates nobody, and a reachable peer can attempt
every advertised command. Never expose this diagnostic server on an untrusted network.
