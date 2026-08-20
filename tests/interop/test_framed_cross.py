"""Cross-language framed-TCP session interop.

Required: --sdk rust|swift|rust-swift
Optional: --suite hello|session|remote|negative (default hello)
"""

from __future__ import annotations

import argparse
import asyncio
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from acp.codec import encode  # noqa: E402
from acp.envelope import make_envelope  # noqa: E402
from acp.framed import connect_framed, serve_framed  # noqa: E402
from acp.session import Session, SessionError, SessionState  # noqa: E402
from acp.testkit import default_caps, identity  # noqa: E402
from acp.types import Endpoint, QoS, Role, new_uuid  # noqa: E402

PROFILES = ["core", "remote", "aurora.remote.prism.v1"]
TID = "0193f8d8-4c4e-7d8b-a2ab-000000000070"
AID = "0193f8d8-4c4e-7d8b-a2ab-000000000071"
SHA = "a" * 64


def rust_bin() -> list[str]:
    built = ROOT / "rust" / "target" / "debug" / "examples" / "framed_hello"
    if built.is_file():
        return [str(built)]
    return [
        "cargo", "run", "--quiet", "--manifest-path", str(ROOT / "rust" / "Cargo.toml"),
        "-p", "acp-session", "--example", "framed_hello", "--",
    ]


def swift_bin() -> list[str]:
    built = ROOT / ".build" / "debug" / "acp-framed-hello"
    if built.is_file():
        return [str(built)]
    return ["swift", "run", "acp-framed-hello"]


def ensure_sdk(sdk: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    need_rust = sdk in {"rust", "rust-swift"}
    need_swift = sdk in {"swift", "rust-swift"}
    if need_rust:
        if shutil.which("cargo"):
            proc = subprocess.run(
                ["cargo", "build", "--manifest-path", str(ROOT / "rust" / "Cargo.toml"),
                 "-p", "acp-session", "--example", "framed_hello"],
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode != 0:
                raise SystemExit(f"failed to build rust framed_hello:\n{proc.stdout}\n{proc.stderr}")
        elif not (ROOT / "rust" / "target" / "debug" / "examples" / "framed_hello").is_file():
            raise SystemExit("required rust sdk not found")
        out["rust"] = rust_bin()
    if need_swift:
        if shutil.which("swift"):
            proc = subprocess.run(
                ["swift", "build", "--product", "acp-framed-hello"],
                cwd=ROOT,
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode != 0:
                raise SystemExit(f"failed to build swift acp-framed-hello:\n{proc.stdout}\n{proc.stderr}")
        elif not (ROOT / ".build" / "debug" / "acp-framed-hello").is_file():
            raise SystemExit("required swift sdk not found")
        out["swift"] = swift_bin()
    return out


def flags_for(encodings: list[str], suite: str) -> list[str]:
    extra = ["--remote"]
    if encodings == ["json"]:
        extra.append("--json")
    if suite in {"session", "negative"}:
        extra.append("--session")
    if suite == "remote":
        extra.extend(["--session", "--xfer"])
    return extra


async def respond(session: Session) -> None:
    async for env in session.subscribe():
        if env.type == "session.goodbye":
            return
        if env.type == "state.request":
            await session.send(make_envelope(
                type="state.snapshot", source=session.source(),
                destination=Endpoint(node_id=env.source.node_id),
                payload={"resources": []},
                correlation_id=env.correlation_id or env.message_id,
            ))
        elif env.type == "resource.offer":
            await session.send(make_envelope(
                type="resource.accept", source=session.source(),
                destination=Endpoint(node_id=env.source.node_id),
                payload={"transfer_id": env.payload["transfer_id"], "max_chunk_bytes": 1024},
                correlation_id=env.correlation_id or env.message_id,
            ))
        elif env.type == "resource.complete":
            await session.send(make_envelope(
                type="resource.transfer_result", source=session.source(),
                destination=Endpoint(node_id=env.source.node_id),
                payload={"transfer_id": env.payload["transfer_id"], "status": "verified"},
                correlation_id=env.correlation_id or env.message_id,
            ))
        elif env.type == "resource.activate":
            await session.send(make_envelope(
                type="resource.activation_result", source=session.source(),
                destination=Endpoint(node_id=env.source.node_id),
                payload={"transfer_id": env.payload["transfer_id"], "status": "applied"},
                correlation_id=env.correlation_id or env.message_id,
            ))
        elif env.type == "remote.control.invoke":
            await session.send(make_envelope(
                type="command.ack", source=session.source(),
                destination=Endpoint(node_id=env.source.node_id),
                payload={"status": "applied"},
                correlation_id=env.correlation_id or env.message_id,
            ))


async def run_session_client(client: Session, xfer: bool) -> None:
    dest = Endpoint(node_id=client.peer.node_id) if client.peer else None
    await client.send(make_envelope(
        type="health.heartbeat", source=client.source(), qos=QoS.LATEST,
        payload={"uptime_ms": 1, "status": "ok"},
    ))
    snap = await client.request(make_envelope(
        type="state.request", source=client.source(), destination=dest,
        payload={"resources": []},
    ), timeout=5)
    assert snap.type == "state.snapshot"
    if not xfer:
        return
    accept = await client.request(make_envelope(
        type="resource.offer", source=client.source(), destination=dest,
        payload={
            "transfer_id": TID,
            "asset": {"asset_id": AID, "asset_type": "lyric.chart", "revision": 1, "sha256": SHA, "size_bytes": 4},
            "locator": {"mode": "chunked"},
        },
    ), timeout=5)
    assert accept.type == "resource.accept"
    await client.send(make_envelope(
        type="resource.chunk", source=client.source(), destination=dest,
        payload={"transfer_id": TID, "offset": 0, "length": 4, "data": bytes([0x00, 0x01, 0xFF, 0xE0])},
    ))
    done = await client.request(make_envelope(
        type="resource.complete", source=client.source(), destination=dest,
        payload={"transfer_id": TID},
    ), timeout=5)
    assert done.type == "resource.transfer_result"
    act = await client.request(make_envelope(
        type="resource.activate", source=client.source(), destination=dest,
        payload={"transfer_id": TID, "idempotency_key": TID},
    ), timeout=5)
    assert act.type == "resource.activation_result"
    ack = await client.request(make_envelope(
        type="remote.control.invoke", source=client.source(), destination=dest,
        payload={"control_id": "cue_go", "invocation_id": TID, "interaction": "activate", "idempotency_key": TID},
    ), timeout=5)
    assert ack.type == "command.ack"


async def python_server(port_holder: dict, encodings: list[str], suite: str, silent: bool = False) -> None:
    finished = asyncio.Event()

    async def on_client(transport) -> None:
        try:
            server = Session(
                transport, identity(Role.CONDUCTOR, "py-server"), is_server=True,
                allow_plaintext=True, encodings=encodings, profiles=PROFILES,
            )
            await server.handshake(default_caps())
            assert server.state == SessionState.ESTABLISHED
            if silent:
                await asyncio.sleep(3)
                return
            if suite == "hello":
                await server.goodbye()
                return
            await respond(server)
            await server.goodbye()
        finally:
            finished.set()

    srv = await serve_framed("127.0.0.1", 0, on_client)
    async with srv:
        port_holder["port"] = srv.sockets[0].getsockname()[1]
        port_holder["ready"].set()
        await asyncio.wait_for(finished.wait(), timeout=45)


async def python_client(host: str, port: int, encodings: list[str], suite: str) -> str:
    client = Session(
        await connect_framed(host, port), identity(Role.REMOTE, "py-client"),
        is_server=False, allow_plaintext=True, encodings=encodings, profiles=PROFILES,
    )
    await client.handshake(default_caps())
    assert client.state == SessionState.ESTABLISHED
    assert client.session_version == "1.2"
    assert client.encoding in encodings
    assert client.peer is not None
    if suite in {"session", "remote"}:
        await run_session_client(client, xfer=suite == "remote")
    await client.goodbye()
    return client.session_id or ""


def wait_listening(proc: subprocess.Popen, timeout: float = 15.0) -> str:
    deadline = time.time() + timeout
    assert proc.stdout is not None
    while time.time() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"peer exited early: {err}")
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if not ready:
            continue
        line = proc.stdout.readline()
        if "listening" in line:
            return line
    raise TimeoutError("peer did not start listening")


def parse_port(line: str) -> int:
    port = line.strip().rsplit(":", 1)[-1].split("]")[-1]
    return int("".join(ch for ch in port if ch.isdigit()))


async def run_proc(cmd: list[str], timeout: float = 45) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out_b.decode(), err_b.decode()
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def python_server_foreign_client(cmd: list[str], encodings: list[str], suite: str) -> None:
    ready = asyncio.Event()
    holder: dict = {"ready": ready}
    silent = suite == "negative-timeout"
    server_task = asyncio.create_task(python_server(holder, encodings, "hello" if silent else suite, silent=silent))
    await ready.wait()
    extra = flags_for(encodings, "session" if silent else suite)
    code, out, err = await run_proc([*cmd, "client", "127.0.0.1", str(holder["port"]), *extra])
    try:
        if silent:
            if code == 0:
                raise RuntimeError(f"expected timeout, client succeeded:\n{out}\n{err}")
            return
        if code != 0:
            raise RuntimeError(f"client failed ({code}): {out}\n{err}")
        assert "ok client" in out, out
        await asyncio.wait_for(server_task, timeout=15)
    finally:
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except (asyncio.CancelledError, Exception):
                pass


def foreign_server_python_client(cmd: list[str], encodings: list[str], suite: str) -> None:
    extra = flags_for(encodings, suite)
    proc = subprocess.Popen(
        [*cmd, "server", "127.0.0.1", "0", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        port = parse_port(wait_listening(proc))
        sid = asyncio.run(python_client("127.0.0.1", port, encodings, suite))
        assert sid
        out, err = proc.communicate(timeout=45)
        if proc.returncode != 0:
            raise RuntimeError(f"server failed ({proc.returncode}): {out}\n{err}")
        if "ok server" not in (out or ""):
            raise RuntimeError(f"server missing ok banner: {out}\n{err}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except Exception:
                proc.kill()
                proc.wait()


async def python_negative_against(host: str, port: int, encodings: list[str]) -> None:
    client = Session(
        await connect_framed(host, port), identity(Role.REMOTE, "neg-client"),
        is_server=False, allow_plaintext=True, encodings=encodings, profiles=PROFILES,
    )
    await client.handshake(default_caps())
    text = client.encoding == "json"
    try:
        await client.transport.send(b"{not-json", text=True)
        await client.transport.send(b"\xff\x00bad", text=False)
        spoof = make_envelope(
            type="health.heartbeat", source=Endpoint(node_id=new_uuid()), qos=QoS.LATEST,
            payload={"uptime_ms": 1, "status": "ok"},
        ).with_session(client.session_id, 99)
        await client.transport.send(encode(spoof, client.encoding), text=text)
    except (ConnectionResetError, ConnectionError, BrokenPipeError):
        pass
    start = time.time()
    try:
        await asyncio.wait_for(client.request(make_envelope(
            type="state.request", source=client.source(),
            destination=Endpoint(node_id=client.peer.node_id) if client.peer else None,
            payload={"resources": []},
        ), timeout=1.5), timeout=3)
    except (SessionError, TimeoutError, ConnectionError, Exception):
        pass
    assert time.time() - start < 5
    try:
        await client.transport.close()
    except Exception:
        pass
    deadline = time.time() + 2
    while client.state == SessionState.ESTABLISHED and time.time() < deadline:
        await asyncio.sleep(0.02)
    assert client.state in {SessionState.FAILED, SessionState.CLOSED}


def foreign_server_negative(cmd: list[str], encodings: list[str]) -> None:
    extra = flags_for(encodings, "session")
    proc = subprocess.Popen(
        [*cmd, "server", "127.0.0.1", "0", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        port = parse_port(wait_listening(proc))
        asyncio.run(python_negative_against("127.0.0.1", port, encodings))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except Exception:
                proc.kill()
                proc.wait()


def foreign_pair(server_cmd: list[str], client_cmd: list[str], encodings: list[str], suite: str) -> None:
    extra = flags_for(encodings, suite)
    proc = subprocess.Popen(
        [*server_cmd, "server", "127.0.0.1", "0", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        port = parse_port(wait_listening(proc))
        code, out, err = asyncio.run(run_proc([*client_cmd, "client", "127.0.0.1", str(port), *extra]))
        if code != 0:
            raise RuntimeError(f"cross client failed: {out}\n{err}")
        assert "ok client" in out
        sout, serr = proc.communicate(timeout=45)
        if proc.returncode != 0:
            raise RuntimeError(f"cross server failed ({proc.returncode}): {sout}\n{serr}")
        if "ok server" not in (sout or ""):
            raise RuntimeError(f"cross server missing ok banner: {sout}\n{serr}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except Exception:
                proc.kill()
                proc.wait()


def run_suite(sdk: str, suite: str) -> None:
    bins = ensure_sdk(sdk)
    encodings_list = [(["cbor", "json"], "cbor"), (["json"], "json")]
    if sdk == "rust-swift":
        for encodings, label in encodings_list:
            print("rust-server swift-client", label, suite, flush=True)
            foreign_pair(bins["rust"], bins["swift"], encodings, suite)
            print("swift-server rust-client", label, suite, flush=True)
            foreign_pair(bins["swift"], bins["rust"], encodings, suite)
        print(f"framed {sdk} {suite} ok", flush=True)
        return
    name = sdk
    cmd = bins[sdk]
    for encodings, label in encodings_list:
        print("python-server", name, label, suite, flush=True)
        if suite == "negative":
            asyncio.run(python_server_foreign_client(cmd, encodings, "negative-timeout"))
            print(name + "-server", "python-negative", label, flush=True)
            foreign_server_negative(cmd, encodings)
        else:
            asyncio.run(python_server_foreign_client(cmd, encodings, suite))
            print(name + "-server", "python", label, suite, flush=True)
            foreign_server_python_client(cmd, encodings, suite)
    print(f"framed {sdk} {suite} ok", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True, choices=("rust", "swift", "rust-swift"))
    parser.add_argument("--suite", default="hello", choices=("hello", "session", "remote", "negative"))
    args = parser.parse_args()
    run_suite(args.sdk, args.suite)


if __name__ == "__main__":
    main()
