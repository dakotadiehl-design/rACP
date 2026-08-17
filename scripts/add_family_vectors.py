#!/usr/bin/env python3
"""Add one valid golden vector per remaining message family."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "src"))

from acp.codec import encode_cbor  # noqa: E402
from acp.envelope import Envelope  # noqa: E402
from acp.validate import validate_message  # noqa: E402

SRC = "0193f8d8-4c4e-7d8b-a2ab-000000000001"
DST = "0193f8d8-4c4e-7d8b-a2ab-000000000002"
SID = "0193f8d8-4c4e-7d8b-a2ab-000000000013"
TS = "2026-08-17T16:42:15.231Z"
SHA = "a" * 64


def mid(n: int) -> str:
    return f"0193f8d8-4c4e-7d8b-a2ab-{n:012d}"


def env(
    typ: str,
    payload: dict,
    qos: str = "reliable",
    seq: int | None = 1,
    dest: bool = True,
    n: int = 20,
) -> dict:
    data = {
        "acp": "1.2",
        "message_id": mid(n),
        "type": typ,
        "source": {"node_id": SRC},
        "timestamp_utc": TS,
        "qos": qos,
        "flags": [],
        "payload": payload,
    }
    if dest:
        data["destination"] = {"node_id": DST}
    if seq is not None:
        data["session_id"] = SID
        data["sequence"] = seq
    return data


VECTORS = [
    env("discovery.advertisement", {
        "node": {"node_id": SRC, "instance_id": DST, "role": "bridge", "name": "B"},
        "protocol": {"min": "1.0", "max": "1.2"},
        "endpoint_url": "ws://127.0.0.1:27421/acp",
        "capabilities_digest": "abcd",
        "security_mode": "trusted_lan",
    }, qos="best_effort", seq=None, dest=False, n=20),
    env("command.execute", {"name": "ping"}, dest=True, n=21),
    env("state.request", {"resources": ["bridge.blackout"]}, n=22),
    env("capability.list", {"capabilities": [{"id": "health.heartbeat", "version": "1.0"}]}, n=23),
    env("config.get", {"path": "bridge.outputs.dmx.0.universe"}, n=24),
    env("log.event", {"code": "boot", "severity": "info", "message": "up"}, qos="best_effort", n=25),
    env("telemetry.metric", {"name": "cpu_pct", "value": 1.5}, qos="latest", n=26),
    env("cue.go", {"idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-000000000099"}, n=27),
    env("song.select", {"song_id": "haywire"}, n=28),
    env("section.enter", {"section_id": "chorus_2"}, n=29),
    env("transport.play", {}, n=30),
    env("resource.offer", {
        "transfer_id": "0193f8d8-4c4e-7d8b-a2ab-000000000070",
        "asset": {"asset_id": "0193f8d8-4c4e-7d8b-a2ab-000000000071", "asset_type": "lyric.chart",
                  "revision": 1, "sha256": SHA, "size_bytes": 4},
        "locator": {"mode": "chunked"},
    }, n=31),
    env("lyric.client_ready", {
        "node_id": SRC, "device_id": DST,
        "supported_chart_types": ["chord_lyrics"],
    }, n=32),
    env("participant.identity", {"participant_id": "0193f8d8-4c4e-7d8b-a2ab-000000000080", "name": "Dakota"}, n=33),
    env("chart.metadata", {
        "asset_id": "0193f8d8-4c4e-7d8b-a2ab-000000000071",
        "asset_type": "lyric.chart",
        "song_id": "haywire",
        "revision": 1,
        "sha256": SHA,
        "chart_type": "chord_lyrics",
    }, n=34),
    env("asset.status", {
        "asset_id": "0193f8d8-4c4e-7d8b-a2ab-000000000071",
        "revision": 1,
        "state": "ready",
        "sha256": SHA,
    }, qos="latest", n=35),
    env("manifest.get", {"show_id": "0193f8d8-4c4e-7d8b-a2ab-000000000050", "revision": 42}, n=36),
    env("show.arm", {
        "show_id": "0193f8d8-4c4e-7d8b-a2ab-000000000050",
        "revision": 42,
        "manifest_sha256": SHA,
    }, n=37),
]


def main() -> None:
    manifest_path = ROOT / "vectors" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    known = {item["id"] for item in manifest["vectors"]}
    for data in VECTORS:
        typ = data["type"]
        validate_message(data)
        env_obj = Envelope.from_dict(data)
        (ROOT / "vectors" / "json" / f"{typ}.json").write_text(json.dumps(data, indent=2) + "\n")
        (ROOT / "vectors" / "cbor" / f"{typ}.cbor").write_bytes(encode_cbor(env_obj))
        if typ not in known:
            manifest["vectors"].append({
                "id": typ,
                "json": f"json/{typ}.json",
                "cbor": f"cbor/{typ}.cbor",
            })
            known.add(typ)
        print("ok", typ)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
