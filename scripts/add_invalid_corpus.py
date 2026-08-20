#!/usr/bin/env python3
"""Write one invalid envelope per schema family for fail-closed codec tests."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "invalid"
SRC = "0193f8d8-4c4e-7d8b-a2ab-000000000001"
TS = "2026-08-17T16:42:15.231Z"


def env(typ: str, payload: dict, **extra) -> dict:
    data = {
        "acp": "1.2",
        "message_id": "0193f8d8-4c4e-7d8b-a2ab-000000000002",
        "type": typ,
        "source": {"node_id": SRC},
        "timestamp_utc": TS,
        "qos": extra.pop("qos", "reliable"),
        "flags": [],
        "payload": payload,
        "session_id": "0193f8d8-4c4e-7d8b-a2ab-000000000013",
        "sequence": 1,
    }
    data.update(extra)
    return {k: v for k, v in data.items() if v is not None}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cases = {
        "session.hello-missing-node": (
            env("session.hello", {"protocol": {"min": "1.0", "max": "1.2"}}, sequence=None, session_id=None),
            "invalid_type",
        ),
        "discovery.query-bad-role": (
            env("discovery.query", {"role_filter": [123]}, qos="best_effort", sequence=None, session_id=None),
            "invalid_type",
        ),
        "state.request-bad-resources": (
            env("state.request", {"resources": [1]}),
            "invalid_type",
        ),
        "health.heartbeat-bad-status": (
            env("health.heartbeat", {"uptime_ms": 1, "status": "explode"}, qos="latest"),
            "invalid_type",
        ),
        "capability.list-not-array": (
            env("capability.list", {"capabilities": "nope"}),
            "invalid_type",
        ),
        "command.execute-missing-name": (
            env("command.execute", {"args": {}}),
            "invalid_type",
        ),
        "config.get-bad-path": (
            env("config.get", {"paths": [False]}),
            "invalid_type",
        ),
        "error.report-missing-code": (
            env("error.report", {"message": "x", "category": "protocol", "severity": "error", "retryable": False}),
            "invalid_type",
        ),
        "resource.chunk-missing-data": (
            env("resource.chunk", {"transfer_id": SRC, "offset": 0, "length": 1}),
            "invalid_type",
        ),
        "remote.control.invoke-missing-control": (
            env(
                "remote.control.invoke",
                {"invocation_id": SRC, "interaction": "activate", "idempotency_key": SRC},
            ),
            "invalid_type",
        ),
        "show.load-missing-show-id": (
            env("show.load", {"revision": 1}),
            "invalid_type",
        ),
        "song.select-missing-song": (
            env("song.select", {"show_id": SRC}),
            "invalid_type",
        ),
        "section.enter-missing-section": (
            env("section.enter", {"song_id": "haywire"}),
            "invalid_type",
        ),
        "cue.go-bad-key": (
            env("cue.go", {"idempotency_key": "not-a-uuid"}),
            "invalid_type",
        ),
        "transport.play-bad-key": (
            env("transport.play", {"idempotency_key": "not-a-uuid"}),
            "invalid_type",
        ),
        "telemetry.metric-missing-name": (
            env("telemetry.metric", {"value": 1}, qos="latest"),
            "invalid_type",
        ),
        "asset.status-missing-asset": (
            env("asset.status", {"status": "ready"}),
            "invalid_type",
        ),
        "chart.catalog-not-array": (
            env("chart.catalog", {"charts": "nope"}),
            "invalid_type",
        ),
        "lyric.ready-missing-participant": (
            env("lyric.ready", {"ready": True, "status": "ready"}),
            "invalid_type",
        ),
        "participant.identity-missing-id": (
            env("participant.identity", {"name": "pad"}),
            "invalid_type",
        ),
        "log.event-missing-message": (
            env("log.event", {"level": "info"}, qos="best_effort"),
            "invalid_type",
        ),
        "bridge.blackout-missing-state": (
            env("bridge.blackout", {"idempotency_key": SRC}),
            "invalid_type",
        ),
        "manifest.get-missing-show": (
            env("manifest.get", {"revision": 1}),
            "invalid_type",
        ),
        "unknown-type": (
            env("x.evil.shell", {}),
            "unsupported_message",
        ),
    }
    manifest = []
    for name, (body, code) in cases.items():
        path = OUT / f"{name}.json"
        path.write_text(json.dumps(body, indent=2) + "\n")
        manifest.append({"id": name, "json": f"invalid/{name}.json", "error": code})
    (OUT / "manifest.json").write_text(json.dumps({"vectors": manifest}, indent=2) + "\n")
    print(f"wrote {len(manifest)} invalid vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
