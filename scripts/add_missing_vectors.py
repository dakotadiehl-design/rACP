#!/usr/bin/env python3
"""Add one valid golden vector for every registry message that lacks one."""

from __future__ import annotations

import base64
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
SHOW = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
TID = "0193f8d8-4c4e-7d8b-a2ab-000000000070"
AID = "0193f8d8-4c4e-7d8b-a2ab-000000000071"
PID = "0193f8d8-4c4e-7d8b-a2ab-000000000080"
KEY = "0193f8d8-4c4e-7d8b-a2ab-000000000099"
ASSET = {
    "asset_id": AID,
    "asset_type": "lyric.chart",
    "revision": 1,
    "sha256": SHA,
    "size_bytes": 4,
}
CHUNK = bytes([0x00, 0x01, 0xFF, 0xE0])
ERR = {
    "code": "not_found",
    "category": "not_found",
    "severity": "error",
    "message": "missing",
    "retryable": False,
}


def mid(n: int) -> str:
    return f"0193f8d8-4c4e-7d8b-a2ab-{n:012d}"


def env(
    typ: str,
    payload: dict,
    qos: str = "reliable",
    seq: int | None = 1,
    dest: bool = True,
    n: int = 100,
    extra: dict | None = None,
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
    if extra:
        data.update(extra)
    return data


def payloads() -> dict[str, dict]:
    chart = {
        "asset_id": AID,
        "asset_type": "lyric.chart",
        "song_id": "haywire",
        "revision": 1,
        "sha256": SHA,
        "chart_type": "chord_lyrics",
    }
    assignment = {
        "show_id": SHOW,
        "song_id": "haywire",
        "participant_id": PID,
        "device_id": DST,
        "chart": {"asset_id": AID, "revision": 1, "sha256": SHA},
        "reason": "explicit_assignment",
    }
    return {
        "session.goodbye": {"reason": "shutdown"},
        "discovery.query": {"role_filter": ["bridge"]},
        "state.snapshot": {
            "resources": [{
                "resource": "cue.current",
                "revision": 1,
                "owner": {"node_id": SRC},
                "value": {"cue_id": "cue_1"},
                "confidence": "confirmed",
            }],
        },
        "health.warning": {
            "code": "hot",
            "severity": "warning",
            "message": "warm",
            "first_seen": TS,
            "last_seen": TS,
            "count": 1,
        },
        "health.snapshot": {"status": "ok", "summary": "nominal"},
        "capability.changed": {
            "capabilities": [{"id": "health.heartbeat", "version": "1.0"}],
            "added": [{"id": "remote.profile", "version": "1.0"}],
            "removed": [],
        },
        "config.schema": {"fields": [{"path": "bridge.outputs.dmx.0.universe", "value_type": "uint"}]},
        "config.set": {
            "transaction_id": KEY,
            "expected_revision": 3,
            "changes": [{"path": "bridge.outputs.dmx.0.universe", "value": 1}],
            "apply": "validate_then_commit",
        },
        "config.result": {
            "transaction_id": KEY,
            "status": "rejected",
            "error": ERR,
        },
        "telemetry.batch": {"metrics": [{"name": "cpu_pct", "value": 1.5}]},
        "show.load": {"show_id": SHOW, "revision": 42, "manifest_sha256": SHA},
        "show.ready": {"show_id": SHOW, "ready": True},
        "show.position": {"show_id": SHOW, "song_id": "haywire"},
        "show.conformance": {"show_id": SHOW, "revision": 42, "status": "ready"},
        "show.verify": {"show_id": SHOW, "revision": 42, "manifest_sha256": SHA},
        "show.armed": {"show_id": SHOW, "revision": 42, "manifest_sha256": SHA, "armed": True},
        "show.disarm": {"show_id": SHOW, "reason": "operator"},
        "song.start": {"song_id": "haywire", "show_id": SHOW},
        "song.stop": {"song_id": "haywire", "show_id": SHOW},
        "song.position": {"song_id": "haywire", "elapsed_ms": 1200},
        "section.exit": {"section_id": "chorus_2", "song_id": "haywire"},
        "section.position": {"section_id": "chorus_2", "bar": 12, "beat": 1},
        "cue.fire": {"cue_id": "cue_1", "idempotency_key": KEY},
        "cue.stop": {"cue_id": "cue_1"},
        "transport.pause": {"idempotency_key": KEY},
        "transport.stop": {"idempotency_key": KEY},
        "transport.seek": {"position_ms": 2500},
        "bridge.status": {"uptime_ms": 90000, "output_mode": "artnet"},
        "manifest.report": {"show_id": SHOW, "revision": 42, "assets": [ASSET], "manifest_sha256": SHA},
        "asset.inventory": {"assets": [ASSET]},
        "asset.required": {"asset": ASSET, "requirement": "required"},
        "asset.sync": {"asset": ASSET},
        "asset.sync_result": {"asset_id": AID, "status": "ready"},
        "resource.accept": {"transfer_id": TID, "max_chunk_bytes": 4294967295},
        "resource.reject": {"transfer_id": TID, "code": "capacity", "message": "too large"},
        "resource.chunk": {
            "transfer_id": TID,
            "offset": 0,
            "length": 4,
            "data": base64.b64encode(CHUNK).decode("ascii"),
        },
        "resource.complete": {"transfer_id": TID},
        "resource.transfer_result": {"transfer_id": TID, "status": "verified"},
        "resource.activate": {"transfer_id": TID, "idempotency_key": KEY},
        "resource.activation_result": {"transfer_id": TID, "status": "applied"},
        "resource.cancel": {"transfer_id": TID, "reason": "user"},
        "participant.preference": {"participant_id": PID, "preferred_chart_type": "chord_lyrics"},
        "participant.assignment": {"participant_id": PID, "device_id": DST, "node_id": SRC},
        "chart.catalog": {"charts": [chart]},
        "chart.assignment": assignment,
        "chart.assignment_set": {"assignments": [assignment]},
        "lyric.assignment_manifest": {"participant_id": PID, "show_id": SHOW, "assets": [ASSET]},
        "lyric.assignment_status": {"participant_id": PID, "show_id": SHOW, "status": "ready"},
        "lyric.ready": {"participant_id": PID, "ready": True, "status": "ready"},
    }


def extras(typ: str) -> dict:
    if typ == "resource.chunk":
        return {"correlation_id": KEY, "causation_id": "0193f8d8-4c4e-7d8b-a2ab-000000000031"}
    return {}


def main() -> int:
    registry = json.loads((ROOT / "schema" / "registry.json").read_text())
    by_type = {row["type"]: row for row in registry["messages"]}
    manifest_path = ROOT / "vectors" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    known = {item["id"] for item in manifest["vectors"]}
    missing = [typ for typ in by_type if typ not in known]
    bodies = payloads()
    next_n = 100
    for typ in missing:
        if typ not in bodies:
            print(f"no payload for {typ}", file=sys.stderr)
            return 1
        row = by_type[typ]
        qos = row.get("qos_default") or row["qos_allowed"][0]
        before = bool(row.get("legal_before_handshake"))
        data = env(
            typ,
            bodies[typ],
            qos=qos,
            seq=None if before and typ.startswith("discovery.") else 1,
            dest=typ not in {"discovery.query", "session.goodbye"},
            n=next_n,
            extra=extras(typ) or None,
        )
        if typ == "session.goodbye":
            data["session_id"] = SID
            data["sequence"] = 1
        validate_message(data)
        env_obj = Envelope.from_dict(data)
        (ROOT / "vectors" / "json" / f"{typ}.json").write_text(json.dumps(data, indent=2) + "\n")
        (ROOT / "vectors" / "cbor" / f"{typ}.cbor").write_bytes(encode_cbor(env_obj))
        manifest["vectors"].append({
            "id": typ,
            "json": f"json/{typ}.json",
            "cbor": f"cbor/{typ}.cbor",
        })
        next_n += 1
        print("added", typ)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("wrote", len(missing), "vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
