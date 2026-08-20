#!/usr/bin/env python3
"""Add golden vectors for Remote Profile message types."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "src"))

from acp.codec import encode_cbor  # noqa: E402
from acp.envelope import Envelope  # noqa: E402
from acp.remote import sample_layout  # noqa: E402
from acp.validate import validate_message  # noqa: E402

SRC = "0193f8d8-4c4e-7d8b-a2ab-0000000000b0"
DST = "0193f8d8-4c4e-7d8b-a2ab-000000000001"
SID = "0193f8d8-4c4e-7d8b-a2ab-0000000000c0"
SHOW = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
LAYOUT = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"
TS = "2026-08-17T16:42:15.231Z"


def mid(n: int) -> str:
    return f"0193f8d8-4c4e-7d8b-a2ab-{n:012d}"


def env(typ: str, payload: dict, qos: str = "reliable", n: int = 40, dest: bool = True) -> dict:
    client = (
        typ.startswith("remote.control.invoke")
        or typ.endswith(".hello")
        or typ.endswith(".request")
        or typ.endswith(".refresh")
        or typ == "remote.readiness"
    )
    data = {
        "acp": "1.2",
        "message_id": mid(n),
        "type": typ,
        "source": {"node_id": SRC if client else DST},
        "timestamp_utc": TS,
        "qos": qos,
        "flags": [],
        "payload": payload,
        "session_id": SID,
        "sequence": 1,
    }
    if dest:
        data["destination"] = {"node_id": DST if data["source"]["node_id"] == SRC else SRC}
    return data


VECTORS = [
    env("remote.hello", {
        "remote": {
            "node_id": SRC,
            "instance_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b1",
            "device_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b2",
            "remote_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b3",
            "device_name": "FOH iPad",
            "platform": "ipados",
            "app_version": "1.0.0",
        },
        "roles": ["remote.operator", "remote.busker"],
        "capabilities": [{"id": "remote.profile", "version": "1.0"}],
    }, n=40),
    env("remote.hello_ack", {
        "accepted": True,
        "permissions": {"roles": ["remote.operator", "remote.busker"], "revision": 1},
        "show_id": SHOW,
        "show_revision": 1,
        "layout_id": LAYOUT,
        "layout_revision": 8,
    }, n=41),
    env("remote.control.invoke", {
        "control_id": "fog_burst",
        "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
        "interaction": "momentary_begin",
        "value": 1.0,
        "client_timestamp_utc": TS,
        "show_id": SHOW,
        "show_revision": 1,
        "layout_id": LAYOUT,
        "layout_revision": 8,
        "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
    }, n=42),
    env("remote.control.state", {
        "control_id": "fog_burst",
        "revision": 2,
        "enabled": True,
        "available": True,
        "value": True,
        "confidence": "confirmed",
    }, qos="latest", n=43),
    env("remote.permissions", {
        "roles": ["remote.operator", "remote.busker"],
        "capabilities": ["remote.control.invoke"],
        "revision": 1,
    }, n=44),
    env("remote.readiness", {
        "state": "ready",
        "remote_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000b3",
        "session_id": SID,
        "layout_revision": 8,
        "permissions_revision": 1,
        "warnings": [],
    }, n=45),
    env("remote.layout.report", {
        "layout": sample_layout(show_id=SHOW, layout_id=LAYOUT),
    }, n=46),
    env("remote.error", {
        "code": "remote.control.permission_denied",
        "category": "authorization",
        "severity": "error",
        "message": "missing remote.operator",
        "retryable": False,
    }, n=47),
    env("remote.layout.request", {"show_id": SHOW, "layout_id": LAYOUT}, n=48),
    env("remote.control.snapshot", {
        "controls": [{
            "control_id": "fog_burst",
            "revision": 1,
            "enabled": True,
            "available": True,
            "value": False,
            "confidence": "confirmed",
        }],
    }, n=49),
    env("remote.permissions.changed", {
        "roles": ["remote.viewer"],
        "revision": 2,
    }, n=50),
    env("remote.readiness.changed", {
        "state": "syncing_state",
        "session_id": SID,
        "layout_revision": 8,
        "permissions_revision": 1,
    }, n=51),
    env("remote.navigation.request", {
        "kind": "browse",
        "song_id": "haywire",
        "show_id": SHOW,
        "idempotency_key": "0193f8d8-4c4e-7d8b-a2ab-0000000000f0",
    }, n=52),
    env("remote.navigation.state", {
        "show_id": SHOW,
        "song_id": "haywire",
        "next_song_id": "encore",
        "cue_id": "cue_1",
        "next_cue_id": "cue_2",
    }, qos="latest", n=53),
    env("remote.presentation.state", {
        "show_id": SHOW,
        "show_revision": 1,
        "song_id": "haywire",
        "cue_id": "cue_1",
        "next_cue_id": "cue_2",
        "transport": "live",
    }, qos="latest", n=54),
    env("remote.momentary.refresh", {
        "control_id": "fog_burst",
        "invocation_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
        "lease_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000d2",
    }, n=55),
]


def main() -> None:
    json_dir = ROOT / "vectors" / "remote" / "json"
    cbor_dir = ROOT / "vectors" / "remote" / "cbor"
    json_dir.mkdir(parents=True, exist_ok=True)
    cbor_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = ROOT / "vectors" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    known = {item["id"] for item in manifest["vectors"]}
    for data in VECTORS:
        typ = data["type"]
        validate_message(data)
        env_obj = Envelope.from_dict(data)
        json_rel = f"remote/json/{typ}.json"
        cbor_rel = f"remote/cbor/{typ}.cbor"
        (ROOT / "vectors" / json_rel).write_text(json.dumps(data, indent=2) + "\n")
        (ROOT / "vectors" / cbor_rel).write_bytes(encode_cbor(env_obj))
        if typ not in known:
            manifest["vectors"].append({"id": typ, "json": json_rel, "cbor": cbor_rel})
            known.add(typ)
        print("ok", typ)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
