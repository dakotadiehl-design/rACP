from __future__ import annotations

from datetime import UTC, datetime

import pytest
from acp.cbor_cde import CborError, decode, encode
from acp.codec import CodecError, decode_cbor, decode_json, encode_cbor, encode_json
from acp.envelope import Envelope
from acp.types import Endpoint, QoS

SRC = Endpoint(node_id="0193f8d8-4c4e-7d8b-a2ab-000000000001")
TS = datetime(2026, 8, 17, 16, 42, 15, 231000, tzinfo=UTC)


def sample() -> Envelope:
    return Envelope(
        acp="1.2",
        message_id="0193f8d8-4c4e-7d8b-a2ab-000000000002",
        type="health.heartbeat",
        source=SRC,
        timestamp_utc=TS,
        qos=QoS.LATEST,
        payload={"uptime_ms": 1000, "status": "ok"},
        flags=frozenset(),
        session_id="0193f8d8-4c4e-7d8b-a2ab-000000000003",
        sequence=1,
    )


def test_json_roundtrip() -> None:
    env = sample()
    again = decode_json(encode_json(env))
    assert again.to_dict() == env.to_dict()


def test_cbor_roundtrip_and_tag0() -> None:
    env = sample()
    raw = encode_cbor(env)
    again = decode_cbor(raw)
    assert again.to_dict() == env.to_dict()
    # tag 0 is 0xc0
    assert b"\xc0" in raw


def test_cde_key_order() -> None:
    raw = encode({"qos": "latest", "acp": "1.2", "type": "x.y"})
    # decode should accept our own CDE
    decoded = decode(raw)
    assert decoded["acp"] == "1.2"
    # re-encode is stable
    assert encode(decoded) == raw


def test_reject_indefinite() -> None:
    with pytest.raises(CborError):
        decode(b"\x9f\x01\xff")


def test_reject_tag1() -> None:
    # tag 1, unsigned 0
    with pytest.raises((CborError, CodecError)):
        decode(b"\xc1\x00")


def test_unknown_fields_dropped() -> None:
    env = sample()
    data = env.to_dict()
    data["extra_envelope"] = True
    data["payload"] = {**data["payload"], "future": 1}
    again = decode_json(__import__("json").dumps(data))
    assert "extra_envelope" not in again.to_dict()
    assert "future" not in again.payload  # unknown optional payload fields dropped


def test_reject_non_preferred_int() -> None:
    # 0 encoded as 0x18 0x00 (1-byte argument for value < 24)
    with pytest.raises(CborError):
        decode(b"\x18\x00")


def test_json_rejects_nan() -> None:
    with pytest.raises(CodecError):
        decode_json('{"acp":"1.2","message_id":"0193f8d8-4c4e-7d8b-a2ab-000000000002","type":"health.heartbeat","source":{"node_id":"0193f8d8-4c4e-7d8b-a2ab-000000000001"},"timestamp_utc":"2026-08-17T16:42:15.231Z","qos":"latest","flags":[],"payload":{"uptime_ms":1,"status":"ok","metrics":{"cpu_pct":NaN}}}')


def test_malformed_uuid() -> None:
    env = sample().to_dict()
    env["message_id"] = "not-a-uuid"
    with pytest.raises((CodecError, ValueError)):
        decode_json(__import__("json").dumps(env))
