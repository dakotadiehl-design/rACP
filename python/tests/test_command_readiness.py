from acp.codec import decode_json, encode_json
from acp.command_ledger import CommandLedger
from acp.envelope import Envelope
from acp.preconditions import PreconditionError, evaluate_preconditions
from acp.priority import BACKGROUND, SAFETY, TELEMETRY, OutboundItem, PriorityQueue
from acp.state_revision import StateSyncRequired, apply_delta, snapshot_payload
from acp.types import new_uuid
from acp.validate import validate_message

SRC = "0193f8d8-4c4e-7d8b-a2ab-000000000001"
SID = "0193f8d8-4c4e-7d8b-a2ab-000000000013"
CMD = "0193f8d8-4c4e-7d8b-a2ab-000000000099"


def test_snapshot_and_revisioned_delta_roundtrip() -> None:
    snap = snapshot_payload(
        authority_epoch=7,
        revision=3,
        resources=[
            {
                "resource": "prism.cue",
                "revision": 3,
                "owner": {"node_id": SRC},
                "value": {"current_cue_id": "cue-a"},
            }
        ],
    )
    env = Envelope.from_dict(
        {
            "acp": "1.2",
            "message_id": new_uuid(),
            "type": "state.snapshot",
            "source": {"node_id": SRC},
            "timestamp_utc": "2026-08-17T16:42:15.231Z",
            "qos": "reliable",
            "payload": snap,
            "session_id": SID,
            "sequence": 1,
        }
    )
    validate_message(env.to_dict())
    restored = decode_json(encode_json(env))
    assert restored.payload["authority_epoch"] == 7
    epoch, rev = apply_delta(
        7,
        3,
        {
            "authority_epoch": 7,
            "base_revision": 3,
            "revision": 4,
            "changes": snap["resources"],
        },
    )
    assert (epoch, rev) == (7, 4)


def test_delta_epoch_mismatch_requires_snapshot() -> None:
    try:
        apply_delta(
            1,
            4,
            {
                "authority_epoch": 2,
                "base_revision": 4,
                "revision": 5,
                "changes": [],
            },
        )
    except StateSyncRequired as exc:
        assert "authority_epoch" in str(exc)
    else:
        raise AssertionError("expected resync")


def test_command_ledger_survives_session_replace_and_hides_other_principals() -> None:
    ledger = CommandLedger()
    rec = ledger.remember(
        CommandLedger.make_record(
            command_id=CMD,
            origin_node_id=SRC,
            origin_instance_id=SRC,
            origin_principal="alice",
            origin_session_id=SID,
            operation="performance.go",
            disposition="applied",
            resulting_epoch=1,
            resulting_revision=2,
        )
    )
    found = ledger.lookup(origin_node_id=SRC, command_id=CMD, origin_principal="alice")
    assert found is rec
    assert ledger.lookup(origin_node_id=SRC, command_id=CMD, origin_principal="bob") is None
    again = ledger.remember(
        CommandLedger.make_record(
            command_id=CMD,
            origin_node_id=SRC,
            origin_instance_id=SRC,
            origin_principal="alice",
            origin_session_id=new_uuid(),
            operation="performance.go",
            disposition="applied",
        )
    )
    assert again.disposition == "applied"
    assert again.origin_session_id == SID


def test_precondition_stale_cue_fails_closed() -> None:
    try:
        evaluate_preconditions(
            [{"op": "equals", "field": "current_cue_id", "value": "cue-a"}],
            authority_epoch=1,
            revision=4,
            current_cue_id="cue-b",
        )
    except PreconditionError as exc:
        assert exc.code == "command.precondition_failed"
    else:
        raise AssertionError("expected precondition failure")


def test_priority_queue_never_coalesces_go_and_drops_telemetry_first() -> None:
    q = PriorityQueue(
        capacities={
            SAFETY: 4,
            "interactive": 4,
            "state": 4,
            BACKGROUND: 1,
            TELEMETRY: 1,
        }
    )
    assert q.push(OutboundItem(TELEMETRY, "t1"))
    assert q.push(OutboundItem(TELEMETRY, "t2")) is False
    assert q.push(
        OutboundItem(
            "interactive",
            "go",
            coalescing_key="go",
            delivery="latest_value_wins",
            action="performance.go",
        )
    )
    assert q.push(OutboundItem("state", 1, coalescing_key="prism.output.master", delivery="latest_value_wins"))
    assert q.push(OutboundItem("state", 2, coalescing_key="prism.output.master", delivery="latest_value_wins"))
    first = q.pop()
    assert first is not None and first.action == "performance.go"
    second = q.pop()
    assert second is not None and second.payload == 2


def test_priority_queue_never_coalesces_live_ephemeral_section_go() -> None:
    q = PriorityQueue()
    assert q.push(
        OutboundItem(
            "interactive",
            "section-a",
            coalescing_key="section",
            delivery="latest_value_wins",
            action="show.section.next",
        )
    )
    assert q.push(
        OutboundItem(
            "interactive",
            "section-b",
            coalescing_key="section",
            delivery="latest_value_wins",
            action="show.section.next",
        )
    )
    first = q.pop()
    second = q.pop()
    assert first is not None and first.payload == "section-a"
    assert second is not None and second.payload == "section-b"
