from acp.registry import allowed_to_send


def test_v12_type_blocked_on_v10_session() -> None:
    err = allowed_to_send(
        "show.prepare",
        session_version="1.0",
        sender_role="conductor",
        negotiated_capabilities={"asset.conformance"},
        handshake_complete=True,
    )
    assert err == "unsupported_message"


def test_capability_required() -> None:
    err = allowed_to_send(
        "bridge.blackout",
        session_version="1.2",
        sender_role="conductor",
        negotiated_capabilities=set(),
        handshake_complete=True,
    )
    assert err == "capability_not_permitted"
