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


def test_min_capability_version_requires_explicit_negotiated_version() -> None:
    err = allowed_to_send(
        "remote.control.invoke",
        session_version="1.2",
        sender_role="remote",
        negotiated_capabilities={"remote.control.invoke"},
        handshake_complete=True,
    )
    assert err == "capability_not_permitted"
    err = allowed_to_send(
        "remote.control.invoke",
        session_version="1.2",
        sender_role="remote",
        negotiated_capabilities={"remote.control.invoke"},
        handshake_complete=True,
        negotiated_versions={},
    )
    assert err == "capability_not_permitted"
    err = allowed_to_send(
        "remote.control.invoke",
        session_version="1.2",
        sender_role="remote",
        negotiated_capabilities={"remote.control.invoke"},
        handshake_complete=True,
        negotiated_versions={"remote.control.invoke": "not-a-version"},
    )
    assert err == "capability_not_permitted"
    err = allowed_to_send(
        "remote.control.invoke",
        session_version="1.2",
        sender_role="remote",
        negotiated_capabilities={"remote.control.invoke"},
        handshake_complete=True,
        negotiated_versions={"remote.control.invoke": "0.9"},
    )
    assert err == "capability_not_permitted"
    err = allowed_to_send(
        "remote.control.invoke",
        session_version="1.2",
        sender_role="remote",
        negotiated_capabilities={"remote.control.invoke"},
        handshake_complete=True,
        negotiated_versions={"remote.control.invoke": "1.0"},
    )
    assert err is None
