import pytest

from racp import (
    Ack,
    Command,
    Error,
    Hello,
    Ping,
    Pong,
    ProtocolError,
    Session,
    SessionClosed,
    SessionState,
    State,
    Subscribe,
)


def established(handler=None, *, now=lambda: 0.0, ledger_size=1024) -> Session:
    session = Session(
        Hello("device", "prism-main", ("cue.current", "cue.go", "state.subscribe")),
        handler,
        now=now,
        ledger_size=ledger_size,
    )
    for line in ["RACP/1 HELLO", "PEER remote desk", "CAP cue.go", "END"]:
        assert session.receive_line(line) == []
    assert session.state is SessionState.ESTABLISHED
    return session


def test_hello_is_strict_and_deterministic() -> None:
    hello = Hello("device", "prism-main", ("cue.go", "state.subscribe"))
    assert hello.lines() == ["RACP/1 HELLO", "PEER device prism-main", "CAP cue.go", "CAP state.subscribe", "END"]
    with pytest.raises(ValueError):
        Hello("bad peer", "x").lines()
    session = Session(Hello("device", "x"))
    with pytest.raises(ProtocolError) as caught:
        session.receive_line("RACP/2 HELLO")
        session.receive_line("PEER remote x")
        session.receive_line("END")
    assert caught.value.code == "unsupported_version" and caught.value.fatal


def test_command_dispatch_capability_and_duplicate_ledger() -> None:
    applied = []
    session = established(lambda cmd: applied.append(cmd) or None)
    command = Command(1, "cue.go")
    assert session.receive(command) == [Ack(1)]
    assert session.receive(command) == [Ack(1)]
    assert len(applied) == 1
    assert session.receive(Command(1, "cue.go", None, True)) == [Error(1, "request_id_conflict")]
    assert session.receive(Command(2, "cue.back")) == [Error(2, "unsupported_capability")]


def test_ledger_is_bounded_and_handler_errors_are_structured() -> None:
    session = established(lambda _cmd: (_ for _ in ()).throw(RuntimeError()), ledger_size=1)
    assert session.receive(Command(1, "cue.go")) == [Error(1, "application_error")]
    assert session.receive(Command(2, "cue.go")) == [Error(2, "application_error")]
    assert len(session._ledger) == 1


def test_subscriptions_and_state_revision_filter() -> None:
    session = established()
    assert session.receive(Subscribe(1, "cue.current")) == [Ack(1)]
    assert "cue.current" in session.subscriptions
    assert session.receive(Subscribe(2, "unknown.state")) == [Error(2, "unsupported_capability")]
    session.receive(State("cue.current", 3, 10))
    session.receive(State("cue.current", 2, 9))
    assert session.state_revisions == {"cue.current": 3}


def test_heartbeat_and_timeout() -> None:
    clock = [0.0]
    session = established(now=lambda: clock[0])
    clock[0] = 10
    assert session.heartbeat(7) == [Ping(7)]
    session.receive(Pong(8))
    assert session.outstanding_ping is not None
    session.receive(Pong(7))
    assert session.outstanding_ping is None
    clock[0] = 20
    session.heartbeat(8)
    clock[0] = 25
    with pytest.raises(SessionClosed, match="heartbeat_timeout"):
        session.heartbeat(9)
    assert session.state is SessionState.CLOSED


def test_outbound_lines_enforce_encoded_byte_limit() -> None:
    with pytest.raises(ProtocolError) as caught:
        Session.encode([Command(1, "cue.go", "é" * 9000, True)])
    assert caught.value.code == "line_too_long" and caught.value.fatal
