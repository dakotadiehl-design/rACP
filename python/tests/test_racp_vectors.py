from pathlib import Path

from racp import Hello, Session, SessionState, encode_message, parse_message

ROOT = Path(__file__).resolve().parents[2]


def test_golden_messages_are_byte_stable() -> None:
    lines = (ROOT / "vectors/racp-v1/messages.txt").read_text(encoding="utf-8").splitlines()
    for line in lines:
        assert encode_message(parse_message(line)) == line


def test_golden_hello_is_byte_stable() -> None:
    lines = (ROOT / "vectors/racp-v1/hello.txt").read_text(encoding="utf-8").splitlines()
    session = Session(Hello("diagnostic", "test"))
    for line in lines:
        session.receive_line(line)
    assert session.state is SessionState.ESTABLISHED
    assert session.peer == Hello(
        "device",
        "prism-main",
        ("cue.current", "cue.go", "output.grand_master.set", "state.subscribe"),
    )
    assert session.peer.lines() == lines
