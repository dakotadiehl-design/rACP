import math

import pytest

from racp.protocol import (
    Ack,
    Bye,
    Command,
    Error,
    LineDecoder,
    Ping,
    ProtocolError,
    State,
    Subscribe,
    encode_message,
    encode_value,
    parse_message,
)


@pytest.mark.parametrize(
    "message",
    [
        Command(41, "cue.go"),
        Command(42, "output.level.set", {"fade": 2, "level": 0.75}, True),
        Ack(41),
        Error(42, "permission_denied"),
        State("cue.current", 18, 18),
        Subscribe(7, "cue.current"),
        Ping(9),
        Bye(),
    ],
)
def test_messages_round_trip(message) -> None:
    assert parse_message(encode_message(message)) == message


def test_no_value_is_distinct_from_null() -> None:
    assert parse_message("CMD 1 cue.go") == Command(1, "cue.go")
    assert parse_message("CMD 1 cue.go null") == Command(1, "cue.go", None, True)


def test_json_may_contain_spaces_without_weakening_token_grammar() -> None:
    assert parse_message('CMD 1 cue.go {"label":"Stage  Left",  "level": 1}') == Command(
        1, "cue.go", {"label": "Stage  Left", "level": 1}, True
    )
    with pytest.raises(ProtocolError, match="malformed_message"):
        parse_message("SUB  1 cue.current")


def test_json_is_deterministic_and_rejects_unsafe_values() -> None:
    assert encode_value({"z": 1, "a": "line\nvalue"}) == '{"a":"line\\nvalue","z":1}'
    for text in ('{"a":1,"a":2}', "NaN", "9007199254740992"):
        with pytest.raises(ProtocolError, match="invalid_value"):
            parse_message(f"CMD 1 test.value {text}")
    with pytest.raises(ProtocolError):
        encode_value(math.inf)
    for value in ("\ud800", {"\udfff": 1}):
        with pytest.raises(ProtocolError, match="invalid_value"):
            encode_value(value)
    with pytest.raises(ProtocolError, match="invalid_value"):
        parse_message(r'CMD 1 test.value "\ud800"')


@pytest.mark.parametrize(
    "line",
    [
        "",
        " CMD 1 cue.go",
        "CMD  1 cue.go",
        "CMD 01 cue.go",
        "CMD 0 cue.go",
        "CMD 1 Cue.Go",
        "ACK 1 ",
        "WAT 1",
        "STATE cue.current -1 2",
    ],
)
def test_malformed_lines_fail_deterministically(line: str) -> None:
    with pytest.raises(ProtocolError, match="malformed_message"):
        parse_message(line)


def test_incremental_decoder_handles_partial_and_multiple_frames() -> None:
    decoder = LineDecoder()
    assert decoder.feed(b"CMD 1 cue") == []
    assert decoder.feed(b".go\r\nPING 2\n") == ["CMD 1 cue.go", "PING 2"]


def test_decoder_bounds_and_utf8() -> None:
    decoder = LineDecoder(4)
    with pytest.raises(ProtocolError) as caught:
        decoder.feed(b"12345")
    assert caught.value.code == "line_too_long" and caught.value.fatal
    decoder.feed(b"discarded\n")
    assert decoder.feed(b"OK\n") == ["OK"]
    with pytest.raises(ProtocolError) as caught:
        LineDecoder().feed(b"\xff\n")
    assert caught.value.fatal


def test_decoder_allows_maximum_line_with_crlf() -> None:
    decoder = LineDecoder(4)
    assert decoder.feed(b"1234\r\n") == ["1234"]
    with pytest.raises(ProtocolError, match="line_too_long"):
        LineDecoder(4).feed(b"12345\n")
