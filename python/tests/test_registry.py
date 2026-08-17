from acp.registry import load_registry, lookup


def test_registry_has_core_and_v12() -> None:
    reg = load_registry()
    assert "session.hello" in reg
    assert "bridge.blackout" in reg
    assert "resource.chunk" in reg
    assert "lyric.assignment_status" in reg
    assert lookup("show.prepare")["min_protocol"] == "1.2"
    assert lookup("session.hello")["legal_before_handshake"] is True
    assert lookup("cue.go")["legal_before_handshake"] is False
