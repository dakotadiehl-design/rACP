from pathlib import Path

import pytest

from prism_harness.config import load_config


def test_load_config_distinguishes_omitted_value_from_null(tmp_path: Path) -> None:
    profile = tmp_path / "profile.toml"
    profile.write_text(
        """
[target]
host = "127.0.0.1"
port = 9100
required_capabilities = ["cue.go"]

[[commands]]
name = "cue.go"

[[commands]]
name = "cue.go"
value_json = "null"
state_changing = true
""",
        encoding="utf-8",
    )
    config = load_config(profile)
    assert not config.commands[0].has_value
    assert config.commands[1].has_value
    assert config.commands[1].value is None
    assert config.commands[1].state_changing


def test_invalid_profile_is_rejected(tmp_path: Path) -> None:
    profile = tmp_path / "profile.toml"
    profile.write_text('[target]\nport = 70000\n', encoding="utf-8")
    with pytest.raises(ValueError, match="port"):
        load_config(profile)
