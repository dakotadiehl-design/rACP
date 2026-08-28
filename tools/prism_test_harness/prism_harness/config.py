"""Configuration for a Prism test target."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from racp.protocol import decode_value

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")


@dataclass(frozen=True)
class CommandCase:
    name: str
    value: Any = None
    has_value: bool = False
    expected: str = "ack"
    state_changing: bool = False


@dataclass(frozen=True)
class SubscriptionCase:
    name: str
    expect_initial: bool = False


@dataclass(frozen=True)
class HarnessConfig:
    host: str = "127.0.0.1"
    port: int = 9000
    peer_type: str = "diagnostic"
    peer_id: str = "prism-harness"
    expected_peer_type: str | None = None
    expected_peer_id: str | None = None
    required_capabilities: tuple[str, ...] = ()
    timeout: float = 5.0
    output_dir: Path = Path("prism-harness-results")
    commands: tuple[CommandCase, ...] = ()
    subscriptions: tuple[SubscriptionCase, ...] = ()
    malformed_tests: bool = True
    metadata: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.host or not 1 <= self.port <= 65535:
            raise ValueError("host must be non-empty and port must be in 1..65535")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        for label, token in (("peer_type", self.peer_type), ("peer_id", self.peer_id)):
            if not TOKEN.fullmatch(token):
                raise ValueError(f"invalid {label}")
        for value in (self.expected_peer_type, self.expected_peer_id):
            if value is not None and not TOKEN.fullmatch(value):
                raise ValueError("invalid expected peer token")
        names = (
            *self.required_capabilities,
            *(case.name for case in self.commands),
            *(case.name for case in self.subscriptions),
        )
        for name in names:
            if len(name) > 128 or not NAME.fullmatch(name):
                raise ValueError(f"invalid capability name: {name!r}")
        for case in self.commands:
            if case.expected != "ack" and not NAME.fullmatch(case.expected):
                raise ValueError(f"invalid expected result for {case.name!r}")


def _table_list(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{key} must be an array of tables")
    return value


def load_config(path: Path) -> HarnessConfig:
    """Load and validate a TOML target profile."""
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    target = data.get("target", {})
    local = data.get("local", {})
    options = data.get("options", {})
    if not all(isinstance(table, dict) for table in (target, local, options)):
        raise ValueError("target, local, and options must be TOML tables")

    command_items = _table_list(data, "commands")
    commands_list: list[CommandCase] = []
    for item in command_items:
        if "value" in item and "value_json" in item:
            raise ValueError("a command may define value or value_json, not both")
        has_value = "value" in item or "value_json" in item
        value = decode_value(str(item["value_json"])) if "value_json" in item else item.get("value")
        commands_list.append(
            CommandCase(
                name=str(item["name"]),
                value=value,
                has_value=has_value,
                expected=str(item.get("expected", "ack")),
                state_changing=bool(item.get("state_changing", False)),
            )
        )
    commands = tuple(commands_list)
    subscriptions = tuple(
        SubscriptionCase(name=str(item["name"]), expect_initial=bool(item.get("expect_initial", False)))
        for item in _table_list(data, "subscriptions")
    )
    metadata = data.get("metadata", {})
    valid_metadata = isinstance(metadata, dict) and all(
        isinstance(key, str) and isinstance(value, str) for key, value in metadata.items()
    )
    if not valid_metadata:
        raise ValueError("metadata values must be strings")
    config = HarnessConfig(
        host=str(target.get("host", "127.0.0.1")),
        port=int(target.get("port", 9000)),
        expected_peer_type=target.get("expected_peer_type"),
        expected_peer_id=target.get("expected_peer_id"),
        peer_type=str(local.get("peer_type", "diagnostic")),
        peer_id=str(local.get("peer_id", "prism-harness")),
        required_capabilities=tuple(str(value) for value in target.get("required_capabilities", [])),
        timeout=float(options.get("timeout", 5.0)),
        output_dir=Path(str(options.get("output_dir", "prism-harness-results"))),
        malformed_tests=bool(options.get("malformed_tests", True)),
        commands=commands,
        subscriptions=subscriptions,
        metadata=dict(metadata),
    )
    config.validate()
    return config
