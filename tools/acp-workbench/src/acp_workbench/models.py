from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ConnectionState(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    NEGOTIATING = "negotiating"
    SYNCHRONIZING = "synchronizing"
    READY = "ready"
    CLOSING = "closing"
    FAILED = "failed"


@dataclass(slots=True)
class ConnectionConfig:
    target: str
    profile: str = "remote-prism"
    name: str = "ACP Workbench"
    node_id: str | None = None
    instance_id: str | None = None
    allow_plaintext: bool = False
    timeout: float = 5.0
    show_id: str = "0193f8d8-4c4e-7d8b-a2ab-000000000050"
    layout_id: str = "0193f8d8-4c4e-7d8b-a2ab-0000000000a0"
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None


@dataclass(slots=True)
class WorkbenchEvent:
    sequence: int
    kind: str
    connection_id: str | None
    monotonic_s: float
    timestamp_utc: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AssertionResult:
    passed: bool
    message: str
    expected: Any = None
    actual: Any = None
    evidence: list[int] = field(default_factory=list)
    duration_s: float = 0.0


@dataclass(slots=True)
class ScenarioResult:
    scenario_id: str
    name: str
    passed: bool
    assertions: list[AssertionResult]
    started_at: str
    duration_s: float
    error: str | None = None


@dataclass(slots=True)
class RunResult:
    passed: bool
    scenarios: list[ScenarioResult]
    started_at: str
    duration_s: float
    metadata: dict[str, Any] = field(default_factory=dict)


def utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
