"""Result and transcript types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class TranscriptEntry:
    elapsed: float
    direction: str
    line: str


@dataclass
class ScenarioResult:
    name: str
    status: Status
    detail: str = ""
    duration: float = 0.0


@dataclass
class RunReport:
    target: str
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, str] = field(default_factory=dict)
    peer: dict[str, Any] | None = None
    results: list[ScenarioResult] = field(default_factory=list)
    transcripts: list[TranscriptEntry] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(result.status is Status.FAIL for result in self.results)
