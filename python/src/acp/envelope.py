from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .types import (
    Endpoint,
    QoS,
    format_ts,
    new_uuid,
    normalize_uuid,
    parse_ts,
)


@dataclass(frozen=True, slots=True)
class Envelope:
    acp: str
    message_id: str
    type: str
    source: Endpoint
    timestamp_utc: datetime
    qos: QoS
    payload: Mapping[str, Any]
    flags: frozenset[str] = field(default_factory=frozenset)
    destination: Endpoint | None = None
    session_id: str | None = None
    sequence: int | None = None
    correlation_id: str | None = None
    causation_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "message_id", normalize_uuid(self.message_id))
        if self.session_id is not None:
            object.__setattr__(self, "session_id", normalize_uuid(self.session_id))
        if self.correlation_id is not None:
            object.__setattr__(self, "correlation_id", normalize_uuid(self.correlation_id))
        if self.causation_id is not None:
            object.__setattr__(self, "causation_id", normalize_uuid(self.causation_id))
        if isinstance(self.qos, str):
            object.__setattr__(self, "qos", QoS(self.qos))
        if self.sequence is not None and self.sequence < 1:
            raise ValueError("sequence must be >= 1")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "acp": self.acp,
            "message_id": self.message_id,
            "type": self.type,
            "source": self.source.to_dict(),
            "timestamp_utc": format_ts(self.timestamp_utc),
            "qos": self.qos.value,
            "flags": sorted(self.flags),
            "payload": dict(self.payload),
        }
        if self.destination is not None:
            data["destination"] = self.destination.to_dict()
        if self.session_id is not None:
            data["session_id"] = self.session_id
        if self.sequence is not None:
            data["sequence"] = self.sequence
        if self.correlation_id is not None:
            data["correlation_id"] = self.correlation_id
        if self.causation_id is not None:
            data["causation_id"] = self.causation_id
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Envelope:
        extra = {k: v for k, v in data.items() if k not in _KNOWN}
        payload = dict(data.get("payload") or {})
        # unknown envelope keys are dropped (typed decode)
        _ = extra
        dest = data.get("destination")
        return cls(
            acp=str(data["acp"]),
            message_id=data["message_id"],
            type=str(data["type"]),
            source=Endpoint.from_dict(data["source"]),
            destination=Endpoint.from_dict(dest) if dest else None,
            session_id=data.get("session_id"),
            sequence=data.get("sequence"),
            timestamp_utc=parse_ts(data["timestamp_utc"])
            if isinstance(data["timestamp_utc"], str)
            else data["timestamp_utc"],
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            qos=QoS(data["qos"]),
            flags=frozenset(data.get("flags") or []),
            payload=payload,
        )

    def with_session(self, session_id: str, sequence: int) -> Envelope:
        return Envelope(
            acp=self.acp,
            message_id=self.message_id,
            type=self.type,
            source=self.source,
            timestamp_utc=self.timestamp_utc,
            qos=self.qos,
            payload=self.payload,
            flags=self.flags,
            destination=self.destination,
            session_id=session_id,
            sequence=sequence,
            correlation_id=self.correlation_id,
            causation_id=self.causation_id,
        )


_KNOWN = {
    "acp",
    "message_id",
    "type",
    "source",
    "destination",
    "session_id",
    "sequence",
    "timestamp_utc",
    "correlation_id",
    "causation_id",
    "qos",
    "flags",
    "payload",
}


def make_envelope(
    *,
    type: str,
    source: Endpoint,
    payload: Mapping[str, Any],
    qos: QoS = QoS.RELIABLE,
    destination: Endpoint | None = None,
    flags: frozenset[str] | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    acp: str = "1.2",
    session_id: str | None = None,
    sequence: int | None = None,
) -> Envelope:
    return Envelope(
        acp=acp,
        message_id=new_uuid(),
        type=type,
        source=source,
        timestamp_utc=datetime.now(UTC),
        qos=qos,
        payload=dict(payload),
        flags=flags or frozenset(),
        destination=destination,
        session_id=session_id,
        sequence=sequence,
        correlation_id=correlation_id,
        causation_id=causation_id,
    )
