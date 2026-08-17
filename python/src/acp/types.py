from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
VERSION_RE = re.compile(r"^([0-9]+)\.([0-9]+)$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")


class Role(str, Enum):
    CONDUCTOR = "conductor"
    PRISM = "prism"
    LYRIC = "lyric"
    BRIDGE = "bridge"
    TOOL = "tool"
    SIMULATOR = "simulator"


class QoS(str, Enum):
    RELIABLE = "reliable"
    LATEST = "latest"
    BEST_EFFORT = "best_effort"


class CommandStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    APPLIED = "applied"
    COMPLETED = "completed"
    FAILED = "failed"
    DUPLICATE = "duplicate"

    def terminal(self) -> bool:
        return self is not CommandStatus.ACCEPTED


class Confidence(str, Enum):
    UNVERIFIED = "unverified"
    SENT_ASSUMED = "sent_assumed"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    MISMATCH = "mismatch"


class HealthStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"


class Encoding(str, Enum):
    CBOR = "cbor"
    JSON = "json"


def normalize_uuid(value: str | uuid.UUID) -> str:
    text = str(value).strip().lower()
    if not UUID_RE.match(text):
        raise ValueError(f"invalid uuid: {value!r}")
    return text


def new_uuid() -> str:
    return str(uuid.uuid4())


def parse_version(text: str) -> tuple[int, int]:
    match = VERSION_RE.match(text)
    if not match:
        raise ValueError(f"invalid version: {text!r}")
    return int(match.group(1)), int(match.group(2))


def format_ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def parse_ts(text: str) -> datetime:
    if not TS_RE.match(text):
        raise ValueError(f"invalid timestamp_utc: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class Endpoint:
    node_id: str
    component_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", normalize_uuid(self.node_id))

    def to_dict(self) -> dict[str, str]:
        data = {"node_id": self.node_id}
        if self.component_id:
            data["component_id"] = self.component_id
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Endpoint:
        return cls(node_id=data["node_id"], component_id=data.get("component_id"))


@dataclass(frozen=True, slots=True)
class Capability:
    id: str
    version: str

    def to_dict(self) -> dict[str, str]:
        parse_version(self.version)
        return {"id": self.id, "version": self.version}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Capability:
        return cls(id=data["id"], version=data["version"])


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    node_id: str
    instance_id: str
    role: Role
    name: str
    product_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", normalize_uuid(self.node_id))
        object.__setattr__(self, "instance_id", normalize_uuid(self.instance_id))
        if isinstance(self.role, str):
            object.__setattr__(self, "role", Role(self.role))

    def to_dict(self) -> dict[str, str]:
        data = {
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "role": self.role.value,
            "name": self.name,
        }
        if self.product_version:
            data["product_version"] = self.product_version
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NodeIdentity:
        return cls(
            node_id=data["node_id"],
            instance_id=data["instance_id"],
            role=Role(data["role"]),
            name=data["name"],
            product_version=data.get("product_version"),
        )


@dataclass(frozen=True, slots=True)
class ProtocolRange:
    min: str
    max: str

    def __post_init__(self) -> None:
        lo = parse_version(self.min)
        hi = parse_version(self.max)
        if lo[0] != hi[0] or lo > hi:
            raise ValueError(f"invalid protocol range {self.min}-{self.max}")

    def to_dict(self) -> dict[str, str]:
        return {"min": self.min, "max": self.max}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProtocolRange:
        return cls(min=data["min"], max=data["max"])


TERMINAL_ACK = {
    CommandStatus.REJECTED,
    CommandStatus.APPLIED,
    CommandStatus.COMPLETED,
    CommandStatus.FAILED,
    CommandStatus.DUPLICATE,
}
