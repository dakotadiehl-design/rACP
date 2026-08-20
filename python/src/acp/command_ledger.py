"""Bounded command disposition ledger that survives session replacement."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .types import normalize_uuid


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class CommandRecord:
    command_id: str
    idempotency_key: str | None
    origin_node_id: str
    origin_instance_id: str
    origin_principal: str | None
    origin_session_id: str | None
    operation: str
    received_at: str
    disposition: str
    result: dict[str, Any]
    resulting_epoch: int | None
    resulting_revision: int | None
    expires_at: str | None

    def to_report(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "command_id": self.command_id,
            "origin_node_id": self.origin_node_id,
            "origin_instance_id": self.origin_instance_id,
            "operation": self.operation,
            "received_at": self.received_at,
            "disposition": self.disposition,
            "result": dict(self.result),
        }
        if self.idempotency_key:
            payload["idempotency_key"] = self.idempotency_key
        if self.origin_principal:
            payload["origin_principal"] = self.origin_principal
        if self.origin_session_id:
            payload["origin_session_id"] = self.origin_session_id
        if self.resulting_epoch is not None:
            payload["resulting_epoch"] = self.resulting_epoch
        if self.resulting_revision is not None:
            payload["resulting_revision"] = self.resulting_revision
        if self.expires_at:
            payload["expires_at"] = self.expires_at
        return payload


@dataclass
class CommandLedger:
    """Retention is keyed by origin node + command identity, never session alone."""

    max_records: int = 1024
    _by_command: dict[tuple[str, str], CommandRecord] = field(default_factory=dict)
    _by_idempotency: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    _order: list[tuple[str, str]] = field(default_factory=list)

    def remember(self, record: CommandRecord) -> CommandRecord:
        normalize_uuid(record.command_id)
        normalize_uuid(record.origin_node_id)
        normalize_uuid(record.origin_instance_id)
        key = (record.origin_node_id, record.command_id)
        existing = self._by_command.get(key)
        if existing is not None:
            if existing.operation != record.operation:
                raise ValueError("command_id reused with different operation")
            return existing
        if record.idempotency_key:
            normalize_uuid(record.idempotency_key)
            ikey = (record.origin_node_id, record.idempotency_key)
            prior = self._by_idempotency.get(ikey)
            if prior is not None:
                held = self._by_command[prior]
                if held.operation != record.operation:
                    raise ValueError("idempotency key reused with different operation")
                return held
            self._by_idempotency[ikey] = key
        if len(self._order) >= self.max_records:
            old = self._order.pop(0)
            dropped = self._by_command.pop(old, None)
            if dropped and dropped.idempotency_key:
                self._by_idempotency.pop((dropped.origin_node_id, dropped.idempotency_key), None)
        self._by_command[key] = record
        self._order.append(key)
        return record

    def lookup(
        self,
        *,
        origin_node_id: str,
        command_id: str | None = None,
        idempotency_key: str | None = None,
        origin_principal: str | None = None,
        origin_instance_id: str | None = None,
    ) -> CommandRecord | None:
        normalize_uuid(origin_node_id)
        rec: CommandRecord | None = None
        if command_id:
            rec = self._by_command.get((origin_node_id, normalize_uuid(command_id)))
        elif idempotency_key:
            mapped = self._by_idempotency.get((origin_node_id, normalize_uuid(idempotency_key)))
            if mapped:
                rec = self._by_command.get(mapped)
        if rec is None:
            return None
        if origin_principal is not None and rec.origin_principal not in (None, origin_principal):
            return None
        if origin_instance_id is not None and rec.origin_instance_id != normalize_uuid(origin_instance_id):
            return None
        return rec

    @staticmethod
    def make_record(
        *,
        command_id: str,
        origin_node_id: str,
        origin_instance_id: str,
        operation: str,
        disposition: str,
        idempotency_key: str | None = None,
        origin_principal: str | None = None,
        origin_session_id: str | None = None,
        result: dict[str, Any] | None = None,
        resulting_epoch: int | None = None,
        resulting_revision: int | None = None,
        expires_at: str | None = None,
        received_at: str | None = None,
    ) -> CommandRecord:
        return CommandRecord(
            command_id=command_id,
            idempotency_key=idempotency_key,
            origin_node_id=origin_node_id,
            origin_instance_id=origin_instance_id,
            origin_principal=origin_principal,
            origin_session_id=origin_session_id,
            operation=operation,
            received_at=received_at or _utc_now(),
            disposition=disposition,
            result=dict(result or {}),
            resulting_epoch=resulting_epoch,
            resulting_revision=resulting_revision,
            expires_at=expires_at,
        )
