"""Node-level bounded TTL idempotency cache."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .constants import load as load_constants
from .types import normalize_uuid


@dataclass
class IdempotencyRecord:
    status: str
    result: dict[str, Any]
    expires_at: float | None
    body_fingerprint: str


@dataclass
class IdempotencyCache:
    max_records: int = 1024
    retain_after_session_s: float = 60.0
    _items: dict[tuple[str, str, str], IdempotencyRecord] = field(default_factory=dict)

    @classmethod
    def from_profile(cls, profile: str = "full") -> IdempotencyCache:
        cfg = load_constants()
        limits = cfg["limits"][profile]
        retain_ms = int(cfg["idempotency"]["retain_after_session_ms"])
        return cls(max_records=int(limits["max_idempotency_records"]), retain_after_session_s=retain_ms / 1000)

    def _purge(self, now: float) -> None:
        expired = [k for k, rec in self._items.items() if rec.expires_at is not None and rec.expires_at <= now]
        for key in expired:
            del self._items[key]

    def remember(
        self,
        node_id: str,
        message_type: str,
        key: str,
        *,
        status: str,
        result: dict[str, Any],
        body_fingerprint: str,
    ) -> None:
        normalize_uuid(key)
        now = time.monotonic()
        self._purge(now)
        if len(self._items) >= self.max_records:
            oldest = next(iter(self._items))
            del self._items[oldest]
        self._items[(node_id, message_type, key)] = IdempotencyRecord(
            status=status,
            result=result,
            expires_at=None,
            body_fingerprint=body_fingerprint,
        )

    def lookup(
        self,
        node_id: str,
        message_type: str,
        key: str,
        body_fingerprint: str | None = None,
    ) -> IdempotencyRecord | None:
        self._purge(time.monotonic())
        rec = self._items.get((node_id, message_type, key))
        if rec is None:
            return None
        if body_fingerprint is not None and rec.body_fingerprint != body_fingerprint:
            raise ValueError("idempotency key reused with different request body")
        return rec

    def on_session_close(self) -> None:
        deadline = time.monotonic() + self.retain_after_session_s
        for rec in self._items.values():
            rec.expires_at = deadline
