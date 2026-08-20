"""Application-layer traffic classes and coalescing rules."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .state_revision import NEVER_COALESCE_ACTIONS

SAFETY = "safety"
INTERACTIVE = "interactive"
STATE = "state"
BACKGROUND = "background"
TELEMETRY = "telemetry"
ORDER = (SAFETY, INTERACTIVE, STATE, BACKGROUND, TELEMETRY)


@dataclass
class OutboundItem:
    traffic_class: str
    payload: Any
    coalescing_key: str | None = None
    delivery: str = "in_order"
    action: str | None = None


@dataclass
class PriorityQueue:
    capacities: dict[str, int] = field(
        default_factory=lambda: {
            SAFETY: 32,
            INTERACTIVE: 64,
            STATE: 128,
            BACKGROUND: 16,
            TELEMETRY: 8,
        }
    )
    _queues: dict[str, deque[OutboundItem]] = field(init=False)
    _state_keys: dict[str, OutboundItem] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._queues = {name: deque() for name in ORDER}

    def push(self, item: OutboundItem) -> bool:
        cls = item.traffic_class if item.traffic_class in self._queues else INTERACTIVE
        if item.action in NEVER_COALESCE_ACTIONS or item.delivery == "never_coalesce":
            item.coalescing_key = None
            item.delivery = "never_coalesce"
        if item.delivery == "latest_value_wins" and item.coalescing_key:
            self._state_keys[item.coalescing_key] = item
            return True
        q = self._queues[cls]
        if len(q) >= self.capacities[cls]:
            if cls == TELEMETRY:
                return False
            if cls == BACKGROUND:
                return False
            raise OverflowError(f"{cls} queue full")
        q.append(item)
        return True

    def pop(self) -> OutboundItem | None:
        for cls in ORDER:
            if cls == STATE and self._state_keys:
                key = next(iter(self._state_keys))
                return self._state_keys.pop(key)
            q = self._queues[cls]
            if q:
                return q.popleft()
        return None

    def paused_background(self) -> bool:
        return bool(self._queues[SAFETY] or self._queues[INTERACTIVE])
