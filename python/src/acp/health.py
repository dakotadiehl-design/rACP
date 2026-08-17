from __future__ import annotations

from dataclasses import dataclass

from .constants import load as load_constants
from .types import HealthStatus


@dataclass
class HealthObserver:
    interval_ms: int = 1000
    missed: int = 0
    good: int = 0
    status: HealthStatus = HealthStatus.OFFLINE
    last_instance_id: str | None = None

    def __post_init__(self) -> None:
        cfg = load_constants()["heartbeat"]
        self.offline_after = int(cfg["offline_missed_intervals"])
        self.recover_after = int(cfg["recover_consecutive_goods"])

    def on_tick_without_heartbeat(self) -> HealthStatus:
        self.missed += 1
        self.good = 0
        if self.missed >= self.offline_after:
            self.status = HealthStatus.OFFLINE
        return self.status

    def on_heartbeat(self, status: HealthStatus, instance_id: str | None = None) -> HealthStatus:
        if instance_id and self.last_instance_id and instance_id != self.last_instance_id:
            # restart: go through offline hysteresis, then apply new status
            self.status = HealthStatus.OFFLINE
        if instance_id:
            self.last_instance_id = instance_id
        self.missed = 0
        if status is HealthStatus.OFFLINE:
            # observers derive offline; ignore self-reported offline
            status = HealthStatus.CRITICAL
        if self.status is HealthStatus.OFFLINE:
            self.good += 1
            if self.good >= self.recover_after:
                self.status = status
        else:
            self.good += 1
            self.status = status
        return self.status
