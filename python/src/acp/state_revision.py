"""Authority epoch / revision helpers for snapshot and delta recovery."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class StateSyncRequired(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "remote.control.stale_state"


def snapshot_payload(
    *,
    authority_epoch: int,
    revision: int,
    resources: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "authority_epoch": authority_epoch,
        "revision": revision,
        "resources": resources,
    }


def revisioned_delta_payload(
    *,
    authority_epoch: int,
    base_revision: int,
    revision: int,
    changes: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "authority_epoch": authority_epoch,
        "base_revision": base_revision,
        "revision": revision,
        "changes": changes,
    }


def apply_delta(
    local_epoch: int,
    local_revision: int,
    payload: Mapping[str, Any],
) -> tuple[int, int]:
    """Return the new (epoch, revision) or raise if a snapshot is required.

    Legacy single-resource deltas have no envelope epoch; they increment local
    revision only when the receiver is already synchronized.
    """
    if "changes" in payload and "authority_epoch" in payload:
        epoch = int(payload["authority_epoch"])
        base = int(payload["base_revision"])
        revision = int(payload["revision"])
        if epoch != local_epoch:
            raise StateSyncRequired("authority_epoch mismatch")
        if base != local_revision:
            raise StateSyncRequired("base_revision mismatch")
        if revision <= local_revision:
            raise StateSyncRequired("delta revision did not advance")
        return epoch, revision
    return local_epoch, local_revision + 1


NEVER_COALESCE_ACTIONS = frozenset(
    {
        "performance.go",
        "performance.back",
        "cue.fire",
        "cue.go",
        "momentary.begin",
        "momentary.end",
        "blackoutOn",
        "blackoutOff",
    }
)
