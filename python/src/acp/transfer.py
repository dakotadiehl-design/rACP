from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NamedTuple

from .constants import limits
from .envelope import Envelope, make_envelope
from .types import Endpoint, QoS, new_uuid


class TransferState(str, Enum):
    IDLE = "idle"
    OFFERED = "offered"
    ACCEPTED = "accepted"
    RECEIVING = "receiving"
    VERIFIED = "verified"
    ACTIVATING = "activating"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"


def _sha256_ok(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass
class Transfer:
    transfer_id: str
    asset: dict[str, Any]
    state: TransferState = TransferState.OFFERED
    ranges: list[tuple[int, int]] = field(default_factory=list)
    parts: dict[int, bytes] = field(default_factory=dict)
    staged: bytes | None = None
    live: bytes | None = None
    live_meta: dict[str, Any] | None = None
    max_chunk_bytes: int = 16384
    size: int = 0
    created_at: float = field(default_factory=time.monotonic)
    reserved_bytes: int = 0

    def accept(self, max_chunk: int | None = None) -> None:
        if max_chunk:
            self.max_chunk_bytes = min(self.max_chunk_bytes, max_chunk)
        self.state = TransferState.ACCEPTED

    def add_chunk(self, offset: int, data: bytes, declared_length: int | None = None) -> None:
        if self.state in {TransferState.REJECTED, TransferState.CANCELLED, TransferState.FAILED}:
            raise ValueError("transfer not receiving")
        if offset < 0 or len(data) <= 0:
            raise ValueError("invalid range")
        if declared_length is not None and declared_length != len(data):
            raise ValueError("length mismatch")
        if self.max_chunk_bytes <= 0 or len(data) > self.max_chunk_bytes:
            raise ValueError("oversize chunk")
        end = offset + len(data)
        if end < offset or end > self.size:
            raise ValueError("invalid range")
        existing = self.parts.get(offset)
        if existing is not None:
            if existing != data:
                self.state = TransferState.FAILED
                raise ValueError("duplicate offset with different bytes")
            return
        for start, stop in self.ranges:
            if offset < stop and end > start and not (offset == start and end == stop):
                overlap_same = start == offset and stop == end
                if not overlap_same:
                    self.state = TransferState.FAILED
                    raise ValueError("overlapping chunk")
        self.parts[offset] = data
        self.ranges.append((offset, end))
        self.ranges.sort()
        self.state = TransferState.RECEIVING

    def complete(self) -> str:
        if self.size < 0:
            self.state = TransferState.FAILED
            return "invalid_range"
        covered = 0
        cursor = 0
        for start, stop in sorted(self.ranges):
            if start > cursor:
                self.state = TransferState.FAILED
                return "incomplete"
            if start < cursor:
                self.state = TransferState.FAILED
                return "overlap"
            cursor = max(cursor, stop)
            covered = cursor
        if covered != self.size:
            self.state = TransferState.FAILED
            return "incomplete"
        buf = bytearray(self.size)
        for offset, data in self.parts.items():
            buf[offset : offset + len(data)] = data
        digest = hashlib.sha256(bytes(buf)).hexdigest()
        expected = self.asset.get("sha256")
        if digest != expected:
            self.state = TransferState.FAILED
            return "hash_mismatch"
        self.staged = bytes(buf)
        self.state = TransferState.VERIFIED
        return "verified"

    def activate(self) -> bool:
        if self.state is not TransferState.VERIFIED or self.staged is None:
            return False
        self.state = TransferState.ACTIVATING
        self.live = self.staged
        self.live_meta = dict(self.asset)
        self.state = TransferState.IDLE
        return True

    def cancel(self) -> None:
        self.state = TransferState.CANCELLED
        self.staged = None
        self.parts.clear()
        self.ranges.clear()


@dataclass
class TransferAgent:
    source: Endpoint
    profile: str = "full"
    transfers: dict[str, Transfer] = field(default_factory=dict)
    live_assets: dict[str, bytes] = field(default_factory=dict)
    ttl_s: float = 120.0

    @property
    def _limits(self) -> dict[str, int]:
        return limits(self.profile)

    def _purge(self) -> None:
        now = time.monotonic()
        drop = []
        for tid, xfer in self.transfers.items():
            expired = now - xfer.created_at > self.ttl_s and xfer.state not in {
                TransferState.IDLE,
            }
            terminal = xfer.state in {TransferState.FAILED, TransferState.CANCELLED, TransferState.REJECTED}
            if expired or terminal:
                drop.append(tid)
        for tid in drop:
            del self.transfers[tid]

    def _reserved(self) -> int:
        return sum(x.size for x in self.transfers.values() if x.state not in {
            TransferState.FAILED, TransferState.CANCELLED, TransferState.REJECTED, TransferState.IDLE,
        })

    def handle(self, env: Envelope) -> list[Envelope]:
        self._purge()
        out: list[Envelope] = []
        t = env.type
        payload = env.payload
        if t == "resource.offer":
            return self._offer(env, dict(payload))
        if t == "resource.chunk":
            return self._chunk(env, dict(payload))
        if t == "resource.complete":
            xfer = self.transfers.get(str(payload.get("transfer_id") or ""))
            if not xfer:
                return out
            status = xfer.complete()
            out.append(self._msg("resource.transfer_result", {
                "transfer_id": xfer.transfer_id,
                "status": "verified" if status == "verified" else "failed",
                "code": None if status == "verified" else status,
            }, env))
            return out
        if t == "resource.activate":
            xfer = self.transfers.get(str(payload.get("transfer_id") or ""))
            if not xfer:
                out.append(self._msg("resource.activation_result", {
                    "transfer_id": payload.get("transfer_id"), "status": "failed", "code": "not_found",
                }, env))
                return out
            prev = xfer.live
            ok = xfer.activate()
            if ok and xfer.live is not None:
                self.live_assets[xfer.asset["asset_id"]] = xfer.live
            elif not ok and prev is not None:
                self.live_assets[xfer.asset["asset_id"]] = prev
            out.append(self._msg("resource.activation_result", {
                "transfer_id": xfer.transfer_id,
                "status": "applied" if ok else "failed",
            }, env))
            return out
        if t == "resource.cancel":
            xfer = self.transfers.get(str(payload.get("transfer_id") or ""))
            if xfer:
                xfer.cancel()
            return out
        return out

    def _offer(self, env: Envelope, payload: dict[str, Any]) -> list[Envelope]:
        tid = payload.get("transfer_id")
        asset = payload.get("asset") or {}
        locator = payload.get("locator") or {}
        if not isinstance(tid, str):
            return [self._msg("resource.reject", {"transfer_id": "", "code": "invalid_type", "message": "bad id"}, env)]
        if locator.get("mode") == "http":
            return [self._msg("resource.reject", {
                "transfer_id": tid, "code": "unsupported", "message": "http locator not implemented",
            }, env)]
        if locator.get("mode") not in (None, "chunked"):
            return [self._msg("resource.reject", {"transfer_id": tid, "code": "unsupported"}, env)]
        raw_size = asset.get("size_bytes")
        try:
            if raw_size is None:
                raise TypeError("size_bytes required")
            size = int(raw_size)
        except (TypeError, ValueError):
            return [self._msg("resource.reject", {"transfer_id": tid, "code": "invalid_range"}, env)]
        max_total = self._limits["max_transfer_bytes"]
        over = self._reserved() + size > max_total * self._limits["max_concurrent_transfers"]
        if size < 0 or size > max_total or over:
            return [self._msg("resource.reject", {"transfer_id": tid, "code": "capacity", "message": "too large"}, env)]
        offered_chunk = payload.get("max_chunk_bytes")
        if offered_chunk is not None:
            try:
                offered_chunk_i = int(offered_chunk)
            except (TypeError, ValueError):
                return [self._msg("resource.reject", {"transfer_id": tid, "code": "invalid_range"}, env)]
            if offered_chunk_i <= 0:
                return [self._msg("resource.reject", {"transfer_id": tid, "code": "invalid_range"}, env)]
        if not _sha256_ok(asset.get("sha256")):
            return [self._msg(
                "resource.reject",
                {"transfer_id": tid, "code": "invalid_type", "message": "bad digest"},
                env,
            )]
        if tid in self.transfers and self.transfers[tid].state not in {
            TransferState.FAILED, TransferState.CANCELLED, TransferState.IDLE,
        }:
            return [self._msg("resource.reject", {"transfer_id": tid, "code": "conflict", "message": "active"}, env)]
        active = sum(1 for x in self.transfers.values() if x.state in {
            TransferState.OFFERED, TransferState.ACCEPTED, TransferState.RECEIVING, TransferState.VERIFIED,
        })
        if active >= self._limits["max_concurrent_transfers"]:
            return [self._msg("resource.reject", {"transfer_id": tid, "code": "capacity"}, env)]
        xfer = Transfer(
            transfer_id=tid,
            asset=asset,
            max_chunk_bytes=min(
                int(payload.get("max_chunk_bytes") or self._limits["max_chunk_bytes"]),
                self._limits["max_chunk_bytes"],
            ),
            size=size,
        )
        xfer.live = self.live_assets.get(str(asset.get("asset_id") or ""))
        xfer.accept(self._limits["max_chunk_bytes"])
        self.transfers[tid] = xfer
        return [self._msg("resource.accept", {
            "transfer_id": tid, "max_chunk_bytes": xfer.max_chunk_bytes,
        }, env)]

    def _chunk(self, env: Envelope, payload: dict[str, Any]) -> list[Envelope]:
        xfer = self.transfers.get(str(payload.get("transfer_id") or ""))
        if not xfer:
            return []
        data = payload.get("data")
        try:
            if isinstance(data, str):
                data = base64.b64decode(data, validate=True)
            elif not isinstance(data, (bytes, bytearray)):
                raise ValueError("chunk data must be bytes")
            raw_offset = payload.get("offset")
            if raw_offset is None:
                raise TypeError("offset required")
            offset = int(raw_offset)
            declared = payload.get("length")
            declared_i = int(declared) if declared is not None else None
            xfer.add_chunk(offset, bytes(data), declared_i)
        except (TypeError, ValueError):
            return [self._msg("resource.transfer_result", {
                "transfer_id": xfer.transfer_id, "status": "failed", "code": "conflict",
            }, env)]
        return []

    def _msg(self, typ: str, payload: dict[str, Any], cause: Envelope) -> Envelope:
        return make_envelope(
            type=typ,
            source=self.source,
            destination=cause.source,
            qos=QoS.RELIABLE,
            payload={k: v for k, v in payload.items() if v is not None},
            correlation_id=cause.correlation_id or cause.message_id,
            causation_id=cause.message_id,
        )


class Offer(NamedTuple):
    messages: list[Envelope]
    transfer_id: str
    asset: dict[str, Any]
    blob: bytes


def offer_bytes(source: Endpoint, dest: Endpoint, asset_id: str, blob: bytes, revision: int = 1) -> Offer:
    tid = new_uuid()
    digest = hashlib.sha256(blob).hexdigest()
    asset = {
        "asset_id": asset_id,
        "asset_type": "lyric.chart",
        "revision": revision,
        "sha256": digest,
        "size_bytes": len(blob),
    }
    msgs = [
        make_envelope(
            type="resource.offer",
            source=source,
            destination=dest,
            qos=QoS.RELIABLE,
            payload={"transfer_id": tid, "asset": asset, "locator": {"mode": "chunked"}},
        )
    ]
    return Offer(msgs, tid, asset, blob)
