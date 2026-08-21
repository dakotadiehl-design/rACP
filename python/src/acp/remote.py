"""Aurora Remote Profile — protocol models and authoritative fail-safe engine.

Remote sends intent. This module never drives DMX, Art-Net, MIDI, or vendor I/O.
Effective permissions are server-authoritative. Layout metadata never grants access.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .constants import load as load_constants
from .envelope import Envelope, make_envelope
from .idempotency import IdempotencyCache
from .negotiate import REMOTE_PROFILE_CONDUCTOR, REMOTE_PROFILE_PRISM, version_at_least
from .persist import NodeStore
from .registry import load_registry
from .session import ReliableOverflow, Session, SessionError, SessionState, make_ack
from .transfer import Transfer, TransferAgent, TransferState
from .types import CommandStatus, Endpoint, QoS, Role, format_ts, new_uuid, parse_ts
from .validate import ValidationError, validate_message

REMOTE_CAPABILITIES = (
    "remote.profile",
    "remote.layout",
    "remote.control.invoke",
    "remote.control.momentary",
    "remote.control.state",
    "remote.navigation.song",
    "remote.navigation.section",
    "remote.navigation.cue",
    "remote.transport",
    "remote.busking",
    "remote.readiness",
    "remote.asset_sync",
    "remote.presentation",
)

REMOTE_ROLES = (
    "remote.viewer",
    "remote.operator",
    "remote.busker",
    "remote.show_navigation",
    "remote.admin",
)

VIEWER_ROLE = "remote.viewer"
ADMIN_ROLE = "remote.admin"
ROLE_CONSTRAINTS = frozenset(REMOTE_ROLES)

MOMENTARY_INTERACTIONS = frozenset({"momentary_begin", "momentary_end", "momentary_cancel"})

CONTROL_INTERACTIONS: dict[str, frozenset[str]] = {
    "button": frozenset({"activate"}),
    "momentary": MOMENTARY_INTERACTIONS,
    "toggle": frozenset({"set"}),
    "slider": frozenset({"set", "adjust"}),
    "encoder": frozenset({"set", "adjust"}),
    "selector": frozenset({"set"}),
    "xy": frozenset({"set", "adjust"}),
    "transport": frozenset({"activate"}),
    "navigation": frozenset({"activate"}),
    "color": frozenset({"set", "adjust"}),
    "preset_tile": frozenset({"activate"}),
}

DEFAULT_FAILSAFE = "release_on_disconnect"
DEFAULT_MAX_HOLD_MS = 10_000

# Authority-owned allowlist. Unknown actions are rejected.
ACTION_POLICY: dict[str, str] = {
    "cue.go": "remote.operator",
    "nav.go": "remote.operator",
    "busk.fog.output": "remote.busker",
    "busk.work_lights": "remote.operator",
    "busk.blinder": "remote.busker",
    "bridge.blackout": "remote.admin",
    "output.blackout.set": "remote.admin",
    "output.grand_master.set": "remote.operator",
    "transport.play": "remote.operator",
    "transport.stop": "remote.operator",
    "nav.song.select": "remote.show_navigation",
    "nav.section.enter": "remote.show_navigation",
    "show.song.select": "remote.viewer",
    "show.song.load": "remote.viewer",
    "show.song.stop": "remote.operator",
    "show.song.next": "remote.show_navigation",
    "show.song.previous": "remote.show_navigation",
    "show.section.next": "remote.operator",
    "show.section.previous": "remote.operator",
    "show.section.restart": "remote.operator",
    "show.progression.hold": "remote.operator",
    "show.free_play.enter": "remote.operator",
    "show.free_play.exit": "remote.operator",
    "look.recall": "remote.operator",
    "look.preview": "remote.operator",
    "look.take": "remote.operator",
    "look.preview.cancel": "remote.operator",
    "effects.stop": "remote.operator",
}

ACTION_FEATURE: dict[str, str] = {
    "cue.go": "cue.go",
    "nav.go": "cue.go",
    "busk.fog.output": "busk.controls",
    "busk.work_lights": "busk.controls",
    "busk.blinder": "busk.controls",
    "bridge.blackout": "output.blackout",
    "output.blackout.set": "output.blackout",
    "output.grand_master.set": "output.grand_master",
    "transport.play": "show.navigation",
    "transport.stop": "show.navigation",
    "nav.song.select": "song.selection",
    "nav.section.enter": "show.navigation",
    "show.song.select": "song.selection",
    "show.song.load": "song.loading",
    "show.song.stop": "song.loading",
    "show.song.next": "song.selection",
    "show.song.previous": "song.selection",
    "show.section.next": "show.navigation",
    "show.section.previous": "show.navigation",
    "show.section.restart": "show.navigation",
    "show.progression.hold": "show.navigation",
    "show.free_play.enter": "show.navigation",
    "show.free_play.exit": "show.navigation",
    "look.recall": "look.global",
    "look.preview": "look.global",
    "look.take": "look.global",
    "look.preview.cancel": "look.global",
    "effects.stop": "look.global",
}

ACTION_DELIVERY: dict[str, str] = dict(load_constants()["remote"]["action_delivery"])

PERMISSION_FOR_ACTION: dict[str, str] = {
    "cue.go": "cue.execute",
    "nav.go": "cue.execute",
    "busk.fog.output": "busk.execute",
    "busk.work_lights": "busk.execute",
    "busk.blinder": "busk.execute",
    "bridge.blackout": "output.blackout",
    "output.blackout.set": "output.blackout",
    "output.grand_master.set": "output.grand_master",
    "nav.song.select": "song.select",
    "nav.section.enter": "song.select",
    "transport.play": "song.load",
    "transport.stop": "song.load",
    "show.free_play.enter": "song.load",
    "show.free_play.exit": "song.load",
    "show.song.select": "song.select",
    "show.song.load": "song.load",
    "show.song.stop": "song.load",
    "show.song.next": "song.select",
    "show.song.previous": "song.select",
    "show.section.next": "cue.execute",
    "show.section.previous": "cue.execute",
    "show.section.restart": "cue.execute",
    "show.progression.hold": "cue.execute",
    "look.recall": "look.execute",
    "look.preview": "look.execute",
    "look.take": "look.execute",
    "look.preview.cancel": "look.execute",
    "effects.stop": "look.execute",
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "remote.viewer": frozenset({"observe", "remote.surface.use"}),
    "remote.show_navigation": frozenset({"observe", "remote.surface.use", "song.select", "song.load"}),
    "remote.operator": frozenset({
        "observe", "remote.surface.use", "song.select", "song.load",
        "cue.execute", "look.execute", "output.grand_master",
    }),
    "remote.busker": frozenset({"observe", "remote.surface.use", "busk.execute"}),
    "remote.admin": frozenset({
        "observe", "remote.surface.use", "song.select", "song.load",
        "cue.execute", "look.execute", "busk.execute",
        "output.grand_master", "output.blackout",
    }),
}

CONTROL_TYPE_ALIASES = {
    "momentary_button": "momentary",
    "fader": "slider",
    "rotary": "encoder",
    "segmented_selector": "selector",
    "xy_pad": "xy",
    "color_control": "color",
}

DISPLAY_ONLY_TYPES = frozenset({
    "label", "value_display", "status_indicator", "status", "meter", "group", "spacer",
})
EXECUTABLE_SURFACE_KEYS = frozenset(load_constants()["remote"]["executable_surface_keys"])
MAX_LIVE_EPHEMERAL_AGE_MS = 5_000
MAX_CLOCK_SKEW_MS = 2_000
SAFETY_STATE_VERSION = 2
MAX_EMERGENCY_RELEASE_ATTEMPTS = 8
EMERGENCY_RETRY_MS = 50
SURFACE_CHUNK_BYTES = 16_384
INLINE_SURFACE_CAPABILITY = "remote.surface.inline"
FINGERPRINT_SKIP = frozenset({"client_timestamp_utc", "issued_at", "expires_at", "max_age_ms"})
STABLE_OUTCOMES = {
    "unauthorized": {"category": "authorization", "retryable": False},
    "unsupported": {"category": "validation", "retryable": False},
    "invalid_state": {"category": "conflict", "retryable": False},
    "stale": {"category": "validation", "retryable": False},
    "expired": {"category": "timeout", "retryable": False},
    "conflict": {"category": "conflict", "retryable": False},
    "not_found": {"category": "not_found", "retryable": False},
    "rate_limited": {"category": "unavailable", "retryable": True},
    "internal": {"category": "internal", "retryable": True},
    "timeout": {"category": "timeout", "retryable": True},
}
CODE_OUTCOMES: dict[str, str] = {
    "remote.control.permission_denied": "unauthorized",
    "capability_not_permitted": "unauthorized",
    "authentication": "unauthorized",
    "remote.session.not_ready": "unauthorized",
    "remote.control.not_armed": "unauthorized",
    "remote.control.disabled": "unauthorized",
    "unsupported": "unsupported",
    "remote.control.unknown": "not_found",
    "remote.layout.missing": "not_found",
    "remote.momentary.unknown_invocation": "not_found",
    "not_found": "not_found",
    "remote.command.invalid_state": "invalid_state",
    "remote.control.unavailable": "invalid_state",
    "remote.layout.invalid": "invalid_state",
    "remote.layout.incompatible": "invalid_state",
    "remote.control.invalid_interaction": "invalid_state",
    "remote.control.invalid_value": "invalid_state",
    "remote.layout.stale": "stale",
    "remote.control.stale_state": "stale",
    "remote.command.expired": "expired",
    "remote.momentary.expired": "expired",
    "remote.control.conflict": "conflict",
    "conflict": "conflict",
    "remote.command.rate_limited": "rate_limited",
    "timeout": "timeout",
    "internal": "internal",
    "hash_mismatch": "invalid_state",
    "remote.control.unconfirmed_release": "invalid_state",
}
CODE_RETRYABLE = {
    "remote.control.conflict": True,
    "remote.control.stale_state": True,
    "remote.control.unavailable": True,
    "remote.session.not_ready": True,
    "timeout": True,
    "internal": True,
    "remote.command.rate_limited": True,
    "remote.control.unconfirmed_release": True,
}
NAMESPACE_POLICY: dict[str, tuple[str, str | None]] = {
    "cue.current": ("observe", "cue.go"),
    "cue.next": ("observe", "cue.go"),
    "show.current_song": ("observe", "show.navigation"),
    "show.selected_song": ("observe", "song.selection"),
    "show.current_section": ("observe", "show.navigation"),
    "show.next_section": ("observe", "show.navigation"),
    "show.running": ("observe", "show.navigation"),
    "show.progression": ("observe", "show.navigation"),
    "show.mode": ("observe", "show.navigation"),
    "show.setlist": ("observe", "show.navigation"),
    "look.catalog": ("observe", "look.global"),
    "look.current": ("observe", "look.global"),
    "look.preview": ("observe", "look.global"),
    "output.blackout": ("observe", "output.blackout"),
    "output.grand_master": ("observe", "output.grand_master"),
    "output.status": ("observe", "state.live"),
    "system.health": ("observe", "system.health"),
    "system.warnings": ("observe", "system.health"),
    "engine.status": ("observe", "system.health"),
    "remote.control_state": ("observe", "remote.control.state"),
    "show.navigation": ("observe", "show.navigation"),
    "show.presentation": ("observe", "remote.presentation"),
}
DEFAULT_REMOTE_NAMESPACES = frozenset(NAMESPACE_POLICY)
LIVE_EPHEMERAL_NAV_KIND = "go"
ACTION_VALUE_BOUNDS: dict[str, tuple[float, float]] = {
    "output.grand_master.set": (0.0, 1.0),
}
SURFACE_LIMITS = {
    "max_pages": 32,
    "max_groups_per_page": 16,
    "max_controls": 256,
    "max_label_chars": 80,
    "max_surface_bytes": 65_536,
    "max_nesting": 6,
}
CLIENT_SURFACE_SCHEMA = "1.0"
DEFAULT_LOOKS = (
    {
        "look_id": "slow_song",
        "name": "Slow Song",
        "default_transition": {"transition_mode": "fade", "transition_ms": 2500},
    },
    {
        "look_id": "full_white",
        "name": "Full White",
        "default_transition": {"transition_mode": "cut", "transition_ms": 0},
    },
    {
        "look_id": "blue_ballad",
        "name": "Blue Ballad",
        "default_transition": {"transition_mode": "fade", "transition_ms": 1800},
    },
)

SAFETY_MIN = {
    "normal": "remote.viewer",
    "caution": "remote.operator",
    "dangerous": "remote.admin",
}

ALLOWED_TARGETS = frozenset({"prism", "conductor", "bridge"})
NAV_KINDS = frozenset({"browse", "select", "load", "next", "previous", "go"})
REMOTE_CLIENT_ROLES = frozenset({Role.REMOTE, Role.TOOL, Role.SIMULATOR})
INTERACTIVE_TYPES = frozenset({
    "remote.control.invoke",
    "remote.momentary.refresh",
    "remote.navigation.request",
})
READY_STATES = frozenset({"ready", "ready_with_warnings"})
CLAIM_FIELDS = ("device_id", "remote_id", "participant_id", "operator_id")


def required_permissions(control: dict[str, Any]) -> frozenset[str]:
    """Independent role predicates. Layout permission may only add a constraint."""
    binding = control.get("binding") or {}
    action = str(binding.get("action") or "")
    action_role = ACTION_POLICY.get(action)
    if action_role is None:
        raise ValueError(f"unknown action {action}")
    safety = (control.get("safety") or {}).get("class") or "normal"
    safety_role = SAFETY_MIN.get(str(safety), "remote.operator")
    needed: set[str] = set()
    if action_role != VIEWER_ROLE:
        needed.add(action_role)
    if safety_role != VIEWER_ROLE:
        needed.add(safety_role)
    if not needed:
        needed.add(VIEWER_ROLE)
    hint = control.get("permission")
    if hint:
        hint_s = str(hint)
        if hint_s == VIEWER_ROLE and needed - {VIEWER_ROLE}:
            raise ValueError("layout permission weaker than authority policy")
        if hint_s != VIEWER_ROLE:
            if hint_s not in ROLE_CONSTRAINTS and hint_s not in PERMISSION_FOR_ACTION.values():
                raise ValueError(f"unknown layout permission {hint_s}")
            needed.add(hint_s)
    return frozenset(needed)


def permissions_for_roles(roles: set[str]) -> set[str]:
    granted: set[str] = set()
    for role in roles:
        granted |= set(ROLE_PERMISSIONS.get(role, ()))
    if ADMIN_ROLE in roles:
        granted |= set(ROLE_PERMISSIONS[ADMIN_ROLE])
    return granted


def has_permissions(roles: set[str], needed: frozenset[str] | set[str]) -> bool:
    if ADMIN_ROLE in roles:
        return True
    granted = permissions_for_roles(roles)
    role_needed = {item for item in needed if item in ROLE_CONSTRAINTS}
    perm_needed = {item for item in needed if item not in ROLE_CONSTRAINTS}
    if role_needed and not role_needed.issubset(roles):
        return False
    if perm_needed and not perm_needed.issubset(granted):
        return False
    return True


def normalize_control_type(control_type: str) -> str:
    return CONTROL_TYPE_ALIASES.get(control_type, control_type)


def surface_id_of(layout: dict[str, Any]) -> str | None:
    return layout.get("surface_id") or layout.get("layout_id")


def default_delivery(action: str, interaction: str) -> str:
    if interaction in MOMENTARY_INTERACTIONS:
        return "live_ephemeral"
    return ACTION_DELIVERY.get(action, "impulse" if interaction == "activate" else "stateful")


def required_permission(control: dict[str, Any]) -> str:
    """Compatibility helper: one label from the required set (not a rank)."""
    needed = required_permissions(control)
    for role in ("remote.admin", "remote.busker", "remote.show_navigation", "remote.operator", "remote.viewer"):
        if role in needed:
            return role
    return next(iter(needed))


def _fingerprint(payload: dict[str, Any]) -> str:
    body = {k: payload[k] for k in sorted(payload) if k not in FINGERPRINT_SKIP}
    raw = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _outcome_for(code: str) -> str:
    return CODE_OUTCOMES.get(code, "unsupported" if code == "unsupported" else "invalid_state")


def _disposition(code: str) -> str:
    return _outcome_for(code)


def _error_fields(code: str, message: str, *, retryable: bool | None = None) -> dict[str, Any]:
    outcome = _outcome_for(code)
    spec = STABLE_OUTCOMES.get(outcome, STABLE_OUTCOMES["invalid_state"])
    retry = spec["retryable"] if retryable is None else retryable
    if retryable is None and code in CODE_RETRYABLE:
        retry = CODE_RETRYABLE[code]
    return {
        "code": code,
        "category": spec["category"],
        "severity": "error" if outcome != "unauthorized" or code != "remote.control.unconfirmed_release" else "error",
        "message": message,
        "retryable": bool(retry),
        "details": {"disposition": outcome},
    }


def _reject_executable(value: Any, *, depth: int = 0) -> None:
    if depth > SURFACE_LIMITS["max_nesting"]:
        raise ValueError("surface nesting too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            norm = str(key).lower().replace("-", "_")
            if norm in EXECUTABLE_SURFACE_KEYS or norm.startswith("on_") or "://" in str(item):
                raise ValueError("executable surface payload")
            _reject_executable(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _reject_executable(item, depth=depth + 1)


def layout_fingerprint(layout: dict[str, Any]) -> str:
    body = {k: layout[k] for k in sorted(layout) if k != "sha256"}
    raw = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionContext:
    session_id: str
    node_id: str
    invocation_id: str
    control_id: str
    interaction: str
    lease_id: str | None = None
    value: Any = None
    reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionResult:
    ok: bool
    status: str = "applied"
    code: str | None = None
    message: str | None = None
    retryable: bool = False
    value: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


class ActionRouter(Protocol):
    """Authority-owned semantic apply/release path. Protocol acks follow this result."""

    def apply(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult: ...
    def begin(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult: ...
    def refresh(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult: ...
    def end(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult: ...
    def force_release(self, action: str, control: dict[str, Any] | None, ctx: ActionContext) -> ActionResult: ...


class MemoryActionRouter:
    """In-process router used by tests and the demo. Not a show-control adapter."""

    def __init__(self, authority: RemoteAuthority | None = None) -> None:
        self.authority = authority
        self.refresh_count = 0

    def bind(self, authority: RemoteAuthority) -> None:
        self.authority = authority

    def apply(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult:
        auth = self._auth()
        cid = control.get("control_id") or ctx.control_id
        extra = dict(ctx.extra)
        if action in {"cue.go", "nav.go"} or cid in {"cue_go", "go"}:
            auth.go_count += 1
            prev = auth.cue_id
            auth.cue_id = auth.next_cue_id
            auth.next_cue_id = f"cue_{auth.go_count + 2}"
            return ActionResult(ok=True, extra={"cue_id": auth.cue_id, "previous_cue_id": prev})
        if action == "show.song.select":
            auth.selected_song_id = str(extra.get("song_id") or ctx.value or auth.selected_song_id)
            return ActionResult(ok=True, extra={"song_id": auth.selected_song_id, "loaded": False})
        if action == "show.song.load":
            auth.song_id = str(extra.get("song_id") or ctx.value or auth.song_id)
            auth.selected_song_id = auth.song_id
            return ActionResult(ok=True, extra={"song_id": auth.song_id, "loaded": True})
        if action == "show.free_play.enter":
            auth.enter_free_play()
            return ActionResult(ok=True, extra={"mode": auth.mode, "return_context": dict(auth.return_context)})
        if action == "show.free_play.exit":
            auth.exit_free_play()
            return ActionResult(ok=True, extra={"mode": auth.mode, "return_context": dict(auth.return_context)})
        if action in {"look.recall", "look.take"}:
            look_id = str(extra.get("look_id") or ctx.value or "")
            try:
                trans = auth.apply_look(look_id, extra.get("transition"), override=action == "look.take")
            except ValueError as exc:
                code = "remote.command.invalid_state" if "override" in str(exc) else "not_found"
                return ActionResult(ok=False, code=code, message=str(exc))
            return ActionResult(ok=True, extra={"look_id": look_id, "transition": trans})
        if action == "look.preview":
            auth.preview_look_id = str(extra.get("look_id") or ctx.value or "")
            return ActionResult(ok=True, extra={"look_id": auth.preview_look_id})
        if action == "look.preview.cancel":
            auth.preview_look_id = None
            return ActionResult(ok=True, extra={"look_id": None})
        if action in {"output.blackout.set", "bridge.blackout"}:
            auth.blackout = bool(ctx.value if ctx.value is not None else extra.get("value"))
            return ActionResult(ok=True, value=auth.blackout)
        if action == "output.grand_master.set":
            auth.grand_master = float(ctx.value if ctx.value is not None else extra.get("value") or 0)
            return ActionResult(ok=True, value=auth.grand_master)
        if control.get("control_type") == "toggle":
            auth.values[cid] = bool(ctx.value)
        elif ctx.interaction in {"set", "adjust"}:
            auth.values[cid] = ctx.value
        return ActionResult(ok=True, value=auth.values.get(cid, True))

    def begin(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        return ActionResult(ok=True)

    def refresh(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        self.refresh_count += 1
        return ActionResult(ok=True)

    def end(self, action: str, control: dict[str, Any], ctx: ActionContext) -> ActionResult:
        del action, control, ctx
        return ActionResult(ok=True)

    def force_release(self, action: str, control: dict[str, Any] | None, ctx: ActionContext) -> ActionResult:
        del action, control
        return ActionResult(ok=True, extra={"reason": ctx.reason or "forced"})

    def _auth(self) -> RemoteAuthority:
        if self.authority is None:
            raise RuntimeError("MemoryActionRouter is not bound to an authority")
        return self.authority


@dataclass(frozen=True, slots=True)
class Enrollment:
    """Server-owned binding from an authenticated node to claimed Remote IDs."""

    node_id: str
    device_id: str | None = None
    remote_id: str | None = None
    participant_id: str | None = None
    operator_id: str | None = None


@dataclass(frozen=True, slots=True)
class RemoteIdentity:
    node_id: str
    instance_id: str
    device_id: str
    remote_id: str
    device_name: str
    platform: str
    app_version: str
    participant_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "device_id": self.device_id,
            "remote_id": self.remote_id,
            "device_name": self.device_name,
            "platform": self.platform,
            "app_version": self.app_version,
        }
        if self.participant_id:
            data["participant_id"] = self.participant_id
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemoteIdentity:
        return cls(
            node_id=data["node_id"],
            instance_id=data["instance_id"],
            device_id=data["device_id"],
            remote_id=data["remote_id"],
            device_name=data["device_name"],
            platform=data["platform"],
            app_version=data["app_version"],
            participant_id=data.get("participant_id"),
        )


@dataclass
class Hold:
    invocation_id: str
    session_id: str
    node_id: str
    control_id: str
    started_ms: int
    max_hold_ms: int
    failsafe: str
    lease_id: str
    value: Any = 1.0
    expires_at_ms: int = 0
    release_pending: bool = False
    release_reason: str | None = None
    physical_active: bool = True


@dataclass
class RemoteAuthority:
    """Server-side Remote Profile. Owns fail-safe timers and permission checks."""

    source: Endpoint
    show_id: str
    show_revision: int = 1
    layout: dict[str, Any] = field(default_factory=dict)
    now_ms: int = 0
    armed: bool = True
    cue_id: str = "cue_1"
    next_cue_id: str = "cue_2"
    song_id: str = "haywire"
    next_song_id: str = "encore"
    playlist: list[str] = field(default_factory=lambda: ["haywire", "encore", "closer"])
    go_count: int = 0
    permissions_revision: int = 1
    policy: dict[str, set[str]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    holds: dict[str, dict[str, Hold]] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    revisions: dict[str, int] = field(default_factory=dict)
    browsing: dict[str, str] = field(default_factory=dict)
    effects: dict[str, bool] = field(default_factory=dict)
    last_releases: list[dict[str, Any]] = field(default_factory=list)
    idempotency: IdempotencyCache = field(default_factory=IdempotencyCache.from_profile)
    enrollment: dict[str, Enrollment] = field(default_factory=dict)
    _bound_device: dict[str, str] = field(default_factory=dict)
    _bound_remote: dict[str, str] = field(default_factory=dict)
    _bound_participant: dict[str, str] = field(default_factory=dict)
    _bound_operator: dict[str, str] = field(default_factory=dict)
    authority_epoch: int = 1
    snapshot_revision: int = 1
    router: ActionRouter | None = None
    store: NodeStore | None = None
    allowed_remote_profiles: set[str] = field(default_factory=lambda: {REMOTE_PROFILE_PRISM})
    selected_song_id: str = "haywire"
    section_id: str = "intro"
    next_section_id: str = "verse"
    running: bool = False
    progression_held: bool = False
    mode: str = "programmed"
    return_context: dict[str, Any] = field(default_factory=dict)
    looks: list[dict[str, Any]] = field(default_factory=lambda: [dict(item) for item in DEFAULT_LOOKS])
    current_look_id: str | None = None
    preview_look_id: str | None = None
    blackout: bool = False
    grand_master: float = 1.0
    apply_seq: int = 0
    client_surface_schema: str = CLIENT_SURFACE_SCHEMA
    last_committed: dict[str, Any] = field(default_factory=dict)
    _active_features: set[str] | None = None
    use_manual_clock: bool = False
    clock_ms: Callable[[], int] = field(default=lambda: int(time.monotonic() * 1000))
    max_live_ephemeral_age_ms: int = MAX_LIVE_EPHEMERAL_AGE_MS
    setlist_id: str = "main"
    setlist_name: str = "Tonight"
    songs: list[dict[str, Any]] = field(default_factory=lambda: [
        {"song_id": "haywire", "title": "Haywire", "order": 0, "status": "current"},
        {"song_id": "encore", "title": "Encore", "order": 1, "status": "next"},
        {"song_id": "closer", "title": "Closer", "order": 2, "status": "queued"},
    ])
    health: dict[str, Any] = field(default_factory=lambda: {"engine": "ok", "output": "ok", "network": "ok"})
    subscriptions: dict[str, set[str]] = field(default_factory=dict)
    _outbound: dict[str, list[Envelope]] = field(default_factory=dict)
    _surface_transfers: dict[str, Transfer] = field(default_factory=dict)
    _surface_offers: dict[str, dict[str, Any]] = field(default_factory=dict)
    unsafe_releases: list[dict[str, Any]] = field(default_factory=list)
    inline_surface: bool = False
    _scheduler_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _scheduler_wakeup: asyncio.Event | None = field(default=None, init=False, repr=False)
    _outbound_event: asyncio.Event | None = field(default=None, init=False, repr=False)
    _emergency_attempts: dict[tuple[str, str], int] = field(default_factory=dict)
    _safety_events: list[dict[str, Any]] = field(default_factory=list)
    reject_activation: bool = False
    _live_surface_meta: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.router is None:
            self.router = MemoryActionRouter(self)
        elif isinstance(self.router, MemoryActionRouter) and self.router.authority is None:
            self.router.bind(self)
        if not self.selected_song_id:
            self.selected_song_id = self.song_id

    def now(self) -> int:
        if self.use_manual_clock:
            return self.now_ms
        return int(self.clock_ms())

    def expire_due(self) -> list[str]:
        now = self.now()
        released = self._release_holds(
            lambda h: bool(h.expires_at_ms) and now >= h.expires_at_ms and not h.release_pending,
            reason="expiry",
        )
        released.extend(self.retry_unsafe_releases())
        return released

    def nearest_deadline_ms(self) -> int | None:
        deadlines: list[int] = []
        for group in self.holds.values():
            for hold in group.values():
                if hold.release_pending:
                    deadlines.append(self.now() + EMERGENCY_RETRY_MS)
                elif hold.expires_at_ms:
                    deadlines.append(hold.expires_at_ms)
        return min(deadlines) if deadlines else None

    def notify_schedule(self) -> None:
        wakeup = self._scheduler_wakeup
        if wakeup is not None:
            wakeup.set()

    def notify_publications(self) -> None:
        ev = self._outbound_event
        if ev is not None:
            ev.set()

    def start_scheduler(self) -> asyncio.Task[None]:
        if self._outbound_event is None:
            self._outbound_event = asyncio.Event()
        if self._scheduler_task is None or self._scheduler_task.done():
            self._scheduler_task = asyncio.create_task(self.run_scheduler(), name="remote-lease-expiry")
        return self._scheduler_task

    async def wait_outbound(self) -> None:
        ev = self._outbound_event
        if ev is None:
            self._outbound_event = asyncio.Event()
            ev = self._outbound_event
        await ev.wait()
        ev.clear()

    async def run_scheduler(self) -> None:
        self._scheduler_wakeup = asyncio.Event()
        try:
            while True:
                deadline = self.nearest_deadline_ms()
                if deadline is None:
                    self._scheduler_wakeup.clear()
                    await self._scheduler_wakeup.wait()
                    continue
                delay = max(0.0, (deadline - self.now()) / 1000.0)
                self._scheduler_wakeup.clear()
                try:
                    await asyncio.wait_for(self._scheduler_wakeup.wait(), timeout=delay)
                except TimeoutError:
                    self.expire_due()
        except asyncio.CancelledError:
            self._release_holds(lambda _h: True, reason="shutdown")
            self.notify_publications()
            raise

    async def stop_scheduler(self) -> None:
        task = self._scheduler_task
        if task is None:
            self._release_holds(lambda _h: True, reason="shutdown")
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        self._scheduler_task = None
        self._scheduler_wakeup = None

    def retry_unsafe_releases(self) -> list[str]:
        def pred(hold: Hold) -> bool:
            if not hold.release_pending:
                return False
            key = (hold.control_id, hold.invocation_id)
            attempts = self._emergency_attempts.get(key, 0)
            if attempts >= MAX_EMERGENCY_RELEASE_ATTEMPTS:
                return False
            self._emergency_attempts[key] = attempts + 1
            return True

        return self._release_holds(pred, reason="emergency_retry")

    def take_outbound(self, session_id: str) -> list[Envelope]:
        return self._outbound.pop(session_id, [])

    def enter_free_play(self) -> None:
        if self.mode == "free_play":
            return
        try:
            position = self.playlist.index(self.song_id)
        except ValueError:
            position = 0
        self.return_context = {
            "return_song_id": self.song_id,
            "return_position": position,
            "return_cue_id": self.cue_id,
            "return_section_id": self.return_context.get("return_section_id"),
        }
        self.mode = "free_play"

    def exit_free_play(self) -> None:
        ctx = dict(self.return_context)
        if ctx.get("return_song_id"):
            self.song_id = str(ctx["return_song_id"])
            self.selected_song_id = self.song_id
        if ctx.get("return_cue_id"):
            self.cue_id = str(ctx["return_cue_id"])
        self.mode = "programmed"

    def apply_look(
        self,
        look_id: str,
        requested: dict[str, Any] | None,
        *,
        override: bool,
    ) -> dict[str, Any]:
        catalog = next((item for item in self.looks if item.get("look_id") == look_id), None)
        if catalog is None:
            raise ValueError(f"unknown look {look_id}")
        default = dict(catalog.get("default_transition") or {"transition_mode": "cut", "transition_ms": 0})
        allowed = catalog.get("remote_transition_override_allowed", True)
        if requested and not allowed and not override:
            raise ValueError("look transition override not allowed")
        transition = dict(default)
        if requested and (allowed or override):
            transition.update({k: v for k, v in requested.items() if v is not None})
        self.current_look_id = look_id
        self.preview_look_id = None
        return transition

    def _router(self) -> ActionRouter:
        if self.router is None:
            self.router = MemoryActionRouter(self)
        return self.router

    def authorize(self, node_id: str, roles: list[str]) -> None:
        """Authorize the authenticated node principal. Never a client-asserted device/remote ID."""
        self.policy[node_id] = set(roles)
        self.permissions_revision += 1
        self.authority_epoch += 1
        self._bump_session_epochs()
        self._reconcile_holds()

    def grant(self, node_id: str, roles: list[str]) -> None:
        self.authorize(node_id, roles)

    def enroll(self, enrollment: Enrollment, roles: list[str] | None = None) -> None:
        """Bind claimed Remote IDs to a server-authenticated node."""
        self._validate_enrollment(enrollment)
        previous = self.enrollment.get(enrollment.node_id)
        previous_roles = set(self.policy.get(enrollment.node_id) or ())
        previous_rev = self.permissions_revision
        previous_epoch = self.authority_epoch
        try:
            if previous:
                self._unbind_enrollment(previous)
            self.enrollment[enrollment.node_id] = enrollment
            self._bind_enrollment(enrollment)
            if roles is not None:
                self.authorize(enrollment.node_id, roles)
        except Exception:
            self._unbind_enrollment(enrollment)
            if previous:
                self.enrollment[enrollment.node_id] = previous
                self._bind_enrollment(previous)
            else:
                self.enrollment.pop(enrollment.node_id, None)
            if roles is not None:
                if previous_roles:
                    self.policy[enrollment.node_id] = previous_roles
                else:
                    self.policy.pop(enrollment.node_id, None)
                self.permissions_revision = previous_rev
                self.authority_epoch = previous_epoch
            raise

    def roles_for(self, node_id: str, remote: dict[str, Any] | None = None) -> set[str]:
        """Policy is keyed only by the authenticated node. Client claims are ignored."""
        del remote
        if not node_id:
            return set()
        return set(self.policy.get(node_id) or ())

    def set_layout(self, layout: dict[str, Any]) -> None:
        ok, _ = self.activate_layout(layout)
        if not ok:
            raise ValueError("invalid remote layout")

    def control(self, control_id: str) -> dict[str, Any] | None:
        for item in self.layout.get("controls") or []:
            if item.get("control_id") == control_id:
                return item
        return None

    def handle(self, env: Envelope, session: Session) -> list[Envelope]:
        """Production entry point. Session and peer come only from the ACP Session."""
        err = self._require_production_context(env, session)
        if err:
            return [self._reject(env, err[0], err[1])]
        assert session.session_id is not None
        self._active_features = set(session.negotiated_capabilities)
        rec = self.sessions.get(session.session_id)
        if rec is not None:
            rec["features"] = set(session.negotiated_capabilities)
            rec["inline_surface"] = INLINE_SURFACE_CAPABILITY in session.negotiated_capabilities
        self.expire_due()
        return self._dispatch(env, session.session_id)

    def handle_simulated(self, env: Envelope, *, session_id: str) -> list[Envelope]:
        """Simulator/test API. Does not bind an ACP Session. Still requires Remote hello."""
        return self._dispatch(env, session_id)

    def _dispatch(self, env: Envelope, session_id: str) -> list[Envelope]:
        if env.type != "remote.hello":
            err = self._require_remote_session(session_id, env.source.node_id)
            if err:
                return [self._reject(env, err[0], err[1])]
        handler = self._handlers().get(env.type)
        if handler is None:
            return [self._reject(env, "unsupported", f"no handler for {env.type}")]
        return handler(env, session_id)

    def _handlers(self) -> dict[str, Any]:
        return {
            "remote.hello": self._hello,
            "remote.layout.request": self._layout_report,
            "remote.control.invoke": self._invoke,
            "remote.momentary.refresh": self._refresh,
            "remote.navigation.request": self._navigate,
            "remote.readiness": self._client_readiness,
            "remote.error": self._client_error,
            "resource.accept": self._resource_accept,
            "resource.reject": self._resource_reject,
            "resource.activate": self._resource_activate,
            "resource.cancel": self._resource_cancel,
            "resource.transfer_result": self._resource_result,
            "state.request": self._state_request,
        }

    def inbound_handler_gaps(self) -> set[str]:
        """Registry client-to-authority Remote types that have no dispatcher entry."""
        expected: set[str] = set()
        for typ, row in load_registry().items():
            if not typ.startswith("remote."):
                continue
            if "remote" not in set(row.get("valid_senders") or ()):
                continue
            if row.get("direction") in {"request", "event"}:
                expected.add(typ)
        return expected - set(self._handlers())

    def _require_production_context(self, env: Envelope, session: Session) -> tuple[str, str] | None:
        if session.state != SessionState.ESTABLISHED:
            return ("authentication", "ACP session is not established")
        if not session.session_id:
            return ("authentication", "ACP session has no session_id")
        if session.peer is None:
            return ("authentication", "ACP session has no authenticated peer")
        if env.source.node_id != session.peer.node_id:
            return ("authentication", "source is not the authenticated peer")
        if session.peer.role not in REMOTE_CLIENT_ROLES:
            return ("authentication", "peer role is not a Remote client")
        if "remote.profile" not in session.negotiated_capabilities:
            return ("capability_not_permitted", "remote.profile was not negotiated")
        have = (session.negotiated_capability_versions or {}).get("remote.profile")
        if have is None:
            return ("capability_not_permitted", "remote.profile version was not negotiated")
        negotiated_profiles: set[str] = set(getattr(session, "negotiated_profiles", set()) or set())
        if self.allowed_remote_profiles and not (set(negotiated_profiles) & self.allowed_remote_profiles):
            return ("capability_not_permitted", "aurora remote profile was not negotiated")
        try:
            if not version_at_least(str(have), "1.0"):
                return ("capability_not_permitted", "remote.profile version is below minimum")
        except ValueError:
            return ("capability_not_permitted", "remote.profile version is malformed")
        if env.type != "remote.hello":
            err = self._require_remote_session(session.session_id, env.source.node_id)
            if err:
                return err
            if env.type in INTERACTIVE_TYPES and self.compute_readiness(session.session_id) not in READY_STATES:
                return ("remote.session.not_ready", "session is not ready")
        return None

    def _require_remote_session(self, session_id: str, node_id: str) -> tuple[str, str] | None:
        rec = self.sessions.get(session_id)
        if rec is None or not rec.get("hello_completed"):
            return ("authentication", "no authenticated Remote session")
        if rec.get("node_id") != node_id:
            return ("authentication", "session does not belong to this source")
        return None

    def compute_readiness(self, session_id: str) -> str:
        rec = self.sessions.get(session_id)
        if rec is None:
            return "disconnected"
        if not rec.get("hello_completed"):
            return "negotiating"
        if rec.get("authority_epoch") != self.authority_epoch:
            return "syncing_state"
        if rec.get("resync_required"):
            return "syncing_state"
        if not self.layout:
            return "syncing_assets"
        layout_rev = self.layout.get("revision")
        layout_hash = layout_fingerprint(self.layout)
        if rec.get("asset_ack_revision") != layout_rev or rec.get("asset_ack_hash") != layout_hash:
            return "syncing_assets"
        if rec.get("snapshot_ack_revision") is None:
            return "syncing_state"
        roles = self.roles_for(str(rec.get("node_id") or ""))
        if not roles:
            return "blocked"
        if not self.armed:
            return "blocked"
        observed = rec.get("client_observed_state")
        if observed in {"degraded", "ready_with_warnings"}:
            return "ready_with_warnings"
        return "ready"

    def bind_test_session(self, session_id: str, node_id: str) -> None:
        """Mark a simulator session as hello-complete and fully synced for unit tests."""
        rec = self._session_record(node_id, {})
        if self.layout:
            rec["asset_ack_revision"] = self.layout.get("revision")
            rec["asset_ack_hash"] = layout_fingerprint(self.layout)
            rec["asset_delivered_revision"] = self.layout.get("revision")
        rec["snapshot_ack_revision"] = self.snapshot_revision
        rec["snapshot_delivered_revision"] = self.snapshot_revision
        rec["subscriptions"] = self._authorized_namespaces(node_id, None)
        rec["features"] = None
        rec["inline_surface"] = True
        self.sessions[session_id] = rec

    def mark_missed_delta(self, session_id: str) -> None:
        rec = self.sessions.get(session_id)
        if rec is not None:
            rec["resync_required"] = True
            rec["snapshot_ack_revision"] = None

    def _session_record(self, node_id: str, remote: dict[str, Any]) -> dict[str, Any]:
        features = set(self._active_features) if self._active_features is not None else None
        return {
            "remote": remote,
            "node_id": node_id,
            "hello_completed": True,
            "authority_epoch": self.authority_epoch,
            "asset_ack_revision": None,
            "asset_ack_hash": None,
            "asset_delivered_revision": None,
            "snapshot_ack_revision": None,
            "snapshot_delivered_revision": None,
            "resync_required": False,
            "client_observed_state": None,
            "features": features,
            "subscriptions": self._authorized_namespaces(node_id, features),
            "inline_surface": self.inline_surface or (
                features is not None and INLINE_SURFACE_CAPABILITY in features
            ),
            "pub_generation": self.authority_epoch,
        }

    def _mark_session_current(self, session_id: str) -> None:
        rec = self.sessions.get(session_id)
        if rec is None:
            return
        rec["snapshot_delivered_revision"] = self.snapshot_revision
        rec["snapshot_ack_revision"] = self.snapshot_revision
        rec["resync_required"] = False

    def _commit_snapshot(self, session_id: str) -> None:
        self.snapshot_revision += 1
        self._mark_session_current(session_id)

    def _validate_enrollment(self, enrollment: Enrollment) -> None:
        seen_values: dict[str, str] = {}
        for claim, index in self._claim_indexes():
            value = getattr(enrollment, claim)
            if not value:
                continue
            owner = index.get(value)
            if owner and owner != enrollment.node_id:
                raise ValueError(f"{claim} already enrolled to another node")
            prior = seen_values.get(str(value))
            if prior:
                raise ValueError(f"{claim} collides with {prior}")
            seen_values[str(value)] = claim
            for other_claim, other_index in self._claim_indexes():
                if other_claim == claim:
                    continue
                other_owner = other_index.get(value)
                if other_owner and other_owner != enrollment.node_id:
                    raise ValueError(f"{claim} collides with enrolled {other_claim}")

    def _bind_enrollment(self, enrollment: Enrollment) -> None:
        if enrollment.device_id:
            self._bound_device[enrollment.device_id] = enrollment.node_id
        if enrollment.remote_id:
            self._bound_remote[enrollment.remote_id] = enrollment.node_id
        if enrollment.participant_id:
            self._bound_participant[enrollment.participant_id] = enrollment.node_id
        if enrollment.operator_id:
            self._bound_operator[enrollment.operator_id] = enrollment.node_id

    def _unbind_enrollment(self, enrollment: Enrollment) -> None:
        for value, index in (
            (enrollment.device_id, self._bound_device),
            (enrollment.remote_id, self._bound_remote),
            (enrollment.participant_id, self._bound_participant),
            (enrollment.operator_id, self._bound_operator),
        ):
            if value and index.get(value) == enrollment.node_id:
                del index[value]

    def _claim_indexes(self) -> tuple[tuple[str, dict[str, str]], ...]:
        return (
            ("device_id", self._bound_device),
            ("remote_id", self._bound_remote),
            ("participant_id", self._bound_participant),
            ("operator_id", self._bound_operator),
        )

    def _validate_hello_claims(self, node_id: str, remote: dict[str, Any]) -> tuple[str, str] | None:
        for claim, index in self._claim_indexes():
            claimed = remote.get(claim)
            if not claimed:
                continue
            owner = index.get(str(claimed))
            if owner and owner != node_id:
                return ("authentication", f"{claim} is enrolled to a different node")
        enrolled = self.enrollment.get(node_id)
        if enrolled:
            for claim in CLAIM_FIELDS:
                expected = getattr(enrolled, claim)
                claimed = remote.get(claim)
                if expected and claimed and str(claimed) != expected:
                    return ("authentication", f"{claim} does not match enrollment")
                if expected and not claimed:
                    return ("authentication", f"{claim} is required by enrollment")
        return None

    def _bump_session_epochs(self) -> None:
        for rec in self.sessions.values():
            rec["authority_epoch"] = self.authority_epoch

    def on_session_lost(self, session_id: str) -> list[str]:
        released = self._release_holds(
            lambda h: h.session_id == session_id and h.failsafe == "release_on_disconnect",
            reason="disconnect",
        )
        self.sessions.pop(session_id, None)
        self.browsing.pop(session_id, None)
        self._outbound.pop(session_id, None)
        drop = [tid for tid, offer in self._surface_offers.items() if offer.get("session_id") == session_id]
        for tid in drop:
            self._surface_offers.pop(tid, None)
        self._surface_transfers.pop(session_id, None)
        self._live_surface_meta.pop(session_id, None)
        self.notify_schedule()
        self.notify_publications()
        return released

    def disarm(self) -> list[str]:
        self.armed = False
        released = self._release_holds(lambda _h: True, reason="disarm")
        self.notify_schedule()
        return released

    def tick(self, now_ms: int) -> list[str]:
        self.now_ms = now_ms
        return self.expire_due()

    def effect_active(self, control_id: str) -> bool:
        return bool(self.holds.get(control_id))

    def _hello(self, env: Envelope, session_id: str) -> list[Envelope]:
        raw_remote = env.payload.get("remote")
        remote = raw_remote if isinstance(raw_remote, dict) else {}
        if remote.get("node_id") != env.source.node_id:
            return [self._reject(env, "authentication", "remote.node_id does not match envelope source")]
        existing = self.sessions.get(session_id)
        if existing and existing.get("hello_completed") and existing.get("node_id") != env.source.node_id:
            return [self._reject(env, "authentication", "session does not belong to this source")]
        claim_err = self._validate_hello_claims(env.source.node_id, remote)
        if claim_err:
            return [self._reject(env, claim_err[0], claim_err[1])]
        # Requested roles and client IDs are untrusted claims. Policy is node-keyed.
        roles = self.roles_for(env.source.node_id)
        self.sessions[session_id] = self._session_record(env.source.node_id, remote)
        return [
            make_envelope(
                type="remote.hello_ack",
                source=self.source,
                destination=env.source,
                payload={
                    "accepted": True,
                    "permissions": {
                        "roles": sorted(roles),
                        "revision": self.permissions_revision,
                    },
                    "show_id": self.show_id,
                    "show_revision": self.show_revision,
                    "layout_id": surface_id_of(self.layout) or self.layout.get("layout_id"),
                    "surface_id": surface_id_of(self.layout),
                    "layout_revision": self.layout.get("revision"),
                },
                correlation_id=env.message_id,
                causation_id=env.message_id,
            ),
            self._permissions_msg(env, roles),
            self._readiness_msg(env, session_id),
        ]

    def surface_bytes(self) -> bytes:
        if not self.layout:
            return b""
        body = {k: self.layout[k] for k in sorted(self.layout) if k != "sha256"}
        return json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()

    def surface_asset(self) -> dict[str, Any]:
        digest = layout_fingerprint(self.layout) if self.layout else ""
        raw = self.surface_bytes()
        return {
            "asset_id": surface_id_of(self.layout) or new_uuid(),
            "asset_type": self.layout.get("asset_type") or "aurora.remote.surface",
            "revision": int(self.layout.get("revision") or 0),
            "sha256": digest,
            "size": len(raw),
            "size_bytes": len(raw),
        }

    def _inline_for(self, session_id: str) -> bool:
        rec = self.sessions.get(session_id) or {}
        if rec.get("inline_surface"):
            return True
        features = rec.get("features")
        if features is not None and INLINE_SURFACE_CAPABILITY in features:
            return True
        return self.inline_surface

    def _layout_report(self, env: Envelope, session_id: str) -> list[Envelope]:
        rec = self.sessions.get(session_id)
        digest = layout_fingerprint(self.layout) if self.layout else ""
        cached = env.payload.get("cached_sha256") or env.payload.get("sha256")
        if rec is not None:
            rec["asset_delivered_revision"] = self.layout.get("revision")
            rec["snapshot_delivered_revision"] = self.snapshot_revision
        asset = self.surface_asset()
        meta = {
            "surface_id": surface_id_of(self.layout),
            "revision": self.layout.get("revision"),
            "sha256": digest,
            "asset": asset,
            "cached": bool(cached and cached == digest),
        }
        report = make_envelope(
            type="remote.layout.report",
            source=self.source,
            destination=env.source,
            payload=dict(meta),
            correlation_id=env.message_id,
            causation_id=env.message_id,
        )
        if cached and cached == digest:
            if rec is not None:
                rec["asset_ack_revision"] = self.layout.get("revision")
                rec["asset_ack_hash"] = digest
            return [report, self._snapshot(env, session_id)]
        if asset["size_bytes"] > SURFACE_LIMITS["max_surface_bytes"]:
            return [self._reject(env, "remote.layout.invalid", "surface exceeds transfer limit")]
        if self._inline_for(session_id):
            layout = dict(self.layout)
            if layout and "sha256" not in layout:
                layout = {**layout, "sha256": digest}
            report = make_envelope(
                type="remote.layout.report",
                source=self.source,
                destination=env.source,
                payload={"layout": layout, **meta},
                correlation_id=env.message_id,
                causation_id=env.message_id,
            )
            return [report, self._snapshot(env, session_id)]
        tid = new_uuid()
        blob = self.surface_bytes()
        stale = [key for key, item in self._surface_offers.items() if item.get("session_id") == session_id]
        for key in stale:
            self._surface_offers.pop(key, None)
        self._surface_offers[tid] = {
            "transfer_id": tid,
            "session_id": session_id,
            "asset": asset,
            "blob": blob,
            "previous_live": self._surface_transfers.get(session_id),
        }
        offer = make_envelope(
            type="resource.offer",
            source=self.source,
            destination=env.source,
            payload={
                "transfer_id": tid,
                "asset": asset,
                "purpose": "remote.surface",
                "locator": {"mode": "chunked"},
                "max_chunk_bytes": SURFACE_CHUNK_BYTES,
            },
            correlation_id=env.message_id,
            causation_id=env.message_id,
        )
        return [report, offer, self._snapshot(env, session_id)]

    def accept_surface_transfer(self, env: Envelope, session_id: str) -> list[Envelope]:
        """Sender-side accept: emit bounded chunks then complete."""
        return self._resource_accept(env, session_id)

    def activate_surface_transfer(self, session_id: str) -> bool:
        transfer = self._surface_transfers.get(session_id)
        if transfer is None:
            return False
        previous = transfer.live
        ok = transfer.activate()
        if not ok and previous is not None:
            transfer.live = previous
        return ok

    def _offer_for(self, transfer_id: str, session_id: str) -> dict[str, Any] | None:
        offer = self._surface_offers.get(transfer_id)
        if offer is None or offer.get("session_id") != session_id:
            return None
        return offer

    def _resource_accept(self, env: Envelope, session_id: str) -> list[Envelope]:
        tid = str(env.payload.get("transfer_id") or "")
        offer = self._offer_for(tid, session_id)
        if offer is None:
            return [self._reject(env, "not_found", "unknown surface transfer")]
        blob: bytes = offer["blob"]
        asset = offer["asset"]
        if len(blob) > SURFACE_LIMITS["max_surface_bytes"]:
            return [self._reject(env, "remote.layout.invalid", "surface exceeds transfer limit")]
        try:
            max_chunk = int(env.payload.get("max_chunk_bytes") or SURFACE_CHUNK_BYTES)
        except (TypeError, ValueError):
            return [self._reject(env, "remote.command.invalid_state", "invalid max_chunk_bytes")]
        if max_chunk <= 0:
            return [self._reject(env, "remote.command.invalid_state", "invalid max_chunk_bytes")]
        max_chunk = min(max_chunk, SURFACE_CHUNK_BYTES)
        transfer = Transfer(
            transfer_id=tid,
            asset=asset,
            size=len(blob),
            max_chunk_bytes=max_chunk,
        )
        if offer.get("previous_live") is not None:
            transfer.live = offer["previous_live"].live if hasattr(offer["previous_live"], "live") else None
        self._surface_transfers[session_id] = transfer
        offer["accepted"] = True
        out: list[Envelope] = []
        for offset in range(0, len(blob), max_chunk):
            part = blob[offset : offset + max_chunk]
            out.append(make_envelope(
                type="resource.chunk",
                source=self.source,
                destination=env.source,
                payload={
                    "transfer_id": tid,
                    "offset": offset,
                    "length": len(part),
                    "data": base64.b64encode(part).decode("ascii"),
                },
                correlation_id=env.correlation_id or env.message_id,
                causation_id=env.message_id,
            ))
        out.append(make_envelope(
            type="resource.complete",
            source=self.source,
            destination=env.source,
            payload={"transfer_id": tid},
            correlation_id=env.correlation_id or env.message_id,
            causation_id=env.message_id,
        ))
        return out

    def _resource_reject(self, env: Envelope, session_id: str) -> list[Envelope]:
        tid = str(env.payload.get("transfer_id") or "")
        offer = self._offer_for(tid, session_id)
        if offer is not None:
            self._surface_offers.pop(tid, None)
        return []

    def _resource_cancel(self, env: Envelope, session_id: str) -> list[Envelope]:
        tid = str(env.payload.get("transfer_id") or "")
        self._surface_offers.pop(tid, None)
        transfer = self._surface_transfers.get(session_id)
        if transfer is not None and transfer.transfer_id == tid:
            transfer.cancel()
        return []

    def _resource_result(self, env: Envelope, session_id: str) -> list[Envelope]:
        tid = str(env.payload.get("transfer_id") or "")
        status = str(env.payload.get("status") or "")
        transfer = self._surface_transfers.get(session_id)
        if transfer is None or transfer.transfer_id != tid:
            return [self._reject(env, "not_found", "unknown surface transfer")]
        if status == "verified":
            transfer.state = TransferState.VERIFIED
            if transfer.staged is None:
                offer = self._surface_offers.get(tid)
                if offer is not None:
                    transfer.staged = offer["blob"]
            return []
        transfer.state = TransferState.FAILED
        return []

    def _finish_surface_transfer(self, session_id: str, tid: str, *, keep_live: bool) -> None:
        self._surface_offers.pop(tid, None)
        transfer = self._surface_transfers.get(session_id)
        if transfer is None or transfer.transfer_id != tid:
            return
        transfer.parts.clear()
        transfer.ranges.clear()
        transfer.staged = None
        if keep_live:
            self._live_surface_meta[session_id] = {
                "asset_id": transfer.asset.get("asset_id"),
                "revision": transfer.asset.get("revision"),
                "sha256": transfer.asset.get("sha256"),
                "asset_type": transfer.asset.get("asset_type"),
            }
            transfer.asset = dict(self._live_surface_meta[session_id])
        else:
            self._surface_transfers.pop(session_id, None)
            self._live_surface_meta.pop(session_id, None)

    def _resource_activate(self, env: Envelope, session_id: str) -> list[Envelope]:
        tid = str(env.payload.get("transfer_id") or "")
        transfer = self._surface_transfers.get(session_id)
        if self.reject_activation or transfer is None or transfer.transfer_id != tid:
            self._finish_surface_transfer(session_id, tid, keep_live=transfer is not None)
            return [make_envelope(
                type="resource.activation_result",
                source=self.source,
                destination=env.source,
                payload={
                    "transfer_id": tid,
                    "status": "failed",
                    "code": "invalid_state" if self.reject_activation else "not_found",
                },
                correlation_id=env.message_id,
            )]
        previous = transfer.live
        ok = transfer.activate()
        if not ok:
            if previous is not None:
                transfer.live = previous
            return [make_envelope(
                type="resource.activation_result",
                source=self.source,
                destination=env.source,
                payload={"transfer_id": tid, "status": "failed", "code": "invalid_state"},
                correlation_id=env.message_id,
            )]
        rec = self.sessions.get(session_id)
        if rec is not None and self.layout:
            rec["asset_ack_revision"] = self.layout.get("revision")
            rec["asset_ack_hash"] = layout_fingerprint(self.layout)
        self._finish_surface_transfer(session_id, tid, keep_live=True)
        return [make_envelope(
            type="resource.activation_result",
            source=self.source,
            destination=env.source,
            payload={"transfer_id": tid, "status": "applied"},
            correlation_id=env.message_id,
        )]

    def _client_readiness(self, env: Envelope, session_id: str) -> list[Envelope]:
        rec = self.sessions[session_id]
        rec["client_observed_state"] = env.payload.get("state")
        declared_layout = env.payload.get("layout_revision")
        declared_hash = env.payload.get("layout_hash") or env.payload.get("sha256")
        declared_snap = env.payload.get("snapshot_revision")
        if (
            declared_layout is not None
            and declared_hash
            and self.layout
            and int(declared_layout) == int(self.layout.get("revision") or 0)
            and str(declared_hash) == layout_fingerprint(self.layout)
        ):
            rec["asset_ack_revision"] = self.layout.get("revision")
            rec["asset_ack_hash"] = str(declared_hash)
        if declared_snap is not None:
            snap = int(declared_snap)
            delivered = rec.get("snapshot_delivered_revision")
            if snap == self.snapshot_revision or (delivered is not None and snap == delivered):
                rec["snapshot_ack_revision"] = snap
                rec["resync_required"] = False
        return [self._readiness_msg(env, session_id)]

    def _client_error(self, env: Envelope, session_id: str) -> list[Envelope]:
        del env, session_id
        return []

    def _invoke(self, env: Envelope, session_id: str) -> list[Envelope]:
        payload = dict(env.payload)
        interaction = str(payload.get("interaction") or "")
        invocation_id = str(payload.get("invocation_id") or "")
        err = self._admit(payload, session_id, env.source.node_id)
        if err:
            return [self._reject(env, err[0], err[1])]
        cache_type = f"remote.control.invoke:{interaction}"
        bound = ((self.control(str(payload.get("control_id") or "")) or {}).get("binding") or {})
        action = str(bound.get("action") or "")
        delivery = default_delivery(action, interaction)
        dedup_scope = env.source.node_id if delivery == "live_ephemeral" else session_id
        try:
            cached = self.idempotency.lookup(
                dedup_scope, cache_type, invocation_id, _fingerprint(payload)
            )
        except ValueError:
            return [self._reject(env, "conflict", "idempotency key reused with different body")]
        if cached:
            return [make_ack(env, self.source, CommandStatus(cached.status), result=cached.result)]
        control = self.control(str(payload.get("control_id") or ""))
        assert control is not None
        if interaction == "momentary_begin":
            out = self._begin(env, session_id, control, invocation_id, payload.get("value", 1.0))
        elif interaction in {"momentary_end", "momentary_cancel"}:
            out = self._end(
                env, session_id, control, invocation_id, payload.get("lease_id"),
                cancel=interaction == "momentary_cancel",
            )
        else:
            out = self._apply(env, session_id, control, interaction, payload.get("value"))
        if out and out[0].type == "command.ack" and out[0].payload.get("status") != "rejected":
            self.idempotency.remember(
                dedup_scope,
                cache_type,
                invocation_id,
                status=str(out[0].payload["status"]),
                result=dict(out[0].payload.get("result") or {}),
                body_fingerprint=_fingerprint(payload),
            )
        return out

    def _admit(
        self,
        payload: dict[str, Any],
        session_id: str,
        node_id: str,
        *,
        command_lifetime: bool = True,
    ) -> tuple[str, str] | None:
        if not self.armed:
            return ("remote.control.not_armed", "show is not armed")
        control_id = str(payload.get("control_id") or "")
        control = self.control(control_id)
        if control is None:
            return ("remote.control.unknown", f"unknown control {control_id}")
        if payload.get("show_id") and payload["show_id"] != self.show_id:
            return ("remote.layout.stale", "show_id does not match active show")
        if payload.get("show_revision") is not None and int(payload["show_revision"]) != self.show_revision:
            return ("remote.layout.stale", "show_revision does not match")
        want_surface = payload.get("surface_id") or payload.get("layout_id")
        have_surface = surface_id_of(self.layout)
        if want_surface and have_surface and want_surface != have_surface:
            return ("remote.layout.stale", "surface_id does not match active surface")
        want_rev = payload.get("layout_revision")
        have_rev = int(self.layout.get("revision") or 0)
        if want_rev is not None and int(want_rev) != have_rev:
            return ("remote.layout.stale", "layout_revision does not match")
        if control.get("enabled") is False:
            return ("remote.control.disabled", "control is disabled")
        if control.get("available") is False:
            return ("remote.control.unavailable", "control is unavailable")
        binding = control.get("binding") or {}
        if binding.get("action") not in ACTION_POLICY:
            return ("remote.control.unknown", "action is not allowlisted")
        if binding.get("target") and binding["target"] not in ALLOWED_TARGETS:
            return ("remote.control.unknown", "unknown binding target")
        try:
            needed = set(required_permissions(control))
        except ValueError as exc:
            return ("remote.control.permission_denied", str(exc))
        action = str((control.get("binding") or {}).get("action") or "")
        perm = PERMISSION_FOR_ACTION.get(action)
        if perm:
            needed.add(perm)
        roles = self.roles_for(node_id)
        if needed and not has_permissions(roles, needed):
            return ("remote.control.permission_denied", f"missing {sorted(needed)}")
        feat = ACTION_FEATURE.get(action)
        if feat and self._active_features is not None and feat not in self._active_features:
            return ("capability_not_permitted", f"missing feature {feat}")
        interaction = str(payload.get("interaction") or "")
        ctype = normalize_control_type(str(control.get("control_type") or ""))
        if ctype in DISPLAY_ONLY_TYPES:
            return ("remote.control.invalid_interaction", "display-only control")
        allowed = CONTROL_INTERACTIONS.get(ctype, frozenset())
        if ctype not in CONTROL_INTERACTIONS and ctype not in DISPLAY_ONLY_TYPES:
            return ("unsupported", f"unsupported control type {ctype}")
        if interaction not in allowed:
            return ("remote.control.invalid_interaction", f"{interaction} not valid for {control['control_type']}")
        if ctype == "toggle" and not isinstance(payload.get("value"), bool):
            return ("remote.control.invalid_value", "toggle requires boolean value")
        value_err = self._value_error(control, action, interaction, payload.get("value"))
        if value_err:
            return value_err
        if command_lifetime:
            expiry = self._live_ephemeral_error(payload, action, interaction)
            if expiry:
                return expiry
        if interaction == "momentary_begin":
            hold_err = self._failsafe_required_error(control)
            if hold_err:
                return hold_err
        return None

    def _live_ephemeral_error(
        self,
        payload: dict[str, Any],
        action: str,
        interaction: str,
    ) -> tuple[str, str] | None:
        classified = default_delivery(action, interaction)
        client_delivery = payload.get("delivery")
        if client_delivery and str(client_delivery) != classified and classified == "live_ephemeral":
            return ("remote.command.invalid_state", "cannot downgrade live-ephemeral delivery")
        if classified != "live_ephemeral":
            return None
        issued = payload.get("issued_at")
        if not issued:
            return ("remote.command.expired", "live-ephemeral command requires issued_at")
        try:
            issued_dt = parse_ts(str(issued))
        except ValueError:
            return ("remote.command.expired", "invalid issued_at")
        now = datetime.now(UTC)
        skew_ms = (issued_dt - now).total_seconds() * 1000
        if skew_ms > MAX_CLOCK_SKEW_MS:
            return ("remote.command.expired", "issued_at is too far in the future")
        age_ms = (now - issued_dt).total_seconds() * 1000
        client_max = payload.get("max_age_ms")
        limit = self.max_live_ephemeral_age_ms
        if client_max is not None:
            try:
                limit = min(limit, int(client_max))
            except (TypeError, ValueError):
                return ("remote.command.expired", "invalid max_age_ms")
        expires_at = payload.get("expires_at")
        if expires_at:
            try:
                exp_dt = parse_ts(str(expires_at))
            except ValueError:
                return ("remote.command.expired", "invalid expires_at")
            if exp_dt <= now:
                return ("remote.command.expired", "live-ephemeral command has expired")
            declared_life = (exp_dt - issued_dt).total_seconds() * 1000
            if declared_life > self.max_live_ephemeral_age_ms + MAX_CLOCK_SKEW_MS:
                return ("remote.command.expired", "live-ephemeral lifetime exceeds provider maximum")
        if age_ms > limit:
            return ("remote.command.expired", "live-ephemeral command exceeded max age")
        return None

    def _value_error(
        self,
        control: dict[str, Any],
        action: str,
        interaction: str,
        value: Any,
    ) -> tuple[str, str] | None:
        if interaction not in {"set", "adjust"}:
            return None
        ctype = normalize_control_type(str(control.get("control_type") or ""))
        if ctype in {"slider", "encoder", "xy", "color"}:
            numbers: list[float] = []
            if isinstance(value, bool) or value is None:
                return ("remote.control.invalid_value", "numeric value required")
            if isinstance(value, (int, float)):
                numbers = [float(value)]
            elif isinstance(value, (list, tuple)):
                if not value or any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in value):
                    return ("remote.control.invalid_value", "numeric vector required")
                numbers = [float(item) for item in value]
            else:
                return ("remote.control.invalid_value", "numeric value required")
            if any(not math.isfinite(item) for item in numbers):
                return ("remote.control.invalid_value", "value must be finite")
            lo, hi = control.get("min"), control.get("max")
            if action in ACTION_VALUE_BOUNDS:
                alo, ahi = ACTION_VALUE_BOUNDS[action]
                lo = alo if lo is None else max(float(lo), alo)
                hi = ahi if hi is None else min(float(hi), ahi)
            for item in numbers:
                if lo is not None and item < float(lo):
                    return ("remote.control.invalid_value", "value below minimum")
                if hi is not None and item > float(hi):
                    return ("remote.control.invalid_value", "value above maximum")
            step = control.get("step")
            if step:
                base = float(lo or 0)
                for item in numbers:
                    units = (item - base) / float(step)
                    if abs(units - round(units)) > 1e-6:
                        return ("remote.control.invalid_value", "value is not an allowed step")
        if action in ACTION_VALUE_BOUNDS and isinstance(value, (int, float)) and not isinstance(value, bool):
            lo, hi = ACTION_VALUE_BOUNDS[action]
            if not math.isfinite(float(value)) or float(value) < lo or float(value) > hi:
                return ("remote.control.invalid_value", "value outside authority bounds")
        return None

    def _failsafe_required_error(self, control: dict[str, Any]) -> tuple[str, str] | None:
        safety = control.get("safety") or {}
        ctype = normalize_control_type(str(control.get("control_type") or ""))
        required = safety.get("failsafe_required")
        if required is None:
            required = ctype == "momentary" and str(safety.get("class") or "normal") in {"caution", "dangerous"}
        if not required:
            return None
        max_hold = int(safety.get("max_hold_ms") or 0)
        failsafe = str(safety.get("failsafe") or DEFAULT_FAILSAFE)
        if max_hold <= 0 or failsafe == "hold_last_state":
            return ("remote.command.invalid_state", "failsafe-required control cannot be leased")
        return None

    def _begin(
        self,
        env: Envelope,
        session_id: str,
        control: dict[str, Any],
        invocation_id: str,
        value: Any,
    ) -> list[Envelope]:
        cid = control["control_id"]
        group = self.holds.setdefault(cid, {})
        if invocation_id in group:
            hold = group[invocation_id]
            if hold.session_id != session_id:
                return [self._reject(env, "remote.control.permission_denied", "hold owned by another session")]
            rec = {"control_id": cid, "active": True, "lease_id": hold.lease_id}
            return [make_ack(env, self.source, CommandStatus.DUPLICATE, result=rec)]
        if any(h.release_pending for h in group.values()):
            return [self._reject(env, "remote.control.conflict", "unsafe release pending")]
        concurrency = control.get("concurrency") or "shared"
        if concurrency in {"exclusive", "single_owner"} and group:
            return [self._reject(env, "remote.control.conflict", "control is already held")]
        ctx = ActionContext(
            session_id=session_id,
            node_id=env.source.node_id,
            invocation_id=invocation_id,
            control_id=cid,
            interaction="momentary_begin",
            value=value,
        )
        routed = self._route(env, "begin", control, ctx)
        if isinstance(routed, list):
            return routed
        safety = control.get("safety") or {}
        now = self.now()
        max_hold = int(safety.get("max_hold_ms") or DEFAULT_MAX_HOLD_MS)
        hold = Hold(
            invocation_id=invocation_id,
            session_id=session_id,
            node_id=env.source.node_id,
            control_id=cid,
            started_ms=now,
            max_hold_ms=max_hold,
            failsafe=str(safety.get("failsafe") or DEFAULT_FAILSAFE),
            lease_id=new_uuid(),
            value=value,
            expires_at_ms=now + max_hold if max_hold else 0,
        )
        group[invocation_id] = hold
        self.effects[cid] = True
        self.notify_schedule()
        try:
            self._persist_safety()
        except Exception:
            self._force_release_hold(hold, control, "persist_failed")
            del group[invocation_id]
            if not group:
                self.holds.pop(cid, None)
                self.effects[cid] = False
            return [self._reject(env, "internal", "failed to persist safety state")]
        result = {
            "control_id": cid,
            "active": True,
            "lease_id": hold.lease_id,
            "expires_ms": hold.max_hold_ms,
            "expires_at_ms": hold.expires_at_ms,
        }
        self.revisions[cid] = self.revisions.get(cid, 1) + 1
        self._commit_snapshot(session_id)
        self._persist_safety()
        result["snapshot_revision"] = self.snapshot_revision
        state = self._state(env, cid, True)
        self._fanout([state], origin=session_id)
        return [make_ack(env, self.source, CommandStatus.APPLIED, result=result), state]

    def _end(
        self,
        env: Envelope,
        session_id: str,
        control: dict[str, Any],
        invocation_id: str,
        lease_id: Any,
        *,
        cancel: bool = False,
    ) -> list[Envelope]:
        cid = control["control_id"]
        group = self.holds.get(cid) or {}
        hold = group.get(invocation_id)
        if hold is None:
            result = {"control_id": cid, "active": self.effect_active(cid), "snapshot_revision": self.snapshot_revision}
            return [make_ack(env, self.source, CommandStatus.DUPLICATE, result=result)]
        if hold.session_id != session_id:
            return [self._reject(env, "remote.control.permission_denied", "cannot release another session hold")]
        if not lease_id or lease_id != hold.lease_id:
            return [self._reject(env, "remote.momentary.unknown_invocation", "lease required")]
        ctx = ActionContext(
            session_id=session_id,
            node_id=env.source.node_id,
            invocation_id=invocation_id,
            control_id=cid,
            interaction="momentary_cancel" if cancel else "momentary_end",
            lease_id=str(lease_id),
        )
        routed = self._route(env, "end", control, ctx)
        if isinstance(routed, list):
            return routed
        del group[invocation_id]
        if not group:
            self.holds.pop(cid, None)
            self.effects[cid] = False
        result = {"control_id": cid, "active": self.effect_active(cid)}
        self.revisions[cid] = self.revisions.get(cid, 1) + 1
        self._commit_snapshot(session_id)
        self._persist_safety()
        self.notify_schedule()
        result["snapshot_revision"] = self.snapshot_revision
        state = self._state(env, cid, self.effect_active(cid))
        self._fanout([state], origin=session_id)
        return [make_ack(env, self.source, CommandStatus.APPLIED, result=result), state]

    def _apply(
        self,
        env: Envelope,
        session_id: str,
        control: dict[str, Any],
        interaction: str,
        value: Any,
    ) -> list[Envelope]:
        cid = control["control_id"]
        action = str((control.get("binding") or {}).get("action") or "")
        extra = {
            "song_id": env.payload.get("song_id") or (value if action.startswith("show.song.") else None),
            "look_id": env.payload.get("look_id") or (value if action.startswith("look.") else None),
            "transition": env.payload.get("transition"),
            "value": value,
        }
        ctx = ActionContext(
            session_id=session_id,
            node_id=env.source.node_id,
            invocation_id=str(env.payload.get("invocation_id") or ""),
            control_id=cid,
            interaction=interaction,
            value=value,
            extra={k: v for k, v in extra.items() if v is not None},
        )
        routed = self._route(env, "apply", control, ctx)
        if isinstance(routed, list):
            return routed
        result_body = routed
        self.apply_seq += 1
        self.last_committed = {"action": action, "seq": self.apply_seq, "extra": dict(result_body.extra)}
        self._commit_snapshot(session_id)
        publications = self._publications_for(env, action, result_body, session_id=session_id)
        if action in {"cue.go", "nav.go"} or cid in {"cue_go", "go"}:
            cue_id = result_body.extra.get("cue_id", self.cue_id)
            prev = result_body.extra.get("previous_cue_id", cue_id)
            result = {
                "control_id": cid,
                "cue_id": cue_id,
                "previous_cue_id": prev,
                "snapshot_revision": self.snapshot_revision,
            }
            return [make_ack(env, self.source, CommandStatus.APPLIED, result=result), *publications]
        value_out = result_body.value if result_body.value is not None else self.values.get(cid, True)
        result = {
            "control_id": cid,
            "value": value_out,
            "snapshot_revision": self.snapshot_revision,
            **{k: v for k, v in result_body.extra.items() if k not in {"transition"} or v is not None},
        }
        if result_body.extra.get("transition") is not None:
            result["transition"] = result_body.extra["transition"]
        self.revisions[cid] = self.revisions.get(cid, 1) + 1
        if publications:
            return [make_ack(env, self.source, CommandStatus.APPLIED, result=result), *publications]
        state = self._state(env, cid, self.values.get(cid, value_out))
        return [make_ack(env, self.source, CommandStatus.APPLIED, result=result), state]

    def _publications_for(
        self,
        env: Envelope,
        action: str,
        result_body: ActionResult,
        *,
        session_id: str,
    ) -> list[Envelope]:
        out: list[Envelope] = []
        if action in {"cue.go", "nav.go"}:
            out.extend([
                self._resource_delta(env, "cue.current", {"cue_id": self.cue_id}),
                self._resource_delta(env, "cue.next", {"cue_id": self.next_cue_id}),
                self._presentation(env),
            ])
        if action in {"show.song.select", "show.song.load", "show.song.stop"}:
            out.append(self._resource_delta(env, "show.selected_song", {"song_id": self.selected_song_id}))
            if action in {"show.song.load", "show.song.stop"}:
                out.append(self._resource_delta(env, "show.current_song", {"song_id": self.song_id}))
                out.append(self._resource_delta(env, "show.running", {"value": self.running}))
            out.append(self._nav_state(env))
        if action in {"show.section.next", "show.section.previous", "show.section.restart", "nav.section.enter"}:
            out.append(self._resource_delta(env, "show.current_section", {"section_id": self.section_id}))
            out.append(self._resource_delta(env, "show.next_section", {"section_id": self.next_section_id}))
        if action == "show.progression.hold":
            out.append(self._resource_delta(
                env,
                "show.progression",
                {"held": self.progression_held, "running": self.running},
            ))
        if action in {"show.free_play.enter", "show.free_play.exit"}:
            out.append(self._resource_delta(
                env,
                "show.mode",
                {"mode": self.mode, "return_context": dict(self.return_context)},
            ))
            out.append(self._nav_state(env))
        if action in {"look.recall", "look.take", "look.preview", "look.preview.cancel"}:
            out.append(self._resource_delta(env, "look.current", {
                "look_id": self.current_look_id,
                "preview_look_id": self.preview_look_id,
                "transition": result_body.extra.get("transition"),
            }))
            out.append(self._resource_delta(env, "look.preview", {"look_id": self.preview_look_id}))
            if action in {"look.recall", "look.take"}:
                out.append(self._resource_delta(env, "look.catalog", {"looks": list(self.looks)}))
        if action in {"output.blackout.set", "bridge.blackout"}:
            out.append(self._resource_delta(env, "output.blackout", {"value": self.blackout}))
        if action == "output.grand_master.set":
            out.append(self._resource_delta(env, "output.grand_master", {"value": self.grand_master}))
        self._fanout(out, origin=session_id)
        return out

    def _authorized_namespaces(self, node_id: str, features: set[str] | None) -> set[str]:
        roles = self.roles_for(node_id)
        allowed: set[str] = set()
        for ns, (perm, feat) in NAMESPACE_POLICY.items():
            if perm and not has_permissions(roles, {perm}):
                continue
            if feat and features is not None and feat not in features:
                continue
            allowed.add(ns)
        return allowed

    def _message_namespace(self, msg: Envelope) -> str | None:
        if msg.type == "state.delta":
            return str(msg.payload.get("resource") or "") or None
        if msg.type == "remote.navigation.state":
            return "show.navigation"
        if msg.type == "remote.presentation.state":
            return "show.presentation"
        if msg.type in {"remote.control.state", "remote.control.snapshot"}:
            return "remote.control_state"
        if msg.type in {"error.report", "health.heartbeat", "remote.error"}:
            return "system.health"
        return None

    def _visible_to(self, rec: dict[str, Any], msg: Envelope) -> bool:
        if rec.get("resync_required") and msg.type != "remote.control.snapshot":
            return False
        ns = self._message_namespace(msg)
        if ns is None:
            return True
        subs = rec.get("subscriptions")
        if isinstance(subs, set) and ns not in subs:
            return False
        node_id = str(rec.get("node_id") or "")
        features = rec.get("features")
        if features is None:
            features = self._active_features
        return ns in self._authorized_namespaces(node_id, features)

    def _fanout(self, messages: list[Envelope], *, origin: str) -> None:
        origin_sid = origin
        for rec_sid, rec in self.sessions.items():
            if rec_sid == origin_sid or not rec.get("hello_completed"):
                continue
            dest = Endpoint(node_id=str(rec.get("node_id") or ""))
            queued = self._outbound.setdefault(rec_sid, [])
            for msg in messages:
                if not self._visible_to(rec, msg):
                    continue
                queued.append(make_envelope(
                    type=msg.type,
                    source=msg.source,
                    destination=dest,
                    qos=msg.qos,
                    payload=dict(msg.payload),
                    causation_id=msg.causation_id,
                ))
        if any(self._outbound.values()):
            self.notify_publications()

    def _broadcast_control_state(
        self,
        control_id: str,
        value: Any,
        *,
        confidence: str = "confirmed",
    ) -> None:
        self.revisions[control_id] = self.revisions.get(control_id, 1) + 1
        msg = make_envelope(
            type="remote.control.state",
            source=self.source,
            qos=QoS.LATEST,
            payload={
                "control_id": control_id,
                "revision": self.revisions[control_id],
                "enabled": True,
                "available": True,
                "value": value,
                "confidence": confidence,
            },
        )
        self._fanout([msg], origin="")

    def _state_request(self, env: Envelope, session_id: str) -> list[Envelope]:
        rec = self.sessions.get(session_id)
        if rec is None:
            return [self._reject(env, "authentication", "no authenticated Remote session")]
        features = rec.get("features")
        if features is None:
            features = self._active_features
        allowed = self._authorized_namespaces(env.source.node_id, features)
        requested = env.payload.get("resources") or []
        if requested:
            rec["subscriptions"] = {str(ns) for ns in requested if str(ns) in allowed}
        else:
            rec["subscriptions"] = set(allowed)
        rec["resync_required"] = False
        rec["pub_generation"] = self.authority_epoch
        resources: list[dict[str, Any]] = []
        for ns in sorted(rec["subscriptions"]):
            item = self._namespace_resource(ns)
            if item is not None:
                resources.append(item)
        rec["snapshot_delivered_revision"] = self.snapshot_revision
        return [make_envelope(
            type="state.snapshot",
            source=self.source,
            destination=env.source,
            qos=QoS.RELIABLE,
            payload={"resources": resources},
            correlation_id=env.message_id,
            causation_id=env.message_id,
        )]

    def _namespace_resource(self, ns: str) -> dict[str, Any] | None:
        value: dict[str, Any] | None = None
        if ns == "cue.current":
            value = {"cue_id": self.cue_id}
        elif ns == "cue.next":
            value = {"cue_id": self.next_cue_id}
        elif ns == "show.current_song":
            value = {"song_id": self.song_id}
        elif ns == "show.selected_song":
            value = {"song_id": self.selected_song_id}
        elif ns == "show.current_section":
            value = {"section_id": self.section_id}
        elif ns == "show.next_section":
            value = {"section_id": self.next_section_id}
        elif ns == "show.running":
            value = {"value": self.running}
        elif ns == "show.progression":
            value = {"held": self.progression_held, "running": self.running}
        elif ns == "show.mode":
            value = {"mode": self.mode, "return_context": dict(self.return_context)}
        elif ns == "look.catalog":
            value = {"looks": list(self.looks)}
        elif ns == "look.current":
            value = {"look_id": self.current_look_id, "preview_look_id": self.preview_look_id}
        elif ns == "look.preview":
            value = {"look_id": self.preview_look_id}
        elif ns == "output.blackout":
            value = {"value": self.blackout}
        elif ns == "output.grand_master":
            value = {"value": self.grand_master}
        elif ns == "system.health":
            value = dict(self.health)
        elif ns == "show.navigation":
            value = {
                "show_id": self.show_id,
                "song_id": self.song_id,
                "selected_song_id": self.selected_song_id,
                "next_song_id": self.next_song_id,
                "cue_id": self.cue_id,
                "next_cue_id": self.next_cue_id,
                "mode": self.mode,
            }
        elif ns == "show.presentation":
            value = {
                "show_id": self.show_id,
                "song_id": self.song_id,
                "cue_id": self.cue_id,
                "next_cue_id": self.next_cue_id,
            }
        elif ns == "show.setlist":
            value = {
                "setlist_id": self.setlist_id,
                "setlist_name": self.setlist_name,
                "songs": list(self.songs),
            }
        elif ns == "remote.control_state":
            value = {"controls": [
                {
                    "control_id": c["control_id"],
                    "value": self.values.get(c["control_id"], self.effect_active(c["control_id"])),
                }
                for c in (self.layout.get("controls") or [])
            ]}
        if value is None:
            return None
        return {
            "resource": ns,
            "revision": self.snapshot_revision,
            "owner": self.source.to_dict(),
            "value": value,
            "confidence": "confirmed",
        }

    def _refresh(self, env: Envelope, session_id: str) -> list[Envelope]:
        payload = {
            "control_id": env.payload.get("control_id"),
            "invocation_id": env.payload.get("invocation_id"),
            "interaction": "momentary_begin",
            "lease_id": env.payload.get("lease_id"),
        }
        err = self._admit(payload, session_id, env.source.node_id, command_lifetime=False)
        if err:
            return [self._reject(env, err[0], err[1])]
        cid = str(payload["control_id"])
        inv = str(payload["invocation_id"])
        hold = (self.holds.get(cid) or {}).get(inv)
        if hold is None:
            return [self._reject(env, "remote.momentary.unknown_invocation", "no active hold")]
        if hold.session_id != session_id:
            return [self._reject(env, "remote.control.permission_denied", "hold owned by another session")]
        if not payload.get("lease_id") or payload["lease_id"] != hold.lease_id:
            return [self._reject(env, "remote.momentary.unknown_invocation", "lease required")]
        control = self.control(cid) or {}
        ctx = ActionContext(
            session_id=session_id,
            node_id=env.source.node_id,
            invocation_id=inv,
            control_id=cid,
            interaction="momentary_refresh",
            lease_id=str(payload.get("lease_id") or ""),
        )
        routed = self._route(env, "refresh", control, ctx)
        if isinstance(routed, list):
            return routed
        now = self.now()
        hold.started_ms = now
        if hold.max_hold_ms:
            hold.expires_at_ms = now + hold.max_hold_ms
        self.notify_schedule()
        return [make_ack(env, self.source, CommandStatus.APPLIED, result={
            "lease_id": hold.lease_id,
            "expires_ms": hold.max_hold_ms,
            "expires_at_ms": hold.expires_at_ms,
            "active": True,
        })]

    def _navigate(self, env: Envelope, session_id: str) -> list[Envelope]:
        roles = self.roles_for(env.source.node_id)
        kind = str(env.payload.get("kind") or "")
        if kind not in NAV_KINDS:
            return [self._reject(env, "unsupported", f"unsupported navigation kind {kind}")]
        needed = frozenset({"remote.viewer"} if kind == "browse" else {"remote.show_navigation"})
        if kind == LIVE_EPHEMERAL_NAV_KIND:
            needed = frozenset({"remote.operator"})
        if not has_permissions(roles, needed):
            return [self._reject(env, "remote.control.permission_denied", "navigation not permitted")]
        nav_feat = "show.navigation" if kind != "select" else "song.selection"
        if kind == "load":
            nav_feat = "song.loading"
        if kind == LIVE_EPHEMERAL_NAV_KIND:
            nav_feat = "cue.go"
            life = self._live_ephemeral_error(dict(env.payload), "nav.go", "activate")
            if life:
                return [self._reject(env, life[0], life[1])]
        if self._active_features is not None and nav_feat not in self._active_features:
            return [self._reject(env, "capability_not_permitted", f"missing feature {nav_feat}")]
        key = str(env.payload.get("idempotency_key") or env.message_id)
        live = kind == LIVE_EPHEMERAL_NAV_KIND
        dedup_scope = env.source.node_id if live else session_id
        cache_type = "remote.navigation.request:go" if live else "remote.navigation.request"
        try:
            nav_fp = _fingerprint(dict(env.payload))
            cached = self.idempotency.lookup(dedup_scope, cache_type, key, nav_fp)
        except ValueError:
            return [self._reject(env, "conflict", "idempotency key reused with different body")]
        if cached:
            return [make_ack(env, self.source, CommandStatus(cached.status), result=cached.result)]
        if kind == "browse":
            song = str(env.payload.get("song_id") or "")
            self.browsing[session_id] = song
            result = {"kind": "browse", "song_id": song}
            self.idempotency.remember(
                dedup_scope, cache_type, key,
                status="applied", result=result, body_fingerprint=_fingerprint(dict(env.payload)),
            )
            return [make_ack(env, self.source, CommandStatus.APPLIED, result=result)]
        if kind == "select":
            self.selected_song_id = str(env.payload.get("song_id") or self.selected_song_id)
        elif kind == "load":
            self.song_id = str(env.payload.get("song_id") or self.song_id)
            self.selected_song_id = self.song_id
        elif kind == "next":
            self._step_playlist(1)
        elif kind == "previous":
            self._step_playlist(-1)
        elif kind == "go":
            nav_control = {
                "control_id": "nav_go",
                "control_type": "navigation",
                "binding": {"target": "prism", "action": "nav.go"},
            }
            ctx = ActionContext(
                session_id=session_id,
                node_id=env.source.node_id,
                invocation_id=key,
                control_id="nav_go",
                interaction="activate",
            )
            routed = self._route(env, "apply", nav_control, ctx)
            if isinstance(routed, list):
                return routed
            self._commit_snapshot(session_id)
        out_result: dict[str, Any] = {
            "kind": kind,
            "song_id": self.song_id,
            "selected_song_id": self.selected_song_id,
            "cue_id": self.cue_id,
            "mode": self.mode,
            "snapshot_revision": self.snapshot_revision,
        }
        self.idempotency.remember(
            dedup_scope, cache_type, key,
            status="applied", result=out_result, body_fingerprint=_fingerprint(dict(env.payload)),
        )
        nav = self._nav_state(env)
        self._fanout([nav], origin=session_id)
        return [
            make_ack(env, self.source, CommandStatus.APPLIED, result=out_result),
            nav,
        ]

    def _step_playlist(self, delta: int) -> None:
        try:
            idx = self.playlist.index(self.song_id)
        except ValueError:
            idx = 0
        nxt = (idx + delta) % len(self.playlist)
        self.song_id = self.playlist[nxt]
        self.selected_song_id = self.song_id
        self.next_song_id = self.playlist[(nxt + 1) % len(self.playlist)]

    def activate_layout(self, layout: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        previous = self.layout
        previous_epoch = self.authority_epoch
        try:
            self._validate_layout(layout)
        except (ValidationError, ValueError):
            return False, previous
        if self.layout and layout_fingerprint(layout) == layout_fingerprint(self.layout):
            self.layout = layout
            return True, previous
        new_ids = {c["control_id"] for c in layout["controls"]}
        to_release = set()
        for cid, _group in self.holds.items():
            if cid not in new_ids:
                to_release.add(cid)
                continue
            old = self.control(cid) or {}
            new = next(c for c in layout["controls"] if c["control_id"] == cid)
            if (
                old.get("binding") != new.get("binding")
                or old.get("safety") != new.get("safety")
                or old.get("control_type") != new.get("control_type")
                or old.get("permission") != new.get("permission")
            ):
                to_release.add(cid)
        release_failed = False
        try:
            for cid in to_release:
                group = self.holds.get(cid) or {}
                control = self.control(cid)
                for _inv, hold in list(group.items()):
                    result = self._force_release_hold(hold, control, "layout_change")
                    rec = {
                        "control_id": cid,
                        "invocation_id": hold.invocation_id,
                        "reason": "layout_change",
                        "router_ok": result.ok,
                    }
                    if result.ok:
                        del group[_inv]
                        hold.physical_active = False
                        hold.release_pending = False
                        self.last_releases.append(rec)
                        self._emergency_attempts.pop((cid, hold.invocation_id), None)
                    else:
                        hold.release_pending = True
                        hold.release_reason = "layout_change"
                        hold.physical_active = True
                        rec["status"] = "release_pending"
                        self.unsafe_releases.append(rec)
                        self.last_releases.append(rec)
                        self.health = {**self.health, "engine": "critical", "output": "degraded"}
                        self._record_safety_event("unconfirmed release during layout change", cid)
                        release_failed = True
                if not group:
                    self.holds.pop(cid, None)
                    pending = any(
                        item.get("control_id") == cid and item.get("status") == "release_pending"
                        for item in self.unsafe_releases
                    )
                    if not pending:
                        self.effects[cid] = False
            if release_failed:
                self._persist_safety()
                self.notify_schedule()
                return False, previous
            self._install_layout(layout)
            self.authority_epoch += 1
            self._bump_session_epochs()
            for rec in self.sessions.values():
                rec["asset_ack_revision"] = None
                rec["asset_ack_hash"] = None
        except Exception:
            self.layout = previous
            self.authority_epoch = previous_epoch
            self.notify_schedule()
            return False, previous
        self.notify_schedule()
        return True, previous

    def _validate_layout(self, layout: dict[str, Any]) -> None:
        if layout.get("show_id") and layout["show_id"] != self.show_id:
            raise ValueError("layout show_id mismatch")
        new_rev = int(layout.get("revision") or 0)
        if self.layout:
            old_rev = int(self.layout.get("revision") or 0)
            if new_rev < old_rev:
                raise ValueError("layout revision not monotonic")
            if new_rev == old_rev and layout_fingerprint(layout) != layout_fingerprint(self.layout):
                raise ValueError("layout content changed at the same revision")
        declared = layout.get("sha256")
        if declared and str(declared) != layout_fingerprint(layout):
            raise ValueError("layout hash mismatch")
        report = {
            "acp": "1.2",
            "message_id": "0193f8d8-4c4e-7d8b-a2ab-0000000000ff",
            "type": "remote.layout.report",
            "source": self.source.to_dict(),
            "timestamp_utc": "2026-08-17T16:42:15.231Z",
            "qos": "reliable",
            "flags": [],
            "payload": {"layout": layout},
        }
        validate_message(report)
        _reject_executable(layout)
        raw = json.dumps(layout, default=str).encode()
        if len(raw) > SURFACE_LIMITS["max_surface_bytes"]:
            raise ValueError("surface exceeds size limit")
        pages = layout.get("pages") or []
        controls = layout.get("controls") or []
        if len(pages) > SURFACE_LIMITS["max_pages"] or len(controls) > SURFACE_LIMITS["max_controls"]:
            raise ValueError("surface exceeds complexity limit")
        for page in pages:
            groups = page.get("groups") or []
            if len(groups) > SURFACE_LIMITS["max_groups_per_page"]:
                raise ValueError("surface exceeds complexity limit")
        min_schema = str(layout.get("min_client_schema") or "1.0")
        max_schema = str(layout.get("max_client_schema") or layout.get("schema_version") or "1.0")
        try:
            schema_ok = version_at_least(self.client_surface_schema, min_schema)
            schema_ok = schema_ok and version_at_least(max_schema, self.client_surface_schema)
            if not schema_ok:
                raise ValueError("incompatible surface schema")
        except ValueError as exc:
            if "incompatible" in str(exc):
                raise
            raise ValueError("incompatible surface schema") from exc
        profile_hint = layout.get("compatible_profile")
        if profile_hint and profile_hint not in {REMOTE_PROFILE_PRISM, REMOTE_PROFILE_CONDUCTOR, "remote"}:
            raise ValueError("incompatible surface schema")
        controls = layout.get("controls") or []
        ids = [c["control_id"] for c in controls]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate control_id")
        pages = layout.get("pages") or []
        page_ids = [p.get("page_id") for p in pages]
        if len(page_ids) != len(set(page_ids)):
            raise ValueError("duplicate page_id")
        known = set(ids)
        for page in pages:
            for group in page.get("groups") or []:
                for cid in group.get("controls") or []:
                    if cid not in known:
                        raise ValueError(f"page references missing control {cid}")
        for control in controls:
            if len(str(control.get("label") or "")) > SURFACE_LIMITS["max_label_chars"]:
                raise ValueError("control label too long")
            ctype = normalize_control_type(str(control.get("control_type") or ""))
            if ctype in DISPLAY_ONLY_TYPES or (
                ctype not in CONTROL_INTERACTIONS and ctype not in DISPLAY_ONLY_TYPES
            ):
                lo, hi = control.get("min"), control.get("max")
                if lo is not None and hi is not None and float(lo) > float(hi):
                    raise ValueError("min greater than max")
                continue
            required_permissions(control)
            lo, hi = control.get("min"), control.get("max")
            if lo is not None and hi is not None and float(lo) > float(hi):
                raise ValueError("min greater than max")

    def _install_layout(self, layout: dict[str, Any]) -> None:
        self.layout = layout
        for control in layout.get("controls") or []:
            cid = control["control_id"]
            self.revisions.setdefault(cid, 1)
            if control["control_type"] == "toggle":
                self.values.setdefault(cid, False)
            elif control["control_type"] in {"slider", "encoder"}:
                self.values.setdefault(cid, 0.0)

    def _reconcile_holds(self) -> None:
        def stale(hold: Hold) -> bool:
            control = self.control(hold.control_id)
            if control is None or not self.armed:
                return True
            try:
                needed = required_permissions(control)
            except ValueError:
                return True
            roles = self.roles_for(hold.node_id)
            return bool(needed and not has_permissions(roles, needed))

        self._release_holds(stale, reason="revoked")

    def _release_holds(self, pred, *, reason: str = "released") -> list[str]:
        released: list[str] = []
        dirty = False
        for control_id, group in list(self.holds.items()):
            control = self.control(control_id)
            for inv_id, hold in list(group.items()):
                if not pred(hold):
                    continue
                result = self._force_release_hold(hold, control, reason)
                rec = {
                    "control_id": control_id,
                    "invocation_id": inv_id,
                    "reason": reason,
                    "router_ok": result.ok,
                }
                if result.ok:
                    del group[inv_id]
                    released.append(control_id)
                    hold.physical_active = False
                    hold.release_pending = False
                    self.last_releases.append(rec)
                    self._broadcast_control_state(control_id, False, confidence="confirmed")
                else:
                    hold.release_pending = True
                    hold.release_reason = reason
                    hold.physical_active = True
                    rec["status"] = "release_pending"
                    self.unsafe_releases.append(rec)
                    self.last_releases.append(rec)
                    self.health = {**self.health, "engine": "critical", "output": "degraded"}
                    self._record_safety_event(f"unconfirmed {reason} release", control_id)
                    self._broadcast_control_state(control_id, True, confidence="unverified")
                    health = make_envelope(
                        type="state.delta",
                        source=self.source,
                        qos=QoS.LATEST,
                        payload={
                            "resource": "system.health",
                            "revision": self.snapshot_revision,
                            "owner": self.source.to_dict(),
                            "value": dict(self.health),
                            "confidence": "confirmed",
                        },
                    )
                    self._fanout([health], origin="")
                dirty = True
            if not group:
                self.holds.pop(control_id, None)
                pending = any(
                    item.get("control_id") == control_id and item.get("status") == "release_pending"
                    for item in self.unsafe_releases
                )
                if not pending:
                    self.effects[control_id] = False
        if dirty:
            self.snapshot_revision += 1
            try:
                self._persist_safety()
            except Exception:
                self.health = {**self.health, "engine": "critical", "output": "degraded"}
                self._record_safety_event("failed to persist safety state", None)
                raise
            self.notify_schedule()
            self.notify_publications()
        return released

    def _force_release_hold(self, hold: Hold, control: dict[str, Any] | None, reason: str) -> ActionResult:
        action = str(((control or {}).get("binding") or {}).get("action") or "")
        ctx = ActionContext(
            session_id=hold.session_id,
            node_id=hold.node_id,
            invocation_id=hold.invocation_id,
            control_id=hold.control_id,
            interaction="force_release",
            lease_id=hold.lease_id,
            reason=reason,
        )
        try:
            return self._router().force_release(action, control, ctx)
        except Exception as exc:  # noqa: BLE001
            return ActionResult(ok=False, code="internal", message=str(exc), extra={"reason": reason})

    def _route(
        self,
        env: Envelope,
        op: str,
        control: dict[str, Any],
        ctx: ActionContext,
    ) -> ActionResult | list[Envelope]:
        action = str((control.get("binding") or {}).get("action") or "")
        try:
            result = getattr(self._router(), op)(action, control, ctx)
        except Exception as exc:  # noqa: BLE001
            return [self._reject(env, "internal", f"action router failed: {exc}")]
        if not result.ok:
            code = result.code or ("timeout" if result.status == "timeout" else "internal")
            return [self._reject(
                env,
                code,
                result.message or "action router rejected",
                retryable=result.retryable,
            )]
        return result

    def export_safety_state(self) -> dict[str, Any]:
        holds = []
        for group in self.holds.values():
            for hold in group.values():
                holds.append({
                    "control_id": hold.control_id,
                    "invocation_id": hold.invocation_id,
                    "session_id": hold.session_id,
                    "node_id": hold.node_id,
                    "started_ms": hold.started_ms,
                    "max_hold_ms": hold.max_hold_ms,
                    "failsafe": hold.failsafe,
                    "lease_id": hold.lease_id,
                    "value": hold.value,
                    "expires_at_ms": hold.expires_at_ms,
                    "release_pending": hold.release_pending,
                    "release_reason": hold.release_reason,
                    "physical_active": hold.physical_active,
                })
        return {
            "version": SAFETY_STATE_VERSION,
            "holds": holds,
            "unsafe_releases": list(self.unsafe_releases),
            "snapshot_revision": self.snapshot_revision,
            "authority_epoch": self.authority_epoch,
            "armed": self.armed,
            "health": dict(self.health),
        }

    @staticmethod
    def _migrate_hold_record(item: dict[str, Any]) -> dict[str, Any]:
        out = dict(item)
        started = int(out.get("started_ms") or 0)
        max_hold = int(out.get("max_hold_ms") or DEFAULT_MAX_HOLD_MS)
        out.setdefault("expires_at_ms", started + max_hold if max_hold else 0)
        out.setdefault("release_pending", False)
        out.setdefault("release_reason", None)
        out.setdefault("physical_active", True)
        return out

    def _persist_safety(self) -> None:
        if self.store is None:
            return
        self.store.save("remote_safety", self.export_safety_state())

    def recover_from_restart(self, state: dict[str, Any] | None = None) -> list[str]:
        data = state
        if data is None and self.store is not None:
            loaded = self.store.load("remote_safety", {})
            data = loaded if isinstance(loaded, dict) else {}
        if not data:
            return []
        self.holds.clear()
        if data.get("unsafe_releases"):
            self.unsafe_releases = [dict(item) for item in data["unsafe_releases"]]
        for item in data.get("holds") or []:
            item = self._migrate_hold_record(item)
            hold = Hold(
                invocation_id=str(item.get("invocation_id") or new_uuid()),
                session_id=str(item.get("session_id") or ""),
                node_id=str(item.get("node_id") or ""),
                control_id=str(item.get("control_id") or ""),
                started_ms=int(item.get("started_ms") or 0),
                max_hold_ms=int(item.get("max_hold_ms") or DEFAULT_MAX_HOLD_MS),
                failsafe=str(item.get("failsafe") or DEFAULT_FAILSAFE),
                lease_id=str(item.get("lease_id") or new_uuid()),
                value=item.get("value"),
                expires_at_ms=int(item.get("expires_at_ms") or 0),
                release_pending=bool(item.get("release_pending")),
                release_reason=item.get("release_reason"),
                physical_active=bool(item.get("physical_active", True)),
            )
            self.holds.setdefault(hold.control_id, {})[hold.invocation_id] = hold
            if hold.physical_active:
                self.effects[hold.control_id] = True
        released = self._release_holds(lambda _h: True, reason="process_recovery")
        if any(group for group in self.holds.values()) or any(
            item.get("status") == "release_pending" for item in self.unsafe_releases
        ):
            self.health = {**self.health, "engine": "critical", "output": "degraded"}
            self._record_safety_event("unconfirmed physical release after restart", None)
        self.notify_schedule()
        return released

    def _record_safety_event(self, message: str, control_id: str | None) -> None:
        rec = {
            "code": "remote.control.unconfirmed_release",
            "severity": "critical",
            "message": message,
            "control_id": control_id,
        }
        self._safety_events.append(rec)
        alert = make_envelope(
            type="error.report",
            source=self.source,
            qos=QoS.RELIABLE,
            payload={
                "code": "remote.control.unconfirmed_release",
                "category": "internal",
                "severity": "critical",
                "message": message,
                "retryable": True,
                "details": {"control_id": control_id, "disposition": "invalid_state"},
            },
        )
        for sid, rec_sess in self.sessions.items():
            if rec_sess.get("hello_completed"):
                dest = Endpoint(node_id=str(rec_sess.get("node_id") or ""))
                queued = self._outbound.setdefault(sid, [])
                queued.append(make_envelope(
                    type=alert.type,
                    source=alert.source,
                    destination=dest,
                    qos=alert.qos,
                    payload=dict(alert.payload),
                ))
        self.notify_publications()

    def _reject(self, env: Envelope, code: str, message: str, *, retryable: bool | None = None) -> Envelope:
        fields = _error_fields(code, message, retryable=retryable)
        if code == "remote.control.unconfirmed_release":
            fields["severity"] = "critical"
        return make_ack(env, self.source, CommandStatus.REJECTED, error=fields)

    def _state(self, env: Envelope, control_id: str, value: Any) -> Envelope:
        payload: dict[str, Any] = {
            "control_id": control_id,
            "revision": self.revisions.get(control_id, 1),
            "enabled": True,
            "available": True,
            "value": value,
            "confidence": "confirmed",
        }
        return make_envelope(
            type="remote.control.state",
            source=self.source,
            destination=env.source,
            qos=QoS.LATEST,
            payload=payload,
            causation_id=env.message_id,
        )

    def _snapshot(self, env: Envelope, session_id: str | None = None) -> Envelope:
        controls = []
        for control in self.layout.get("controls") or []:
            cid = control["control_id"]
            controls.append({
                "control_id": cid,
                "revision": self.revisions.get(cid, 1),
                "enabled": control.get("enabled", True),
                "available": control.get("available", True),
                "value": self.values.get(cid, self.effect_active(cid)),
                "confidence": "confirmed",
            })
        rec = self.sessions.get(session_id) if session_id else None
        if rec is not None:
            rec["snapshot_delivered_revision"] = self.snapshot_revision
        return make_envelope(
            type="remote.control.snapshot",
            source=self.source,
            destination=env.source,
            payload={"controls": controls, "snapshot_revision": self.snapshot_revision},
            causation_id=env.message_id,
        )

    def _permissions_msg(self, env: Envelope, roles: set[str]) -> Envelope:
        return make_envelope(
            type="remote.permissions",
            source=self.source,
            destination=env.source,
            payload={
                "roles": sorted(roles),
                "permissions": sorted(permissions_for_roles(roles)),
                "revision": self.permissions_revision,
            },
            causation_id=env.message_id,
        )

    def _readiness_msg(self, env: Envelope, session_id: str) -> Envelope:
        return make_envelope(
            type="remote.readiness.changed",
            source=self.source,
            destination=env.source,
            payload={
                "state": self.compute_readiness(session_id),
                "session_id": session_id,
                "layout_revision": self.layout.get("revision"),
                "permissions_revision": self.permissions_revision,
                "snapshot_revision": self.snapshot_revision,
            },
            correlation_id=env.message_id,
            causation_id=env.message_id,
        )

    def _nav_state(self, env: Envelope) -> Envelope:
        return make_envelope(
            type="remote.navigation.state",
            source=self.source,
            destination=env.source,
            qos=QoS.LATEST,
            payload={
                "show_id": self.show_id,
                "song_id": self.song_id,
                "selected_song_id": self.selected_song_id,
                "next_song_id": self.next_song_id,
                "cue_id": self.cue_id,
                "next_cue_id": self.next_cue_id,
                "mode": self.mode,
                "return_context": dict(self.return_context) or None,
                "setlist_id": self.setlist_id,
                "setlist_name": self.setlist_name,
                "songs": list(self.songs),
            },
            causation_id=env.message_id,
        )

    def _presentation(self, env: Envelope) -> Envelope:
        return make_envelope(
            type="remote.presentation.state",
            source=self.source,
            destination=env.source,
            qos=QoS.LATEST,
            payload={
                "show_id": self.show_id,
                "show_revision": self.show_revision,
                "song_id": self.song_id,
                "cue_id": self.cue_id,
                "next_cue_id": self.next_cue_id,
                "transport": "live",
            },
            causation_id=env.message_id,
        )

    def _resource_delta(self, env: Envelope, resource: str, value: dict[str, Any]) -> Envelope:
        return make_envelope(
            type="state.delta",
            source=self.source,
            destination=env.source,
            qos=QoS.LATEST,
            payload={
                "resource": resource,
                "revision": self.go_count,
                "owner": self.source.to_dict(),
                "value": value,
                "confidence": "confirmed",
            },
            causation_id=env.message_id,
        )


class RemoteHost:
    """Production session loop: expiry, fanout drain, transfer, and subscriptions."""

    def __init__(self, authority: RemoteAuthority, *, inline_surface: bool = False) -> None:
        self.authority = authority
        self.authority.inline_surface = inline_surface
        self.sessions: dict[str, Session] = {}
        self._closed = False
        self._pub_task: asyncio.Task[None] | None = None

    def attach(self, session: Session) -> None:
        if not session.session_id:
            raise SessionError("authentication", "session has no session_id")
        self.sessions[session.session_id] = session

    def detach(self, session: Session) -> None:
        sid = session.session_id
        if not sid:
            return
        self.authority.on_session_lost(sid)
        self.sessions.pop(sid, None)

    async def start(self) -> None:
        self.authority.start_scheduler()
        if self._pub_task is None or self._pub_task.done():
            self._pub_task = asyncio.create_task(self._publish_loop(), name="remote-pub-flush")

    async def _publish_loop(self) -> None:
        try:
            while not self._closed:
                await self.authority.wait_outbound()
                await self.flush()
        except asyncio.CancelledError:
            return

    async def close(self) -> None:
        await self.authority.stop_scheduler()
        try:
            await asyncio.wait_for(self.flush(), timeout=1.0)
        except TimeoutError:
            pass
        self._closed = True
        for session in list(self.sessions.values()):
            self.detach(session)
        try:
            await asyncio.wait_for(self.flush(), timeout=0.5)
        except TimeoutError:
            pass
        if self._pub_task is not None:
            self._pub_task.cancel()
            try:
                await self._pub_task
            except asyncio.CancelledError:
                pass
            self._pub_task = None

    async def serve(self, session: Session) -> None:
        if session.session_id:
            self.attach(session)
        try:
            async for env in session.subscribe():
                if self._closed:
                    break
                if session.session_id and session.session_id not in self.sessions:
                    self.attach(session)
                replies = self.authority.handle(env, session)
                for reply in replies:
                    await session.send(reply)
                await self.flush()
        finally:
            self.detach(session)
            await self.flush()

    async def flush(self) -> None:
        for sid, session in list(self.sessions.items()):
            if session.state != SessionState.ESTABLISHED:
                continue
            pending = self.authority.take_outbound(sid)
            for env in pending:
                try:
                    await session.send(env)
                except ReliableOverflow:
                    self.authority.mark_missed_delta(sid)
                    break
                except Exception:
                    self.authority.mark_missed_delta(sid)
                    break


def sample_layout(*, show_id: str, layout_id: str) -> dict[str, Any]:
    return {
        "surface_id": layout_id,
        "layout_id": layout_id,
        "revision": 8,
        "show_id": show_id,
        "show_revision": 1,
        "name": "Haywire FOH Remote",
        "schema_version": "1.0",
        "min_client_schema": "1.0",
        "max_client_schema": "1.0",
        "compatible_profile": "aurora.remote.prism.v1",
        "asset_type": "aurora.remote.surface",
        "pages": [{
            "page_id": "main",
            "title": "FOH",
            "order": 0,
            "groups": [{
                "group_id": "live",
                "title": "Live",
                "order": 0,
                "controls": ["cue_go", "fog_burst", "work_lights"],
            }],
        }],
        "controls": [
            {
                "control_id": "cue_go",
                "label": "GO",
                "control_type": "button",
                "permission": "remote.operator",
                "style": "primary",
                "feedback": "state",
                "binding": {"target": "prism", "action": "cue.go"},
                "safety": {"class": "caution"},
            },
            {
                "control_id": "fog_burst",
                "label": "FOG",
                "control_type": "momentary",
                "permission": "remote.busker",
                "style": "warning",
                "feedback": "state",
                "concurrency": "shared",
                "binding": {"target": "prism", "action": "busk.fog.output", "parameters": {"value": 1.0}},
                "safety": {
                    "class": "caution",
                    "failsafe": "release_on_disconnect",
                    "failsafe_required": True,
                    "max_hold_ms": 10000,
                    "heartbeat_required": True,
                },
            },
            {
                "control_id": "work_lights",
                "label": "Work Lights",
                "control_type": "toggle",
                "permission": "remote.operator",
                "feedback": "state",
                "binding": {"target": "prism", "action": "busk.work_lights"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "look_recall",
                "label": "Look",
                "control_type": "button",
                "permission": "look.execute",
                "binding": {"target": "prism", "action": "look.recall"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "free_play_enter",
                "label": "Free Play",
                "control_type": "button",
                "permission": "remote.operator",
                "binding": {"target": "prism", "action": "show.free_play.enter"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "free_play_exit",
                "label": "Return to Setlist",
                "control_type": "button",
                "permission": "remote.operator",
                "binding": {"target": "prism", "action": "show.free_play.exit"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "song_load",
                "label": "Load Song",
                "control_type": "button",
                "permission": "song.load",
                "binding": {"target": "prism", "action": "show.song.load"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "song_select",
                "label": "Select Song",
                "control_type": "button",
                "permission": "song.select",
                "binding": {"target": "prism", "action": "show.song.select"},
                "safety": {"class": "normal"},
            },
            {
                "control_id": "grand_master",
                "label": "GM",
                "control_type": "slider",
                "permission": "output.grand_master",
                "binding": {"target": "prism", "action": "output.grand_master.set"},
                "min": 0,
                "max": 1,
                "step": 0.01,
                "safety": {"class": "caution"},
            },
            {
                "control_id": "blackout",
                "label": "Blackout",
                "control_type": "toggle",
                "permission": "output.blackout",
                "binding": {"target": "prism", "action": "output.blackout.set"},
                "safety": {"class": "dangerous"},
            },
        ],
    }


def default_remote_identity(node_id: str, name: str = "FOH iPad") -> RemoteIdentity:
    return RemoteIdentity(
        node_id=node_id,
        instance_id=new_uuid(),
        device_id=new_uuid(),
        remote_id=new_uuid(),
        device_name=name,
        platform="ipados",
        app_version="1.0.0",
    )


class RemoteClient:
    """Client helper. Constructs protocol envelopes and waits for terminal acks."""

    def __init__(
        self,
        source: Endpoint,
        *,
        show_id: str,
        layout_id: str,
        layout_revision: int = 8,
        show_revision: int = 1,
        session: Session | None = None,
        destination: Endpoint | None = None,
    ) -> None:
        self.source = source
        self.show_id = show_id
        self.show_revision = show_revision
        self.layout_id = layout_id
        self.layout_revision = layout_revision
        self.session = session
        self.destination = destination
        self.pending: dict[str, str] = {}
        self.leases: dict[str, str] = {}
        self.values: dict[str, Any] = {}
        self.errors: dict[str, dict[str, Any]] = {}
        self._seen_results: set[str] = set()
        self.snapshot_revision: int | None = None
        self.layout_hash: str | None = None
        self.view: dict[str, Any] = {}
        self.stale = False
        self.ready = False
        self.layout: dict[str, Any] | None = None
        self._sent_invokes: dict[str, Envelope] = {}
        self._ephemeral_pending: set[str] = set()
        self._lease_expires: dict[str, int] = {}
        self._lease_duration: dict[str, int] = {}
        self._lease_controls: dict[str, str] = {}
        self._refresh_in_flight: set[str] = set()
        self.transfer = TransferAgent(source)
        self._lifecycle_task: asyncio.Task[None] | None = None
        self._renew_task: asyncio.Task[None] | None = None
        self._pending_end: dict[str, Envelope] = {}
        self._staged_layout: dict[str, Any] | None = None
        self._staged_hash: str | None = None
        self._staged_transfer_id: str | None = None
        self._staged_ready: asyncio.Event = asyncio.Event()
        self._dispatching = False

    def _dest(self) -> Endpoint | None:
        if self.destination is not None:
            return self.destination
        if self.session is not None and self.session.peer is not None:
            return Endpoint(node_id=self.session.peer.node_id)
        return None

    def record_result(self, invocation_id: str, ack: Envelope) -> None:
        status = str(ack.payload.get("status") or "")
        if status not in {"applied", "duplicate", "rejected", "failed", "completed"}:
            return
        result = dict(ack.payload.get("result") or {})
        snap = result.get("snapshot_revision")
        if snap is not None:
            incoming = int(snap)
            if self.snapshot_revision is not None and incoming < self.snapshot_revision:
                return
            self.snapshot_revision = incoming
        if invocation_id in self._seen_results and status == "duplicate":
            lease = result.get("lease_id")
            if lease:
                self.leases.setdefault(invocation_id, str(lease))
            return
        self._seen_results.add(invocation_id)
        self.pending.pop(invocation_id, None)
        if status in {"rejected", "failed"}:
            self.errors[invocation_id] = dict(ack.payload.get("error") or {})
            self._drop_lease(invocation_id, stale=True)
            return
        lease = result.get("lease_id")
        if lease:
            self.leases[invocation_id] = str(lease)
        if result.get("active") is False:
            self.leases.pop(invocation_id, None)
        if "value" in result:
            control_id = str(result.get("control_id") or "")
            if control_id:
                self.values[control_id] = result["value"]
        if status in {"applied", "duplicate"} and result.get("lease_id"):
            duration = result.get("expires_ms")
            if duration is not None:
                self._lease_duration[invocation_id] = int(duration)
                self._lease_expires[invocation_id] = int(time.monotonic() * 1000) + int(duration)
            elif result.get("expires_at_ms") is not None:
                self._lease_expires[invocation_id] = int(result["expires_at_ms"])
            self._lease_controls[invocation_id] = str(result.get("control_id") or "")
        if result.get("active") is False or status in {"rejected", "failed"}:
            self._drop_lease(invocation_id, stale=status in {"rejected", "failed"})

    def apply_publication(self, env: Envelope) -> None:
        """Authoritative view comes from state publications, never from command.ack."""
        if env.type == "state.delta":
            self.view[str(env.payload.get("resource") or "")] = dict(env.payload.get("value") or {})
        elif env.type == "state.snapshot":
            for item in env.payload.get("resources") or []:
                if isinstance(item, dict) and item.get("resource"):
                    self.view[str(item["resource"])] = dict(item.get("value") or {})
            self.stale = False
        elif env.type == "remote.navigation.state":
            self.view["show.navigation"] = dict(env.payload)
        elif env.type == "remote.presentation.state":
            self.view["show.presentation"] = dict(env.payload)
        elif env.type == "remote.control.state":
            cid = str(env.payload.get("control_id") or "")
            self.view[f"control.{cid}"] = dict(env.payload)
            if env.payload.get("value") is False or env.payload.get("confidence") == "unverified":
                for inv, control_id in list(self._lease_controls.items()):
                    if control_id == cid:
                        self._drop_lease(inv, stale=env.payload.get("confidence") == "unverified")
        elif env.type == "remote.control.snapshot":
            self.view["snapshot_revision"] = env.payload.get("snapshot_revision")
            self.snapshot_revision = env.payload.get("snapshot_revision", self.snapshot_revision)
            self.stale = False
        elif env.type == "error.report":
            self.view["system.alert"] = dict(env.payload)
        if env.type in {"state.delta", "remote.navigation.state", "remote.presentation.state", "remote.control.state"}:
            if self.stale:
                self.view.setdefault("_stale", True)

    def _drop_lease(self, invocation_id: str, *, stale: bool = False) -> None:
        self.leases.pop(invocation_id, None)
        self._lease_expires.pop(invocation_id, None)
        self._lease_duration.pop(invocation_id, None)
        self._lease_controls.pop(invocation_id, None)
        self._refresh_in_flight.discard(invocation_id)
        if stale:
            self.stale = True
            self.ready = False

    def invoke(
        self,
        control_id: str,
        interaction: str = "activate",
        value: Any = None,
        *,
        invocation_id: str | None = None,
        lease_id: str | None = None,
    ) -> Envelope:
        inv = invocation_id or new_uuid()
        sent_key = f"{inv}:{interaction}:{lease_id or ''}"
        if invocation_id and sent_key in self._sent_invokes:
            return self._sent_invokes[sent_key]
        self.pending[inv] = "pending"
        issued = datetime.now(UTC)
        live = interaction in MOMENTARY_INTERACTIONS or control_id in {"cue_go", "go", "nav_go"}
        payload: dict[str, Any] = {
            "control_id": control_id,
            "invocation_id": inv,
            "interaction": interaction,
            "value": value,
            "show_id": self.show_id,
            "show_revision": self.show_revision,
            "layout_id": self.layout_id,
            "layout_revision": self.layout_revision,
            "idempotency_key": inv,
            "issued_at": format_ts(issued),
            "expires_at": format_ts(issued + timedelta(milliseconds=MAX_LIVE_EPHEMERAL_AGE_MS)),
            "max_age_ms": MAX_LIVE_EPHEMERAL_AGE_MS,
            "delivery": "live_ephemeral" if live else None,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        if lease_id:
            payload["lease_id"] = lease_id
        env = make_envelope(
            type="remote.control.invoke",
            source=self.source,
            destination=self._dest(),
            payload=payload,
        )
        self._sent_invokes[sent_key] = env
        if live:
            self._ephemeral_pending.add(inv)
        return env

    def navigate(self, kind: str, *, song_id: str | None = None, idempotency_key: str | None = None) -> Envelope:
        key = idempotency_key or new_uuid()
        payload: dict[str, Any] = {"kind": kind, "idempotency_key": key}
        if song_id:
            payload["song_id"] = song_id
        if kind == LIVE_EPHEMERAL_NAV_KIND:
            issued = datetime.now(UTC)
            payload["issued_at"] = format_ts(issued)
            payload["expires_at"] = format_ts(issued + timedelta(milliseconds=MAX_LIVE_EPHEMERAL_AGE_MS))
            payload["max_age_ms"] = MAX_LIVE_EPHEMERAL_AGE_MS
            payload["delivery"] = "live_ephemeral"
        return make_envelope(
            type="remote.navigation.request",
            source=self.source,
            destination=self._dest(),
            payload=payload,
        )

    def begin_momentary(self, control_id: str, value: Any = 1.0, *, invocation_id: str | None = None) -> Envelope:
        return self.invoke(control_id, "momentary_begin", value, invocation_id=invocation_id)

    def end_momentary(self, control_id: str, invocation_id: str, *, lease_id: str | None = None) -> Envelope:
        lease = lease_id if lease_id is not None else self.leases.get(invocation_id)
        return self.invoke(control_id, "momentary_end", invocation_id=invocation_id, lease_id=lease)

    def layout_request(self) -> Envelope:
        payload: dict[str, Any] = {"show_id": self.show_id, "layout_id": self.layout_id}
        if self.layout_hash:
            payload["cached_sha256"] = self.layout_hash
        return make_envelope(
            type="remote.layout.request",
            source=self.source,
            destination=self._dest(),
            payload=payload,
        )

    def state_request(self, resources: list[str] | None = None) -> Envelope:
        return make_envelope(
            type="state.request",
            source=self.source,
            destination=self._dest(),
            payload={"resources": list(resources or [])},
        )

    def readiness_ack(
        self,
        *,
        layout: dict[str, Any] | None = None,
        snapshot_revision: int | None = None,
        state: str = "ready",
    ) -> Envelope:
        body = layout or {}
        layout_rev = body.get("revision", self.layout_revision)
        layout_hash = body.get("sha256") or (layout_fingerprint(body) if body else self.layout_hash)
        payload: dict[str, Any] = {"state": state, "layout_revision": layout_rev}
        if layout_hash:
            payload["layout_hash"] = layout_hash
        snap = snapshot_revision if snapshot_revision is not None else self.snapshot_revision
        if snap is not None:
            payload["snapshot_revision"] = snap
        return make_envelope(
            type="remote.readiness",
            source=self.source,
            destination=self._dest(),
            payload=payload,
        )

    async def send(self, env: Envelope) -> Envelope | None:
        if self.session is None:
            raise RuntimeError("RemoteClient has no Session; this is an envelope builder")
        return await self.session.send(env)

    async def request(self, env: Envelope, timeout: float = 5.0) -> Envelope:
        if self.session is None:
            raise RuntimeError("RemoteClient has no Session; this is an envelope builder")
        try:
            ack = await self.session.request(env, timeout=timeout)
        except SessionError:
            if env.type == "remote.control.invoke":
                inv = str(env.payload.get("invocation_id") or "")
                if inv:
                    self.errors[inv] = {"code": "timeout", "message": "request timed out"}
                    self.pending.pop(inv, None)
                    self.cancel_pending_ephemeral()
            raise
        if env.type == "remote.control.invoke":
            self.record_result(str(env.payload.get("invocation_id") or ""), ack)
        elif env.type == "remote.layout.request" and ack.type == "remote.layout.report":
            self._apply_layout_report(ack)
        if env.type == "remote.control.invoke" and ack.type == "command.ack":
            pass
        else:
            self.apply_publication(ack)
        return ack

    def _apply_layout_report(self, ack: Envelope) -> None:
        layout = ack.payload.get("layout") or {}
        if layout.get("layout_id") or layout.get("surface_id"):
            self.layout_id = str(layout.get("surface_id") or layout["layout_id"])
        if layout.get("revision") is not None:
            self.layout_revision = int(layout["revision"])
        if layout:
            self.layout = dict(layout)
            self.layout_hash = str(layout.get("sha256") or layout_fingerprint(layout))
        elif ack.payload.get("sha256"):
            self.layout_hash = str(ack.payload["sha256"])
        if ack.payload.get("cached"):
            self.ready = False

    def ingest(self, messages: list[Envelope]) -> None:
        for item in messages:
            if item.type != "command.ack":
                self.apply_publication(item)

    def cancel_pending_ephemeral(self) -> None:
        for inv in list(self._ephemeral_pending):
            self.pending.pop(inv, None)
        self._ephemeral_pending.clear()

    def mark_stale(self) -> None:
        self.stale = True
        self.ready = False
        for key, value in list(self.view.items()):
            if isinstance(value, dict):
                self.view[key] = {**value, "stale": True}
        self.cancel_pending_ephemeral()

    async def start_dispatcher(self) -> None:
        if self.session is None:
            raise RuntimeError("RemoteClient has no Session")
        if self._lifecycle_task is None or self._lifecycle_task.done():
            self._dispatching = True
            self._lifecycle_task = asyncio.create_task(self._consume_publications())

    async def start_lifecycle(self) -> None:
        await self.start_dispatcher()
        if self._renew_task is None or self._renew_task.done():
            self._renew_task = asyncio.create_task(self._renew_leases())

    async def stop_lifecycle(self) -> None:
        for task in (self._lifecycle_task, self._renew_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._lifecycle_task = None
        self._renew_task = None
        self._dispatching = False

    async def _consume_publications(self) -> None:
        assert self.session is not None
        async for env in self.session.subscribe():
            if env.type.startswith("resource."):
                await self._handle_resource(env)
            else:
                self.apply_publication(env)

    async def _renew_leases(self) -> None:
        while True:
            await asyncio.sleep(0.05)
            if self.session is None or self.stale:
                continue
            now_ms = int(time.monotonic() * 1000)
            for inv, expires in list(self._lease_expires.items()):
                duration = self._lease_duration.get(inv)
                if not duration:
                    continue
                remaining = expires - now_ms
                if remaining <= 0:
                    self._drop_lease(inv, stale=True)
                    continue
                if remaining > int(duration * 0.5):
                    continue
                if inv in self._refresh_in_flight:
                    continue
                control_id = self._lease_controls.get(inv)
                lease = self.leases.get(inv)
                if not control_id or not lease:
                    continue
                self._refresh_in_flight.add(inv)
                try:
                    ack = await self.session.request(make_envelope(
                        type="remote.momentary.refresh",
                        source=self.source,
                        destination=self._dest(),
                        payload={"control_id": control_id, "invocation_id": inv, "lease_id": lease},
                    ), timeout=1.0)
                    status = str(ack.payload.get("status") or "")
                    if status in {"rejected", "failed"}:
                        self._drop_lease(inv, stale=True)
                        continue
                    result = dict(ack.payload.get("result") or {})
                    granted = int(result.get("expires_ms") or duration)
                    self._lease_duration[inv] = granted
                    self._lease_expires[inv] = int(time.monotonic() * 1000) + granted
                except Exception:
                    self._drop_lease(inv, stale=True)
                finally:
                    self._refresh_in_flight.discard(inv)

    async def _handle_resource(self, env: Envelope) -> None:
        if self.session is None:
            return
        replies = self.transfer.handle(env)
        for reply in replies:
            await self.session.send(reply)
        if env.type != "resource.complete":
            return
        tid = str(env.payload.get("transfer_id") or "")
        xfer = self.transfer.transfers.get(tid)
        if xfer is None or xfer.state is not TransferState.VERIFIED or xfer.staged is None:
            return
        try:
            layout = json.loads(xfer.staged.decode())
        except (ValueError, UnicodeDecodeError):
            return
        if isinstance(layout, dict):
            self._staged_layout = layout
            self._staged_hash = layout_fingerprint(layout)
            self._staged_transfer_id = tid
            self._staged_ready.set()

    def _commit_staged_layout(self) -> None:
        if self._staged_layout is None:
            return
        self.layout = self._staged_layout
        self.layout_hash = self._staged_hash or layout_fingerprint(self._staged_layout)
        if self._staged_layout.get("revision") is not None:
            self.layout_revision = int(self._staged_layout["revision"])
        if self.layout.get("layout_id") or self.layout.get("surface_id"):
            self.layout_id = str(self.layout.get("surface_id") or self.layout["layout_id"])
        self._clear_staged()

    def _clear_staged(self) -> None:
        self._staged_layout = None
        self._staged_hash = None
        self._staged_transfer_id = None
        self._staged_ready = asyncio.Event()

    async def sync_until_ready(self, hello: Envelope, timeout: float = 5.0) -> None:
        if self.session is None:
            raise RuntimeError("RemoteClient has no Session")
        await self.start_dispatcher()
        await self.request(hello, timeout=timeout)
        report = await self.request(self.layout_request(), timeout=timeout)
        if not report.payload.get("cached") and not report.payload.get("layout"):
            await self._wait_surface_transfer(timeout=timeout)
        if self.session.gap_count:
            self.mark_stale()
            snap_env = await self.request(self.state_request(), timeout=timeout)
            self.apply_publication(snap_env)
        else:
            try:
                await self.session.send(self.state_request())
            except Exception:
                pass
        snap = self.snapshot_revision
        ack = await self.request(
            self.readiness_ack(layout=self.layout, snapshot_revision=snap),
            timeout=timeout,
        )
        self.ready = str(ack.payload.get("state") or "") in READY_STATES
        if not self.ready:
            raise SessionError("remote.session.not_ready", "surface/snapshot sync incomplete")

    async def _wait_surface_transfer(self, timeout: float) -> None:
        assert self.session is not None
        await self.start_dispatcher()
        try:
            await asyncio.wait_for(self._staged_ready.wait(), timeout=timeout)
        except TimeoutError as exc:
            self._clear_staged()
            raise SessionError("timeout", "surface transfer did not complete") from exc
        tid = self._staged_transfer_id
        if not tid or self._staged_layout is None:
            raise SessionError("timeout", "surface transfer did not complete")
        try:
            ack = await self.request(make_envelope(
                type="resource.activate",
                source=self.source,
                destination=self._dest(),
                payload={"transfer_id": tid},
            ), timeout=timeout)
        except SessionError:
            self._clear_staged()
            raise
        if ack.payload.get("status") != "applied":
            self._clear_staged()
            raise SessionError("invalid_state", "surface activation rejected")
        self._commit_staged_layout()

    async def send_end_promptly(self, control_id: str, invocation_id: str) -> Envelope:
        env = self.end_momentary(control_id, invocation_id)
        self._pending_end[invocation_id] = env
        return await self.request(env)

    def on_disconnect(self) -> None:
        self.mark_stale()
        for inv, control_id in list(self._lease_controls.items()):
            self._pending_end[inv] = self.end_momentary(control_id, inv)

    async def invoke_wait(
        self,
        control_id: str,
        interaction: str = "activate",
        value: Any = None,
        *,
        invocation_id: str | None = None,
        lease_id: str | None = None,
        timeout: float = 5.0,
    ) -> Envelope:
        return await self.request(
            self.invoke(control_id, interaction, value, invocation_id=invocation_id, lease_id=lease_id),
            timeout=timeout,
        )

    async def begin_momentary_wait(
        self,
        control_id: str,
        value: Any = 1.0,
        *,
        invocation_id: str | None = None,
        timeout: float = 5.0,
    ) -> Envelope:
        return await self.invoke_wait(
            control_id, "momentary_begin", value, invocation_id=invocation_id, timeout=timeout,
        )

    async def end_momentary_wait(
        self,
        control_id: str,
        invocation_id: str,
        *,
        lease_id: str | None = None,
        timeout: float = 5.0,
    ) -> Envelope:
        return await self.request(
            self.end_momentary(control_id, invocation_id, lease_id=lease_id),
            timeout=timeout,
        )


def require_remote_role(role: Role) -> None:
    if role not in {Role.REMOTE, Role.TOOL, Role.SIMULATOR}:
        raise ValueError("remote profile client role required")
