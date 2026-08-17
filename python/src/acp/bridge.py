from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .constants import schema_root
from .envelope import Envelope, make_envelope
from .persist import NodeStore
from .session import Session, make_ack
from .types import CommandStatus, Endpoint, QoS

ALLOWED_SCOPES = frozenset({"all", "artnet", "dmx"})


def _field_catalog() -> dict[str, dict]:
    path = schema_root() / "bridge" / "config_fields.json"
    return json.loads(path.read_text())["fields"]


def is_secret_path(path: str) -> bool:
    meta = _field_catalog().get(path)
    return bool(meta and meta.get("secret"))


@dataclass
class ConfigStore:
    revision: int = 0
    values: dict[str, Any] = field(default_factory=dict)
    secrets_configured: set[str] = field(default_factory=set)
    restart_paths: set[str] = field(default_factory=set)
    store: NodeStore | None = None

    def get_public(self, path: str) -> dict[str, Any]:
        if is_secret_path(path):
            return {"path": path, "configured": path in self.secrets_configured}
        if path not in self.values:
            nested = {k: v for k, v in self.values.items() if k == path or k.startswith(path + ".")}
            if not nested:
                return {"path": path, "value": None}
            return {"path": path, "value": nested}
        return {"path": path, "value": self.values[path]}

    def apply(self, expected: int, changes: list[dict[str, Any]]) -> dict[str, Any]:
        if expected != self.revision:
            return {
                "status": CommandStatus.REJECTED.value,
                "error": {
                    "code": "config.revision_conflict",
                    "category": "conflict",
                    "severity": "warning",
                    "message": f"Configuration changed since revision {expected}.",
                    "retryable": True,
                    "details": {"expected": expected, "actual": self.revision},
                },
            }
        if not isinstance(changes, list) or not changes:
            return {
                "status": CommandStatus.REJECTED.value,
                "error": {
                    "code": "invalid_type",
                    "category": "validation",
                    "severity": "error",
                    "message": "changes must be a non-empty list",
                    "retryable": False,
                },
            }
        catalog = _field_catalog()
        validated: list[tuple[str, Any]] = []
        field_errors: list[dict[str, Any]] = []
        for change in changes:
            if not isinstance(change, dict) or "path" not in change:
                field_errors.append({"path": "?", "status": "rejected", "error": {"code": "invalid_type"}})
                continue
            path = change["path"]
            if not isinstance(path, str) or path not in catalog:
                field_errors.append({"path": str(path), "status": "rejected", "error": {"code": "not_found"}})
                continue
            value = change.get("value")
            meta = catalog[path]
            if meta["type"] == "boolean" and type(value) is not bool:
                field_errors.append({"path": path, "status": "rejected", "error": {"code": "invalid_type"}})
                continue
            if meta["type"] == "integer" and type(value) is not int:
                field_errors.append({"path": path, "status": "rejected", "error": {"code": "invalid_type"}})
                continue
            if meta["type"] == "string" and type(value) is not str:
                field_errors.append({"path": path, "status": "rejected", "error": {"code": "invalid_type"}})
                continue
            if "minimum" in meta and isinstance(value, int) and value < meta["minimum"]:
                field_errors.append({"path": path, "status": "rejected", "error": {"code": "invalid_range"}})
                continue
            if "maximum" in meta and isinstance(value, int) and value > meta["maximum"]:
                field_errors.append({"path": path, "status": "rejected", "error": {"code": "invalid_range"}})
                continue
            validated.append((path, value))
        if field_errors:
            return {
                "status": CommandStatus.REJECTED.value,
                "error": {
                    "code": "invalid_type",
                    "category": "validation",
                    "severity": "error",
                    "message": "one or more fields failed validation",
                    "retryable": False,
                },
                "field_results": field_errors,
            }
        field_results = []
        restart = False
        for path, value in validated:
            if is_secret_path(path):
                self.secrets_configured.add(path)
                self.values.pop(path, None)
                field_results.append({"path": path, "status": "applied", "configured": True})
            else:
                self.values[path] = value
                field_results.append({"path": path, "status": "applied"})
            if path in self.restart_paths:
                restart = True
        self.revision += 1
        if self.store:
            self.store.save("config.json", {"revision": self.revision, "values": {
                k: v for k, v in self.values.items()
            }, "secrets_configured": sorted(self.secrets_configured)})
        return {
            "status": CommandStatus.APPLIED.value,
            "new_revision": self.revision,
            "restart_required": restart,
            "field_results": field_results,
        }


@dataclass
class BridgeNode:
    source: Endpoint
    config: ConfigStore = field(default_factory=ConfigStore)
    blackout_enabled: bool = False
    blackout_scope: str = "all"
    revision: int = 0
    store: NodeStore | None = None

    def __post_init__(self) -> None:
        if self.store:
            self.config.store = self.store
            saved = self.store.load("blackout.json", None)
            if isinstance(saved, dict):
                self.blackout_enabled = bool(saved.get("enabled"))
                self.blackout_scope = str(saved.get("scope") or "all")
                self.revision = int(saved.get("revision") or 0)
            cfg = self.store.load("config.json", None)
            if isinstance(cfg, dict):
                self.config.revision = int(cfg.get("revision") or 0)
                self.config.values = dict(cfg.get("values") or {})
                self.config.secrets_configured = set(cfg.get("secrets_configured") or [])

    @property
    def clear_on_disconnect(self) -> bool:
        return bool(self.config.values.get("bridge.blackout.clear_on_disconnect", False))

    @clear_on_disconnect.setter
    def clear_on_disconnect(self, value: bool) -> None:
        self.config.values["bridge.blackout.clear_on_disconnect"] = bool(value)

    def handle(self, env: Envelope, session: Session | None = None) -> list[Envelope]:
        out: list[Envelope] = []
        if env.type == "bridge.blackout":
            key = env.payload.get("idempotency_key")
            if session and isinstance(key, str):
                try:
                    cached = session.lookup_idempotent(env.type, key, request_payload=dict(env.payload))
                except ValueError:
                    out.append(make_ack(
                        env, self.source, CommandStatus.REJECTED,
                        error={"code": "conflict", "category": "conflict", "severity": "error",
                               "message": "idempotency key reused with different body", "retryable": False},
                    ))
                    return out
                if cached:
                    result = {k: v for k, v in cached.items() if k != "status"}
                    out.append(make_ack(env, self.source, CommandStatus.DUPLICATE, result=result or cached))
                    return out
            enabled = env.payload.get("enabled")
            if not isinstance(enabled, bool):
                out.append(make_ack(
                    env, self.source, CommandStatus.REJECTED,
                    error={"code": "invalid_type", "category": "validation", "severity": "error",
                           "message": "enabled must be a boolean", "retryable": False},
                ))
                return out
            scope = env.payload.get("scope", "all")
            if scope not in ALLOWED_SCOPES:
                out.append(make_ack(
                    env, self.source, CommandStatus.REJECTED,
                    error={"code": "invalid_range", "category": "validation", "severity": "error",
                           "message": "invalid blackout scope", "retryable": False},
                ))
                return out
            self.blackout_enabled = enabled
            self.blackout_scope = scope
            self.revision += 1
            result = {"enabled": enabled, "scope": scope}
            if session and isinstance(key, str):
                session.remember_idempotent(
                    env.type, key, result, status="applied", request_payload=dict(env.payload)
                )
            if self.store:
                self.store.save("blackout.json", {
                    "enabled": self.blackout_enabled,
                    "scope": self.blackout_scope,
                    "revision": self.revision,
                })
            out.append(make_ack(env, self.source, CommandStatus.APPLIED, result=result))
            out.append(
                make_envelope(
                    type="state.delta",
                    source=self.source,
                    qos=QoS.LATEST,
                    causation_id=env.message_id,
                    payload={
                        "resource": "bridge.blackout",
                        "revision": self.revision,
                        "owner": self.source.to_dict(),
                        "value": result,
                        "confidence": "confirmed",
                    },
                )
            )
            return out
        if env.type == "config.get":
            public = self.config.get_public(env.payload["path"])
            out.append(
                make_envelope(
                    type="config.result",
                    source=self.source,
                    qos=QoS.RELIABLE,
                    correlation_id=env.correlation_id or env.message_id,
                    causation_id=env.message_id,
                    payload={
                        "transaction_id": env.payload.get("transaction_id") or env.message_id,
                        "status": CommandStatus.APPLIED.value,
                        "new_revision": self.config.revision,
                        "restart_required": False,
                        "field_results": [public],
                    },
                )
            )
            return out
        if env.type == "config.set":
            applied = self.config.apply(int(env.payload["expected_revision"]), list(env.payload["changes"]))
            payload = {"transaction_id": env.payload["transaction_id"], **applied}
            out.append(
                make_envelope(
                    type="config.result",
                    source=self.source,
                    qos=QoS.RELIABLE,
                    correlation_id=env.correlation_id or env.message_id,
                    causation_id=env.message_id,
                    payload=payload,
                )
            )
            if applied.get("status") == CommandStatus.APPLIED.value:
                out.append(
                    make_envelope(
                        type="state.delta",
                        source=self.source,
                        qos=QoS.LATEST,
                        causation_id=env.message_id,
                        payload={
                            "resource": "bridge.config",
                            "revision": self.config.revision,
                            "owner": self.source.to_dict(),
                            "value": {"revision": self.config.revision},
                            "confidence": "confirmed",
                        },
                    )
                )
            return out
        if env.type == "state.request":
            out.append(
                make_envelope(
                    type="state.snapshot",
                    source=self.source,
                    qos=QoS.RELIABLE,
                    correlation_id=env.correlation_id or env.message_id,
                    payload={
                        "resources": [
                            {
                                "resource": "bridge.blackout",
                                "revision": self.revision,
                                "owner": self.source.to_dict(),
                                "value": {"enabled": self.blackout_enabled, "scope": self.blackout_scope},
                                "confidence": "confirmed",
                            },
                            {
                                "resource": "bridge.config",
                                "revision": self.config.revision,
                                "owner": self.source.to_dict(),
                                "value": {"revision": self.config.revision},
                                "confidence": "confirmed",
                            },
                        ]
                    },
                )
            )
            return out
        return out

    def on_session_close(self) -> None:
        if self.clear_on_disconnect:
            self.blackout_enabled = False
            self.revision += 1
