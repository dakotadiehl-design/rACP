from __future__ import annotations

import asyncio
import json
import math
import uuid
from dataclasses import dataclass, replace
from typing import Any, Protocol

from acp.constants import load as load_constants
from acp.envelope import Envelope, make_envelope
from acp.remote import RemoteClient, RemoteIdentity, layout_fingerprint
from acp.types import Capability, Endpoint, NodeIdentity, Role

from .models import ConnectionConfig

WORKBENCH_NODE_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://aurora.invalid/acp/workbench/remote"))


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    id: str
    label: str
    kind: str = "activate"
    dangerous: bool = False
    minimum: float | None = None
    maximum: float | None = None
    enabled: bool = True
    available: bool = True
    reason: str | None = None


class Profile(Protocol):
    id: str
    display_name: str
    node: NodeIdentity

    def identity(self, config: ConnectionConfig) -> NodeIdentity: ...
    def capabilities(self) -> list[Capability]: ...
    def session_profiles(self) -> list[str]: ...
    async def synchronize(self, connection: Any) -> None: ...
    def handle(self, envelope: Envelope) -> None: ...
    async def handle_resource(self, connection: Any, envelope: Envelope) -> None: ...
    async def prepare_disconnect(self, connection: Any) -> None: ...
    def actions(self) -> list[ActionDefinition]: ...
    def envelope_for_action(self, action: str, value: Any = None, **parameters: Any) -> Envelope: ...
    def navigation(self, kind: str, *, song_id: str | None = None) -> Envelope: ...
    @property
    def view(self) -> dict[str, Any]: ...


class RemotePrismProfile:
    id = "remote-prism"
    display_name = "Remote → Prism"

    def __init__(self, config: ConnectionConfig, identity: NodeIdentity) -> None:
        self.config = config
        self.node = identity
        self.client: RemoteClient | None = None
        self.permissions: dict[str, Any] = {}
        self._invocations_by_message: dict[str, str] = {}
        self._surface_ready = asyncio.Event()
        self._authority_epoch: int | None = None

    @staticmethod
    def identity(config: ConnectionConfig) -> NodeIdentity:
        from acp.types import new_uuid

        return NodeIdentity(
            node_id=config.node_id or WORKBENCH_NODE_ID,
            instance_id=config.instance_id or new_uuid(),
            role=Role.REMOTE,
            name=config.name,
            product_version="0.1.0",
        )

    def capabilities(self) -> list[Capability]:
        remote = load_constants()["remote"]
        capability_ids = {
            "health.heartbeat",
            "resource.transfer",
            *remote["capabilities"],
            *remote["feature_capabilities"],
        }
        return [
            Capability(capability_id, "1.2" if capability_id == "resource.transfer" else "1.0")
            for capability_id in sorted(capability_ids)
        ]

    def session_profiles(self) -> list[str]:
        return ["core", "remote", "aurora.remote.prism.v1"]

    async def synchronize(self, connection: Any) -> None:
        assert connection.session is not None
        destination = Endpoint(connection.session.peer.node_id) if connection.session.peer else None
        self.client = RemoteClient(
            Endpoint(self.node.node_id),
            show_id=self.config.show_id,
            layout_id=self.config.layout_id,
            session=connection.session,
            destination=destination,
        )
        from acp.types import new_uuid

        remote = RemoteIdentity(
            node_id=self.node.node_id,
            instance_id=self.node.instance_id,
            device_id=new_uuid(),
            remote_id=new_uuid(),
            device_name=self.config.name,
            # ACP describes the host platform, not the implementation language.
            platform="macos",
            app_version="0.1.0",
        )
        hello = make_envelope(
            type="remote.hello",
            source=Endpoint(self.node.node_id),
            destination=destination,
            payload={
                "remote": remote.to_dict(),
                "roles": ["remote.operator", "remote.busker", "remote.show_navigation", "remote.admin"],
                "capabilities": [cap.to_dict() for cap in self.capabilities()],
            },
        )
        ack = await connection.request(hello, timeout=self.config.timeout)
        if not ack.payload.get("accepted"):
            raise RuntimeError(f"Remote hello rejected: {ack.payload.get('error') or 'unknown reason'}")
        self.permissions = dict(ack.payload.get("permissions") or {})
        if ack.payload.get("show_id"):
            self.client.show_id = str(ack.payload["show_id"])
        if ack.payload.get("show_revision") is not None:
            self.client.show_revision = int(ack.payload["show_revision"])
        if ack.payload.get("layout_id") or ack.payload.get("surface_id"):
            self.client.layout_id = str(ack.payload.get("surface_id") or ack.payload["layout_id"])
        if ack.payload.get("layout_revision") is not None:
            self.client.layout_revision = int(ack.payload["layout_revision"])
        report = await connection.request(self.client.layout_request(), timeout=self.config.timeout)
        self.client._apply_layout_report(report)
        if self.client.layout is None:
            try:
                await asyncio.wait_for(self._surface_ready.wait(), timeout=self.config.timeout)
            except TimeoutError as exc:
                raise RuntimeError("Remote surface transfer did not complete") from exc
            transfer_id = self.client._staged_transfer_id
            if not transfer_id or self.client._staged_layout is None:
                raise RuntimeError("Remote surface transfer completed without a staged layout")
            activation = make_envelope(
                type="resource.activate",
                source=Endpoint(self.node.node_id),
                destination=destination,
                payload={"transfer_id": transfer_id},
            )
            activation_ack = await connection.request(activation, timeout=self.config.timeout)
            if activation_ack.payload.get("status") != "applied":
                raise RuntimeError("Remote surface activation was rejected")
            self.client._commit_staged_layout()
        snapshot = await connection.request(self.client.state_request(), timeout=self.config.timeout)
        epoch = snapshot.payload.get("authority_epoch")
        if isinstance(epoch, int):
            self._authority_epoch = epoch
        self.client.apply_publication(snapshot)
        readiness = await connection.request(
            self.client.readiness_ack(layout=self.client.layout, snapshot_revision=self.client.snapshot_revision),
            timeout=self.config.timeout,
        )
        self.client.ready = str(readiness.payload.get("state") or "") in {"ready", "ready_with_warnings"}
        if not self.client.ready:
            raise RuntimeError(f"Remote synchronization incomplete: {readiness.payload.get('state') or 'unknown'}")

    def handle(self, envelope: Envelope) -> None:
        if self.client is None:
            return
        if envelope.type in {"state.snapshot", "state.delta"}:
            epoch = envelope.payload.get("authority_epoch")
            if isinstance(epoch, int):
                self._authority_epoch = epoch
        if envelope.type == "state.delta":
            # Canonical ACP deltas carry one or more resource changes. Keep the
            # Remote view current so subsequent guarded actions use fresh state.
            for change in envelope.payload.get("changes") or []:
                if isinstance(change, dict) and change.get("resource"):
                    self.client.view[str(change["resource"])] = dict(change.get("value") or {})
        if envelope.type == "command.ack":
            invocation = self._invocations_by_message.pop(str(envelope.correlation_id or ""), "")
            if not invocation:
                invocation = str(envelope.payload.get("result", {}).get("invocation_id") or "")
            if invocation:
                self.client.record_result(invocation, envelope)
        elif envelope.type == "remote.control.snapshot":
            self.client.apply_publication(envelope)
            for control in envelope.payload.get("controls") or []:
                if isinstance(control, dict) and control.get("control_id"):
                    self.client.view[f"control.{control['control_id']}"] = dict(control)
        else:
            self.client.apply_publication(envelope)

    async def handle_resource(self, connection: Any, envelope: Envelope) -> None:
        if self.client is None:
            return
        for reply in self.client.transfer.handle(envelope):
            await connection.send(reply)
        if envelope.type != "resource.complete":
            return
        transfer_id = str(envelope.payload.get("transfer_id") or "")
        transfer = self.client.transfer.transfers.get(transfer_id)
        if transfer is None or transfer.staged is None or str(transfer.state.value) != "verified":
            return
        try:
            layout = json.loads(transfer.staged.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        if not isinstance(layout, dict):
            return
        self.client._staged_layout = layout
        self.client._staged_hash = layout_fingerprint(layout)
        self.client._staged_transfer_id = transfer_id
        self._surface_ready.set()

    async def prepare_disconnect(self, connection: Any) -> None:
        """Best-effort Remote-side release; the authority still owns the fail-safe."""
        if self.client is None:
            return
        for invocation_id, lease_id in list(self.client.leases.items()):
            control_id = self.client._lease_controls.get(invocation_id)
            if not control_id:
                continue
            envelope = self.client.end_momentary(
                control_id,
                invocation_id,
                lease_id=lease_id,
            )
            try:
                await connection.send(envelope)
            except Exception:
                pass
        self.client.on_disconnect()

    def actions(self) -> list[ActionDefinition]:
        if self.client and self.client.layout:
            result = []
            for control in self.client.layout.get("controls") or []:
                safety = (control.get("safety") or {}).get("class")
                state = self.client.view.get(f"control.{control['control_id']}") or {}
                result.append(ActionDefinition(
                    id=str(control["control_id"]),
                    label=str(control.get("label") or control["control_id"]),
                    kind=str(control.get("control_type") or "activate"),
                    dangerous=safety in {"dangerous", "critical"},
                    minimum=float(control["min"]) if control.get("min") is not None else None,
                    maximum=float(control["max"]) if control.get("max") is not None else None,
                    enabled=bool(state.get("enabled", control.get("enabled", True))),
                    available=bool(state.get("available", control.get("available", True))),
                    reason=str(state.get("reason")) if state.get("reason") else None,
                ))
            return result
        return []

    def envelope_for_action(self, action: str, value: Any = None, **parameters: Any) -> Envelope:
        if self.client is None:
            raise RuntimeError("Remote profile is not synchronized")
        interaction = str(parameters.get("interaction") or "activate")
        invocation_id = parameters.get("invocation_id")
        lease_id = parameters.get("lease_id")
        guarded_cue_action = action in {"cue_go", "go", "nav_go", "cue_fire"}
        guarded_blackout_action = action in {"blackout_on", "blackout_off"}
        cue_state = self.client.view.get("prism.cue", {})
        if action == "grand_master":
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                raise ValueError("Grand Master requires a finite numeric value")
            if not 0 <= float(value) <= 1:
                raise ValueError("Grand Master must be between 0 and 1")
            interaction = "set"
        if action == "cue_fire" and value is None:
            value = cue_state.get("next_cue_id") or None
            if value is None:
                raise RuntimeError("Fire Next Cue requires a published next_cue_id")
        envelope = self.client.invoke(
            action,
            interaction,
            value,
            invocation_id=invocation_id,
            lease_id=lease_id,
        )
        if action in {"cue_fire", "grand_master", "blackout_on", "blackout_off"}:
            envelope = replace(envelope, payload={**envelope.payload, "delivery": "live_ephemeral"})
        if action == "grand_master" and self._authority_epoch is not None:
            envelope = replace(envelope, payload={
                **envelope.payload,
                "preconditions": [
                    {"op": "equals", "field": "authority_epoch", "value": self._authority_epoch},
                ],
            })
        if guarded_blackout_action and self._authority_epoch is not None:
            envelope = replace(envelope, payload={
                **envelope.payload,
                "preconditions": [
                    {"op": "equals", "field": "authority_epoch", "value": self._authority_epoch},
                ],
            })
        if guarded_cue_action and self._authority_epoch is not None:
            current_cue = cue_state.get("current_cue_id") or None
            payload = dict(envelope.payload)
            payload["preconditions"] = [
                {"op": "equals", "field": "authority_epoch", "value": self._authority_epoch},
                {"op": "equals", "field": "current_cue_id", "value": current_cue},
            ]
            envelope = replace(envelope, payload=payload)
        self._invocations_by_message[envelope.message_id] = str(envelope.payload["invocation_id"])
        return envelope

    def navigation(self, kind: str, *, song_id: str | None = None) -> Envelope:
        if self.client is None:
            raise RuntimeError("Remote profile is not synchronized")
        return self.client.navigate(kind, song_id=song_id)

    @property
    def view(self) -> dict[str, Any]:
        return self.client.view if self.client else {}


class CoreInspectionProfile:
    id = "core"
    display_name = "Generic ACP Core Inspector"

    def __init__(self, config: ConnectionConfig, identity: NodeIdentity) -> None:
        self.config = config
        self.node = identity
        self._view: dict[str, Any] = {}

    @staticmethod
    def identity(config: ConnectionConfig) -> NodeIdentity:
        from acp.types import new_uuid

        return NodeIdentity(
            node_id=config.node_id or new_uuid(),
            instance_id=config.instance_id or new_uuid(),
            role=Role.TOOL,
            name=config.name,
            product_version="0.1.0",
        )

    def capabilities(self) -> list[Capability]:
        return [Capability("health.heartbeat", "1.0")]

    def session_profiles(self) -> list[str]:
        return ["core"]

    async def synchronize(self, connection: Any) -> None:
        assert connection.session is not None
        destination = Endpoint(connection.session.peer.node_id) if connection.session.peer else None
        request = make_envelope(
            type="state.request",
            source=Endpoint(self.node.node_id),
            destination=destination,
            payload={"resources": []},
        )
        snapshot = await connection.request(request, timeout=self.config.timeout)
        self.handle(snapshot)

    def handle(self, envelope: Envelope) -> None:
        if envelope.type == "state.snapshot":
            for resource in envelope.payload.get("resources") or []:
                if isinstance(resource, dict) and resource.get("resource"):
                    self._view[str(resource["resource"])] = dict(resource)
        elif envelope.type == "state.delta" and envelope.payload.get("resource"):
            self._view[str(envelope.payload["resource"])] = dict(envelope.payload)
        elif envelope.type in {"health.snapshot", "health.warning", "error.report"}:
            self._view[envelope.type] = dict(envelope.payload)

    async def handle_resource(self, connection: Any, envelope: Envelope) -> None:
        return

    async def prepare_disconnect(self, connection: Any) -> None:
        return

    def actions(self) -> list[ActionDefinition]:
        return []

    def envelope_for_action(self, action: str, value: Any = None, **parameters: Any) -> Envelope:
        raise RuntimeError("the core inspection profile does not expose control actions")

    def navigation(self, kind: str, *, song_id: str | None = None) -> Envelope:
        raise RuntimeError("the core inspection profile does not expose navigation actions")

    @property
    def view(self) -> dict[str, Any]:
        return self._view


PROFILE_TYPES: dict[str, Any] = {
    CoreInspectionProfile.id: CoreInspectionProfile,
    RemotePrismProfile.id: RemotePrismProfile,
}


def create_profile(profile_id: str, config: ConnectionConfig) -> Profile:
    try:
        cls = PROFILE_TYPES[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown profile {profile_id!r}") from exc
    identity = cls.identity(config)
    return cls(config, identity)
