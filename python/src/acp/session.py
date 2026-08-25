from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .codec import decode, encode
from .constants import limits as profile_limits
from .envelope import Envelope, make_envelope
from .idempotency import IdempotencyCache
from .negotiate import (
    VersionError,
    intersect_capabilities,
    intersect_profiles,
    select_encoding,
    select_version,
    validate_heartbeat,
    validate_max_message_bytes,
    version_at_least,
    version_leq,
)
from .registry import allowed_to_receive, allowed_to_send, expected_response_type, lookup
from .security import (
    AuthenticatedPrincipal,
    PrincipalState,
    SecurityAdmissionError,
    TransportEvidence,
    bind_hello_auth,
)
from .types import (
    Capability,
    CommandStatus,
    Endpoint,
    NodeIdentity,
    ProtocolRange,
    QoS,
    new_uuid,
    normalize_uuid,
)


class SessionState(str, Enum):
    CLOSED = "closed"
    CONNECTING = "connecting"
    HELLO_SENT = "hello_sent"
    ESTABLISHED = "established"
    GOODBYE_SENT = "goodbye_sent"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


class ReliableOverflow(RuntimeError):
    pass


class SessionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class SessionCounters:
    sent: int = 0
    received: int = 0
    decode_errors: int = 0
    rejected_inbound: int = 0
    reconnects: int = 0
    dropped_latest: int = 0
    dropped_best_effort: int = 0
    sequence_gaps: int = 0


class Transport:
    peer_identity: str | None = None

    async def send(self, data: bytes, *, text: bool) -> None:  # pragma: no cover
        raise NotImplementedError

    async def recv(self) -> tuple[bytes, bool]:  # pragma: no cover
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover
        raise NotImplementedError


@dataclass
class _Waiter:
    future: asyncio.Future[Envelope]
    expected_types: frozenset[str]
    peer_node_id: str | None
    correlation_id: str


@dataclass
class Session:
    transport: Transport
    local: NodeIdentity
    is_server: bool = False
    profile: str = "full"
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    protocol: ProtocolRange = field(default_factory=lambda: ProtocolRange("1.0", "1.2"))
    encodings: list[str] = field(default_factory=lambda: ["cbor", "json"])
    profiles: list[str] = field(default_factory=lambda: ["core"])
    auth_mode: str = "trusted_lan"
    allow_plaintext: bool = False
    transport_identity: str | None = None
    transport_evidence: TransportEvidence | None = None
    local_auth: dict[str, Any] | None = None
    idempotency: IdempotencyCache | None = None

    state: SessionState = field(default=SessionState.CLOSED, init=False)
    session_id: str | None = field(default=None, init=False)
    session_version: str = field(default="1.2", init=False)
    encoding: str = field(default="cbor", init=False)
    peer: NodeIdentity | None = field(default=None, init=False)
    peer_node_id: str | None = field(default=None, init=False)
    authenticated_principal: AuthenticatedPrincipal | None = field(default=None, init=False)
    local_offered: list[Capability] = field(default_factory=list, init=False)
    peer_offered: list[Capability] = field(default_factory=list, init=False)
    negotiated_capabilities: set[str] = field(default_factory=set, init=False)
    negotiated_capability_versions: dict[str, str] = field(default_factory=dict, init=False)
    negotiated_profiles: set[str] = field(default_factory=set, init=False)
    heartbeat_interval_ms: int = field(default=1000, init=False)
    max_message_bytes: int = field(default=1_048_576, init=False)
    _shutting_down: bool = field(default=False, init=False)
    next_sequence: int = field(default=0, init=False)
    last_rx_sequence: int | None = field(default=None, init=False)
    gap_count: int = field(default=0, init=False)
    counters: SessionCounters = field(default_factory=SessionCounters, init=False)

    _inbox: asyncio.Queue[Envelope] = field(default_factory=asyncio.Queue, init=False)
    _waiters: dict[str, _Waiter] = field(default_factory=dict, init=False)
    _reliable_q: deque[tuple[Envelope, asyncio.Future[Envelope | None]]] = field(default_factory=deque, init=False)
    _latest_q: OrderedDict[tuple[str, str], Envelope] = field(default_factory=OrderedDict, init=False)
    _best_q: deque[Envelope] = field(default_factory=deque, init=False)
    _recv_task: asyncio.Task[None] | None = field(default=None, init=False)
    _writer_task: asyncio.Task[None] | None = field(default=None, init=False)
    _work: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _closed: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _pending_snapshot: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.idempotency is None:
            self.idempotency = IdempotencyCache.from_profile(self.profile)
        if self.transport_identity is None:
            self.transport_identity = getattr(self.transport, "peer_identity", None)
        if self.transport_evidence is None:
            self.transport_evidence = getattr(self.transport, "peer_evidence", None)

    @property
    def limits(self) -> dict[str, int]:
        return profile_limits(self.profile)

    @property
    def local_capabilities(self) -> set[str]:
        return {c.id for c in self.local_offered}

    @local_capabilities.setter
    def local_capabilities(self, value: set[str]) -> None:
        self.local_offered = [Capability(cid, "1.0") for cid in value]
        self._refresh_negotiated()

    @property
    def peer_capabilities(self) -> set[str]:
        return set(self.negotiated_capabilities)

    @peer_capabilities.setter
    def peer_capabilities(self, value: set[str]) -> None:
        self.peer_offered = [Capability(cid, "1.0") for cid in value]
        self._refresh_negotiated()

    def _refresh_negotiated(self) -> None:
        caps = intersect_capabilities(self.local_offered, self.peer_offered) if self.peer_offered else []
        self.negotiated_capability_versions = {c.id: c.version for c in caps}
        self.negotiated_capabilities = set(self.negotiated_capability_versions)

    def source(self) -> Endpoint:
        return Endpoint(node_id=self.local.node_id)

    def _require_auth_mode(self, mode: str) -> None:
        implemented = {"trusted_lan", "tls", "aurora_trust"}
        if mode not in implemented:
            raise SessionError("authentication", f"auth mode {mode!r} is not implemented")
        if mode == "trusted_lan" and not self.allow_plaintext:
            raise SessionError(
                "authentication",
                "trusted_lan is unauthenticated plaintext; set allow_plaintext=True to opt in",
            )
        if mode == "tls" and not self.transport_identity:
            raise SessionError("authentication", f"{mode} requires a TLS transport identity")
        if mode == "aurora_trust" and self.transport_evidence is None:
            raise SessionError("authentication", "aurora_trust requires verified transport evidence")

    async def start_receiver(self) -> None:
        if self._recv_task is None:
            self._recv_task = asyncio.create_task(self._recv_loop())
        if self._writer_task is None:
            self._writer_task = asyncio.create_task(self._writer_loop())

    async def handshake(
        self,
        capabilities: list[Capability],
        *,
        heartbeat_interval_ms: int | None = None,
    ) -> Envelope:
        self._require_auth_mode(self.auth_mode)
        self.local_offered = list(capabilities)
        self.state = SessionState.CONNECTING
        await self.start_receiver()
        if heartbeat_interval_ms is not None:
            self.heartbeat_interval_ms = validate_heartbeat(heartbeat_interval_ms)
        if self.is_server:
            hello = await self._wait_type("session.hello", timeout=5.0)
            return await self._accept_hello(hello, capabilities)
        hello = self._build_hello(capabilities)
        self.state = SessionState.HELLO_SENT
        await self._transmit(hello, established=False)
        ack = await self._wait_type("session.hello_ack", timeout=5.0)
        self._apply_hello_ack(ack)
        return ack

    def _build_hello(self, capabilities: list[Capability]) -> Envelope:
        auth = dict(self.local_auth or {"mode": self.auth_mode})
        if auth.get("mode") != self.auth_mode or (self.auth_mode == "aurora_trust" and self.local_auth is None):
            raise SessionError("authentication", "local HELLO auth does not match the authenticated transport")
        return make_envelope(
            type="session.hello",
            source=self.source(),
            qos=QoS.RELIABLE,
            acp="1.2",
            payload={
                "node": self.local.to_dict(),
                "protocol": self.protocol.to_dict(),
                "encodings": list(self.encodings),
                "profiles": list(self.profiles),
                "capabilities": [c.to_dict() for c in capabilities],
                "auth": auth,
            },
        )

    def _caps_from_payload(self, items: Any) -> list[Capability]:
        out: list[Capability] = []
        for item in items or []:
            if isinstance(item, dict) and "id" in item and "version" in item:
                out.append(Capability.from_dict(item))
        return out

    async def _accept_hello(self, hello: Envelope, capabilities: list[Capability]) -> Envelope:
        payload = hello.payload
        try:
            peer_range = ProtocolRange.from_dict(payload["protocol"])
            selected = select_version(peer_range, self.protocol)
            encoding = select_encoding(list(payload.get("encodings") or []), self.encodings)
            peer_caps = self._caps_from_payload(payload.get("capabilities"))
            negotiated = intersect_capabilities(capabilities, peer_caps)
            negotiated_profiles = intersect_profiles(
                list(self.profiles),
                [str(p) for p in (payload.get("profiles") or [])],
            )
            auth_mode = (payload.get("auth") or {}).get("mode", "trusted_lan")
            self._require_auth_mode(str(auth_mode))
            peer = NodeIdentity.from_dict(payload["node"])
            if hello.source.node_id != peer.node_id:
                raise SessionError("authentication", "HELLO source does not match payload node_id")
            if str(auth_mode) == "aurora_trust":
                auth = payload.get("auth")
                if not isinstance(auth, dict):
                    raise SessionError("authentication", "HELLO auth is malformed")
                security_caps = tuple(
                    (str(item["id"]), str(item["version"]))
                    for item in auth.get("security_capabilities", [])
                    if isinstance(item, dict) and "id" in item and "version" in item
                )
                self.authenticated_principal = bind_hello_auth(
                    peer.node_id,
                    auth,
                    self.transport_evidence,
                    hardened=not self.allow_plaintext,
                    security_capabilities=security_caps,
                )
            elif self.transport_identity and self.transport_identity != peer.node_id:
                raise SessionError("authentication", "HELLO node_id does not match transport identity")
        except (KeyError, TypeError, ValueError, VersionError, SessionError, SecurityAdmissionError) as exc:
            ack = make_envelope(
                type="session.hello_ack",
                source=self.source(),
                qos=QoS.RELIABLE,
                payload={
                    "accepted": False,
                    "protocol": self.protocol.max,
                    "encoding": self.encodings[0],
                    "session_id": new_uuid(),
                    "heartbeat_interval_ms": self.heartbeat_interval_ms,
                    "node": self.local.to_dict(),
                    "peer_capabilities": [],
                    "limits": {"max_message_bytes": self.limits["max_message_bytes"]},
                    "error": {
                        "code": getattr(exc, "code", "unsupported_version"),
                        "category": "protocol",
                        "severity": "error",
                        "message": str(exc) or "protocol negotiation failed",
                        "retryable": False,
                    },
                },
            )
            await self._transmit(ack, established=False)
            self.state = SessionState.FAILED
            raise SessionError(getattr(exc, "code", "unsupported_version"), "protocol negotiation failed") from exc
        self.peer = peer
        self.peer_node_id = peer.node_id
        self.peer_offered = peer_caps
        self.local_offered = list(capabilities)
        self.negotiated_capability_versions = {c.id: c.version for c in negotiated}
        self.negotiated_capabilities = set(self.negotiated_capability_versions)
        self.negotiated_profiles = set(negotiated_profiles)
        self.session_id = new_uuid()
        self.session_version = selected
        self.encoding = encoding
        self.max_message_bytes = int(self.limits["max_message_bytes"])
        self.next_sequence = 0
        self.last_rx_sequence = None
        self.gap_count = 0
        ack = make_envelope(
            type="session.hello_ack",
            source=self.source(),
            qos=QoS.RELIABLE,
            payload={
                "accepted": True,
                "protocol": selected,
                "encoding": encoding,
                "session_id": self.session_id,
                "heartbeat_interval_ms": self.heartbeat_interval_ms,
                "node": self.local.to_dict(),
                "peer_capabilities": [c.to_dict() for c in negotiated],
                "profiles": negotiated_profiles,
                "limits": {"max_message_bytes": self.limits["max_message_bytes"]},
            },
        )
        await self._transmit(ack, established=False)
        self.state = SessionState.ESTABLISHED
        return ack

    def _apply_hello_ack(self, ack: Envelope) -> None:
        payload = ack.payload
        if not payload.get("accepted"):
            self.state = SessionState.FAILED
            err = (payload.get("error") or {}).get("code", "unsupported_version")
            raise SessionError(str(err), "hello rejected")
        try:
            protocol = str(payload["protocol"])
            if not version_leq(self.protocol.min, protocol) or not version_leq(protocol, self.protocol.max):
                raise VersionError("selected protocol outside offer")
            encoding = str(payload.get("encoding", ""))
            if encoding not in self.encodings:
                raise VersionError("selected encoding not offered")
            session_id = normalize_uuid(payload["session_id"])
            heartbeat = validate_heartbeat(int(payload.get("heartbeat_interval_ms") or 1000))
            max_bytes = validate_max_message_bytes(
                int((payload.get("limits") or {}).get("max_message_bytes") or self.limits["max_message_bytes"])
            )
        except (KeyError, TypeError, ValueError, VersionError) as exc:
            self.state = SessionState.FAILED
            raise SessionError("malformed_envelope", f"invalid hello_ack: {exc}") from exc
        peer_caps = self._caps_from_payload(payload.get("peer_capabilities"))
        self.peer_offered = peer_caps
        self._refresh_negotiated()
        ack_profiles = payload.get("profiles")
        if isinstance(ack_profiles, list):
            self.negotiated_profiles = set(intersect_profiles(list(self.profiles), [str(p) for p in ack_profiles]))
        else:
            self.negotiated_profiles = set(self.profiles)
        if "node" not in payload:
            self.state = SessionState.FAILED
            raise SessionError("authentication", "hello_ack missing node identity")
        peer = NodeIdentity.from_dict(payload["node"])
        if ack.source.node_id != peer.node_id:
            self.state = SessionState.FAILED
            raise SessionError("authentication", "ACK source does not match payload node_id")
        if self.auth_mode == "aurora_trust":
            evidence = self.transport_evidence
            if evidence is None or evidence.node_id != peer.node_id:
                self.state = SessionState.FAILED
                raise SessionError("authentication", "ACK node_id does not match verified transport evidence")
            self.authenticated_principal = AuthenticatedPrincipal(
                PrincipalState.AUTHENTICATED,
                evidence.mode,
                evidence.trust_domain_id,
                evidence.node_id,
                evidence.credential_id,
                evidence.identity_key_id,
                evidence.credential_format,
                evidence.role_constraints,
                evidence.profile,
            )
        elif self.transport_identity and peer.node_id != self.transport_identity:
            self.state = SessionState.FAILED
            raise SessionError("authentication", "ACK node_id does not match transport identity")
        self.peer = peer
        self.peer_node_id = peer.node_id
        self.session_id = session_id
        self.session_version = protocol
        self.encoding = encoding
        self.heartbeat_interval_ms = heartbeat
        self.max_message_bytes = min(int(self.limits["max_message_bytes"]), max_bytes)
        self.next_sequence = 0
        self.last_rx_sequence = None
        self.gap_count = 0
        self.state = SessionState.ESTABLISHED

    def coalesce_key(self, envelope: Envelope) -> tuple[str, str]:
        resource = ""
        if isinstance(envelope.payload, dict):
            resource = str(envelope.payload.get("resource") or "")
        dest = envelope.destination.node_id if envelope.destination else ""
        return (envelope.type, resource or dest)

    def _authorize_out(self, envelope: Envelope) -> None:
        if self.state != SessionState.ESTABLISHED:
            return
        err = allowed_to_send(
            envelope.type,
            session_version=self.session_version,
            sender_role=self.local.role.value,
            negotiated_capabilities=self.negotiated_capabilities,
            handshake_complete=True,
            negotiated_versions=self.negotiated_capability_versions,
        )
        if err:
            raise SessionError(err, f"not allowed to send {envelope.type}")
        row = lookup(envelope.type)
        if row and envelope.qos.value not in row.get("qos_allowed", [envelope.qos.value]):
            raise SessionError("invalid_type", f"qos {envelope.qos.value} not allowed for {envelope.type}")

    async def send(self, envelope: Envelope) -> Envelope | None:
        self._authorize_out(envelope)
        if envelope.qos is QoS.LATEST:
            key = self.coalesce_key(envelope)
            if key in self._latest_q:
                self.counters.dropped_latest += 1
            self._latest_q[key] = envelope
            self._work.set()
            return None
        if envelope.qos is QoS.BEST_EFFORT:
            if len(self._best_q) >= self.limits["outbound_best_effort_queue"]:
                self.counters.dropped_best_effort += 1
                return None
            self._best_q.append(envelope)
            self._work.set()
            return None
        if len(self._reliable_q) >= self.limits["outbound_reliable_queue"]:
            raise ReliableOverflow("reliable outbound queue full")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Envelope | None] = loop.create_future()
        self._reliable_q.append((envelope, fut))
        self._work.set()
        return await fut

    async def request(self, envelope: Envelope, timeout: float = 5.0) -> Envelope:
        if envelope.correlation_id is None:
            envelope = Envelope(
                acp=envelope.acp,
                message_id=envelope.message_id,
                type=envelope.type,
                source=envelope.source,
                timestamp_utc=envelope.timestamp_utc,
                qos=envelope.qos,
                payload=envelope.payload,
                flags=envelope.flags | frozenset({"ack_required"}),
                destination=envelope.destination,
                session_id=envelope.session_id,
                sequence=envelope.sequence,
                correlation_id=envelope.message_id,
                causation_id=envelope.causation_id,
            )
        corr = envelope.correlation_id
        if corr is None:
            raise SessionError("internal", "request missing correlation_id")
        if corr in self._waiters:
            raise SessionError("conflict", "duplicate in-flight correlation_id")
        expected = expected_response_type(envelope.type)
        expected_types = {"error.report"}
        if expected:
            expected_types.add(expected)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Envelope] = loop.create_future()
        waiter = _Waiter(
            future=fut,
            expected_types=frozenset(expected_types),
            peer_node_id=self.peer.node_id if self.peer else None,
            correlation_id=corr,
        )
        self._waiters[corr] = waiter
        try:
            await self.send(envelope)
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except TimeoutError as exc:
            raise SessionError("timeout", "request timed out") from exc
        finally:
            current = self._waiters.get(corr)
            if current is waiter:
                self._waiters.pop(corr, None)

    async def subscribe(self) -> AsyncIterator[Envelope]:
        while not self._closed.is_set() and self.state not in {SessionState.FAILED, SessionState.CLOSED}:
            try:
                item = await asyncio.wait_for(self._inbox.get(), timeout=0.1)
            except TimeoutError:
                continue
            yield item

    async def goodbye(self, reason: str = "shutdown") -> None:
        if self.state == SessionState.ESTABLISHED:
            self.state = SessionState.GOODBYE_SENT
            env = make_envelope(
                type="session.goodbye",
                source=self.source(),
                qos=QoS.BEST_EFFORT,
                acp=self.session_version,
                payload={"reason": reason},
            )
            try:
                await self._transmit(env, established=True)
            except Exception:  # noqa: BLE001
                pass
        await self._shutdown("cancelled", "session closed")

    async def _shutdown(self, code: str, message: str) -> None:
        if self._shutting_down:
            return
        self._shutting_down = True
        if self.idempotency:
            self.idempotency.on_session_close()
        for waiter in list(self._waiters.values()):
            if not waiter.future.done():
                waiter.future.set_exception(SessionError(code, message))
                # Mark the exception observed even if the owning request task
                # was concurrently cancelled; awaiting the future still raises.
                waiter.future.exception()
        self._waiters.clear()
        for _, fut in list(self._reliable_q):
            if not fut.done():
                fut.set_exception(SessionError(code, message))
                fut.exception()
        self._reliable_q.clear()
        self._latest_q.clear()
        self._best_q.clear()
        if self.state not in {SessionState.FAILED}:
            self.state = SessionState.CLOSED
        self._closed.set()
        self._work.set()
        current = asyncio.current_task()
        pending: list[asyncio.Task[None]] = []
        for task in (self._recv_task, self._writer_task):
            if task and task is not current and not task.done():
                task.cancel()
                pending.append(task)
        for task in pending:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        try:
            await self.transport.close()
        except Exception:  # noqa: BLE001
            pass

    def _pop_outbound(self) -> tuple[Envelope, asyncio.Future[Envelope | None] | None] | None:
        if self._reliable_q:
            return self._reliable_q.popleft()
        if self._latest_q:
            _, env = self._latest_q.popitem(last=False)
            return env, None
        if self._best_q:
            return self._best_q.popleft(), None
        return None

    async def _writer_loop(self) -> None:
        while not self._closed.is_set():
            try:
                await asyncio.wait_for(self._work.wait(), timeout=0.1)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                return
            self._work.clear()
            while not self._closed.is_set():
                item = self._pop_outbound()
                if item is None:
                    break
                env, fut = item
                try:
                    committed = await self._transmit(env, established=self.state == SessionState.ESTABLISHED)
                except Exception as exc:  # noqa: BLE001
                    if fut is not None and not fut.done():
                        fut.set_exception(exc)
                        fut.exception()
                    for _, leftover in list(self._reliable_q):
                        if not leftover.done():
                            leftover.set_exception(exc)
                            leftover.exception()
                    self._reliable_q.clear()
                    await self._fail("internal", f"send failed: {exc}")
                    return
                if fut is not None and not fut.done():
                    fut.set_result(committed)

    async def _transmit(self, envelope: Envelope, *, established: bool) -> Envelope:
        if established:
            if self.session_id is None:
                raise SessionError("internal", "no session")
            self.next_sequence += 1
            envelope = envelope.with_session(self.session_id, self.next_sequence)
        encoding = self.encoding if established else envelope_encoding_guess(self.encodings)
        raw = encode(envelope, encoding, max_bytes=self.max_message_bytes)
        await self.transport.send(raw, text=(encoding == "json"))
        self.counters.sent += 1
        return envelope

    async def _wait_type(self, message_type: str, timeout: float) -> Envelope:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise SessionError("timeout", f"timed out waiting for {message_type}")
            env = await asyncio.wait_for(self._inbox.get(), timeout=remaining)
            if env.type == message_type:
                return env
            await self._inbox.put(env)

    async def _recv_loop(self) -> None:
        while not self._closed.is_set():
            try:
                raw, is_text = await self.transport.recv()
            except asyncio.CancelledError:
                return
            except Exception:
                if self._closed.is_set():
                    return
                await self._fail("unavailable", "transport closed")
                return
            encoding = "json" if is_text else "cbor"
            try:
                env = decode(raw, encoding)
            except Exception:
                self.counters.decode_errors += 1
                continue
            self.counters.received += 1
            error = self._admit(env)
            if error:
                self.counters.rejected_inbound += 1
                if self.state == SessionState.ESTABLISHED:
                    await self._emit_error(error, f"inbound rejected: {env.type}")
                    if error in {"malformed_envelope", "authentication", "protocol.sequence_gap"}:
                        await self._fail(error, "inbound validation failed")
                        return
                continue
            if self.state == SessionState.ESTABLISHED:
                if not await self._check_sequence(env):
                    continue
            if env.type == "session.goodbye" and self.state == SessionState.ESTABLISHED:
                await self._shutdown("cancelled", "remote goodbye")
                return
            self._complete_waiter(env)
            await self._inbox.put(env)

    def _admit(self, env: Envelope) -> str | None:
        established = self.state == SessionState.ESTABLISHED
        if not established:
            row = lookup(env.type)
            if row is None or not row["legal_before_handshake"]:
                return "malformed_envelope"
            if self.is_server and env.type not in {"session.hello", "error.report"}:
                return "malformed_envelope"
            if (not self.is_server) and self.state == SessionState.HELLO_SENT and env.type not in {
                "session.hello_ack",
                "error.report",
            }:
                return "malformed_envelope"
            return None
        if env.session_id != self.session_id:
            return "malformed_envelope"
        if env.sequence is None or env.sequence < 1:
            return "malformed_envelope"
        row = lookup(env.type)
        try:
            if not version_leq(env.acp, self.session_version):
                return "unsupported_version"
            if row and not version_at_least(env.acp, row["min_protocol"]):
                return "unsupported_message"
        except ValueError:
            return "malformed_envelope"
        if self.peer is None:
            return "authentication"
        if env.source.node_id != self.peer.node_id:
            return "authentication"
        dest_err = _destination_ok(env, self.local, row)
        if dest_err:
            return dest_err
        return allowed_to_receive(
            env.type,
            session_version=self.session_version,
            envelope_version=env.acp,
            sender_role=self.peer.role.value,
            negotiated_capabilities=self.negotiated_capabilities,
            handshake_complete=True,
            qos=env.qos.value,
            negotiated_versions=self.negotiated_capability_versions,
        )

    async def _check_sequence(self, env: Envelope) -> bool:
        seq = env.sequence
        assert seq is not None
        if self.last_rx_sequence is None:
            if seq == 1:
                self.last_rx_sequence = seq
                return True
            self.counters.sequence_gaps += 1
            self.gap_count += 1
            self.last_rx_sequence = seq
            if seq > 2:
                await self._fail("protocol.sequence_gap", "first sequence is not 1")
                return False
            await self._recover_gap()
            return True
        if seq == self.last_rx_sequence or seq < self.last_rx_sequence:
            return False
        delta = seq - self.last_rx_sequence
        if delta == 1:
            self.last_rx_sequence = seq
            return True
        self.counters.sequence_gaps += 1
        self.gap_count += 1
        self.last_rx_sequence = seq
        if delta > 2 or self.gap_count >= 2:
            await self._fail("protocol.sequence_gap", "sequence gap reset")
            return False
        await self._recover_gap()
        return True

    async def _recover_gap(self) -> None:
        await self._emit_error("protocol.sequence_gap", "sequence gap")
        req = make_envelope(
            type="state.request",
            source=self.source(),
            destination=Endpoint(node_id=self.peer.node_id) if self.peer else None,
            qos=QoS.RELIABLE,
            payload={"resources": []},
        )
        try:
            await self.send(req)
        except Exception:  # noqa: BLE001
            pass

    async def _emit_error(self, code: str, message: str) -> None:
        env = make_envelope(
            type="error.report",
            source=self.source(),
            qos=QoS.RELIABLE,
            payload={
                "code": code,
                "category": "protocol",
                "severity": "error",
                "message": message,
                "retryable": True,
            },
        )
        try:
            await self.send(env)
        except Exception:  # noqa: BLE001
            pass

    async def _fail(self, code: str, message: str) -> None:
        self.state = SessionState.FAILED
        await self._shutdown(code, message)

    def _complete_waiter(self, env: Envelope) -> None:
        corr = env.correlation_id
        if not corr or corr not in self._waiters:
            return
        waiter = self._waiters[corr]
        if env.type not in waiter.expected_types:
            return
        if waiter.peer_node_id and env.source.node_id != waiter.peer_node_id:
            return
        if env.type == "command.ack":
            status = env.payload.get("status")
            try:
                if not CommandStatus(str(status)).terminal():
                    return
            except ValueError:
                return
        self._waiters.pop(corr, None)
        if not waiter.future.done():
            waiter.future.set_result(env)

    def remember_idempotent(
        self,
        message_type: str,
        key: str,
        result: dict[str, Any],
        status: str = "applied",
        request_payload: dict[str, Any] | None = None,
    ) -> None:
        assert self.idempotency is not None
        body = _request_fingerprint(request_payload or result)
        self.idempotency.remember(
            self.local.node_id,
            message_type,
            key,
            status=status,
            result=result,
            body_fingerprint=body,
        )

    def lookup_idempotent(self, message_type: str, key: str, request_payload: dict[str, Any] | None = None):
        assert self.idempotency is not None
        fingerprint = _request_fingerprint(request_payload) if request_payload is not None else None
        rec = self.idempotency.lookup(self.local.node_id, message_type, key, body_fingerprint=fingerprint)
        if rec is None:
            return None
        return {"status": rec.status, **rec.result}


def _request_fingerprint(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "idempotency_key"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _destination_ok(env: Envelope, local, row: dict[str, Any] | None) -> str | None:
    allowed = set((row or {}).get("valid_destinations") or [])
    dest = env.destination
    if dest is None:
        if allowed and not allowed.intersection({"session", "broadcast"}):
            return "malformed_envelope"
        return None
    if dest.node_id != local.node_id:
        return "malformed_envelope"
    if dest.component_id and "component" not in allowed and "node" not in allowed:
        return "malformed_envelope"
    if not dest.component_id and allowed and not allowed.intersection({"node", "session", "component"}):
        return "malformed_envelope"
    return None


def envelope_encoding_guess(encodings: list[str]) -> str:
    return "cbor" if "cbor" in encodings else "json"


def correlation_for(request: Envelope) -> str:
    return request.correlation_id or request.message_id


def make_ack(request: Envelope, source: Endpoint, status: CommandStatus, **extra: Any) -> Envelope:
    payload: dict[str, Any] = {"status": status.value}
    payload.update(extra)
    return make_envelope(
        type="command.ack",
        source=source,
        destination=request.source,
        qos=QoS.RELIABLE,
        payload=payload,
        correlation_id=correlation_for(request),
        causation_id=request.message_id,
        flags=frozenset(),
        acp=request.acp,
    )
