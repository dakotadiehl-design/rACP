from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from acp.envelope import Envelope

from .engine import WorkbenchEngine
from .models import AssertionResult, ConnectionConfig, ScenarioResult, utc_now_text

TOP_KEYS = {"schema_version", "id", "name", "simulate", "target", "profile", "tags", "timeout", "steps"}
REQUIRED_KEYS = {"schema_version", "id", "name", "simulate", "profile", "steps"}
STEP_NAMES = {
    "connect", "disconnect", "send", "invoke", "navigate", "expect", "expect_none",
    "expect_state_change", "assert_state", "sleep",
}
STEP_KEYS = {
    "connect": set(),
    "disconnect": {"graceful"},
    "sleep": {"duration"},
    "invoke": {"control_id", "value", "interaction", "invocation_id", "lease_id"},
    "navigate": {"kind", "song_id"},
    "send": {"envelope"},
    "expect": {"type", "types", "where", "capture", "timeout", "correlation_id"},
    "expect_state_change": {"type", "types", "where", "capture", "timeout", "correlation_id"},
    "expect_none": {"type", "types", "where", "timeout", "correlation_id"},
    "assert_state": {"path", "equals"},
}
STEP_REQUIRED = {
    "invoke": {"control_id"},
    "navigate": {"kind"},
    "send": {"envelope"},
    "assert_state": {"path"},
}
VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True, slots=True)
class Scenario:
    schema_version: int
    id: str
    name: str
    simulate: str
    profile: str
    steps: list[dict[str, Any]]
    target: str | None = None
    tags: tuple[str, ...] = ()
    timeout: float = 15.0


def _duration(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    if text.endswith("ms"):
        return float(text[:-2]) / 1000
    if text.endswith("s"):
        return float(text[:-1])
    return float(text)


def load_data(path: str | Path) -> Any:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if file.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("YAML scenario support requires: pip install 'aurora-acp-workbench[yaml]'") from exc
    return yaml.safe_load(text)


def parse_scenario(data: Any) -> Scenario:
    if not isinstance(data, dict):
        raise ValueError("scenario must be an object")
    unknown = set(data) - TOP_KEYS
    missing = REQUIRED_KEYS - set(data)
    if unknown:
        raise ValueError(f"unknown scenario keys: {sorted(unknown)}")
    if missing:
        raise ValueError(f"missing scenario keys: {sorted(missing)}")
    if data["schema_version"] != 1:
        raise ValueError("unsupported scenario schema_version")
    if data["simulate"] != "remote":
        raise ValueError("only the remote simulated role is implemented")
    steps = data["steps"]
    if not isinstance(steps, list) or not steps:
        raise ValueError("steps must be a non-empty array")
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError(f"step {index + 1} must contain exactly one operation")
        operation = next(iter(step))
        if operation not in STEP_NAMES:
            raise ValueError(f"unknown step operation {operation!r}")
        if not isinstance(step[operation], dict):
            raise ValueError(f"step {operation!r} parameters must be an object")
        parameters = step[operation]
        unknown_parameters = set(parameters) - STEP_KEYS[operation]
        missing_parameters = STEP_REQUIRED.get(operation, set()) - set(parameters)
        if unknown_parameters:
            raise ValueError(f"step {operation!r} has unknown parameters: {sorted(unknown_parameters)}")
        if missing_parameters:
            raise ValueError(f"step {operation!r} is missing parameters: {sorted(missing_parameters)}")
    return Scenario(
        schema_version=1,
        id=str(data["id"]),
        name=str(data["name"]),
        simulate=str(data["simulate"]),
        target=str(data["target"]) if data.get("target") else None,
        profile=str(data["profile"]),
        tags=tuple(str(tag) for tag in data.get("tags") or []),
        timeout=_duration(data.get("timeout", 15)),
        steps=steps,
    )


def load_scenario(path: str | Path) -> Scenario:
    return parse_scenario(load_data(path))


def discover_scenarios(path: str | Path) -> list[Path]:
    root = Path(path)
    if root.is_file():
        return [root]
    return sorted(item for item in root.rglob("*") if item.suffix.lower() in {".json", ".yaml", ".yml"})


def dotted(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(path)
    return current


def substitute(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: substitute(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, variables) for item in value]
    if not isinstance(value, str):
        return value
    match = VAR_RE.fullmatch(value)
    if match:
        if match.group(1) not in variables:
            raise ValueError(f"unknown variable {match.group(1)!r}")
        return variables[match.group(1)]
    return VAR_RE.sub(lambda m: str(variables[m.group(1)]), value)


class ScenarioRunner:
    def __init__(self, engine: WorkbenchEngine) -> None:
        self.engine = engine

    async def run(self, scenario: Scenario, config: ConnectionConfig) -> ScenarioResult:
        started_text = utc_now_text()
        started = time.monotonic()
        assertions: list[AssertionResult] = []
        variables: dict[str, Any] = {}
        cursor = self.engine.history[-1].sequence if self.engine.history else 0
        error: str | None = None
        connection_id = scenario.id
        try:
            async with asyncio.timeout(scenario.timeout):
                for raw_step in scenario.steps:
                    operation, raw_parameters = next(iter(raw_step.items()))
                    parameters = substitute(raw_parameters, variables)
                    before = time.monotonic()
                    if operation == "connect":
                        await self.engine.connect(config, connection_id=connection_id)
                    elif operation == "disconnect":
                        await self.engine.disconnect(connection_id, graceful=bool(parameters.get("graceful", True)))
                    elif operation == "sleep":
                        await asyncio.sleep(_duration(parameters.get("duration", 0)))
                    elif operation == "invoke":
                        env = await self.engine.invoke(
                            connection_id,
                            str(parameters["control_id"]),
                            parameters.get("value"),
                            interaction=parameters.get("interaction", "activate"),
                            invocation_id=parameters.get("invocation_id"),
                            lease_id=parameters.get("lease_id"),
                        )
                        variables["last_message_id"] = env.message_id
                        variables["last_invocation_id"] = env.payload.get("invocation_id")
                        variables["last_intent_sequence"] = self._outbound_sequence(env.message_id)
                    elif operation == "navigate":
                        env = await self.engine.navigate(
                            connection_id,
                            str(parameters["kind"]),
                            song_id=parameters.get("song_id"),
                        )
                        variables["last_message_id"] = env.message_id
                        variables["last_intent_sequence"] = self._outbound_sequence(env.message_id)
                    elif operation == "send":
                        conn = self.engine.connections[connection_id]
                        env = Envelope.from_dict(parameters["envelope"])
                        await conn.send(env)
                        variables["last_message_id"] = env.message_id
                        variables["last_intent_sequence"] = self._outbound_sequence(env.message_id)
                    elif operation in {"expect", "expect_state_change"}:
                        spec = dict(parameters)
                        if operation == "expect_state_change" and "types" not in spec:
                            spec["types"] = [
                                "state.delta", "state.snapshot", "remote.control.state",
                                "remote.control.snapshot", "remote.navigation.state", "remote.presentation.state",
                            ]
                        if operation == "expect" and spec.get("type") == "command.ack":
                            spec.setdefault("correlation_id", variables.get("last_message_id"))
                        search_cursor = cursor
                        if operation == "expect_state_change":
                            search_cursor = int(variables.get("last_intent_sequence") or cursor)
                        event = await self._expect(connection_id, spec, search_cursor)
                        cursor = event.sequence
                        envelope = event.data["envelope"]
                        for name, path in (spec.get("capture") or {}).items():
                            variables[str(name)] = dotted(envelope, str(path))
                        assertions.append(AssertionResult(
                            True,
                            f"received {envelope['type']}",
                            evidence=[event.sequence],
                            duration_s=time.monotonic() - before,
                        ))
                    elif operation == "expect_none":
                        try:
                            await self._expect(connection_id, parameters, cursor)
                        except TimeoutError:
                            assertions.append(AssertionResult(
                                True,
                                "no matching message received",
                                duration_s=time.monotonic() - before,
                            ))
                        else:
                            assertions.append(AssertionResult(
                                False,
                                "unexpected matching message received",
                                duration_s=time.monotonic() - before,
                            ))
                    elif operation == "assert_state":
                        conn = self.engine.connections[connection_id]
                        actual = dotted(conn.profile.view, str(parameters["path"]))
                        expected = parameters.get("equals")
                        passed = actual == expected
                        assertions.append(AssertionResult(
                            passed,
                            f"state {parameters['path']}",
                            expected,
                            actual,
                            duration_s=time.monotonic() - before,
                        ))
                        if not passed:
                            raise AssertionError(f"state {parameters['path']}: expected {expected!r}, got {actual!r}")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if connection_id in self.engine.connections:
                await self.engine.disconnect(connection_id, graceful=True)
        return ScenarioResult(
            scenario_id=scenario.id,
            name=scenario.name,
            passed=error is None and all(item.passed for item in assertions),
            assertions=assertions,
            started_at=started_text,
            duration_s=time.monotonic() - started,
            error=error,
        )

    async def _expect(self, connection_id: str, spec: dict[str, Any], cursor: int):
        expected_type = spec.get("type")
        expected_types = set(spec.get("types") or ([] if expected_type is None else [expected_type]))
        where = dict(spec.get("where") or {})

        def predicate(event) -> bool:
            if event.connection_id != connection_id or event.kind != "envelope.in":
                return False
            env = event.data["envelope"]
            if expected_types and env.get("type") not in expected_types:
                return False
            if spec.get("correlation_id") and env.get("correlation_id") != spec["correlation_id"]:
                return False
            try:
                return all(dotted(env, path) == value for path, value in where.items())
            except KeyError:
                return False

        return await self.engine.wait_for(
            predicate,
            after_sequence=cursor,
            timeout=_duration(spec.get("timeout", 2)),
        )

    def _outbound_sequence(self, message_id: str) -> int:
        for event in reversed(self.engine.history):
            envelope = event.data.get("envelope") or {}
            if event.kind == "envelope.out" and envelope.get("message_id") == message_id:
                return event.sequence
        return self.engine.history[-1].sequence if self.engine.history else 0


def scenario_to_dict(scenario: Scenario) -> dict[str, Any]:
    return asdict(scenario)
