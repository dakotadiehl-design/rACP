"""Typed command preconditions evaluated against authoritative state."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class PreconditionError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "command.precondition_failed"


def evaluate_preconditions(
    preconditions: list[Mapping[str, Any]] | None,
    *,
    authority_epoch: int,
    revision: int,
    show_id: str | None = None,
    current_cue_id: str | None = None,
    resources: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    if not preconditions:
        return
    resources = resources or {}
    for pred in preconditions:
        op = pred.get("op")
        field = pred.get("field")
        value = pred.get("value")
        actual: Any
        if field == "authority_epoch":
            actual = authority_epoch
        elif field == "revision":
            actual = revision
        elif field == "show_id":
            actual = show_id
        elif field == "current_cue_id":
            actual = current_cue_id
        elif field == "resource_field":
            resource = pred.get("resource")
            resource_field = pred.get("resource_field")
            if not resource or not resource_field:
                raise PreconditionError("resource_field precondition is incomplete")
            actual = (resources.get(resource) or {}).get(resource_field)
        else:
            raise PreconditionError(f"unknown precondition field {field}")
        if op == "equals":
            if actual != value:
                raise PreconditionError(f"{field} equals {value!r} failed (actual {actual!r})")
        elif op == "at_least":
            if actual is None or value is None:
                raise PreconditionError(f"{field} at_least requires integers")
            try:
                if int(actual) < int(value):
                    raise PreconditionError(f"{field} at_least {value!r} failed (actual {actual!r})")
            except (TypeError, ValueError) as exc:
                raise PreconditionError(f"{field} at_least requires integers") from exc
        else:
            raise PreconditionError(f"unknown precondition op {op}")
