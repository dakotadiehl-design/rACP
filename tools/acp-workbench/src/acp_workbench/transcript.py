from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import WorkbenchEvent

SENSITIVE_KEYS = {
    "auth", "authorization", "credential", "credential_body", "enrollment_code",
    "key_file", "key_material", "pake_message", "password", "private_key", "proof",
    "recovery_code", "secret", "token",
}
SENSITIVE_SUFFIXES = ("_credential", "_password", "_private_key", "_proof", "_secret", "_token")
REDACTED = {"$redacted": True}


def _sensitive(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS or normalized.endswith(SENSITIVE_SUFFIXES)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: dict(REDACTED) if _sensitive(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class TranscriptWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a", encoding="utf-8")

    def write(self, event: WorkbenchEvent) -> None:
        record = {"transcript_schema": 1, **event.to_dict()}
        record["data"] = redact(record["data"])
        self._file.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> TranscriptWriter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
