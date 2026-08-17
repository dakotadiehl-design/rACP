"""Atomic JSON persistence for node-owned safety state."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class NodeStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        return self.root / name

    def load(self, name: str, default: Any) -> Any:
        target = self.path(name)
        if not target.is_file():
            return default
        return json.loads(target.read_text())

    def save(self, name: str, value: Any) -> None:
        target = self.path(name)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str))
        os.replace(tmp, target)
