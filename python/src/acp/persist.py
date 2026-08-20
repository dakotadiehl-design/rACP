"""Atomic JSON persistence for node-owned safety state."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class NodeStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, stat.S_IRWXU)

    def path(self, name: str) -> Path:
        if not SAFE_NAME.match(name):
            raise ValueError(f"unsafe store key: {name!r}")
        target = (self.root / name).resolve()
        if not str(target).startswith(str(self.root) + os.sep) and target != self.root:
            raise ValueError("store path escapes root")
        return target

    def load(self, name: str, default: Any) -> Any:
        target = self.path(name)
        if not target.is_file():
            return default
        try:
            data = json.loads(target.read_text())
        except (OSError, json.JSONDecodeError):
            return default
        if not isinstance(data, (dict, list, str, int, float, bool)) and data is not None:
            return default
        return data

    def save(self, name: str, value: Any) -> None:
        target = self.path(name)
        tmp = target.with_suffix(target.suffix + ".tmp")
        payload = json.dumps(value, indent=2, sort_keys=True, default=str)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        dir_fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
