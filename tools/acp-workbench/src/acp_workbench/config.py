from __future__ import annotations

import ipaddress
import os
from dataclasses import fields
from urllib.parse import urlparse

from .models import ConnectionConfig


def from_environment(base: ConnectionConfig) -> ConnectionConfig:
    values = {field.name: getattr(base, field.name) for field in fields(base)}
    prefix = "ACP_WORKBENCH_"
    for name in values:
        raw = os.getenv(prefix + name.upper())
        if raw is None:
            continue
        current = values[name]
        if isinstance(current, bool):
            values[name] = raw.lower() in {"1", "true", "yes", "on"}
        elif isinstance(current, float):
            values[name] = float(raw)
        else:
            values[name] = raw
    return ConnectionConfig(**values)


def is_loopback_target(target: str) -> bool:
    host = urlparse(target).hostname
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def enforce_target_safety(target: str, *, allow_live_target: bool) -> None:
    if not is_loopback_target(target) and not allow_live_target:
        raise PermissionError("non-loopback target refused; pass --allow-live-target explicitly")

