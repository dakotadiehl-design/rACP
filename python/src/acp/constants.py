"""Load protocol constants from packaged data, falling back to the repo tree."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path


def _packaged_file(*parts: str) -> Path | None:
    try:
        root = resources.files("acp.data")
        target = root.joinpath(*parts)
        if target.is_file():
            return Path(str(target))
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        return None
    return None


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "schema" / "constants.json").is_file():
            return candidate
    raise FileNotFoundError("schema/constants.json not found from " + str(here))


def data_file(*parts: str) -> Path:
    packaged = _packaged_file(*parts)
    if packaged is not None:
        return packaged
    return repo_root().joinpath("schema", *parts)


@lru_cache(maxsize=1)
def load() -> dict:
    return json.loads(data_file("constants.json").read_text())


def discovery() -> dict:
    return load()["discovery"]


def session() -> dict:
    return load()["session"]


def limits(profile: str = "full") -> dict:
    return load()["limits"][profile]


def schema_root() -> Path:
    packaged = _packaged_file("schema", "envelope.schema.json")
    if packaged is not None:
        return packaged.parent
    return repo_root() / "schema"
