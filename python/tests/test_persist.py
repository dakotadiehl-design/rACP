from __future__ import annotations

import pytest

from acp.persist import NodeStore


def test_store_rejects_path_escape(tmp_path) -> None:
    store = NodeStore(tmp_path)
    with pytest.raises(ValueError):
        store.save("../etc", {"x": 1})
    with pytest.raises(ValueError):
        store.load("bad/name", {})


def test_store_recovers_corrupt_json(tmp_path) -> None:
    store = NodeStore(tmp_path)
    store.save("blackout.json", {"enabled": True})
    (tmp_path / "blackout.json").write_text("{not-json")
    assert store.load("blackout.json", {"enabled": False}) == {"enabled": False}
    store.save("blackout.json", {"enabled": True})
    assert store.load("blackout.json", {})["enabled"] is True
