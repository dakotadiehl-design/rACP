from __future__ import annotations

from pathlib import Path

import pytest
from acp.cbor_cde import CborError, decode
from acp.constants import repo_root


def malformed_dir() -> Path:
    return repo_root() / "vectors" / "malformed"


def test_shared_malformed_corpus_rejected() -> None:
    files = sorted(malformed_dir().glob("*.cbor"))
    assert files, "expected shared malformed CBOR corpus"
    for path in files:
        with pytest.raises(CborError, match="."):
            decode(path.read_bytes())
