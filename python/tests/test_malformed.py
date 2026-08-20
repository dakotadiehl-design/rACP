from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.cbor_cde import CborError, decode
from acp.codec import CodecError, decode_json
from acp.constants import repo_root


def malformed_dir() -> Path:
    return repo_root() / "vectors" / "malformed"


def test_invalid_message_corpus_rejected() -> None:
    manifest = json.loads((repo_root() / "vectors" / "invalid" / "manifest.json").read_text())
    for item in manifest["vectors"]:
        raw = (repo_root() / "vectors" / item["json"]).read_bytes()
        with pytest.raises(CodecError) as err:
            decode_json(raw)
        assert item["error"] in str(err.value)


def test_shared_malformed_corpus_rejected() -> None:
    files = sorted(malformed_dir().glob("*.cbor"))
    assert files, "expected shared malformed CBOR corpus"
    for path in files:
        with pytest.raises(CborError, match="."):
            decode(path.read_bytes())
