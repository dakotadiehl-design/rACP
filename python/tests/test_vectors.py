from __future__ import annotations

import json

from acp.codec import decode_cbor, decode_json, encode_cbor
from acp.constants import repo_root


def test_golden_vectors_roundtrip() -> None:
    root = repo_root()
    manifest = json.loads((root / "vectors" / "manifest.json").read_text())
    for item in manifest["vectors"]:
        data = json.loads((root / "vectors" / item["json"]).read_text())
        env = decode_json(json.dumps(data))
        encoded = encode_cbor(env)
        cbor_path = root / "vectors" / item["cbor"]
        assert cbor_path.is_file(), item["id"]
        pinned = cbor_path.read_bytes()
        assert encoded == pinned, item["id"]
        again = decode_cbor(pinned)
        assert again.to_dict() == env.to_dict(), item["id"]
