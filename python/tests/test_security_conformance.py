from __future__ import annotations

from pathlib import Path

from acp.security_conformance import validate_fixture_set

ROOT = Path(__file__).resolve().parents[2]


def test_python_consumes_swift_and_rust_security_fixtures() -> None:
    languages = validate_fixture_set(
        ROOT / "vectors/security/conformance",
        ROOT / "vectors/security/conformance/manifest.schema.json",
        consumer_language="python",
    )
    assert languages == {"swift", "rust"}
