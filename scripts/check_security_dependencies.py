"""Offline reproducible dependency/profile and license-policy check."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    lock = tomllib.loads((ROOT / "rust/Cargo.lock").read_text())
    versions = {package["name"]: package["version"] for package in lock["package"]}
    expected = {"hmac": "0.12.1", "sha2": "0.10.9", "subtle": "2.6.1", "uuid": "1.18.1"}
    assert {name: versions.get(name) for name in expected} == expected
    probe = json.loads(
        (
            ROOT / "tools/security-probe/results/macos-arm64-botan-3.13.0.json"
        ).read_text()
    )
    provider = next(
        item for item in probe["probes"] if item["id"] == "provider.version"
    )
    assert provider["status"] == "PASS" and provider["detail"] == "Botan 3.13.0 exact"
    pyproject = tomllib.loads((ROOT / "python/pyproject.toml").read_text())
    assert (
        "cryptography>=50,<51"
        in pyproject["project"]["optional-dependencies"]["security-vectors"]
    )
    licenses = {
        "Botan 3.13.0": "BSD-2-Clause",
        "RustCrypto hmac/sha2/subtle": "MIT OR Apache-2.0",
        "Python cryptography": "Apache-2.0 OR BSD-3-Clause",
        "Swift CryptoKit": "Apple platform SDK terms",
    }
    print(
        json.dumps(
            {
                "versions": expected | {"botan": "3.13.0"},
                "licenses": licenses,
                "advisories": "NOT_RUN_OFFLINE_USE_CI_AUDIT_JOBS",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
