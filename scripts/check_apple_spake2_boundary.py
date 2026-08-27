#!/usr/bin/env python3
"""Audit the restricted Apple SPAKE2+ source and packaged visibility boundary."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "Artifacts/AuroraACPSPAKE2.xcframework"
HEADER = ROOT / "native/apple-spake2/include/AuroraACPSPAKE2.h"
MANIFEST = ROOT / "config/apple-botan-3.13.0.json"

EXPECTED = {
    "acp_spake2_create_registration_record",
    "acp_spake2_prover_create",
    "acp_spake2_verifier_create",
    "acp_spake2_prover_generate_share",
    "acp_spake2_verifier_process_share",
    "acp_spake2_prover_process_response_and_consume_key",
    "acp_spake2_verifier_verify_confirmation_and_consume_key",
    "acp_spake2_destroy",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


config = json.loads(MANIFEST.read_text(encoding="utf-8"))
require(config["botan"]["version"] == "3.13.0", "Botan version drift")
require(config["botan"]["sha256"] == "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620",
        "Botan source hash drift")
require("pcurves_secp256r1" in config["module_closure"], "P-256 implementation missing")

header = HEADER.read_text(encoding="utf-8")
declared = set(re.findall(r"\b(acp_spake2_[a-z0-9_]+)\s*\(", header))
require(declared == EXPECTED, f"restricted ABI drift: {sorted(declared ^ EXPECTED)}")
for forbidden in ("botan_", "skip_confirmation", "ciphersuite", "curve_name", "rng_handle"):
    require(forbidden not in header.lower(), f"public header exposes forbidden surface: {forbidden}")

for packaged_header in ARTIFACT.rglob("*.h"):
    text = packaged_header.read_text(encoding="utf-8")
    require("<botan/" not in text and "botan_" not in text.lower(),
            f"Botan API exposed by {packaged_header}")
require(not list(ARTIFACT.rglob("botan*.h")), "Botan headers packaged")
require(not list(ARTIFACT.rglob("module.modulemap")), "restricted implementation is importable as a Clang module")
require(not list(ARTIFACT.rglob("*.symlink")), "symlink marker packaged")
require(not [path for path in ARTIFACT.rglob("*") if path.is_symlink()], "packaged symlink")

for library in ARTIFACT.rglob("*.a"):
    symbols = subprocess.run(["nm", "-g", str(library)], check=True, text=True,
                             capture_output=True).stdout
    require(not re.search(r"\b_botan_[a-z0-9_]", symbols),
            f"unrestricted Botan C FFI symbol in {library}")
    for expected in EXPECTED:
        require(f"_{expected}" in symbols, f"missing {expected} in {library}")

swift = (ROOT / "Sources/AuroraACPAppleSecurity/ACPAppleSPAKE2Plus.swift").read_text(encoding="utf-8")
require("import AuroraACPSPAKE2" not in swift, "restricted implementation is imported as a Swift module")
require('@_silgen_name("acp_spake2_' in swift, "private link-only bindings missing")
require("import Botan" not in swift, "Swift imports Botan")
require("sharedSecret" not in swift and "shared_secret" not in swift,
        "Swift exposes a standalone shared-secret getter")

print("PASS: Apple SPAKE2+ boundary exposes only ACP restricted operations")
print("NOTE: static archives retain Botan C++ symbols; no Botan headers, C FFI, or Swift module surface is exposed")
