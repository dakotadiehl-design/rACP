#!/usr/bin/env python3
"""Audit built release artifacts for security test/fabrication APIs."""

from __future__ import annotations

import argparse
import json
import subprocess
import zipfile
from pathlib import Path

FORBIDDEN = (
    "unsafe_transport_evidence_for_testing",
    "unsafe_authenticated_principal_for_testing",
    "unsafe_full_tls_handshake_for_testing",
)
FORBIDDEN_SWIFT_PATHS = (
    "ACPTransportEvidence.init",
    "ACPFullTLSHandshake.init",
    "ACPAuthenticatedConnection.init",
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def audit_swift(directory: Path) -> None:
    graphs = list(directory.glob("*.symbols.json"))
    if not graphs:
        fail(f"no Swift symbol graphs in {directory}")
    for graph in graphs:
        document = json.loads(graph.read_text(encoding="utf-8"))
        for symbol in document.get("symbols", []):
            path = ".".join(symbol.get("pathComponents", []))
            if any(value in path for value in (*FORBIDDEN_SWIFT_PATHS, *FORBIDDEN)):
                fail(f"release-visible Swift fabrication API: {path}")


def audit_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        shipped = "\n".join(archive.namelist())
        if "security_testkit" in shipped:
            fail("Python wheel contains the test-only security helper")
        for name in archive.namelist():
            if not name.startswith("acp/") or not name.endswith(".py"):
                continue
            source = archive.read(name).decode("utf-8")
            for forbidden in FORBIDDEN:
                if forbidden in source:
                    fail(f"Python wheel exposes {forbidden} in {name}")


def audit_rust(library: Path) -> None:
    result = subprocess.run(["nm", "-g", str(library)], check=True, text=True, capture_output=True)
    for forbidden in FORBIDDEN:
        if forbidden in result.stdout:
            fail(f"Rust release library exposes {forbidden}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--swift-symbol-dir", type=Path, required=True)
    parser.add_argument("--python-wheel", type=Path, required=True)
    parser.add_argument("--rust-library", type=Path, required=True)
    args = parser.parse_args()
    audit_swift(args.swift_symbol_dir)
    audit_wheel(args.python_wheel)
    audit_rust(args.rust_library)
    print("PASS: release artifacts contain no authenticated-state fabrication API")


if __name__ == "__main__":
    main()
