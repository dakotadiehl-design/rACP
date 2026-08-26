#!/usr/bin/env python3
"""Fail when release-visible APIs reopen authenticated-evidence fabrication."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


swift_evidence = read("Sources/AuroraACP/Session/ACPSecurity.swift")
swift_handshake = read("Sources/AuroraACP/Security/ACPAuthenticatedTransport.swift")
swift_connection = read("Sources/AuroraACP/Security/ACPAuthenticatedConnection.swift")
swift_provenance = read("Sources/AuroraACP/Security/ACPProviderProvenance.swift")
rust_security = read("rust/acp-security/src/lib.rs")
rust_manifest = read("rust/acp-security/Cargo.toml")
python_security = read("python/src/acp/security.py")
python_testkit = read("python/src/acp/testkit.py")

for type_name, source in (
    ("ACPTransportEvidence", swift_evidence),
    ("ACPFullTLSHandshake", swift_handshake),
    ("ACPAuthenticatedConnection", swift_connection),
):
    body = re.search(rf"(?:struct|class) {type_name}\b.*?\n}}", source, re.DOTALL)
    require(body is not None, f"Swift {type_name} declaration missing")
    require("public init(" not in body.group(0), f"Swift {type_name} has a public initializer")
    require("package init(" in body.group(0), f"Swift {type_name} is not package-owned")

require("public struct ACPTransportEvidence: Sendable, Equatable" in swift_evidence,
        "Swift evidence unexpectedly gained serialization conformance")
require("public final class ACPAuthenticatedConnection" in swift_connection,
        "Swift authenticated connection is not an opaque reference capability")
require("private var payload: Payload?" in swift_connection,
        "Swift authenticated connection no longer owns private one-shot state")
require("providerProvenance: ACPProviderProvenance" in swift_connection,
        "Swift connection accepts an unvalidated provider digest")
require("requireQualified: Bool = true" in swift_provenance,
        "Swift provider manifests do not fail closed on qualification status")

require("pub struct TransportEvidence" in rust_security, "Rust evidence declaration missing")
rust_evidence = re.search(r"pub struct TransportEvidence \{(.*?)\n}", rust_security, re.DOTALL)
require(rust_evidence is not None, "Rust evidence body missing")
require("pub " not in rust_evidence.group(1), "Rust evidence contains a public field")
require("#[derive(Debug, Clone, PartialEq, Eq)]\npub struct TransportEvidence" not in rust_security,
        "Rust evidence is cloneable across connections")
require("pub struct AuthenticatedConnection<T>" in rust_security,
        "Rust authenticated connection declaration missing")
require("pub(crate) fn from_provider" in rust_security,
        "Rust provider constructor is not crate-owned")
require("pub(crate) fn into_parts" in rust_security,
        "Rust connection exposes verified evidence to downstream callers")
require("default = []" in rust_manifest, "Rust default features are not empty")
require("testkit = []" in rust_manifest, "Rust testkit feature declaration missing")

require("_EVIDENCE_PROVENANCE = object()" in python_security,
        "Python evidence provenance sentinel missing")
require("if _provenance is not _EVIDENCE_PROVENANCE" in python_security,
        "Python evidence constructor does not enforce provenance")
require("unsafe_transport_evidence_for_testing" not in python_testkit,
        "Python release package ships an unsafe evidence factory")
require("unsafe_authenticated_principal_for_testing" not in python_testkit,
        "Python release package ships an unsafe principal factory")

print("PASS: authenticated evidence boundary remains sealed in Swift, Python, and Rust")
