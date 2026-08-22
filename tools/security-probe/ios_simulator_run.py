#!/usr/bin/env python3
"""Run ACP M0 evidence probes in a genuine arm64 iOS Simulator process."""

from __future__ import annotations

import argparse
import base64
import json
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(__file__).resolve().parent
RESULT = TOOL / "results/ios-simulator-arm64-botan-3.13.0.json"
SDK = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator26.5.sdk"
)
TARGET = "arm64-apple-ios16.0-simulator"
SCALAR = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF


def run(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def probe(probe_id: str, status: str, detail: str, mandatory: bool = True) -> dict[str, object]:
    return {"id": probe_id, "status": status, "detail": detail, "mandatory": mandatory}


def compile_cpp(source: Path, output: Path, include: Path, library: Path) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "/usr/bin/clang++",
            "-std=c++20",
            "-target",
            TARGET,
            "-isysroot",
            str(SDK),
            "-I",
            str(include),
            str(source),
            str(library),
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            str(output),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True, help="booted Simulator UDID")
    parser.add_argument("--botan-build", type=Path, required=True)
    args = parser.parse_args()
    include = args.botan_build / "build/include/public"
    library = args.botan_build / "libbotan-3.a"
    probes: list[dict[str, object]] = []
    registration = json.loads((ROOT / "vectors/security/registration/raw128_primary.json").read_text())
    context = json.loads((ROOT / "vectors/security/context/primary.json").read_text())

    with tempfile.TemporaryDirectory(prefix="acp-ios-simulator-") as temporary:
        temp = Path(temporary)
        core = temp / "botan-probe"
        core_compile = compile_cpp(TOOL / "botan_probe.cpp", core, include, library)
        if core_compile.returncode:
            probes.append(probe("botan.spake_hash_kdf", "FAIL", core_compile.stderr[-1000:]))
        else:
            core_run = run(
                [
                    "xcrun",
                    "simctl",
                    "spawn",
                    args.device,
                    str(core),
                    registration["w0_hex"],
                    registration["w1_hex"],
                    context["canonical_cbor_hex"],
                ]
            )
            probes.append(
                probe(
                    "botan.spake_hash_kdf",
                    "PASS" if core_run.returncode == 0 else "FAIL",
                    core_run.stdout.strip() or core_run.stderr.strip(),
                )
            )

        x509_vector = json.loads((ROOT / "vectors/security/x509/full_profile.json").read_text())
        root = temp / "root.der"
        leaf = temp / "leaf.der"
        key = temp / "key.pem"
        root.write_bytes(base64.b64decode(x509_vector["root_der_base64"]))
        leaf.write_bytes(base64.b64decode(x509_vector["leaf_der_base64"]))
        private_key = ec.derive_private_key(SCALAR, ec.SECP256R1())
        key.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        tls = temp / "botan-tls-probe"
        tls_compile = compile_cpp(TOOL / "botan_tls_probe.cpp", tls, include, library)
        if tls_compile.returncode:
            probes.extend(
                probe(name, "FAIL", tls_compile.stderr[-1000:])
                for name in ("tls13.mutual_auth", "tls13.peer_evidence", "tls13.exporter", "tls13.no_resumption_0rtt")
            )
        else:
            tls_run = run(["xcrun", "simctl", "spawn", args.device, str(tls), str(leaf), str(root), str(key)])
            try:
                payload = json.loads(tls_run.stdout)
            except json.JSONDecodeError:
                payload = {}
            detail = tls_run.stdout.strip() or tls_run.stderr.strip()
            probes.append(probe("tls13.mutual_auth", "PASS" if payload.get("tls13") is True else "FAIL", detail))
            peer_pass = (
                payload.get("client_verified_certificates") == 1 and payload.get("server_verified_certificates") == 1
            )
            probes.append(probe("tls13.peer_evidence", "PASS" if peer_pass else "FAIL", detail))
            exporter_pass = payload.get("exporter_equal") is True and payload.get("exporter_length") == 32
            probes.append(probe("tls13.exporter", "PASS" if exporter_pass else "FAIL", detail))
            resume_pass = payload.get("session_manager") == "noop" and payload.get("tickets_issued") == 0
            probes.append(probe("tls13.no_resumption_0rtt", "PASS" if resume_pass else "FAIL", detail))

        swift = temp / "platform-probe"
        swift_compile = run(
            [
                "xcrun",
                "swiftc",
                "-target",
                TARGET,
                "-sdk",
                str(SDK),
                str(TOOL / "ios_simulator_platform_probe.swift"),
                "-o",
                str(swift),
            ]
        )
        if swift_compile.returncode:
            probes.append(probe("ios.platform", "FAIL", swift_compile.stderr[-1000:]))
        else:
            swift_run = run(["xcrun", "simctl", "spawn", args.device, str(swift), str(ROOT / "vectors/security")])
            try:
                probes.extend(json.loads(swift_run.stdout))
            except json.JSONDecodeError:
                probes.append(probe("ios.platform", "FAIL", swift_run.stdout.strip() or swift_run.stderr.strip()))

    # These require production adapter code or physical hardware and must stay explicit.
    probes.extend(
        [
        probe(
            "x509.acp_identity_policy",
            "NOT_RUN",
            "Simulator Botan TLS validates the isolated chain; complete SAN/domain/node/EKU/time/revocation "
            "adapter is not implemented before M1",
        ),
            probe(
                "network.negative_tls",
                "NOT_RUN",
                "wrong-CA/domain/node/credential network adapter cases are not implemented before M1",
            ),
            probe(
                "bonjour.trust_metadata",
                "NOT_RUN",
                "no app-hosted Bonjour qualification target; existing discovery contract remains unauthenticated",
                False,
            ),
            probe(
                "secure_enclave.hardware",
                "NOT_RUN",
                "physical-device-only; Simulator software behavior is not evidence",
                False,
            ),
        ]
    )
    mandatory_applicable = [p for p in probes if p.get("mandatory", True)]
    qualified = all(p["status"] == "PASS" for p in mandatory_applicable)
    report = {
        "schema_version": 1,
        "freeze": "2.1.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {
            "environment": "iOS Simulator",
            "runtime": "iOS 26.5",
            "device": "iPhone 17 Pro",
            "architecture": "arm64",
            "udid": args.device,
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "xcode": "26.6 (17F113)",
            "swift": "6.3.3",
        },
        "provider": {"name": "Botan", "version": "3.13.0", "target": TARGET, "linkage": "static", "sdk": str(SDK)},
        "probes": probes,
        "ios_simulator_full_profile_functional_qualified": qualified,
        "ios_physical_device_full_profile": "NOT_RUN",
        "secure_enclave_hardware": "NOT_RUN",
    }
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    counts = {
        status: sum(p["status"] == status for p in probes) for status in ("PASS", "FAIL", "NOT_RUN", "NOT_SUPPORTED")
    }
    print(f"iOS Simulator qualified={str(qualified).lower()} " + " ".join(f"{k}={v}" for k, v in counts.items()))
    return 0 if qualified else 1


if __name__ == "__main__":
    sys.exit(main())
