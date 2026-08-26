#!/usr/bin/env python3
"""Qualify durable Apple Full identity/trust/revocation across real processes."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import uuid
from pathlib import Path


def invoke(executable: Path, mode: str, fixture: Path, service: str, *extra: str,
           expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(executable), mode, str(fixture), service, *extra],
        text=True, capture_output=True, timeout=20, check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"{mode} returned {result.returncode}, expected {expected}: {result.stderr.strip()}"
        )
    return result


def connection(executable: Path, fixture: Path, service: str, expect_success: bool) -> dict[str, str]:
    server = subprocess.Popen(
        [str(executable), "server", str(fixture), service],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert server.stdout is not None
    first = server.stdout.readline()
    if not first:
        _, error = server.communicate(timeout=20)
        raise RuntimeError(f"server did not publish endpoint: {error.strip()}")
    port = str(json.loads(first)["port"])
    client = subprocess.run(
        [str(executable), "client", str(fixture), service, port],
        text=True, capture_output=True, timeout=20, check=False,
    )
    server_out, server_error = server.communicate(timeout=20)
    if expect_success:
        if client.returncode or server.returncode:
            raise RuntimeError(
                f"connection failed: client={client.stderr.strip()} server={server_error.strip()}"
            )
        return {
            "client": json.loads(client.stdout.splitlines()[-1])["status"],
            "server": json.loads(server_out.splitlines()[-1])["status"],
        }
    if client.returncode == 0 or server.returncode == 0:
        raise RuntimeError("revoked reconnect unexpectedly authenticated")
    return {"client": "rejected", "server": "rejected"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    service = f"com.aurora.acp.qualification.{uuid.uuid4()}"
    result: dict[str, object] = {
        "schema_version": "1.0",
        "platform": "macos-arm64",
        "profile": "full",
        "service_hash": str(uuid.uuid5(uuid.NAMESPACE_URL, service)),
    }
    with tempfile.TemporaryDirectory(prefix="acp-apple-full-") as directory:
        fixture = Path(directory)
        subprocess.run([
            "python3", str(root / "scripts/apple_full_qualification_fixtures.py"), str(fixture),
            "--host-label", f"Aurora Qualification Host {uuid.uuid4()}",
            "--client-label", f"Aurora Qualification Client {uuid.uuid4()}",
        ], check=True, timeout=20)
        try:
            invoke(args.executable, "bootstrap", fixture, service)
            result["fresh_identity_process"] = "PASS"
            result["connection_after_bootstrap_restart"] = connection(
                args.executable, fixture, service, True)
            result["connection_after_both_processes_restart"] = connection(
                args.executable, fixture, service, True)
            invoke(args.executable, "revoke", fixture, service)
            result["revocation_process"] = "PASS"
            result["rejected_after_host_restart"] = connection(
                args.executable, fixture, service, False)
            result["overall"] = "PASS"
        finally:
            cleanup = invoke(args.executable, "cleanup", fixture, service)
            result["cleanup"] = json.loads(cleanup.stdout)["status"]
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
