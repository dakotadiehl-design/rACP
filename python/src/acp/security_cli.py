"""Offline Aurora Trust operator CLI. Secret values are never accepted as argv options."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .security_operations import MigrationStage, OperationalStateStore, migration_decision

REDACT_KEYS = frozenset(
    {
        "bootstrap_secret",
        "manual_code",
        "pake_input",
        "derived_key",
        "private_key",
        "approval_plaintext",
        "credential",
        "ciphertext",
        "confirmation",
    }
)
MAX_BOOTSTRAP_SECRET_BYTES = 4096


def redact(value: Any, key: str = "") -> Any:
    if key.lower() in REDACT_KEYS or any(token in key.lower() for token in ("secret", "private_key", "derived_key")):
        return "<redacted>"
    if isinstance(value, dict):
        return {name: redact(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _secret(path: str | None) -> bytes:
    if path is None:
        value = getpass.getpass("Bootstrap secret (input hidden; never pass secrets on the command line): ").encode()
        if not value or len(value) > MAX_BOOTSTRAP_SECRET_BYTES:
            raise ValueError("security.credential_invalid")
        return value
    source = Path(path)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or metadata.st_size > MAX_BOOTSTRAP_SECRET_BYTES + 2
        ):
            raise ValueError("secret input file must be an owner-only regular file within the size limit")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            value = stream.read(MAX_BOOTSTRAP_SECRET_BYTES + 3).rstrip(b"\r\n")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not value or len(value) > MAX_BOOTSTRAP_SECRET_BYTES:
        raise ValueError("security.credential_invalid")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acp-security")
    parser.add_argument("--state-dir", default=os.environ.get("ACP_SECURITY_STATE_DIR", ".acp-security"))
    parser.add_argument("--json", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    domain = commands.add_parser("domain")
    domain_sub = domain.add_subparsers(dest="action", required=True)
    create = domain_sub.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument(
        "--authority-key-id", required=True, help="ID of an existing provider-managed authority signing key"
    )
    imp = domain_sub.add_parser("import")
    imp.add_argument("package")
    enrollment = commands.add_parser("enrollment")
    enrollment_sub = enrollment.add_subparsers(dest="action", required=True)
    opened = enrollment_sub.add_parser("open")
    opened.add_argument("domain_id")
    opened.add_argument("--secret-file")
    for action in ("candidate", "commissioner"):
        item = enrollment_sub.add_parser(action)
        item.add_argument("enrollment_id")
        if action == "commissioner":
            item.add_argument("--node-id", required=True)
            item.add_argument("--credential-id", required=True)
            item.add_argument("--identity-key-id", required=True)
    node = commands.add_parser("node")
    node_sub = node.add_subparsers(dest="action", required=True)
    node_sub.add_parser("list")
    inspect = node_sub.add_parser("inspect")
    inspect.add_argument("node_id")
    for action in ("renew", "rotate", "revoke", "reset", "recover"):
        item = node_sub.add_parser(action)
        item.add_argument("node_id")
        if action in {"renew", "rotate"}:
            item.add_argument("--credential-id", required=True)
        if action == "rotate":
            item.add_argument("--identity-key-id", required=True)
        if action == "recover":
            item.add_argument("--identity-store", required=True)
    revocation = commands.add_parser("revocation")
    revocation.add_argument("action", choices=["status"])
    audit = commands.add_parser("audit")
    audit.add_argument("action", choices=["verify"])
    commands.add_parser("diagnostics")
    migration = commands.add_parser("migration")
    migration_sub = migration.add_subparsers(dest="action", required=True)
    migration_sub.add_parser("status")
    setting = migration_sub.add_parser("set")
    setting.add_argument("stage", choices=[stage.value for stage in MigrationStage])
    setting.add_argument("--allow-trusted-lan", action="store_true")
    return parser


def execute(args: argparse.Namespace, store: OperationalStateStore) -> Any:
    state = store.load()
    if args.command == "domain":
        return (
            store.create_domain(args.name, args.authority_key_id)
            if args.action == "create"
            else store.import_domain(json.loads(Path(args.package).read_text()))
        )
    if args.command == "enrollment":
        if args.action == "open":
            return store.open_enrollment(args.domain_id, _secret(args.secret_file))
        return store.advance_enrollment(
            args.enrollment_id,
            args.action,
            getattr(args, "node_id", None),
            getattr(args, "credential_id", None),
            getattr(args, "identity_key_id", None),
        )
    if args.command == "node":
        if args.action == "list":
            return list(state["nodes"].values())
        if args.action == "inspect":
            return state["nodes"].get(args.node_id) or _raise("security.credential_invalid")
        if args.action == "recover":
            return store.recover_identity(args.node_id, Path(args.identity_store))
        return store.credential_action(
            args.node_id,
            args.action,
            credential_id=getattr(args, "credential_id", None),
            identity_key_id=getattr(args, "identity_key_id", None),
        )
    if args.command == "revocation":
        return {
            "epoch": state["revocation_epoch"],
            "credential_ids": state["revoked_credentials"],
            "revoked": [node for node in state["nodes"].values() if node["status"] == "revoked"],
        }
    if args.command == "audit":
        valid, entries = store.verify_audit()
        return {"valid": valid, "entries": entries}
    if args.command == "migration":
        if args.action == "set":
            return store.set_migration(MigrationStage(args.stage), args.allow_trusted_lan)
        return state["migration"]
    migration = state["migration"]
    decision = migration_decision(
        MigrationStage(migration["stage"]),
        authenticated=False,
        explicitly_allow_trusted_lan=migration["allow_trusted_lan"],
    )
    return {
        "security_mode": "offline",
        "enrollment_state": [value["state"] for value in state["enrollments"].values()],
        "trust_domain_ids": sorted(state["domains"]),
        "authentication_state": "not_connected",
        "revocation_epoch": state["revocation_epoch"],
        "policy_revision": len(state["audit"]) + 1,
        "migration": migration,
        "unauthenticated_control_allowed": decision.sensitive_control_allowed,
    }


def _raise(message: str) -> Any:
    raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = redact(execute(args, OperationalStateStore(Path(args.state_dir))))
        print(json.dumps(result, sort_keys=True) if args.json else json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}) if args.json else f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
