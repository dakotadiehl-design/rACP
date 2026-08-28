"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import replace
from pathlib import Path

from .config import HarnessConfig, load_config
from .reporting import summary, write_report
from .runner import HarnessRunner


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Black-box Prism rACP integration tester")
    subparsers = result.add_subparsers(dest="action", required=True)
    test = subparsers.add_parser("test", help="run the configured integration suite")
    test.add_argument("--profile", type=Path, required=True)
    test.add_argument("--allow-state-changes", action="store_true")
    probe = subparsers.add_parser("probe", help="perform only HELLO and PING/PONG")
    probe.add_argument("--host", default="127.0.0.1")
    probe.add_argument("--port", type=int, default=9000)
    probe.add_argument("--timeout", type=float, default=5.0)
    probe.add_argument("--output-dir", type=Path, default=Path("prism-harness-results"))
    return result


async def _run(args: argparse.Namespace) -> int:
    if args.action == "test":
        config = load_config(args.profile)
        runner = HarnessRunner(config, allow_state_changes=args.allow_state_changes)
    else:
        config = replace(
            HarnessConfig(), host=args.host, port=args.port, timeout=args.timeout, output_dir=args.output_dir
        )
        config.validate()
        runner = HarnessRunner(config, probe_only=True)
    report = await runner.run()
    output = write_report(report, config.output_dir)
    print(summary(report))
    print(f"Artifacts: {output}")
    return 1 if report.failed else 0


def main() -> None:
    raise SystemExit(asyncio.run(_run(parser().parse_args())))


if __name__ == "__main__":
    main()
