from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .config import enforce_target_safety, from_environment
from .engine import WorkbenchEngine
from .models import ConnectionConfig, RunResult, utc_now_text
from .profiles import PROFILE_TYPES
from .reports import console_summary, write_json, write_junit
from .scenarios import discover_scenarios, load_scenario
from .transcript import TranscriptWriter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acp-workbench")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="list profiles or scenarios")
    listing.add_argument("kind", choices=["profiles", "scenarios"])
    listing.add_argument("--path", default=str(Path(__file__).parents[2] / "scenarios"))

    validate = sub.add_parser("validate", help="validate scenario files")
    validate.add_argument("path")

    for name in ("connect", "send", "test"):
        command = sub.add_parser(name)
        command.add_argument("--target", required=True)
        command.add_argument("--profile", default="remote-prism", choices=sorted(PROFILE_TYPES))
        command.add_argument("--allow-plaintext", action="store_true")
        command.add_argument("--allow-live-target", action="store_true")
        command.add_argument("--timeout", type=float, default=5.0)
        command.add_argument("--transcript")
        command.add_argument("--node-id")
        command.add_argument("--instance-id")
        command.add_argument("--ca-file")
        command.add_argument("--cert-file")
        command.add_argument("--key-file")
        if name == "connect":
            command.add_argument("--duration", type=float, default=0.0, help="seconds; 0 waits until interrupted")
        elif name == "send":
            command.add_argument("file", help="decoded ACP envelope JSON file")
            command.add_argument("--wait", type=float, default=0.25, help="seconds to observe replies")
        else:
            command.add_argument("paths", nargs="*")
            command.add_argument("--suite", choices=["remote-prism"])
            command.add_argument("--report-json")
            command.add_argument("--report-junit")
            command.add_argument("--fail-fast", action="store_true")
            command.add_argument("--i-understand-this-is-not-a-live-show", action="store_true", dest="unsafe")

    sub.add_parser("gui", help="launch the optional PySide6 GUI")
    return parser


def _config(args: argparse.Namespace) -> ConnectionConfig:
    return from_environment(ConnectionConfig(
        target=args.target,
        profile=args.profile,
        allow_plaintext=args.allow_plaintext,
        timeout=args.timeout,
        ca_file=args.ca_file,
        cert_file=args.cert_file,
        key_file=args.key_file,
        node_id=args.node_id,
        instance_id=args.instance_id,
    ))


async def _connect(args: argparse.Namespace) -> int:
    engine = None
    try:
        enforce_target_safety(args.target, allow_live_target=args.allow_live_target)
        transcript = TranscriptWriter(args.transcript) if args.transcript else None
        engine = WorkbenchEngine(transcript=transcript)
        conn = await engine.connect(_config(args))
        print(json.dumps({
            "state": conn.state.value,
            "session_id": conn.session.session_id if conn.session else None,
            "node_id": conn.profile.node.node_id,
            "actions": [asdict(action) for action in conn.profile.actions()],
        }, indent=2))
        if args.duration > 0:
            await asyncio.sleep(args.duration)
        else:
            await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 5
    except (ConnectionError, TimeoutError) as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    finally:
        if engine:
            await engine.close()
    return 0


async def _send(args: argparse.Namespace) -> int:
    from acp.envelope import Envelope

    try:
        enforce_target_safety(args.target, allow_live_target=args.allow_live_target)
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        envelope = Envelope.from_dict(data)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 5
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    transcript = TranscriptWriter(args.transcript) if args.transcript else None
    engine = WorkbenchEngine(transcript=transcript)
    try:
        connection = await engine.connect(_config(args))
        await connection.send(envelope)
        await asyncio.sleep(max(0, args.wait))
        for event in engine.history:
            if event.kind == "envelope.in":
                print(json.dumps(event.data["envelope"], separators=(",", ":"), default=str))
    except (ConnectionError, TimeoutError) as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    finally:
        await engine.close()
    return 0


def _scenario_paths(args: argparse.Namespace) -> list[Path]:
    paths = [Path(item) for item in args.paths]
    if args.suite:
        paths.append(Path(__file__).parents[2] / "scenarios" / args.suite)
    return [item for path in paths for item in discover_scenarios(path)]


async def _test(args: argparse.Namespace) -> int:
    try:
        enforce_target_safety(args.target, allow_live_target=args.allow_live_target)
        scenarios = [load_scenario(path) for path in _scenario_paths(args)]
        if not scenarios:
            raise ValueError("no scenarios selected")
        if any("live_show_unsafe" in scenario.tags for scenario in scenarios) and not args.unsafe:
            raise PermissionError("suite includes live_show_unsafe scenarios; pass the explicit acknowledgement flag")
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 5
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    from .scenarios import ScenarioRunner

    transcript = TranscriptWriter(args.transcript) if args.transcript else None
    engine = WorkbenchEngine(transcript=transcript)
    started_text, started = utc_now_text(), time.monotonic()
    results = []
    try:
        runner = ScenarioRunner(engine)
        for scenario in scenarios:
            config = _config(args)
            result = await runner.run(scenario, config)
            results.append(result)
            if args.fail_fast and not result.passed:
                break
    finally:
        await engine.close()
    run = RunResult(
        passed=all(item.passed for item in results),
        scenarios=results,
        started_at=started_text,
        duration_s=time.monotonic() - started,
        metadata={"workbench_version": __version__, "target": args.target},
    )
    print(console_summary(run))
    if args.report_json:
        write_json(run, args.report_json)
    if args.report_junit:
        write_junit(run, args.report_junit)
    return 0 if run.passed else 1


def _validate(path: str) -> int:
    try:
        files = discover_scenarios(path)
        if not files:
            raise ValueError("no scenario files found")
        for file in files:
            scenario = load_scenario(file)
            print(f"OK {file}: {scenario.id}")
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        if args.kind == "profiles":
            for profile_id, cls in PROFILE_TYPES.items():
                print(f"{profile_id}\t{cls.display_name}")
        else:
            for path in discover_scenarios(args.path):
                try:
                    scenario = load_scenario(path)
                    print(f"{scenario.id}\t{scenario.name}")
                except Exception as exc:
                    print(f"INVALID {path}: {exc}", file=sys.stderr)
                    return 2
        return 0
    if args.command == "validate":
        return _validate(args.path)
    if args.command == "connect":
        return asyncio.run(_connect(args))
    if args.command == "send":
        return asyncio.run(_send(args))
    if args.command == "test":
        return asyncio.run(_test(args))
    if args.command == "gui":
        try:
            from .gui import run_gui
        except ImportError as exc:
            print("GUI requires: pip install 'aurora-acp-workbench[gui]'", file=sys.stderr)
            print(exc, file=sys.stderr)
            return 2
        return run_gui()
    return 2
