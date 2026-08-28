import asyncio
from pathlib import Path

from fake_prism import FakePrism

from prism_harness.config import CommandCase, HarnessConfig
from prism_harness.model import Status
from prism_harness.reporting import write_report
from prism_harness.runner import HarnessRunner


def test_full_black_box_suite_and_reports(tmp_path: Path) -> None:
    async def body() -> None:
        prism = FakePrism()
        await prism.start()
        try:
            config = HarnessConfig(
                port=prism.port,
                expected_peer_type="device",
                expected_peer_id="fake-prism",
                required_capabilities=("cue.go",),
                timeout=1,
                output_dir=tmp_path,
                commands=(CommandCase("cue.go"),),
            )
            report = await HarnessRunner(config).run()
        finally:
            await prism.stop()

        assert not report.failed, [(item.name, item.detail) for item in report.results]
        assert all(item.status is Status.PASS for item in report.results)
        # Identical replay and conflicting ID reuse must not redispatch the command.
        assert len(prism.commands) == 1
        output = write_report(report, tmp_path)
        assert (output / "report.json").is_file()
        assert (output / "wire.log").is_file()
        assert (output / "junit.xml").is_file()

    asyncio.run(body())


def test_state_changing_commands_require_opt_in() -> None:
    async def body() -> None:
        prism = FakePrism()
        await prism.start()
        try:
            config = HarnessConfig(
                port=prism.port,
                timeout=1,
                malformed_tests=False,
                commands=(CommandCase("cue.go", state_changing=True),),
            )
            report = await HarnessRunner(config).run()
        finally:
            await prism.stop()
        command = next(item for item in report.results if item.name == "command cue.go")
        assert command.status is Status.SKIP
        assert not prism.commands

    asyncio.run(body())


def test_failed_handshake_stops_dependent_scenarios() -> None:
    config = HarnessConfig(port=1, timeout=0.05, malformed_tests=False)
    report = asyncio.run(HarnessRunner(config).run())
    assert len(report.results) == 1
    assert report.results[0].status is Status.FAIL

