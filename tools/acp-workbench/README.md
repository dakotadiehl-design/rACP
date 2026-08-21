# ACP Workbench

ACP Workbench is a black-box ACP interoperability and conformance tester. It has a headless CLI for automation and an optional PySide6 GUI using the same engine.

It does **not** drive production hardware or treat a socket write/command acknowledgement as authoritative state. Confirmed state comes only from target-published ACP state.

## Development install

From the repository root:

```bash
python3 -m pip install -e './python' -e './tools/acp-workbench[dev,yaml]'
```

Add `gui` to install the desktop UI:

```bash
python3 -m pip install -e './tools/acp-workbench[gui]'
```

## Commands

```bash
acp-workbench list profiles
acp-workbench list scenarios
acp-workbench validate tools/acp-workbench/scenarios
acp-workbench connect --target ws://127.0.0.1:27421/acp --allow-plaintext
acp-workbench test --target ws://127.0.0.1:27421/acp --suite remote-prism --allow-plaintext
acp-workbench gui
```

Non-loopback targets require `--allow-live-target`. Operations tagged `live_show_unsafe` also require `--i-understand-this-is-not-a-live-show`.

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), [SCENARIOS.md](SCENARIOS.md),
[FEATURE_COVERAGE.md](FEATURE_COVERAGE.md), and [ARCHITECTURE.md](ARCHITECTURE.md).

Targets may use `ws://`, `wss://`, `tcp://`, or `acp+tcp://`. Framed TCP and plaintext WebSocket require `--allow-plaintext`. For TLS, use `--ca-file`; add `--cert-file` and `--key-file` for mutual TLS.
