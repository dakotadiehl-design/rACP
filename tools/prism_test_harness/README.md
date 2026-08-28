# Prism rACP test harness

This directory contains a black-box Python integration tester for Prism's rACP TCP
endpoint. It does not import Prism, edit Prism, or alter either rACP implementation.
Valid messages and HELLO validation use the existing Python reference package; malformed
tests deliberately use raw disposable TCP connections.

Use this only against a disposable Prism instance on a trusted or isolated network.
rACP v1 is plaintext and authenticates nobody. The malformed and overlong-line tests
intentionally make Prism close individual connections.

## Install and run

From the rACP repository root, install both local packages in a virtual environment:

```sh
python3 -m venv .venv-prism-harness
.venv-prism-harness/bin/pip install -e ./python -e './tools/prism_test_harness[dev]'
```

Perform a read-only connectivity probe:

```sh
.venv-prism-harness/bin/prism-racp-test probe --host 127.0.0.1 --port 9000
```

Copy and edit `example.prism.toml`, then run the integration suite:

```sh
.venv-prism-harness/bin/prism-racp-test test --profile prism-test.toml
```

Commands marked `state_changing = true` are skipped unless explicitly enabled:

```sh
.venv-prism-harness/bin/prism-racp-test test \
  --profile prism-test.toml --allow-state-changes
```

Each run writes `report.json`, `wire.log`, and CI-compatible `junit.xml` to a new
timestamped directory. The wire log contains protocol payloads, so command values must
not contain secrets.

## Profile behavior

- `required_capabilities` are hard requirements.
- Configured commands absent from Prism's advertised capabilities are skipped.
- `expected = "ack"` expects success; any valid error name can be used instead.
- Every configured command checks identical duplicate replay and conflicting ID reuse.
- A subscription can require an initial authoritative `STATE` with `expect_initial`.
- `malformed_tests = false` disables CRLF, invalid HELLO, unknown verb, and overlong-line tests.

TOML cannot directly represent JSON `null`, so profiles may set `value_json = "null"`.
`value_json` accepts any strict JSON value and cannot be combined with `value`. This also
makes it possible to test omitted values and explicit null as distinct requests.

## Harness self-tests

The tests use a disposable reference-backed fake Prism and never require the Prism app:

```sh
PYTHONPATH=python/src:tools/prism_test_harness \
  python3 -m pytest tools/prism_test_harness/tests
```

The harness currently targets Prism acting as the TCP server, which is the integration
shape observable from this repository. If Prism is configured as a TCP client, add a
listener adapter inside this harness directory; no protocol or Prism changes are needed.
