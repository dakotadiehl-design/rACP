# Aurora Trust Full-profile provider qualification

This M0-only tool tests Candidate Freeze 2.1.1 against the selected Botan
3.13.0 provider. It is not production Trust implementation. Run:

```sh
.venv/bin/python tools/security-probe/run.py
```

The runner exits nonzero until every mandatory probe passes. `NOT_RUN` is an
explicit qualification failure, never an inferred pass. Results contain no
live secrets; all inputs come from the synthetic security-vector corpus.

The report separates `provider_crypto_qualified` from each
`platform_adapter_qualified` result. A core Botan PASS never implies that a
platform TLS/exporter adapter passed, and one platform cannot qualify another.

## iOS Simulator

`ios_simulator_run.py` compiles and executes the provider probes as genuine
`arm64-apple-ios16.0-simulator` processes. It requires a Botan 3.13.0 static
build configured for the iPhoneSimulator SDK; the Homebrew macOS bottle is not
compatible and must not be substituted.

Example after configuring/building Botan into `/tmp/acp-botan-ios-build`:

```sh
.venv/bin/python tools/security-probe/ios_simulator_run.py \
  --device SIMULATOR_UDID \
  --botan-build /tmp/acp-botan-ios-build
```

The runner writes `results/ios-simulator-arm64-botan-3.13.0.json`. A nonzero
exit is expected while any mandatory Simulator-applicable probe is FAIL or
NOT_RUN. Simulator evidence never qualifies a physical iOS device or Secure
Enclave.
