# acp (Python)

Python 3.11+ reference SDK for the Aurora Communications Protocol.

This package is the reference encoder for ACP-CDE-1.2 golden vectors, the home of `acp-inspect` / `acp-sim`, and the **only amendment-conformant production Remote authority** (`RemoteHost` + `RemoteAuthority`). The Rust and Swift packages ship codecs, models, and non-production Remote simulators.

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest
```
