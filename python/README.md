# racp

Dependency-free Python 3.11+ reference implementation of rACP v1.

```sh
python3 -m pip install -e '.[dev]'
python3 -m pytest
```

The package provides strict message parsing and encoding, a transport-independent
session core, and a bounded asyncio plain-TCP adapter. See the repository's
[`docs/RACP_SPEC_V1.md`](../docs/RACP_SPEC_V1.md) for the wire protocol and trust model.
