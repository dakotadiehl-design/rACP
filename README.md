# rACP — reasonable ACP

rACP is a deliberately small, plain-text control protocol for trusted or isolated
show-control networks. It provides capabilities, commands, authoritative state,
subscriptions, acknowledgements, structured errors, and bounded connection lifecycle
behavior over an ordered byte stream.

The v1 TCP transport provides **no confidentiality, peer authentication,
cryptographic integrity, or protection from a malicious reachable host**. Protect it
with appropriate VLANs, ACLs, firewalls, physical isolation, or a VPN.

## Start here

- [rACP v1 specification](docs/RACP_SPEC_V1.md)
- [Manual TCP test](docs/RACP_TCP_MANUAL_TEST.md)
- [Cross-language conformance plan](docs/RACP_CROSS_LANGUAGE.md)

## Repository layout

```text
docs/             normative specification and operational guidance
python/src/racp/  dependency-free Python reference implementation
python/tests/     parser, session, bounds, lifecycle, and TCP tests
vectors/racp-v1/ canonical wire transcripts for future implementations
```

## Test

Requires Python 3.11 or newer.

```sh
cd python
python3 -m pip install -e '.[dev]'
python3 -m pytest
python3 -m ruff check src tests
python3 -m mypy src/racp
```

The implementation is transport-independent above its byte-stream adapter. A future
TLS/TCP transport can wrap the same rACP messages without changing application
semantics.
