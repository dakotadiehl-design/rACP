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
Sources/           Swift 6 ReasonableACP implementation and Network.framework adapter
Tests/             Swift codec, session, bounds, lifecycle, and transport tests
vectors/racp-v1/ canonical cross-language wire transcripts
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

The Swift package requires Swift 6 or newer:

```sh
swift test
python3 tools/interoperability/run.py
```

Add the repository as a Swift Package dependency and depend on the
`ReasonableACP` product. The portable core exposes `JSONValue`, `RACPMessage`,
`RACPLineDecoder`, `RACPSession`, and `RACPConnection`. Apple platforms also expose
`NetworkByteStream` and `RACPNetworkServer` for bounded plain-TCP connections.

Client applications can observe `connection.stateUpdates()`, await
`connection.waitUntilReady()`, and issue correlated requests with
`connection.command(_:arguments:timeout:)`, `subscribe`, and `unsubscribe`. Pending
requests are bounded and fail on timeout, cancellation, or disconnect. Hosts can use
`RACPNetworkServer`'s `connectionHandler` to retain ready-capable connections for
authoritative state publication.

Ordinary `send()` rejects CMD, SUB, and UNSUB messages with manual request IDs; use
the correlated high-level APIs instead. A request timeout or Swift task cancellation
only means the local caller stopped waiting. If TCP bytes were already sent, the peer
may still receive and execute the operation; rACP does not provide remote rollback or
cancellation.

Network.framework `.waiting` is treated as recoverable during startup because path
changes can resolve it. Startup remains bounded to five seconds; `.failed` and
`.cancelled` are terminal before readiness. Once connected, stream read/write errors
drive the ordinary rACP disconnection lifecycle.

The implementation is transport-independent above its byte-stream adapter. A future
TLS/TCP transport can wrap the same rACP messages without changing application
semantics.
