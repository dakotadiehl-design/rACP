# Swift ↔ Python interoperability

Run the real-TCP bidirectional interoperability matrix from the repository root:

```sh
python3 tools/interoperability/run.py
```

The harness builds the repository's `RACPInteropPeer` executable and tests Swift as
both client and server against the Python reference. It covers HELLO, capabilities,
omitted versus explicit-null command arguments, canonical JSON whitespace and key
ordering, ACK, ERR, subscription state, revisions, PING/PONG, duplicate replay,
request-ID conflict, UNSUB, and BYE.
