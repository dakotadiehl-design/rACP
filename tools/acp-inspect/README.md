# acp-inspect

```bash
python3 -m acp inspect path/to/envelope.json
python3 -m acp inspect path/to/envelope.cbor
```

Replay of captures against a live show is refused unless you pass
`--i-understand-this-is-not-a-live-show` on `acp sim`.

Aurora Trust inspection exposes only protocol-safe metadata such as node, trust-domain,
credential/key IDs, suite, capability, and authentication state. PAKE shares and
confirmations, channel bindings, encrypted credential offers, signatures, credential
bodies, and key material are sensitive and must remain redacted in output and captures.
