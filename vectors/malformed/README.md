# Shared non-canonical / malformed CBOR corpus

Every SDK decoder must reject these files. They are not envelopes — they are
hostile or non-canonical CBOR items used as a shared parser corpus.

| File | Reason |
|---|---|
| `indefinite_array.cbor` | Indefinite-length array |
| `indefinite_map.cbor` | Indefinite-length map |
| `nonpreferred_int.cbor` | Additional info 24 for value < 24 |
| `tag1_datetime.cbor` | CBOR tag 1 (forbidden) |
| `truncated.cbor` | Truncated map |
| `oversized_len.cbor` | Array length above the shared item cap |
