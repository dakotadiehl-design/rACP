# Adding a message type

Status: **Current contributor guide**

1. Add or extend a JSON Schema under `schema/<family>/`.
2. Add a row to `scripts/gen_registry.py` and run `python3 scripts/gen_registry.py`.
3. Run `python3 scripts/check_registry.py`.
4. Add golden vectors under `vectors/json/<type>/` and freeze CBOR with `python3 scripts/freeze_vectors.py --regen` (explicit flag required).
5. Register the type in each SDK decoder/registry. Do not overload an existing type with a new payload meaning.
6. Experimental / vendor types use `x.<organization>.<name>`.

Schema conformance is mandatory. Language APIs may be idiomatic.
