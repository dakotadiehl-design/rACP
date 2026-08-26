from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from acp.cbor_cde import decode, encode

atoms = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.text(max_size=40),
    st.binary(max_size=40),
)

jsonish = st.recursive(
    atoms,
    lambda children: st.lists(children, max_size=6) | st.dictionaries(st.text(max_size=16), children, max_size=6),
    max_leaves=20,
)


@given(jsonish)
@settings(max_examples=80, deadline=None)
def test_cde_roundtrip_is_deterministic(value: object) -> None:
    raw = encode(value)
    again = decode(raw)
    assert again == value
    assert encode(again) == raw
