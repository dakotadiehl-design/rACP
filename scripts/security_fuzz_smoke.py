"""Deterministic, reproducible smoke fuzzing for Aurora Trust parser boundaries."""

from __future__ import annotations

import random
import string

from acp.cbor_cde import decode
from acp.security_context import base64url_decode, canonical_enrollment_context
from acp.security_credentials import X509ValidationEvidence, validate_compact_credential
from acp.security_models import SecurityNodeID, TrustDomainID
from acp.security_transport import hello_exporter_context, parse_lightweight_preface

EXPECTED = (ValueError, TypeError, KeyError, UnicodeError)
DOMAIN = TrustDomainID("40516273-8495-4a6b-8a3b-4c5d6e7f8091")
NODE = SecurityNodeID("00112233-4455-4677-8899-aabbccddeeff")


def run(seed: int = 0xA0C, iterations: int = 2_000) -> None:
    rng = random.Random(seed)
    for _ in range(iterations):
        raw = rng.randbytes(rng.randrange(0, 4097))
        text = "".join(
            rng.choice(string.printable) for _ in range(rng.randrange(0, 257))
        )
        for operation in (
            lambda raw=raw: decode(raw),
            lambda text=text: base64url_decode(text),
            lambda raw=raw: parse_lightweight_preface(raw, lambda _: None),  # type: ignore[arg-type]
            lambda raw=raw: validate_compact_credential(
                raw,
                expected_domain=DOMAIN,
                expected_node=NODE,
                now=__import__("datetime").datetime.now(__import__("datetime").UTC),
                verifier=lambda *_: False,
                revoked=lambda _: False,
                possession_valid=False,
                allowed_roles=frozenset(),
            ),
            lambda raw=raw, text=text: hello_exporter_context(
                {"node": text, "protocol": raw, "auth": None}
            ),
            lambda text=text: canonical_enrollment_context({text: text}),
        ):
            try:
                operation()
            except EXPECTED:
                pass
        facts = [bool(rng.getrandbits(1)) for _ in range(15)]
        try:
            X509ValidationEvidence(*facts).require_valid()
        except EXPECTED:
            pass


if __name__ == "__main__":
    run()
    print("security fuzz smoke ok: seed=0xA0C iterations=2000")
