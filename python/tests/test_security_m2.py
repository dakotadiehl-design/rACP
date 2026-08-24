from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path

import pytest

from acp.security_context import (
    base64url_decode,
    base64url_encode,
    canonical_enrollment_context,
    canonical_transcript,
    channel_bindings_equal,
    derive_enrollment_keys,
    digest_id,
    permission_digest,
    sha256,
)
from acp.security_models import DowngradePolicy
from acp.security_secrets import SecretBytes

ROOT = Path(__file__).parents[2]


def vector(path: str) -> dict[str, object]:
    return json.loads((ROOT / "vectors/security" / path).read_text())


def test_frozen_context_transcript_key_schedule_and_ids() -> None:
    context = vector("context/primary.json")
    context_bytes = canonical_enrollment_context(context["semantic"])
    assert context_bytes.hex() == context["canonical_cbor_hex"]
    assert sha256(context_bytes).hex() == context["sha256_hex"]

    transcript = vector("transcript/primary.json")
    items = [bytes.fromhex(value) for value in transcript["items_hex"]]
    transcript_bytes = canonical_transcript(items)
    assert transcript_bytes.hex() == transcript["canonical_cbor_hex"]
    assert sha256(transcript_bytes).hex() == transcript["sha256_hex"]

    schedule = vector("key_schedule/primary.json")
    keys = derive_enrollment_keys(
        bytes.fromhex(schedule["K_shared_hex"]), bytes.fromhex(schedule["transcript_hash_hex"])
    )
    assert {label: value.hex() for label, value in keys.items()} == schedule["keys"]

    identity = vector("identity/p256_primary.json")
    assert digest_id(bytes.fromhex(identity["spki_der_hex"])) == identity["identity_key_id"]
    assert permission_digest({}) == "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"


def test_normalization_binding_and_closed_context_reject_mutations() -> None:
    fixture = bytes(range(32))
    assert base64url_decode(base64url_encode(fixture)) == fixture
    for malformed in ("", "AA==", "!!", "AB"):
        with pytest.raises(ValueError):
            base64url_decode(malformed)
    assert channel_bindings_equal(fixture, fixture)
    assert not channel_bindings_equal(fixture, fixture[:-1] + b"x")
    with pytest.raises(ValueError):
        canonical_enrollment_context({})
    with pytest.raises(ValueError):
        canonical_transcript([b"x"] * 4)


def test_secrets_are_redacted_and_not_diagnostic_serializable(caplog: pytest.LogCaptureFixture) -> None:
    fixture = bytes.fromhex("c0ffee" * 10 + "c0ff")
    secret = SecretBytes(fixture, label="fixture")
    assert fixture.hex() not in repr(secret)
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with caplog.at_level(logging.INFO):
        logging.info("secret=%r", secret)
    assert fixture.hex() not in caplog.text


def test_downgrade_policy_never_falls_back_after_stronger_attempt() -> None:
    assert not DowngradePolicy.hardened_production().permits_unauthenticated(stronger_auth_attempted=False)
    migration = DowngradePolicy.migration(allow_trusted_lan=True)
    assert migration.permits_unauthenticated(stronger_auth_attempted=False)
    assert not migration.permits_unauthenticated(stronger_auth_attempted=True)
