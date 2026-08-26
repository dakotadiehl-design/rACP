from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from acp.security import CredentialState, SecurityAdmissionError, bind_hello_auth
from acp.security_context import base64url_encode
from acp.security_models import SecurityProfile
from acp.security_transport import (
    FullTLSHandshake,
    LightweightFinishedInputs,
    full_transport_evidence,
    hello_exporter_context,
    lightweight_finished_context,
    parse_lightweight_preface,
    verify_lightweight_finished,
)
from acp.testkit import unsafe_full_tls_handshake_for_testing, unsafe_replace_security_value_for_testing

replace = unsafe_replace_security_value_for_testing

ROOT = Path(__file__).parents[2]


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    vector = json.loads((ROOT / "vectors/security/hello_binding/primary.json").read_text())
    hello = vector["semantic"]
    hello["auth"]["channel_binding"] = base64url_encode(b"e" * 32)
    return vector, hello


def facts():
    return unsafe_full_tls_handshake_for_testing(
        protocol="TLSv1.3",
        mutual_authentication=True,
        isolated_trust_store=True,
        peer_certificate_valid=True,
        local_credential_selected=True,
        peer_san_extracted=True,
        trust_domain_id="40516273-8495-4a6b-8a3b-4c5d6e7f8091",
        node_id="00112233-4455-4677-8899-aabbccddeeff",
        credential_id="sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20",
        identity_key_id="sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d",
        role_constraints=frozenset({"remote"}),
        credential_state=CredentialState.ACTIVE,
    )


def test_tls_facts_cannot_be_constructed_by_application_code() -> None:
    with pytest.raises(TypeError, match="_provenance"):
        FullTLSHandshake(protocol="TLSv1.3")  # type: ignore[call-arg]


def test_frozen_hello_projection_and_full_admission() -> None:
    vector, hello = fixture()
    assert hello_exporter_context(hello).hex() == vector["exporter_context_sha256_hex"]
    hello["capabilities"][0]["ignored"] = "not-projected"
    assert hello_exporter_context(hello).hex() == vector["exporter_context_sha256_hex"]
    evidence = full_transport_evidence(hello, facts(), lambda label, context, length: b"e" * 32)
    principal = bind_hello_auth(
        hello["node"]["node_id"],
        hello["auth"],
        evidence,
        hardened=True,
        security_capabilities=(("aurora-trust", "1.0"),),
    )
    assert principal.node_id == facts().node_id


@pytest.mark.parametrize(
    "change",
    (
        "protocol",
        "mutual_authentication",
        "isolated_trust_store",
        "peer_certificate_valid",
        "local_credential_selected",
        "peer_san_extracted",
        "zero_rtt_used",
        "resumption_used",
        "exporter",
    ),
)
def test_full_transport_fails_closed_without_every_fact(change: str) -> None:
    _, hello = fixture()
    current = facts()
    if change == "protocol":
        current = replace(current, protocol="TLSv1.2")
    elif change in {"zero_rtt_used", "resumption_used"}:
        current = replace(current, **{change: True})
    elif change != "exporter":
        current = replace(current, **{change: False})
    exporter = (lambda *_: b"x" * 32) if change == "exporter" else (lambda *_: b"e" * 32)
    with pytest.raises(SecurityAdmissionError):
        full_transport_evidence(hello, current, exporter)


def test_reconnect_revocation_and_stripped_claims_fail() -> None:
    _, hello = fixture()
    with pytest.raises(SecurityAdmissionError, match="revoked"):
        full_transport_evidence(hello, replace(facts(), credential_state=CredentialState.REVOKED), lambda *_: b"e" * 32)
    del hello["auth"]["identity_key_id"]
    with pytest.raises(SecurityAdmissionError):
        full_transport_evidence(hello, facts(), lambda *_: b"e" * 32)


def test_lightweight_preface_and_finished_are_bounded() -> None:
    _, hello = fixture()
    evidence = full_transport_evidence(hello, facts(), lambda *_: b"e" * 32)
    lightweight = replace(
        evidence, profile=SecurityProfile.LIGHTWEIGHT, credential_format="acp-compact-credential-v1"
    )
    credential = b"credential"
    parsed, raw = parse_lightweight_preface(len(credential).to_bytes(2, "big") + credential, lambda _: lightweight)
    assert parsed == lightweight and raw == credential
    key = b"k" * 32
    inputs = LightweightFinishedInputs(
        credential,
        credential,
        b"client-spki",
        b"server-spki",
        facts().node_id,
        facts().node_id,
        facts().trust_domain_id,
    )
    context = lightweight_finished_context(inputs)
    finished = hmac.new(key, context, hashlib.sha256).digest()
    verify_lightweight_finished(key, inputs, finished)
    with pytest.raises(SecurityAdmissionError):
        verify_lightweight_finished(key, inputs, b"x" * 32)
