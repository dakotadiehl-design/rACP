#!/usr/bin/env python3
"""Generate and validate provider-independent Aurora Trust M0 vectors.

Generation is deliberately separate from every production SDK.  Private keys and
secrets here are synthetic fixtures and MUST NOT be reused outside tests.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import shutil
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "security"
PROFILE = "ACP-Aurora-Trust-1.0-Candidate-Freeze-2.1.1"
SUITE = "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1"
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (GX, GY)
IDENTITY_SCALAR = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF
ISSUER_SCALAR = 0x23456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1
M_COMPRESSED = bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
N_COMPRESSED = bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def cde(value: Any) -> bytes:
    return cbor2.dumps(value, canonical=True)


def hx(data: bytes) -> str:
    return data.hex()


def tagged_time(value: str) -> cbor2.CBORTag:
    return cbor2.CBORTag(0, value)


def le64(value: int) -> bytes:
    return struct.pack("<Q", value)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def inv(value: int, modulus: int = P) -> int:
    return pow(value, -1, modulus)


def add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = ((3 * x1 * x1 + A) * inv(2 * y1)) % P if left == right else ((y2 - y1) * inv(x2 - x1)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def decompress(encoded: bytes) -> tuple[int, int]:
    x = int.from_bytes(encoded[1:], "big")
    y = pow((x * x * x + A * x + B) % P, (P + 1) // 4, P)
    if y & 1 != encoded[0] & 1:
        y = P - y
    return x, y


def sec1(point: tuple[int, int] | None) -> bytes:
    assert point is not None
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def der_signature(private_scalar: int, digest: bytes) -> bytes:
    # RFC 6979 deterministic k, SHA-256, followed by mandatory low-S normalization.
    x = private_scalar.to_bytes(32, "big")
    h1 = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < N:
            break
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
    r = mul(nonce, G)[0] % N  # type: ignore[index]
    s = inv(nonce, N) * (int.from_bytes(digest, "big") + r * private_scalar) % N
    s = min(s, N - s)
    return utils.encode_dss_signature(r, s)


def key_material(scalar: int) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes, str]:
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    public = key.public_key()
    point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, point, spki, "sha256:" + sha(spki).hex()


def crockford_encode(raw: bytes) -> str:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = int.from_bytes(raw, "big")
    return "".join(alphabet[(value >> (5 * (25 - i))) & 31] for i in range(26))


def crockford_decode(text: str) -> bytes:
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    clean = "".join(c for c in text.upper() if c not in "- \t\r\n")
    if len(clean) != 26 or clean[0] not in "01234567" or any(c not in alphabet for c in clean):
        raise ValueError("invalid ACP RAW128 representation")
    value = 0
    for char in clean:
        value = (value << 5) | alphabet.index(char)
    return value.to_bytes(16, "big")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def artifact(category: str, vector_id: str, semantic: Any, binary: bytes | None = None) -> dict[str, Any]:
    base = OUT / category / vector_id
    semantic_path = base.with_suffix(".json")
    write_json(semantic_path, semantic)
    outputs = [str(semantic_path.relative_to(OUT))]
    if binary is not None:
        bin_path = base.with_suffix(".cbor")
        bin_path.write_bytes(binary)
        hex_path = base.with_suffix(".hex")
        hex_path.write_text(binary.hex() + "\n")
        outputs.extend([str(bin_path.relative_to(OUT)), str(hex_path.relative_to(OUT))])
    return {"id": f"{category}.{vector_id}", "category": category, "outputs": outputs}


def generate() -> None:
    # ECDSA certificate signatures are intentionally retained as fixed synthetic
    # validation fixtures; their deterministic TBSCertificate bytes are checked
    # separately. Rebuilding a certificate must be an explicit fixture rotation.
    fixed_x509 = None
    fixed_x509_path = OUT / "x509" / "full_profile.json"
    if fixed_x509_path.exists():
        fixed_x509 = json.loads(fixed_x509_path.read_text())
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    entries: list[dict[str, Any]] = []
    uuids = {
        "candidate_node_id": "00112233-4455-4677-8899-aabbccddeeff",
        "commissioner_node_id": "10213243-5465-4768-9a0b-1c2d3e4f5061",
        "candidate_instance_id": "20314253-6475-4869-aa1b-2c3d4e5f6071",
        "commissioner_instance_id": "30415263-7485-496a-ba2b-3c4d5e6f7081",
        "trust_domain_id": "40516273-8495-4a6b-8a3b-4c5d6e7f8091",
        "enrollment_id": "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1",
        "attempt_id": "60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1",
    }
    secrets = [bytes(16), bytes.fromhex("00ff807f0102030405060708090a0b0c"), b"\xff" * 16, b"\xa5" * 16]
    bootstrap_cases = []
    for index, secret in enumerate(secrets):
        encoded = crockford_encode(secret)
        assert crockford_decode(encoded) == secret
        bootstrap_cases.append({"id": index, "synthetic_secret": True, "raw_hex": hx(secret), "human": encoded})
    entries.append(
        artifact(
            "bootstrap",
            "raw128",
            {
                "cases": bootstrap_cases,
                "accepted_transform_example": "00-0G 40R4 0M30 E209 185G R38E1W",
                "rejections": [
                    "I0000000000000000000000000",
                    "O0000000000000000000000000",
                    "80000000000000000000000000",
                    "0000",
                ],
            },
        )
    )
    entries.append(
        artifact(
            "identity",
            "uuid_encodings",
            {
                "identifiers": {k: {"text": v, "rfc4122_hex": v.replace("-", "")} for k, v in uuids.items()},
                "registration_uses": "rfc4122_hex",
                "context_uses": "text",
            },
        )
    )

    secret = secrets[1]
    prover = bytes.fromhex(uuids["candidate_node_id"].replace("-", ""))
    verifier = bytes.fromhex(uuids["commissioner_node_id"].replace("-", ""))
    enrollment = bytes.fromhex(uuids["enrollment_id"].replace("-", ""))
    salt_input = b"ACP SPAKE2+ registration salt v1" + le64(16) + enrollment + le64(16) + prover + le64(16) + verifier
    salt = sha(salt_input)
    registration_input = le64(len(secret)) + secret + le64(16) + prover + le64(16) + verifier
    wbytes = hkdf(registration_input, salt, b"ACP SPAKE2+ RAW128 registration v1", 80)
    w0, w1 = int.from_bytes(wbytes[:40], "big") % N, int.from_bytes(wbytes[40:], "big") % N
    l_point = sec1(mul(w1, G))
    entries.append(
        artifact(
            "registration",
            "raw128_primary",
            {
                "synthetic_secret": True,
                "suite": SUITE,
                "password_hex": hx(secret),
                "idProver_hex": hx(prover),
                "idVerifier_hex": hx(verifier),
                "enrollment_id_hex": hx(enrollment),
                "salt_input_hex": hx(salt_input),
                "salt_hex": hx(salt),
                "registration_input_hex": hx(registration_input),
                "w_bytes_hex": hx(wbytes),
                "w0_hex": f"{w0:064x}",
                "w1_hex": f"{w1:064x}",
                "L_hex": hx(l_point),
            },
        )
    )

    # Deterministic ACP online run. Scalars are synthetic fixtures, never RNG examples.
    m_point, n_point = decompress(M_COMPRESSED), decompress(N_COMPRESSED)
    x = int.from_bytes(sha(b"ACP synthetic x Freeze 2.1.1"), "big") % N
    y = int.from_bytes(sha(b"ACP synthetic y Freeze 2.1.1"), "big") % N
    share_p = sec1(add(mul(x, G), mul(w0, m_point)))
    share_v = sec1(add(mul(y, G), mul(w0, n_point)))
    z = sec1(
        mul(x, add((int.from_bytes(share_v[1:33], "big"), int.from_bytes(share_v[33:], "big")), mul(N - w0, n_point)))
    )
    v = sec1(mul(w1, mul(y, G)))
    identity_private_scalar = IDENTITY_SCALAR
    identity_key, public_point, spki, identity_key_id = key_material(identity_private_scalar)
    empty_permissions = cde({})
    permission_digest = "sha256:" + sha(empty_permissions).hex()
    context = {
        "application": "Aurora Communications Protocol",
        "purpose": "security.enrollment",
        "extension_version": "1.0",
        "acp_version": "1.2",
        "suite": SUITE,
        **uuids,
        "requested_role": "remote",
        "requested_permissions_digest": permission_digest,
        "identity_algorithm": "ecdsa_p256_sha256",
        "identity_key_id": identity_key_id,
    }
    context_bytes = cde(context)

    def framed(value: bytes) -> bytes:
        return le64(len(value)) + value

    tt = b"".join(
        framed(item)
        for item in [
            context_bytes,
            prover,
            verifier,
            sec1(m_point),
            sec1(n_point),
            share_p,
            share_v,
            z,
            v,
            w0.to_bytes(32, "big"),
        ]
    )
    k_main = sha(tt)
    confirms = hkdf_expand(hkdf_extract(b"", k_main), b"ConfirmationKeys", 64)
    k_shared = hkdf_expand(hkdf_extract(b"", k_main), b"SharedKey", 32)
    confirm_p = hmac.new(confirms[:32], share_v, hashlib.sha256).digest()
    confirm_v = hmac.new(confirms[32:], share_p, hashlib.sha256).digest()
    entries.append(
        artifact(
            "spake2p",
            "acp_raw128_online",
            {
                "suite": SUITE,
                "M_compressed_hex": hx(M_COMPRESSED),
                "M_uncompressed_hex": hx(sec1(m_point)),
                "N_compressed_hex": hx(N_COMPRESSED),
                "N_uncompressed_hex": hx(sec1(n_point)),
                "x_hex": f"{x:064x}",
                "y_hex": f"{y:064x}",
                "shareP_hex": hx(share_p),
                "shareV_hex": hx(share_v),
                "Z_hex": hx(z),
                "V_hex": hx(v),
                "TT_hex": hx(tt),
                "K_main_hex": hx(k_main),
                "K_confirmP_hex": hx(confirms[:32]),
                "K_confirmV_hex": hx(confirms[32:]),
                "confirmP_hex": hx(confirm_p),
                "confirmV_hex": hx(confirm_v),
                "K_shared_hex": hx(k_shared),
                "point_encoding": "SEC1-uncompressed-65",
            },
        )
    )
    entries.append(
        artifact(
            "spake2p",
            "rfc9383_appendix_c_p256_sha256",
            {
                "source": "RFC 9383 Appendix C",
                "context_utf8": "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
                "w0_hex": "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
                "w1_hex": "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba",
                "shareP_hex": (
                    "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0"
                    "c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727"
                ),
                "shareV_hex": (
                    "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810"
                    "fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048"
                ),
                "confirmP_hex": "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527",
                "confirmV_hex": "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68",
                "K_shared_hex": "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7",
            },
        )
    )
    entries.append(
        artifact(
            "context",
            "primary",
            {
                "semantic": context,
                "canonical_cbor_hex": hx(context_bytes),
                "sha256_hex": hx(sha(context_bytes)),
                "closed_keys": sorted(context),
            },
            context_bytes,
        )
    )
    entries.append(
        artifact(
            "permissions",
            "empty_v1",
            {
                "semantic": {},
                "canonical_cbor_hex": hx(empty_permissions),
                "digest": permission_digest,
                "non_empty_expected": "FAIL security.permission_denied",
            },
            empty_permissions,
        )
    )
    transcript_semantic = [context_bytes, share_p, share_v, confirm_v, confirm_p]
    transcript_bytes = cde(transcript_semantic)
    transcript_hash = sha(transcript_bytes)
    entries.append(
        artifact(
            "transcript",
            "primary",
            {
                "items_hex": [hx(item) for item in transcript_semantic],
                "canonical_cbor_hex": hx(transcript_bytes),
                "sha256_hex": hx(transcript_hash),
            },
            transcript_bytes,
        )
    )
    root = hkdf_extract(transcript_hash, k_shared)
    labels = ["candidate confirm", "commissioner confirm", "approval AEAD", "SAS", "audit binding"]
    keys = {label: hkdf_expand(root, f"ACP enrollment {label} v1".encode(), 32) for label in labels}
    entries.append(
        artifact(
            "key_schedule",
            "primary",
            {
                "K_shared_hex": hx(k_shared),
                "transcript_hash_hex": hx(transcript_hash),
                "enrollment_root_hex": hx(root),
                "keys": {k: hx(v) for k, v in keys.items()},
                "construction": "RFC5869 Extract then Expand; direct UTF-8 info; not TLS Expand-Label",
            },
        )
    )

    credential = b"synthetic ACP Full credential fixture"
    authority = b"synthetic ACP trust anchor fixture"
    credential_id = "sha256:" + sha(credential).hex()
    approval_plain = {
        "trust_domain_id": uuids["trust_domain_id"],
        "trust_domain_name": "Vector Domain",
        "credential": credential,
        "credential_format": "x509_der",
        "authority_key_id": "sha256:" + sha(authority).hex(),
        "trust_anchor": authority,
        "role_constraints": [],
        "policy_id": "vector-policy",
        "policy_revision": 1,
        "not_before": tagged_time("2026-08-21T12:00:00Z"),
        "expires_at": tagged_time("2027-08-21T12:00:00Z"),
        "rotation_deadline": tagged_time("2027-07-21T12:00:00Z"),
        "commissioner_node_id": uuids["commissioner_node_id"],
        "transcript_hash": transcript_hash,
    }
    aad = {
        "message_type": "security.enrollment.approval",
        "attempt_id": uuids["attempt_id"],
        "enrollment_id": uuids["enrollment_id"],
        "candidate_node_id": uuids["candidate_node_id"],
        "commissioner_node_id": uuids["commissioner_node_id"],
        "trust_domain_id": uuids["trust_domain_id"],
        "acp_version": "1.2",
        "extension_version": "1.0",
        "suite": SUITE,
        "identity_algorithm": "ecdsa_p256_sha256",
        "identity_key_id": identity_key_id,
        "transcript_hash": transcript_hash,
    }
    nonce = bytes.fromhex("000102030405060708090a0b")
    sealed = AESGCM(keys["approval AEAD"]).encrypt(nonce, cde(approval_plain), cde(aad))
    entries.append(
        artifact(
            "approval",
            "primary",
            {
                "plaintext_cbor_hex": hx(cde(approval_plain)),
                "aad_cbor_hex": hx(cde(aad)),
                "key_hex": hx(keys["approval AEAD"]),
                "nonce_hex": hx(nonce),
                "ciphertext_hex": hx(sealed[:-16]),
                "tag_hex": hx(sealed[-16:]),
                "wire": {
                    "nonce_base64url": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(),
                    "ciphertext_base64url": base64.urlsafe_b64encode(sealed).rstrip(b"=").decode(),
                },
            },
        )
    )

    proof_digest = sha(b"ACP enrollment install proof v1" + transcript_hash + credential_id.encode())
    proof = der_signature(IDENTITY_SCALAR, proof_digest)
    install = {
        "attempt_id": uuids["attempt_id"],
        "status": "installed",
        "credential_id": credential_id,
        "identity_key_id": identity_key_id,
        "trust_domain_id": uuids["trust_domain_id"],
        "storage_posture": {"class": "os_protected", "hardware_backed": False, "private_key_exportable": False},
        "proof_of_possession": proof,
    }
    confirmation = hmac.new(keys["candidate confirm"], cde(install), hashlib.sha256).digest()
    entries.append(
        artifact(
            "installation",
            "primary",
            {
                "signed_digest_hex": hx(proof_digest),
                "proof_der_hex": hx(proof),
                "install_without_confirmation_cbor_hex": hx(cde(install)),
                "confirmation_hex": hx(confirmation),
                "public_spki_hex": hx(spki),
                "expected": "PASS",
            },
            cde({**install, "confirmation": confirmation}),
        )
    )
    entries.append(
        artifact(
            "identity",
            "p256_primary",
            {
                "synthetic_private_scalar_hex": f"{identity_private_scalar:064x}",
                "synthetic_secret": True,
                "public_point_hex": hx(public_point),
                "spki_der_hex": hx(spki),
                "identity_key_id": identity_key_id,
            },
        )
    )

    issuer_key, _, issuer_spki, issuer_key_id = key_material(ISSUER_SCALAR)
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    issuer_ski = sha(issuer_spki[-65:])[:20]
    subject_ski = sha(public_point)[:20]
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aurora Vector CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(issuer_key.public_key())
        .serial_number(0x102030405060708090A0B0C0D0E0F101)
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier(issuer_ski), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aurora Vector Node")])
    san = f"urn:aurora:acp:node:{uuids['trust_domain_id']}:{uuids['candidate_node_id']}"
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(name)
        .public_key(identity_key.public_key())
        .serial_number(0x112233445566778899AABBCCDDEEFF00)
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier(subject_ski), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier(issuer_ski, None, None), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    root_der, leaf_der = (
        root_cert.public_bytes(serialization.Encoding.DER),
        leaf_cert.public_bytes(serialization.Encoding.DER),
    )
    if fixed_x509 is not None:
        root_der = base64.b64decode(fixed_x509["root_der_base64"])
        leaf_der = base64.b64decode(fixed_x509["leaf_der_base64"])
    entries.append(
        artifact(
            "x509",
            "full_profile",
            {
                "root_der_base64": base64.b64encode(root_der).decode(),
                "leaf_der_base64": base64.b64encode(leaf_der).decode(),
                "root_tbs_sha256": hx(sha(x509.load_der_x509_certificate(root_der).tbs_certificate_bytes)),
                "leaf_tbs_sha256": hx(sha(x509.load_der_x509_certificate(leaf_der).tbs_certificate_bytes)),
                "leaf_credential_id": "sha256:" + sha(leaf_der).hex(),
                "san_uri": san,
                "eku": ["clientAuth", "serverAuth"],
                "key_usage": ["digitalSignature"],
                "subject_ski_hex": hx(subject_ski),
                "authority_ski_hex": hx(issuer_ski),
                "negative_cases": [
                    "wrong-node",
                    "wrong-domain",
                    "missing-client-eku",
                    "missing-server-eku",
                    "public-web-pki-anchor",
                ],
            },
        )
    )

    hello = {
        "node": {
            "node_id": uuids["candidate_node_id"],
            "instance_id": uuids["candidate_instance_id"],
            "role": "remote",
            "name": "Vector Remote",
        },
        "protocol": {"min": "1.2", "max": "1.2"},
        "encodings": ["cbor", "json"],
        "profiles": ["remote"],
        "capabilities": [{"id": "remote.view", "version": "1.0"}],
        "auth": {
            "mode": "aurora_trust",
            "trust_domain_id": uuids["trust_domain_id"],
            "credential_id": credential_id,
            "identity_key_id": identity_key_id,
            "security_capabilities": [{"id": "aurora-trust", "version": "1.0"}],
        },
    }
    hello_cbor = cde(hello)
    exporter_context = sha(hello_cbor)
    entries.append(
        artifact(
            "hello_binding",
            "primary",
            {
                "semantic": hello,
                "canonical_cbor_hex": hx(hello_cbor),
                "exporter_label_ascii": "EXPORTER-Aurora-ACP-1.2-HELLO",
                "exporter_context_sha256_hex": hx(exporter_context),
                "output_length": 32,
                "negative_cases": [
                    "wrong-node",
                    "wrong-domain",
                    "wrong-key-id",
                    "changed-profile",
                    "channel-binding-null",
                    "unknown-projected-field",
                ],
            },
            hello_cbor,
        )
    )

    compact_body = {
        "format": "acp-compact-credential-v1",
        "serial": 1,
        "trust_domain_id": uuids["trust_domain_id"],
        "node_id": uuids["candidate_node_id"],
        "identity_algorithm": "ecdsa_p256_sha256",
        "identity_public_key": spki,
        "role_constraints": ["remote"],
        "permission_policy_id": "vector-policy",
        "issued_at": tagged_time("2026-08-21T12:00:00Z"),
        "not_before": tagged_time("2026-08-21T11:58:00Z"),
        "expires_at": tagged_time("2027-08-21T12:00:00Z"),
        "issuer_key_id": issuer_key_id,
        "extensions": {"1.3.6.1.4.1.55555.1": {"critical": False, "value": b"vector"}},
    }
    compact_digest = sha(b"ACP compact credential v1" + cde(compact_body))
    compact_sig = der_signature(ISSUER_SCALAR, compact_digest)
    compact = {"body": compact_body, "algorithm": "ecdsa_p256_sha256", "signature": compact_sig}
    compact_bytes = cde(compact)
    entries.append(
        artifact(
            "compact_credential",
            "primary",
            {
                "body_cbor_hex": hx(cde(compact_body)),
                "signature_input_sha256_hex": hx(compact_digest),
                "signature_der_hex": hx(compact_sig),
                "credential_cbor_hex": hx(compact_bytes),
                "credential_id": "sha256:" + sha(compact_bytes).hex(),
            },
            compact_bytes,
        )
    )

    rev_body = {
        "format": "acp-revocation-snapshot-v1",
        "trust_domain_id": uuids["trust_domain_id"],
        "epoch": 7,
        "issued_at": tagged_time("2026-08-21T12:00:00Z"),
        "next_update": tagged_time("2026-08-22T12:00:00Z"),
        "entries": [
            {
                "credential_id": credential_id,
                "node_id": uuids["candidate_node_id"],
                "revoked_at": tagged_time("2026-08-21T11:30:00Z"),
                "reason": "key_compromise",
            }
        ],
        "issuer_key_id": issuer_key_id,
    }
    rev_digest = sha(b"ACP revocation state v1" + cde(rev_body))
    rev_sig = der_signature(ISSUER_SCALAR, rev_digest)
    rev = {"body": rev_body, "algorithm": "ecdsa_p256_sha256", "signature": rev_sig}
    entries.append(
        artifact(
            "revocation",
            "snapshot_epoch_7",
            {
                "body_cbor_hex": hx(cde(rev_body)),
                "signature_input_sha256_hex": hx(rev_digest),
                "signature_der_hex": hx(rev_sig),
                "snapshot_id": "sha256:" + sha(cde(rev)).hex(),
                "negative_cases": [
                    "epoch-rollback",
                    "same-epoch-replay",
                    "wrong-domain",
                    "bad-signature",
                    "duplicate-credential",
                    "unsorted-entries",
                ],
            },
            cde(rev),
        )
    )

    negative = [
        {"id": name, "expected": "FAIL", "mutation": name}
        for name in [
            "wrong-secret",
            "wrong-node",
            "wrong-domain",
            "wrong-role",
            "wrong-instance",
            "wrong-key",
            "wrong-permission-digest",
            "wrong-suite",
            "wrong-version",
            "malformed-point",
            "reflected-confirmation",
            "replayed-approval",
            "wrong-aad",
            "wrong-nonce",
            "wrong-tag",
            "ciphertext-transplant",
            "malformed-credential",
            "revoked-credential",
            "future-credential",
            "revocation-rollback",
            "invalid-base32",
            "null-instead-of-absent",
            "unknown-context-field",
        ]
    ]
    entries.append(artifact("negative", "mutations", {"vectors": negative}))

    hashes_map: dict[str, str] = {}
    for path in sorted(OUT.rglob("*")):
        if path.is_file():
            hashes_map[str(path.relative_to(OUT))] = sha(path.read_bytes()).hex()
    manifest = {
        "profile": PROFILE,
        "freeze": "2.1.1",
        "synthetic_test_material_only": True,
        "provider_independent": True,
        "normative": True,
        "vectors": entries,
        "files_sha256": hashes_map,
    }
    write_json(OUT / "manifest.json", manifest)


def validate() -> None:
    manifest = json.loads((OUT / "manifest.json").read_text())
    assert manifest["profile"] == PROFILE and manifest["synthetic_test_material_only"] is True
    ids = [item["id"] for item in manifest["vectors"]]
    assert len(ids) == len(set(ids)), "duplicate vector ID"
    for relative, expected in manifest["files_sha256"].items():
        path = OUT / relative
        assert path.is_file() and sha(path.read_bytes()).hex() == expected, relative
    for path in OUT.rglob("*.cbor"):
        raw = path.read_bytes()
        assert cde(cbor2.loads(raw)) == raw, f"noncanonical CBOR: {path}"
    bootstrap = json.loads((OUT / "bootstrap" / "raw128.json").read_text())
    for case in bootstrap["cases"]:
        assert crockford_decode(case["human"]) == bytes.fromhex(case["raw_hex"])
    registration = json.loads((OUT / "registration" / "raw128_primary.json").read_text())
    assert "00" in registration["password_hex"] and registration["synthetic_secret"]
    approval = json.loads((OUT / "approval" / "primary.json").read_text())
    AESGCM(bytes.fromhex(approval["key_hex"])).decrypt(
        bytes.fromhex(approval["nonce_hex"]),
        bytes.fromhex(approval["ciphertext_hex"] + approval["tag_hex"]),
        bytes.fromhex(approval["aad_cbor_hex"]),
    )
    install = json.loads((OUT / "installation" / "primary.json").read_text())
    r, s = utils.decode_dss_signature(bytes.fromhex(install["proof_der_hex"]))
    assert 1 <= r < N and 1 <= s <= N // 2
    pub = serialization.load_der_public_key(bytes.fromhex(install["public_spki_hex"]))
    pub.verify(
        bytes.fromhex(install["proof_der_hex"]),
        bytes.fromhex(install["signed_digest_hex"]),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    x509_vector = json.loads((OUT / "x509" / "full_profile.json").read_text())
    for field in ("root_der_base64", "leaf_der_base64"):
        certificate = x509.load_der_x509_certificate(base64.b64decode(x509_vector[field]))
        _, cert_s = utils.decode_dss_signature(certificate.signature)
        assert cert_s <= N // 2, f"high-S certificate: {field}"
    print(f"security vectors ok: {len(ids)} vector sets, {len(manifest['files_sha256'])} hashed artifacts")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        generate()
    validate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
