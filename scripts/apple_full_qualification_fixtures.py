#!/usr/bin/env python3
"""Generate isolated synthetic ACP Full-profile identities for Apple qualification."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DOMAIN = "40516273-8495-4a6b-8a3b-4c5d6e7f8091"
HOST = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CLIENT = "00112233-4455-4677-8899-aabbccddeeff"
PASSWORD = b"aurora-synthetic-qualification"


def issue(output: Path, host_label: str) -> None:
    now = datetime.now(UTC)
    ca_key = ec.derive_private_key(0x23456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1, ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aurora S10 Synthetic CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(0x102030405060708090A0B0C0D0E0F101)
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    output.mkdir(parents=True, exist_ok=True)
    (output / "root.der").write_bytes(ca.public_bytes(serialization.Encoding.DER))
    for name, node, serial in [
        ("host", HOST, 0x112233445566778899AABBCCDDEEFF00),
        ("client", CLIENT, 0x2233445566778899AABBCCDDEEFF0011),
    ]:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Aurora S10 {name}")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(serial)
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
                .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                    f"urn:aurora:acp:node:{DOMAIN}:{node}")]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        bundle = pkcs12.serialize_key_and_certificates(
            (host_label if name == "host" else name).encode(), key, cert, [ca],
            serialization.BestAvailableEncryption(PASSWORD))
        (output / f"{name}.p12").write_bytes(bundle)
    (output / "manifest.json").write_text(json.dumps({"domain": DOMAIN, "host": HOST, "client": CLIENT,
                                                        "password": PASSWORD.decode(),
                                                        "host_label": host_label}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--host-label", required=True)
    args = parser.parse_args()
    issue(args.output, args.host_label)
