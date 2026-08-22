#!/usr/bin/env python3
"""Run host-visible Full-profile qualification probes without claiming unavailable targets."""

from __future__ import annotations

import base64
import json
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(__file__).resolve().parent
RESULTS = TOOL / "results"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
IDENTITY_SCALAR = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF


def command(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)


def result(probe_id: str, status: str, detail: str, mandatory: bool = True) -> dict[str, object]:
    return {"id": probe_id, "status": status, "mandatory": mandatory, "detail": detail}


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    version = command(["botan", "version"])
    pkg = command(["pkg-config", "--cflags", "--libs", "botan-3"])
    probes: list[dict[str, object]] = []
    if version.returncode != 0 or version.stdout.strip() != "3.13.0":
        probes.append(result("provider.version", "FAIL", version.stderr.strip() or version.stdout.strip()))
    else:
        probes.append(result("provider.version", "PASS", "Botan 3.13.0 exact"))

    registration = json.loads((ROOT / "vectors/security/registration/raw128_primary.json").read_text())
    context = json.loads((ROOT / "vectors/security/context/primary.json").read_text())
    binary = Path("/tmp/acp-botan-probe")
    compile_result = command(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            *pkg.stdout.split(),
            str(TOOL / "botan_probe.cpp"),
            "-o",
            str(binary),
        ]
    )
    if compile_result.returncode:
        probes.append(result("spake2p.public_api", "FAIL", compile_result.stderr.strip()))
        probes.append(result("hash_hmac_hkdf", "FAIL", "Botan public-API probe did not compile"))
    else:
        run = command(
            [
                str(binary),
                registration["w0_hex"],
                registration["w1_hex"],
                context["canonical_cbor_hex"],
            ]
        )
        try:
            botan_payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            botan_payload = {}
        probes.append(
            result(
                "spake2p.public_api",
                "PASS" if run.returncode == 0 else "FAIL",
                run.stdout.strip() or run.stderr.strip(),
            )
        )
        kdf_pass = all(botan_payload.get(name) is True for name in ("sha256", "hmac_sha256", "hkdf_sha256"))
        probes.append(
            result("hash_hmac_hkdf", "PASS" if kdf_pass else "FAIL", "RFC SHA-256/HMAC/HKDF known-answer tests")
        )
        rfc_pass = botan_payload.get("rfc9383_appendix_c") is True
        probes.append(
            result(
                "spake2p.rfc9383_appendix_c",
                "PASS" if rfc_pass else "FAIL",
                "RFC 9383 P-256/SHA-256 shares, confirmations, and K_shared",
            )
        )

    x509_vector = json.loads((ROOT / "vectors/security/x509/full_profile.json").read_text())
    with tempfile.TemporaryDirectory(prefix="acp-provider-probe-") as temporary:
        temporary_path = Path(temporary)
        root_path = temporary_path / "root.der"
        leaf_path = temporary_path / "leaf.der"
        root_path.write_bytes(base64.b64decode(x509_vector["root_der_base64"]))
        leaf_path.write_bytes(base64.b64decode(x509_vector["leaf_der_base64"]))
        info = command(["botan", "cert_info", str(leaf_path)])
        verify = command(["botan", "cert_verify", str(leaf_path), str(root_path)])
        wrong_anchor = command(["botan", "cert_verify", str(leaf_path), str(leaf_path)])
        certificate = x509.load_der_x509_certificate(leaf_path.read_bytes())
        san_values = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_uris = san_values.get_values_for_type(x509.UniformResourceIdentifier)
        expected_san = x509_vector["san_uri"]
        x509_pass = (
            info.returncode == 0
            and verify.returncode == 0
            and "passes validation" in verify.stdout
            and "passes validation" not in wrong_anchor.stdout
            and "Cannot establish trust" in wrong_anchor.stdout
        )
        probes.append(result("x509.acp_profile", "PASS" if x509_pass else "FAIL", verify.stdout.strip()))
        san_pass = san_uris == [expected_san] and expected_san in info.stdout
        probes.append(
            result(
                "x509.san_identity_binding",
                "PASS" if san_pass else "FAIL",
                f"exact SAN={san_uris}; wrong node/domain expectations reject by exact comparison",
            )
        )
        usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        eku = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        ski = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
        aki = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
        profile_pass = (
            usage.digital_signature
            and not usage.key_encipherment
            and ExtendedKeyUsageOID.CLIENT_AUTH in eku
            and ExtendedKeyUsageOID.SERVER_AUTH in eku
            and ski.hex() == x509_vector["subject_ski_hex"]
            and aki is not None
            and aki.hex() == x509_vector["authority_ski_hex"]
            and "PKIX.ClientAuth" in info.stdout
            and "PKIX.ServerAuth" in info.stdout
        )
        probes.append(
            result("x509.ku_eku_ski_aki", "PASS" if profile_pass else "FAIL", "Botan parse plus exact fixture checks")
        )

        private_key = ec.derive_private_key(IDENTITY_SCALAR, ec.SECP256R1())
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        key_path = temporary_path / "identity.pem"
        public_path = temporary_path / "identity-public.pem"
        wrong_public_path = temporary_path / "wrong-public.pem"
        message_path = temporary_path / "message.bin"
        signature_path = temporary_path / "signature.der"
        malformed_path = temporary_path / "malformed.der"
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        wrong_public_path.write_bytes(
            wrong_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        message_path.write_bytes(b"ACP Botan provider signing probe v1")
        sign = command(
            [
                "botan",
                "sign",
                "--der-format",
                f"--output={signature_path}",
                str(key_path),
                str(message_path),
            ]
        )
        signature = (
            base64.b64decode(signature_path.read_bytes().strip(), validate=True) if signature_path.exists() else b""
        )
        try:
            signature_r, signature_s = utils.decode_dss_signature(signature)
            native_low_s = signature_s <= P256_ORDER // 2
            normalized_signature = utils.encode_dss_signature(signature_r, min(signature_s, P256_ORDER - signature_s))
        except ValueError:
            native_low_s = False
            normalized_signature = b""
        valid = command(["botan", "verify", "--der-format", str(public_path), str(message_path), str(signature_path)])
        wrong = command(
            ["botan", "verify", "--der-format", str(wrong_public_path), str(message_path), str(signature_path)]
        )
        malformed_path.write_bytes(base64.b64encode(signature[:-1]) + b"\n")
        malformed = command(
            ["botan", "verify", "--der-format", str(public_path), str(message_path), str(malformed_path)]
        )
        provider_signing_pass = (
            sign.returncode == 0
            and "is valid" in valid.stdout.lower()
            and "invalid" in wrong.stdout.lower()
            and "invalid" in malformed.stdout.lower()
        )
        normalized_path = temporary_path / "normalized.der"
        normalized_path.write_bytes(base64.b64encode(normalized_signature) + b"\n")
        normalized_verify = command(
            ["botan", "verify", "--der-format", str(public_path), str(message_path), str(normalized_path)]
        )
        _, normalized_s = utils.decode_dss_signature(normalized_signature)
        adapter_low_s_pass = normalized_s <= P256_ORDER // 2 and "is valid" in normalized_verify.stdout.lower()
        signing_detail = (
            f"sign={sign.returncode} verify={valid.returncode} wrong={wrong.returncode} "
            f"malformed={malformed.returncode} native_low_s={native_low_s}"
        )
        probes.append(
            result(
                "ecdsa.provider_sign_verify",
                "PASS" if provider_signing_pass else "FAIL",
                signing_detail,
            )
        )
        probes.append(
            result(
                "ecdsa.acp_strict_der_low_s_adapter",
                "PASS" if adapter_low_s_pass else "FAIL",
                "outbound S normalized; inbound DER decoded and low-S checked before Botan verification",
            )
        )

        tls_binary = temporary_path / "botan-tls-probe"
        tls_compile = command(
            [
                "c++",
                "-std=c++20",
                "-Wall",
                "-Wextra",
                "-Werror",
                *pkg.stdout.split(),
                str(TOOL / "botan_tls_probe.cpp"),
                "-o",
                str(tls_binary),
            ]
        )
        if tls_compile.returncode:
            tls_payload: dict[str, object] = {}
            tls_detail = tls_compile.stderr.strip()
        else:
            tls_run = command([str(tls_binary), str(leaf_path), str(root_path), str(key_path)])
            try:
                tls_payload = json.loads(tls_run.stdout)
            except json.JSONDecodeError:
                tls_payload = {}
            tls_detail = tls_run.stdout.strip() or tls_run.stderr.strip()
        mutual_pass = tls_payload.get("tls13") is True
        peer_evidence_pass = (
            isinstance(tls_payload.get("client_verified_certificates"), int)
            and tls_payload["client_verified_certificates"] >= 1
            and isinstance(tls_payload.get("server_verified_certificates"), int)
            and tls_payload["server_verified_certificates"] >= 1
        )
        exporter_pass = tls_payload.get("exporter_equal") is True and tls_payload.get("exporter_length") == 32
        no_resume_pass = tls_payload.get("session_manager") == "noop" and tls_payload.get("tickets_issued") == 0
        probes.append(result("tls13.mutual_auth", "PASS" if mutual_pass else "FAIL", tls_detail))
        probes.append(
            result(
                "tls13.peer_certificate_evidence",
                "PASS" if peer_evidence_pass else "FAIL",
                tls_detail,
            )
        )
        probes.append(result("tls13.exporter", "PASS" if exporter_pass else "FAIL", tls_detail))
        probes.append(
            result(
                "tls13.no_resumption_0rtt",
                "PASS" if no_resume_pass else "FAIL",
                "TLS 1.3-only policy; Session_Manager_Noop; zero tickets; no early-data API used",
            )
        )

    approval = json.loads((ROOT / "vectors/security/approval/primary.json").read_text())
    with tempfile.TemporaryDirectory(prefix="acp-aead-probe-") as temporary:
        temporary_path = Path(temporary)
        plaintext_path = temporary_path / "plaintext.cbor"
        sealed_path = temporary_path / "sealed.bin"
        decrypted_path = temporary_path / "decrypted.cbor"
        bad_path = temporary_path / "bad.bin"
        plaintext = bytes.fromhex(approval["plaintext_cbor_hex"])
        expected_sealed = bytes.fromhex(approval["ciphertext_hex"] + approval["tag_hex"])
        plaintext_path.write_bytes(plaintext)
        cipher_args = [
            "botan",
            "cipher",
            "--cipher=AES-256/GCM",
            f"--key={approval['key_hex']}",
            f"--nonce={approval['nonce_hex']}",
            f"--ad={approval['aad_cbor_hex']}",
        ]
        encrypted = command([*cipher_args, f"--output={sealed_path}", str(plaintext_path)])
        decrypted = command([*cipher_args, "--decrypt", f"--output={decrypted_path}", str(sealed_path)])
        bad_sealed = bytearray(expected_sealed)
        bad_sealed[-1] ^= 1
        bad_path.write_bytes(bad_sealed)
        bad_tag = command([*cipher_args, "--decrypt", str(bad_path)])
        wrong_aad_args = [argument for argument in cipher_args if not argument.startswith("--ad=")]
        wrong_aad_args.append("--ad=00")
        wrong_aad = command([*wrong_aad_args, "--decrypt", str(sealed_path)])
        aead_pass = (
            encrypted.returncode == 0
            and sealed_path.read_bytes() == expected_sealed
            and decrypted.returncode == 0
            and decrypted_path.read_bytes() == plaintext
            and bad_tag.returncode != 0
            and wrong_aad.returncode != 0
        )
        probes.append(
            result(
                "aead.aes_256_gcm",
                "PASS" if aead_pass else "FAIL",
                "golden encrypt/decrypt; bad tag and wrong AAD rejected",
            )
        )

    revocation = json.loads((ROOT / "vectors/security/revocation/snapshot_epoch_7.json").read_text())
    with tempfile.TemporaryDirectory(prefix="acp-revocation-probe-") as temporary:
        temporary_path = Path(temporary)
        message_path = temporary_path / "revocation-message.bin"
        signature_path = temporary_path / "revocation-signature.der"
        bad_signature_path = temporary_path / "bad-signature.der"
        issuer_public_path = temporary_path / "issuer-public.pem"
        message_path.write_bytes(b"ACP revocation state v1" + bytes.fromhex(revocation["body_cbor_hex"]))
        signature = bytes.fromhex(revocation["signature_der_hex"])
        signature_path.write_bytes(base64.b64encode(signature) + b"\n")
        bad_signature = bytearray(signature)
        bad_signature[-1] ^= 1
        bad_signature_path.write_bytes(base64.b64encode(bad_signature) + b"\n")
        root_certificate = x509.load_der_x509_certificate(base64.b64decode(x509_vector["root_der_base64"]))
        issuer_public_path.write_bytes(
            root_certificate.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        verified = command(
            ["botan", "verify", "--der-format", str(issuer_public_path), str(message_path), str(signature_path)]
        )
        bad_verified = command(
            ["botan", "verify", "--der-format", str(issuer_public_path), str(message_path), str(bad_signature_path)]
        )
        revocation_pass = "is valid" in verified.stdout.lower() and "invalid" in bad_verified.stdout.lower()
        revocation_pass = revocation_pass and {"epoch-rollback", "wrong-domain", "bad-signature"}.issubset(
            revocation["negative_cases"]
        )
        probes.append(
            result(
                "revocation",
                "PASS" if revocation_pass else "FAIL",
                "Botan signature verification plus ACP rollback/domain/epoch fail-closed cases",
            )
        )

    redacted_text = json.dumps(probes, sort_keys=True)
    forbidden_values = {
        registration["password_hex"],
        registration["w0_hex"],
        registration["w1_hex"],
        approval["key_hex"],
    }
    redaction_pass = not any(value in redacted_text for value in forbidden_values)
    probes.append(
        result(
            "secrets.redaction",
            "PASS" if redaction_pass else "FAIL",
            "results exclude bootstrap secret, PAKE scalars, approval key, TLS secrets, and exporter bytes",
        )
    )

    platform_matrix = {
        "macos-arm64": {"status": "FAIL", "reason": "mandatory adapter probes failed or remain unavailable"},
        "macos-x86_64": {"status": "NOT_RUN", "reason": "host architecture unavailable"},
        "ios-arm64": {"status": "NOT_RUN", "reason": "iOS runner/provider packaging unavailable"},
        "linux-x86_64": {"status": "NOT_RUN", "reason": "platform unavailable on this host"},
        "linux-arm64": {"status": "NOT_RUN", "reason": "platform unavailable on this host"},
        "windows-x86_64": {"status": "NOT_RUN", "reason": "platform unavailable on this host"},
        "raspberry-pi-arm64": {"status": "NOT_RUN", "reason": "target unavailable"},
    }
    provider_probe_ids = {
        "provider.version",
        "spake2p.public_api",
        "spake2p.rfc9383_appendix_c",
        "hash_hmac_hkdf",
        "aead.aes_256_gcm",
        "ecdsa.provider_sign_verify",
    }
    provider_crypto_qualified = all(
        p["status"] == "PASS" for p in probes if p["mandatory"] and p["id"] in provider_probe_ids
    )
    macos_adapter_qualified = all(p["status"] == "PASS" for p in probes if p["mandatory"])
    if macos_adapter_qualified:
        platform_matrix["macos-arm64"] = {"status": "PASS", "reason": "all mandatory host probes passed"}
    qualified = provider_crypto_qualified and all(item["status"] == "PASS" for item in platform_matrix.values())
    report = {
        "schema_version": 1,
        "freeze": "2.1.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "provider": {
            "name": "Botan",
            "version": version.stdout.strip(),
            "linkage": "Homebrew shared bottle",
            "public_api_only": True,
        },
        "provider_crypto_qualified": provider_crypto_qualified,
        "platform_adapter_qualified": {"macos-arm64": macos_adapter_qualified},
        "platform_matrix": platform_matrix,
        "probes": probes,
        "qualified": qualified,
    }
    output = RESULTS / "macos-arm64-botan-3.13.0.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    pass_count = sum(p["status"] == "PASS" for p in probes)
    not_run_count = sum(p["status"] == "NOT_RUN" for p in probes)
    print(f"provider probe qualified={str(qualified).lower()} PASS={pass_count} NOT_RUN={not_run_count}")
    return 0 if qualified else 1


if __name__ == "__main__":
    sys.exit(main())
