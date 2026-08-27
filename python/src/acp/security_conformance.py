"""Consumer for frozen ACP cross-language security conformance manifests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .security_authority import PortableIssuanceMetadata, PortableIssuancePurpose
from .security_models import CredentialID, IdentityKeyID, SecurityNodeID, TrustDomainID


def validate_fixture_set(root: Path, schema_path: Path, *, consumer_language: str) -> set[str]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(manifest)
    fixtures = manifest["fixtures"]
    ids = {fixture["id"] for fixture in fixtures}
    if len(ids) != len(fixtures):
        raise ValueError("duplicate fixture ID")
    foreign: set[str] = set()
    for fixture in fixtures:
        path = (root / fixture["path"]).resolve()
        if root.resolve() not in path.parents:
            raise ValueError("fixture path escapes root")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != fixture["sha256"]:
            raise ValueError(f"fixture hash mismatch: {fixture['id']}")
        if not set(fixture["dependencies"]).issubset(ids):
            raise ValueError(f"fixture dependency missing: {fixture['id']}")
        language = fixture["producer"]["language"]
        if language != consumer_language:
            foreign.add(language)
            _validate_foreign_artifact(fixture, json.loads(raw))
    if not foreign:
        raise ValueError("self-produced fixtures cannot establish conformance")
    return foreign


def _validate_foreign_artifact(fixture: dict[str, Any], artifact: dict[str, Any]) -> None:
    kind = fixture["artifact_type"]
    if kind == "canonical_spki":
        spki = bytes.fromhex(artifact["spki_der_hex"])
        if len(spki) != 91 or not spki.startswith(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")):
            raise ValueError("noncanonical P-256 SPKI")
        if "sha256:" + hashlib.sha256(spki).hexdigest() != artifact["identity_key_id"]:
            raise ValueError("identity key ID mismatch")
    elif kind == "x509_chain":
        leaf = base64.b64decode(artifact["leaf_der_base64"], validate=True)
        root = base64.b64decode(artifact["root_der_base64"], validate=True)
        if "sha256:" + hashlib.sha256(leaf).hexdigest() != artifact["leaf_credential_id"]:
            raise ValueError("leaf credential ID mismatch")
        if "sha256:" + hashlib.sha256(root).hexdigest() != artifact["root_credential_id"]:
            raise ValueError("root credential ID mismatch")
    elif kind == "issuance_metadata":
        PortableIssuanceMetadata(
            authorization_id=artifact["authorization_id"],
            enrollment_id=artifact["enrollment_id"], attempt_id=artifact["attempt_id"],
            trust_domain_id=TrustDomainID(artifact["trust_domain_id"]),
            authority_key_id=IdentityKeyID(artifact["authority_key_id"]),
            commissioner_node_id=SecurityNodeID(artifact["commissioner_node_id"]),
            candidate_node_id=SecurityNodeID(artifact["candidate_node_id"]),
            identity_key_id=IdentityKeyID(artifact["identity_key_id"]),
            credential_id=CredentialID(artifact["credential_id"]),
            purpose=PortableIssuancePurpose(artifact["purpose"]),
            replaces_credential_id=(CredentialID(artifact["replaces_credential_id"])
                                    if artifact.get("replaces_credential_id") else None),
        )
    elif kind == "negative_mutation":
        if fixture["expectation"]["result"] != "reject" or not artifact.get("expected_error"):
            raise ValueError("negative fixture lacks rejection category")
