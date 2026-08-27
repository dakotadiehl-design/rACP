use crate::{CredentialId, IdentityKeyId, SecurityErrorCode, SecurityNodeId, TrustDomainId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomainAuthorityIdentity {
    pub trust_domain_id: TrustDomainId,
    pub authority_key_id: IdentityKeyId,
    pub trust_anchor_credential_id: CredentialId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommissionerIdentity {
    pub node_id: SecurityNodeId,
    pub instance_id: String,
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableIssuancePurpose {
    Initial,
    Renewal,
    KeyRotation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableIssuanceMetadata {
    pub authorization_id: String,
    pub enrollment_id: String,
    pub attempt_id: String,
    pub trust_domain_id: TrustDomainId,
    pub authority_key_id: IdentityKeyId,
    pub commissioner_node_id: SecurityNodeId,
    pub candidate_node_id: SecurityNodeId,
    pub identity_key_id: IdentityKeyId,
    pub credential_id: CredentialId,
    pub purpose: PortableIssuancePurpose,
    pub replaces_credential_id: Option<CredentialId>,
}
impl PortableIssuanceMetadata {
    pub fn validate(&self) -> Result<(), SecurityErrorCode> {
        let replacement_matches = matches!(self.purpose, PortableIssuancePurpose::Initial)
            == self.replaces_credential_id.is_none();
        if replacement_matches {
            Ok(())
        } else {
            Err(SecurityErrorCode::CredentialInvalid)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableRevocationMetadata {
    pub trust_domain_id: TrustDomainId,
    pub authority_key_id: IdentityKeyId,
    pub epoch: u64,
    pub snapshot_id: CredentialId,
    pub previous_snapshot_id: Option<CredentialId>,
}
impl PortableRevocationMetadata {
    pub fn validate(&self) -> Result<(), SecurityErrorCode> {
        if self.epoch > 0 {
            Ok(())
        } else {
            Err(SecurityErrorCode::CredentialInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/security/conformance")
    }
    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rust_consumes_swift_and_python_security_fixtures() {
        let root = root();
        let manifest: Value = serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let fixtures = manifest["fixtures"].as_array().unwrap();
        let ids: HashSet<&str> = fixtures.iter().map(|f| f["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), fixtures.len());
        let mut foreign = HashSet::new();
        for fixture in fixtures {
            let path = root.join(fixture["path"].as_str().unwrap());
            let raw = fs::read(&path).unwrap();
            assert_eq!(digest(&raw), fixture["sha256"].as_str().unwrap());
            for dependency in fixture["dependencies"].as_array().unwrap() {
                assert!(ids.contains(dependency.as_str().unwrap()));
            }
            let language = fixture["producer"]["language"].as_str().unwrap();
            if language == "rust" { continue; }
            foreign.insert(language);
            let artifact: Value = serde_json::from_slice(&raw).unwrap();
            match fixture["artifact_type"].as_str().unwrap() {
                "x509_chain" => {
                    let leaf = base64_decode(artifact["leaf_der_base64"].as_str().unwrap());
                    let anchor = base64_decode(artifact["root_der_base64"].as_str().unwrap());
                    assert_eq!(format!("sha256:{}", digest(&leaf)), artifact["leaf_credential_id"]);
                    assert_eq!(format!("sha256:{}", digest(&anchor)), artifact["root_credential_id"]);
                }
                "revocation_state" => {
                    let snapshot = hex(artifact["snapshot_cbor_hex"].as_str().unwrap());
                    assert_eq!(format!("sha256:{}", digest(&snapshot)), artifact["snapshot_id"]);
                    assert!(artifact["epoch"].as_u64().unwrap() > 0);
                }
                "negative_mutation" => {
                    assert_eq!(fixture["expectation"]["result"], "reject");
                    assert_eq!(artifact["expected_error"], fixture["expectation"]["error_category"]);
                }
                _ => {}
            }
        }
        assert_eq!(foreign, HashSet::from(["swift", "python"]));
    }

    fn hex(value: &str) -> Vec<u8> {
        value.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        }).collect()
    }

    fn base64_decode(value: &str) -> Vec<u8> {
        fn digit(byte: u8) -> u32 {
            match byte {
                b'A'..=b'Z' => (byte - b'A') as u32,
                b'a'..=b'z' => (byte - b'a' + 26) as u32,
                b'0'..=b'9' => (byte - b'0' + 52) as u32,
                b'+' => 62, b'/' => 63, _ => 0,
            }
        }
        let mut output = Vec::new();
        for chunk in value.as_bytes().chunks_exact(4) {
            let bits = (digit(chunk[0]) << 18) | (digit(chunk[1]) << 12)
                | (digit(chunk[2]) << 6) | digit(chunk[3]);
            output.push((bits >> 16) as u8);
            if chunk[2] != b'=' { output.push((bits >> 8) as u8); }
            if chunk[3] != b'=' { output.push(bits as u8); }
        }
        output
    }
}
