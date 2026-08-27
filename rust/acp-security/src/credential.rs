use crate::{
    ClockTrustState, CredentialId, IdentityKeyId, SecurityErrorCode, SecurityNodeId,
    SigningKeyHandle, TrustDomainId,
};
use acp_codec::{decode_cbor_value, encode_cbor_value};
use acp_model::Json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static IDENTITY_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509ValidationEvidence {
    pub der_parsed: bool,
    pub isolated_chain: bool,
    pub signature_valid: bool,
    pub san_well_formed: bool,
    pub domain_matches: bool,
    pub node_matches: bool,
    pub eku_valid: bool,
    pub ku_valid: bool,
    pub ca_constraints_valid: bool,
    pub validity_valid: bool,
    pub revocation_valid: bool,
    pub credential_id_valid: bool,
    pub identity_key_id_valid: bool,
    pub possession_valid: bool,
    pub local_policy_valid: bool,
    pub unknown_critical_extensions: bool,
}
impl X509ValidationEvidence {
    pub fn require_valid(self) -> Result<(), SecurityErrorCode> {
        if self.der_parsed
            && self.isolated_chain
            && self.signature_valid
            && self.san_well_formed
            && self.domain_matches
            && self.node_matches
            && self.eku_valid
            && self.ku_valid
            && self.ca_constraints_valid
            && self.validity_valid
            && self.revocation_valid
            && self.credential_id_valid
            && self.identity_key_id_valid
            && self.possession_valid
            && self.local_policy_valid
            && !self.unknown_critical_extensions
        {
            Ok(())
        } else {
            Err(SecurityErrorCode::CredentialInvalid)
        }
    }
}

pub trait CredentialSignatureVerifier {
    fn verify(&self, issuer_key_id: &str, digest: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomainIdentity {
    pub trust_domain_id: TrustDomainId,
    pub authority_key_id: IdentityKeyId,
}
pub struct CredentialAuthority<'a> {
    pub identity: TrustDomainIdentity,
    signing_key: &'a dyn SigningKeyHandle,
}
impl<'a> CredentialAuthority<'a> {
    pub fn new(
        identity: TrustDomainIdentity,
        signing_key: &'a dyn SigningKeyHandle,
    ) -> Result<Self, SecurityErrorCode> {
        if signing_key.key_id() != &identity.authority_key_id {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        Ok(Self {
            identity,
            signing_key,
        })
    }
    pub fn restore(
        expected: &TrustDomainIdentity,
        restored: TrustDomainIdentity,
        signing_key: &'a dyn SigningKeyHandle,
    ) -> Result<Self, SecurityErrorCode> {
        if expected != &restored {
            return Err(SecurityErrorCode::TrustDomainMismatch);
        }
        Self::new(restored, signing_key)
    }
    pub fn issue_compact(&self, body: &Json) -> Result<Vec<u8>, SecurityErrorCode> {
        let fields = object(body)?;
        if fields.get("trust_domain_id").and_then(|v| v.as_str())
            != Some(self.identity.trust_domain_id.as_str())
            || fields.get("issuer_key_id").and_then(|v| v.as_str())
                != Some(self.identity.authority_key_id.as_str())
        {
            return Err(SecurityErrorCode::TrustDomainMismatch);
        }
        let body_bytes =
            encode_cbor_value(body).map_err(|_| SecurityErrorCode::CredentialInvalid)?;
        let mut signed = b"ACP compact credential v1".to_vec();
        signed.extend_from_slice(&body_bytes);
        let signature = self.signing_key.sign_digest(&Sha256::digest(&signed))?;
        encode_cbor_value(&Json::Object(vec![
            ("body".into(), body.clone()),
            ("algorithm".into(), Json::String("ecdsa_p256_sha256".into())),
            ("signature".into(), Json::Bytes(signature)),
        ]))
        .map_err(|_| SecurityErrorCode::CredentialInvalid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalPlan {
    pub node_id: SecurityNodeId,
    pub current_key_id: IdentityKeyId,
    pub next_key_id: IdentityKeyId,
    pub rotation: bool,
}
impl RenewalPlan {
    pub fn create(
        node_id: SecurityNodeId,
        current_key_id: IdentityKeyId,
        rotation: bool,
        requested_key_id: Option<IdentityKeyId>,
    ) -> Result<Self, SecurityErrorCode> {
        let next_key_id = if rotation {
            let requested = requested_key_id.ok_or(SecurityErrorCode::CredentialInvalid)?;
            if requested == current_key_id {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            requested
        } else {
            if requested_key_id.is_some() {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            current_key_id.clone()
        };
        Ok(Self {
            node_id,
            current_key_id,
            next_key_id,
            rotation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCompactCredential {
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
    pub trust_domain_id: TrustDomainId,
    pub node_id: SecurityNodeId,
    pub public_key: Vec<u8>,
    pub roles: Vec<String>,
}

pub struct CompactCredentialPolicy<'a> {
    pub expected_domain: &'a TrustDomainId,
    pub expected_node: &'a SecurityNodeId,
    pub possession_valid: bool,
    pub allowed_roles: &'a [&'a str],
    pub max_bytes: usize,
    pub evaluation_time_rfc3339: &'a str,
}

fn object(value: &Json) -> Result<BTreeMap<&str, &Json>, SecurityErrorCode> {
    let Json::Object(values) = value else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    let mut result = BTreeMap::new();
    for (key, value) in values {
        if result.insert(key.as_str(), value).is_some() {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
    }
    Ok(result)
}

fn digest_id(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn validate_compact_credential(
    raw: &[u8],
    verifier: &dyn CredentialSignatureVerifier,
    revoked: impl Fn(&CredentialId) -> bool,
    policy: CompactCredentialPolicy<'_>,
) -> Result<ValidatedCompactCredential, SecurityErrorCode> {
    if raw.is_empty() || raw.len() > policy.max_bytes {
        return Err(SecurityErrorCode::ResourceLimit);
    }
    let value = decode_cbor_value(raw).map_err(|_| SecurityErrorCode::CredentialInvalid)?;
    if encode_cbor_value(&value).map_err(|_| SecurityErrorCode::CredentialInvalid)? != raw {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let outer = object(&value)?;
    if outer.len() != 3 {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let body = *outer
        .get("body")
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    let algorithm = outer
        .get("algorithm")
        .and_then(|value| value.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    let Json::Bytes(signature) = outer
        .get("signature")
        .ok_or(SecurityErrorCode::CredentialInvalid)?
    else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    if algorithm != "ecdsa_p256_sha256" {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let fields = object(body)?;
    let required = [
        "format",
        "serial",
        "trust_domain_id",
        "node_id",
        "identity_algorithm",
        "identity_public_key",
        "role_constraints",
        "permission_policy_id",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "extensions",
    ];
    if fields.len() != required.len() || required.iter().any(|key| !fields.contains_key(key)) {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    if fields.get("format").and_then(|v| v.as_str()) != Some("acp-compact-credential-v1")
        || fields.get("identity_algorithm").and_then(|v| v.as_str()) != Some(algorithm)
        || fields.get("trust_domain_id").and_then(|v| v.as_str())
            != Some(policy.expected_domain.as_str())
        || fields.get("node_id").and_then(|v| v.as_str()) != Some(policy.expected_node.as_str())
    {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    match fields.get("serial") {
        Some(Json::UInt(_)) => {}
        Some(Json::Int(value)) if *value >= 0 => {}
        _ => return Err(SecurityErrorCode::CredentialInvalid),
    }
    let permission_policy_id = fields
        .get("permission_policy_id")
        .and_then(|value| value.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    if permission_policy_id.is_empty() || permission_policy_id.len() > 128 {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let issuer = fields
        .get("issuer_key_id")
        .and_then(|v| v.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    IdentityKeyId::parse(issuer)?;
    let Json::Bytes(public_key) = fields
        .get("identity_public_key")
        .ok_or(SecurityErrorCode::CredentialInvalid)?
    else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    if public_key.is_empty() {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let Json::Array(role_values) = fields
        .get("role_constraints")
        .ok_or(SecurityErrorCode::CredentialInvalid)?
    else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    if role_values.len() > 16 {
        return Err(SecurityErrorCode::ResourceLimit);
    }
    let mut roles: Vec<String> = Vec::new();
    for value in role_values {
        let role = value.as_str().ok_or(SecurityErrorCode::CredentialInvalid)?;
        if role.is_empty()
            || role.len() > 64
            || !policy.allowed_roles.contains(&role)
            || roles
                .last()
                .is_some_and(|previous| previous.as_str() >= role)
        {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        roles.push(role.to_owned());
    }
    let extensions = object(
        fields
            .get("extensions")
            .ok_or(SecurityErrorCode::CredentialInvalid)?,
    )?;
    if extensions.len() > 16 {
        return Err(SecurityErrorCode::ResourceLimit);
    }
    for extension in extensions.values() {
        let values = object(extension)?;
        if values.len() != 2 || !values.contains_key("critical") || !values.contains_key("value") {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        if !matches!(values.get("critical"), Some(Json::Bool(false)))
            || !matches!(values.get("value"), Some(Json::Bytes(_)))
        {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
    }
    let issued_at = fields
        .get("issued_at")
        .and_then(|v| v.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    let not_before = fields
        .get("not_before")
        .and_then(|v| v.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    let expires_at = fields
        .get("expires_at")
        .and_then(|v| v.as_str())
        .ok_or(SecurityErrorCode::CredentialInvalid)?;
    let (Some(issued_key), Some(not_before_key), Some(expires_key), Some(now_key)) = (
        timestamp_key(issued_at),
        timestamp_key(not_before),
        timestamp_key(expires_at),
        timestamp_key(policy.evaluation_time_rfc3339),
    ) else {
        return Err(SecurityErrorCode::CredentialExpired);
    };
    if issued_key > now_key
        || not_before_key > now_key
        || now_key > expires_key
        || not_before_key > expires_key
    {
        return Err(SecurityErrorCode::CredentialExpired);
    }
    let body_bytes = encode_cbor_value(body).map_err(|_| SecurityErrorCode::CredentialInvalid)?;
    let mut signed = b"ACP compact credential v1".to_vec();
    signed.extend_from_slice(&body_bytes);
    if !verifier.verify(issuer, &Sha256::digest(&signed), signature) || !policy.possession_valid {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let credential_id = CredentialId::parse(digest_id(raw))?;
    if revoked(&credential_id) {
        return Err(SecurityErrorCode::CredentialRevoked);
    }
    Ok(ValidatedCompactCredential {
        credential_id,
        identity_key_id: IdentityKeyId::parse(digest_id(public_key))?,
        trust_domain_id: policy.expected_domain.clone(),
        node_id: policy.expected_node.clone(),
        public_key: public_key.clone(),
        roles,
    })
}

fn timestamp_key(value: &str) -> Option<[u32; 7]> {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes.last() != Some(&b'Z')
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<u32> {
        std::str::from_utf8(&bytes[start..end]).ok()?.parse().ok()
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let nanos = if bytes.len() == 20 {
        0
    } else {
        if bytes.get(19) != Some(&b'.') || !(22..=30).contains(&bytes.len()) {
            return None;
        }
        let digits = &bytes[20..bytes.len() - 1];
        if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut padded = digits.to_vec();
        padded.resize(9, b'0');
        std::str::from_utf8(&padded).ok()?.parse().ok()?
    };
    Some([year, month, day, hour, minute, second, nanos])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEntry {
    pub credential_id: CredentialId,
    pub node_id: SecurityNodeId,
    pub revoked_at: String,
    pub reason: String,
}

pub struct RevocationState {
    domain: TrustDomainId,
    max_entries: usize,
    epoch: u64,
    entries: HashMap<CredentialId, RevocationEntry>,
    issued_at: Option<String>,
    next_update: Option<String>,
    snapshot_hash: Option<CredentialId>,
}
impl RevocationState {
    pub fn new(domain: TrustDomainId, max_entries: usize) -> Self {
        Self {
            domain,
            max_entries,
            epoch: 0,
            entries: HashMap::new(),
            issued_at: None,
            next_update: None,
            snapshot_hash: None,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn contains(&self, id: &CredentialId) -> bool {
        self.entries.contains_key(id)
    }
    pub fn ingest(
        &mut self,
        raw: &[u8],
        signature: &[u8],
        verifier: &dyn CredentialSignatureVerifier,
    ) -> Result<(), SecurityErrorCode> {
        let maximum_bytes = if self.max_entries <= 128 {
            8192
        } else {
            65_536
        };
        if raw.is_empty() || raw.len() > maximum_bytes {
            return Err(SecurityErrorCode::ResourceLimit);
        }
        let body = decode_cbor_value(raw).map_err(|_| SecurityErrorCode::CredentialInvalid)?;
        if encode_cbor_value(&body).map_err(|_| SecurityErrorCode::CredentialInvalid)? != raw {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let fields = object(&body)?;
        let format = fields
            .get("format")
            .and_then(|v| v.as_str())
            .ok_or(SecurityErrorCode::CredentialInvalid)?;
        if format != "acp-revocation-snapshot-v1" && format != "acp-revocation-delta-v1" {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let required = [
            "format",
            "trust_domain_id",
            "epoch",
            "issued_at",
            "next_update",
            "issuer_key_id",
            "entries",
        ];
        let allowed = [
            "format",
            "trust_domain_id",
            "epoch",
            "issued_at",
            "next_update",
            "issuer_key_id",
            "entries",
            "base_epoch",
            "previous_snapshot_hash",
        ];
        if required.iter().any(|key| !fields.contains_key(key))
            || fields.keys().any(|key| !allowed.contains(key))
            || (format == "acp-revocation-snapshot-v1" && fields.contains_key("base_epoch"))
        {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        if fields.get("trust_domain_id").and_then(|v| v.as_str()) != Some(self.domain.as_str()) {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let epoch = match fields.get("epoch") {
            Some(Json::UInt(value)) => *value,
            Some(Json::Int(value)) if *value >= 0 => *value as u64,
            _ => return Err(SecurityErrorCode::CredentialInvalid),
        };
        if epoch <= self.epoch {
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        let previous_hash = fields
            .get("previous_snapshot_hash")
            .map(|value| {
                value
                    .as_str()
                    .ok_or(SecurityErrorCode::CredentialInvalid)
                    .and_then(CredentialId::parse)
            })
            .transpose()?;
        if self.snapshot_hash.is_some() && previous_hash.as_ref() != self.snapshot_hash.as_ref() {
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        if format == "acp-revocation-delta-v1" {
            let base = match fields.get("base_epoch") {
                Some(Json::UInt(value)) => *value,
                Some(Json::Int(value)) if *value >= 0 => *value as u64,
                _ => return Err(SecurityErrorCode::CredentialInvalid),
            };
            if base != self.epoch || epoch != self.epoch + 1 {
                return Err(SecurityErrorCode::AuthenticationFailed);
            }
        }
        let issuer = fields
            .get("issuer_key_id")
            .and_then(|v| v.as_str())
            .ok_or(SecurityErrorCode::CredentialInvalid)?;
        let issued_at = fields
            .get("issued_at")
            .and_then(|v| v.as_str())
            .ok_or(SecurityErrorCode::CredentialInvalid)?;
        let next_update = fields
            .get("next_update")
            .and_then(|v| v.as_str())
            .ok_or(SecurityErrorCode::CredentialInvalid)?;
        let (Some(issued_key), Some(next_key)) =
            (timestamp_key(issued_at), timestamp_key(next_update))
        else {
            return Err(SecurityErrorCode::CredentialInvalid);
        };
        if next_key <= issued_key {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let mut signed = b"ACP revocation state v1".to_vec();
        signed.extend_from_slice(raw);
        if !verifier.verify(issuer, &Sha256::digest(&signed), signature) {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let Json::Array(values) = fields
            .get("entries")
            .ok_or(SecurityErrorCode::CredentialInvalid)?
        else {
            return Err(SecurityErrorCode::CredentialInvalid);
        };
        let prospective = if format == "acp-revocation-snapshot-v1" {
            values.len()
        } else {
            let mut ids = self
                .entries
                .keys()
                .map(CredentialId::as_str)
                .collect::<std::collections::HashSet<_>>();
            ids.extend(
                values
                    .iter()
                    .filter_map(|value| object(value).ok()?.get("credential_id")?.as_str()),
            );
            ids.len()
        };
        if values.len() > self.max_entries || prospective > self.max_entries {
            return Err(SecurityErrorCode::ResourceLimit);
        }
        let mut parsed = Vec::new();
        let mut previous = "";
        for value in values {
            let entry = object(value)?;
            let required_entry = ["credential_id", "node_id", "revoked_at", "reason"];
            let allowed_entry = [
                "credential_id",
                "node_id",
                "revoked_at",
                "reason",
                "replacement_credential_id",
            ];
            if required_entry.iter().any(|key| !entry.contains_key(key))
                || entry.keys().any(|key| !allowed_entry.contains(key))
            {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            let id_text = entry
                .get("credential_id")
                .and_then(|v| v.as_str())
                .ok_or(SecurityErrorCode::CredentialInvalid)?;
            if id_text <= previous {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            previous = id_text;
            let credential_id = CredentialId::parse(id_text)?;
            let reason = entry
                .get("reason")
                .and_then(|v| v.as_str())
                .ok_or(SecurityErrorCode::CredentialInvalid)?;
            if ![
                "key_compromise",
                "superseded",
                "retired",
                "policy",
                "operator_request",
            ]
            .contains(&reason)
            {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            if let Some(replacement) = entry.get("replacement_credential_id") {
                let replacement = replacement
                    .as_str()
                    .ok_or(SecurityErrorCode::CredentialInvalid)?;
                if CredentialId::parse(replacement)? == credential_id {
                    return Err(SecurityErrorCode::CredentialInvalid);
                }
            }
            let revoked_at = entry
                .get("revoked_at")
                .and_then(|v| v.as_str())
                .ok_or(SecurityErrorCode::CredentialInvalid)?;
            if timestamp_key(revoked_at).is_none() {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            parsed.push(RevocationEntry {
                credential_id,
                node_id: SecurityNodeId::parse(
                    entry
                        .get("node_id")
                        .and_then(|v| v.as_str())
                        .ok_or(SecurityErrorCode::CredentialInvalid)?,
                )?,
                revoked_at: revoked_at.into(),
                reason: reason.into(),
            });
        }
        if format == "acp-revocation-snapshot-v1" {
            self.entries.clear();
        }
        self.entries.extend(
            parsed
                .into_iter()
                .map(|entry| (entry.credential_id.clone(), entry)),
        );
        self.epoch = epoch;
        self.issued_at = Some(issued_at.into());
        self.next_update = Some(next_update.into());
        self.snapshot_hash = Some(CredentialId::parse(digest_id(raw))?);
        Ok(())
    }

    pub fn require_fresh(&self, now_rfc3339: &str) -> Result<(), SecurityErrorCode> {
        match (&self.issued_at, &self.next_update) {
            (Some(issued), Some(next))
                if timestamp_key(now_rfc3339).is_some_and(|now| {
                    timestamp_key(issued).is_some_and(|start| now >= start)
                        && timestamp_key(next).is_some_and(|end| now <= end)
                }) =>
            {
                Ok(())
            }
            _ => Err(SecurityErrorCode::AuthenticationFailed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveSessionRevocationPolicy {
    HardenedTerminate,
    ExplicitAuditedGrace,
}

impl ActiveSessionRevocationPolicy {
    pub const HARDENED_TERMINATE_ID: &'static str = "hardened_terminate";
    pub const EXPLICIT_AUDITED_GRACE_ID: &'static str = "explicit_audited_grace";

    /// Unknown or absent persisted values resolve to the frozen fail-closed
    /// version-1 policy. Grace requires an exact, explicit selection.
    pub fn resolve(persisted_value: Option<&str>) -> Self {
        match persisted_value {
            Some(Self::EXPLICIT_AUDITED_GRACE_ID) => Self::ExplicitAuditedGrace,
            _ => Self::HardenedTerminate,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardenedTerminate => Self::HARDENED_TERMINATE_ID,
            Self::ExplicitAuditedGrace => Self::EXPLICIT_AUDITED_GRACE_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSessionAction {
    Retain,
    Terminate,
    AuditedGrace,
}

pub fn revocation_session_action(
    revoked: bool,
    policy: ActiveSessionRevocationPolicy,
) -> RevocationSessionAction {
    if !revoked {
        return RevocationSessionAction::Retain;
    }
    match policy {
        ActiveSessionRevocationPolicy::HardenedTerminate => RevocationSessionAction::Terminate,
        ActiveSessionRevocationPolicy::ExplicitAuditedGrace => {
            RevocationSessionAction::AuditedGrace
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialGeneration {
    pub generation: u64,
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
    pub credential: Vec<u8>,
}
#[derive(Debug, Clone)]
struct Slot {
    value: CredentialGeneration,
    committed: bool,
    checksum: [u8; 32],
}
impl Slot {
    fn new(value: CredentialGeneration, committed: bool) -> Self {
        let checksum = generation_checksum(&value, committed);
        Self {
            value,
            committed,
            checksum,
        }
    }
    fn valid(&self) -> bool {
        self.checksum == generation_checksum(&self.value, self.committed)
    }
}
fn generation_checksum(value: &CredentialGeneration, committed: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(value.generation.to_be_bytes());
    digest.update(value.credential_id.as_str());
    digest.update(value.identity_key_id.as_str());
    digest.update(&value.credential);
    digest.update([u8::from(committed)]);
    digest.finalize().into()
}

#[derive(Debug, Default)]
pub struct TwoSlotIdentityStore {
    slots: [Option<Slot>; 2],
    selector: Option<u64>,
}
impl TwoSlotIdentityStore {
    pub fn stage(&mut self, value: CredentialGeneration) -> Result<(), SecurityErrorCode> {
        if value.credential.is_empty() {
            return Err(SecurityErrorCode::StorageFailed);
        }
        if let Some(existing) = self
            .slots
            .iter()
            .flatten()
            .find(|slot| slot.value.generation == value.generation)
        {
            return if !existing.committed && existing.valid() && existing.value == value {
                Ok(())
            } else {
                Err(SecurityErrorCode::StorageFailed)
            };
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.value.generation >= value.generation)
        {
            return Err(SecurityErrorCode::StorageFailed);
        }
        let active = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                slot.as_ref()
                    .is_some_and(|slot| slot.committed && slot.valid())
            })
            .max_by_key(|(_, slot)| slot.as_ref().map(|slot| slot.value.generation))
            .map(|(index, _)| index);
        let index = active.map_or(0, |index| 1 - index);
        self.slots[index] = Some(Slot::new(value, false));
        Ok(())
    }
    pub fn validate_staged(&self, generation: u64, valid: bool) -> Result<(), SecurityErrorCode> {
        let slot = self
            .slots
            .iter()
            .flatten()
            .find(|slot| slot.value.generation == generation)
            .ok_or(SecurityErrorCode::StorageFailed)?;
        if slot.value.generation != generation || slot.committed || !slot.valid() || !valid {
            return Err(SecurityErrorCode::StorageFailed);
        }
        Ok(())
    }
    pub fn commit(&mut self, generation: u64) -> Result<(), SecurityErrorCode> {
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.value.generation == generation)
            .ok_or(SecurityErrorCode::StorageFailed)?;
        if slot.value.generation != generation || !slot.valid() {
            return Err(SecurityErrorCode::StorageFailed);
        }
        slot.committed = true;
        slot.checksum = generation_checksum(&slot.value, true);
        self.selector = Some(generation);
        Ok(())
    }
    pub fn recover(&self) -> Option<&CredentialGeneration> {
        self.slots
            .iter()
            .flatten()
            .filter(|slot| slot.committed && slot.valid())
            .max_by_key(|slot| slot.value.generation)
            .map(|slot| &slot.value)
    }
    pub fn reset_trust(&mut self) {
        self.slots = [None, None];
        self.selector = None;
    }
}

#[derive(Debug)]
pub struct HostIdentityStore {
    root: PathBuf,
}
impl HostIdentityStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, SecurityErrorCode> {
        let root = root.into();
        if fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(SecurityErrorCode::StorageFailed);
        }
        fs::create_dir_all(&root).map_err(|_| SecurityErrorCode::StorageFailed)?;
        if !fs::symlink_metadata(&root)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            return Err(SecurityErrorCode::StorageFailed);
        }
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| SecurityErrorCode::StorageFailed)?;
        Ok(Self { root })
    }
    pub fn atomic_write(&self, name: &str, data: &[u8]) -> Result<(), SecurityErrorCode> {
        if name.contains('/') || name.contains("..") {
            return Err(SecurityErrorCode::StorageFailed);
        }
        let target = self.root.join(name);
        let (temporary, mut file) = (0..128)
            .find_map(|_| {
                let nonce = IDENTITY_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = self
                    .root
                    .join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                match options.open(&path) {
                    Ok(file) => Some((path, file)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(_) => None,
                }
            })
            .ok_or(SecurityErrorCode::StorageFailed)?;
        let result = (|| {
            file.write_all(data)
                .and_then(|_| file.sync_all())
                .map_err(|_| SecurityErrorCode::StorageFailed)?;
            fs::rename(&temporary, &target).map_err(|_| SecurityErrorCode::StorageFailed)?;
            Ok::<(), SecurityErrorCode>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        #[cfg(unix)]
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .map_err(|_| SecurityErrorCode::StorageFailed)?;
        OpenOptions::new()
            .read(true)
            .open(&self.root)
            .and_then(|file| file.sync_all())
            .map_err(|_| SecurityErrorCode::StorageFailed)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPhase {
    Idle,
    KeyPrepared,
    CredentialObtained,
    Staged,
    PossessionProved,
    Active,
}
pub struct RotationCoordinator {
    phase: RotationPhase,
    pending: Option<CredentialGeneration>,
}
impl Default for RotationCoordinator {
    fn default() -> Self {
        Self {
            phase: RotationPhase::Idle,
            pending: None,
        }
    }
}
impl RotationCoordinator {
    pub fn phase(&self) -> RotationPhase {
        self.phase
    }
    pub fn prepare(
        &mut self,
        store: &TwoSlotIdentityStore,
        value: CredentialGeneration,
    ) -> Result<(), SecurityErrorCode> {
        if self.phase != RotationPhase::Idle || store.recover().is_none() {
            return Err(SecurityErrorCode::StorageFailed);
        }
        self.pending = Some(value);
        self.phase = RotationPhase::KeyPrepared;
        Ok(())
    }
    pub fn credential_obtained(&mut self) -> Result<(), SecurityErrorCode> {
        self.advance(
            RotationPhase::KeyPrepared,
            RotationPhase::CredentialObtained,
        )
    }
    pub fn stage(
        &mut self,
        store: &mut TwoSlotIdentityStore,
        valid: bool,
    ) -> Result<(), SecurityErrorCode> {
        if self.phase != RotationPhase::CredentialObtained {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let pending = self
            .pending
            .clone()
            .ok_or(SecurityErrorCode::CredentialInvalid)?;
        store.stage(pending.clone())?;
        store.validate_staged(pending.generation, valid)?;
        self.phase = RotationPhase::Staged;
        Ok(())
    }
    pub fn possession_proved(&mut self, valid: bool) -> Result<(), SecurityErrorCode> {
        if !valid {
            self.abort();
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        self.advance(RotationPhase::Staged, RotationPhase::PossessionProved)
    }
    pub fn activate(&mut self, store: &mut TwoSlotIdentityStore) -> Result<(), SecurityErrorCode> {
        if self.phase != RotationPhase::PossessionProved {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        let generation = self
            .pending
            .as_ref()
            .ok_or(SecurityErrorCode::CredentialInvalid)?
            .generation;
        store.commit(generation)?;
        self.phase = RotationPhase::Active;
        Ok(())
    }
    pub fn abort(&mut self) {
        self.pending = None;
        self.phase = RotationPhase::Idle;
    }
    fn advance(
        &mut self,
        expected: RotationPhase,
        target: RotationPhase,
    ) -> Result<(), SecurityErrorCode> {
        if self.phase != expected {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        self.phase = target;
        Ok(())
    }
}

pub fn accepted_time(
    state: ClockTrustState,
    wall: Option<u64>,
    checkpoint: Option<u64>,
    commissioner: Option<u64>,
    last_checkpoint: Option<u64>,
) -> Result<u64, SecurityErrorCode> {
    let candidate = match state {
        ClockTrustState::TrustedWallClock => wall,
        ClockTrustState::AuthenticatedCheckpoint => checkpoint,
        ClockTrustState::CommissionerBounded => commissioner,
        ClockTrustState::Untrusted => None,
    }
    .ok_or(SecurityErrorCode::ClockUntrusted)?;
    if last_checkpoint.is_some_and(|last| candidate < last) {
        return Err(SecurityErrorCode::ClockUntrusted);
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_timestamps_are_canonical_and_calendar_valid() {
        assert!(timestamp_key("2026-08-26T12:34:56Z").is_some());
        assert!(timestamp_key("2024-02-29T12:34:56.123456789Z").is_some());
        for invalid in [
            "2026-02-29T12:34:56Z",
            "2026-08-26T24:00:00Z",
            "2026-08-26T12:34:60Z",
            "2026-08-26T12:34:56+00:00",
            "2026-08-26T12:34:56.1234567890Z",
        ] {
            assert!(timestamp_key(invalid).is_none(), "accepted {invalid}");
        }
    }

    struct ExpectedVerifier(Vec<u8>, Vec<u8>);
    impl CredentialSignatureVerifier for ExpectedVerifier {
        fn verify(&self, _issuer_key_id: &str, digest: &[u8], signature: &[u8]) -> bool {
            digest == self.0 && signature == self.1
        }
    }
    struct AuthorityKey {
        id: IdentityKeyId,
        digest: Vec<u8>,
        signature: Vec<u8>,
    }
    impl SigningKeyHandle for AuthorityKey {
        fn key_id(&self) -> &IdentityKeyId {
            &self.id
        }
        fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SecurityErrorCode> {
            if digest != self.digest {
                return Err(SecurityErrorCode::CredentialInvalid);
            }
            Ok(self.signature.clone())
        }
    }
    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }
    fn domain() -> TrustDomainId {
        TrustDomainId::parse("40516273-8495-4a6b-8a3b-4c5d6e7f8091").unwrap()
    }
    fn node() -> SecurityNodeId {
        SecurityNodeId::parse("00112233-4455-4677-8899-aabbccddeeff").unwrap()
    }
    fn generation(number: u64) -> CredentialGeneration {
        let id = format!("sha256:{number:064x}");
        CredentialGeneration {
            generation: number,
            credential_id: CredentialId::parse(&id).unwrap(),
            identity_key_id: IdentityKeyId::parse(id).unwrap(),
            credential: vec![number as u8],
        }
    }

    #[test]
    fn compact_and_revocation_frozen_vectors_validate() {
        let compact = include_bytes!("../../../vectors/security/compact_credential/primary.cbor");
        let compact_verifier = ExpectedVerifier(
            hex("cb2fbb3a803784e25b0b6c15b2809ae75f18f2208c5dced47ffa24b5709267b8"),
            hex("3045022100fbfa53de47e3e81b66a4dfc3cc10760ff03bb3eea400da0c7726822ca7f9aa6f02200d3838d8f13100558c31ede68ce725513b58090a344ff0503721a9de72a7169c"),
        );
        let validated = validate_compact_credential(
            compact,
            &compact_verifier,
            |_| false,
            CompactCredentialPolicy {
                expected_domain: &domain(),
                expected_node: &node(),
                possession_valid: true,
                allowed_roles: &["remote"],
                max_bytes: 2048,
                evaluation_time_rfc3339: "2026-08-25T00:00:00Z",
            },
        )
        .unwrap();
        assert_eq!(
            validated.credential_id.as_str(),
            "sha256:df742e543f19926ac10607c0302facaab2f3576965e244324fd37d5d2acc2168"
        );

        let signed = decode_cbor_value(include_bytes!(
            "../../../vectors/security/revocation/snapshot_epoch_7.cbor"
        ))
        .unwrap();
        let values = object(&signed).unwrap();
        let body = encode_cbor_value(values["body"]).unwrap();
        let Json::Bytes(signature) = values["signature"] else {
            panic!("signature")
        };
        let verifier = ExpectedVerifier(
            hex("77817afa34dc31786200e7f39049408b9ec9b3c15d7d7fbebeb08d1a4e546079"),
            signature.clone(),
        );
        let mut state = RevocationState::new(domain(), 128);
        state.ingest(&body, signature, &verifier).unwrap();
        assert_eq!(state.epoch(), 7);
        state.require_fresh("2026-08-22T12:00:00Z").unwrap();
        assert_eq!(
            state.require_fresh("2026-08-23T12:00:00Z"),
            Err(SecurityErrorCode::AuthenticationFailed)
        );
        assert_eq!(
            revocation_session_action(true, ActiveSessionRevocationPolicy::HardenedTerminate),
            RevocationSessionAction::Terminate
        );
        assert_eq!(
            revocation_session_action(true, ActiveSessionRevocationPolicy::ExplicitAuditedGrace),
            RevocationSessionAction::AuditedGrace
        );
        assert_eq!(
            ActiveSessionRevocationPolicy::resolve(None),
            ActiveSessionRevocationPolicy::HardenedTerminate
        );
        assert_eq!(
            ActiveSessionRevocationPolicy::resolve(Some("unknown")),
            ActiveSessionRevocationPolicy::HardenedTerminate
        );
        assert_eq!(
            ActiveSessionRevocationPolicy::resolve(Some("explicit_audited_grace")),
            ActiveSessionRevocationPolicy::ExplicitAuditedGrace
        );
        assert_eq!(
            state.ingest(&body, signature, &verifier),
            Err(SecurityErrorCode::AuthenticationFailed)
        );
    }

    #[test]
    fn x509_policy_requires_every_fact() {
        let valid = X509ValidationEvidence {
            der_parsed: true,
            isolated_chain: true,
            signature_valid: true,
            san_well_formed: true,
            domain_matches: true,
            node_matches: true,
            eku_valid: true,
            ku_valid: true,
            ca_constraints_valid: true,
            validity_valid: true,
            revocation_valid: true,
            credential_id_valid: true,
            identity_key_id_valid: true,
            possession_valid: true,
            local_policy_valid: true,
            unknown_critical_extensions: false,
        };
        assert_eq!(valid.require_valid(), Ok(()));
        assert_eq!(
            X509ValidationEvidence {
                node_matches: false,
                ..valid
            }
            .require_valid(),
            Err(SecurityErrorCode::CredentialInvalid)
        );
        assert_eq!(
            X509ValidationEvidence {
                unknown_critical_extensions: true,
                ..valid
            }
            .require_valid(),
            Err(SecurityErrorCode::CredentialInvalid)
        );
    }

    #[test]
    fn two_slot_recovery_never_selects_staged_data() {
        let mut store = TwoSlotIdentityStore::default();
        store.stage(generation(1)).unwrap();
        store.validate_staged(1, true).unwrap();
        store.commit(1).unwrap();
        store.stage(generation(2)).unwrap();
        assert_eq!(store.recover(), Some(&generation(1)));
        store.validate_staged(2, true).unwrap();
        store.commit(2).unwrap();
        assert_eq!(store.recover(), Some(&generation(2)));
    }

    #[test]
    fn two_slot_nonsequential_stage_preserves_active_generation() {
        let mut store = TwoSlotIdentityStore::default();
        store.stage(generation(2)).unwrap();
        store.validate_staged(2, true).unwrap();
        store.commit(2).unwrap();
        store.stage(generation(4)).unwrap();
        assert_eq!(store.recover(), Some(&generation(2)));
        store.validate_staged(4, true).unwrap();
        store.commit(4).unwrap();
        assert_eq!(store.recover(), Some(&generation(4)));
    }

    #[cfg(unix)]
    #[test]
    fn host_identity_store_rejects_symlink_root_and_ignores_predictable_symlink() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "acp-security-store-{}-{}",
            std::process::id(),
            IDENTITY_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let real = base.join("real");
        fs::create_dir_all(&real).unwrap();
        let linked = base.join("linked");
        symlink(&real, &linked).unwrap();
        assert!(HostIdentityStore::new(&linked).is_err());

        let store = HostIdentityStore::new(&real).unwrap();
        let victim = base.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, real.join(".identity.tmp")).unwrap();
        store.atomic_write("identity", b"credential").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::read(real.join("identity")).unwrap(), b"credential");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rotation_failure_retains_previous_identity() {
        let mut store = TwoSlotIdentityStore::default();
        store.stage(generation(1)).unwrap();
        store.validate_staged(1, true).unwrap();
        store.commit(1).unwrap();
        let mut rotation = RotationCoordinator::default();
        rotation.prepare(&store, generation(2)).unwrap();
        rotation.credential_obtained().unwrap();
        rotation.stage(&mut store, true).unwrap();
        assert_eq!(
            rotation.possession_proved(false),
            Err(SecurityErrorCode::CredentialInvalid)
        );
        assert_eq!(store.recover(), Some(&generation(1)));
    }

    #[test]
    fn clock_policy_rejects_untrusted_and_rollback() {
        assert_eq!(
            accepted_time(
                ClockTrustState::TrustedWallClock,
                Some(10),
                None,
                None,
                Some(9)
            ),
            Ok(10)
        );
        assert_eq!(
            accepted_time(ClockTrustState::Untrusted, Some(10), None, None, None),
            Err(SecurityErrorCode::ClockUntrusted)
        );
        assert_eq!(
            accepted_time(
                ClockTrustState::AuthenticatedCheckpoint,
                None,
                Some(8),
                None,
                Some(9)
            ),
            Err(SecurityErrorCode::ClockUntrusted)
        );
    }

    #[test]
    fn authority_issuance_and_renewal_preserve_node_identity() {
        let compact = decode_cbor_value(include_bytes!(
            "../../../vectors/security/compact_credential/primary.cbor"
        ))
        .unwrap();
        let values = object(&compact).unwrap();
        let body = values["body"].clone();
        let issuer =
            IdentityKeyId::parse(object(&body).unwrap()["issuer_key_id"].as_str().unwrap())
                .unwrap();
        let key = AuthorityKey {
            id: issuer.clone(),
            digest: hex("cb2fbb3a803784e25b0b6c15b2809ae75f18f2208c5dced47ffa24b5709267b8"),
            signature: hex("3045022100fbfa53de47e3e81b66a4dfc3cc10760ff03bb3eea400da0c7726822ca7f9aa6f02200d3838d8f13100558c31ede68ce725513b58090a344ff0503721a9de72a7169c"),
        };
        let identity = TrustDomainIdentity {
            trust_domain_id: domain(),
            authority_key_id: issuer,
        };
        let authority = CredentialAuthority::restore(&identity, identity.clone(), &key).unwrap();
        assert_eq!(
            authority.issue_compact(&body).unwrap(),
            encode_cbor_value(&compact).unwrap()
        );
        let current = IdentityKeyId::parse(format!("sha256:{}", "1".repeat(64))).unwrap();
        let renewed = RenewalPlan::create(node(), current.clone(), false, None).unwrap();
        assert_eq!(renewed.next_key_id, current);
        let next = IdentityKeyId::parse(format!("sha256:{}", "2".repeat(64))).unwrap();
        let rotated = RenewalPlan::create(node(), current, true, Some(next.clone())).unwrap();
        assert_eq!(rotated.next_key_id, next);
    }
}
