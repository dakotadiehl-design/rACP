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
pub trait X509IssuanceProvider {
    fn issue_node_certificate(
        &self,
        domain: &TrustDomainId,
        node: &SecurityNodeId,
        public_key_spki: &[u8],
    ) -> Result<Vec<u8>, SecurityErrorCode>;
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
    pub fn issue_x509(
        &self,
        provider: &dyn X509IssuanceProvider,
        node: &SecurityNodeId,
        public_key_spki: &[u8],
    ) -> Result<Vec<u8>, SecurityErrorCode> {
        provider.issue_node_certificate(&self.identity.trust_domain_id, node, public_key_spki)
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
        if !policy.allowed_roles.contains(&role)
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
    if extensions.len() > 64 {
        return Err(SecurityErrorCode::ResourceLimit);
    }
    for extension in extensions.values() {
        let values = object(extension)?;
        if values.len() != 2 || !values.contains_key("critical") || !values.contains_key("value") {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
        if matches!(values.get("critical"), Some(Json::Bool(true))) {
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
    if !canonical_utc(issued_at)
        || !canonical_utc(not_before)
        || !canonical_utc(expires_at)
        || !canonical_utc(policy.evaluation_time_rfc3339)
        || issued_at > policy.evaluation_time_rfc3339
        || not_before > policy.evaluation_time_rfc3339
        || policy.evaluation_time_rfc3339 > expires_at
        || not_before > expires_at
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

fn canonical_utc(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && value.ends_with('Z')
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
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
        if next_update <= issued_at || !canonical_utc(issued_at) || !canonical_utc(next_update) {
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
            values.len() + self.entries.len()
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
            parsed.push(RevocationEntry {
                credential_id: CredentialId::parse(id_text)?,
                node_id: SecurityNodeId::parse(
                    entry
                        .get("node_id")
                        .and_then(|v| v.as_str())
                        .ok_or(SecurityErrorCode::CredentialInvalid)?,
                )?,
                revoked_at: entry
                    .get("revoked_at")
                    .and_then(|v| v.as_str())
                    .ok_or(SecurityErrorCode::CredentialInvalid)?
                    .into(),
                reason: entry
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .ok_or(SecurityErrorCode::CredentialInvalid)?
                    .into(),
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
        Ok(())
    }

    pub fn require_fresh(&self, now_rfc3339: &str) -> Result<(), SecurityErrorCode> {
        match (&self.issued_at, &self.next_update) {
            (Some(issued), Some(next))
                if canonical_utc(now_rfc3339)
                    && now_rfc3339 >= issued.as_str()
                    && now_rfc3339 <= next.as_str() =>
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
        let index = (value.generation & 1) as usize;
        self.slots[index] = Some(Slot::new(value, false));
        Ok(())
    }
    pub fn validate_staged(&self, generation: u64, valid: bool) -> Result<(), SecurityErrorCode> {
        let slot = self.slots[(generation & 1) as usize]
            .as_ref()
            .ok_or(SecurityErrorCode::StorageFailed)?;
        if slot.value.generation != generation || slot.committed || !slot.valid() || !valid {
            return Err(SecurityErrorCode::StorageFailed);
        }
        Ok(())
    }
    pub fn commit(&mut self, generation: u64) -> Result<(), SecurityErrorCode> {
        let slot = self.slots[(generation & 1) as usize]
            .as_mut()
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
        fs::create_dir_all(&root).map_err(|_| SecurityErrorCode::StorageFailed)?;
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
        let temporary = self.root.join(format!(".{name}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|_| SecurityErrorCode::StorageFailed)?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| SecurityErrorCode::StorageFailed)?;
        fs::rename(&temporary, &target).map_err(|_| SecurityErrorCode::StorageFailed)?;
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
