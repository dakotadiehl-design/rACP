//! Aurora Trust typed models and narrow cryptographic provider boundaries. No networking.

use acp_model::Json;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, SecurityErrorCode> {
                let value = value.into();
                if valid_uuid(&value) {
                    Ok(Self(value))
                } else {
                    Err(SecurityErrorCode::CredentialInvalid)
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
macro_rules! digest_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, SecurityErrorCode> {
                let value = value.into();
                if valid_digest_id(&value) {
                    Ok(Self(value))
                } else {
                    Err(SecurityErrorCode::CredentialInvalid)
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

uuid_id!(TrustDomainId);
uuid_id!(SecurityNodeId);
uuid_id!(EnrollmentId);
uuid_id!(EnrollmentAttemptId);
digest_id!(CredentialId);
digest_id!(IdentityKeyId);

fn valid_uuid(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|i| b[*i] == b'-')
        && b.iter().enumerate().all(|(i, c)| {
            [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
        })
        && matches!(b[14], b'1'..=b'8')
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}
fn valid_digest_id(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMode {
    TrustedLan,
    Tls,
    AuroraTrust,
    EnrollmentSpake2Plus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    Full,
    Lightweight,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalState {
    Unauthenticated,
    Authenticated,
    Revoked,
    Expired,
    IdentityConflict,
    Invalid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecuritySuite {
    Raw128,
    Pbkdf2_100k,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFormat {
    X509Der,
    CompactV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Staged,
    Active,
    Expired,
    Revoked,
    Superseded,
    Invalid,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentMethod {
    ManualCode,
    Qr,
    ProvisioningFile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Closed,
    Open,
    CandidateSelected,
    SecretAcquired,
    Negotiating,
    KeyConfirmed,
    AwaitingOperatorApproval,
    IssuingCredential,
    AwaitingInstallReceipt,
    Complete,
    Cancelled,
    Expired,
    Locked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    HardwareBacked,
    OsProtected,
    EncryptedFile,
    ProtectedFlash,
    PlainFile,
    Ephemeral,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoragePosture {
    pub class: StorageClass,
    pub hardware_backed: bool,
    pub private_key_exportable: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockTrustState {
    TrustedWallClock,
    AuthenticatedCheckpoint,
    CommissionerBounded,
    Untrusted,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCapabilityVersion {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityErrorCode {
    EnrollmentClosed,
    EnrollmentExpired,
    EnrollmentLocked,
    EnrollmentReplayed,
    NoCommonSuite,
    AuthenticationFailed,
    KeyConfirmationFailed,
    TranscriptMismatch,
    IdentityMismatch,
    TrustDomainMismatch,
    CredentialExpired,
    CredentialRevoked,
    CredentialInvalid,
    PermissionDenied,
    DowngradeForbidden,
    StorageFailed,
    ResourceLimit,
    ClockUntrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DowngradePolicy {
    pub hardened: bool,
    pub allow_trusted_lan: bool,
}
impl DowngradePolicy {
    pub const HARDENED_PRODUCTION: Self = Self {
        hardened: true,
        allow_trusted_lan: false,
    };
    pub fn migration(allow_trusted_lan: bool) -> Self {
        Self {
            hardened: false,
            allow_trusted_lan,
        }
    }
    pub fn permits_unauthenticated(self, stronger_auth_attempted: bool) -> bool {
        self.allow_trusted_lan && !self.hardened && !stronger_auth_attempted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportEvidence {
    pub mode: AuthenticationMode,
    pub profile: SecurityProfile,
    pub trust_domain_id: TrustDomainId,
    pub node_id: SecurityNodeId,
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
    pub credential_format: CredentialFormat,
    pub channel_binding: Option<[u8; 32]>,
    pub credential_status: CredentialStatus,
    pub channel_binding_verified: bool,
    pub zero_rtt_used: bool,
    pub resumption_used: bool,
    pub role_constraints: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub state: PrincipalState,
    pub mode: AuthenticationMode,
    pub profile: Option<SecurityProfile>,
    pub trust_domain_id: Option<TrustDomainId>,
    pub node_id: Option<SecurityNodeId>,
    pub credential_id: Option<CredentialId>,
    pub identity_key_id: Option<IdentityKeyId>,
    pub credential_format: Option<CredentialFormat>,
    pub role_constraints: HashSet<String>,
}

pub struct SecretBytes(Vec<u8>);
impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Result<Self, SecurityErrorCode> {
        if value.is_empty() {
            Err(SecurityErrorCode::CredentialInvalid)
        } else {
            Ok(Self(value))
        }
    }
    pub fn expose_to<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(&self.0)
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

const CONTEXT_KEYS: [&str; 16] = [
    "acp_version",
    "application",
    "attempt_id",
    "candidate_instance_id",
    "candidate_node_id",
    "commissioner_instance_id",
    "commissioner_node_id",
    "enrollment_id",
    "extension_version",
    "identity_algorithm",
    "identity_key_id",
    "purpose",
    "requested_permissions_digest",
    "requested_role",
    "suite",
    "trust_domain_id",
];

pub fn canonical_enrollment_context(
    values: &BTreeMap<String, String>,
) -> Result<Vec<u8>, SecurityErrorCode> {
    if values.len() != CONTEXT_KEYS.len()
        || !CONTEXT_KEYS.iter().all(|key| values.contains_key(*key))
    {
        return Err(SecurityErrorCode::TranscriptMismatch);
    }
    let json = Json::Object(
        values
            .iter()
            .map(|(k, v)| (k.clone(), Json::String(v.clone())))
            .collect(),
    );
    acp_codec::encode_cbor_value(&json).map_err(|_| SecurityErrorCode::TranscriptMismatch)
}
pub fn canonical_transcript(items: &[Vec<u8>]) -> Result<Vec<u8>, SecurityErrorCode> {
    if items.len() != 5 || items.iter().any(Vec::is_empty) {
        return Err(SecurityErrorCode::TranscriptMismatch);
    }
    acp_codec::encode_cbor_value(&Json::Array(
        items.iter().cloned().map(Json::Bytes).collect(),
    ))
    .map_err(|_| SecurityErrorCode::TranscriptMismatch)
}
pub fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
pub fn digest_id_for(value: &[u8]) -> String {
    format!("sha256:{}", hex(&sha256(value)))
}
pub fn permission_digest(permissions: &Json) -> Result<String, SecurityErrorCode> {
    acp_codec::encode_cbor_value(permissions)
        .map(|v| digest_id_for(&v))
        .map_err(|_| SecurityErrorCode::TranscriptMismatch)
}
pub fn canonical_approval_aad(
    values: &BTreeMap<String, Json>,
) -> Result<Vec<u8>, SecurityErrorCode> {
    const KEYS: [&str; 12] = [
        "message_type",
        "attempt_id",
        "enrollment_id",
        "candidate_node_id",
        "commissioner_node_id",
        "trust_domain_id",
        "acp_version",
        "extension_version",
        "suite",
        "identity_algorithm",
        "identity_key_id",
        "transcript_hash",
    ];
    if values.len() != KEYS.len()
        || !KEYS.iter().all(|key| values.contains_key(*key))
        || values.get("message_type") != Some(&Json::String("security.enrollment.approval".into()))
        || !matches!(values.get("transcript_hash"), Some(Json::Bytes(hash)) if hash.len() == 32)
    {
        return Err(SecurityErrorCode::TranscriptMismatch);
    }
    acp_codec::encode_cbor_value(&Json::Object(
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    ))
    .map_err(|_| SecurityErrorCode::TranscriptMismatch)
}
pub fn canonical_install_result_without_confirmation(
    values: &BTreeMap<String, Json>,
) -> Result<Vec<u8>, SecurityErrorCode> {
    const KEYS: [&str; 7] = [
        "attempt_id",
        "status",
        "credential_id",
        "identity_key_id",
        "trust_domain_id",
        "storage_posture",
        "proof_of_possession",
    ];
    if values.len() != KEYS.len()
        || !KEYS.iter().all(|key| values.contains_key(*key))
        || values.get("status") != Some(&Json::String("installed".into()))
        || !matches!(values.get("proof_of_possession"), Some(Json::Bytes(proof)) if !proof.is_empty())
    {
        return Err(SecurityErrorCode::TranscriptMismatch);
    }
    let Some(Json::Object(posture)) = values.get("storage_posture") else {
        return Err(SecurityErrorCode::TranscriptMismatch);
    };
    let posture_keys: HashSet<&str> = posture.iter().map(|(key, _)| key.as_str()).collect();
    if posture_keys != HashSet::from(["class", "hardware_backed", "private_key_exportable"]) {
        return Err(SecurityErrorCode::TranscriptMismatch);
    }
    acp_codec::encode_cbor_value(&Json::Object(
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    ))
    .map_err(|_| SecurityErrorCode::TranscriptMismatch)
}
pub fn install_confirmation(
    key: &[u8],
    values: &BTreeMap<String, Json>,
) -> Result<[u8; 32], SecurityErrorCode> {
    Ok(hmac(
        key,
        &canonical_install_result_without_confirmation(values)?,
    ))
}
pub fn install_proof_digest(
    transcript_hash: &[u8],
    credential_id: &str,
) -> Result<[u8; 32], SecurityErrorCode> {
    if transcript_hash.len() != 32 || !valid_digest_id(credential_id) {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let mut input = b"ACP enrollment install proof v1".to_vec();
    input.extend_from_slice(transcript_hash);
    input.extend_from_slice(credential_id.as_bytes());
    Ok(sha256(&input))
}
pub fn derive_enrollment_keys(
    shared_key: &[u8],
    transcript_hash: &[u8],
) -> BTreeMap<&'static str, [u8; 32]> {
    let root = hmac(transcript_hash, shared_key);
    [
        "candidate confirm",
        "commissioner confirm",
        "approval AEAD",
        "audit binding",
        "SAS",
    ]
    .into_iter()
    .map(|label| {
        let info = format!("ACP enrollment {label} v1");
        let expanded = hkdf_expand(&root, info.as_bytes(), 32);
        (label, expanded.try_into().expect("fixed HKDF length"))
    })
    .collect()
}
pub fn channel_bindings_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == 32
        && right.len() == 32
        && left.iter().zip(right).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
fn hkdf_expand(key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut input = previous;
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac(key, &input).to_vec();
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(length);
    out
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

pub trait SecureRandomProvider: Send + Sync {
    fn bytes(&self, count: usize) -> Result<SecretBytes, SecurityErrorCode>;
}
pub trait SigningKeyHandle: Send + Sync {
    fn key_id(&self) -> &IdentityKeyId;
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SecurityErrorCode>;
}
pub trait CryptoProvider: Send + Sync {
    fn sha256(&self, value: &[u8]) -> [u8; 32];
    fn hmac_sha256(&self, key: &SecretBytes, value: &[u8]) -> [u8; 32];
}
pub trait Spake2PlusOperation: Send {
    fn receive_peer_share(&mut self, share: &[u8]) -> Result<Vec<u8>, SecurityErrorCode>;
    fn verify_confirmation(&mut self, value: &[u8]) -> Result<(), SecurityErrorCode>;
}
pub trait AeadProvider: Send + Sync {
    fn seal(
        &self,
        key: &SecretBytes,
        plaintext: &SecretBytes,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityErrorCode>;
    fn open(
        &self,
        key: &SecretBytes,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, SecurityErrorCode>;
}
pub trait IdentityKeyProvider: Send + Sync {
    fn generate(&self) -> Result<Box<dyn SigningKeyHandle>, SecurityErrorCode>;
}
pub trait CredentialValidator: Send + Sync {
    fn validate(
        &self,
        credential: &[u8],
        domain: &TrustDomainId,
        node: &SecurityNodeId,
    ) -> Result<TransportEvidence, SecurityErrorCode>;
}
pub trait SecurityClock: Send + Sync {
    fn monotonic_ns(&self) -> u64;
    fn utc_timestamp(&self) -> Option<String>;
    fn trust_state(&self) -> ClockTrustState;
}
pub trait SecureTimeCheckpoint: Send + Sync {
    fn load(&self) -> Result<Option<(String, u64)>, SecurityErrorCode>;
    fn store(&self, timestamp: &str, monotonic_ns: u64) -> Result<(), SecurityErrorCode>;
}
pub trait IdentityStore: Send + Sync {
    fn stage(
        &self,
        id: &CredentialId,
        credential: &[u8],
        key: &dyn SigningKeyHandle,
    ) -> Result<(), SecurityErrorCode>;
    fn commit(&self, id: &CredentialId) -> Result<(), SecurityErrorCode>;
    fn rollback(&self) -> Result<(), SecurityErrorCode>;
}
pub trait TrustDomainAuthority: Send + Sync {
    fn issue(&self, request: &[u8]) -> Result<Vec<u8>, SecurityErrorCode>;
}
pub trait EnrollmentPolicy: Send + Sync {
    fn approve(&self, request: &[u8]) -> Result<bool, SecurityErrorCode>;
}
pub trait AuthorizationPolicy: Send + Sync {
    fn permissions(&self, principal: &AuthenticatedPrincipal) -> HashSet<String>;
}
pub trait AuditSink: Send + Sync {
    fn record(&self, event: &str, public_fields: &BTreeMap<String, String>);
}
pub trait RevocationStore: Send + Sync {
    fn contains(&self, id: &CredentialId) -> bool;
    fn epoch(&self) -> u64;
}

pub struct OneShotApprovalProtector<'a> {
    aead: &'a dyn AeadProvider,
    random: &'a dyn SecureRandomProvider,
    consumed: HashSet<EnrollmentAttemptId>,
}
impl<'a> OneShotApprovalProtector<'a> {
    pub fn new(aead: &'a dyn AeadProvider, random: &'a dyn SecureRandomProvider) -> Self {
        Self {
            aead,
            random,
            consumed: HashSet::new(),
        }
    }
    pub fn seal(
        &mut self,
        attempt: EnrollmentAttemptId,
        key: &SecretBytes,
        plaintext: &SecretBytes,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecurityErrorCode> {
        if !self.consumed.insert(attempt) {
            return Err(SecurityErrorCode::EnrollmentReplayed);
        }
        let nonce_secret = self.random.bytes(12)?;
        let nonce = nonce_secret.expose_to(ToOwned::to_owned);
        if nonce.len() != 12 {
            return Err(SecurityErrorCode::ResourceLimit);
        }
        let ciphertext = self.aead.seal(key, plaintext, &nonce, aad)?;
        Ok((nonce, ciphertext))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateEnrollmentState {
    Unenrolled,
    EnrollmentOpen,
    Negotiating,
    KeyConfirmed,
    AwaitingApproval,
    CredentialStaged,
    Enrolled,
    Cancelled,
    Expired,
    Locked,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionerEnrollmentState {
    Idle,
    CandidateSelected,
    SecretAcquired,
    Negotiating,
    KeyConfirmed,
    AwaitingOperatorApproval,
    IssuingCredential,
    AwaitingInstallReceipt,
    Complete,
    Cancelled,
    Expired,
    Locked,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentLimits {
    pub concurrent_attempts: usize,
    pub attempts_per_enrollment: usize,
    pub attempt_timeout_ns: u64,
    pub enrollment_window_ns: u64,
}
impl EnrollmentLimits {
    pub fn for_profile(profile: SecurityProfile) -> Self {
        Self {
            concurrent_attempts: if profile == SecurityProfile::Full {
                2
            } else {
                1
            },
            attempts_per_enrollment: 5,
            attempt_timeout_ns: 60_000_000_000,
            enrollment_window_ns: 600_000_000_000,
        }
    }
}
pub fn select_enrollment_suite(
    preferred: &[SecuritySuite],
    supported: &HashSet<SecuritySuite>,
) -> Result<SecuritySuite, SecurityErrorCode> {
    preferred
        .iter()
        .copied()
        .find(|suite| supported.contains(suite))
        .ok_or(SecurityErrorCode::NoCommonSuite)
}
#[derive(Debug, Clone)]
struct CandidateAttempt {
    state: CandidateEnrollmentState,
    deadline_ns: u64,
    peer_share_processed: bool,
    durable_install_verified: bool,
}

pub struct CandidateEnrollment {
    pub enrollment_id: EnrollmentId,
    state: CandidateEnrollmentState,
    failed_attempts: usize,
    suites: HashSet<SecuritySuite>,
    limits: EnrollmentLimits,
    opened_ns: u64,
    attempts: HashMap<EnrollmentAttemptId, CandidateAttempt>,
    consumed_attempts: HashSet<EnrollmentAttemptId>,
    audit: Option<Arc<dyn AuditSink>>,
}
impl CandidateEnrollment {
    pub fn state(&self) -> CandidateEnrollmentState {
        self.state
    }
    pub fn failed_attempts(&self) -> usize {
        self.failed_attempts
    }
    pub fn is_consumed(&self, id: &EnrollmentAttemptId) -> bool {
        self.consumed_attempts.contains(id)
    }
    pub fn new(
        enrollment_id: EnrollmentId,
        suites: HashSet<SecuritySuite>,
        limits: EnrollmentLimits,
        opened_ns: u64,
    ) -> Self {
        Self::new_with_audit(enrollment_id, suites, limits, opened_ns, None)
    }
    pub fn new_with_audit(
        enrollment_id: EnrollmentId,
        suites: HashSet<SecuritySuite>,
        limits: EnrollmentLimits,
        opened_ns: u64,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> Self {
        Self {
            enrollment_id,
            state: CandidateEnrollmentState::EnrollmentOpen,
            failed_attempts: 0,
            suites,
            limits,
            opened_ns,
            attempts: HashMap::new(),
            consumed_attempts: HashSet::new(),
            audit,
        }
    }
    pub fn begin(
        &mut self,
        id: EnrollmentAttemptId,
        suite: SecuritySuite,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.check_window(now)?;
        if self.state == CandidateEnrollmentState::Locked {
            return Err(SecurityErrorCode::EnrollmentLocked);
        }
        if !matches!(
            self.state,
            CandidateEnrollmentState::EnrollmentOpen | CandidateEnrollmentState::Negotiating
        ) {
            return Err(SecurityErrorCode::EnrollmentClosed);
        }
        if self.attempts.contains_key(&id) || self.consumed_attempts.contains(&id) {
            return Err(SecurityErrorCode::EnrollmentReplayed);
        }
        if !self.suites.contains(&suite) {
            return Err(SecurityErrorCode::NoCommonSuite);
        }
        if self.attempts.len() >= self.limits.concurrent_attempts {
            return Err(SecurityErrorCode::ResourceLimit);
        }
        if self.limits.concurrent_attempts == 0 || self.limits.attempts_per_enrollment == 0 {
            return Err(SecurityErrorCode::ResourceLimit);
        }
        let deadline_ns = now
            .checked_add(self.limits.attempt_timeout_ns)
            .ok_or(SecurityErrorCode::ResourceLimit)?;
        self.attempts.insert(
            id.clone(),
            CandidateAttempt {
                state: CandidateEnrollmentState::Negotiating,
                deadline_ns,
                peer_share_processed: false,
                durable_install_verified: false,
            },
        );
        self.state = CandidateEnrollmentState::Negotiating;
        self.record("security.enrollment.attempt_started", Some(&id));
        Ok(())
    }
    pub fn verify_key_confirmation(
        &mut self,
        id: &EnrollmentAttemptId,
        operation: &mut dyn Spake2PlusOperation,
        confirmation: &[u8],
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.require(id, CandidateEnrollmentState::Negotiating, now)?;
        if !self
            .attempts
            .get(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .peer_share_processed
        {
            self.cryptographic_failure(id);
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        if operation.verify_confirmation(confirmation).is_err() {
            self.cryptographic_failure(id);
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        self.transition(
            id,
            CandidateEnrollmentState::Negotiating,
            CandidateEnrollmentState::KeyConfirmed,
            now,
        )?;
        self.record("security.enrollment.key_confirmed", Some(id));
        Ok(())
    }
    pub fn process_peer_share(
        &mut self,
        id: &EnrollmentAttemptId,
        operation: &mut dyn Spake2PlusOperation,
        encoded_share: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, SecurityErrorCode> {
        self.require(id, CandidateEnrollmentState::Negotiating, now)?;
        if self
            .attempts
            .get(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .peer_share_processed
        {
            self.cryptographic_failure(id);
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        let response = match operation.receive_peer_share(encoded_share) {
            Ok(value) if !value.is_empty() => value,
            _ => {
                self.cryptographic_failure(id);
                return Err(SecurityErrorCode::AuthenticationFailed);
            }
        };
        self.attempts
            .get_mut(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .peer_share_processed = true;
        self.record("security.enrollment.peer_share_processed", Some(id));
        Ok(response)
    }
    pub fn await_approval(
        &mut self,
        id: &EnrollmentAttemptId,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.transition(
            id,
            CandidateEnrollmentState::KeyConfirmed,
            CandidateEnrollmentState::AwaitingApproval,
            now,
        )
    }
    pub fn credential_staged(
        &mut self,
        id: &EnrollmentAttemptId,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.transition(
            id,
            CandidateEnrollmentState::AwaitingApproval,
            CandidateEnrollmentState::CredentialStaged,
            now,
        )
    }
    pub fn durable_install_verified(
        &mut self,
        id: &EnrollmentAttemptId,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.require(id, CandidateEnrollmentState::CredentialStaged, now)?;
        self.attempts
            .get_mut(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .durable_install_verified = true;
        Ok(())
    }
    pub fn complete(
        &mut self,
        id: &EnrollmentAttemptId,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.require(id, CandidateEnrollmentState::CredentialStaged, now)?;
        if !self
            .attempts
            .get(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .durable_install_verified
        {
            return Err(SecurityErrorCode::StorageFailed);
        }
        self.consume(id);
        self.consume_all();
        self.state = CandidateEnrollmentState::Enrolled;
        self.record("security.enrollment.enrolled", Some(id));
        Ok(())
    }
    pub fn cryptographic_failure(&mut self, id: &EnrollmentAttemptId) {
        self.consume(id);
        self.failed_attempts += 1;
        if self.failed_attempts >= self.limits.attempts_per_enrollment {
            self.consume_all();
            self.state = CandidateEnrollmentState::Locked;
        } else {
            self.state = if self.attempts.is_empty() {
                CandidateEnrollmentState::EnrollmentOpen
            } else {
                CandidateEnrollmentState::Negotiating
            };
        }
        self.record("security.enrollment.cryptographic_failure", Some(id));
    }
    pub fn restart(&mut self) {
        self.consume_all();
        if !matches!(
            self.state,
            CandidateEnrollmentState::Enrolled | CandidateEnrollmentState::Locked
        ) {
            self.state = CandidateEnrollmentState::Failed;
        }
        self.record("security.enrollment.restart_invalidated", None);
    }
    fn transition(
        &mut self,
        id: &EnrollmentAttemptId,
        expected: CandidateEnrollmentState,
        target: CandidateEnrollmentState,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.require(id, expected, now)?;
        self.attempts
            .get_mut(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?
            .state = target;
        self.record("security.enrollment.candidate_transition", Some(id));
        Ok(())
    }
    fn require(
        &mut self,
        id: &EnrollmentAttemptId,
        expected: CandidateEnrollmentState,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        self.check_window(now)?;
        let attempt = self
            .attempts
            .get(id)
            .ok_or(SecurityErrorCode::EnrollmentReplayed)?;
        if now >= attempt.deadline_ns {
            self.consume(id);
            self.state = CandidateEnrollmentState::Expired;
            return Err(SecurityErrorCode::EnrollmentExpired);
        }
        if attempt.state != expected {
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        Ok(())
    }
    fn check_window(&mut self, now: u64) -> Result<(), SecurityErrorCode> {
        let deadline = self
            .opened_ns
            .checked_add(self.limits.enrollment_window_ns)
            .ok_or(SecurityErrorCode::ResourceLimit)?;
        if now >= deadline {
            self.consume_all();
            self.state = CandidateEnrollmentState::Expired;
            Err(SecurityErrorCode::EnrollmentExpired)
        } else {
            Ok(())
        }
    }
    fn consume(&mut self, id: &EnrollmentAttemptId) {
        self.attempts.remove(id);
        self.consumed_attempts.insert(id.clone());
    }
    fn consume_all(&mut self) {
        self.consumed_attempts.extend(self.attempts.keys().cloned());
        self.attempts.clear();
    }
    fn record(&self, event: &str, attempt: Option<&EnrollmentAttemptId>) {
        if let Some(audit) = &self.audit {
            let mut fields = BTreeMap::from([
                ("enrollment_id".into(), self.enrollment_id.as_str().into()),
                ("state".into(), format!("{:?}", self.state)),
            ]);
            if let Some(attempt) = attempt {
                fields.insert("attempt_id".into(), attempt.as_str().into());
            }
            audit.record(event, &fields);
        }
    }
}

pub struct CommissionerEnrollment {
    pub enrollment_id: EnrollmentId,
    pub attempt_id: EnrollmentAttemptId,
    pub deadline_ns: u64,
    state: CommissionerEnrollmentState,
    consumed: bool,
    audit: Option<Arc<dyn AuditSink>>,
}
impl CommissionerEnrollment {
    pub fn new(
        enrollment_id: EnrollmentId,
        attempt_id: EnrollmentAttemptId,
        deadline_ns: u64,
    ) -> Self {
        Self::new_with_audit(enrollment_id, attempt_id, deadline_ns, None)
    }
    pub fn new_with_audit(
        enrollment_id: EnrollmentId,
        attempt_id: EnrollmentAttemptId,
        deadline_ns: u64,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> Self {
        Self {
            enrollment_id,
            attempt_id,
            deadline_ns,
            state: CommissionerEnrollmentState::Idle,
            consumed: false,
            audit,
        }
    }
    pub fn state(&self) -> CommissionerEnrollmentState {
        self.state
    }
    pub fn consumed(&self) -> bool {
        self.consumed
    }
    pub fn transition(
        &mut self,
        expected: CommissionerEnrollmentState,
        target: CommissionerEnrollmentState,
        now: u64,
    ) -> Result<(), SecurityErrorCode> {
        if self.consumed {
            return Err(SecurityErrorCode::EnrollmentReplayed);
        }
        if now >= self.deadline_ns {
            self.consumed = true;
            self.state = CommissionerEnrollmentState::Expired;
            return Err(SecurityErrorCode::EnrollmentExpired);
        }
        if self.state != expected {
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        let legal = matches!(
            (self.state, target),
            (
                CommissionerEnrollmentState::Idle,
                CommissionerEnrollmentState::CandidateSelected
            ) | (
                CommissionerEnrollmentState::CandidateSelected,
                CommissionerEnrollmentState::SecretAcquired
            ) | (
                CommissionerEnrollmentState::SecretAcquired,
                CommissionerEnrollmentState::Negotiating
            ) | (
                CommissionerEnrollmentState::Negotiating,
                CommissionerEnrollmentState::KeyConfirmed
            ) | (
                CommissionerEnrollmentState::KeyConfirmed,
                CommissionerEnrollmentState::AwaitingOperatorApproval
            ) | (
                CommissionerEnrollmentState::AwaitingOperatorApproval,
                CommissionerEnrollmentState::IssuingCredential
            ) | (
                CommissionerEnrollmentState::IssuingCredential,
                CommissionerEnrollmentState::AwaitingInstallReceipt
            ) | (
                CommissionerEnrollmentState::AwaitingInstallReceipt,
                CommissionerEnrollmentState::Complete
            )
        );
        if !legal {
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        self.state = target;
        self.record("security.enrollment.commissioner_transition");
        Ok(())
    }
    pub fn complete_verified_install(
        &mut self,
        now: u64,
        hmac_valid: bool,
        proof_valid: bool,
    ) -> Result<(), SecurityErrorCode> {
        if !hmac_valid || !proof_valid {
            self.consumed = true;
            self.state = CommissionerEnrollmentState::Failed;
            return Err(SecurityErrorCode::AuthenticationFailed);
        }
        self.transition(
            CommissionerEnrollmentState::AwaitingInstallReceipt,
            CommissionerEnrollmentState::Complete,
            now,
        )?;
        self.consumed = true;
        self.record("security.enrollment.install_verified");
        Ok(())
    }
    pub fn cancel(&mut self) {
        self.consumed = true;
        self.state = CommissionerEnrollmentState::Cancelled;
        self.record("security.enrollment.cancelled");
    }
    pub fn fail(&mut self) {
        self.consumed = true;
        self.state = CommissionerEnrollmentState::Failed;
        self.record("security.enrollment.failed");
    }
    fn record(&self, event: &str) {
        if let Some(audit) = &self.audit {
            audit.record(
                event,
                &BTreeMap::from([
                    ("enrollment_id".into(), self.enrollment_id.as_str().into()),
                    ("attempt_id".into(), self.attempt_id.as_str().into()),
                    ("state".into(), format!("{:?}", self.state)),
                ]),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeterministicRandom {
        fixture: Vec<u8>,
        offset: std::sync::Mutex<usize>,
    }
    impl SecureRandomProvider for DeterministicRandom {
        fn bytes(&self, count: usize) -> Result<SecretBytes, SecurityErrorCode> {
            let mut offset = self
                .offset
                .lock()
                .map_err(|_| SecurityErrorCode::StorageFailed)?;
            let end = offset
                .checked_add(count)
                .ok_or(SecurityErrorCode::ResourceLimit)?;
            let value = self
                .fixture
                .get(*offset..end)
                .ok_or(SecurityErrorCode::ResourceLimit)?;
            *offset = end;
            SecretBytes::new(value.to_vec())
        }
    }

    struct DeterministicClock(u64, ClockTrustState);
    impl SecurityClock for DeterministicClock {
        fn monotonic_ns(&self) -> u64 {
            self.0
        }
        fn utc_timestamp(&self) -> Option<String> {
            None
        }
        fn trust_state(&self) -> ClockTrustState {
            self.1
        }
    }
    struct FixtureAead;
    impl AeadProvider for FixtureAead {
        fn seal(
            &self,
            _key: &SecretBytes,
            plaintext: &SecretBytes,
            nonce: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, SecurityErrorCode> {
            let mut value = plaintext.expose_to(ToOwned::to_owned);
            value.extend_from_slice(nonce);
            value.extend_from_slice(aad);
            Ok(value)
        }
        fn open(
            &self,
            _key: &SecretBytes,
            _ciphertext: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
        ) -> Result<SecretBytes, SecurityErrorCode> {
            Err(SecurityErrorCode::AuthenticationFailed)
        }
    }
    struct FixtureSpake(bool);
    impl Spake2PlusOperation for FixtureSpake {
        fn receive_peer_share(&mut self, share: &[u8]) -> Result<Vec<u8>, SecurityErrorCode> {
            Ok(share.to_vec())
        }
        fn verify_confirmation(&mut self, value: &[u8]) -> Result<(), SecurityErrorCode> {
            if self.0 && value == b"valid" {
                Ok(())
            } else {
                Err(SecurityErrorCode::AuthenticationFailed)
            }
        }
    }
    #[test]
    fn secrets_are_not_debug_or_clone() {
        let secret = SecretBytes::new(vec![0xaa; 32]).unwrap();
        assert_eq!(secret.expose_to(|v| v.len()), 32);
    }
    #[test]
    fn deterministic_providers_are_test_scoped_and_bounded() {
        let random = DeterministicRandom {
            fixture: vec![1, 2, 3],
            offset: std::sync::Mutex::new(0),
        };
        assert_eq!(
            random.bytes(2).unwrap().expose_to(|v| v.to_vec()),
            vec![1, 2]
        );
        assert!(random.bytes(2).is_err());
        assert_eq!(
            DeterministicClock(7, ClockTrustState::Untrusted).monotonic_ns(),
            7
        );
    }
    #[test]
    fn hardened_downgrade_is_closed() {
        assert!(!DowngradePolicy::HARDENED_PRODUCTION.permits_unauthenticated(false));
        assert!(!DowngradePolicy::migration(true).permits_unauthenticated(true));
    }
    #[test]
    fn frozen_context_transcript_and_schedule_match() {
        let pairs = [
            ("acp_version", "1.2"),
            ("application", "Aurora Communications Protocol"),
            ("attempt_id", "60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1"),
            (
                "candidate_instance_id",
                "20314253-6475-4869-aa1b-2c3d4e5f6071",
            ),
            ("candidate_node_id", "00112233-4455-4677-8899-aabbccddeeff"),
            (
                "commissioner_instance_id",
                "30415263-7485-496a-ba2b-3c4d5e6f7081",
            ),
            (
                "commissioner_node_id",
                "10213243-5465-4768-9a0b-1c2d3e4f5061",
            ),
            ("enrollment_id", "50617283-94a5-4b6c-9a4b-5c6d7e8f90a1"),
            ("extension_version", "1.0"),
            ("identity_algorithm", "ecdsa_p256_sha256"),
            (
                "identity_key_id",
                "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d",
            ),
            ("purpose", "security.enrollment"),
            (
                "requested_permissions_digest",
                "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0",
            ),
            ("requested_role", "remote"),
            ("suite", "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1"),
            ("trust_domain_id", "40516273-8495-4a6b-8a3b-4c5d6e7f8091"),
        ];
        let context: BTreeMap<_, _> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let encoded = canonical_enrollment_context(&context).unwrap();
        assert_eq!(
            digest_id_for(&encoded),
            "sha256:5236d0f7af47b5953368218918e49f65e023f548119b3b12a132d973c1e8a1c9"
        );
        let keys = derive_enrollment_keys(
            &decode_hex("b9824463682ad84c7cf15c61b4d71a5bab9c5f882e868d04f58a68f6862cdd75"),
            &decode_hex("1713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba"),
        );
        assert_eq!(
            hex(&keys["candidate confirm"]),
            "2e6621403e7994557bcfe9fd9e7b2be4c20fad8ca91d95f7603e5d3016c1d190"
        );
        assert_eq!(
            hex(&keys["SAS"]),
            "944e3bdfdf07dc2a3a8860c84d6587c3fe3db65d64207dd62a7fe4d0531828fa"
        );
        assert_eq!(
            permission_digest(&Json::Object(vec![])).unwrap(),
            "sha256:c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"
        );
    }
    fn decode_hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn enrollment_requires_durable_install_and_bounds_replay() {
        let enrollment = EnrollmentId::parse("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1").unwrap();
        let attempt = EnrollmentAttemptId::parse("60718293-a4b5-4c6d-aa5b-000000000001").unwrap();
        let mut machine = CandidateEnrollment::new(
            enrollment,
            HashSet::from([SecuritySuite::Raw128]),
            EnrollmentLimits::for_profile(SecurityProfile::Full),
            0,
        );
        machine
            .begin(attempt.clone(), SecuritySuite::Raw128, 1)
            .unwrap();
        machine
            .process_peer_share(&attempt, &mut FixtureSpake(true), b"share", 2)
            .unwrap();
        machine
            .verify_key_confirmation(&attempt, &mut FixtureSpake(true), b"valid", 2)
            .unwrap();
        machine.await_approval(&attempt, 3).unwrap();
        machine.credential_staged(&attempt, 4).unwrap();
        assert_eq!(
            machine.complete(&attempt, 5),
            Err(SecurityErrorCode::StorageFailed)
        );
        machine.durable_install_verified(&attempt, 5).unwrap();
        machine.complete(&attempt, 6).unwrap();
        assert_eq!(machine.state, CandidateEnrollmentState::Enrolled);
        assert_eq!(
            machine.verify_key_confirmation(&attempt, &mut FixtureSpake(true), b"valid", 7),
            Err(SecurityErrorCode::EnrollmentReplayed)
        );
    }

    #[test]
    fn enrollment_concurrency_and_lockout_are_bounded() {
        let enrollment = EnrollmentId::parse("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1").unwrap();
        let mut machine = CandidateEnrollment::new(
            enrollment,
            HashSet::from([SecuritySuite::Raw128]),
            EnrollmentLimits::for_profile(SecurityProfile::Lightweight),
            0,
        );
        for n in 1..=5 {
            let id =
                EnrollmentAttemptId::parse(format!("60718293-a4b5-4c6d-aa5b-{n:012x}")).unwrap();
            machine.begin(id.clone(), SecuritySuite::Raw128, n).unwrap();
            machine.cryptographic_failure(&id);
        }
        assert_eq!(machine.state, CandidateEnrollmentState::Locked);
    }

    #[test]
    fn frozen_approval_and_installation_vectors_match() {
        let transcript =
            decode_hex("1713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba");
        let key_id = "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d";
        let aad: BTreeMap<String, Json> = [
            (
                "message_type",
                Json::String("security.enrollment.approval".into()),
            ),
            (
                "attempt_id",
                Json::String("60718293-a4b5-4c6d-aa5b-6c7d8e9fa0b1".into()),
            ),
            (
                "enrollment_id",
                Json::String("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1".into()),
            ),
            (
                "candidate_node_id",
                Json::String("00112233-4455-4677-8899-aabbccddeeff".into()),
            ),
            (
                "commissioner_node_id",
                Json::String("10213243-5465-4768-9a0b-1c2d3e4f5061".into()),
            ),
            (
                "trust_domain_id",
                Json::String("40516273-8495-4a6b-8a3b-4c5d6e7f8091".into()),
            ),
            ("acp_version", Json::String("1.2".into())),
            ("extension_version", Json::String("1.0".into())),
            (
                "suite",
                Json::String("ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1".into()),
            ),
            (
                "identity_algorithm",
                Json::String("ecdsa_p256_sha256".into()),
            ),
            ("identity_key_id", Json::String(key_id.into())),
            ("transcript_hash", Json::Bytes(transcript.clone())),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect();
        assert_eq!(hex(&canonical_approval_aad(&aad).unwrap()), "ac657375697465782f4143502d5350414b4532504c55532d503235362d5348413235362d484b44465348413235362d5241573132382d76316a617474656d70745f6964782436303731383239332d613462352d346336642d616135622d3663376438653966613062316b6163705f76657273696f6e63312e326c6d6573736167655f74797065781c73656375726974792e656e726f6c6c6d656e742e617070726f76616c6d656e726f6c6c6d656e745f6964782435303631373238332d393461352d346236632d396134622d3563366437653866393061316f6964656e746974795f6b65795f696478477368613235363a663363396431333536303433343638323461353638626130393235316633313138653031383462343137666165393732613636363638666633663933643735646f7472616e7363726970745f6861736858201713be11b1b0ef86de03b3eca4dbc6d1ae1309f4dda0b0c842b9e9b442b673ba6f74727573745f646f6d61696e5f6964782434303531363237332d383439352d346136622d386133622d3463356436653766383039317163616e6469646174655f6e6f64655f6964782430303131323233332d343435352d343637372d383839392d61616262636364646565666671657874656e73696f6e5f76657273696f6e63312e30726964656e746974795f616c676f726974686d7165636473615f703235365f73686132353674636f6d6d697373696f6e65725f6e6f64655f6964782431303231333234332d353436352d343736382d396130622d316332643365346635303631");
        let credential = "sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20";
        assert_eq!(
            hex(&install_proof_digest(&transcript, credential).unwrap()),
            "e7e2cd80703a6adfe8fa6aeb725e3d735d79cb0972719a9553d264f7cda1f350"
        );
    }

    #[test]
    fn suite_intersection_and_deadline_overflow_fail_closed() {
        let supported = HashSet::from([SecuritySuite::Raw128]);
        assert_eq!(
            select_enrollment_suite(
                &[SecuritySuite::Pbkdf2_100k, SecuritySuite::Raw128],
                &supported
            ),
            Ok(SecuritySuite::Raw128)
        );
        assert_eq!(
            select_enrollment_suite(&[SecuritySuite::Pbkdf2_100k], &supported),
            Err(SecurityErrorCode::NoCommonSuite)
        );
    }
    #[test]
    fn approval_key_is_one_shot() {
        let random = DeterministicRandom {
            fixture: (0..12).collect(),
            offset: std::sync::Mutex::new(0),
        };
        let mut protector = OneShotApprovalProtector::new(&FixtureAead, &random);
        let id = EnrollmentAttemptId::parse("60718293-a4b5-4c6d-aa5b-000000000001").unwrap();
        let key = SecretBytes::new(vec![1; 32]).unwrap();
        let plaintext = SecretBytes::new(vec![2]).unwrap();
        assert_eq!(
            protector
                .seal(id.clone(), &key, &plaintext, b"aad")
                .unwrap()
                .0,
            (0..12).collect::<Vec<_>>()
        );
        assert_eq!(
            protector.seal(id, &key, &plaintext, b"aad"),
            Err(SecurityErrorCode::EnrollmentReplayed)
        );
    }

    #[test]
    fn missing_and_duplicate_peer_shares_consume_attempts() {
        let enrollment = EnrollmentId::parse("50617283-94a5-4b6c-9a4b-5c6d7e8f90a1").unwrap();
        let mut missing = CandidateEnrollment::new(
            enrollment.clone(),
            HashSet::from([SecuritySuite::Raw128]),
            EnrollmentLimits::for_profile(SecurityProfile::Lightweight),
            0,
        );
        let missing_id =
            EnrollmentAttemptId::parse("60718293-a4b5-4c6d-aa5b-000000000008").unwrap();
        missing
            .begin(missing_id.clone(), SecuritySuite::Raw128, 1)
            .unwrap();
        assert_eq!(
            missing.verify_key_confirmation(&missing_id, &mut FixtureSpake(true), b"valid", 2),
            Err(SecurityErrorCode::AuthenticationFailed)
        );

        let mut duplicate = CandidateEnrollment::new(
            enrollment,
            HashSet::from([SecuritySuite::Raw128]),
            EnrollmentLimits::for_profile(SecurityProfile::Lightweight),
            0,
        );
        let duplicate_id =
            EnrollmentAttemptId::parse("60718293-a4b5-4c6d-aa5b-000000000009").unwrap();
        duplicate
            .begin(duplicate_id.clone(), SecuritySuite::Raw128, 1)
            .unwrap();
        duplicate
            .process_peer_share(&duplicate_id, &mut FixtureSpake(true), b"share", 2)
            .unwrap();
        assert_eq!(
            duplicate.process_peer_share(&duplicate_id, &mut FixtureSpake(true), b"share", 3),
            Err(SecurityErrorCode::AuthenticationFailed)
        );
    }
}
