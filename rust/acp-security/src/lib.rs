//! Aurora Trust typed models and narrow cryptographic provider boundaries. No networking.

use acp_model::Json;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        plaintext: &SecretBytes,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityErrorCode>;
    fn open(
        &self,
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
}
