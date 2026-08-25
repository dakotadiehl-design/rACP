use crate::{
    AuthenticationMode, CredentialFormat, CredentialId, CredentialStatus, IdentityKeyId,
    SecurityErrorCode, SecurityNodeId, SecurityProfile, TransportEvidence, TrustDomainId,
};
use acp_model::Json;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const HELLO_EXPORTER_LABEL: &str = "EXPORTER-Aurora-ACP-1.2-HELLO";

pub trait TlsExporter {
    fn export(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, SecurityErrorCode>;
}

pub struct FullTlsHandshake {
    pub protocol: String,
    pub mutual_authentication: bool,
    pub isolated_trust_store: bool,
    pub peer_certificate_valid: bool,
    pub local_credential_selected: bool,
    pub peer_san_extracted: bool,
    pub trust_domain_id: TrustDomainId,
    pub node_id: SecurityNodeId,
    pub credential_id: CredentialId,
    pub identity_key_id: IdentityKeyId,
    pub role_constraints: HashSet<String>,
    pub credential_status: CredentialStatus,
    pub zero_rtt_used: bool,
    pub resumption_used: bool,
}

fn field<'a>(object: &'a [(String, Json)], key: &str) -> Result<&'a Json, SecurityErrorCode> {
    object
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .ok_or(SecurityErrorCode::CredentialInvalid)
}

fn closed(object: &[(String, Json)], keys: &[&str]) -> Result<Json, SecurityErrorCode> {
    Ok(Json::Object(
        keys.iter()
            .map(|key| Ok(((*key).into(), field(object, key)?.clone())))
            .collect::<Result<Vec<_>, SecurityErrorCode>>()?,
    ))
}

fn capabilities(value: &Json) -> Result<Json, SecurityErrorCode> {
    let Json::Array(values) = value else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    Ok(Json::Array(
        values
            .iter()
            .map(|value| {
                let Json::Object(fields) = value else {
                    return Err(SecurityErrorCode::CredentialInvalid);
                };
                closed(fields, &["id", "version"])
            })
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

pub fn hello_exporter_context(hello: &Json) -> Result<[u8; 32], SecurityErrorCode> {
    let Json::Object(root) = hello else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    let Json::Object(node) = field(root, "node")? else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    let Json::Object(protocol) = field(root, "protocol")? else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    let Json::Object(auth) = field(root, "auth")? else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    for key in ["encodings", "profiles", "capabilities"] {
        if !matches!(field(root, key)?, Json::Array(_)) {
            return Err(SecurityErrorCode::CredentialInvalid);
        }
    }
    let projected = Json::Object(vec![
        (
            "node".into(),
            closed(node, &["node_id", "instance_id", "role", "name"])?,
        ),
        ("protocol".into(), closed(protocol, &["min", "max"])?),
        ("encodings".into(), field(root, "encodings")?.clone()),
        ("profiles".into(), field(root, "profiles")?.clone()),
        (
            "capabilities".into(),
            capabilities(field(root, "capabilities")?)?,
        ),
        (
            "auth".into(),
            match closed(
                auth,
                &[
                    "mode",
                    "trust_domain_id",
                    "credential_id",
                    "identity_key_id",
                    "security_capabilities",
                ],
            )? {
                Json::Object(mut value) => {
                    let index = value
                        .iter()
                        .position(|(key, _)| key == "security_capabilities")
                        .ok_or(SecurityErrorCode::CredentialInvalid)?;
                    value[index].1 = capabilities(&value[index].1)?;
                    Json::Object(value)
                }
                _ => unreachable!(),
            },
        ),
    ]);
    let encoded = acp_codec::encode_cbor_value(&projected)
        .map_err(|_| SecurityErrorCode::CredentialInvalid)?;
    Ok(Sha256::digest(encoded).into())
}

pub fn full_transport_evidence(
    hello: &Json,
    handshake: FullTlsHandshake,
    exporter: &dyn TlsExporter,
) -> Result<TransportEvidence, SecurityErrorCode> {
    if handshake.protocol != "TLSv1.3"
        || !handshake.mutual_authentication
        || !handshake.isolated_trust_store
        || !handshake.peer_certificate_valid
        || !handshake.local_credential_selected
        || !handshake.peer_san_extracted
    {
        return Err(SecurityErrorCode::AuthenticationFailed);
    }
    if handshake.zero_rtt_used || handshake.resumption_used {
        return Err(SecurityErrorCode::DowngradeForbidden);
    }
    match handshake.credential_status {
        CredentialStatus::Active => {}
        CredentialStatus::Revoked => return Err(SecurityErrorCode::CredentialRevoked),
        CredentialStatus::Expired => return Err(SecurityErrorCode::CredentialExpired),
        _ => return Err(SecurityErrorCode::CredentialInvalid),
    }
    let context = hello_exporter_context(hello)?;
    let exported = exporter.export(HELLO_EXPORTER_LABEL, &context, 32)?;
    if exported.len() != 32 {
        return Err(SecurityErrorCode::AuthenticationFailed);
    }
    let Json::Object(root) = hello else {
        unreachable!()
    };
    let Json::Object(auth) = field(root, "auth")? else {
        return Err(SecurityErrorCode::CredentialInvalid);
    };
    let claimed = match field(auth, "channel_binding")? {
        Json::Bytes(value) => value,
        _ => return Err(SecurityErrorCode::CredentialInvalid),
    };
    if !crate::channel_bindings_equal(claimed, &exported) {
        return Err(SecurityErrorCode::AuthenticationFailed);
    }
    let binding: [u8; 32] = exported
        .try_into()
        .map_err(|_| SecurityErrorCode::AuthenticationFailed)?;
    Ok(TransportEvidence {
        mode: AuthenticationMode::AuroraTrust,
        profile: SecurityProfile::Full,
        trust_domain_id: handshake.trust_domain_id,
        node_id: handshake.node_id,
        credential_id: handshake.credential_id,
        identity_key_id: handshake.identity_key_id,
        credential_format: CredentialFormat::X509Der,
        channel_binding: Some(binding),
        credential_status: CredentialStatus::Active,
        channel_binding_verified: true,
        zero_rtt_used: false,
        resumption_used: false,
        role_constraints: handshake.role_constraints,
    })
}

pub fn parse_lightweight_preface(
    data: &[u8],
    validate: impl FnOnce(&[u8]) -> Result<TransportEvidence, SecurityErrorCode>,
) -> Result<(TransportEvidence, &[u8]), SecurityErrorCode> {
    if data.len() < 3 {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if !(1..=2048).contains(&length) || data.len() != length + 2 {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    let evidence = validate(&data[2..])?;
    if evidence.profile != SecurityProfile::Lightweight
        || evidence.credential_status != CredentialStatus::Active
    {
        return Err(SecurityErrorCode::CredentialInvalid);
    }
    Ok((evidence, &data[2..]))
}

pub fn verify_lightweight_finished(
    exported_key: &[u8],
    context: &[u8],
    received: &[u8],
) -> Result<(), SecurityErrorCode> {
    if exported_key.len() != 32 || context.len() > 8192 || received.len() != 32 {
        return Err(SecurityErrorCode::AuthenticationFailed);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(exported_key)
        .map_err(|_| SecurityErrorCode::AuthenticationFailed)?;
    mac.update(context);
    mac.verify_slice(received)
        .map_err(|_| SecurityErrorCode::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedExporter;
    impl TlsExporter for FixedExporter {
        fn export(
            &self,
            label: &str,
            context: &[u8],
            length: usize,
        ) -> Result<Vec<u8>, SecurityErrorCode> {
            if label != HELLO_EXPORTER_LABEL || context.len() != 32 || length != 32 {
                return Err(SecurityErrorCode::AuthenticationFailed);
            }
            Ok(vec![0x65; 32])
        }
    }
    fn handshake() -> FullTlsHandshake {
        FullTlsHandshake {
            protocol: "TLSv1.3".into(),
            mutual_authentication: true,
            isolated_trust_store: true,
            peer_certificate_valid: true,
            local_credential_selected: true,
            peer_san_extracted: true,
            trust_domain_id: TrustDomainId::parse("40516273-8495-4a6b-8a3b-4c5d6e7f8091").unwrap(),
            node_id: SecurityNodeId::parse("00112233-4455-4677-8899-aabbccddeeff").unwrap(),
            credential_id: CredentialId::parse(
                "sha256:466363fece7088b31d8e677611eab7caab29f8aef3bfd4e207c63c17bd4cfb20",
            )
            .unwrap(),
            identity_key_id: IdentityKeyId::parse(
                "sha256:f3c9d135604346824a568ba09251f3118e0184b417fae972a66668ff3f93d75d",
            )
            .unwrap(),
            role_constraints: HashSet::from(["remote".into()]),
            credential_status: CredentialStatus::Active,
            zero_rtt_used: false,
            resumption_used: false,
        }
    }
    #[test]
    fn frozen_hello_context_and_full_evidence() {
        let mut hello = acp_codec::decode_cbor_value(include_bytes!(
            "../../../vectors/security/hello_binding/primary.cbor"
        ))
        .unwrap();
        let Json::Object(root) = &mut hello else {
            panic!()
        };
        let auth_value = &mut root.iter_mut().find(|(key, _)| key == "auth").unwrap().1;
        let Json::Object(auth) = auth_value else {
            panic!()
        };
        auth.push(("channel_binding".into(), Json::Bytes(vec![0x65; 32])));
        assert_eq!(
            hello_exporter_context(&hello).unwrap(),
            hex32("a6b1396ca5417bbd0ac7f680577ed824ad007d784a784cd156b13b0b9c0d0cb9")
        );
        assert!(
            full_transport_evidence(&hello, handshake(), &FixedExporter)
                .unwrap()
                .channel_binding_verified
        );
        let mut invalid = handshake();
        invalid.protocol = "TLSv1.2".into();
        assert_eq!(
            full_transport_evidence(&hello, invalid, &FixedExporter),
            Err(SecurityErrorCode::AuthenticationFailed)
        );
    }
    #[test]
    fn lightweight_preface_and_finished_are_bounded() {
        let mut hello = acp_codec::decode_cbor_value(include_bytes!(
            "../../../vectors/security/hello_binding/primary.cbor"
        ))
        .unwrap();
        let Json::Object(root) = &mut hello else {
            panic!()
        };
        let auth_value = &mut root.iter_mut().find(|(key, _)| key == "auth").unwrap().1;
        let Json::Object(auth) = auth_value else {
            panic!()
        };
        auth.push(("channel_binding".into(), Json::Bytes(vec![0x65; 32])));
        let mut evidence = full_transport_evidence(&hello, handshake(), &FixedExporter).unwrap();
        evidence.profile = SecurityProfile::Lightweight;
        evidence.credential_format = CredentialFormat::CompactV1;
        let credential = b"credential";
        let mut preface = (credential.len() as u16).to_be_bytes().to_vec();
        preface.extend_from_slice(credential);
        let (parsed, raw) = parse_lightweight_preface(&preface, |_| Ok(evidence.clone())).unwrap();
        assert_eq!(parsed, evidence);
        assert_eq!(raw, credential);
        let key = [0x6b; 32];
        let context = b"finished-context";
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(context);
        let finished = mac.finalize().into_bytes();
        assert_eq!(
            verify_lightweight_finished(&key, context, &finished),
            Ok(())
        );
        assert_eq!(
            verify_lightweight_finished(&key, context, &[0; 32]),
            Err(SecurityErrorCode::AuthenticationFailed)
        );
    }
    fn hex32(value: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }
}
