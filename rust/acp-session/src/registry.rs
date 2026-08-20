use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct RegistryRow {
    pub min_protocol: String,
    pub required_capability: Option<String>,
    pub valid_senders: Vec<String>,
    pub valid_destinations: Vec<String>,
    pub qos_allowed: Vec<String>,
    pub legal_before_handshake: bool,
    pub response_type: Option<String>,
    pub min_capability_version: Option<String>,
}

fn table() -> &'static HashMap<String, RegistryRow> {
    static TABLE: OnceLock<HashMap<String, RegistryRow>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let raw = include_str!("../../../schema/registry.json");
        let v: Value = serde_json::from_str(raw).expect("registry json");
        let mut map = HashMap::new();
        for msg in v["messages"].as_array().unwrap() {
            map.insert(
                msg["type"].as_str().unwrap().to_string(),
                RegistryRow {
                    min_protocol: msg["min_protocol"].as_str().unwrap().to_string(),
                    required_capability: msg["required_capability"].as_str().map(str::to_string),
                    valid_senders: msg["valid_senders"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect(),
                    valid_destinations: msg["valid_destinations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect(),
                    qos_allowed: msg["qos_allowed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect(),
                    legal_before_handshake: msg["legal_before_handshake"]
                        .as_bool()
                        .unwrap_or(false),
                    response_type: msg["response_type"].as_str().map(str::to_string),
                    min_capability_version: msg["min_capability_version"]
                        .as_str()
                        .map(str::to_string),
                },
            );
        }
        map
    })
}

pub fn lookup(message_type: &str) -> Option<&'static RegistryRow> {
    table().get(message_type)
}

pub fn allowed(
    message_type: &str,
    sender_role: &str,
    negotiated: &[String],
    handshake_complete: bool,
    qos: Option<&str>,
    envelope_version: Option<&str>,
    negotiated_versions: Option<&HashMap<String, String>>,
) -> Option<&'static str> {
    let Some(row) = lookup(message_type) else {
        return if handshake_complete {
            Some("unsupported_message")
        } else {
            Some("malformed_envelope")
        };
    };
    if !handshake_complete && !row.legal_before_handshake {
        return Some("malformed_envelope");
    }
    if handshake_complete {
        let ver = envelope_version.unwrap_or("1.2");
        if !crate::negotiate::version_at_least(ver, &row.min_protocol) {
            return Some("unsupported_message");
        }
    }
    if let Some(cap) = &row.required_capability {
        if !negotiated.iter().any(|c| c == cap) {
            return Some("capability_not_permitted");
        }
        if let Some(min_cap) = &row.min_capability_version {
            let have = negotiated_versions.and_then(|versions| versions.get(cap));
            let Some(have) = have else {
                return Some("capability_not_permitted");
            };
            if !crate::negotiate::version_at_least(have, min_cap) {
                return Some("capability_not_permitted");
            }
        }
    }
    if !row.valid_senders.iter().any(|s| s == sender_role) {
        return Some("capability_not_permitted");
    }
    if let Some(q) = qos {
        if !row.qos_allowed.iter().any(|a| a == q) {
            return Some("invalid_type");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_capability_version_requires_explicit_version() {
        let mut versions = HashMap::new();
        assert_eq!(
            allowed(
                "remote.control.invoke",
                "remote",
                &["remote.control.invoke".into()],
                true,
                Some("reliable"),
                Some("1.2"),
                None,
            ),
            Some("capability_not_permitted")
        );
        assert_eq!(
            allowed(
                "remote.control.invoke",
                "remote",
                &["remote.control.invoke".into()],
                true,
                Some("reliable"),
                Some("1.2"),
                Some(&versions),
            ),
            Some("capability_not_permitted")
        );
        versions.insert("remote.control.invoke".into(), "not-a-version".into());
        assert_eq!(
            allowed(
                "remote.control.invoke",
                "remote",
                &["remote.control.invoke".into()],
                true,
                Some("reliable"),
                Some("1.2"),
                Some(&versions),
            ),
            Some("capability_not_permitted")
        );
        versions.insert("remote.control.invoke".into(), "0.9".into());
        assert_eq!(
            allowed(
                "remote.control.invoke",
                "remote",
                &["remote.control.invoke".into()],
                true,
                Some("reliable"),
                Some("1.2"),
                Some(&versions),
            ),
            Some("capability_not_permitted")
        );
        versions.insert("remote.control.invoke".into(), "1.0".into());
        assert_eq!(
            allowed(
                "remote.control.invoke",
                "remote",
                &["remote.control.invoke".into()],
                true,
                Some("reliable"),
                Some("1.2"),
                Some(&versions),
            ),
            None
        );
    }
}
