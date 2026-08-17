//! ACP typed models. No Tokio.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Conductor,
    Prism,
    Lyric,
    Bridge,
    Tool,
    Simulator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Conductor => "conductor",
            Role::Prism => "prism",
            Role::Lyric => "lyric",
            Role::Bridge => "bridge",
            Role::Tool => "tool",
            Role::Simulator => "simulator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "conductor" => Some(Self::Conductor),
            "prism" => Some(Self::Prism),
            "lyric" => Some(Self::Lyric),
            "bridge" => Some(Self::Bridge),
            "tool" => Some(Self::Tool),
            "simulator" => Some(Self::Simulator),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub instance_id: String,
    pub role: Role,
    pub name: String,
    pub product_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRange {
    pub min: String,
    pub max: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub node_id: String,
    pub component_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qos {
    Reliable,
    Latest,
    BestEffort,
}

impl Qos {
    pub fn as_str(self) -> &'static str {
        match self {
            Qos::Reliable => "reliable",
            Qos::Latest => "latest",
            Qos::BestEffort => "best_effort",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reliable" => Some(Self::Reliable),
            "latest" => Some(Self::Latest),
            "best_effort" => Some(Self::BestEffort),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub acp: String,
    pub message_id: String,
    pub message_type: String,
    pub source: Endpoint,
    pub destination: Option<Endpoint>,
    pub session_id: Option<String>,
    pub sequence: Option<u64>,
    pub timestamp_utc: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub qos: Qos,
    pub flags: BTreeSet<String>,
    pub payload: Json,
}

/// Minimal JSON-like value used on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn object(pairs: Vec<(&str, Json)>) -> Self {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            Json::UInt(u) if *u <= i64::MAX as u64 => Some(*u as i64),
            _ => None,
        }
    }
}

pub const PROTOCOL_VERSION: &str = "1.2";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_baseline() {
        assert_eq!(PROTOCOL_VERSION, "1.2");
    }
}
