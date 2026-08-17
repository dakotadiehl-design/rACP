//! JSON + ACP-CDE-1.2 envelope codec.

mod cbor;

use acp_model::{Endpoint, Envelope, Json, Qos};
use std::collections::BTreeSet;

pub use cbor::{decode as decode_cbor_value, encode as encode_cbor_value, CborError};

#[derive(Debug)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CodecError {}

fn cerr(msg: impl Into<String>) -> CodecError {
    CodecError(msg.into())
}

pub fn json_from_serde(v: &serde_json::Value) -> Json {
    match v {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(b) => Json::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Json::Int(i)
            } else if let Some(u) = n.as_u64() {
                Json::UInt(u)
            } else {
                Json::Float(n.as_f64().unwrap())
            }
        }
        serde_json::Value::String(s) => Json::String(s.clone()),
        serde_json::Value::Array(a) => Json::Array(a.iter().map(json_from_serde).collect()),
        serde_json::Value::Object(o) => Json::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), json_from_serde(v)))
                .collect(),
        ),
    }
}

pub fn serde_from_json(v: &Json) -> serde_json::Value {
    match v {
        Json::Null => serde_json::Value::Null,
        Json::Bool(b) => serde_json::Value::Bool(*b),
        Json::Int(i) => serde_json::json!(i),
        Json::UInt(u) => serde_json::json!(u),
        Json::Float(f) => serde_json::json!(f),
        Json::String(s) => serde_json::Value::String(s.clone()),
        Json::Bytes(b) => serde_json::Value::String(b.iter().map(|x| format!("{x:02x}")).collect()),
        Json::Array(a) => serde_json::Value::Array(a.iter().map(serde_from_json).collect()),
        Json::Object(o) => {
            let mut map = serde_json::Map::new();
            for (k, v) in o {
                map.insert(k.clone(), serde_from_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

fn endpoint_from(v: &Json) -> Result<Endpoint, CodecError> {
    let Json::Object(pairs) = v else {
        return Err(cerr("endpoint must be object"));
    };
    let mut node_id = None;
    let mut component_id = None;
    for (k, val) in pairs {
        match (k.as_str(), val) {
            ("node_id", Json::String(s)) => node_id = Some(s.clone()),
            ("component_id", Json::String(s)) => component_id = Some(s.clone()),
            _ => {}
        }
    }
    Ok(Endpoint {
        node_id: node_id.ok_or_else(|| cerr("missing node_id"))?,
        component_id,
    })
}

fn endpoint_json(ep: &Endpoint) -> Json {
    let mut pairs = vec![("node_id".into(), Json::String(ep.node_id.clone()))];
    if let Some(c) = &ep.component_id {
        pairs.push(("component_id".into(), Json::String(c.clone())));
    }
    Json::Object(pairs)
}

pub fn envelope_to_json(env: &Envelope) -> Json {
    let mut pairs = vec![
        ("acp".into(), Json::String(env.acp.clone())),
        ("message_id".into(), Json::String(env.message_id.clone())),
        ("type".into(), Json::String(env.message_type.clone())),
        ("source".into(), endpoint_json(&env.source)),
        (
            "timestamp_utc".into(),
            Json::String(env.timestamp_utc.clone()),
        ),
        ("qos".into(), Json::String(env.qos.as_str().into())),
        (
            "flags".into(),
            Json::Array(env.flags.iter().cloned().map(Json::String).collect()),
        ),
        ("payload".into(), env.payload.clone()),
    ];
    if let Some(d) = &env.destination {
        pairs.push(("destination".into(), endpoint_json(d)));
    }
    if let Some(s) = &env.session_id {
        pairs.push(("session_id".into(), Json::String(s.clone())));
    }
    if let Some(seq) = env.sequence {
        pairs.push(("sequence".into(), Json::UInt(seq)));
    }
    if let Some(c) = &env.correlation_id {
        pairs.push(("correlation_id".into(), Json::String(c.clone())));
    }
    if let Some(c) = &env.causation_id {
        pairs.push(("causation_id".into(), Json::String(c.clone())));
    }
    Json::Object(pairs)
}

pub fn envelope_from_json(value: &Json) -> Result<Envelope, CodecError> {
    let Json::Object(pairs) = value else {
        return Err(cerr("envelope must be object"));
    };
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let req_str = |k: &str| match get(k) {
        Some(Json::String(s)) => Ok(s.clone()),
        _ => Err(cerr(format!("missing {k}"))),
    };
    let qos = Qos::parse(&req_str("qos")?).ok_or_else(|| cerr("bad qos"))?;
    let flags = match get("flags") {
        Some(Json::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                Json::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    let sequence = match get("sequence") {
        Some(Json::Int(i)) if *i >= 0 => Some(*i as u64),
        Some(Json::UInt(u)) => Some(*u),
        _ => None,
    };
    Ok(Envelope {
        acp: req_str("acp")?,
        message_id: req_str("message_id")?,
        message_type: req_str("type")?,
        source: endpoint_from(get("source").ok_or_else(|| cerr("missing source"))?)?,
        destination: match get("destination") {
            Some(v) => Some(endpoint_from(v)?),
            None => None,
        },
        session_id: match get("session_id") {
            Some(Json::String(s)) => Some(s.clone()),
            _ => None,
        },
        sequence,
        timestamp_utc: req_str("timestamp_utc")?,
        correlation_id: match get("correlation_id") {
            Some(Json::String(s)) => Some(s.clone()),
            _ => None,
        },
        causation_id: match get("causation_id") {
            Some(Json::String(s)) => Some(s.clone()),
            _ => None,
        },
        qos,
        flags,
        payload: get("payload").cloned().unwrap_or(Json::Object(vec![])),
    })
}

pub fn encode_json(env: &Envelope) -> Result<Vec<u8>, CodecError> {
    let v = serde_from_json(&envelope_to_json(env));
    serde_json::to_vec(&v).map_err(|e| cerr(e.to_string()))
}

pub fn decode_json(raw: &[u8]) -> Result<Envelope, CodecError> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(|e| cerr(e.to_string()))?;
    envelope_from_json(&json_from_serde(&v))
}

pub fn encode_cbor(env: &Envelope) -> Result<Vec<u8>, CodecError> {
    let map = match envelope_to_json(env) {
        Json::Object(p) => p,
        _ => return Err(cerr("internal")),
    };
    encode_cbor_envelope(&map)
}

fn encode_cbor_envelope(pairs: &[(String, Json)]) -> Result<Vec<u8>, CodecError> {
    // Convert timestamp_utc string into tagged string via a custom Json we write specially.
    let mut prepared: Vec<(String, Prepared)> = pairs
        .iter()
        .map(|(k, v)| {
            if k == "timestamp_utc" {
                if let Json::String(s) = v {
                    return (k.clone(), Prepared::Tag0(s.clone()));
                }
            }
            (k.clone(), Prepared::Plain(v.clone()))
        })
        .collect();
    // CDE sort by encoded key
    let mut encoded_keys: Vec<(Vec<u8>, Prepared)> = Vec::new();
    for (k, v) in prepared.drain(..) {
        let kb = encode_cbor_value(&Json::String(k)).map_err(|e| cerr(e.0))?;
        encoded_keys.push((kb, v));
    }
    encoded_keys.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    // map header
    let n = encoded_keys.len() as u64;
    if n < 24 {
        out.push(0xa0 | n as u8);
    } else if n < 256 {
        out.push(0xb8);
        out.push(n as u8);
    } else {
        out.push(0xb9);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
    for (k, v) in encoded_keys {
        out.extend_from_slice(&k);
        match v {
            Prepared::Plain(j) => out.extend(encode_cbor_value(&j).map_err(|e| cerr(e.0))?),
            Prepared::Tag0(s) => {
                out.push(0xc0);
                out.extend(encode_cbor_value(&Json::String(s)).map_err(|e| cerr(e.0))?);
            }
        }
    }
    Ok(out)
}

enum Prepared {
    Plain(Json),
    Tag0(String),
}

pub fn decode_cbor(raw: &[u8]) -> Result<Envelope, CodecError> {
    let v = decode_cbor_value(raw).map_err(|e| cerr(e.0))?;
    envelope_from_json(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p
    }

    #[test]
    fn golden_vectors() {
        let root = repo_root();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("vectors/manifest.json")).unwrap())
                .unwrap();
        for item in manifest["vectors"].as_array().unwrap() {
            let json_path = root.join("vectors").join(item["json"].as_str().unwrap());
            let cbor_path = root.join("vectors").join(item["cbor"].as_str().unwrap());
            let raw_json = fs::read(&json_path).unwrap();
            let env = decode_json(&raw_json).expect(item["id"].as_str().unwrap());
            let encoded = encode_cbor(&env).unwrap();
            let pinned = fs::read(&cbor_path).unwrap();
            assert_eq!(encoded, pinned, "cbor mismatch {}", item["id"]);
            let again = decode_cbor(&pinned).unwrap();
            assert_eq!(again.acp, env.acp);
            assert_eq!(again.message_type, env.message_type);
            assert_eq!(again.message_id, env.message_id);
        }
    }

    #[test]
    fn reject_indefinite() {
        assert!(decode_cbor_value(&[0x9f, 0x01, 0xff]).is_err());
    }

    #[test]
    fn reject_shared_malformed_corpus() {
        let dir = repo_root().join("vectors/malformed");
        let mut seen = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("cbor") {
                continue;
            }
            seen += 1;
            let raw = fs::read(&path).unwrap();
            assert!(
                decode_cbor_value(&raw).is_err(),
                "expected reject {}",
                path.display()
            );
        }
        assert!(seen >= 4, "expected shared malformed corpus");
    }

    #[test]
    fn preferred_ints_roundtrip() {
        for n in [0i64, 23, 24, 255, 256, 65535, 65536, i64::MAX, -1, -24, -25] {
            let v = Json::Int(n);
            let raw = encode_cbor_value(&v).unwrap();
            assert_eq!(decode_cbor_value(&raw).unwrap(), v, "int {n}");
        }
    }
}
