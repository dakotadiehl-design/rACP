//! JSON + ACP-CDE-1.2 envelope codec.

mod cbor;
mod schema;

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

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(B64[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn b64_decode(text: &str) -> Result<Vec<u8>, CodecError> {
    let raw = text.as_bytes();
    if raw.len() % 4 != 0 {
        return Err(cerr("invalid resource.chunk base64"));
    }
    let mut table = [0xffu8; 256];
    for (i, b) in B64.iter().enumerate() {
        table[*b as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let mut vals = [0u8; 4];
        let mut pads = 0;
        for (j, slot) in vals.iter_mut().enumerate() {
            let c = raw[i + j];
            if c == b'=' {
                pads += 1;
                *slot = 0;
                continue;
            }
            if pads > 0 || table[c as usize] == 0xff {
                return Err(cerr("invalid resource.chunk base64"));
            }
            *slot = table[c as usize];
        }
        if pads > 2 {
            return Err(cerr("invalid resource.chunk base64"));
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if pads < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if pads < 1 {
            out.push((vals[2] << 6) | vals[3]);
        }
        i += 4;
    }
    Ok(out)
}

fn json_uint(value: &Json) -> Option<u64> {
    match value {
        Json::UInt(u) => Some(*u),
        Json::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn normalize_chunk_payload(message_type: &str, payload: Json) -> Result<Json, CodecError> {
    if message_type != "resource.chunk" {
        return Ok(payload);
    }
    let Json::Object(mut pairs) = payload else {
        return Ok(payload);
    };
    let Some(idx) = pairs.iter().position(|(k, _)| k == "data") else {
        return Ok(Json::Object(pairs));
    };
    let decoded = match &pairs[idx].1 {
        Json::String(s) => b64_decode(s)?,
        Json::Bytes(b) => b.clone(),
        _ => return Err(cerr("resource.chunk data must be base64 or bytes")),
    };
    if let Some(declared) = pairs
        .iter()
        .find(|(k, _)| k == "length")
        .and_then(|(_, v)| json_uint(v))
    {
        if declared != decoded.len() as u64 {
            return Err(cerr("resource.chunk length does not match decoded bytes"));
        }
    }
    pairs[idx].1 = Json::Bytes(decoded);
    Ok(Json::Object(pairs))
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
        Json::Bytes(b) => serde_json::Value::String(b64_encode(b)),
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
        payload: normalize_chunk_payload(
            &req_str("type")?,
            get("payload").cloned().unwrap_or(Json::Object(vec![])),
        )?,
    })
}

pub fn encode_json(env: &Envelope) -> Result<Vec<u8>, CodecError> {
    let v = serde_from_json(&envelope_to_json(env));
    serde_json::to_vec(&v).map_err(|e| cerr(e.to_string()))
}

pub fn decode_json(raw: &[u8]) -> Result<Envelope, CodecError> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(|e| cerr(e.to_string()))?;
    let env = envelope_from_json(&json_from_serde(&v))?;
    schema::validate_envelope(&env)?;
    Ok(env)
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
    let env = envelope_from_json(&v)?;
    schema::validate_envelope(&env)?;
    Ok(env)
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
            let id = item["id"].as_str().unwrap();
            let env = decode_json(&raw_json).unwrap_or_else(|err| panic!("{id}: {err}"));
            let encoded = encode_cbor(&env).unwrap();
            let pinned = fs::read(&cbor_path).unwrap();
            assert_eq!(encoded, pinned, "cbor mismatch {}", item["id"]);
            let again = decode_cbor(&pinned).unwrap();
            assert_eq!(
                serde_from_json(&envelope_to_json(&again)),
                serde_from_json(&envelope_to_json(&env)),
                "decoded envelope mismatch {id}"
            );
            let reencoded = encode_json(&again).unwrap();
            let via_json = decode_json(&reencoded).unwrap();
            assert_eq!(
                serde_from_json(&envelope_to_json(&via_json)),
                serde_from_json(&envelope_to_json(&env)),
                "json re-encode mismatch {id}"
            );
        }
    }

    #[test]
    fn chunk_bytes_roundtrip_and_reject_bad_base64() {
        let raw_json = br#"{
          "acp":"1.2",
          "message_id":"0193f8d8-4c4e-7d8b-a2ab-000000000040",
          "type":"resource.chunk",
          "source":{"node_id":"0193f8d8-4c4e-7d8b-a2ab-000000000001"},
          "timestamp_utc":"2026-08-17T16:42:15.231Z",
          "qos":"reliable",
          "flags":[],
          "payload":{"transfer_id":"0193f8d8-4c4e-7d8b-a2ab-000000000070","offset":0,"length":4,"data":"AAH/4A=="}
        }"#;
        let env = decode_json(raw_json).unwrap();
        match env.payload.get("data") {
            Some(Json::Bytes(b)) => assert_eq!(b, &vec![0x00, 0x01, 0xff, 0xe0]),
            other => panic!("expected bytes {other:?}"),
        }
        let cbor = encode_cbor(&env).unwrap();
        assert!(cbor.contains(&0x44));
        let again = decode_cbor(&cbor).unwrap();
        assert_eq!(again.payload.get("data"), env.payload.get("data"));
        let json = encode_json(&again).unwrap();
        let text = String::from_utf8(json).unwrap();
        assert!(text.contains("AAH/4A=="), "{text}");
        let bad = String::from_utf8_lossy(raw_json).replace("AAH/4A==", "!!!!");
        assert!(decode_json(bad.as_bytes()).is_err());
    }

    #[test]
    fn remote_momentary_end_lease_conditional() {
        let with_lease = br#"{
          "acp":"1.2",
          "message_id":"0193f8d8-4c4e-7d8b-a2ab-000000000042",
          "type":"remote.control.invoke",
          "source":{"node_id":"0193f8d8-4c4e-7d8b-a2ab-0000000000b0"},
          "timestamp_utc":"2026-08-17T16:42:15.231Z",
          "qos":"reliable",
          "flags":[],
          "payload":{
            "control_id":"fog_burst",
            "invocation_id":"0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
            "interaction":"momentary_end",
            "lease_id":"0193f8d8-4c4e-7d8b-a2ab-0000000000aa",
            "idempotency_key":"0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
          }
        }"#;
        assert!(decode_json(with_lease).is_ok());
        let activate = br#"{
          "acp":"1.2",
          "message_id":"0193f8d8-4c4e-7d8b-a2ab-000000000042",
          "type":"remote.control.invoke",
          "source":{"node_id":"0193f8d8-4c4e-7d8b-a2ab-0000000000b0"},
          "timestamp_utc":"2026-08-17T16:42:15.231Z",
          "qos":"reliable",
          "flags":[],
          "payload":{
            "control_id":"cue_go",
            "invocation_id":"0193f8d8-4c4e-7d8b-a2ab-0000000000d1",
            "interaction":"activate",
            "idempotency_key":"0193f8d8-4c4e-7d8b-a2ab-0000000000d1"
          }
        }"#;
        assert!(decode_json(activate).is_ok());
    }

    #[test]
    fn invalid_corpus_rejected() {
        let dir = repo_root().join("vectors/invalid");
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
        for item in manifest["vectors"].as_array().unwrap() {
            let path = repo_root()
                .join("vectors")
                .join(item["json"].as_str().unwrap());
            let raw = fs::read(&path).unwrap();
            let err = decode_json(&raw).expect_err(item["id"].as_str().unwrap());
            let expected = item["error"].as_str().unwrap();
            assert!(
                err.0.starts_with(expected) || err.0.contains(expected),
                "{}: {}",
                item["id"],
                err.0
            );
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
