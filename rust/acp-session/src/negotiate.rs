use acp_model::{Capability, ProtocolRange};

pub const ENCODING_PREFERENCE: [&str; 2] = ["cbor", "json"];
pub const HEARTBEAT_MIN_MS: i64 = 100;
pub const HEARTBEAT_MAX_MS: i64 = 60_000;

#[derive(Debug)]
pub struct NegotiateError(pub String);

impl std::fmt::Display for NegotiateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for NegotiateError {}

fn parse_version(text: &str) -> Result<(u32, u32), NegotiateError> {
    let mut parts = text.split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| NegotiateError("bad version".into()))?;
    let minor = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| NegotiateError("bad version".into()))?;
    if parts.next().is_some() {
        return Err(NegotiateError("bad version".into()));
    }
    Ok((major, minor))
}

pub fn select_version(
    client: &ProtocolRange,
    server: &ProtocolRange,
) -> Result<String, NegotiateError> {
    let cmin = parse_version(&client.min)?;
    let cmax = parse_version(&client.max)?;
    let smin = parse_version(&server.min)?;
    let smax = parse_version(&server.max)?;
    if cmin.0 != smin.0 || cmin.0 != cmax.0 || smin.0 != smax.0 || cmin > cmax || smin > smax {
        return Err(NegotiateError(
            "protocol major mismatch or malformed range".into(),
        ));
    }
    let lo = cmin.1.max(smin.1);
    let hi = cmax.1.min(smax.1);
    if lo > hi {
        return Err(NegotiateError("empty protocol intersection".into()));
    }
    Ok(format!("{}.{}", cmin.0, hi))
}

pub fn select_encoding(client: &[String], server: &[String]) -> Result<String, NegotiateError> {
    for enc in ENCODING_PREFERENCE {
        if client.iter().any(|e| e == enc) && server.iter().any(|e| e == enc) {
            return Ok(enc.to_string());
        }
    }
    Err(NegotiateError("no common encoding".into()))
}

pub fn intersect_profiles(local: &[String], peer: &[String]) -> Vec<String> {
    local
        .iter()
        .filter(|name| peer.iter().any(|p| p == *name))
        .cloned()
        .collect()
}

pub fn intersect_capabilities(local: &[Capability], peer: &[Capability]) -> Vec<Capability> {
    let mut out = Vec::new();
    for cap in local {
        if let Some(other) = peer.iter().find(|p| p.id == cap.id) {
            let Ok(lv) = parse_version(&cap.version) else {
                continue;
            };
            let Ok(ov) = parse_version(&other.version) else {
                continue;
            };
            if lv.0 != ov.0 {
                continue;
            }
            let version = if lv <= ov {
                cap.version.clone()
            } else {
                other.version.clone()
            };
            out.push(Capability {
                id: cap.id.clone(),
                version,
            });
        }
    }
    out
}

pub fn version_at_least(actual: &str, required: &str) -> bool {
    match (parse_version(actual), parse_version(required)) {
        (Ok(a), Ok(r)) => a >= r,
        _ => false,
    }
}

pub fn version_leq(actual: &str, maximum: &str) -> bool {
    match (parse_version(actual), parse_version(maximum)) {
        (Ok(a), Ok(m)) => a <= m,
        _ => false,
    }
}

pub fn validate_heartbeat(ms: i64) -> Result<i64, NegotiateError> {
    if (HEARTBEAT_MIN_MS..=HEARTBEAT_MAX_MS).contains(&ms) {
        Ok(ms)
    } else {
        Err(NegotiateError("heartbeat out of bounds".into()))
    }
}
