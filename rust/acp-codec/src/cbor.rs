//! ACP-CDE-1.2 encoder/decoder.

use acp_model::Json;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct CborError(pub String);

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CborError {}

const MAX_DEPTH: usize = 16;
const MAX_ITEMS: u64 = 1_048_576;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

fn err(msg: impl Into<String>) -> CborError {
    CborError(msg.into())
}

fn bound_len(n: u64, max: u64) -> Result<usize, CborError> {
    if n > max {
        return Err(err("item or byte length exceeds limit"));
    }
    usize::try_from(n).map_err(|_| err("overflow"))
}

pub fn encode(value: &Json) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    write_value(&mut out, value)?;
    Ok(out)
}

pub fn decode(data: &[u8]) -> Result<Json, CborError> {
    let (value, rest) = read_value(data, 0, 0)?;
    if rest != data.len() {
        return Err(err("trailing bytes"));
    }
    Ok(value)
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push((major << 5) | n as u8);
    } else if n < 256 {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n < 65536 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < (1u64 << 32) {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write_value(out: &mut Vec<u8>, value: &Json) -> Result<(), CborError> {
    match value {
        Json::Null => out.push(0xf6),
        Json::Bool(false) => out.push(0xf4),
        Json::Bool(true) => out.push(0xf5),
        Json::Int(n) if *n >= 0 => head(out, 0, *n as u64),
        Json::Int(n) => head(out, 1, (-1 - n) as u64),
        Json::UInt(n) => head(out, 0, *n),
        Json::Float(f) => {
            if !f.is_finite() {
                return Err(err("NaN/Inf forbidden"));
            }
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Json::String(s) => {
            let raw = s.as_bytes();
            head(out, 3, raw.len() as u64);
            out.extend_from_slice(raw);
        }
        Json::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Json::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                write_value(out, item)?;
            }
        }
        Json::Object(pairs) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for (k, v) in pairs {
                let mut kb = Vec::new();
                write_value(&mut kb, &Json::String(k.clone()))?;
                let mut vb = Vec::new();
                write_value(&mut vb, v)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            let mut seen = BTreeMap::new();
            for (k, _) in &encoded {
                if seen.insert(k.clone(), ()).is_some() {
                    return Err(err("duplicate map key"));
                }
            }
            head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
    }
    Ok(())
}

fn read_arg(data: &[u8], ai: u8, offset: usize) -> Result<(u64, usize), CborError> {
    match ai {
        n if n < 24 => Ok((n as u64, offset)),
        24 => {
            let b = *data.get(offset).ok_or_else(|| err("truncated"))?;
            if b < 24 {
                return Err(err("non-preferred integer encoding"));
            }
            Ok((b as u64, offset + 1))
        }
        25 => {
            let sl = data
                .get(offset..offset + 2)
                .ok_or_else(|| err("truncated"))?;
            let n = u16::from_be_bytes([sl[0], sl[1]]) as u64;
            if n < 256 {
                return Err(err("non-preferred integer encoding"));
            }
            Ok((n, offset + 2))
        }
        26 => {
            let sl = data
                .get(offset..offset + 4)
                .ok_or_else(|| err("truncated"))?;
            let n = u32::from_be_bytes([sl[0], sl[1], sl[2], sl[3]]) as u64;
            if n < 65536 {
                return Err(err("non-preferred integer encoding"));
            }
            Ok((n, offset + 4))
        }
        27 => {
            let sl = data
                .get(offset..offset + 8)
                .ok_or_else(|| err("truncated"))?;
            let n = u64::from_be_bytes(sl.try_into().unwrap());
            if n < (1u64 << 32) {
                return Err(err("non-preferred integer encoding"));
            }
            Ok((n, offset + 8))
        }
        31 => Err(err("indefinite length forbidden")),
        _ => Err(err("reserved additional info")),
    }
}

fn read_value(data: &[u8], mut offset: usize, depth: usize) -> Result<(Json, usize), CborError> {
    if depth > MAX_DEPTH {
        return Err(err("nesting too deep"));
    }
    let initial = *data.get(offset).ok_or_else(|| err("truncated"))?;
    offset += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    if ai == 31 {
        return Err(err("indefinite length forbidden"));
    }
    match major {
        0 => {
            let (n, off) = read_arg(data, ai, offset)?;
            if n <= i64::MAX as u64 {
                Ok((Json::Int(n as i64), off))
            } else {
                Ok((Json::UInt(n), off))
            }
        }
        1 => {
            let (n, off) = read_arg(data, ai, offset)?;
            if n > i64::MAX as u64 {
                return Err(err("negative integer out of range"));
            }
            Ok((Json::Int(-1 - n as i64), off))
        }
        2 => {
            let (n, off) = read_arg(data, ai, offset)?;
            let len = bound_len(n, MAX_BYTES)?;
            let end = off.checked_add(len).ok_or_else(|| err("overflow"))?;
            let sl = data.get(off..end).ok_or_else(|| err("truncated"))?;
            Ok((Json::Bytes(sl.to_vec()), end))
        }
        3 => {
            let (n, off) = read_arg(data, ai, offset)?;
            let len = bound_len(n, MAX_BYTES)?;
            let end = off.checked_add(len).ok_or_else(|| err("overflow"))?;
            let sl = data.get(off..end).ok_or_else(|| err("truncated"))?;
            let s = std::str::from_utf8(sl).map_err(|_| err("bad utf8"))?;
            Ok((Json::String(s.to_string()), end))
        }
        4 => {
            let (n, mut off) = read_arg(data, ai, offset)?;
            let len = bound_len(n, MAX_ITEMS)?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                let (v, next) = read_value(data, off, depth + 1)?;
                items.push(v);
                off = next;
            }
            Ok((Json::Array(items), off))
        }
        5 => {
            let (n, mut off) = read_arg(data, ai, offset)?;
            let len = bound_len(n, MAX_ITEMS)?;
            let mut pairs = Vec::with_capacity(len);
            let mut last_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = off;
                let (key, next) = read_value(data, off, depth + 1)?;
                let encoded = data[key_start..next].to_vec();
                if let Some(prev) = &last_key {
                    if encoded < *prev {
                        return Err(err("map keys not in CDE order"));
                    }
                    if encoded == *prev {
                        return Err(err("duplicate map key"));
                    }
                }
                last_key = Some(encoded);
                off = next;
                let Json::String(k) = key else {
                    return Err(err("map keys must be text"));
                };
                let (val, next) = read_value(data, off, depth + 1)?;
                off = next;
                pairs.push((k, val));
            }
            Ok((Json::Object(pairs), off))
        }
        6 => {
            let (tag, off) = read_arg(data, ai, offset)?;
            if tag != 0 {
                return Err(err("only CBOR tag 0 is permitted"));
            }
            let (inner, off) = read_value(data, off, depth + 1)?;
            Ok((inner, off))
        }
        7 => match ai {
            20 => Ok((Json::Bool(false), offset)),
            21 => Ok((Json::Bool(true), offset)),
            22 => Ok((Json::Null, offset)),
            27 => {
                let sl = data
                    .get(offset..offset + 8)
                    .ok_or_else(|| err("truncated"))?;
                let bits = u64::from_be_bytes(sl.try_into().unwrap());
                let f = f64::from_bits(bits);
                if !f.is_finite() {
                    return Err(err("NaN/Inf forbidden"));
                }
                Ok((Json::Float(f), offset + 8))
            }
            _ => Err(err("unsupported simple/float")),
        },
        _ => Err(err("bad major type")),
    }
}
