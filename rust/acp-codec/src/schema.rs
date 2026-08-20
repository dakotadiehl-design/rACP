//! JSON Schema 2020-12 subset validator driven by the packed canonical schemas.

use crate::{cerr, serde_from_json, CodecError};
use serde_json::Value;
use std::sync::OnceLock;

const PACK: &str = include_str!("../../../schema/schema_pack.json");

struct Pack {
    docs: serde_json::Map<String, Value>,
    messages: serde_json::Map<String, Value>,
}

fn pack() -> &'static Pack {
    static PACKED: OnceLock<Pack> = OnceLock::new();
    PACKED.get_or_init(|| {
        let raw: Value = serde_json::from_str(PACK).expect("schema pack");
        Pack {
            docs: raw["docs"].as_object().cloned().unwrap_or_default(),
            messages: raw["messages"].as_object().cloned().unwrap_or_default(),
        }
    })
}

fn pointer<'a>(doc: &'a Value, pointer: &str) -> Result<&'a Value, CodecError> {
    let mut node = doc;
    if pointer.is_empty() {
        return Ok(node);
    }
    for part in pointer.trim_start_matches('/').split('/') {
        let part = part.replace("~1", "/").replace("~0", "~");
        node = node
            .get(&part)
            .ok_or_else(|| cerr(format!("schema pointer {pointer} missing {part}")))?;
    }
    Ok(node)
}

fn resolve_ref<'a>(
    pack: &'a Pack,
    current_path: &str,
    current_doc: &'a Value,
    refer: &str,
) -> Result<(&'a Value, String, &'a Value), CodecError> {
    let (target, frag) = refer.split_once('#').unwrap_or((refer, ""));
    if target.is_empty() {
        return Ok((
            pointer(current_doc, frag)?,
            current_path.to_string(),
            current_doc,
        ));
    }
    let base = PathRel(current_path);
    let joined = base.join(target);
    let doc = pack
        .docs
        .get(&joined)
        .ok_or_else(|| cerr(format!("schema {joined} not packed")))?;
    Ok((pointer(doc, frag)?, joined, doc))
}

struct PathRel<'a>(&'a str);

impl PathRel<'_> {
    fn join(&self, rel: &str) -> String {
        if !rel.contains('/') && !rel.starts_with('.') {
            let parent = self.0.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            return if parent.is_empty() {
                rel.to_string()
            } else {
                format!("{parent}/{rel}")
            };
        }
        let mut parts: Vec<&str> = self
            .0
            .rsplit_once('/')
            .map(|(p, _)| p.split('/').collect())
            .unwrap_or_default();
        for part in rel.split('/') {
            match part {
                "." | "" => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        parts.join("/")
    }
}

fn instance_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_ok(got: &str, wanted: &str) -> bool {
    got == wanted || (wanted == "number" && got == "integer")
}

fn match_pattern(text: &str, pattern: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<String, regex::Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("regex cache");
    let re = map.entry(pattern.to_string()).or_insert_with(|| {
        regex::Regex::new(pattern)
            .unwrap_or_else(|_| regex::Regex::new("$.").expect("invalid fallback"))
    });
    re.is_match(text)
}

fn validate(
    instance: &Value,
    schema: &Value,
    pack: &Pack,
    path: &str,
    doc: &Value,
) -> Result<(), CodecError> {
    if let Some(refer) = schema.get("$ref").and_then(Value::as_str) {
        let (target, tpath, tdoc) = resolve_ref(pack, path, doc, refer)?;
        return validate(instance, target, pack, &tpath, tdoc);
    }
    if let Some(types) = schema.get("type") {
        let got = instance_type(instance);
        let ok = match types {
            Value::String(s) => type_ok(got, s),
            Value::Array(items) => items
                .iter()
                .any(|t| t.as_str().is_some_and(|s| type_ok(got, s))),
            _ => true,
        };
        if !ok {
            return Err(cerr(format!("invalid type: expected {types}, got {got}")));
        }
    }
    if let Some(Value::Array(req)) = schema.get("required") {
        let obj = instance
            .as_object()
            .ok_or_else(|| cerr("object required"))?;
        for key in req {
            if let Some(k) = key.as_str() {
                if !obj.contains_key(k) {
                    return Err(cerr(format!("missing required {k}")));
                }
            }
        }
    }
    if let Some(Value::Array(opts)) = schema.get("enum") {
        if !opts.iter().any(|opt| opt == instance) {
            return Err(cerr("value not in enum"));
        }
    }
    if let Some(cst) = schema.get("const") {
        if cst != instance {
            return Err(cerr("const mismatch"));
        }
    }
    if let Some(pat) = schema.get("pattern").and_then(Value::as_str) {
        let text = instance
            .as_str()
            .ok_or_else(|| cerr("pattern on non-string"))?;
        if !match_pattern(text, pat) {
            return Err(cerr(format!("pattern {pat} failed")));
        }
    }
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
        let text = instance.as_str().unwrap_or("");
        if (text.len() as u64) < min {
            return Err(cerr("minLength"));
        }
    }
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        let n = instance
            .as_f64()
            .ok_or_else(|| cerr("minimum on non-number"))?;
        if n < min {
            return Err(cerr("minimum"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        let n = instance
            .as_f64()
            .ok_or_else(|| cerr("maximum on non-number"))?;
        if n > max {
            return Err(cerr("maximum"));
        }
    }
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        let n = instance.as_array().map(|a| a.len() as u64).unwrap_or(0);
        if n < min {
            return Err(cerr("minItems"));
        }
    }
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        if let Some(obj) = instance.as_object() {
            for (k, v) in obj {
                if let Some(sub) = props.get(k) {
                    validate(v, sub, pack, path, doc)?;
                }
            }
        }
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        if let Some(obj) = instance.as_object() {
            let empty = serde_json::Map::new();
            let props = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or(&empty);
            for key in obj.keys() {
                if !props.contains_key(key) {
                    return Err(cerr(format!("additional property {key}")));
                }
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if let Some(arr) = instance.as_array() {
            for item in arr {
                validate(item, items, pack, path, doc)?;
            }
        }
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for sub in all {
            validate(instance, sub, pack, path, doc)?;
        }
    }
    if let Some(any) = schema.get("anyOf").and_then(Value::as_array) {
        if !any
            .iter()
            .any(|sub| validate(instance, sub, pack, path, doc).is_ok())
        {
            return Err(cerr("anyOf failed"));
        }
    }
    if let Some(one) = schema.get("oneOf").and_then(Value::as_array) {
        let hits = one
            .iter()
            .filter(|sub| validate(instance, sub, pack, path, doc).is_ok())
            .count();
        if hits != 1 {
            return Err(cerr("oneOf failed"));
        }
    }
    Ok(())
}

pub fn validate_message_value(data: &Value) -> Result<(), CodecError> {
    let pack = pack();
    let envelope = pack
        .docs
        .get("envelope.schema.json")
        .ok_or_else(|| cerr("missing envelope schema"))?;
    validate(data, envelope, pack, "envelope.schema.json", envelope)
        .map_err(|e| CodecError(format!("malformed_envelope: {}", e.0)))?;
    let typ = data.get("type").and_then(Value::as_str).unwrap_or("");
    let Some(schema_ref) = pack.messages.get(typ).and_then(Value::as_str) else {
        return Err(CodecError(format!(
            "unsupported_message: unknown type {typ}"
        )));
    };
    let (target, tpath, tdoc) = resolve_ref(pack, "", envelope, schema_ref)?;
    let payload = data.get("payload").unwrap_or(&Value::Null);
    validate(payload, target, pack, &tpath, tdoc)
        .map_err(|e| CodecError(format!("invalid_type: {}", e.0)))
}

pub fn validate_envelope(env: &acp_model::Envelope) -> Result<(), CodecError> {
    let value = serde_from_json(&crate::envelope_to_json(env));
    validate_message_value(&value)
}
