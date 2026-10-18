//! Interpret the shared wire source, without Rust message-shape copies.
use super::{constants, jcs, strict_json};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::OnceLock};

// Must match server/src/smb/wire.ts and wire.json, including the include_str! path.
const SOURCE: &str = include_str!("../../../server/src/smb/wire.json");
/// The sole schema/edge registry, shared with TypeScript.
pub fn source() -> &'static Value {
    static VALUE: OnceLock<Value> = OnceLock::new();
    // Safety: embedded_schema_inventory parses and checks every schema and edge in embedded wire.json.
    VALUE.get_or_init(|| strict_json::embedded(SOURCE).expect("SMB wire source"))
}
fn resolve(spec: &Value) -> &Value {
    if let Some(name) = spec.as_str() {
        return resolve(&source()["schemas"][name]);
    }
    if let Some(name) = spec.get("ref").and_then(Value::as_str) {
        return resolve(&source()["schemas"][name]);
    }
    spec
}
fn bound(spec: &Value) -> usize {
    if let Some(number) = spec.as_u64() {
        return number as usize;
    }
    // Safety: embedded_schema_inventory checks every embedded size bound is numeric or a constant name.
    let name = spec.as_str().expect("SMB schema bound");
    // Safety: embedded_schema_inventory resolves every embedded bound to a platform-sized number.
    constants::bound(name).expect("SMB schema constant bound")
}
fn fields(spec: &Value) -> Map<String, Value> {
    let mut result = spec
        .get("extends")
        .map(|s| fields(resolve(s)))
        .unwrap_or_default();
    // Safety: embedded_schema_inventory checks every embedded object schema has an object fields map.
    result.extend(
        spec["fields"]
            .as_object()
            .expect("SMB schema fields")
            .clone(),
    );
    result
}
fn matches(spec: &Value, value: &Value, depth: usize) -> bool {
    let Ok(max_depth) = constants::bound("JSON_MAX_DEPTH") else {
        return false;
    };
    if depth > max_depth + 1 {
        return false;
    }
    let spec = resolve(spec);
    if let Some(literal) = spec.get("const") {
        return value == literal;
    }
    if let Some(values) = spec.get("enum") {
        // Safety: embedded_schema_inventory checks every embedded enum is an array.
        return values.as_array().unwrap().contains(value);
    }
    if let Some(alternatives) = spec.get("oneOf") {
        // Safety: embedded_schema_inventory checks every embedded oneOf is an array.
        return alternatives
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| matches(s, value, depth))
            .count()
            == 1;
    }
    // An unresolved caller-selected schema is a refusal, never a process failure.
    let Some(operation) = spec["type"].as_str() else {
        return false;
    };
    match operation {
        "object" => value.as_object().is_some_and(|values| {
            let expected = fields(spec);
            // Full-set agreement refuses both unknown and missing fields at the seam.
            values.len() == expected.len()
                && expected
                    .iter()
                    .all(|(key, s)| values.get(key).is_some_and(|v| matches(s, v, depth + 1)))
        }),
        "array" => value.as_array().is_some_and(|values| {
            values.len() <= bound(&spec["max"])
                && values.iter().all(|v| matches(&spec["items"], v, depth + 1))
        }),
        "decimal" => value.as_str().is_some_and(|text| {
            // u64 strings preserve precision and have exactly one spelling; JSON numbers refuse.
            !text.is_empty()
                && (text == "0" || !text.starts_with('0'))
                && text.bytes().all(|b| b.is_ascii_digit())
                && text.parse::<u64>().is_ok_and(|n| {
                    // Safety: embedded_schema_inventory checks every embedded decimal max is a string.
                    let max = spec["max"].as_str().unwrap();
                    // Safety: embedded_schema_inventory parses every embedded decimal max as u64.
                    let max = max.parse::<u64>().unwrap();
                    // Safety: embedded_schema_inventory parses each embedded decimal min; absent means zero.
                    let min = spec
                        .get("min")
                        .and_then(Value::as_str)
                        .unwrap_or("0")
                        .parse::<u64>()
                        .unwrap();
                    n <= max && n >= min
                })
        }),
        "integer" => value.as_f64().is_some_and(|n| n.fract() == 0.0),
        "string" => value.as_str().is_some_and(|text| {
            if let Some(prefix) = spec.get("prefix").and_then(Value::as_str) {
                // Safety: embedded_schema_inventory resolves every embedded prefix constant name.
                let prefix = constants::value(prefix).expect("SMB prefix constant");
                // Safety: embedded_schema_inventory checks each embedded prefix constant is a string.
                let prefix = prefix.as_str().unwrap();
                return text.strip_prefix(prefix).is_some_and(|suffix| {
                    matches(&spec["suffix"], &Value::String(suffix.into()), depth + 1)
                });
            }
            text.len() >= bound(&spec["min"])
                && text.len() <= bound(&spec["max"])
                && spec.get("chars").map_or(true, |chars| {
                    // Safety: embedded_schema_inventory checks every embedded chars constraint is a string.
                    text.chars().all(|c| chars.as_str().unwrap().contains(c))
                })
        }),
        "base64" | "base64url" => value.as_str().is_some_and(|text| {
            let engine = if spec["type"] == "base64" {
                STANDARD
            } else {
                URL_SAFE_NO_PAD
            };
            // Must match wire.ts: encoded caps reserve the surrounding frame before decoding.
            if spec
                .get("encoded_max")
                .is_some_and(|max| text.len() > bound(max))
            {
                return false;
            }
            // Exact round-trip prevents padding and ignored-character ambiguities.
            engine.decode(text).is_ok_and(|bytes| {
                bytes.len() <= bound(&spec["max"]) && engine.encode(bytes) == text
            })
        }),
        "json" => true, // validate applies the strict numeric domain to the whole value first.
        _ => false,
    }
}
/// Validate a caller value against the shared schema and strict JSON domain.
pub fn validate(schema: &str, value: &Value) -> bool {
    jcs::encode(value).is_ok_and(|text| {
        constants::bound("TASK_STORE_BYTES")
            .is_ok_and(|maximum| strict_json::parse(text.as_bytes(), maximum).is_ok())
    }) && matches(&Value::String(schema.into()), value, 0)
}
/// Parse and validate without removing duplicate names before the parser sees them.
pub fn validate_bytes(schema: &str, bytes: &[u8], maximum: usize) -> Result<Value, String> {
    let value = strict_json::parse(bytes, maximum)?;
    if !validate(schema, &value) {
        return Err("SMB schema".into());
    }
    Ok(value)
}
/// Normalize a kernel UUID before comparing or emitting the shared boot-id field.
// Must match normalizeBootId in server/src/smb/wire.ts; both produce the same wire identity.
pub fn normalize_boot_id(uuid: &str) -> Result<String, String> {
    let normalized = uuid.replace('-', "").to_lowercase();
    if !validate("boot_id", &Value::String(normalized.clone())) {
        return Err("SMB boot id".into());
    }
    Ok(normalized)
}
/// Explicit connection states: any refusal transitions permanently to Closed.
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Open,
    Closed,
}
/// Bounded request registry, with no retained history after replies or closure.
pub struct ReplyMatcher {
    pub state: ConnectionState,
    edge: String,
    next_id: Option<u64>,
    pending: BTreeMap<String, String>,
}
impl ReplyMatcher {
    /// Select a real shared edge; the edge's capacity is required, never optional.
    pub fn new(edge: &str) -> Result<Self, String> {
        if source()["edges"].get(edge).is_none() {
            return Err("SMB edge".into());
        }
        Ok(Self {
            state: ConnectionState::Open,
            edge: edge.into(),
            next_id: Some(1),
            pending: BTreeMap::new(),
        })
    }
    /// Number of requests that must be failed if the connection closes.
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }
    /// Permanently fail all outstanding work; late replies cannot revive it.
    pub fn close(&mut self) {
        self.state = ConnectionState::Closed;
        self.pending.clear();
    }
    /// Reserve an id and capacity before sending its schema-checked request.
    pub fn register(&mut self, request: &Value) -> Result<(), String> {
        let edge = &source()["edges"][&self.edge];
        let route = &edge["requests"][request["kind"].as_str().unwrap_or("")];
        let schema = route["request"].as_str();
        // Open continues only with exact schema, a typed fresh id, and reserved capacity.
        let admission = schema.zip(request["id"].as_str()).filter(|(schema, id)| {
            self.state == ConnectionState::Open
                && validate(schema, request)
                && self.next_id.map(|id| id.to_string()).as_deref() == Some(*id)
                && self.pending.len() < bound(&edge["pending_max"])
        });
        let Some((_, id)) = admission else {
            self.close();
            return Err("SMB request refused".into());
        };
        // Safety: embedded_schema_inventory checks every embedded route has a string reply schema name.
        let reply_schema = route["reply"].as_str().unwrap();
        self.pending.insert(id.into(), reply_schema.into());
        self.next_id = self.next_id.and_then(|id| id.checked_add(1));
        Ok(())
    }
    /// Consume exactly one matching reply, or close the entire registry.
    pub fn receive(&mut self, reply: &Value) -> Result<Value, String> {
        let id = reply["id"].as_str().unwrap_or("");
        let schema = self.pending.get(id);
        // Open continues only for one outstanding id and that request's exact reply shape.
        if self.state != ConnectionState::Open
            || !schema
                .is_some_and(|schema| validate(schema, reply) || validate("error_envelope", reply))
        {
            self.close();
            return Err("SMB reply refused".into());
        }
        self.pending.remove(id);
        Ok(reply.clone())
    }
}
