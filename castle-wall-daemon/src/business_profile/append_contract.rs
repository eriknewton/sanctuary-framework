//! Shared append shapes, exact envelope identity and projection. No authentication is conferred here.
use super::{records, writer_protocol};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
include!("append_contract_constants.rs");
pub const CONTRACT: &str =
    include_str!("../../../server/src/signing/business-append-contract.json");
pub fn contract() -> Option<Value> {
    serde_json::from_str(CONTRACT).ok()
}
pub fn shape(name: &str, value: &Value) -> bool {
    let Some(contract) = contract() else {
        return false;
    };
    let Some(fields) = contract[name].as_object() else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == fields.len()
        && fields.iter().all(|(key, token)| {
            let Some(v) = object.get(key) else {
                return false;
            };
            match token.as_str() {
                Some("safe" | "positive") => v
                    .as_u64()
                    .map(|n| n <= 9_007_199_254_740_991 && (token != "positive" || n > 0))
                    .unwrap_or(false),
                Some("digest") => v
                    .as_str()
                    .map(super::drain_protocol::digest)
                    .unwrap_or(false),
                Some("nullable_hex") if v.is_null() => true,
                Some("hex" | "nullable_hex") => v
                    .as_str()
                    .map(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .unwrap_or(false),
                Some("text") => v
                    .as_str()
                    .map(|s| s.chars().count() <= PRODUCER_ENVELOPE_MAX_BYTES)
                    .unwrap_or(false),
                Some("base64") => v
                    .as_str()
                    .map(|s| {
                        s.len() <= (PRODUCER_ENVELOPE_MAX_BYTES * 8).div_ceil(6)
                            && !s.is_empty()
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    })
                    .unwrap_or(false),
                Some("identity") => shape("identity", v),
                _ => v == token,
            }
        })
}
pub fn envelope(encoded: &str) -> Option<(Vec<u8>, Value)> {
    // Encoded input is bounded before allocating decoded bytes.
    if encoded.len() > (PRODUCER_ENVELOPE_MAX_BYTES * 8).div_ceil(6) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return None;
    }
    let value = writer_protocol::decode_envelope(&bytes).ok()?;
    Some((bytes, value))
}
pub fn identity(bytes: &[u8]) -> Option<Value> {
    let record = writer_protocol::decode_envelope(bytes).ok()?;
    Some(
        json!({"version":1,"sequence":record["body"]["sequence"],"commitment":records::join_commitment(&record)?,"envelope_sha256":format!("sha256:{}",hex::encode(Sha256::digest(bytes)))}),
    )
}
pub fn projection(record: &Value) -> Option<Value> {
    let data = contract()?;
    let fields = data["projection"].as_object()?;
    let mut out = serde_json::Map::new();
    for (key, source) in fields {
        out.insert(key.clone(), record["body"].get(source.as_str()?)?.clone());
    }
    Some(Value::Object(out))
}
pub fn event(value: &Value) -> Option<(Vec<u8>, Value)> {
    if !shape("event", value) {
        return None;
    }
    let (bytes, record) = envelope(value["business_envelope"].as_str()?)?;
    if value["captured_at_unix_ms"] != record["body"]["captured_at_unix_ms"]
        || value["event_canonical_json"].as_str()?
            != crate::smb::jcs::encode(&record["body"]).ok()?
    {
        return None;
    }
    Some((bytes, record))
}
