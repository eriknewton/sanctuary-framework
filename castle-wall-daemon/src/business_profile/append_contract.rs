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
    shape_with(name, value, &contract)
}
fn shape_with(name: &str, value: &Value, contract: &Value) -> bool {
    let Some(fields) = contract[name].as_object() else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let valid = object.len() == fields.len()
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
                    .map(|s| s.len() <= PRODUCER_ENVELOPE_MAX_BYTES)
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
                Some("identity" | "observation" | "wal_checkpoint") => {
                    shape_with(token.as_str().unwrap_or(""), v, contract)
                }
                Some("boolean") => v.is_boolean(),
                Some("id") => v.as_str().map(super::drain_protocol::id).unwrap_or(false),
                Some("u64") => v
                    .as_str()
                    .and_then(super::writer_protocol::canonical_deadline)
                    .is_some(),
                Some("commitment") => {
                    v == "GENESIS"
                        || v.as_str()
                            .map(super::drain_protocol::digest)
                            .unwrap_or(false)
                }
                Some("nullable_digest") => {
                    v.is_null()
                        || v.as_str()
                            .map(super::drain_protocol::digest)
                            .unwrap_or(false)
                }
                Some("nullable_anchor") => v.is_null() || super::activation_anchor::valid(v),
                Some("observation_state") => contract["observation_states"]
                    .as_array()
                    .map(|states| states.contains(v))
                    .unwrap_or(false),
                Some("join_state") => records::join_state_valid(v),
                Some("retained_originals") => v
                    .as_array()
                    .map(|rows| {
                        rows.len() <= super::drain_store::D_UNDRAINED_MAX
                            && rows
                                .iter()
                                .all(|row| shape_with("retained_original", row, contract))
                    })
                    .unwrap_or(false),
                _ => v == token,
            }
        });
    if !valid || name != "observation" {
        return valid;
    }
    // Must match the native READ_REPLY decoder; this is shape evidence only.
    if value["state"] == "ABSENT" {
        return value["anchor"].is_null()
            && value["anchor_digest"].is_null()
            && value["latched"] == false;
    }
    super::activation_anchor::anchor_digest(&value["anchor"]).as_deref()
        == value["anchor_digest"].as_str()
        && !value["anchor"].is_null()
        && value["latched"] == value["anchor"]["recovery_required"]
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

/// Serialized ingress retains duplicate-key evidence before interpreting the event.
pub fn event_bytes(bytes: &[u8]) -> Option<(Vec<u8>, Value)> {
    let value =
        super::frame::canonical(bytes, super::signer_contract::SIGNER_FRAME_MAX_BYTES).ok()?;
    event(&value)
}
