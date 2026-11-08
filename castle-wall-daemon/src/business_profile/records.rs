//! Pure business record decoding and verification, with no signer or installed constructor.
use super::{records_schema, verify_role};
use serde_json::Value;

/// Decode only canonical records admitted by the compiled business schema.
pub fn decode(bytes: &[u8]) -> Option<Value> {
    let body = crate::smb::strict_json::parse(bytes, records_schema::MAX_BYTES).ok()?;
    // Canonical strict parsing preserves duplicate evidence before integer representation is normalized.
    if crate::smb::jcs::encode(&body).ok()?.as_bytes() != bytes {
        return None;
    }
    let body: Value = serde_json::from_slice(bytes).ok()?;
    // Must match parseRecord in signing/contract.ts and the generated business schema in both languages.
    if !records_schema::valid(&body) || crate::smb::jcs::encode(&body).ok()?.as_bytes() != bytes {
        return None;
    }
    Some(body)
}

/// Verify the record against an independently enrolled role, identity, machine and key pin.
pub fn verify(bytes: &[u8], signature: &[u8], pin: &Value, public_key: &[u8]) -> bool {
    let Some(body) = decode(bytes) else {
        return false;
    };
    // The pin describes the producer subject, so a signature alone cannot substitute another enrolled identity.
    if ["role", "epoch", "kid", "identity_id", "machine_id"]
        .iter()
        .any(|key| body[*key] != pin[*key])
    {
        return false;
    }
    let Some(epoch) = body["epoch"].as_u64() else {
        return false;
    };
    let text = |key: &str| body[key].as_str().unwrap_or("");
    verify_role(
        text("role"),
        epoch,
        text("kid"),
        text("signature_scheme"),
        text("record_kind"),
        bytes,
        signature,
        public_key,
    )
}
