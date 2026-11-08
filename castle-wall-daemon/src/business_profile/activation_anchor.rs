//! Pure canonical anchor proposals without persistence or authentication authority.
use serde_json::Value;
use sha2::{Digest, Sha256};
// Must match linux-business/activation-anchor.ts, including every field and operation.
pub const MAX_BYTES: usize = 65536;
pub const OPS: &[&str] = &[
    "READ",
    "PREPARE",
    "COMMIT",
    "RESERVE",
    "DRAIN",
    "LATCH",
    "RECOVERY_COMMIT",
];
const SAFE_INTEGER: u64 = 9007199254740991; // Largest exact JavaScript integer.
const FIELDS: &[&str] = &[
    "version",
    "fortress_id",
    "machine_id",
    "role",
    "enrollment_revision",
    "descriptor_digest",
    "roster_digest",
    "custody_envelope_digest",
    "retired",
    "activation_id",
    "boot_id",
    "generation_high_water",
    "reserved_sequence",
    "committed_sequence",
    "committed_digest",
    "drained_sequence",
    "drained_digest",
    "transaction_id",
    "recovery_required",
    "recovery_reason",
    "recovery_revision",
];
fn exact(v: &Value, fields: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
fn hex(v: &Value, prefix: &str, length: usize) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix(prefix))
        .is_some_and(|s| {
            s.len() == length
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
}
fn n(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or(0)
}
/// Validate the entire tuple before any proposal is considered.
pub fn valid(a: &Value) -> bool {
    if !exact(a, FIELDS) || a["version"] != 1 || a["role"] != "extension:linux-business-producer-v0"
    {
        return false;
    }
    // Identifiers encode sixteen bytes and SHA-256 digests encode thirty-two bytes.
    if ["fortress_id", "machine_id", "activation_id", "boot_id"]
        .iter()
        .any(|k| !hex(&a[*k], "", 32))
        || [
            "descriptor_digest",
            "roster_digest",
            "custody_envelope_digest",
        ]
        .iter()
        .any(|k| !hex(&a[*k], "sha256:", 64))
        || !a["retired"].is_boolean()
        || !a["recovery_required"].is_boolean()
        || !(a["transaction_id"].is_null() || hex(&a["transaction_id"], "", 32))
    {
        return false;
    }
    for k in [
        "enrollment_revision",
        "generation_high_water",
        "reserved_sequence",
        "committed_sequence",
        "drained_sequence",
        "recovery_revision",
    ] {
        if !a[k].as_u64().is_some_and(|n| n <= SAFE_INTEGER) {
            return false;
        }
    }
    // High-water and latch consistency prevent a shaped proposal from erasing uncertainty.
    if n(a, "enrollment_revision") == 0
        || n(a, "drained_sequence") > n(a, "committed_sequence")
        || n(a, "committed_sequence") > n(a, "reserved_sequence")
        || n(a, "reserved_sequence") - n(a, "committed_sequence") > 1
    {
        return false;
    }
    for (seq, digest) in [
        ("committed_sequence", "committed_digest"),
        ("drained_sequence", "drained_digest"),
    ] {
        if (n(a, seq) == 0) != (a[digest] == "GENESIS")
            || !(a[digest] == "GENESIS" || hex(&a[digest], "sha256:", 64))
        {
            return false;
        }
    }
    let required = a["recovery_required"] == true;
    if required {
        n(a, "recovery_revision") > 0
            && a["recovery_reason"].as_str().is_some_and(|r| {
                ["integrity", "restart", "storage_fault", "counter_lost"].contains(&r)
            })
    } else {
        a["recovery_reason"].is_null()
    }
}
pub fn anchor_digest(a: &Value) -> Option<String> {
    if !valid(a) {
        return None;
    }
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(crate::smb::jcs::encode(a).ok()?.as_bytes()))
    ))
}
/// Decode bounded, canonical messages before an external peer-authentication boundary.
pub fn decode_message(bytes: &[u8]) -> Option<Value> {
    let m = crate::smb::strict_json::parse(bytes, MAX_BYTES).ok()?;
    // Canonical strict parsing preserves duplicate evidence before integer representation is normalized.
    if crate::smb::jcs::encode(&m).ok()?.as_bytes() != bytes {
        return None;
    }
    let m: Value = serde_json::from_slice(bytes).ok()?;
    // Canonical equality gives retries one exact byte identity.
    if !exact(&m, &["version", "op", "request_id", "expected", "next"])
        || m["version"] != 1
        || !hex(&m["request_id"], "", 32)
        || !OPS.contains(&m["op"].as_str()?)
        || !valid(&m["expected"])
        || ((m["op"] == "READ") != m["next"].is_null())
        || (!m["next"].is_null() && !valid(&m["next"]))
        || crate::smb::jcs::encode(&m).ok()?.as_bytes() != bytes
    {
        return None;
    }
    Some(m)
}
/// Return a checked proposal, never a durable acknowledgment or signing grant.
pub fn propose(old: &Value, message: &Value) -> Option<Value> {
    let m = decode_message(crate::smb::jcs::encode(message).ok()?.as_bytes())?;
    // The entire expected tuple binds this proposal to one observed anchor and sticky latch.
    if !valid(old) || old != &m["expected"] {
        return None;
    }
    if m["op"] == "READ" {
        return Some(old.clone());
    }
    let next = &m["next"];
    let changed: &[&str] = match m["op"].as_str()? {
        "RESERVE" => {
            if old["recovery_required"] == true
                || old["retired"] == true
                || !old["transaction_id"].is_null()
                || old["reserved_sequence"] != old["committed_sequence"]
                || n(next, "reserved_sequence") != n(old, "reserved_sequence") + 1
            {
                return None;
            }
            &["reserved_sequence"]
        }
        "COMMIT" => {
            if !old["transaction_id"].is_null() {
                if !next["transaction_id"].is_null() {
                    return None;
                }
                &["transaction_id"]
            } else {
                if n(old, "reserved_sequence") != n(old, "committed_sequence") + 1
                    || next["committed_sequence"] != old["reserved_sequence"]
                    || next["committed_digest"] == old["committed_digest"]
                {
                    return None;
                }
                &["committed_sequence", "committed_digest"]
            }
        }
        "DRAIN" => {
            if n(next, "drained_sequence") != n(old, "drained_sequence") + 1
                || n(next, "drained_sequence") > n(old, "committed_sequence")
                || next["drained_digest"] == old["drained_digest"]
                || (next["drained_sequence"] == old["committed_sequence"]
                    && next["drained_digest"] != old["committed_digest"])
            {
                return None;
            }
            &["drained_sequence", "drained_digest"]
        }
        "PREPARE" => {
            if old["recovery_required"] == true
                || old["retired"] == true
                || !old["transaction_id"].is_null()
                || old["reserved_sequence"] != old["committed_sequence"]
                || n(next, "enrollment_revision") != n(old, "enrollment_revision") + 1
                || next["transaction_id"] != m["request_id"]
            {
                return None;
            }
            &[
                "enrollment_revision",
                "transaction_id",
                "descriptor_digest",
                "roster_digest",
                "custody_envelope_digest",
            ]
        }
        "LATCH" => {
            if next["recovery_required"] != true
                || n(next, "recovery_revision") != n(old, "recovery_revision") + 1
            {
                return None;
            }
            &["recovery_required", "recovery_reason", "recovery_revision"]
        }
        // Installed recovery evidence has no constructor here, so this codec cannot clear a latch.
        _ => return None,
    };
    // Only the operation's named fields can change across the whole-tuple comparison.
    if FIELDS
        .iter()
        .any(|k| !changed.contains(k) && old[*k] != next[*k])
    {
        return None;
    }
    Some(next.clone())
}
/// Classify consistency without a live recovery destination or latch caller.
pub fn reconcile(
    custody: &Value,
    drain: &Value,
    outside_receipt: Option<&str>,
    original_tail: Option<&str>,
) -> bool {
    // a custody-only rollback refuses; no total-host rollback protection is claimed.
    // Same-epoch recovery requires comparison with the last exported receipt from outside the restored failure domain; without that comparison it refuses and a new epoch is required.
    valid(custody)
        && valid(drain)
        && outside_receipt.is_some()
        && outside_receipt == anchor_digest(drain).as_deref()
        && original_tail == drain["committed_digest"].as_str()
        && custody == drain
        && custody["recovery_required"] == false
        && custody["retired"] == false
        && custody["transaction_id"].is_null()
        && drain["reserved_sequence"] == drain["committed_sequence"]
}
