//! Pure canonical anchor proposals without persistence or authentication authority.
use serde_json::Value;
use sha2::{Digest, Sha256};
// Must match linux-business/activation-anchor.ts, including every field and operation.
pub const MAX_BYTES: usize = 65536;
pub use super::protocol_transitions::ANCHOR_OPS as OPS;
/// Must match PREPARE_CHANGED_FIELDS in activation-anchor.ts and prepare_changed_fields in closure_vectors.json, which both languages pin as a whole set.
// reserved_body_digest is excluded: custody preparation cannot rewrite record evidence.
pub const PREPARE_CHANGED_FIELDS: &[&str] = &[
    "enrollment_revision",
    "transaction_id",
    "descriptor_digest",
    "roster_digest",
    "custody_envelope_digest",
];
/// Must match DRAIN_TUPLE_FIELDS in activation-anchor.ts and drain_tuple_fields in closure_vectors.json, which both languages pin as a whole set; reconcile is defined over exactly this set.
// reserved_body_digest is excluded: drain progress cannot rewrite a pending reservation.
pub const DRAIN_TUPLE_FIELDS: &[&str] = &[
    "reserved_sequence",
    "committed_sequence",
    "committed_digest",
    "drained_sequence",
    "drained_digest",
];
// DRAIN_SCHEMA_BEGIN
// must match `drain_schema.json` via `scripts/generate-drain-contract.mjs`
pub const DRAIN_SCHEMA_DIGEST: &str =
    "sha256:a9ce79996945b09990ea8ab538bbe3288a19be4051db013238d14431bfc4254d";
pub const ID_HEX_LENGTH: usize = 32;
pub const DIGEST_HEX_LENGTH: usize = 64;
pub const KEY_HEX_LENGTH: usize = 64;
pub const PRODUCER_ROLE: &str = "extension:linux-business-producer-v0";
#[rustfmt::skip]
pub const REASONS: &[&str] = &["integrity", "restart", "storage_fault", "counter_lost"];
pub const SAFE_INTEGER: u64 = 9007199254740991; // Largest exact JSON integer.
#[rustfmt::skip]
pub const FIELDS: &[&str] = &["version", "fortress_id", "machine_id", "role", "enrollment_revision", "descriptor_digest", "roster_digest", "custody_envelope_digest", "retired", "activation_id", "boot_id", "generation_high_water", "reserved_sequence", "committed_sequence", "committed_digest", "drained_sequence", "drained_digest", "transaction_id", "recovery_required", "recovery_reason", "recovery_revision", "reserved_body_digest"];
#[rustfmt::skip]
pub const ANCHOR_DOMAINS: &[(&str, &str)] = &[
    ("version", "literal1"),
    ("fortress_id", "id"),
    ("machine_id", "id"),
    ("role", "producer"),
    ("enrollment_revision", "positiveInteger"),
    ("descriptor_digest", "digest"),
    ("roster_digest", "digest"),
    ("custody_envelope_digest", "digest"),
    ("retired", "boolean"),
    ("activation_id", "id"),
    ("boot_id", "id"),
    ("generation_high_water", "safeInteger"),
    ("reserved_sequence", "safeInteger"),
    ("committed_sequence", "safeInteger"),
    ("committed_digest", "commitment"),
    ("drained_sequence", "safeInteger"),
    ("drained_digest", "commitment"),
    ("transaction_id", "nullableId"),
    ("recovery_required", "boolean"),
    ("recovery_reason", "nullableReason"),
    ("recovery_revision", "safeInteger"),
    ("reserved_body_digest", "nullableDigest"),
];
#[rustfmt::skip]
pub const DESCRIPTOR_ROOT: &[(&str, &str)] = &[
    ("version", "literal1"),
    ("fortress_id", "id"),
    ("machine_id", "id"),
    ("identity_id", "id"),
    ("epochs", "epochs"),
];
#[rustfmt::skip]
pub const DESCRIPTOR_ENTRY: &[(&str, &str)] = &[
    ("role", "registeredRole"),
    ("epoch", "positiveInteger"),
    ("kid", "kid"),
    ("public_key", "key"),
];
#[rustfmt::skip]
const MESSAGE_KEYS: &[&str] = &["version", "op", "request_id", "expected", "next"];
#[rustfmt::skip]
const BODY_DIGEST_OPS: &[&str] = &["RESERVE"];
const BODY_DIGEST_CONDITIONAL_OP: &str = "COMMIT";
const BODY_DIGEST_EXPECTED_FIELD: &str = "transaction_id";
pub const D_DESCRIPTOR_EPOCHS_MAX: usize = super::signer_contract::SIGNER_EPOCHS_MAX;
// Frozen signer aliases must equal the schema bounds before either runtime can admit input.
const _: () = assert!(D_DESCRIPTOR_EPOCHS_MAX == 256);
#[cfg(target_os = "linux")]
pub const D_DESCRIPTOR_MAX_BYTES: usize = super::custody::CONFIG_MAX_BYTES;
// The pure parser remains available where Linux custody is not compiled.
#[cfg(not(target_os = "linux"))]
pub const D_DESCRIPTOR_MAX_BYTES: usize = 65536;
const _: () = assert!(D_DESCRIPTOR_MAX_BYTES == 65536);
pub const D_EPOCH_MAX: u64 = 9007199254740991; // 2^53 - 1 is the largest shared safe integer epoch.
const _: () = assert!(D_EPOCH_MAX == SAFE_INTEGER);
// DRAIN_SCHEMA_END
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
    // The shared primitive table rejects fields that cannot carry the anchor's evidence.
    if !exact(a, FIELDS)
        || !ANCHOR_DOMAINS
            .iter()
            .all(|(key, domain)| domain_valid(&a[*key], domain))
    {
        return false;
    }
    // High-water and latch consistency prevent a shaped proposal from erasing uncertainty.
    if n(a, "enrollment_revision") == 0
        || n(a, "drained_sequence") > n(a, "committed_sequence")
        || n(a, "committed_sequence") > n(a, "reserved_sequence")
        || n(a, "reserved_sequence") - n(a, "committed_sequence") > 1
        || (a["reserved_body_digest"].is_null()
            != (a["reserved_sequence"] == a["committed_sequence"]))
    {
        return false;
    }
    // Sequence commitments use the schema digest width so cross-field validation cannot drift from primitive parsing.
    for (seq, digest) in [
        ("committed_sequence", "committed_digest"),
        ("drained_sequence", "drained_digest"),
    ] {
        if (n(a, seq) == 0) != (a[digest] == "GENESIS")
            || !(a[digest] == "GENESIS" || hex(&a[digest], "sha256:", DIGEST_HEX_LENGTH))
        {
            return false;
        }
    }
    (a["recovery_required"] == true) != a["recovery_reason"].is_null()
        && (a["recovery_required"] != true || n(a, "recovery_revision") > 0)
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
    let needs_body = BODY_DIGEST_OPS.contains(&m["op"].as_str()?)
        || (m["op"] == BODY_DIGEST_CONDITIONAL_OP
            && m["expected"].is_object()
            && m["expected"][BODY_DIGEST_EXPECTED_FIELD].is_null());
    let mut keys = MESSAGE_KEYS.to_vec();
    if needs_body {
        keys.push("body_digest");
    }
    // The message digest names the frozen body; the reducer checks it against the reservation.
    if !exact(&m, &keys)
        || (needs_body && !domain_valid(&m["body_digest"], "digest"))
        || m["version"] != 1
        // Request identity uses the schema width just like anchor identities.
        || !hex(&m["request_id"], "", ID_HEX_LENGTH)
        || !OPS.contains(&m["op"].as_str()?)
        || !(valid(&m["expected"]) || (m["expected"].is_null() && m["op"] == "PREPARE"))
        || ((m["op"] == "READ") != m["next"].is_null())
        || (!m["next"].is_null() && !valid(&m["next"]))
        || crate::smb::jcs::encode(&m).ok()?.as_bytes() != bytes
    {
        return None;
    }
    Some(m)
}
/// Return a checked proposal, never a durable acknowledgment or signing grant.
pub fn propose(prior: Prior<'_>, message: &Value) -> Option<Value> {
    let m = decode_message(crate::smb::jcs::encode(message).ok()?.as_bytes())?;
    let old = match prior {
        Prior::Present(old) => old,
        Prior::Absent => {
            let next = &m["next"];
            // An absent slot can only be created by an attended provisioning prepare; no other operation may conjure history.
            return (m["op"] == "PREPARE"
                && m["expected"].is_null()
                && next["enrollment_revision"] == 1
                && next["reserved_sequence"] == 0
                && next["committed_sequence"] == 0
                && next["drained_sequence"] == 0
                && next["committed_digest"] == "GENESIS"
                && next["drained_digest"] == "GENESIS"
                && next["retired"] == false
                && next["recovery_required"] == false
                && next["recovery_reason"].is_null()
                && next["recovery_revision"] == 0
                && next["transaction_id"] == m["request_id"]
                && next["reserved_body_digest"].is_null())
            .then(|| next.clone());
        }
    };
    // The entire expected tuple binds this proposal to one observed anchor and sticky latch.
    if !valid(old) || old != &m["expected"] {
        return None;
    }
    // A recovery latch freezes the observed tail and transaction until the named recovery path proves completion.
    // Must match LATCH_DENIED_OPS in activation-anchor.ts and the generated protocol rule.
    if old["recovery_required"] == true
        && super::protocol_transitions::LATCH_DENIED_OPS.contains(&m["op"].as_str()?)
    {
        return None;
    }
    if m["op"] == "READ" {
        return Some(old.clone());
    }
    let next = &m["next"];
    let changed: &[&str] = match m["op"].as_str()? {
        "RESERVE" => {
            if old["retired"] == true
                || !old["transaction_id"].is_null()
                || old["reserved_sequence"] != old["committed_sequence"]
                || !old["reserved_body_digest"].is_null()
                || n(next, "reserved_sequence") != n(old, "reserved_sequence") + 1
                || next["reserved_body_digest"] != m["body_digest"]
            {
                return None;
            }
            &["reserved_sequence", "reserved_body_digest"]
        }
        "COMMIT" => {
            if !old["transaction_id"].is_null() {
                // The prepared request owns custody completion, so another request cannot settle it.
                if m["request_id"] != old["transaction_id"] || !next["transaction_id"].is_null() {
                    return None;
                }
                &["transaction_id"]
            } else {
                if n(old, "reserved_sequence") != n(old, "committed_sequence") + 1
                    || next["committed_sequence"] != old["reserved_sequence"]
                    || next["committed_digest"] == old["committed_digest"]
                    // The reserved digest is evidence for this body only, never a different signed body.
                    || m["body_digest"] != old["reserved_body_digest"]
                    || !next["reserved_body_digest"].is_null()
                {
                    return None;
                }
                &[
                    "committed_sequence",
                    "committed_digest",
                    "reserved_body_digest",
                ]
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
            if old["retired"] == true
                || !old["transaction_id"].is_null()
                || old["reserved_sequence"] != old["committed_sequence"]
                || !old["reserved_body_digest"].is_null()
                || n(next, "enrollment_revision") != n(old, "enrollment_revision") + 1
                || next["transaction_id"] != m["request_id"]
            {
                return None;
            }
            PREPARE_CHANGED_FIELDS
        }
        "LATCH" => {
            if next["recovery_required"] != true
                || n(next, "recovery_revision") != n(old, "recovery_revision") + 1
            {
                return None;
            }
            &["recovery_required", "recovery_reason", "recovery_revision"]
        }
        "ADVANCE_GENERATION" | "ADVANCE_ACTIVATION" | "ADVANCE_BOOT" => {
            // New grant identities require a settled tail and increasing generation to prevent reuse.
            if old["retired"] == true
                || !old["transaction_id"].is_null()
                || old["reserved_sequence"] != old["committed_sequence"]
                || !old["reserved_body_digest"].is_null()
                || old["drained_sequence"] != old["committed_sequence"]
                || old["drained_digest"] != old["committed_digest"]
                || n(next, "generation_high_water") != n(old, "generation_high_water") + 1
            {
                return None;
            }
            match m["op"].as_str()? {
                "ADVANCE_ACTIVATION" => {
                    // Must match activation-anchor.ts: fixed-length lowercase hex identities compare in numeric order and strictly increase, so an earlier activation can never return.
                    if next["activation_id"].as_str()? <= old["activation_id"].as_str()? {
                        return None;
                    }
                    &["generation_high_water", "activation_id"]
                }
                "ADVANCE_BOOT" => {
                    // A boot advance changes its identity, and with the strictly increasing generation no (boot, generation) pair repeats.
                    if next["boot_id"] == old["boot_id"] {
                        return None;
                    }
                    &["generation_high_water", "boot_id"]
                }
                _ => &["generation_high_water"],
            }
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
        // A matching custody copy cannot certify records that the drain has not acknowledged, so every drained tuple field is settled at the committed tail.
        && DRAIN_TUPLE_FIELDS.iter().all(|field| {
            let settled = if field.ends_with("_sequence") {
                "committed_sequence"
            } else {
                "committed_digest"
            };
            drain[*field] == drain[settled]
        })
}
/// The anchor a recovery PREPARE steps from: the prior anchor carrying the reconciled drain's drained tuple, or None when the drain disagrees with the prior anchor anywhere else.
/// Must match recoveryPrepareBase in activation-anchor.ts and the recover group in closure_vectors.json.
pub fn recovery_prepare_base(prior: &Value, drain: &Value) -> Option<Value> {
    if !valid(prior) || !valid(drain) {
        return None;
    }
    let (before, after) = (prior.as_object()?, drain.as_object()?);
    // Outside the drained tuple the drain must be the prior anchor itself, so a recovery cannot carry in a foreign generation, identity or latch history.
    if before.iter().any(|(key, value)| {
        !DRAIN_TUPLE_FIELDS.contains(&key.as_str()) && after.get(key) != Some(value)
    }) {
        return None;
    }
    let mut base = before.clone();
    for field in DRAIN_TUPLE_FIELDS {
        base.insert(field.to_string(), after.get(*field)?.clone());
    }
    let base = Value::Object(base);
    valid(&base).then_some(base)
}

/// A missing slot is a typed prior, never a fabricated revision-zero anchor.
#[derive(Clone, Copy)]
pub enum Prior<'a> {
    Absent,
    Present(&'a Value),
}
/// Observation is independent of proposal admission and cannot clear a latch.
pub fn observe(prior: Prior<'_>) -> Value {
    match prior {
        Prior::Absent => serde_json::json!({"state":"ABSENT", "latched":false}),
        Prior::Present(a) => {
            serde_json::json!({"state":"PRESENT", "latched":a["recovery_required"] == true})
        }
    }
}
fn domain_valid(v: &Value, domain: &str) -> bool {
    match domain {
        "literal1" => v == 1,
        "producer" => v == PRODUCER_ROLE,
        "id" => hex(v, "", ID_HEX_LENGTH),
        "digest" => hex(v, "sha256:", DIGEST_HEX_LENGTH),
        "commitment" => v == "GENESIS" || domain_valid(v, "digest"),
        "boolean" => v.is_boolean(),
        "nullableId" => v.is_null() || domain_valid(v, "id"),
        "nullableDigest" => v.is_null() || domain_valid(v, "digest"),
        "nullableReason" => v.is_null() || v.as_str().is_some_and(|s| REASONS.contains(&s)),
        "safeInteger" => v.as_u64().is_some_and(|n| n <= SAFE_INTEGER),
        "positiveInteger" => v.as_u64().is_some_and(|n| n > 0 && n <= SAFE_INTEGER),
        "registeredRole" => v.as_str().is_some_and(|s| {
            super::signer_contract::ROLE_REGISTRY
                .iter()
                .any(|r| r.0 == s)
        }),
        "key" => hex(v, "", KEY_HEX_LENGTH),
        "kid" => hex(v, "k1:sha256:", DIGEST_HEX_LENGTH),
        "epochs" => v.is_array(),
        _ => false,
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorEpoch {
    pub role: String,
    pub epoch: u64,
    pub kid: String,
    pub public_key: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub fortress_id: String,
    pub machine_id: String,
    pub identity_id: String,
    pub epochs: Vec<DescriptorEpoch>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DescriptorRefusal {
    SIZE,
    DIGEST,
    CANONICAL,
    SHAPE,
    ID,
    COUNT,
    ENTRY_SHAPE,
    ROLE,
    EPOCH,
    KEY,
    KID,
    ORDER,
}
/// The descriptor pin authenticates public history; parsed keys authorize only their own role and epoch.
pub fn parse_descriptor(bytes: &[u8], pin: &str) -> Result<Descriptor, DescriptorRefusal> {
    use DescriptorRefusal::*;
    if bytes.len() > D_DESCRIPTOR_MAX_BYTES {
        return Err(SIZE);
    }
    // Authenticate the exact public evidence before interpreting any historical key.
    if format!("sha256:{}", hex::encode(Sha256::digest(bytes))) != pin {
        return Err(DIGEST);
    }
    let raw =
        crate::smb::strict_json::parse(bytes, D_DESCRIPTOR_MAX_BYTES).map_err(|_| CANONICAL)?;
    if crate::smb::jcs::encode(&raw)
        .map_err(|_| CANONICAL)?
        .as_bytes()
        != bytes
    {
        return Err(CANONICAL);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| CANONICAL)?;
    let root: Vec<_> = DESCRIPTOR_ROOT.iter().map(|(k, _)| *k).collect();
    if !exact(&v, &root)
        || !domain_valid(&v["version"], "literal1")
        || !domain_valid(&v["epochs"], "epochs")
    {
        return Err(SHAPE);
    }
    if DESCRIPTOR_ROOT
        .iter()
        .filter(|(_, d)| *d == "id")
        .any(|(k, d)| !domain_valid(&v[*k], d))
    {
        return Err(ID);
    }
    let entries = v["epochs"].as_array().ok_or(SHAPE)?;
    if entries.is_empty() || entries.len() > D_DESCRIPTOR_EPOCHS_MAX {
        return Err(COUNT);
    }
    let fields: Vec<_> = DESCRIPTOR_ENTRY.iter().map(|(k, _)| *k).collect();
    let mut epochs: Vec<DescriptorEpoch> = Vec::new();
    for entry in entries {
        if !exact(entry, &fields) {
            return Err(ENTRY_SHAPE);
        }
        for (key, stage) in [
            ("role", ROLE),
            ("epoch", EPOCH),
            ("public_key", KEY),
            ("kid", KID),
        ] {
            let domain = DESCRIPTOR_ENTRY
                .iter()
                .find(|(k, _)| *k == key)
                .ok_or(ENTRY_SHAPE)?
                .1;
            if !domain_valid(&entry[key], domain) {
                return Err(stage);
            }
        }
        let role = entry["role"].as_str().ok_or(ROLE)?;
        let epoch = entry["epoch"].as_u64().ok_or(EPOCH)?;
        let public_key: [u8; 32] = hex::decode(entry["public_key"].as_str().ok_or(KEY)?)
            .map_err(|_| KEY)?
            .try_into()
            .map_err(|_| KEY)?;
        let kid = entry["kid"].as_str().ok_or(KID)?;
        // The role registry and decoded key, not the descriptor's hex spelling, determine the kid.
        if super::role_kid(role, epoch, &public_key).as_deref() != Some(kid) {
            return Err(KID);
        }
        if epochs
            .last()
            .is_some_and(|last| (last.role.as_str(), last.epoch) >= (role, epoch))
        {
            return Err(ORDER);
        }
        epochs.push(DescriptorEpoch {
            role: role.into(),
            epoch,
            kid: kid.into(),
            public_key,
        });
    }
    Ok(Descriptor {
        fortress_id: v["fortress_id"].as_str().ok_or(ID)?.into(),
        machine_id: v["machine_id"].as_str().ok_or(ID)?.into(),
        identity_id: v["identity_id"].as_str().ok_or(ID)?.into(),
        epochs,
    })
}
