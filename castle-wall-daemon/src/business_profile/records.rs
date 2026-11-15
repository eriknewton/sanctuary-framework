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

/// Parse original join-state bytes; this pure boundary grants no checkpoint authority.
pub fn decode_join_state(bytes: &[u8]) -> Option<Value> {
    decode_join_state_checked(bytes).ok()
}
fn decode_join_state_checked(bytes: &[u8]) -> Result<Value, String> {
    // Bound original bytes before allocating; canonical equality rejects duplicate keys and alternate spellings.
    if bytes.len() > JOIN_STATE_BYTES_MAX {
        return Err("SMB JSON size".into());
    }
    let state: Value = serde_json::from_slice(bytes).map_err(|_| "JOIN_JSON")?;
    if !join_state_valid(&state) {
        return Err("JOIN_STATE".into());
    }
    // Must match parseJoinState in record-joins.ts: only original canonical bytes admit authority.
    // Closed join domains contain ASCII keys/strings and unsigned safe integers. Their serde encoding
    // equals JCS, avoiding general binary64 formatting for every retained history number.
    if canonical_integer_domain(&state).as_deref() != Some(bytes) {
        return Err("JOIN_CANONICAL".into());
    }
    Ok(state)
}

/// Canonical serialization for the closed ASCII/integer protocol domain, never arbitrary JSON.
pub(crate) fn canonical_integer_domain(value: &Value) -> Option<Vec<u8>> {
    fn admitted(v: &Value) -> bool {
        match v {
            Value::Null | Value::Bool(_) => true,
            Value::Number(n) => n.as_u64().is_some_and(|n| n <= SAFE_INTEGER),
            Value::String(s) => s.is_ascii(),
            Value::Array(a) => a.iter().all(admitted),
            Value::Object(o) => o.iter().all(|(k, v)| k.is_ascii() && admitted(v)),
        }
    }
    admitted(value)
        .then(|| serde_json::to_vec(value).ok())
        .flatten()
}

/// Must match BUSINESS_PIN_FIELDS in producer-custody.ts and verify_pin_fields in closure_vectors.json: the one business verify contract binds the enrolled subject and the grant's activation, lease and generation.
pub const VERIFY_PIN_FIELDS: &[&str] = &[
    "role",
    "epoch",
    "kid",
    "identity_id",
    "machine_id",
    "activation_id",
    "lease_id",
    "generation",
];
/// Verify the record against an independently enrolled role, identity, machine and key pin.
pub fn verify(bytes: &[u8], signature: &[u8], pin: &Value, public_key: &[u8]) -> bool {
    let Some(body) = decode(bytes) else {
        return false;
    };
    // The pin describes the producer subject and grant, so a signature alone cannot substitute another identity or lease.
    // Must match SigningGrant in record-signer.ts and verifyIndexedRecord in producer-custody.ts.
    if VERIFY_PIN_FIELDS.iter().any(|key| body[*key] != pin[*key]) {
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

// Must match record-joins.ts and all three record_join_vectors.json consumers, including refusal precedence and retained state.
pub const JOIN_HISTORY_MAX: usize = 64; // The design retains sixty-four replay records without live eviction.
pub const COUNTER_PERIOD_NS: u64 = 1_000_000_000; // One second in nanoseconds.
/// Must match JOIN_STATE_SCHEMA in record-joins.ts and state_schema in record_join_vectors.json, which both executors pin as a whole set.
#[rustfmt::skip]
mod bounded_contract { include!("join_state_contract.rs"); }
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
pub use bounded_contract::{
    JOIN_STATE_BYTES_MAX, JOIN_STATE_SCHEMA, POLICY_AGENT_UIDS_MAX, POLICY_VENDORS_MAX,
};
use bounded_contract::{OUTER_INDEX, PORT_MAX, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
fn canonical_base64(v: &Value, bytes: usize) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == (bytes * 8).div_ceil(6)
            && URL_SAFE_NO_PAD
                .decode(s)
                .is_ok_and(|decoded| decoded.len() == bytes && URL_SAFE_NO_PAD.encode(decoded) == s)
    })
}
/// Closed producer index; the caller first validates the body's generated domains.
pub fn outer_valid(record: &Value) -> bool {
    // Body validation plus named outer lookups and exact counts close both wrapper key sets.
    // Must match joinOuterValid in record-joins.ts: retained wrappers cannot carry unbounded unsigned data.
    record.as_object().is_some_and(|fields| fields.len() == 2)
        && record["outer"].as_object().is_some_and(|outer| {
            outer.len() == OUTER_INDEX.len() + 1
                && OUTER_INDEX.iter().all(|key| {
                    outer.get(*key).is_some() && outer.get(*key) == record["body"].get(*key)
                })
                && canonical_base64(&record["outer"]["signature"], SIGNATURE_BYTES)
        })
}
const SAFE_INTEGER: u64 = 9_007_199_254_740_991; // Largest exact JavaScript integer, 2^53 - 1.
const ID_HEX_LENGTH: usize = 32; // Sixteen-byte identifiers in lowercase hex.
const DIGEST_HEX_LENGTH: usize = 64; // SHA-256 digests in lowercase hex.
fn lower_hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
// Must match safeU64 in record-joins.ts: as_u64 refuses negative zero and every floating Number.
fn safe_u64(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= SAFE_INTEGER)
}
/// Must match STATE_TOKENS in record-joins.ts: each token admits one exact representation.
fn state_token(token: &str, v: &Value) -> bool {
    match token {
        "role" => v.as_str().is_some_and(|s| {
            super::signer_contract::ROLE_REGISTRY
                .iter()
                .any(|entry| entry.0 == s)
        }),
        // Must match records_schema.rs encoding: the record schema owns kid and IPv4 domains.
        "kid" => records_schema::encoding(v, "kid"),
        "public_key" => canonical_base64(v, PUBLIC_KEY_BYTES),
        "id" => v.as_str().is_some_and(|s| lower_hex(s, ID_HEX_LENGTH)),
        "digest" => v
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .is_some_and(|s| lower_hex(s, DIGEST_HEX_LENGTH)),
        "commitment" => v == "GENESIS" || state_token("digest", v),
        "safe_u64" => safe_u64(v),
        // Canonical decimal text only: no sign, whitespace, radix prefix, leading zero or u64 overflow.
        "u64_text" => v.as_str().is_some_and(|s| {
            !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'))
                && s.parse::<u64>().is_ok()
        }),
        // Canonical bounded policies preserve caller bytes and refuse duplicates instead of sorting.
        "safe_u64_list" => v.as_array().is_some_and(|a| {
            a.len() <= POLICY_AGENT_UIDS_MAX
                && a.iter().all(safe_u64)
                && a.windows(2).all(|w| w[0].as_u64() < w[1].as_u64())
        }),
        "vendor_list" => v.as_array().is_some_and(|a| {
            a.len() <= POLICY_VENDORS_MAX
                && a.iter().all(|e| {
                    e.as_object().is_some_and(|o| o.len() == 2)
                        && records_schema::encoding(&e["address"], "ipv4")
                        && e["port"].as_u64().is_some_and(|n| n <= PORT_MAX)
                })
                && a.windows(2).all(|w| {
                    (w[0]["address"].as_str(), w[0]["port"].as_u64())
                        < (w[1]["address"].as_str(), w[1]["port"].as_u64())
                })
        }),
        // Retained history holds only bounded, schema-valid records, so history lookups interpret the same values in both executors.
        "history" => v.as_array().is_some_and(|a| {
            a.len() <= JOIN_HISTORY_MAX
                && a.iter().all(|e| {
                    e.as_object().is_some_and(|o| o.len() == 2)
                        && e.get("body").is_some_and(records_schema::valid)
                        && outer_valid(e)
                })
        }),
        _ => false,
    }
}
/// Parse the relying-party join state against the one shared state schema before any record field is read.
pub fn join_state_valid(state: &Value) -> bool {
    state
        .as_object()
        .is_some_and(|o| o.len() == JOIN_STATE_SCHEMA.len())
        && JOIN_STATE_SCHEMA.iter().all(|(name, fields)| {
            state[*name]
                .as_object()
                .is_some_and(|o| o.len() == fields.len())
                && fields.iter().all(|(key, token)| {
                    state[*name]
                        .get(*key)
                        .is_some_and(|v| state_token(token, v))
                })
        })
}
fn number(value: &Value) -> Result<u64, &'static str> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .ok_or("INPUT")
}
fn counts_le(a: &Value, b: &Value) -> Result<bool, &'static str> {
    for direction in ["original", "reply"] {
        for unit in ["ip_bytes", "packets"] {
            if number(&a[direction][unit])? > number(&b[direction][unit])? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
fn same_context(a: &Value, b: &Value) -> bool {
    a["payload"]["context"] == b["payload"]["context"]
}
fn prior<'a>(history: &'a [Value], sequence: &Value, kind: &str) -> &'a Value {
    history
        .iter()
        .find(|r| r["body"]["sequence"] == *sequence && r["body"]["record_kind"] == kind)
        .map(|r| &r["body"])
        .unwrap_or(&Value::Null)
}
/// Hash the canonical signed envelope, including its signature, after caller-side verification.
pub fn join_commitment(record: &Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let envelope =
        serde_json::json!({"body":record["body"], "signature":record["outer"]["signature"]});
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            crate::smb::jcs::encode(&envelope).ok()?.as_bytes()
        ))
    ))
}
#[cfg(test)]
thread_local! {
    pub(super) static ADVANCE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
/// Pure history validation only; callers authenticate the checkpoint and verify signatures separately.
pub fn advance(state: &Value, record: &Value) -> Result<Value, &'static str> {
    #[cfg(test)]
    ADVANCE_CALLS.with(|calls| calls.set(calls.get() + 1));
    // Malformed relying-party state refuses before any record field is read, so INPUT precedes SCHEMA in both executors.
    if !join_state_valid(state) {
        return Err("INPUT");
    }
    let b = &record["body"];
    let p = &b["payload"];
    let history = state["flow_state"]["history"].as_array().ok_or("INPUT")?;
    // Generated validation owns all intra-record predicates before any history value is interpreted.
    if !records_schema::valid(b) {
        return Err("SCHEMA");
    }
    // The outer index must match every indexed signed field so storage cannot relabel an authentic body.
    if !outer_valid(record) {
        return Err("OUTER");
    }
    // The relying party's enrolled subject and grant constrain the producer's self-description.
    if ["role", "epoch", "kid", "identity_id", "machine_id"]
        .iter()
        .any(|key| b[*key] != state["pin"][*key])
    {
        return Err("PIN");
    }
    // Grant identity and expiry bind each record to the relying session.
    if ["boot_id", "activation_id", "lease_id", "generation"]
        .iter()
        .any(|key| b[*key] != state["grant"][*key])
        || number(&b["captured_at_boottime_ns"])? > number(&state["grant"]["expires_ns"])?
    {
        return Err("GRANT");
    }
    let anchor = &state["anchor"];
    // Exact consecutive sequences and signed-envelope commitments prevent replay, omission and body-only chaining.
    if number(&b["sequence"])? != number(&anchor["sequence"])?.checked_add(1).ok_or("CHAIN")?
        || b["prior_commitment"] != anchor["commitment"]
        || number(&b["captured_at_boottime_ns"])? < number(&anchor["captured_at_boottime_ns"])?
    {
        return Err("CHAIN");
    }
    // Relying policy commitments cannot be selected by the signed record itself.
    if ["policy_digest", "runtime_digest", "config_digest"]
        .iter()
        .any(|key| b[*key] != state["policy"][*key])
    {
        return Err("POLICY");
    }
    // Evidence exhaustion refuses admission instead of evicting a still-replayable reference or permit.
    if history.len() >= JOIN_HISTORY_MAX {
        return Err("CAPACITY");
    }
    let boundary = b["record_kind"] == "control" && p["type"] == "lease_boundary";
    let changed_lease =
        b["lease_id"] != anchor["lease_id"] || b["generation"] != anchor["generation"];
    // Lease transitions name the original checkpoint and restart gaps rather than silently resetting continuity.
    if changed_lease || boundary {
        let genesis = anchor["sequence"] == 0;
        if !boundary
            || (if genesis {
                p["boundary"] != "activation_start"
            } else {
                p["boundary"] == "activation_start"
                    || !changed_lease
                    || number(&b["generation"])? <= number(&anchor["generation"])?
                    || p["previous_lease_id"] != anchor["lease_id"]
                    || p["previous_generation"] != anchor["generation"]
            })
            || p["previous_sequence"] != anchor["sequence"]
            || p["previous_commitment"] != anchor["commitment"]
            // Must match record-joins.ts: a restart gap covers the checkpoint at both ends, as a counter epoch change does.
            || (p["boundary"] == "restart"
                && (number(&p["gap"]["first_ns"])? > number(&anchor["captured_at_boottime_ns"])?
                    || number(&p["gap"]["last_ns"])?
                        < number(&anchor["captured_at_boottime_ns"])?))
        {
            return Err("BOUNDARY");
        }
    }
    let context = &p["context"];
    let flow = &context["flow"];
    let opened = prior(history, &flow["open_sequence"], "open");
    let same_flow: Vec<&Value> = history
        .iter()
        .map(|r| &r["body"])
        .filter(|r| !flow.is_null() && r["payload"]["context"]["flow"] == *flow)
        .collect();
    // Contextual continuations name an earlier immutable open and cannot continue a terminal flow.
    if !context.is_null()
        && b["record_kind"] != "open"
        && (opened.is_null()
            || !same_context(b, opened)
            || same_flow.iter().any(|r| r["record_kind"] == "terminal"))
    {
        return Err("CONTEXT");
    }
    if b["record_kind"] == "open" {
        // The actual open sequence owns the flow identity so references cannot alias another flow.
        if flow["open_sequence"] != b["sequence"] {
            return Err("OPEN_SEQUENCE");
        }
        if p["edge"] == "agent_endpoint" {
            // The relying policy determines which agent may initiate the listener flow.
            if !state["policy"]["agent_uids"]
                .as_array()
                .ok_or("INPUT")?
                .contains(&context["actor_uid"])
            {
                return Err("LISTENER");
            }
        } else {
            let origin = prior(history, &p["origin_link_sequence"], "link");
            let ingress = prior(
                history,
                &origin["payload"]["link"]["ingress_sequence"],
                "link",
            );
            // Vendor opens inherit an earlier egress origin and its observed endpoint actor.
            if origin.is_null()
                || origin["payload"]["link"]["kind"] != "egress"
                || ingress.is_null()
                || context["actor_uid"] != ingress["payload"]["link"]["listener"]["uid"]
                || context["netns_inode"] != origin["payload"]["context"]["netns_inode"]
            {
                return Err("ORIGIN");
            }
            // Only a pinned IPv4 TCP vendor destination inherits the admitted origin.
            if context["original"]["family"] != "ipv4"
                || context["original"]["protocol"] != "tcp"
                || !state["policy"]["vendors"]
                    .as_array()
                    .ok_or("INPUT")?
                    .iter()
                    .any(|v| {
                        v["address"] == context["original"]["dst_ip"]
                            && v["port"] == context["original"]["dst_port"]
                    })
            {
                return Err("VENDOR");
            }
        }
    }
    if b["record_kind"] == "link" {
        let agent = prior(history, &p["link"]["agent_flow"]["open_sequence"], "open");
        // The full agent flow is checked against the earlier agent open rather than trusting a sequence alone.
        if agent.is_null()
            || agent["payload"]["edge"] != "agent_endpoint"
            || agent["payload"]["context"]["flow"] != p["link"]["agent_flow"]
        {
            return Err("AGENT_FLOW");
        }
        if p["link"]["kind"] == "ingress" {
            // Ingress evidence binds the listener to the earlier agent open while the accepted socket remains a separate observation.
            if !same_context(b, agent) || p["link"]["listener"] != agent["payload"]["listener"] {
                return Err("INGRESS");
            }
        } else {
            let ingress = prior(history, &p["link"]["ingress_sequence"], "link");
            // Egress attribution comes from the referenced ingress and original agent actor.
            if ingress.is_null()
                || ingress["payload"]["link"]["kind"] != "ingress"
                || ingress["payload"]["link"]["agent_flow"] != p["link"]["agent_flow"]
                || p["link"]["origin_agent_uid"] != agent["payload"]["context"]["actor_uid"]
            {
                return Err("EGRESS");
            }
        }
    }
    if b["record_kind"] == "allowance" {
        let link = prior(history, &p["link_sequence"], "link");
        // Allowance budget inherits exactly the open's origin rather than an unrelated link.
        if link.is_null()
            || (if opened["payload"]["edge"] == "endpoint_vendor" {
                p["link_sequence"] != opened["payload"]["origin_link_sequence"]
            } else {
                link["payload"]["link"]["kind"] != "ingress" || !same_context(b, link)
            })
        {
            return Err("ALLOWANCE_LINK");
        }
        let previous = same_flow
            .iter()
            .rev()
            .find(|r| r["record_kind"] == "allowance");
        // Cumulative lifetime ceilings cannot decrease when a replacement permit is allocated.
        if let Some(previous) = previous {
            if !counts_le(&previous["payload"]["ceiling"], &p["ceiling"])? {
                return Err("CUMULATIVE");
            }
        }
        // Permit identifiers stay reserved for the entire retained history, including across flows.
        if history.iter().any(|r| {
            r["body"]["record_kind"] == "allowance"
                && r["body"]["payload"]["permit_id"] == p["permit_id"]
        }) {
            return Err("PERMIT_UNIQUE");
        }
        // Packet authority cannot outlive the relying grant's fixed expiry.
        if number(&p["expires_ns"])? > number(&state["grant"]["expires_ns"])? {
            return Err("EXPIRY");
        }
    }
    if b["record_kind"] == "counter" {
        let allowance = prior(history, &p["allowance_sequence"], "allowance");
        // Counters consume only the same flow's cumulative directional allowance.
        if allowance.is_null() || !same_context(b, allowance) {
            return Err("COUNTER_ALLOWANCE");
        }
        // Observed directional totals cannot exceed the referenced cumulative allowance.
        if !counts_le(&p["totals"], &allowance["payload"]["ceiling"])? {
            return Err("CEILING");
        }
        let previous = same_flow
            .iter()
            .rev()
            .find(|r| r["record_kind"] == "counter")
            .copied()
            .unwrap_or(&Value::Null);
        // Final observations close counters and periodic observations obey the cap starting at open.
        if previous["payload"]["checkpoint"] == "final" {
            return Err("FINAL_CLOSED");
        }
        let last = if previous.is_null() { opened } else { previous };
        // The periodic rate bound starts at open and repeats from the previous counter.
        if p["checkpoint"] == "periodic"
            && number(&b["captured_at_boottime_ns"])?
                .saturating_sub(number(&last["captured_at_boottime_ns"])?)
                < COUNTER_PERIOD_NS
        {
            return Err("PERIODIC");
        }
        if !previous.is_null() {
            // Same-epoch time and totals cannot erase prior observed usage.
            if number(&p["window"]["last_ns"])? < number(&previous["payload"]["window"]["last_ns"])?
                || (p["counter_epoch"] == previous["payload"]["counter_epoch"]
                    && !counts_le(&previous["payload"]["totals"], &p["totals"])?)
            {
                return Err("MONOTONE");
            }
            // Epoch changes carry an incomplete interval covering the last trusted observation.
            if p["counter_epoch"] != previous["payload"]["counter_epoch"]
                && (p["complete"] != false
                    || number(&p["gap"]["first_ns"])?
                        > number(&previous["payload"]["window"]["last_ns"])?
                    || number(&p["gap"]["last_ns"])?
                        < number(&previous["payload"]["window"]["last_ns"])?)
            {
                return Err("EPOCH_GAP");
            }
        }
    }
    if b["record_kind"] == "terminal" && !p["final_counter_sequence"].is_null() {
        let final_record = prior(history, &p["final_counter_sequence"], "counter");
        // Terminals name their own final counter without promoting periodic or incomplete observations.
        if final_record.is_null()
            || !same_context(b, final_record)
            || final_record["payload"]["checkpoint"] != "final"
            || (p["effect"] == "OBSERVED" && final_record["payload"]["complete"] != true)
        {
            return Err("TERMINAL");
        }
    }
    if b["record_kind"] == "control" && p["type"] == "permit" {
        let allowance = prior(history, &p["allowance_sequence"], "allowance");
        // Each permit consumes the exact flow and identifier of one earlier allowance.
        if allowance.is_null()
            || p["flow"] != allowance["payload"]["context"]["flow"]
            || p["permit_id"] != allowance["payload"]["permit_id"]
        {
            return Err("PERMIT_LINK");
        }
        let issued: Vec<&Value> = history
            .iter()
            .filter(|r| {
                r["body"]["payload"]["type"] == "permit"
                    && r["body"]["payload"]["permit_id"] == p["permit_id"]
            })
            .collect();
        // One issuance followed by at most one settlement prevents reuse of the reserved permit.
        if if p["outcome"] == "issued" {
            !issued.is_empty()
        } else {
            issued.len() != 1
                || issued.first().ok_or("INPUT")?["body"]["payload"]["outcome"] != "issued"
        } {
            return Err("PERMIT_ONCE");
        }
        // Issuance expires with its allowance while later settlement remains recordable.
        if p["outcome"] == "issued"
            && number(&b["captured_at_boottime_ns"])? > number(&allowance["payload"]["expires_ns"])?
        {
            return Err("PERMIT_EXPIRED");
        }
    }
    let mut next = state.clone();
    next["anchor"] = serde_json::json!({"sequence":b["sequence"], "commitment":join_commitment(record).ok_or("INPUT")?, "lease_id":b["lease_id"], "generation":b["generation"], "captured_at_boottime_ns":b["captured_at_boottime_ns"]});
    next["flow_state"]["history"]
        .as_array_mut()
        .ok_or("INPUT")?
        .push(record.clone());
    Ok(next)
}

#[cfg(all(test, target_os = "linux"))]
mod bounded_tests {
    use super::super::{append_contract, join_lifecycle};
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_join_byte_cap_precedes_parsing() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/join-byte-boundary.json"))
                .unwrap();
        let bytes =
            vec![b'!'; JOIN_STATE_BYTES_MAX + fixture["over_cap_bytes"].as_u64().unwrap() as usize];
        assert_eq!(
            decode_join_state_checked(&bytes).unwrap_err(),
            "SMB JSON size",
            "raw join byte gate before parser"
        );
        assert!(decode_join_state(&bytes).is_none());
        let contract = append_contract::contract().unwrap();
        let state = &contract["lifecycle_states"]["ready"]["committed"];
        let valid = crate::smb::jcs::encode(state).unwrap();
        assert!(
            decode_join_state(valid.as_bytes()).is_some(),
            "canonical seed positive control"
        );
        let bytes = vec![b'!'; JOIN_STATE_BYTES_MAX];
        assert_ne!(
            decode_join_state_checked(&bytes).unwrap_err(),
            "SMB JSON size",
            "inclusive byte gate control"
        );
    }

    #[test]
    fn raw_join_numbers_refuse_before_admission() {
        let rows: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/join-raw-numbers.json"))
                .unwrap();
        for row in rows.as_array().unwrap() {
            assert_eq!(
                decode_join_state(row["raw"].as_str().unwrap().as_bytes()).is_some(),
                row["valid"].as_bool().unwrap(),
                "raw number boundary {}",
                row["id"]
            );
        }
    }

    #[test]
    fn shared_bounded_join_paths() {
        let rows: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/join-bounds.json")).unwrap();
        let contract = append_contract::contract().unwrap();
        let seed = &contract["lifecycle_states"]["ready"]["committed"];
        let record = &contract["lifecycle_events"]["admit"]["record"];
        for row in rows.as_array().unwrap() {
            let id = row["id"].as_str().unwrap();
            let valid = row["valid"].as_bool().unwrap();
            let path = row["path"].as_str().unwrap();
            let mut state = seed.clone();
            if path.starts_with("flow_state") {
                state["flow_state"]["history"] = json!([record]);
            }
            let keys: Vec<_> = path.split('.').collect();
            let mut target = &mut state;
            for key in keys {
                target = if let Ok(i) = key.parse::<usize>() {
                    &mut target[i]
                } else {
                    &mut target[key]
                };
            }
            *target = row["value"].clone();
            assert_eq!(join_state_valid(&state), valid, "state boundary {id}");
            assert_eq!(
                join_lifecycle::step(
                    &join_lifecycle::initial(),
                    &json!({"type":"Checkpoint","checkpoint":state})
                )
                .is_some(),
                valid,
                "seed boundary {id}"
            );
            let mut lifecycle = join_lifecycle::initial();
            lifecycle["committed"] = state.clone();
            assert_eq!(
                join_lifecycle::step(&lifecycle, &json!({"type":"NextGrant"})).is_some(),
                valid,
                "retained boundary {id}"
            );
            lifecycle = join_lifecycle::initial();
            lifecycle["provisional"] = json!({"state":state,"signed":false,"identity":null});
            assert_eq!(
                join_lifecycle::step(&lifecycle, &json!({"type":"LostOrUnmatched"})).is_some(),
                valid,
                "provisional boundary {id}"
            );
            let wal = json!({"committed_sequence":0,"committed_digest":"GENESIS","drained_sequence":0,"drained_digest":"GENESIS","retained_originals":[],"join_state":state,"unresolved_intent":false});
            assert_eq!(
                append_contract::shape("wal_checkpoint", &wal),
                valid,
                "checkpoint boundary {id}"
            );
            if !valid {
                assert_eq!(
                    advance(&state, record),
                    Err("INPUT"),
                    "advance boundary {id}"
                );
            }
        }
        for role in super::super::signer_contract::ROLE_REGISTRY {
            let mut maximum = seed.clone();
            maximum["pin"]["role"] = json!(role.0);
            maximum["policy"]["agent_uids"] = json!(
                (SAFE_INTEGER - POLICY_AGENT_UIDS_MAX as u64 + 1..=SAFE_INTEGER)
                    .collect::<Vec<_>>()
            );
            maximum["policy"]["vendors"] = json!((PORT_MAX - POLICY_VENDORS_MAX as u64 + 1
                ..=PORT_MAX)
                .map(|port| json!({"address":"255.255.255.255","port":port}))
                .collect::<Vec<_>>());
            let largest: Value =
                serde_json::from_str(include_str!("../../tests/fixtures/maximal-join-state.json"))
                    .unwrap();
            maximum = largest;
            maximum["pin"]["role"] = json!(role.0);
            assert!(join_state_valid(&maximum), "maximal state for {}", role.0);
            let raw = crate::smb::jcs::encode(&maximum).unwrap();
            assert!(raw.len() <= JOIN_STATE_BYTES_MAX);
            // 64 envelopes times 96 conservative bytes, plus registry role widths.
            assert!(raw.len() > JOIN_STATE_BYTES_MAX - 6500);
            assert_eq!(
                decode_join_state(raw.as_bytes()),
                Some(maximum),
                "maximal raw round trip"
            );
        }
        assert!(advance(seed, record).is_ok());
        let mut bad = record.clone();
        bad["outer"]["signature"] = json!("A");
        assert_eq!(advance(seed, &bad), Err("OUTER"), "new signature boundary");
        let mut extra = record.clone();
        extra["extra"] = json!("x".repeat(8194)); // Survey growth input exceeds two envelope caps.
        assert_eq!(advance(seed, &extra), Err("OUTER"), "new wrapper boundary");
    }
}
