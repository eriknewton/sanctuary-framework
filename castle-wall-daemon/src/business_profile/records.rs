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
    // Must match SigningGrant in record-signer.ts: the enrolled grant binds activation, lease and generation.
    if [
        "role",
        "epoch",
        "kid",
        "identity_id",
        "machine_id",
        "activation_id",
        "lease_id",
        "generation",
    ]
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

// Must match record-joins.ts and all three record_join_vectors.json consumers, including refusal precedence and retained state.
pub const JOIN_HISTORY_MAX: usize = 64; // The design retains sixty-four replay records without live eviction.
pub const COUNTER_PERIOD_NS: u64 = 1_000_000_000; // One second in nanoseconds.
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
/// Pure history validation only; callers authenticate the checkpoint and verify signatures separately.
pub fn advance(state: &Value, record: &Value) -> Result<Value, &'static str> {
    let b = &record["body"];
    let p = &b["payload"];
    let history = state["flow_state"]["history"].as_array().ok_or("INPUT")?;
    // Generated validation owns all intra-record predicates before any history value is interpreted.
    if !records_schema::valid(b) {
        return Err("SCHEMA");
    }
    // The outer index must match every indexed signed field so storage cannot relabel an authentic body.
    let mut index: Vec<&str> = super::signer_contract::LINUX_FIELDS
        .iter()
        .copied()
        .filter(|key| !key.ends_with("_digest"))
        .collect();
    index.push("machine_id");
    let outer = record["outer"].as_object().ok_or("OUTER")?;
    if outer.len() != index.len() + 1
        || !outer.contains_key("signature")
        || index.iter().any(|key| outer.get(*key) != b.get(*key))
    {
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
            || (p["boundary"] == "restart"
                && number(&p["gap"]["first_ns"])? > number(&anchor["captured_at_boottime_ns"])?)
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
