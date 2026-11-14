// fail-before-exempt: shared vectors, checked corpus and isolated expiry constructors read native and shared contract inputs.
// W-PROVENANCE
// W-LEASE-ADMISSION
// W-ENVELOPE-CAP
// W-JOIN-LIFECYCLE
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::{
    append_budget::*, append_contract as contract, join_lifecycle, records_schema, writer_protocol,
};
use serde_json::{json, Value};
#[path = "support/checked_corpus.rs"]
mod checked_corpus;
fn corpus() -> Value {
    checked_corpus::corpus("record_join_vectors.json")
}

#[test]
fn shared_identity_and_lifecycle_vectors() {
    let data = contract::contract().unwrap();
    // Must match the shared data pin consumed by TS, without reading native source text.
    assert_eq!(
        data["limits"],
        json!({"d_undrained_max":castle_wall_daemon::business_profile::drain_store::D_UNDRAINED_MAX,"join_history_max":castle_wall_daemon::business_profile::records::JOIN_HISTORY_MAX})
    );
    for row in data["checkpoint_vectors"].as_array().unwrap() {
        assert_eq!(
            contract::shape("checkpoint", &row["value"]),
            row["accepted"].as_bool().unwrap(),
            "{}",
            row["id"]
        );
    }
    for row in data["identity_vectors"].as_array().unwrap() {
        assert_eq!(
            contract::shape("identity", &row["value"]),
            row["accepted"].as_bool().unwrap(),
            "{}",
            row["id"]
        );
        assert_eq!(
            contract::shape("ack", &json!({"version":1,"identity":row["value"]})),
            row["accepted"].as_bool().unwrap()
        );
    }
    for row in data["ack_vectors"].as_array().unwrap() {
        assert_eq!(
            contract::shape("ack", &row["value"]),
            row["accepted"].as_bool().unwrap(),
            "{}",
            row["id"]
        );
    }
    for row in data["event_vectors"].as_array().unwrap() {
        assert_eq!(
            contract::event(&row["value"]).is_some(),
            row["accepted"].as_bool().unwrap(),
            "{}",
            row["id"]
        );
    }
    let bytes = castle_wall_daemon::smb::jcs::encode(&data["event_vectors"][0]["value"]).unwrap();
    assert!(contract::event_bytes(bytes.as_bytes()).is_some());
    let duplicate = bytes.replace("\"critical\":true", "\"critical\":true,\"critical\":true");
    assert!(contract::event_bytes(duplicate.as_bytes()).is_none());
    for row in data["lifecycle_vectors"].as_array().unwrap() {
        let mut state = join_lifecycle::initial();
        for step in row["steps"].as_array().unwrap() {
            let result =
                join_lifecycle::step(&state, &data["lifecycle_events"][step[0].as_str().unwrap()]);
            assert_eq!(
                result.is_some(),
                step[1].as_bool().unwrap(),
                "{} {}",
                row["id"],
                step
            );
            if let Some(next) = result {
                state = next
            }
            assert_eq!(state, data["lifecycle_states"][step[2].as_str().unwrap()]);
        }
    }
}
#[test]
fn envelope_caps_and_provenance_boundary() {
    assert_eq!(
        contract::contract().unwrap()["envelope_max_bytes"]
            .as_u64()
            .unwrap() as usize,
        contract::PRODUCER_ENVELOPE_MAX_BYTES
    );
    assert!(contract::ENVELOPE_BRANCH_BOUNDS
        .iter()
        .all(|bound| *bound <= contract::PRODUCER_ENVELOPE_MAX_BYTES));
    assert_eq!(
        contract::ENVELOPE_BRANCH_BOUNDS.len(),
        serde_json::from_str::<Value>(records_schema::SCHEMA_AST).unwrap()["record"]["branches"]
            .as_array()
            .unwrap()
            .len()
    );
    assert!(writer_protocol::envelope_size_admitted_for_test(4096));
    assert!(!writer_protocol::envelope_size_admitted_for_test(4097));
    for row in corpus()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["id"].as_str().unwrap().starts_with("provenance-"))
    {
        assert_eq!(
            records_schema::valid(&row["records"].as_array().unwrap().last().unwrap()["body"]),
            row["id"].as_str().unwrap().ends_with("-equal"),
            "{}",
            row["id"]
        );
    }
}
fn input(p: u64, h: u64) -> RecheckInputs {
    observed_input(0, [1; 16], p, h)
}
fn observed_input(now: u64, grant: [u8; 16], p: u64, h: u64) -> RecheckInputs {
    RecheckInputs::checked_for_test(
        now,
        ProducerExpiry::checked_for_test(grant, p, now).unwrap(),
        HExpiry::checked_for_test(h, now).unwrap(),
    )
    .unwrap()
}
#[test]
fn three_admission_predicates_and_absolute_completion() {
    let seal = seal_ms(GRANT_FLOW_CAP).unwrap();
    assert_eq!(seal, 60000);
    assert!(!finish_admitted(FINISH_MS + seal, seal));
    assert!(finish_admitted(FINISH_MS + seal + 1, seal));
    assert!(admit(input(300000, FINISH_MS + seal), 13).is_none());
    assert!(admit(input(300000, FINISH_MS + seal + 1), 13).is_some());
    assert!(admit(input(299999, 240000), 13).is_none());
    assert!(admit(input(300000, 240000), 13).is_some());
    assert!(admit(input(300001, 240000), 13).is_some());
    // Isolate the cap with all remaining budget predicates satisfied.
    assert!(admit(input(304000, 240000), 14).is_none());
    let snap = admit(input(300000, 240000), 13).unwrap();
    let late = observed_input(179001, [1; 16], 300000, 240000);
    let window = snap.begin_append(179000, 240000).unwrap();
    assert_eq!(window.deadline_ms(), 180000);
    assert!(window.recheck(late, 999));
    let expired = observed_input(180000, [1; 16], 300000, 240000);
    assert!(!window.recheck(expired, 0));
    assert!(!window.recheck(observed_input(179001, [2; 16], 300000, 240000), 999));
    assert_eq!(
        admit(input(300000, 240000), 13)
            .unwrap()
            .begin_append(0, 4000)
            .unwrap()
            .deadline_ms(),
        4000
    );
    assert!(ProducerExpiry::checked_for_test([1; 16], 1, 1).is_none());
    assert!(HExpiry::checked_for_test(1, 1).is_none());
    assert!(RecheckInputs::checked_for_test(
        240000,
        ProducerExpiry::checked_for_test([1; 16], 300000, 0).unwrap(),
        HExpiry::checked_for_test(240000, 0).unwrap()
    )
    .is_none());
    let mut cuts = CutObligation::default();
    assert!(cuts.retain([1; 16], 1));
    assert!(cuts.retain([1; 16], 2));
    assert!(!cuts.retain([2; 16], 1));
    assert!(!cuts.retain([1; 16], u64::MAX));
    assert_eq!(cuts.pending(), Some(([1; 16], 3)));
}

#[test]
fn real_envelope_boundary_precedes_schema_rejection() {
    let data = contract::contract().unwrap();
    for length in [4096, 4097] {
        let mut record = data["lifecycle_events"]["admit"]["record"].clone();
        let original = crate_bytes(&record).len();
        let reason = record["body"]["payload"]["reason"].as_str().unwrap().len();
        record["body"]["payload"]["reason"] = json!("a".repeat(length - original + reason));
        assert_eq!(crate_bytes(&record).len(), length);
        let body = crate_bytes(&record["body"]);
        assert_eq!(
            writer_protocol::envelope(&body, &[0; writer_protocol::SIGNATURE_BYTES]),
            Err(if length == 4097 {
                writer_protocol::Refusal::Envelope
            } else {
                writer_protocol::Refusal::Canonical
            })
        );
    }
}
fn crate_bytes(value: &Value) -> Vec<u8> {
    castle_wall_daemon::smb::jcs::encode(value)
        .unwrap()
        .into_bytes()
}

#[test]
fn shared_projections_cover_schema_kinds() {
    use std::collections::BTreeSet;
    let data = contract::contract().unwrap();
    let rows = data["projection_vectors"].as_array().unwrap();
    for row in rows {
        assert!(
            records_schema::valid(&row["record"]["body"]),
            "{}",
            row["id"]
        );
        assert_eq!(
            contract::projection(&row["record"]),
            Some(row["expected"].clone()),
            "{}",
            row["id"]
        );
    }
    let kinds: BTreeSet<_> = rows
        .iter()
        .map(|row| row["record"]["body"]["record_kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        records_schema::BUSINESS_KINDS.iter().copied().collect()
    );
    let unknown = rows
        .iter()
        .find(|row| row["id"] == "permit-unknown")
        .unwrap();
    assert_eq!(unknown["record"]["body"]["payload"]["outcome"], "unknown");
}
