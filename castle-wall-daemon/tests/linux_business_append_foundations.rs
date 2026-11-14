// fail-before-exempt: shared append contracts and native budget boundaries are new isolated entrypoints.
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::{
    append_budget::*, append_contract as contract, join_lifecycle, records_schema, writer_protocol,
};
use serde_json::{json, Value};
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap()
}
#[test]
fn shared_identity_and_lifecycle_vectors() {
    let data = contract::contract().unwrap();
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
    assert_eq!(contract::PRODUCER_ENVELOPE_MAX_BYTES, 4096);
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
    RecheckInputs {
        observed_ms: 0,
        producer: ProducerExpiry {
            grant: [1; 16],
            at_ms: p,
        },
        h: HExpiry { at_ms: h },
    }
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
    assert_eq!(snap.append_deadline(179000, 240000), Some(180000));
    let mut late = input(300000, 240000);
    late.observed_ms = 179001;
    let window = snap.begin_append(179000, 240000).unwrap();
    assert_eq!(window.deadline_ms(), 180000);
    assert!(window.recheck(late, 999));
    let mut expired = late;
    expired.observed_ms = 180000;
    assert!(!window.recheck(expired, 0));
    late.producer.grant = [2; 16];
    assert!(!window.recheck(late, 999));
    assert_eq!(snap.append_deadline(0, 4000), Some(4000));
    let mut cuts = CutObligation::default();
    assert!(cuts.retain([1; 16], 1));
    assert!(cuts.retain([1; 16], 2));
    assert!(!cuts.retain([2; 16], 1));
    assert!(!cuts.retain([1; 16], u64::MAX));
    assert_eq!(cuts.pending(), Some(([1; 16], 3)));
}
