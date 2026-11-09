use castle_wall_daemon::business_profile::{
    activation_anchor as anchor, protocol_transitions, records, records_schema,
};
use serde_json::{json, Value};
fn sample(node: &Value, definitions: &Value) -> Value {
    match node["type"].as_str().unwrap() {
        "ref" => sample(&definitions[node["name"].as_str().unwrap()], definitions),
        "literal" => node["value"].clone(),
        "enum" => node["values"][0].clone(),
        "integer" => node["min"].clone(),
        "union" => sample(&node["branches"][0], definitions),
        "object" => Value::Object(
            node["fields"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), sample(v, definitions)))
                .collect(),
        ),
        "string" => match node["encoding"].as_str().unwrap() {
            "id" => json!("a".repeat(32)),
            "digest" => json!(format!("sha256:{}", "b".repeat(64))),
            "kid" => json!(format!("k1:sha256:{}", "b".repeat(64))),
            "u64" => json!("1"),
            "ipv4" => json!("192.0.2.1"),
            "ipv6" => json!("2001:db8::1"),
            _ => panic!("unknown encoding"),
        },
        _ => panic!("unknown AST node"),
    }
}
fn bodies() -> Vec<Value> {
    // Must match businessBodies in the TypeScript fixture: every root branch executes in both languages.
    let schema: Value = serde_json::from_str(records_schema::SCHEMA_AST).unwrap();
    schema["record"]["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| sample(b, &schema["definitions"]))
        .collect()
}
#[test]
fn every_strict_branch_and_canonical_decoder() {
    use sha2::{Digest, Sha256};
    assert_eq!(
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(records_schema::SCHEMA_AST.as_bytes()))
        ),
        records_schema::SCHEMA_DIGEST
    );
    let rows = bodies();
    let mut kinds = std::collections::BTreeSet::new();
    for b in rows {
        kinds.insert(b["record_kind"].as_str().unwrap().to_owned());
        let bytes = castle_wall_daemon::smb::jcs::encode(&b).unwrap();
        assert!(
            records::decode(bytes.as_bytes()).is_some(),
            "{}",
            b["payload"]
        );
        let mut extra = b.clone();
        extra["payload"]["extra"] = json!(true);
        assert!(!records_schema::valid(&extra));
        assert!(records::decode(format!("{bytes} ").as_bytes()).is_none());
    }
    assert_eq!(
        kinds,
        records_schema::BUSINESS_KINDS
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
}
#[test]
fn branch_predicates() {
    for op in ["eq", "le", "reverse_tuple", "address_family"] {
        let mut b = bodies()
            .into_iter()
            .find(|b| b["record_kind"] == if op == "le" { "allowance" } else { "open" })
            .unwrap();
        match op {
            "eq" => b["payload"]["context"]["flow"]["machine_id"] = json!("c".repeat(32)),
            "le" => b["payload"]["expires_ns"] = json!("0"),
            "reverse_tuple" => b["payload"]["context"]["reply"]["src_ip"] = json!("192.0.2.2"),
            _ => {
                b["payload"]["context"]["original"]["src_ip"] = json!("2001:db8::1");
                b["payload"]["context"]["reply"]["dst_ip"] = json!("2001:db8::1");
            }
        }
        assert!(!records_schema::valid(&b), "{op}");
    }
}
#[test]
fn generated_transition_complement() {
    let protocol: Value = serde_json::from_str(protocol_transitions::SOURCE).unwrap();
    let states = protocol["states"].as_array().unwrap();
    let rows = protocol["rows"].as_array().unwrap();
    let events: std::collections::BTreeSet<_> =
        rows.iter().map(|r| r["event"].as_str().unwrap()).collect();
    let guards: std::collections::BTreeSet<_> =
        rows.iter().map(|r| r["guard"].as_str().unwrap()).collect();
    let mut denied = std::collections::BTreeSet::new();
    for from in states {
        for event in &events {
            for guard in &guards {
                let from = from.as_str().unwrap();
                let found = rows
                    .iter()
                    .find(|r| r["from"] == from && r["event"] == *event && r["guard"] == *guard);
                assert_eq!(
                    protocol_transitions::transition(from, event, guard).map(|r| r.0),
                    found.map(|r| r["to"].as_str().unwrap())
                );
                if found.is_none() {
                    denied.insert((from, *event, *guard));
                }
            }
        }
    }
    assert_eq!(
        denied,
        protocol_transitions::DENIED.iter().copied().collect()
    );
    assert_eq!(denied.len(), protocol_transitions::DENIED.len());
    assert!(protocol_transitions::transition("UNKNOWN", "UNKNOWN", "UNKNOWN").is_none());
}
// Must match the complete shared anchor fixture consumed by activation-anchor.test.ts.
const ANCHOR_FIXTURE: &str = r#"{"version":1,"fortress_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","machine_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","role":"extension:linux-business-producer-v0","enrollment_revision":1,"descriptor_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","roster_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","custody_envelope_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","retired":false,"activation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","boot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation_high_water":0,"reserved_sequence":0,"committed_sequence":0,"committed_digest":"GENESIS","drained_sequence":0,"drained_digest":"GENESIS","transaction_id":null,"recovery_required":false,"recovery_reason":null,"recovery_revision":0}"#;
#[test]
fn anchor_proposals_and_outside_receipt() {
    let old: Value = serde_json::from_str(ANCHOR_FIXTURE).unwrap();
    let receipt = anchor::anchor_digest(&old).unwrap();
    assert!(anchor::reconcile(
        &old,
        &old,
        Some(&receipt),
        Some("GENESIS")
    ));
    assert!(!anchor::reconcile(&old, &old, None, Some("GENESIS")));
    assert!(!anchor::reconcile(&old, &old, Some(&receipt), None));
    let mut reserved = old.clone();
    reserved["reserved_sequence"] = json!(1);
    let m = json!({"version":1,"op":"RESERVE","request_id":"c".repeat(32),"expected":old,"next":reserved});
    assert_eq!(anchor::propose(&old, &m), Some(reserved.clone()));
    let mut stale = old.clone();
    stale["generation_high_water"] = json!(1);
    let mut stale_message = m.clone();
    stale_message["next"]["generation_high_water"] = json!(1);
    assert!(anchor::propose(&stale, &stale_message).is_none());
    let mut committed = reserved.clone();
    committed["committed_sequence"] = json!(1);
    committed["committed_digest"] = json!(format!("sha256:{}", "d".repeat(64)));
    let mut m = m;
    m["expected"] = reserved.clone();
    m["next"] = committed.clone();
    m["op"] = json!("COMMIT");
    assert_eq!(anchor::propose(&reserved, &m), Some(committed.clone()));
    let mut drained = committed.clone();
    drained["drained_sequence"] = json!(1);
    drained["drained_digest"] = committed["committed_digest"].clone();
    m["expected"] = committed.clone();
    m["next"] = drained.clone();
    m["op"] = json!("DRAIN");
    assert_eq!(anchor::propose(&committed, &m), Some(drained));
    let mut latched = old.clone();
    latched["recovery_required"] = json!(true);
    latched["recovery_reason"] = json!("integrity");
    latched["recovery_revision"] = json!(1);
    m["expected"] = old.clone();
    m["next"] = latched.clone();
    m["op"] = json!("LATCH");
    assert_eq!(anchor::propose(&old, &m), Some(latched.clone()));
    m["expected"] = latched.clone();
    m["next"] = old.clone();
    m["op"] = json!("RECOVERY_COMMIT");
    assert!(anchor::propose(&latched, &m).is_none());
    for key in old.as_object().unwrap().keys() {
        let mut bad = old.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(!anchor::valid(&bad), "{key}");
    }
}

#[test]
fn every_business_branch_verifies_only_for_its_enrolled_subject() {
    use castle_wall_daemon::business_profile::{role_kid, signer_contract};
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let role = signer_contract::ROLE_REGISTRY[0].0;
    let kid = role_kid(role, 1, &public).unwrap();
    for mut body in bodies() {
        body["kid"] = json!(kid);
        let bytes = castle_wall_daemon::smb::jcs::encode(&body).unwrap();
        let message = [
            signer_contract::ROLE_REGISTRY[0].1.as_bytes(),
            bytes.as_bytes(),
        ]
        .concat();
        let signature = key.sign(&message).to_bytes();
        let pin = json!({"role":role,"epoch":1,"kid":kid,"identity_id":body["identity_id"],"machine_id":body["machine_id"]});
        assert!(records::verify(bytes.as_bytes(), &signature, &pin, &public));
        let mut foreign = pin.clone();
        foreign["identity_id"] = json!("c".repeat(32));
        assert!(!records::verify(
            bytes.as_bytes(),
            &signature,
            &foreign,
            &public
        ));
        let mut invalid = signature;
        invalid[0] ^= 1;
        assert!(!records::verify(bytes.as_bytes(), &invalid, &pin, &public));
    }
}

#[test]
fn shared_join_vectors() {
    // Must match both TS join executors: every corpus id, result and complete final state participates without filtering.
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    assert_eq!(corpus["version"], 1); // Initial shared join format version.
    assert_eq!(corpus["schema_digest"], records_schema::SCHEMA_DIGEST);
    let cases = corpus["cases"].as_array().unwrap();
    let mut ids = std::collections::BTreeSet::new();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate {id}");
        let mut state = case["initial"].clone();
        let mut accepted_prefix = 0;
        let mut refusal_code = Value::Null;
        for record in case["records"].as_array().unwrap() {
            let before = state.clone();
            match records::advance(&state, record) {
                Ok(next) => {
                    state = next;
                    accepted_prefix += 1;
                }
                Err(code) => {
                    assert_eq!(state, before, "{id}");
                    refusal_code = json!(code);
                    break;
                }
            }
        }
        assert_eq!(refusal_code, case["expect"]["refusal_code"], "{id}");
        let result = json!({"id":id,"accepted_prefix":accepted_prefix,"refusal_code":refusal_code,"final_state":state});
        let mut want = case["expect"].clone();
        want["id"] = json!(id);
        assert_eq!(result, want, "{id}");
        actual.push(result);
        expected.push(want);
    }
    assert_eq!(ids.len(), cases.len());
    assert_eq!(actual, expected);
}
