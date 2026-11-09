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
#[test]
fn anchor_proposals_and_outside_receipt() {
    let old: Value =
        serde_json::from_str::<Value>(include_str!("../src/business_profile/closure_vectors.json"))
            .unwrap()["anchor"]
            .clone();
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
        let pin = json!({"role":role,"epoch":1,"kid":kid,"identity_id":body["identity_id"],"machine_id":body["machine_id"],"activation_id":body["activation_id"],"lease_id":body["lease_id"],"generation":body["generation"]});
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

#[test]
fn closure_anchor_vectors() {
    // Must match closure_vectors.json and activation-anchor.test.ts: full id and result equality forbids filtering.
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for c in corpus["anchors"].as_array().unwrap() {
        let m = json!({"version":1,"op":c["op"],"request_id":c["request_id"],"expected":c["old"],"next":c["next"]});
        let result = anchor::propose(&c["old"], &m);
        actual.push(json!([c["id"], result.is_some()]));
        expected.push(json!([c["id"], c["accept"]]));
    }
    eprintln!("CLOSURE_RESULTS {}", json!(actual));
    assert_eq!(actual, expected);
}
#[test]
fn closure_reconcile_vectors() {
    // Must match closure_vectors.json and activation-anchor.test.ts, including both drain fields.
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for c in corpus["reconcile"].as_array().unwrap() {
        let a = &c["anchor"];
        actual.push(json!([
            c["id"],
            anchor::reconcile(
                a,
                a,
                anchor::anchor_digest(a).as_deref(),
                a["committed_digest"].as_str()
            )
        ]));
        expected.push(json!([c["id"], c["accept"]]));
    }
    eprintln!("CLOSURE_RESULTS {}", json!(actual));
    assert_eq!(actual, expected);
}
#[test]
fn closure_schema_vectors() {
    // Must match closure_vectors.json and linux-business-schema.test.ts: no nested choice is sampled by a language-local list.
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    let cases = corpus["schema"].as_array().unwrap();
    let ids: std::collections::BTreeSet<_> =
        cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), cases.len());
    let actual: Vec<_> = cases
        .iter()
        .map(|c| json!([c["id"], records_schema::valid(&c["body"])]))
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|c| json!([c["id"], c["accept"]]))
        .collect();
    use castle_wall_daemon::business_profile::{role_kid, signer_contract};
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[7; 32]); // Public synthetic Ed25519 seed length.
    let public = key.verifying_key().to_bytes();
    let role = signer_contract::ROLE_REGISTRY[0].0;
    let kid = role_kid(role, 1, &public).unwrap();
    let verified: Vec<_> = cases.iter().map(|c| {
        let mut b = c["body"].clone(); b["kid"] = json!(kid);
        let pin = json!({"role":role,"epoch":1,"kid":kid,"identity_id":b["identity_id"],"machine_id":b["machine_id"],"activation_id":b["activation_id"],"lease_id":b["lease_id"],"generation":b["generation"]});
        let bytes = castle_wall_daemon::smb::jcs::encode(&b).unwrap();
        let sig = key.sign(&[signer_contract::ROLE_REGISTRY[0].1.as_bytes(),bytes.as_bytes()].concat()).to_bytes();
        json!([c["id"],records::verify(bytes.as_bytes(),&sig,&pin,&public)])
    }).collect();
    eprintln!("CLOSURE_RESULTS {}", json!(verified));
    assert_eq!(verified, expected);
    eprintln!("CLOSURE_RESULTS {}", json!(actual));
    assert_eq!(actual, expected);
}
#[test]
fn closure_pin_vectors() {
    use castle_wall_daemon::business_profile::{role_kid, signer_contract};
    use ed25519_dalek::{Signer, SigningKey};
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]); // Public synthetic Ed25519 seed length.
    let public = key.verifying_key().to_bytes();
    let role = signer_contract::ROLE_REGISTRY[0].0;
    let kid = role_kid(role, 1, &public).unwrap();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for c in corpus["verify"].as_array().unwrap() {
        let mut b = c["body"].clone();
        b["kid"] = json!(kid);
        let mut pin = json!({"role":role,"epoch":1,"kid":kid,"identity_id":b["identity_id"],"machine_id":b["machine_id"],"activation_id":b["activation_id"],"lease_id":b["lease_id"],"generation":b["generation"]});
        for (k, v) in c["pin_change"].as_object().unwrap() {
            pin[k] = v.clone();
        }
        let bytes = castle_wall_daemon::smb::jcs::encode(&b).unwrap();
        let sig = key
            .sign(
                &[
                    signer_contract::ROLE_REGISTRY[0].1.as_bytes(),
                    bytes.as_bytes(),
                ]
                .concat(),
            )
            .to_bytes();
        actual.push(json!([
            c["id"],
            records::verify(bytes.as_bytes(), &sig, &pin, &public)
        ]));
        expected.push(json!([c["id"], c["accept"]]));
    }
    eprintln!("CLOSURE_RESULTS {}", json!(actual));
    assert_eq!(actual, expected);
}

#[test]
fn closure_nested_choice_coverage() {
    use std::collections::BTreeSet;
    // Must match linux-business-schema.test.ts: derive both sets from the schema and all accepted shared bodies.
    let schema: Value = serde_json::from_str(records_schema::SCHEMA_AST).unwrap();
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    fn fits(n: &Value, v: &Value, defs: &Value) -> bool {
        match n["type"].as_str().unwrap() {
            "ref" => fits(&defs[n["name"].as_str().unwrap()], v, defs),
            "literal" => n["value"] == *v,
            "enum" => n["values"].as_array().unwrap().contains(v),
            "union" => n["branches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| fits(b, v, defs)),
            "object" => {
                v.is_object()
                    && n["fields"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .all(|(k, b)| fits(b, &v[k], defs))
            }
            "integer" => v.is_number(),
            _ => v
                .as_str()
                .is_some_and(|s| match n["encoding"].as_str().unwrap() {
                    "ipv4" => s.contains('.'),
                    "ipv6" => s.contains(':'),
                    "digest" => s.starts_with("sha256:"),
                    _ => true,
                }),
        }
    }
    fn walk(
        n: &Value,
        path: &str,
        defs: &Value,
        target: &mut BTreeSet<String>,
        value: Option<&Value>,
    ) {
        match n["type"].as_str().unwrap() {
            "ref" => {
                let name = n["name"].as_str().unwrap();
                walk(
                    &defs[name],
                    &format!("definitions.{name}"),
                    defs,
                    target,
                    value,
                );
            }
            "enum" => {
                for (i, v) in n["values"].as_array().unwrap().iter().enumerate() {
                    if value.is_none_or(|x| x == v) {
                        target.insert(format!("{path}:{i}"));
                    }
                }
            }
            "union" => {
                for (i, b) in n["branches"].as_array().unwrap().iter().enumerate() {
                    if value.is_none_or(|v| fits(b, v, defs)) {
                        target.insert(format!("{path}:{i}"));
                        walk(b, &format!("{path}.branches.{i}"), defs, target, value);
                    }
                }
            }
            "object" => {
                for (k, b) in n["fields"].as_object().unwrap() {
                    walk(
                        b,
                        &format!("{path}.fields.{k}"),
                        defs,
                        target,
                        value.map(|v| &v[k]),
                    );
                }
            }
            _ => (),
        }
    }
    let mut expected = BTreeSet::new();
    let mut actual = BTreeSet::new();
    walk(
        &schema["record"],
        "record",
        &schema["definitions"],
        &mut expected,
        None,
    );
    for c in corpus["schema"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["accept"] == true)
    {
        walk(
            &schema["record"],
            "record",
            &schema["definitions"],
            &mut actual,
            Some(&c["body"]),
        );
    }
    assert_eq!(actual, expected);
    assert_eq!(json!(actual), corpus["coverage"]);
}

#[test]
fn closure_full_id_sets() {
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    for name in ["anchors", "reconcile", "schema", "verify"] {
        let cases = corpus[name].as_array().unwrap();
        let ids: std::collections::BTreeSet<_> =
            cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), cases.len(), "{name}");
    }
}

#[test]
fn closure_reserve_latch_commit_sequence() {
    let corpus: Value =
        serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap();
    let cases = corpus["anchors"].as_array().unwrap();
    let case = |id: &str| cases.iter().find(|c| c["id"] == id).unwrap();
    let mut state = case("reserve")["old"].clone();
    for id in ["reserve", "latch"] {
        let c = case(id);
        let message = json!({"version":1,"op":c["op"],"request_id":c["request_id"],"expected":state,"next":c["next"]});
        state = anchor::propose(&state, &message).unwrap();
    }
    let c = case("latched-commit");
    let message = json!({"version":1,"op":c["op"],"request_id":c["request_id"],"expected":state,"next":c["next"]});
    let accepted = anchor::propose(&state, &message).is_some();
    eprintln!(
        "CLOSURE_RESULTS {}",
        json!([["closure reserve-latch-commit sequence", accepted]])
    );
    assert!(!accepted);
    assert_eq!(state, case("latch")["next"]);
}
