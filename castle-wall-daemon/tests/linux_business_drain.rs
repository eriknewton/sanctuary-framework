// fail-before-exempt: New drain authority, durability and peer witnesses read isolated native artifacts and files; capability setup uses the inherited actor helper.
#![cfg(target_os = "linux")]
#[path = "support/drain_run.rs"]
mod drain_run;
mod isolation;
#[path = "support/writer_bus.rs"]
mod writer_bus;
use castle_wall_daemon::business_profile::{
    drain_protocol as protocol, drain_service::packet_digest,
};
use drain_run::*;
use serde_json::{json, Value};
use std::{
    fs,
    time::{Duration, Instant},
};
// Scheduling grace beyond the request deadline, separate from negative observation windows.
const DEADLINE_GRACE_MS: u64 = 20;
// A short receive window samples absence while the executor is held.
const NO_REPLY_WINDOW_MS: u64 = 10;
// Readback holds use a longer observation window to expose an early ACK.
const READBACK_OBSERVATION_MS: u64 = 20;
// Child-liveness polling cadence, independent of protocol deadlines.
const CHILD_POLL_MS: i32 = 10;
#[test]
fn genesis_phase_retry_restart_and_conflict() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    assert_eq!(f.read(true)["state"], "ABSENT");
    let id = "c".repeat(32);
    let mut next = f.anchor.clone();
    next["transaction_id"] = json!(id);
    let prepare = anchor_packet(
        &json!({"version":1,"op":"PREPARE","request_id":id,"expected":null,"next":next}),
        &[],
    );
    let commit = anchor_packet(
        &json!({"version":1,"op":"COMMIT","request_id":id,"expected":next,"next":f.anchor}),
        &[],
    );
    for packet in [&prepare, &commit] {
        let reply = f.request(true, packet);
        assert_eq!(
            reply.as_ref().and_then(|r| r["op"].as_str()),
            Some("ANCHOR_ACK"),
            "PREPARE then custody COMMIT share one id"
        );
        assert!(
            !f.stages().contains(&"RETRY".into()),
            "PREPARE then custody COMMIT must not conflict"
        );
    }
    assert_eq!(f.request(true, &prepare).unwrap()["op"], "REFUSED");
    let count = f
        .events()
        .iter()
        .filter(|v| v["event"] == "StepCompleted")
        .count();
    assert_eq!(f.request(true, &commit).unwrap()["op"], "ANCHOR_ACK");
    assert_eq!(
        f.events()
            .iter()
            .filter(|v| v["event"] == "StepCompleted")
            .count(),
        count
    );
    f.stop();
    f.start();
    let count = f.events().len();
    assert_eq!(f.request(true, &commit).unwrap()["op"], "ANCHOR_ACK");
    assert!(f.events()[count..]
        .iter()
        .all(|v| v["event"] != "StepCompleted"));
    let mut m: Value = {
        let (h, p) = castle_wall_daemon::business_profile::frame::split(
            &commit,
            protocol::D_HEADER_MAX_BYTES,
            protocol::D_REQUEST_MAX_BYTES,
        )
        .unwrap();
        serde_json::from_slice(&p[..h["message_length"].as_u64().unwrap() as usize]).unwrap()
    };
    m["next"]["roster_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert!(f.request(true, &anchor_packet(&m, &[])).is_none());
    assert!(f.stages().contains(&"RETRY".into()));
    let m = json!({"version":1,"op":"ADVANCE_GENERATION","request_id":"d".repeat(32),"expected":f.anchor,"next":{}});
    let mut m = m;
    m["next"] = f.anchor.clone();
    m["next"]["generation_high_water"] =
        json!(f.anchor["generation_high_water"].as_u64().unwrap() + 1);
    assert!(f.request(true, &anchor_packet(&m, &[])).is_none());
    assert_eq!(f.read(false)["state"], "PRESENT");
    assert_eq!(
        fs::read_to_string(f.root.join("diagnostics.log")).unwrap(),
        "drain authority closed\n",
        "one content-free diagnostic per authority closure"
    );
}
#[test]
fn signed_commits_originals_and_ledger_conflict() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let (commit, envelope) = f.reserve_commit(&"d".repeat(32));
    let n = f.events().len();
    assert_eq!(f.request(false, &commit).unwrap()["op"], "ANCHOR_ACK");
    assert!(f.events()[n..]
        .iter()
        .all(|v| v["event"] != "StepCompleted"));
    let before = f.events().len();
    f.bus.unit.lock().unwrap().pid = std::process::id();
    f.w.send(&commit);
    assert!(f.w.receive(WAIT_MS).is_none());
    assert!(f.events()[before..]
        .iter()
        .all(|v| v["event"] != "StoreEntered" && v["event"] != "StepCompleted"));
    assert_eq!(f.read(true)["uncertain"], false);
    f.bus.unit.lock().unwrap().pid = f.w.child.id();
    let p = original_packet(&"f".repeat(32), 1, &envelope);
    assert_eq!(f.request(false, &p).unwrap()["op"], "ORIGINAL_ACK");
    assert_eq!(f.request(false, &p).unwrap()["op"], "ORIGINAL_ACK");
    let mut bad: Value = serde_json::from_slice(&envelope).unwrap();
    bad["outer"]["signature"] = json!("A".repeat(86));
    let bad = canonical(&bad);
    assert!(f
        .request(false, &original_packet(&"f".repeat(32), 1, &bad))
        .is_none());
    assert_eq!(f.read(true)["uncertain"], false);
    assert!(f.stages().contains(&"RETRY".into()));
}
#[test]
fn uncertain_read_does_not_reconcile_and_retry_recovers() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let mut next = f.anchor.clone();
    next["generation_high_water"] = json!(next["generation_high_water"].as_u64().unwrap() + 1);
    let m = json!({"version":1,"op":"ADVANCE_GENERATION","request_id":"d".repeat(32),"expected":f.anchor,"next":next});
    let packet = anchor_packet(&m, &[]);
    f.fault("record", "DirSync", "fail", Value::Null, 100);
    assert!(f.request(true, &packet).is_none());
    assert_eq!(f.read(false)["uncertain"], true);
    assert_eq!(f.request(true, &packet).unwrap()["op"], "REFUSED");
    assert_eq!(f.read(false)["uncertain"], true);
    f.clear();
    assert_eq!(f.request(true, &packet).unwrap()["op"], "ANCHOR_ACK");
    assert_eq!(f.read(false)["uncertain"], false);
}
#[test]
fn sticky_latch_preserves_pending_reservation() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let digest = packet_digest(&canonical(&f.body));
    let mut next = f.anchor.clone();
    next["reserved_sequence"] = json!(1);
    next["reserved_body_digest"] = json!(digest);
    let m = json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":f.anchor,"next":next,"body_digest":digest});
    assert_eq!(
        f.request(false, &anchor_packet(&m, &[])).unwrap()["op"],
        "ANCHOR_ACK"
    );
    let old = next.clone();
    next["recovery_required"] = json!(true);
    next["recovery_reason"] = json!("integrity");
    next["recovery_revision"] = json!(1);
    let m =
        json!({"version":1,"op":"LATCH","request_id":"e".repeat(32),"expected":old,"next":next});
    assert_eq!(
        f.request(false, &anchor_packet(&m, &[])).unwrap()["op"],
        "REFUSED"
    );
    assert_eq!(
        f.request(true, &anchor_packet(&m, &[])).unwrap()["op"],
        "ANCHOR_ACK"
    );
    f.stop();
    f.start();
    let read = f.read(true);
    assert_eq!(read["latched"], true);
    assert_eq!(read["uncertain"], false);
    let path = f
        .root
        .join("state")
        .join(FORTRESS)
        .join("anchors")
        .join(format!("{SLOT}.json"));
    let record: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(record["anchor"], next);
    for op in castle_wall_daemon::business_profile::protocol_transitions::LATCH_DENIED_OPS {
        let mut m =
            json!({"version":1,"op":op,"request_id":"f".repeat(32),"expected":next,"next":next});
        let envelope = if *op == "COMMIT" {
            f.signed(&f.body)
        } else {
            Vec::new()
        };
        if matches!(*op, "COMMIT" | "RESERVE") {
            m["body_digest"] = next["reserved_body_digest"].clone();
        }
        let message = canonical(&m);
        let mut header = protocol::header("ANCHOR", &"f".repeat(32), ROLE);
        header["message_length"] = json!(message.len());
        header["envelope_length"] = json!(envelope.len());
        let h = canonical(&header);
        let packet = [&(h.len() as u32).to_be_bytes()[..], &h, &message, &envelope].concat();
        assert!(f.request(true, &packet).is_none_or_refused(), "{op}");
        assert_eq!(f.read(true)["latched"], true);
    }
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let (_, envelope) = f.reserve_commit(&"d".repeat(32));
    let mut latched = f.anchor.clone();
    latched["recovery_required"] = json!(true);
    latched["recovery_reason"] = json!("integrity");
    latched["recovery_revision"] = json!(1);
    let latch = anchor_packet(
        &json!({"version":1,"op":"LATCH","request_id":"e".repeat(32),"expected":f.anchor,"next":latched}),
        &[],
    );
    assert_eq!(f.request(true, &latch).unwrap()["op"], "ANCHOR_ACK");
    assert_eq!(
        f.request(false, &original_packet(&"f".repeat(32), 1, &envelope))
            .unwrap()["op"],
        "REFUSED"
    );
    assert_eq!(f.read(true)["uncertain"], false);
    assert_eq!(f.read(true)["latched"], true);
}
#[test]
fn packet_and_verification_refusals_preserve_state() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let mut next = f.anchor.clone();
    next["generation_high_water"] = json!(next["generation_high_water"].as_u64().unwrap() + 1);
    let mut expected = f.anchor.clone();
    expected["roster_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    let m = json!({"version":1,"op":"ADVANCE_GENERATION","request_id":"d".repeat(32),"expected":expected,"next":next});
    assert_eq!(
        f.request(true, &anchor_packet(&m, &[])).unwrap()["op"],
        "REFUSED"
    );
    assert!(f.stages().contains(&"PROPOSE".into()));
    let mut h = protocol::header("READ", &"e".repeat(32), "unknown");
    let b = canonical(&h);
    let p = [&(b.len() as u32).to_be_bytes()[..], &b].concat();
    assert!(f.request(true, &p).is_none());
    h["role"] = json!("extension:linux-business-retrospective-v0");
    let b = canonical(&h);
    let p = [&(b.len() as u32).to_be_bytes()[..], &b].concat();
    assert!(f.request(true, &p).is_none());
    assert_eq!(f.read(false)["uncertain"], false);
}
#[test]
fn mainpid_impostor_and_failed_signer_never_mutate() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.bus.unit.lock().unwrap().pid = std::process::id();
    f.start();
    let p = protocol::encode(
        &protocol::header("READ", &"e".repeat(32), ROLE),
        &[],
        protocol::Direction::ToDrain,
    )
    .unwrap();
    assert!(f.request(false, &p).is_none());
    assert!(f.stages().contains(&"CLASSIFY".into()));
    assert_eq!(f.read(true)["state"], "ABSENT");
}
#[test]
fn held_readback_never_acknowledges_original_early() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let (_, envelope) = f.reserve_commit(&"d".repeat(32));
    f.fault("copy", "Readback", "hold", json!("copy"), 1);
    let path = f.socket();
    f.w.connect(&path);
    f.w.send(&original_packet(&"f".repeat(32), 1, &envelope));
    let end = Instant::now() + Duration::from_millis(WAIT_MS);
    while !f.events().iter().any(|v| {
        v["event"] == "StepCompleted" && v["publication"] == "copy" && v["step"] == "DirSync"
    }) {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(f.w.receive(READBACK_OBSERVATION_MS).is_none());
    write_private(&f.root.join("release-copy"), b"");
    let reply = f.w.receive(WAIT_MS).unwrap();
    let (h, _) = castle_wall_daemon::business_profile::frame::split(
        &reply,
        protocol::D_HEADER_MAX_BYTES,
        protocol::D_REPLY_MAX_BYTES,
    )
    .unwrap();
    assert_eq!(h["op"], "ORIGINAL_ACK");
}

#[test]
fn every_commit_evidence_stage_refuses_before_publication() {
    let _guard = isolation::guard();
    for stage in [
        "ENVELOPE",
        "ENVELOPE_INDEX",
        "ENVELOPE_FOREIGN_ROLE",
        "BODY_DIGEST",
        "CHAIN",
        "DESCRIPTOR",
        "DESCRIPTOR_FORTRESS",
        "DESCRIPTOR_MACHINE",
        "DESCRIPTOR_IDENTITY",
        "DESCRIPTOR_BODY_MACHINE",
        "KID",
        "KID_ABSENT_EPOCH",
        "GRANT",
        "GRANT_ACTIVATION",
        "GRANT_BOOT",
        "SIGNATURE",
        "COMMITMENT",
    ] {
        // A targeted mutation run selects one evidence predicate; ordinary suites run every case.
        if std::env::var("DRAIN_VERIFY_CASE").is_ok_and(|selected| selected != stage) {
            continue;
        }
        let mut f = Fixture::new();
        let foreign = castle_wall_daemon::business_profile::signer_contract::ROLE_REGISTRY
            .iter()
            .find(|r| r.0 != ROLE)
            .unwrap();
        let foreign_kid = castle_wall_daemon::business_profile::role_kid(
            foreign.0,
            f.body["epoch"].as_u64().unwrap(),
            &f.key.verifying_key().to_bytes(),
        )
        .unwrap();
        if stage == "ENVELOPE_FOREIGN_ROLE" {
            let path = f
                .root
                .join("custody")
                .join(FORTRESS)
                .join(SLOT)
                .join("public/epochs.json");
            let mut descriptor: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            descriptor["epochs"].as_array_mut().unwrap().push(json!({"role":foreign.0,"epoch":f.body["epoch"],"kid":foreign_kid,"public_key":hex::encode(f.key.verifying_key().to_bytes())}));
            descriptor["epochs"]
                .as_array_mut()
                .unwrap()
                .sort_by(|a, b| a["role"].as_str().cmp(&b["role"].as_str()));
            let bytes = canonical(&descriptor);
            f.anchor["descriptor_digest"] = json!(packet_digest(&bytes));
            fs::write(path, bytes).unwrap();
        }
        if matches!(
            stage,
            "DESCRIPTOR_FORTRESS" | "DESCRIPTOR_MACHINE" | "DESCRIPTOR_IDENTITY"
        ) {
            let path = f
                .root
                .join("custody")
                .join(FORTRESS)
                .join(SLOT)
                .join("public/epochs.json");
            let mut descriptor: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let field = match stage {
                "DESCRIPTOR_FORTRESS" => "fortress_id",
                "DESCRIPTOR_MACHINE" => "machine_id",
                _ => "identity_id",
            };
            descriptor[field] = json!("f".repeat(32));
            let bytes = canonical(&descriptor);
            f.anchor["descriptor_digest"] = json!(packet_digest(&bytes));
            fs::write(path, bytes).unwrap();
        }
        f.start();
        f.prepare();
        let mut body = f.body.clone();
        body["sequence"] = json!(1);
        body["prior_commitment"] = json!("GENESIS");
        match stage {
            "DESCRIPTOR_BODY_MACHINE" | "DESCRIPTOR_MACHINE" => {
                body["machine_id"] = json!("f".repeat(32))
            }
            "KID_ABSENT_EPOCH" => body["epoch"] = json!(2),
            "GRANT_ACTIVATION" => body["activation_id"] = json!("f".repeat(32)),
            "GRANT_BOOT" => body["boot_id"] = json!("f".repeat(32)),
            _ => {}
        }
        for field in ["machine_id", "activation_id", "boot_id"] {
            body["payload"]["context"]["flow"][field] = body[field].clone();
        }
        if stage == "CHAIN" {
            body["prior_commitment"] = json!(format!("sha256:{}", "f".repeat(64)));
        }
        if stage == "KID" {
            body["kid"] = json!(format!("k1:sha256:{}", "f".repeat(64)));
        }
        if stage == "GRANT" {
            body["generation"] = json!(body["generation"].as_u64().unwrap() + 1);
        }
        if stage == "ENVELOPE_FOREIGN_ROLE" {
            body["role"] = json!(foreign.0);
            body["kid"] = json!(foreign_kid);
        }
        let reserved = packet_digest(&canonical(&body));
        let mut next = f.anchor.clone();
        next["reserved_sequence"] = json!(1);
        next["reserved_body_digest"] = json!(reserved);
        let reserve = json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":f.anchor,"next":next,"body_digest":reserved});
        assert_eq!(
            f.request(false, &anchor_packet(&reserve, &[])).unwrap()["op"],
            "ANCHOR_ACK",
            "{stage}"
        );
        if stage == "BODY_DIGEST" {
            body["captured_at_unix_ms"] = json!(body["captured_at_unix_ms"].as_u64().unwrap() + 1);
        }
        let mut envelope = if stage == "ENVELOPE_FOREIGN_ROLE" {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            use ed25519_dalek::Signer;
            // Build hostile bytes directly: the fixture encoder correctly rejects foreign roles.
            let signature = f
                .key
                .sign(&[foreign.1.as_bytes(), &canonical(&body)].concat());
            let mut outer = serde_json::Map::new();
            for key in castle_wall_daemon::business_profile::signer_contract::LINUX_FIELDS
                .iter()
                .copied()
                .filter(|key| !key.ends_with("_digest"))
                .chain(std::iter::once("machine_id"))
            {
                outer.insert(key.into(), body[key].clone());
            }
            outer.insert(
                "signature".into(),
                json!(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            );
            canonical(&json!({"body":body,"outer":outer}))
        } else {
            f.signed(&body)
        };
        if stage == "SIGNATURE" {
            let e: Value = serde_json::from_slice(&envelope).unwrap();
            envelope = castle_wall_daemon::business_profile::writer_protocol::envelope(
                &canonical(&e["body"]),
                &[0; 64],
            )
            .unwrap();
        }
        if stage == "ENVELOPE_INDEX" {
            let mut value: Value = serde_json::from_slice(&envelope).unwrap();
            value["outer"]["sequence"] = json!(2);
            envelope = canonical(&value);
        }
        let digest = castle_wall_daemon::business_profile::records::join_commitment(
            &serde_json::from_slice(&envelope).unwrap(),
        )
        .unwrap();
        let old = next.clone();
        next["committed_sequence"] = json!(1);
        next["reserved_body_digest"] = Value::Null;
        next["committed_digest"] = json!(digest);
        if stage == "COMMITMENT" {
            next["committed_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
        }
        if stage == "ENVELOPE" {
            envelope.insert(0, b' ');
        }
        if stage == "DESCRIPTOR" {
            fs::write(
                f.root
                    .join("custody")
                    .join(FORTRESS)
                    .join(SLOT)
                    .join("public/epochs.json"),
                b"{}",
            )
            .unwrap();
        }
        let m = json!({"version":1,"op":"COMMIT","request_id":"d".repeat(32),"expected":old,"next":next,"body_digest":reserved});
        let before = f
            .events()
            .iter()
            .filter(|v| v["event"] == "StoreEntered")
            .count();
        assert_eq!(
            f.request(false, &anchor_packet(&m, &envelope))
                .as_ref()
                .and_then(|r| r["op"].as_str()),
            Some("REFUSED"),
            "{stage}"
        );
        assert!(
            f.stages().contains(&if stage == "BODY_DIGEST" {
                stage.to_owned()
            } else {
                stage.split('_').next().unwrap().to_owned()
            }),
            "{stage}: {:?}",
            f.stages()
        );
        assert_eq!(
            f.events()
                .iter()
                .filter(|v| v["event"] == "StoreEntered")
                .count(),
            before,
            "{stage}: refusal must not publish"
        );
        assert_eq!(
            f.read(true)["anchor_digest"],
            json!(castle_wall_daemon::business_profile::activation_anchor::anchor_digest(&old)),
            "{stage}: unchanged anchor"
        );
    }
}
#[test]
fn three_originals_require_each_exact_ledger_entry() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let mut envelopes = Vec::new();
    for i in 1..=3 {
        let (_, e) = f.reserve_commit(&format!("{i:032x}"));
        envelopes.push(e);
    }
    let mut bad_signature: Value = serde_json::from_slice(&envelopes[0]).unwrap();
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut bytes = URL_SAFE_NO_PAD
            .decode(bad_signature["outer"]["signature"].as_str().unwrap())
            .unwrap();
        bytes[0] ^= 1;
        bad_signature["outer"]["signature"] = json!(URL_SAFE_NO_PAD.encode(bytes));
    }
    for (case, sequence, envelope, stage) in [
        ("header body sequence", 1, envelopes[1].clone(), "CHAIN"),
        ("gap", 2, envelopes[1].clone(), "CHAIN"),
        (
            "changed signature",
            1,
            canonical(&bad_signature),
            "COMMITMENT",
        ),
    ] {
        let before = f.read(true)["anchor_digest"].clone();
        let reply = f.request(
            false,
            &original_packet(&"e".repeat(32), sequence, &envelope),
        );
        assert_eq!(
            reply.as_ref().and_then(|r| r["op"].as_str()),
            Some("REFUSED"),
            "{case}: original refusal"
        );
        assert_eq!(
            f.stages().last().map(String::as_str),
            Some(stage),
            "{case}: named refusal stage"
        );
        assert_eq!(
            f.read(true)["anchor_digest"],
            before,
            "{case}: unchanged anchor"
        );
    }
    assert_eq!(
        f.request(false, &original_packet(&"e".repeat(32), 1, &envelopes[0]))
            .unwrap()["op"],
        "ORIGINAL_ACK"
    );
    let mut body: Value = serde_json::from_slice::<Value>(&envelopes[1]).unwrap()["body"].clone();
    body["generation"] = json!(body["generation"].as_u64().unwrap() + 1);
    let other = f.signed(&body);
    assert_eq!(
        f.request(false, &original_packet(&"e".repeat(32), 2, &other))
            .unwrap()["op"],
        "REFUSED"
    );
    assert!(f.stages().contains(&"COMMITMENT".into()));
    for sequence in 2..=3 {
        assert_eq!(
            f.request(
                false,
                &original_packet(&"e".repeat(32), sequence, &envelopes[sequence as usize - 1])
            )
            .unwrap()["op"],
            "ORIGINAL_ACK"
        );
    }
    let mut beyond: Value = serde_json::from_slice::<Value>(&envelopes[2]).unwrap()["body"].clone();
    beyond["sequence"] = json!(4);
    beyond["prior_commitment"] = f.anchor["committed_digest"].clone();
    let envelope = f.signed(&beyond);
    let before = f.read(true)["anchor_digest"].clone();
    let reply = f.request(false, &original_packet(&"e".repeat(32), 4, &envelope));
    assert_eq!(
        reply.as_ref().and_then(|r| r["op"].as_str()),
        Some("REFUSED"),
        "above committed original refuses"
    );
    assert_eq!(
        f.stages().last().map(String::as_str),
        Some("CHAIN"),
        "above committed original stage"
    );
    assert_eq!(
        f.read(true)["anchor_digest"],
        before,
        "above committed unchanged anchor"
    );
    let before = f.read(true)["anchor_digest"].clone();
    let reply = f.request(false, &original_packet(&"e".repeat(32), 1, &envelopes[0]));
    assert_eq!(
        reply.as_ref().and_then(|r| r["op"].as_str()),
        Some("REFUSED"),
        "stale original refusal"
    );
    assert_eq!(
        f.stages().last().map(String::as_str),
        Some("CHAIN"),
        "stale original named stage"
    );
    assert_eq!(
        f.read(true)["anchor_digest"],
        before,
        "stale original unchanged anchor"
    );
}
#[test]
fn disconnected_timeout_waves_keep_one_request_until_settlement() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    const WAVES: usize = 30; // Repeated deadline/admission schedule required for the shared executor.
    for wave in 0..WAVES {
        let id = format!("{:032x}", wave + 1);
        let release = format!("wave{wave}");
        let mut next = f.anchor.clone();
        next["generation_high_water"] = json!(next["generation_high_water"].as_u64().unwrap() + 1);
        let m = json!({"version":1,"op":"ADVANCE_GENERATION","request_id":id,"expected":f.anchor,"next":next});
        let packet = anchor_packet(&m, &[]);
        f.fault("record", "FileSync", "hold", json!(release), 1);
        let path = f.socket();
        f.s.connect(&path);
        f.s.send(&packet);
        let end = Instant::now() + Duration::from_millis(WAIT_MS);
        let start = f.events().len();
        while !f
            .events()
            .iter()
            .any(|v| v["request_id"] == id && v["event"] == "StepCompleted" && v["step"] == "Write")
        {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(
            protocol::D_REQUEST_DEADLINE_MS as u64 + DEADLINE_GRACE_MS,
        ));
        f.s.command(json!({"op":"close"}));
        f.w.connect(&path);
        let read = protocol::encode(
            &protocol::header("READ", &"e".repeat(32), ROLE),
            &[],
            protocol::Direction::ToDrain,
        )
        .unwrap();
        f.w.send(&read);
        assert!(f.w.receive(NO_REPLY_WINDOW_MS).is_none());
        assert!(f.events()[start..]
            .iter()
            .all(|v| v["event"] != "RequestAdmitted" || v["request_id"] == id));
        write_private(&f.root.join(format!("release-{release}")), b"");
        assert!(f.w.receive(WAIT_MS).is_some());
        f.clear();
        assert_eq!(f.request(true, &packet).unwrap()["op"], "ANCHOR_ACK");
        f.anchor = next;
        let events = f.events();
        let settled = events
            .iter()
            .position(|v| v["event"] == "RequestSettled" && v["request_id"] == id)
            .unwrap();
        let subsequent = events
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, v)| v["event"] == "RequestAdmitted" && v["request_id"] != id)
            .unwrap()
            .0;
        assert!(settled < subsequent);
        assert!(events.iter().all(|v| v["active"] == 1));
    }
}

#[test]
fn full_ledger_retries_then_drain_frees_exactly_one_slot() {
    use castle_wall_daemon::business_profile::{
        drain_store::{encode_record, Authority, DrainRecord, LastOp, Phase, D_UNDRAINED_MAX},
        records, writer_protocol,
    };
    use std::os::unix::fs::PermissionsExt;
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    let mut a = f.anchor.clone();
    let mut ledger = Vec::new();
    let mut first = Vec::new();
    let mut retry = Vec::new();
    for sequence in 1..=D_UNDRAINED_MAX as u64 {
        let mut body = f.body.clone();
        body["sequence"] = json!(sequence);
        body["prior_commitment"] = a["committed_digest"].clone();
        let e = f.signed(&body);
        if sequence == 1 {
            first = e.clone();
        }
        let d = packet_digest(&canonical(&body));
        let mut prior = a.clone();
        prior["reserved_sequence"] = json!(sequence);
        prior["reserved_body_digest"] = json!(d);
        let commitment =
            records::join_commitment(&writer_protocol::decode_envelope(&e).unwrap()).unwrap();
        a["committed_sequence"] = json!(sequence);
        a["reserved_sequence"] = json!(sequence);
        a["committed_digest"] = json!(commitment);
        ledger.push(commitment);
        retry = anchor_packet(
            &json!({"version":1,"op":"COMMIT","request_id":"d".repeat(32),"expected":prior,"next":a,"body_digest":d}),
            &e,
        );
    }
    let record = DrainRecord {
        anchor: a.clone(),
        ledger,
        last: LastOp {
            authority: Authority::W,
            phase: Phase::RECORD_COMMIT,
            request_id: "d".repeat(32),
            request_sha256: packet_digest(&retry),
        },
    };
    let fort = f.root.join("state").join(FORTRESS);
    let anchors = fort.join("anchors");
    for d in [&fort, &anchors] {
        fs::create_dir(d).unwrap();
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
    }
    write_private(
        &anchors.join(format!("{SLOT}.json")),
        &encode_record(&record).unwrap(),
    );
    f.start();
    assert_eq!(f.request(false, &retry).unwrap()["op"], "ANCHOR_ACK");
    let sequence = D_UNDRAINED_MAX as u64 + 1;
    let mut body = f.body.clone();
    body["sequence"] = json!(sequence);
    body["prior_commitment"] = a["committed_digest"].clone();
    let envelope = f.signed(&body);
    let digest = packet_digest(&canonical(&body));
    let mut reserved = a.clone();
    reserved["reserved_sequence"] = json!(sequence);
    reserved["reserved_body_digest"] = json!(digest);
    assert_eq!(f.request(false,&anchor_packet(&json!({"version":1,"op":"RESERVE","request_id":"e".repeat(32),"expected":a,"next":reserved,"body_digest":digest}),&[])).unwrap()["op"],"ANCHOR_ACK");
    let mut next = reserved.clone();
    next["committed_sequence"] = json!(sequence);
    next["committed_digest"] = json!(records::join_commitment(
        &writer_protocol::decode_envelope(&envelope).unwrap()
    )
    .unwrap());
    next["reserved_body_digest"] = Value::Null;
    let mut message = json!({"version":1,"op":"COMMIT","request_id":"e".repeat(32),"expected":reserved,"next":next,"body_digest":digest});
    assert_eq!(
        f.request(false, &anchor_packet(&message, &envelope))
            .unwrap()["op"],
        "REFUSED"
    );
    assert!(f.stages().contains(&"CAPACITY".into()));
    assert_eq!(
        f.request(false, &original_packet(&"f".repeat(32), 1, &first))
            .unwrap()["op"],
        "ORIGINAL_ACK"
    );
    let first_digest =
        records::join_commitment(&writer_protocol::decode_envelope(&first).unwrap()).unwrap();
    for field in ["expected", "next"] {
        message[field]["drained_sequence"] = json!(1);
        message[field]["drained_digest"] = json!(first_digest);
    }
    assert_eq!(
        f.request(false, &anchor_packet(&message, &envelope))
            .unwrap()["op"],
        "ANCHOR_ACK"
    );
}

#[test]
fn every_mutation_fault_has_no_ack_and_preserves_uncertainty_boundary() {
    let _guard = isolation::guard();
    for op in [
        "PREPARE",
        "CUSTODY_COMMIT",
        "RESERVE",
        "RECORD_COMMIT",
        "LATCH",
        "ADVANCE_GENERATION",
        "ORIGINAL",
    ] {
        for step in ["Stage", "DirSync"] {
            let mut f = Fixture::new();
            f.start();
            let id = "d".repeat(32);
            let (signer, packet, publication) = pending_operation(&mut f, op, &id);
            f.fault(publication, step, "fail", Value::Null, 100);
            assert!(f.request(signer, &packet).is_none(), "{op} {step}");
            assert_eq!(
                f.read(!signer)["uncertain"],
                step == "DirSync",
                "{op} {step}"
            );
            f.clear();
            assert!(
                matches!(
                    f.request(signer, &packet).unwrap()["op"].as_str(),
                    Some("ANCHOR_ACK" | "ORIGINAL_ACK")
                ),
                "{op} {step}"
            );
            assert_eq!(f.read(!signer)["uncertain"], false);
        }
    }
}

#[test]
fn authority_cells_and_direct_operations_are_closed() {
    let _guard = isolation::guard();
    for op in [
        "PREPARE",
        "LATCH",
        "ADVANCE_GENERATION",
        "ADVANCE_ACTIVATION",
        "ADVANCE_BOOT",
    ] {
        let mut f = Fixture::new();
        f.start();
        f.prepare();
        let mut next = f.anchor.clone();
        match op {
            "PREPARE" => {
                next["enrollment_revision"] =
                    json!(next["enrollment_revision"].as_u64().unwrap() + 1);
                next["transaction_id"] = json!("d".repeat(32));
            }
            "LATCH" => {
                next["recovery_required"] = json!(true);
                next["recovery_reason"] = json!("integrity");
                next["recovery_revision"] = json!(1);
            }
            _ => {
                next["generation_high_water"] =
                    json!(next["generation_high_water"].as_u64().unwrap() + 1);
                if op == "ADVANCE_ACTIVATION" {
                    next["activation_id"] = json!("f".repeat(32));
                }
                if op == "ADVANCE_BOOT" {
                    next["boot_id"] = json!("f".repeat(32));
                }
            }
        }
        let m = json!({"version":1,"op":op,"request_id":"d".repeat(32),"expected":f.anchor,"next":next});
        let p = anchor_packet(&m, &[]);
        assert_eq!(f.request(false, &p).unwrap()["op"], "REFUSED", "{op}");
        assert_eq!(f.stages().last().unwrap(), "AUTHORITY");
        assert_eq!(f.request(true, &p).unwrap()["op"], "ANCHOR_ACK", "{op}");
        if op == "PREPARE" {
            let mut committed = next.clone();
            committed["transaction_id"] = Value::Null;
            let m = json!({"version":1,"op":"COMMIT","request_id":"d".repeat(32),"expected":next,"next":committed});
            let p = anchor_packet(&m, &[]);
            assert_eq!(f.request(false, &p).unwrap()["op"], "REFUSED");
            assert_eq!(f.request(true, &p).unwrap()["op"], "ANCHOR_ACK");
        }
    }
    let mut f = Fixture::new();
    f.start();
    let mut next = f.anchor.clone();
    next["transaction_id"] = json!("c".repeat(32));
    let m =
        json!({"version":1,"op":"PREPARE","request_id":"c".repeat(32),"expected":null,"next":next});
    assert_eq!(
        f.request(false, &anchor_packet(&m, &[])).unwrap()["op"],
        "REFUSED"
    );
    let mut foreign = m.clone();
    foreign["next"]["fortress_id"] = json!("f".repeat(32));
    assert_eq!(
        f.request(true, &anchor_packet(&foreign, &[])).unwrap()["op"],
        "REFUSED"
    );
    assert_eq!(f.read(true)["state"], "ABSENT");
    let mut foreign = m.clone();
    foreign["next"]["role"] = json!("extension:linux-business-retrospective-v0");
    // The frozen anchor schema rejects this before a reply identity exists; decode refusal is a silent close.
    let message = canonical(&foreign);
    let mut header = protocol::header("ANCHOR", &"c".repeat(32), ROLE);
    header["message_length"] = json!(message.len());
    header["envelope_length"] = json!(0);
    let bytes = canonical(&header);
    let packet = [&(bytes.len() as u32).to_be_bytes()[..], &bytes, &message].concat();
    assert!(
        f.request(true, &packet).is_none(),
        "foreign genesis role silently refuses at decode"
    );
    assert_eq!(
        f.stages().last().map(String::as_str),
        Some("ENVELOPE"),
        "foreign genesis role stage"
    );
    assert_eq!(
        f.read(true)["state"],
        "ABSENT",
        "foreign genesis preserves absence"
    );
    f.prepare();
    let mut next = f.anchor.clone();
    let digest = packet_digest(&canonical(&f.body));
    next["reserved_sequence"] = json!(1);
    next["reserved_body_digest"] = json!(digest);
    let m = json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":f.anchor,"next":next,"body_digest":digest});
    assert_eq!(
        f.request(true, &anchor_packet(&m, &[])).unwrap()["op"],
        "REFUSED"
    );
    let (commit, envelope) = f.reserve_commit(&"d".repeat(32));
    assert_eq!(f.request(true, &commit).unwrap()["op"], "REFUSED");
    let original = original_packet(&"f".repeat(32), 1, &envelope);
    assert_eq!(f.request(true, &original).unwrap()["op"], "REFUSED");
    assert_eq!(f.request(false, &original).unwrap()["op"], "ORIGINAL_ACK");
    for op in ["READ", "DRAIN", "RECOVERY_COMMIT"] {
        for signer in [false, true] {
            let m = json!({"version":1,"op":op,"request_id":"e".repeat(32),"expected":f.anchor,"next":f.anchor});
            let payload = canonical(&m);
            let mut h = protocol::header("ANCHOR", &"e".repeat(32), ROLE);
            h["message_length"] = json!(payload.len());
            h["envelope_length"] = json!(0);
            let b = canonical(&h);
            let p = [&(b.len() as u32).to_be_bytes()[..], &b, &payload].concat();
            assert!(f.request(signer, &p).is_none_or_refused());
        }
    }
}
trait RefusedReply {
    fn is_none_or_refused(&self) -> bool;
}
impl RefusedReply for Option<Value> {
    fn is_none_or_refused(&self) -> bool {
        self.as_ref().map_or(true, |v| v["op"] == "REFUSED")
    }
}

#[test]
fn durable_orphan_retries_and_conflicts_keep_signer_available() {
    let _guard = isolation::guard();
    for conflict in [false, true] {
        let mut f = Fixture::new();
        f.start();
        f.prepare();
        let (_, envelope) = f.reserve_commit(&"d".repeat(32));
        f.fault("record", "Stage", "fail", Value::Null, 1);
        let p = original_packet(&"f".repeat(32), 1, &envelope);
        assert!(f.request(false, &p).is_none());
        assert_eq!(f.read(true)["uncertain"], false);
        f.clear();
        if conflict {
            let mut bad: Value = serde_json::from_slice(&envelope).unwrap();
            bad["outer"]["signature"] = json!("A".repeat(86));
            assert!(f
                .request(
                    false,
                    &original_packet(&"f".repeat(32), 1, &canonical(&bad))
                )
                .is_none());
            assert!(f.request(false, &p).is_none());
            assert_eq!(f.read(true)["uncertain"], false);
            assert!(f.stages().contains(&"RETRY".into()));
        } else {
            f.stop();
            f.start();
            assert_eq!(f.request(false, &p).unwrap()["op"], "ORIGINAL_ACK");
            assert_eq!(f.read(true)["uncertain"], false);
        }
    }
}

#[test]
fn post_store_identity_loss_has_no_success_reply() {
    let _guard = isolation::guard();
    for death in [false, true] {
        let mut f = Fixture::new();
        f.start();
        f.prepare();
        let digest = packet_digest(&canonical(&f.body));
        let mut next = f.anchor.clone();
        next["reserved_sequence"] = json!(1);
        next["reserved_body_digest"] = json!(digest);
        let m = json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":f.anchor,"next":next,"body_digest":digest});
        let p = anchor_packet(&m, &[]);
        f.fault("record", "FileSync", "hold", json!("identity"), 1);
        let path = f.socket();
        f.w.connect(&path);
        f.w.send(&p);
        let end = Instant::now() + Duration::from_millis(WAIT_MS);
        while !f.events().iter().any(|v| {
            v["request_id"] == "d".repeat(32)
                && v["event"] == "StepCompleted"
                && v["step"] == "Write"
        }) {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        if death {
            f.w.child.kill().unwrap();
            f.w.child.wait().unwrap();
            f.w = Actor::new();
        } else {
            f.bus.unit.lock().unwrap().pid = std::process::id();
        }
        write_private(&f.root.join("release-identity"), b"");
        if death {
            while !f
                .events()
                .iter()
                .any(|v| v["request_id"] == "d".repeat(32) && v["event"] == "RequestSettled")
            {
                assert!(Instant::now() < end);
                std::thread::sleep(Duration::from_millis(1));
            }
        } else {
            assert!(f.w.receive(WAIT_MS).is_none());
        }
        assert_eq!(f.read(true)["uncertain"], true);
        assert!(f
            .events()
            .iter()
            .all(|v| v["request_id"] != "d".repeat(32) || v["event"] != "ReplySent"));
        f.bus.unit.lock().unwrap().pid = f.w.child.id();
        f.clear();
        assert_eq!(f.request(false, &p).unwrap()["op"], "ANCHOR_ACK");
    }
}

fn pending_operation(f: &mut Fixture, op: &str, id: &str) -> (bool, Vec<u8>, &'static str) {
    if op == "PREPARE" || op == "CUSTODY_COMMIT" {
        let mut prepared = f.anchor.clone();
        prepared["transaction_id"] = json!(id);
        let prepare =
            json!({"version":1,"op":"PREPARE","request_id":id,"expected":null,"next":prepared});
        if op == "PREPARE" {
            (true, anchor_packet(&prepare, &[]), "record")
        } else {
            assert_eq!(
                f.request(true, &anchor_packet(&prepare, &[])).unwrap()["op"],
                "ANCHOR_ACK"
            );
            (
                true,
                anchor_packet(
                    &json!({"version":1,"op":"COMMIT","request_id":id,"expected":prepared,"next":f.anchor}),
                    &[],
                ),
                "record",
            )
        }
    } else {
        f.prepare();
        let mut next = f.anchor.clone();
        match op {
            "LATCH" => {
                next["recovery_required"] = json!(true);
                next["recovery_reason"] = json!("integrity");
                next["recovery_revision"] = json!(1);
                (
                    true,
                    anchor_packet(
                        &json!({"version":1,"op":op,"request_id":id,"expected":f.anchor,"next":next}),
                        &[],
                    ),
                    "record",
                )
            }
            "ADVANCE_GENERATION" => {
                next["generation_high_water"] =
                    json!(next["generation_high_water"].as_u64().unwrap() + 1);
                (
                    true,
                    anchor_packet(
                        &json!({"version":1,"op":op,"request_id":id,"expected":f.anchor,"next":next}),
                        &[],
                    ),
                    "record",
                )
            }
            "ORIGINAL" => {
                let (_, e) = f.reserve_commit(id);
                (false, original_packet(id, 1, &e), "copy")
            }
            _ => {
                let digest = packet_digest(&canonical(&f.body));
                next["reserved_sequence"] = json!(1);
                next["reserved_body_digest"] = json!(digest);
                let reserve = anchor_packet(
                    &json!({"version":1,"op":"RESERVE","request_id":id,"expected":f.anchor,"next":next,"body_digest":digest}),
                    &[],
                );
                if op == "RESERVE" {
                    (false, reserve, "record")
                } else {
                    assert_eq!(f.request(false, &reserve).unwrap()["op"], "ANCHOR_ACK");
                    let old = next.clone();
                    let envelope = f.signed(&f.body);
                    next["committed_sequence"] = json!(1);
                    next["reserved_body_digest"] = Value::Null;
                    next["committed_digest"] = json!(
                        castle_wall_daemon::business_profile::records::join_commitment(
                            &serde_json::from_slice(&envelope).unwrap()
                        )
                        .unwrap()
                    );
                    (
                        false,
                        anchor_packet(
                            &json!({"version":1,"op":"COMMIT","request_id":id,"expected":old,"next":next,"body_digest":digest}),
                            &envelope,
                        ),
                        "record",
                    )
                }
            }
        }
    }
}

#[test]
fn custody_record_and_original_waves_settle_before_another_admission() {
    let _guard = isolation::guard();
    const WAVES: usize = 30;
    for op in ["CUSTODY_COMMIT", "RECORD_COMMIT", "ORIGINAL"] {
        for wave in 0..WAVES {
            let mut f = Fixture::new();
            f.start();
            let id = "d".repeat(32);
            let (signer, packet, publication) = pending_operation(&mut f, op, &id);
            let step = if wave % 3 == 2 {
                "Readback"
            } else {
                "FileSync"
            };
            f.fault(publication, step, "hold", json!("wave"), 1);
            if wave % 3 != 2 {
                let path = f.root.join("store-faults.json");
                let mut rules: Vec<Value> =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                rules.push(json!({"slot":SLOT,"publication":publication,"step":if wave%3==0 {"Rename"} else {"DirSync"},"position":"before","action":"fail","value":null,"times":1}));
                write_private(&path, &canonical(&json!(rules)));
            }
            let path = f.socket();
            let before = f.events().len();
            let actor = if signer { &mut f.s } else { &mut f.w };
            actor.connect(&path);
            actor.send(&packet);
            let end = Instant::now() + Duration::from_millis(WAIT_MS);
            while !f.events()[before..].iter().any(|v| {
                v["event"] == "StepCompleted"
                    && v["publication"] == publication
                    && v["step"]
                        == if step == "Readback" {
                            "DirSync"
                        } else {
                            "Write"
                        }
            }) {
                assert!(Instant::now() < end);
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(
                protocol::D_REQUEST_DEADLINE_MS as u64 + DEADLINE_GRACE_MS,
            ));
            let actor = if signer { &mut f.s } else { &mut f.w };
            actor.command(json!({"op":"close"}));
            let read = protocol::encode(
                &protocol::header("READ", &"e".repeat(32), ROLE),
                &[],
                protocol::Direction::ToDrain,
            )
            .unwrap();
            let other = if signer { &mut f.w } else { &mut f.s };
            other.connect(&path);
            other.send(&read);
            assert!(other.receive(NO_REPLY_WINDOW_MS).is_none());
            assert!(f.events()[before..]
                .iter()
                .all(|v| v["event"] != "RequestAdmitted" || v["request_id"] == id));
            write_private(&f.root.join("release-wave"), b"");
            let other = if signer { &mut f.w } else { &mut f.s };
            assert!(other.receive(WAIT_MS).is_some());
            let events = f.events();
            let settled = events[before..]
                .iter()
                .position(|v| v["event"] == "RequestSettled" && v["request_id"] == id)
                .unwrap();
            let admitted = events[before..]
                .iter()
                .position(|v| v["event"] == "RequestAdmitted" && v["request_id"] != id)
                .unwrap();
            assert!(settled < admitted, "{op} {wave}");
            assert!(events.iter().all(|v| v["active"] == 1));
            f.clear();
            assert!(
                matches!(
                    f.request(signer, &packet).unwrap()["op"].as_str(),
                    Some("ANCHOR_ACK" | "ORIGINAL_ACK")
                ),
                "{op} {wave}"
            );
            assert_eq!(f.read(true)["uncertain"], false);
        }
    }
}

#[test]
fn lost_custody_and_record_ack_restart_retry_has_no_store_steps() {
    let _guard = isolation::guard();
    for op in ["CUSTODY_COMMIT", "RECORD_COMMIT"] {
        let mut f = Fixture::new();
        f.start();
        let id = "d".repeat(32);
        let (signer, packet, publication) = pending_operation(&mut f, op, &id);
        f.fault(publication, "Readback", "hold", json!("lost"), 1);
        let path = f.socket();
        let before = f.events().len();
        let actor = if signer { &mut f.s } else { &mut f.w };
        actor.connect(&path);
        actor.send(&packet);
        let end = Instant::now() + Duration::from_millis(WAIT_MS);
        while !f.events()[before..]
            .iter()
            .any(|v| v["event"] == "StepCompleted" && v["step"] == "DirSync")
        {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        let actor = if signer { &mut f.s } else { &mut f.w };
        actor.command(json!({"op":"close"}));
        write_private(&f.root.join("release-lost"), b"");
        loop {
            let events = f.events();
            if let Some(readback) = events[before..]
                .iter()
                .position(|v| v["event"] == "StepCompleted" && v["step"] == "Readback")
            {
                if events[before + readback + 1..]
                    .iter()
                    .any(|v| v["event"] == "RequestSettled")
                {
                    break;
                }
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        f.stop();
        f.clear();
        f.start();
        let before = f.events().len();
        assert_eq!(f.request(signer, &packet).unwrap()["op"], "ANCHOR_ACK");
        assert!(f.events()[before..]
            .iter()
            .all(|v| v["event"] != "StoreEntered" && v["event"] != "StepCompleted"));
    }
}

#[test]
#[ignore = "child driver; invoked explicitly by the real drain transport witness"]
fn drain_transport_child_driver() {
    use castle_wall_daemon::business_profile::signer_peer;
    use std::os::fd::AsRawFd;
    // The drain-actor launcher drops capabilities before exec, so every harness thread inherits the same empty principal.
    let root = std::path::PathBuf::from(
        std::env::var_os("DRAIN_TRANSPORT_FIXTURE").expect("explicit fixture root"),
    );
    let mode = std::env::var("DRAIN_TRANSPORT_MODE").unwrap();
    let end = Instant::now() + Duration::from_millis(WAIT_MS);
    while !root.join("runtime/drain.sock").exists() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    let socket = signer_peer::connect(&root.join("runtime/drain.sock")).unwrap();
    let packet = protocol::encode(
        &protocol::header("READ", &"e".repeat(32), ROLE),
        &[],
        protocol::Direction::ToDrain,
    )
    .unwrap();
    signer_peer::send(socket.as_raw_fd(), &packet, &[]).unwrap();
    loop {
        assert!(Instant::now() < end);
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, CHILD_POLL_MS) } == 0 {
            continue;
        }
        match signer_peer::receive(socket.as_raw_fd(), protocol::D_REPLY_MAX_BYTES) {
            Ok(p) => {
                let (h, _) = castle_wall_daemon::business_profile::frame::split(
                    &p.bytes,
                    protocol::D_HEADER_MAX_BYTES,
                    protocol::D_REPLY_MAX_BYTES,
                )
                .unwrap();
                assert_eq!(h["op"], "READ_REPLY");
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("control receive: {e}"),
        }
    }
    write_private(&root.join("transport-control"), b"READ_REPLY");
    match mode.as_str() {
        "duplicates" => {
            let mut extra = Vec::new();
            for _ in 0..protocol::D_CONNECTIONS_MAX {
                let fd = signer_peer::connect(&root.join("runtime/drain.sock")).unwrap();
                let _ = signer_peer::send(fd.as_raw_fd(), &packet, &[]);
                let mut p = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(unsafe { libc::poll(&mut p, 1, WAIT_MS as i32) }, 1);
                assert!(signer_peer::receive(fd.as_raw_fd(), protocol::D_REPLY_MAX_BYTES).is_err());
                extra.push(fd);
            }
            return;
        }
        "rights" => {
            let file = fs::File::open(root.join("config.json")).unwrap();
            signer_peer::send(socket.as_raw_fd(), &packet, &[file.as_raw_fd()]).unwrap();
        }
        "truncated" => {
            let oversized = vec![0u8; protocol::D_REQUEST_MAX_BYTES + 1];
            assert_eq!(
                unsafe {
                    libc::send(
                        socket.as_raw_fd(),
                        oversized.as_ptr().cast(),
                        oversized.len(),
                        libc::MSG_NOSIGNAL,
                    )
                },
                oversized.len() as isize
            );
        }
        "passed" => {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let ok = signer_peer::send(socket.as_raw_fd(), &packet, &[]).is_ok();
                unsafe { libc::_exit(if ok { 0 } else { 1 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(status, 0);
        }
        _ => panic!("unknown fixture mode"),
    }
    loop {
        assert!(Instant::now() < end);
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, CHILD_POLL_MS) } == 0 {
            continue;
        }
        match signer_peer::receive(socket.as_raw_fd(), protocol::D_REPLY_MAX_BYTES) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => break,
            Ok(p) => assert!(
                p.bytes.is_empty(),
                "hostile packet received an application reply"
            ),
        }
    }
}

#[test]
fn transport_rights_truncation_and_passed_socket_refuse_before_decode() {
    use sha2::{Digest, Sha256};
    let _guard = isolation::guard();
    for mode in ["rights", "truncated", "passed", "duplicates"] {
        let mut f = Fixture::new();
        let executable = std::env::current_exe().unwrap();
        let mut config: Value =
            serde_json::from_slice(&fs::read(f.root.join("config.json")).unwrap()).unwrap();
        if mode != "duplicates" {
            config["signer"]["executable_sha256"] =
                json!(hex::encode(Sha256::digest(fs::read(&executable).unwrap())));
        }
        write_private(&f.root.join("config.json"), &canonical(&config));
        let mut child = Reaped(
            // Must match the --transport-child exec path in helpers/drain-actor.rs.
            std::process::Command::new(actor_path())
                .arg("--transport-child")
                .arg(executable)
                .env("DRAIN_TRANSPORT_FIXTURE", &f.root)
                .env("DRAIN_TRANSPORT_MODE", mode)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut seam: Value =
            serde_json::from_slice(&fs::read(f.root.join("seam.json")).unwrap()).unwrap();
        if mode == "duplicates" {
            f.bus.unit.lock().unwrap().pid = child.0.id();
        } else {
            seam["signer_pid"] = json!(child.0.id());
        }
        write_private(&f.root.join("seam.json"), &canonical(&seam));
        f.start();
        let end = Instant::now() + Duration::from_millis(WAIT_MS * 2);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "{mode}");
                break;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            fs::read(f.root.join("transport-control")).unwrap(),
            b"READ_REPLY"
        );
        if mode != "duplicates" {
            assert!(
                f.stages().contains(&"BIND".into()),
                "{mode}: {:?}",
                f.stages()
            );
        }
        assert_eq!(
            f.events()
                .iter()
                .filter(|v| v["event"] == "RequestAdmitted")
                .count(),
            1
        );
        assert_eq!(f.read(mode == "duplicates")["uncertain"], false);
    }
}

#[test]
fn classification_partition_failures_precede_payload() {
    let _guard = isolation::guard();
    for mode in [
        "signer_pin",
        "bus_absent",
        "overlap",
        "artifact",
        "deadline",
    ] {
        let mut f = Fixture::new();
        match mode {
            "signer_pin" => {
                let mut config: Value =
                    serde_json::from_slice(&fs::read(f.root.join("config.json")).unwrap()).unwrap();
                config["signer"]["executable_sha256"] = json!("f".repeat(64));
                write_private(&f.root.join("config.json"), &canonical(&config));
                f.bus.unit.lock().unwrap().pid = f.s.child.id();
            }
            "bus_absent" => fs::remove_file(f.bus.root.path().join("bus")).unwrap(),
            "overlap" => {
                let mut seam: Value =
                    serde_json::from_slice(&fs::read(f.root.join("seam.json")).unwrap()).unwrap();
                seam["signer_group"] = json!(
                    castle_wall_daemon::business_profile::writer_peer::normalized_cgroup(
                        &fs::read_to_string("/proc/self/cgroup").unwrap()
                    )
                    .unwrap()
                );
                write_private(&f.root.join("seam.json"), &canonical(&seam));
            }
            "artifact" => fs::write(&f.bus.config.wall_exec, b"changed artifact").unwrap(),
            "deadline" => {
                f.bus.fault.lock().unwrap().reply_delay_ms =
                    protocol::D_CLASSIFY_DEADLINE_MS as u64 * 2
            }
            _ => unreachable!(),
        }
        f.start();
        let packet = protocol::encode(
            &protocol::header("READ", &"e".repeat(32), ROLE),
            &[],
            protocol::Direction::ToDrain,
        )
        .unwrap();
        let start = Instant::now();
        assert!(f.request(mode == "signer_pin", &packet).is_none(), "{mode}");
        assert!(start.elapsed() < Duration::from_millis(WAIT_MS));
        assert!(
            f.stages().contains(&"CLASSIFY".into()),
            "{mode}: {:?}",
            f.stages()
        );
        assert!(f.events().iter().all(|v| v["event"] != "RequestAdmitted"));
        if mode == "signer_pin" {
            f.bus.unit.lock().unwrap().pid = f.w.child.id();
            assert_eq!(f.read(false)["state"], "ABSENT");
        } else {
            assert_eq!(f.read(true)["state"], "ABSENT");
        }
    }
}

#[test]
fn retained_copy_caps_refuse_without_eviction() {
    use castle_wall_daemon::business_profile::{drain_store, records, writer_protocol};
    let _guard = isolation::guard();
    for entries_bound in [true, false] {
        let mut f = Fixture::new();
        f.start();
        f.prepare();
        f.stop();
        let count = if entries_bound {
            drain_store::D_COPY_ENTRIES_MAX
        } else {
            drain_store::D_COPY_MAX_BYTES as usize / writer_protocol::WRITER_ENVELOPE_MAX_BYTES
        };
        let mut body = f.body.clone();
        body["sequence"] = json!(count);
        let tip = f.signed(&body);
        let drained = records::join_commitment(&serde_json::from_slice(&tip).unwrap()).unwrap();
        body["sequence"] = json!(count + 1);
        body["prior_commitment"] = json!(drained);
        let candidate = f.signed(&body);
        let committed =
            records::join_commitment(&serde_json::from_slice(&candidate).unwrap()).unwrap();
        let mut anchor = f.anchor.clone();
        anchor["reserved_sequence"] = json!(count + 1);
        anchor["committed_sequence"] = json!(count + 1);
        anchor["drained_sequence"] = json!(count);
        anchor["drained_digest"] = json!(drained);
        anchor["committed_digest"] = json!(committed);
        let record = json!({"version":1,"anchor":anchor,"ledger":[committed],"last":{"authority":"W","phase":"RECORD_COMMIT","request_id":"d".repeat(32),"request_sha256":packet_digest(b"fixture")}});
        let record_path = f
            .root
            .join("state")
            .join(FORTRESS)
            .join("anchors")
            .join(format!("{SLOT}.json"));
        write_private(&record_path, &canonical(&record));
        let copies = f
            .root
            .join("state")
            .join(FORTRESS)
            .join("originals")
            .join(SLOT);
        let filler = vec![
            0;
            if entries_bound {
                1
            } else {
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES
            }
        ];
        // Earlier retained copies receive metadata checks at startup; the drained tip is the bounded envelope read.
        for sequence in 1..=count {
            write_private(
                &copies.join(format!("{sequence:020}.env")),
                if sequence == count { &tip } else { &filler },
            );
        }
        f.start();
        let before = fs::read(&record_path).unwrap();
        let packet = original_packet(&"e".repeat(32), (count + 1) as u64, &candidate);
        assert!(f.request(false, &packet).is_none());
        assert!(f.stages().contains(&"CAP".into()));
        assert!(f.notification().contains("copy_cap_refusals=1"));
        assert_eq!(f.read(true)["uncertain"], false);
        assert_eq!(fs::read(&record_path).unwrap(), before);
        assert_eq!(fs::read_dir(&copies).unwrap().count(), count);
        assert!(!copies.join(format!("{:020}.env", count + 1)).exists());
    }
}

#[test]
fn competing_reserve_and_advance_share_one_cas_prior() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    f.read(false);
    f.read(true);
    let mut reserve = f.anchor.clone();
    let digest = packet_digest(&canonical(&f.body));
    reserve["reserved_sequence"] = json!(1);
    reserve["reserved_body_digest"] = json!(digest);
    let w = anchor_packet(
        &json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":f.anchor,"next":reserve,"body_digest":digest}),
        &[],
    );
    let mut advance = f.anchor.clone();
    advance["generation_high_water"] =
        json!(advance["generation_high_water"].as_u64().unwrap() + 1);
    let s = anchor_packet(
        &json!({"version":1,"op":"ADVANCE_GENERATION","request_id":"e".repeat(32),"expected":f.anchor,"next":advance}),
        &[],
    );
    f.w.send(&w);
    f.s.send(&s);
    let replies = [f.w.receive(WAIT_MS).unwrap(), f.s.receive(WAIT_MS).unwrap()];
    let ops: Vec<String> = replies
        .iter()
        .map(|p| {
            castle_wall_daemon::business_profile::frame::split(
                p,
                protocol::D_HEADER_MAX_BYTES,
                protocol::D_REPLY_MAX_BYTES,
            )
            .unwrap()
            .0["op"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(ops.iter().filter(|s| *s == "ANCHOR_ACK").count(), 1);
    assert_eq!(ops.iter().filter(|s| *s == "REFUSED").count(), 1);
    assert!(f.stages().contains(&"PROPOSE".into()));
}

#[test]
fn schema_role_set_requires_a_role_stage_witness_when_expanded() {
    use castle_wall_daemon::business_profile::{records_schema, signer_contract::ROLE_REGISTRY};
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    let mut body = corpus["cases"][0]["records"][0]["body"].clone();
    assert!(records_schema::valid(&body), "producer schema control");
    for (role, _, _) in ROLE_REGISTRY {
        if *role == ROLE {
            continue;
        }
        body["role"] = json!(role);
        assert!(
            !records_schema::valid(&body),
            "schema admits {role}: add the W-COMMIT-VERIFY ROLE-stage witness"
        );
    }
}

#[test]
fn drained_original_lost_retry_ack_reconciles_and_conflict_closes_writer() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let (_, envelope) = f.reserve_commit(&"d".repeat(32));
    let packet = original_packet(&"e".repeat(32), 1, &envelope);
    assert_eq!(f.request(false, &packet).unwrap()["op"], "ORIGINAL_ACK");
    let before = f.read(true)["anchor_digest"].clone();
    let events = f.events().len();
    f.fault("copy", "Readback", "hold", json!("retry"), 1);
    f.w.connect(&f.socket());
    f.w.send(&packet);
    let end = Instant::now() + Duration::from_millis(WAIT_MS);
    while !f.events()[events..]
        .iter()
        .any(|e| e["publication"] == "copy" && e["step"] == "DirSync")
    {
        assert!(
            Instant::now() < end,
            "drained retry reaches copy durability barrier"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    f.w.command(json!({"op":"close"}));
    write_private(&f.root.join("release-retry"), b"");
    let read = f.read(true);
    assert_eq!(
        read["uncertain"], true,
        "lost drained retry ACK marks uncertainty"
    );
    assert_eq!(read["anchor_digest"], before, "lost retry preserves anchor");
    f.clear();
    let reply = f.request(false, &packet);
    assert_eq!(
        reply.as_ref().and_then(|r| r["op"].as_str()),
        Some("ORIGINAL_ACK"),
        "next mutation reconciles the drained retry"
    );
    let read = f.read(true);
    assert_eq!(
        read["uncertain"], false,
        "reconciled retry clears uncertainty"
    );
    assert_eq!(
        read["anchor_digest"], before,
        "reconciled retry preserves anchor"
    );
    let mut different = envelope.clone();
    different.push(b' ');
    assert!(
        f.request(false, &original_packet(&"f".repeat(32), 1, &different))
            .is_none(),
        "different drained bytes close W"
    );
    assert!(
        f.request(false, &packet).is_none(),
        "W remains closed after conflicting drained bytes"
    );
    assert_eq!(
        f.read(true)["anchor_digest"],
        before,
        "S remains served without changing anchor"
    );
    assert_eq!(
        fs::read_to_string(f.root.join("diagnostics.log")).unwrap(),
        "drain authority closed\n",
        "one content-free diagnostic for W closure"
    );
}
