// fail-before-exempt: advancing serve schedules use native socket, bus and clock fixtures.
// fail-before-exempt: isolated checkpoint predicates and scheduling exercise native primitives and shared schema fixtures.
// W-CHECKPOINT
use castle_wall_daemon::business_profile::{
    activation_anchor as anchor, append_checkpoint as cp, append_contract, records, records_schema,
    signer_contract,
    writer_protocol::{self as wire, Direction, Operation},
    writer_service::{
        self as service, test_support as support, DrainReconciler, WriterMachine, WriterState,
    },
};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
#[path = "writer_state.rs"]
mod state;
const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
type Machine = WriterMachine<support::ScriptedSigner, DrainReconciler>;
fn bytes(v: &Value) -> Vec<u8> {
    castle_wall_daemon::smb::jcs::encode(v)
        .unwrap()
        .into_bytes()
}
pub(super) fn fixture() -> (state::Fixture, Machine, Value) {
    let f = state::Fixture::new();
    let mut v = append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"].clone();
    let mut g = v["wal_checkpoint"]["join_state"]["pin"].clone();
    for key in ["activation_id", "lease_id", "generation"] {
        g[key] = v["wal_checkpoint"]["join_state"]["grant"][key].clone();
    }
    f.view.lock().unwrap().grant = serde_json::from_value(g).unwrap();
    let mut m = WriterMachine::isolated(
        f.signer(),
        DrainReconciler::production(cp::OrdinaryCheckpointProvider::production()),
        "a".repeat(32),
        f.clock(),
    )
    .unwrap();
    support::checkpoint_identity(&mut m, "a".repeat(32), 1);
    m.captured_wall_for_test().unwrap();
    f.unlock();
    v["wal_checkpoint"]["join_state"]["grant"]["expires_ns"] =
        json!(f.view.lock().unwrap().expires_boottime_ns);
    f.view.lock().unwrap().anchor_digest =
        Some(anchor::anchor_digest(&v["d_observation"]["anchor"]).unwrap());
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::WallBound);
    (f, m, v)
}
fn query(f: &state::Fixture, m: &mut Machine, v: &mut Value, id: &str) -> Vec<Vec<u8>> {
    let q = wire::encode(
        Direction::ToWriter,
        SESSION,
        &Operation::CheckpointQuery {
            request_id: id.into(),
        },
        &[],
    )
    .unwrap();
    let (op, payload) = support::checkpoint_packet(m, SESSION, &q).unwrap().unwrap();
    let Operation::CheckpointChallenge {
        request_id,
        nonce,
        issued_boottime_ns,
    } = op
    else {
        panic!("challenge")
    };
    v["request_id"] = json!(request_id);
    v["nonce"] = json!(nonce);
    v["session_id"] = json!(SESSION);
    v["observed_boottime_ns"] = json!(f.now.load(Ordering::SeqCst).to_string());
    v["status_digest"] = json!(cp::digest(&payload));
    assert_eq!(issued_boottime_ns, f.now.load(Ordering::SeqCst));
    packets(v)
}
fn packets(v: &Value) -> Vec<Vec<u8>> {
    let raw = bytes(v);
    let count = raw.len().div_ceil(anchor::MAX_BYTES);
    let digest = cp::digest(&raw);
    raw.chunks(anchor::MAX_BYTES)
        .enumerate()
        .map(|(i, part)| {
            wire::encode(
                Direction::ToWriter,
                SESSION,
                &Operation::CheckpointPart(cp::Part {
                    request_id: v["request_id"].as_str().unwrap().into(),
                    nonce: v["nonce"].as_str().unwrap().into(),
                    part_index: i,
                    part_count: count,
                    total_length: raw.len(),
                    checkpoint_digest: digest.clone(),
                }),
                part,
            )
            .unwrap()
        })
        .collect()
}
fn prepare(m: &mut Machine, packets: &[Vec<u8>]) {
    for packet in packets {
        assert!(support::checkpoint_packet(m, SESSION, packet)
            .unwrap()
            .is_none());
    }
    for _ in 0..3 {
        support::checkpoint_step(m).unwrap();
    }
    assert!(
        support::awaiting(m).is_some(),
        "predicate-passing checkpoint awaits reread"
    );
}
#[test]
fn ordinary_checkpoint_grants_once_and_replays_without_consuming_new_challenge() {
    let (f, mut m, mut v) = fixture();
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    assert_eq!(f.binds.load(Ordering::SeqCst), 0);
    assert!(matches!(
        support::checkpoint_reread(&mut m).unwrap(),
        Some(Operation::CheckpointAck { .. })
    ));
    assert_eq!(m.state(), WriterState::Granted);
    assert_eq!(f.binds.load(Ordering::SeqCst), 1);
    let _new = query(&f, &mut m, &mut v, &"c".repeat(32));
    assert!(matches!(
        support::checkpoint_packet(&mut m, SESSION, &parts[0]).unwrap(),
        Some((Operation::CheckpointAck { .. }, _))
    ));
    assert_eq!(f.binds.load(Ordering::SeqCst), 1);
    let mut changed = parts[0].clone();
    let n = changed.len();
    changed[n - 2] ^= 1;
    assert!(
        support::checkpoint_packet(&mut m, SESSION, &changed).is_err(),
        "changed replay is terminal"
    );
    m.settle();
    assert!(!support::has_candidate(&m));
}
#[test]
fn reread_refusal_disposes_candidate_and_a_second_checkpoint_can_succeed() {
    let (f, mut m, mut v) = fixture();
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    let saved = f.view.lock().unwrap().clone();
    f.view.lock().unwrap().state = "LOCKED".into();
    assert!(support::checkpoint_reread(&mut m).unwrap().is_none());
    assert!(!support::has_candidate(&m));
    assert!(support::awaiting(&m).is_none());
    assert_eq!(f.binds.load(Ordering::SeqCst), 0);
    *f.view.lock().unwrap() = saved;
    m.heartbeat().unwrap();
    let parts = query(&f, &mut m, &mut v, &"d".repeat(32));
    prepare(&mut m, &parts);
    assert!(support::checkpoint_reread(&mut m).unwrap().is_some());
    assert_eq!(f.binds.load(Ordering::SeqCst), 1);
}
#[test]
fn lifetime_and_freshness_are_independent_at_promotion() {
    for expired in [false, true] {
        let (f, mut m, mut v) = fixture();
        let _ = query(&f, &mut m, &mut v, REQUEST);
        if expired {
            v["observed_boottime_ns"] =
                json!((state::NOW + cp::CHECKPOINT_CHALLENGE_MS * state::NS_PER_MS).to_string());
        }
        let parts = packets(&v);
        prepare(&mut m, &parts);
        f.now.store(
            state::NOW
                + if expired {
                    cp::CHECKPOINT_CHALLENGE_MS * state::NS_PER_MS
                } else {
                    (cp::CHECKPOINT_AGE_MS + 1) * state::NS_PER_MS
                },
            Ordering::SeqCst,
        );
        assert!(
            support::checkpoint_reread(&mut m).unwrap().is_none(),
            "lifetime/freshness refuses without a competing state failure"
        );
        assert_eq!(m.state(), WriterState::WallBound);
        assert_eq!(f.binds.load(Ordering::SeqCst), 0);
        assert!(!support::has_candidate(&m));
        m.heartbeat().unwrap();
        assert_eq!(f.binds.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn preemption_of_a_985ms_reply_keeps_the_next_request_time() {
    let (f, mut m, mut v) = fixture();
    // Admit just before the one-tick guard, then let the next loop reach the ordinary due point.
    f.now.fetch_add(
        (wire::WRITER_HEARTBEAT_MS - 11) * state::NS_PER_MS,
        Ordering::SeqCst,
    );
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    f.now.fetch_add(11 * state::NS_PER_MS, Ordering::SeqCst);

    f.status_times.lock().unwrap().clear();
    f.status_delay
        .store(985 * state::NS_PER_MS, Ordering::SeqCst);
    let t0 = f.now.load(Ordering::SeqCst);
    assert!(support::checkpoint_reread(&mut m).unwrap().is_none());
    assert_eq!(f.binds.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.now.load(Ordering::SeqCst),
        t0 + 985 * state::NS_PER_MS,
        "preemption performs zero adjudication work"
    );
    f.status_delay.store(0, Ordering::SeqCst);
    f.now.fetch_add(10 * state::NS_PER_MS, Ordering::SeqCst);
    m.heartbeat().unwrap();
    assert_eq!(
        f.status_times.lock().unwrap()[1],
        t0 + 995 * state::NS_PER_MS
    );
    let (baseline, mut ordinary, _) = fixture();
    baseline.now.store(t0, Ordering::SeqCst);
    baseline
        .status_delay
        .store(985 * state::NS_PER_MS, Ordering::SeqCst);
    assert!(ordinary.heartbeat_due().unwrap());
    ordinary.heartbeat().unwrap();
    baseline.status_delay.store(0, Ordering::SeqCst);
    baseline
        .now
        .fetch_add(10 * state::NS_PER_MS, Ordering::SeqCst);
    ordinary.heartbeat().unwrap();
    assert_eq!(
        *baseline.status_times.lock().unwrap().last().unwrap(),
        *f.status_times.lock().unwrap().last().unwrap(),
        "same slow-heartbeat schedule leaves at the same time without a checkpoint"
    );
}
#[test]
fn raw_checkpoint_preserves_number_spelling_and_payload_echo() {
    let (f, mut m, mut v) = fixture();
    let parts = query(&f, &mut m, &mut v, REQUEST);
    assert!(cp::Candidate::parse(&bytes(&v)).is_ok());
    let text = String::from_utf8(bytes(&v))
        .unwrap()
        .replace("\"agent_uids\":[1000]", "\"agent_uids\":[1e3]");
    assert!(cp::Candidate::parse(text.as_bytes()).is_err());
    v["nonce"] = json!("e".repeat(32));
    let wrong = packets(&v);
    for p in wrong {
        support::checkpoint_packet(&mut m, SESSION, &p).unwrap();
    }
    for _ in 0..3 {
        support::checkpoint_step(&mut m).unwrap();
    }
    assert!(support::awaiting(&m).is_none());
    assert!(!parts.is_empty());
}
fn max_node(node: &Value, defs: &Value) -> Value {
    match node["type"].as_str().unwrap() {
        "ref" => max_node(&defs[node["name"].as_str().unwrap()], defs),
        "literal" => node["value"].clone(),
        "enum" => node["values"]
            .as_array()
            .unwrap()
            .iter()
            .max_by_key(|v| bytes(v).len())
            .unwrap()
            .clone(),
        "integer" => node["max"].clone(),
        "union" => node["branches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| max_node(n, defs))
            .max_by_key(|v| bytes(v).len())
            .unwrap(),
        "object" => {
            let mut value = Value::Object(
                node["fields"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, n)| (k.clone(), max_node(n, defs)))
                    .collect(),
            );
            if value["family"] == "ipv4" {
                for key in ["src_ip", "dst_ip"] {
                    value[key] = json!("255.255.255.255");
                }
            }
            value
        }
        "string" => json!(match node["encoding"].as_str().unwrap() {
            "id" => "f".repeat(32),
            "digest" => format!("sha256:{}", "f".repeat(64)),
            "kid" => format!("k1:sha256:{}", "f".repeat(64)),
            "u64" => u64::MAX.to_string(),
            "ipv4" => "255.255.255.255".into(),
            "ipv6" => "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into(),
            _ => panic!("encoding"),
        }),
        _ => panic!("schema node"),
    }
}
fn maximal_checkpoint_value() -> Value {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../server/src/signing/linux-business-records.schema.json"
    ))
    .unwrap();
    let bodies = schema["record"]["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| max_node(n, &schema["definitions"]))
        .collect::<Vec<_>>();
    let envelopes = bodies
        .iter()
        .filter(|b| records_schema::valid(b))
        .map(|b| wire::envelope(&bytes(b), &[0; 64]).unwrap())
        .collect::<Vec<_>>();
    let biggest = envelopes
        .iter()
        .max_by_key(|b| b.len())
        .expect("maximal schema branch");
    assert_eq!(biggest.len(), 2661, "attained all-branch maximum");
    let mut v = append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"].clone();
    let join = &mut v["wal_checkpoint"]["join_state"];
    join["pin"]["role"] = json!(signer_contract::ROLE_REGISTRY
        .iter()
        .map(|r| r.0)
        .max_by_key(|s| s.len())
        .unwrap());
    join["policy"]["agent_uids"] = json!((0..records::POLICY_AGENT_UIDS_MAX)
        .map(|i| anchor::SAFE_INTEGER - records::POLICY_AGENT_UIDS_MAX as u64 + 1 + i as u64)
        .collect::<Vec<_>>());
    join["policy"]["vendors"] = json!((0..records::POLICY_VENDORS_MAX)
        .map(|i| json!({"address":"255.255.255.255","port":65535-records::POLICY_VENDORS_MAX+1+i}))
        .collect::<Vec<_>>());
    join["flow_state"]["history"] = json!(vec![
        serde_json::from_slice::<Value>(biggest).unwrap();
        records::JOIN_HISTORY_MAX
    ]);
    join["pin"]["epoch"] = json!(anchor::SAFE_INTEGER);
    join["grant"]["generation"] = json!(anchor::SAFE_INTEGER);
    join["grant"]["expires_ns"] = json!(u64::MAX.to_string());
    join["anchor"]["sequence"] = json!(anchor::SAFE_INTEGER);
    join["anchor"]["generation"] = json!(anchor::SAFE_INTEGER);
    join["anchor"]["captured_at_boottime_ns"] = json!(u64::MAX.to_string());
    join["anchor"]["commitment"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert!(records::join_state_valid(join));
    let a = &mut v["d_observation"]["anchor"];
    for key in [
        "enrollment_revision",
        "generation_high_water",
        "reserved_sequence",
        "recovery_revision",
    ] {
        a[key] = json!(anchor::SAFE_INTEGER);
    }
    a["committed_sequence"] = json!(anchor::SAFE_INTEGER - 1);
    a["drained_sequence"] = json!(anchor::SAFE_INTEGER - 1);
    for key in ["committed_digest", "drained_digest", "reserved_body_digest"] {
        a[key] = json!(format!("sha256:{}", "f".repeat(64)));
    }
    a["transaction_id"] = json!("f".repeat(32));
    a["recovery_required"] = json!(true);
    a["recovery_reason"] = json!("storage_fault");
    assert!(anchor::valid(a));
    let ad = anchor::anchor_digest(a).unwrap();
    v["d_observation"]["anchor_digest"] = json!(ad);
    v["d_observation"]["latched"] = json!(true);
    v["observed_boottime_ns"] = json!(u64::MAX.to_string());
    v["enrollment_revision"] = json!(anchor::SAFE_INTEGER);
    for key in ["committed_sequence", "drained_sequence"] {
        v["wal_checkpoint"][key] = json!(anchor::SAFE_INTEGER);
    }
    for key in ["committed_digest", "drained_digest"] {
        v["wal_checkpoint"][key] = json!(format!("sha256:{}", "f".repeat(64)));
    }
    v["wal_checkpoint"]["retained_originals"]=json!((0..512).map(|i|json!({"sequence":anchor::SAFE_INTEGER-511+i,"commitment":format!("sha256:{}","f".repeat(64))})).collect::<Vec<_>>());
    v
}
#[test]
fn maximal_checkpoint_is_within_the_derived_transport_bound() {
    let v = maximal_checkpoint_value();
    let raw = bytes(&v);
    assert_eq!(raw.len(), 237298, "attained complete maximum");
    assert!(raw.len() <= cp::CHECKPOINT_HONEST_MAX_BYTES);
    assert_eq!(cp::CHECKPOINT_PARTS_MAX, 4);
    let start = std::time::Instant::now();
    assert!(cp::Candidate::parse(&raw).is_ok());
    println!(
        "size_fixture_bytes={} honest_bound={} parse_us={}",
        raw.len(),
        cp::CHECKPOINT_HONEST_MAX_BYTES,
        start.elapsed().as_micros()
    );
}

#[test]
fn phase_shift_remains_inside_the_anchored_request_bound() {
    let (f, mut m, mut v) = fixture();
    f.now.fetch_add(50 * state::NS_PER_MS, Ordering::SeqCst);
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    assert!(support::checkpoint_reread(&mut m).unwrap().is_some());
    f.now.fetch_add(state::NS_PER_MS, Ordering::SeqCst);
    for _ in 0..100 {
        f.now.fetch_add(10 * state::NS_PER_MS, Ordering::SeqCst);
        if m.heartbeat_due().unwrap() {
            m.heartbeat().unwrap();
        }
    }
    let times = f.status_times.lock().unwrap();
    assert!(
        times
            .windows(2)
            .any(|t| t[1] - t[0] == 251 * state::NS_PER_MS),
        "legal relative-sleep phase shift exercised"
    );
    for t in times.windows(2) {
        assert!(t[1] <= service::writer_next_request_bound_ns(t[0]).unwrap());
    }
}
#[test]
fn full_adjudication_budget_preserves_wall_deadline_anchor() {
    let (f, mut m, mut v) = fixture();
    f.now.fetch_add(50 * state::NS_PER_MS, Ordering::SeqCst);
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    let t0 = f.now.load(Ordering::SeqCst);
    let signer = support::scripted_signer(&mut m);
    let mut bind = std::mem::replace(
        &mut signer.bind,
        Box::new(|_| panic!("replaced bound work")),
    );
    let now = f.now.clone();
    signer.bind = Box::new(move |g| {
        now.fetch_add(
            service::CHECKPOINT_ADJUDICATION_BUDGET_MS * state::NS_PER_MS,
            Ordering::SeqCst,
        );
        bind(g)
    });
    assert!(support::checkpoint_reread(&mut m).unwrap().is_some());
    assert_eq!(
        f.now.load(Ordering::SeqCst),
        t0 + service::CHECKPOINT_ADJUDICATION_BUDGET_MS * state::NS_PER_MS,
        "full budget consumed within adjudication"
    );
    assert_eq!(
        support::last_status(&m),
        t0,
        "adjudication cannot refresh the S admission anchor"
    );
    let end = support::wall_deadline(&m, f.now.load(Ordering::SeqCst)).unwrap();
    assert_eq!(
        end,
        t0 + wire::WRITER_SIGN_DEADLINE_MAX_MS * state::NS_PER_MS,
        "wall deadline retains the admission anchor"
    );
    // The supremum of successful revalidation is one nanosecond before its exclusive deadline.
    f.now
        .store(end - 1 + 10 * state::NS_PER_MS, Ordering::SeqCst);
    m.heartbeat().unwrap();
    let sent = *f.status_times.lock().unwrap().last().unwrap();
    assert!(sent <= service::writer_next_request_bound_ns(t0).unwrap());
    assert!(sent < t0 + signer_contract::SIGNER_IDLE_DEADLINE_MS as u64 * state::NS_PER_MS);
}
fn bounded_ordinary_report(f: &state::Fixture, v: &mut Value) {
    let maximal = maximal_checkpoint_value();
    v["wal_checkpoint"]["join_state"]["flow_state"]["history"] =
        maximal["wal_checkpoint"]["join_state"]["flow_state"]["history"].clone();
    v["wal_checkpoint"]["join_state"]["policy"] =
        maximal["wal_checkpoint"]["join_state"]["policy"].clone();
    let digest = format!("sha256:{}", "f".repeat(64));
    v["d_observation"]["anchor"]["reserved_sequence"] = json!(512);
    v["d_observation"]["anchor"]["committed_sequence"] = json!(512);
    v["d_observation"]["anchor"]["committed_digest"] = json!(digest);
    v["wal_checkpoint"]["committed_sequence"] = json!(512);
    v["wal_checkpoint"]["committed_digest"] = json!(digest);
    v["wal_checkpoint"]["join_state"]["anchor"]["sequence"] = json!(512);
    v["wal_checkpoint"]["join_state"]["anchor"]["commitment"] = json!(digest);
    v["wal_checkpoint"]["retained_originals"] = json!((1..=512)
        .map(|sequence| json!({"sequence":sequence,"commitment":digest}))
        .collect::<Vec<_>>());
    let digest = anchor::anchor_digest(&v["d_observation"]["anchor"]).unwrap();
    v["d_observation"]["anchor_digest"] = json!(digest);
    f.view.lock().unwrap().anchor_digest = Some(digest);
}
#[test]
fn full_ordinary_sequence_replays_only_complete_exact_order() {
    let (f, mut m, mut v) = fixture();
    bounded_ordinary_report(&f, &mut v);
    m.heartbeat().unwrap();
    let parts = query(&f, &mut m, &mut v, REQUEST);
    assert_eq!(parts.len(), cp::CHECKPOINT_PARTS_MAX);
    prepare(&mut m, &parts);
    assert!(support::checkpoint_reread(&mut m).unwrap().is_some());
    assert!(
        support::checkpoint_packet(&mut m, SESSION, &parts[1])
            .unwrap()
            .is_none(),
        "reordered replay has no ACK"
    );
    for (i, p) in parts.iter().enumerate() {
        assert_eq!(
            support::checkpoint_packet(&mut m, SESSION, p)
                .unwrap()
                .is_some(),
            i + 1 == parts.len(),
            "only complete exact replay ACKs"
        );
    }
    let _new = query(&f, &mut m, &mut v, &"d".repeat(32));
    for (i, p) in parts.iter().enumerate() {
        assert_eq!(
            support::checkpoint_packet(&mut m, SESSION, p)
                .unwrap()
                .is_some(),
            i + 1 == parts.len()
        );
    }
    assert_eq!(f.binds.load(Ordering::SeqCst), 1);
}
#[test]
fn transfer_digest_order_and_repeated_metadata_are_enforced() {
    let raw = vec![b'a'; anchor::MAX_BYTES + 1];
    let base = cp::Part {
        request_id: REQUEST.into(),
        nonce: SESSION.into(),
        part_index: 0,
        part_count: 2,
        total_length: raw.len(),
        checkpoint_digest: cp::digest(&raw),
    };
    for field in ["request", "nonce", "count", "length", "digest", "index"] {
        let mut transfer = cp::Transfer::begin(&base, 0).unwrap();
        assert!(!transfer
            .push(&base, &raw[..anchor::MAX_BYTES], b"first", 0)
            .unwrap());
        let mut last = base.clone();
        last.part_index = 1;
        match field {
            "request" => last.request_id = "c".repeat(32),
            "nonce" => last.nonce = "c".repeat(32),
            "count" => last.part_count = 3,
            "length" => last.total_length += 1,
            "digest" => last.checkpoint_digest = format!("sha256:{}", "d".repeat(64)),
            "index" => last.part_index = 0,
            _ => unreachable!(),
        }
        assert!(
            transfer
                .push(&last, &raw[anchor::MAX_BYTES..], b"last", 0)
                .is_err(),
            "changed {field} refuses"
        );
    }
    let mut transfer = cp::Transfer::begin(&base, 0).unwrap();
    transfer
        .push(&base, &raw[..anchor::MAX_BYTES], b"first", 0)
        .unwrap();
    let mut last = base.clone();
    last.part_index = 1;
    transfer.push(&last, b"b", b"last", 0).unwrap();
    assert!(
        transfer.finish().is_err(),
        "digest authenticates complete assembled bytes"
    );
    let transfer = cp::Transfer::begin(&base, 0).unwrap();
    assert!(transfer.expired(0, cp::CHECKPOINT_PART_SILENCE_MS * state::NS_PER_MS));
}
#[test]
fn adjudication_work_measurement() {
    let mut worst = std::time::Duration::ZERO;
    // Repeated independently prepared bounded candidates include success and freshness refusal.
    for stale in [false, true] {
        for _ in 0..20 {
            let (f, mut m, mut v) = fixture();
            bounded_ordinary_report(&f, &mut v);
            m.heartbeat().unwrap();
            let parts = query(&f, &mut m, &mut v, REQUEST);
            prepare(&mut m, &parts);
            if stale {
                f.now.fetch_add(
                    (cp::CHECKPOINT_AGE_MS + 1) * state::NS_PER_MS,
                    Ordering::SeqCst,
                );
            }
            m.heartbeat().unwrap();
            let received = support::awaiting(&m).unwrap();
            let start = std::time::Instant::now();
            let result = support::adjudicate(&mut m, received).unwrap();
            worst = worst.max(start.elapsed());
            assert_eq!(result.is_some(), !stale);
        }
    }
    println!(
        "adjudicate_worst_ns={} budget_ms={}",
        worst.as_nanos(),
        service::CHECKPOINT_ADJUDICATION_BUDGET_MS
    );
    assert!(worst.as_millis() < u128::from(service::CHECKPOINT_ADJUDICATION_BUDGET_MS));
}

#[path = "writer_bus.rs"]
mod bus_fixture;
const FIXTURE_STARTUP_MS: u64 = 10_000;
const FIXTURE_OPERATION_MS: u64 = cp::CHECKPOINT_CHALLENGE_MS;
fn fixture_poll_retry(
    end: std::time::Instant,
    mut poll: impl FnMut(i32) -> std::io::Result<()>,
) -> std::io::Result<()> {
    loop {
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        match poll(left.as_millis().max(1).min(i32::MAX as u128) as i32) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}
fn fixture_poll(fd: i32, budget_ms: u64) {
    let end = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    fixture_poll_retry(end, |timeout| {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut p, 1, timeout) } {
            1 => Ok(()),
            0 => Err(std::io::ErrorKind::TimedOut.into()),
            _ => Err(std::io::Error::last_os_error()),
        }
    })
    .expect("bounded fixture receive");
}
#[test]
fn fixture_poll_retries_interruption_without_renewing_the_absolute_deadline() {
    let mut calls = 0;
    fixture_poll_retry(
        std::time::Instant::now() + std::time::Duration::from_millis(FIXTURE_OPERATION_MS),
        |_| {
            calls += 1;
            if calls < 3 {
                Err(std::io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(calls, 3, "interruption retains one bounded poll");
    let deadline = std::time::Instant::now();
    assert_eq!(
        fixture_poll_retry(deadline, |_| panic!("expired poll cannot run"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}
fn wire_receive(fd: i32) -> Vec<u8> {
    fixture_poll(fd, FIXTURE_OPERATION_MS);
    castle_wall_daemon::business_profile::signer_peer::receive(
        fd,
        wire::WRITER_REPLY_PACKET_MAX_BYTES,
    )
    .unwrap()
    .bytes
}
fn accepting_serve_fixture(
    partial: bool,
    held: bool,
    second: bool,
    ack_failure: bool,
    expiry: bool,
) {
    accepting_serve_case(partial, held, second, ack_failure, expiry, None);
}
#[allow(clippy::too_many_arguments)]
fn accepting_serve_case(
    partial: bool,
    held: bool,
    second: bool,
    ack_failure: bool,
    expiry: bool,
    supplied: Option<(state::Fixture, Machine, Value, bool)>,
) {
    use castle_wall_daemon::business_profile::{
        signer_peer,
        writer_peer::{HeldConfig, ListenerExpectations},
    };
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
    let (f, mut machine, mut report, expect_grant) = supplied.unwrap_or_else(|| {
        let (f, m, report) = fixture();
        (f, m, report, true)
    });
    if partial {
        bounded_ordinary_report(&f, &mut report);
        machine.heartbeat().unwrap();
    }
    if expiry {
        support::ordinary_reconciliation(&mut machine);
        let clock = f.now.clone();
        let expires = f
            .view
            .lock()
            .unwrap()
            .expires_boottime_ns
            .parse::<u64>()
            .unwrap();
        let signer = support::scripted_signer(&mut machine);
        let mut bind = std::mem::replace(&mut signer.bind, Box::new(|_| panic!("replaced bind")));
        signer.bind = Box::new(move |grant| {
            let result = bind(grant);
            clock.store(expires, Ordering::SeqCst);
            result
        });
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    if held {
        let signer = support::scripted_signer(&mut machine);
        let mut status =
            std::mem::replace(&mut signer.status, Box::new(|| panic!("replaced status")));
        let mut first = Some((entered_tx, release_rx));
        signer.status = Box::new(move || {
            if let Some((entered, release)) = first.take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            status()
        });
    }
    let mut bus = bus_fixture::Fixture::new();
    bus.config.fortress_id = "a".repeat(32);
    let config = HeldConfig::isolated(&bus.config_path(), unsafe { libc::geteuid() }).unwrap();
    let path = bus.root.path().join("records");
    let listener = signer_peer::listen(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let expect = ListenerExpectations::isolated(path.clone(), unsafe { libc::geteuid() }, unsafe {
        libc::getegid()
    });
    let target = bus.target.clone();
    let clock = f.clock();
    let runner = std::thread::spawn(move || {
        let result = support::serve_accept(
            &mut machine,
            &config,
            &target,
            &listener,
            &expect,
            unsafe { libc::geteuid() },
            &clock,
        );
        assert!(result.is_err(), "disconnect is terminal");
        assert!(
            !support::checkpoint_owned(&machine),
            "every serve exit cancels all checkpoint ownership"
        );
        assert!(support::awaiting(&machine).is_none());
    });
    let socket = signer_peer::connect(&path).unwrap();
    let hello = wire_receive(socket.as_raw_fd());
    let n = u32::from_be_bytes(hello[..4].try_into().unwrap()) as usize;
    let h: Value = serde_json::from_slice(&hello[4..4 + n]).unwrap();
    let session = h["session_id"].as_str().unwrap();
    signer_peer::send(
        socket.as_raw_fd(),
        &wire::encode(Direction::ToWriter, session, &Operation::HelloAck, &[]).unwrap(),
        &[],
    )
    .unwrap();
    signer_peer::send(
        socket.as_raw_fd(),
        &wire::encode(
            Direction::ToWriter,
            session,
            &Operation::CheckpointQuery {
                request_id: REQUEST.into(),
            },
            &[],
        )
        .unwrap(),
        &[],
    )
    .unwrap();
    let response = wire_receive(socket.as_raw_fd());
    let response = wire::decode(&response, Direction::ToWall, session).unwrap();
    let Operation::CheckpointChallenge { nonce, .. } = response.operation else {
        panic!("challenge");
    };
    report["session_id"] = json!(session);
    report["request_id"] = json!(REQUEST);
    report["nonce"] = json!(nonce);
    report["status_digest"] = json!(cp::digest(response.payload));
    report["observed_boottime_ns"] = json!(f.now.load(Ordering::SeqCst).to_string());
    let raw = bytes(&report);
    let op = Operation::CheckpointPart(cp::Part {
        request_id: REQUEST.into(),
        nonce: report["nonce"].as_str().unwrap().into(),
        part_index: 0,
        part_count: raw.len().div_ceil(anchor::MAX_BYTES),
        total_length: raw.len(),
        checkpoint_digest: cp::digest(&raw),
    });
    signer_peer::send(
        socket.as_raw_fd(),
        &wire::encode(
            Direction::ToWriter,
            session,
            &op,
            &raw[..raw.len().min(anchor::MAX_BYTES)],
        )
        .unwrap(),
        &[],
    )
    .unwrap();
    if !expect_grant {
        std::thread::sleep(std::time::Duration::from_millis(
            state::BUS_SCHEDULING_SLACK_MS,
        ));
        signer_peer::send(
            socket.as_raw_fd(),
            &wire::encode(
                Direction::ToWriter,
                session,
                &Operation::Status {
                    request_id: "d".repeat(32),
                },
                &[],
            )
            .unwrap(),
            &[],
        )
        .unwrap();
        let reply = wire_receive(socket.as_raw_fd());
        assert!(
            matches!(
                wire::decode(&reply, Direction::ToWall, session)
                    .unwrap()
                    .operation,
                Operation::StatusReply { .. }
            ),
            "null S checkpoint produces no acceptance ACK"
        );
        assert_eq!(
            f.binds.load(Ordering::SeqCst),
            0,
            "null S checkpoint produces no grant"
        );
        assert_eq!(
            f.signs.load(Ordering::SeqCst),
            0,
            "null S checkpoint produces no effect"
        );
        drop(socket);
        runner.join().unwrap();
        return;
    }
    if expiry {
        runner.join().unwrap();
        assert_eq!(
            f.binds.load(Ordering::SeqCst),
            1,
            "ordinary transition precedes frozen expiry"
        );
        return;
    }
    if ack_failure {
        assert_eq!(
            unsafe { libc::shutdown(socket.as_raw_fd(), libc::SHUT_RD) },
            0
        );
        runner.join().unwrap();
        assert_eq!(
            f.binds.load(Ordering::SeqCst),
            1,
            "ACK failure follows exactly one grant transition"
        );
        return;
    }
    if held {
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            f.binds.load(Ordering::SeqCst),
            0,
            "no promotion before the held reread resolves"
        );
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut poll, 1, 0) },
            0,
            "no ACK before decisive reread"
        );
        let _second = if second {
            Some(signer_peer::connect(&path).unwrap())
        } else {
            None
        };
        if !second {
            f.view.lock().unwrap().anchor_digest = Some(format!("sha256:{}", "e".repeat(64)));
        }
        release_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(
            f.binds.load(Ordering::SeqCst),
            0,
            "decisive reread refusal never binds later"
        );
        drop(socket);
        runner.join().unwrap();
        return;
    }
    if partial {
        drop(socket);
        runner.join().unwrap();
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(
        8 * castle_wall_daemon::business_profile::signer_watchdog::WATCHDOG_TICK_MS as u64,
    ));
    assert!(
        f.statuses.load(Ordering::SeqCst) > 1,
        "pending reread advances STATUS while ordinary heartbeat is not due"
    );
    let reply = wire_receive(socket.as_raw_fd());
    assert!(matches!(
        wire::decode(&reply, Direction::ToWall, session)
            .unwrap()
            .operation,
        Operation::CheckpointAck { .. }
    ));
    assert_eq!(
        f.binds.load(Ordering::SeqCst),
        1,
        "real accepting serve grants once before its ACK"
    );
    drop(socket);
    runner.join().unwrap();
}

#[test]
fn accepting_serve_promotes_the_complete_fixture_and_cancels_on_disconnect() {
    accepting_serve_fixture(false, false, false, false, false);
}
#[test]
fn every_serve_exit_cancels_a_partial_transfer() {
    accepting_serve_fixture(true, false, false, false, false);
}

#[test]
fn held_reread_cannot_promote_or_ack_before_its_decisive_reply() {
    accepting_serve_fixture(false, true, false, false, false);
}

#[test]
fn second_accept_during_reread_is_terminal_before_binding() {
    accepting_serve_fixture(false, true, true, false, false);
}

// The existing one-test child-driver pattern (also used by wal_nits) keeps the
// scripted peer in a separate process without adding a standalone test case.
fn checkpoint_signer_child(root: &std::path::Path) {
    use castle_wall_daemon::business_profile::{signer_peer, signer_service};
    use std::{fs, os::fd::AsRawFd};
    // Check the post-exec principal too: no capability can return across exec.
    signer_peer::empty_capabilities(unsafe { libc::getpid() }, unsafe { libc::geteuid() } == 0)
        .unwrap();
    let view: Value = serde_json::from_slice(&fs::read(root.join("signer-view")).unwrap()).unwrap();
    let reply = signer_service::encode(&view, &[]).unwrap();
    // Bind in the child: SO_PEERCRED must name this dropped principal, not the parent.
    let listener = signer_peer::listen(&root.join("signer")).unwrap();
    fs::write(root.join("signer-ready"), b"ready").unwrap();
    fixture_poll(listener.as_raw_fd(), FIXTURE_STARTUP_MS);
    let socket = signer_peer::accept(listener.as_raw_fd()).unwrap();
    loop {
        fixture_poll(socket.as_raw_fd(), FIXTURE_OPERATION_MS);
        let Ok(packet) =
            signer_peer::receive(socket.as_raw_fd(), wire::WRITER_SIGN_PACKET_MAX_BYTES)
        else {
            break;
        };
        if packet.bytes.is_empty() {
            break;
        }
        assert_eq!(packet.bytes, b"{\"op\":\"STATUS\"}");
        if signer_peer::send(socket.as_raw_fd(), &reply, &[]).is_err() {
            break;
        }
    }
}

#[test]
#[ignore = "private child driver invoked by the checkpoint parent"]
fn checkpoint_status_child() {
    use castle_wall_daemon::business_profile::signer_peer;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    assert!(std::env::args().any(|arg| arg == "--ignored"));
    let mut parent = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    parent
        .set_read_timeout(Some(std::time::Duration::from_millis(FIXTURE_STARTUP_MS)))
        .unwrap();
    let mut token = [0; 32];
    parent.read_exact(&mut token).unwrap();
    assert!(token.iter().any(|b| *b != 0));
    signer_peer::drop_capabilities().unwrap();
    parent.write_all(&token).unwrap();
    let root = std::env::var_os("K1_CHECKPOINT_SIGNER_CHILD").unwrap();
    checkpoint_signer_child(std::path::Path::new(&root));
}

#[test]
fn shared_run_refuses_every_checkpoint_opcode() {
    use castle_wall_daemon::business_profile::signer_peer;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::{
            fd::AsRawFd,
            unix::{
                fs::{MetadataExt, PermissionsExt},
                process::CommandExt,
            },
        },
        time::{Duration, Instant},
    };
    const SIGNER_CHILD: &str = "K1_CHECKPOINT_SIGNER_CHILD";
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for part in [false, true] {
        let bus = bus_fixture::Fixture::new();
        let root = bus.root.path();
        let image = root.join("writer");
        fs::copy(
            std::path::PathBuf::from(
                std::env::var_os("SANCTUARY_K1_TEST_BINARIES")
                    .expect("K1_NATIVE_BINARIES_REQUIRED"),
            )
            .join("debug/sanctuary-business-writer"),
            &image,
        )
        .unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let (f, _, report) = fixture();
        let mut view = f.view.lock().unwrap().clone();
        view.state = "LOCKED".into();
        let s_path = root.join("signer");
        fs::write(root.join("signer-view"), serde_json::to_vec(&view).unwrap()).unwrap();
        // Match linux_business_signer_client::capability_dropped_exe: root CI's
        // dropped child cannot exec through the runner's home. Both images and
        // every fixture path live under this test-owned temp root instead.
        let signer_image = root.join("signer-child");
        fs::copy("/proc/self/exe", &signer_image).unwrap();
        fs::set_permissions(&signer_image, fs::Permissions::from_mode(0o700)).unwrap();
        // Hash the large test image before starting the child's bounded accept wait.
        let signer_hash = hex::encode(Sha256::digest(fs::read(&signer_image).unwrap()));
        use std::io::{Read, Write};
        let (mut parent_handshake, child_handshake) =
            std::os::unix::net::UnixStream::pair().unwrap();
        parent_handshake
            .set_read_timeout(Some(Duration::from_millis(FIXTURE_STARTUP_MS)))
            .unwrap();
        let handshake_fd = child_handshake.as_raw_fd();
        let last_cap: i32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!((0..64).contains(&last_cap));
        let signer_stderr = root.join("signer-stderr");
        let mut signer_command = std::process::Command::new(&signer_image);
        signer_command
            .args([
                "--exact",
                "checkpoint::checkpoint_status_child",
                "--nocapture",
                "--ignored",
                "--test-threads=1",
            ])
            .env(SIGNER_CHILD, root)
            .current_dir(root)
            // CI counts libtest summaries, so only the parent may print one.
            .stdout(std::process::Stdio::null())
            .stderr(fs::File::create(&signer_stderr).unwrap());
        unsafe {
            signer_command.pre_exec(move || {
                // Match signer_peer's Linux v3 ABI; every pre-exec operation uses stack
                // storage and syscalls only. The child rechecks the resulting principal.
                #[repr(C)]
                struct CapHeader {
                    version: u32,
                    pid: i32,
                }
                #[repr(C)]
                #[derive(Clone, Copy)]
                struct CapData {
                    effective: u32,
                    permitted: u32,
                    inheritable: u32,
                }
                const CAPABILITY_VERSION_3: u32 = 0x20080522;
                for cap in 0..=last_cap {
                    let present = libc::prctl(libc::PR_CAPBSET_READ, cap);
                    if present < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if present == 1 && libc::prctl(libc::PR_CAPBSET_DROP, cap) != 0 {
                        let error = std::io::Error::last_os_error();
                        if uid == 0 || error.raw_os_error() != Some(libc::EPERM) {
                            return Err(error);
                        }
                    }
                }
                let header = CapHeader {
                    version: CAPABILITY_VERSION_3,
                    pid: 0,
                };
                let data = [CapData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                // Only allocation-free descriptor operations follow the capability drop.
                if libc::dup2(handshake_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut signer = Child(signer_command.spawn().unwrap());
        drop(child_handshake);
        let mut token = [0u8; 32];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut token)
            .unwrap();
        parent_handshake.write_all(&token).unwrap();
        let mut echoed = [0u8; 32];
        parent_handshake
            .read_exact(&mut echoed)
            .unwrap_or_else(|error| {
                panic!(
                    "child handshake: {error}; {}",
                    fs::read_to_string(&signer_stderr).unwrap()
                )
            });
        assert_eq!(echoed, token, "private child handshake");
        let end = Instant::now() + Duration::from_millis(FIXTURE_STARTUP_MS);
        while !root.join("signer-ready").exists() {
            assert!(
                signer.0.try_wait().unwrap().is_none(),
                "signer child exited: {}",
                fs::read_to_string(&signer_stderr).unwrap()
            );
            assert!(
                Instant::now() < end,
                "signer child readiness timeout: {}",
                fs::read_to_string(&signer_stderr).unwrap()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let listener_path = root.join("records");
        let listener = signer_peer::listen(&listener_path).unwrap();
        fs::set_permissions(&listener_path, fs::Permissions::from_mode(0o660)).unwrap();
        let notify_path = root.join("notify");
        let notify = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
        notify
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let config_path = bus.config_path();
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config["writer_sha256"] = json!(hex::encode(Sha256::digest(fs::read(&image).unwrap())));
        config["signer"] = json!({"uid":uid,"gid":gid,"executable_sha256":signer_hash,"cgroup":fs::read_to_string(format!("/proc/{}/cgroup", signer.0.id())).unwrap().trim()});
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let status = root.join("status");
        fs::write(&status,"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n").unwrap();
        let maps = root.join("maps");
        let m = fs::metadata(&image).unwrap();
        fs::write(
            &maps,
            format!(
                "1000-2000 r-xp 00000000 {:02x}:{:02x} {} {}\n",
                libc::major(m.dev()),
                libc::minor(m.dev()),
                m.ino(),
                image.display()
            ),
        )
        .unwrap();
        let seam = root.join("seam");
        fs::write(&seam,serde_json::to_vec(&json!({"config":config_path,"exec":image,"status":status,"maps":maps,"self_exe":"/proc/self/exe","boot_id":"/proc/sys/kernel/random/boot_id",
            "bus":{"socket":root.join("bus"),"socket_owner_uid":uid,"expected_manager_uid":uid,"expected_manager_pid":std::process::id(),"wall_unit":"fixture.service"},
            "listener":{"path":listener_path,"owner":uid,"group":gid,"peer_uid":uid},"artifact_owner":uid,"library_owner":uid,"signer_socket":s_path})).unwrap()).unwrap();
        fs::set_permissions(&seam, fs::Permissions::from_mode(0o600)).unwrap();
        let raw = listener.as_raw_fd();
        let writer_stderr = root.join("writer-stderr");
        let mut command = std::process::Command::new("/usr/bin/python3");
        command.env_clear().current_dir(root);
        command.args(["-c","import os,sys; os.environ['LISTEN_PID']=str(os.getpid()); os.execve(sys.argv[1],sys.argv[1:],os.environ)"]).arg(&image);
        command
            .args(["--test-writer", seam.to_str().unwrap()])
            .env("LISTEN_FDS", "1")
            .env("LISTEN_FDNAMES", "records")
            .env("NOTIFY_SOCKET", &notify_path)
            .stdout(std::process::Stdio::null())
            .stderr(fs::File::create(&writer_stderr).unwrap());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(raw, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = Child(command.spawn().unwrap());
        let mut text = [0; 1024];
        let n = notify.recv(&mut text).unwrap_or_else(|error| {
            panic!(
                "writer notification: {error}; {}",
                fs::read_to_string(&writer_stderr).unwrap()
            )
        });
        assert_eq!(
            &text[..n],
            b"READY=1\nSTATUS=writer closed",
            "test-writer reaches shared run before the opcode"
        );
        let socket = signer_peer::connect(&listener_path).unwrap();
        let hello = wire_receive(socket.as_raw_fd());
        let n = u32::from_be_bytes(hello[..4].try_into().unwrap()) as usize;
        let h: Value = serde_json::from_slice(&hello[4..4 + n]).unwrap();
        let session = h["session_id"].as_str().unwrap();
        signer_peer::send(
            socket.as_raw_fd(),
            &wire::encode(Direction::ToWriter, session, &Operation::HelloAck, &[]).unwrap(),
            &[],
        )
        .unwrap();
        let raw_report = bytes(&report);
        let op = if part {
            Operation::CheckpointPart(cp::Part {
                request_id: REQUEST.into(),
                nonce: report["nonce"].as_str().unwrap().into(),
                part_index: 0,
                part_count: 1,
                total_length: raw_report.len(),
                checkpoint_digest: cp::digest(&raw_report),
            })
        } else {
            Operation::CheckpointQuery {
                request_id: REQUEST.into(),
            }
        };
        signer_peer::send(
            socket.as_raw_fd(),
            &wire::encode(
                Direction::ToWriter,
                session,
                &op,
                if part { &raw_report } else { &[] },
            )
            .unwrap(),
            &[],
        )
        .unwrap();
        fixture_poll(socket.as_raw_fd(), FIXTURE_OPERATION_MS);
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    &mut byte as *mut _ as _,
                    1,
                    libc::MSG_DONTWAIT,
                )
            },
            0,
            "Refuse emits no checkpoint frame"
        );
        let n = notify.recv(&mut text).unwrap_or_else(|error| {
            panic!(
                "writer notification: {error}; {}",
                fs::read_to_string(&writer_stderr).unwrap()
            )
        });
        assert_eq!(
            &text[..n],
            service::STOP_STATUS.as_bytes(),
            "shared run chooses terminal Refuse for every checkpoint opcode"
        );
        assert!(!child.0.wait().unwrap().success());
        assert!(
            signer.0.wait().unwrap().success(),
            "signer STATUS loop: {}",
            fs::read_to_string(&signer_stderr).unwrap()
        );
    }
}

#[test]
fn adjudication_guards_exclude_competing_refusals() {
    for guard in ["state", "admission", "bind", "observe", "silence"] {
        let (f, mut m, mut v) = fixture();
        let parts = query(&f, &mut m, &mut v, REQUEST);
        prepare(&mut m, &parts);
        assert!(
            support::silence_disarmed(&m),
            "awaiting reread disarms the silence timer"
        );
        let result = match guard {
            "state" => {
                support::ordinary_reconciliation(&mut m);
                support::checkpoint_reread(&mut m)
            }
            "admission" => {
                let received = support::last_status(&m) + 1;
                support::adjudicate(&mut m, received)
            }
            "bind" => {
                support::scripted_signer(&mut m).bind = Box::new(|_| {
                    Err(castle_wall_daemon::business_profile::signer_client::Refusal::Grant)
                });
                support::checkpoint_reread(&mut m)
            }
            "observe" => {
                f.view.lock().unwrap().state = "UNKNOWN".into();
                support::checkpoint_reread(&mut m)
            }
            "silence" => {
                let before = f.now.load(Ordering::SeqCst);
                // Two elapsed ticks followed by the near-deadline reread cross the old part timer.
                f.now.fetch_add(20 * state::NS_PER_MS, Ordering::SeqCst);
                f.status_delay
                    .store(985 * state::NS_PER_MS, Ordering::SeqCst);
                let result = support::checkpoint_reread(&mut m);
                assert!(
                    f.now.load(Ordering::SeqCst) - before
                        > cp::CHECKPOINT_PART_SILENCE_MS * state::NS_PER_MS
                );
                assert!(
                    f.now.load(Ordering::SeqCst) - before
                        < cp::CHECKPOINT_CHALLENGE_MS * state::NS_PER_MS
                );
                assert_eq!(
                    f.binds.load(Ordering::SeqCst),
                    0,
                    "slow reread preempts before any age adjudication"
                );
                result
            }
            _ => unreachable!(),
        };
        assert!(!matches!(result, Ok(Some(_))), "{guard} cannot ACK");
        assert!(
            !support::checkpoint_owned(&m),
            "{guard} clears all checkpoint ownership"
        );
        if guard == "state" {
            assert_eq!(
                f.binds.load(Ordering::SeqCst),
                1,
                "only the ordinary reconciled transition bound"
            );
        }
    }
}
#[test]
fn partial_transfer_expiry_frees_the_buffer_at_the_earlier_deadline() {
    for challenge_first in [false, true] {
        let (f, mut m, mut v) = fixture();
        bounded_ordinary_report(&f, &mut v);
        m.heartbeat().unwrap();
        let parts = query(&f, &mut m, &mut v, REQUEST);
        if challenge_first {
            f.now.fetch_add(
                (cp::CHECKPOINT_CHALLENGE_MS - cp::CHECKPOINT_PART_SILENCE_MS / 2)
                    * state::NS_PER_MS,
                Ordering::SeqCst,
            );
        }
        support::checkpoint_packet(&mut m, SESSION, &parts[0]).unwrap();
        assert!(support::checkpoint_owned(&m));
        let delta = if challenge_first {
            cp::CHECKPOINT_PART_SILENCE_MS / 2
        } else {
            cp::CHECKPOINT_PART_SILENCE_MS
        };
        f.now.fetch_add(delta * state::NS_PER_MS, Ordering::SeqCst);
        support::checkpoint_step(&mut m).unwrap();
        assert!(
            !support::checkpoint_owned(&m),
            "earlier transfer deadline frees the buffer"
        );
    }
}

#[test]
fn four_maximal_wall_packets_do_not_occupy_the_signer_socket() {
    use castle_wall_daemon::business_profile::signer_peer;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }
    let (wall, queued) = pair();
    let packet = vec![0; cp::CHECKPOINT_PART_PACKET_MAX_BYTES];
    for _ in 0..cp::CHECKPOINT_PARTS_MAX {
        signer_peer::send(wall.as_raw_fd(), &packet, &[]).unwrap();
    }
    let (signer, receive) = pair();
    signer_peer::passcred(receive.as_raw_fd()).unwrap();
    let (f, mut m, _) = fixture();
    let port = support::scripted_signer(&mut m);
    let mut original = std::mem::replace(&mut port.status, Box::new(|| panic!("replaced port")));
    port.status = Box::new(move || {
        signer_peer::send(signer.as_raw_fd(), b"{\"op\":\"STATUS\"}", &[]).unwrap();
        original()
    });
    f.now.fetch_add(
        wire::WRITER_HEARTBEAT_MS * state::NS_PER_MS,
        Ordering::SeqCst,
    );
    m.heartbeat().unwrap();
    assert_eq!(
        signer_peer::receive(receive.as_raw_fd(), wire::WRITER_SIGN_PACKET_MAX_BYTES)
            .unwrap()
            .bytes,
        b"{\"op\":\"STATUS\"}"
    );
    for _ in 0..cp::CHECKPOINT_PARTS_MAX {
        let mut bytes = vec![0; packet.len()];
        assert_eq!(
            unsafe {
                libc::recv(
                    queued.as_raw_fd(),
                    bytes.as_mut_ptr() as _,
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            },
            packet.len() as isize
        );
    }
}

#[test]
fn cancellation_covers_each_owned_checkpoint_stage() {
    for stage in 0..4 {
        let (f, mut m, mut v) = fixture();
        bounded_ordinary_report(&f, &mut v);
        m.heartbeat().unwrap();
        let parts = query(&f, &mut m, &mut v, REQUEST);
        if stage == 1 {
            support::checkpoint_packet(&mut m, SESSION, &parts[0]).unwrap();
        }
        if stage == 2 {
            for p in &parts {
                support::checkpoint_packet(&mut m, SESSION, p).unwrap();
            }
        }
        if stage == 3 {
            prepare(&mut m, &parts);
        }
        assert!(support::checkpoint_owned(&m));
        m.settle();
        assert!(
            !support::checkpoint_owned(&m),
            "cancel clears every owned field at stage {stage}"
        );
    }
}
#[test]
fn slow_reread_burns_observation_freshness_without_preemption() {
    for delay in [100, 200] {
        let (f, mut m, mut v) = fixture();
        let parts = query(&f, &mut m, &mut v, REQUEST);
        prepare(&mut m, &parts);
        assert!(support::silence_disarmed(&m));
        f.now.fetch_add(850 * state::NS_PER_MS, Ordering::SeqCst);
        f.status_delay
            .store(delay * state::NS_PER_MS, Ordering::SeqCst);
        assert_eq!(
            support::checkpoint_reread(&mut m).unwrap().is_some(),
            delay == 100,
            "slow reread uses the original observation date"
        );
        assert_eq!(f.binds.load(Ordering::SeqCst), usize::from(delay == 100));
    }
}
#[test]
fn payload_echo_and_issue_time_are_checked_independently() {
    let (f, mut m, mut v) = fixture();
    query(&f, &mut m, &mut v, REQUEST);
    let nonce = v["nonce"].as_str().unwrap().to_owned();
    assert!(cp::Candidate::parse(&bytes(&v))
        .unwrap()
        .echo(SESSION, REQUEST, &nonce)
        .is_ok());
    for field in ["session_id", "request_id", "nonce"] {
        let mut altered = v.clone();
        altered[field] = json!("f".repeat(32));
        assert!(
            cp::Candidate::parse(&bytes(&altered))
                .unwrap()
                .echo(SESSION, REQUEST, &nonce)
                .is_err(),
            "payload {field} must echo the owned challenge"
        );
    }
    let now = f.now.load(Ordering::SeqCst);
    assert!(
        cp::Candidate::parse(&bytes(&v))
            .unwrap()
            .fresh(now + 1, now + 1)
            .is_err(),
        "observation cannot predate issue"
    );
}

#[test]
fn gaps_and_sorted_completion_cannot_replace_receive_order() {
    let raw = vec![b'a'; 2 * anchor::MAX_BYTES + 1];
    let first = cp::Part {
        request_id: REQUEST.into(),
        nonce: SESSION.into(),
        part_index: 0,
        part_count: 3,
        total_length: raw.len(),
        checkpoint_digest: cp::digest(&raw),
    };
    let result = (|| {
        let mut transfer = cp::Transfer::begin(&first, 0)?;
        for i in [0, 2, 1] {
            let mut part = first.clone();
            part.part_index = i;
            let start = i * anchor::MAX_BYTES;
            let end = (start + anchor::MAX_BYTES).min(raw.len());
            transfer.push(&part, &raw[start..end], b"part", 0)?;
        }
        transfer.finish()
    })();
    assert!(
        result.is_err(),
        "complete bytes cannot repair a gap or reordered arrival"
    );
}
#[test]
fn the_last_part_cannot_replace_the_first_digest() {
    let raw = vec![b'a'; anchor::MAX_BYTES + 1];
    let first = cp::Part {
        request_id: REQUEST.into(),
        nonce: SESSION.into(),
        part_index: 0,
        part_count: 2,
        total_length: raw.len(),
        checkpoint_digest: format!("sha256:{}", "0".repeat(64)),
    };
    let result = (|| {
        let mut transfer = cp::Transfer::begin(&first, 0)?;
        transfer.push(&first, &raw[..anchor::MAX_BYTES], b"first", 0)?;
        let mut last = first.clone();
        last.part_index = 1;
        last.checkpoint_digest = cp::digest(&raw);
        transfer.push(&last, &raw[anchor::MAX_BYTES..], b"last", 0)?;
        transfer.finish()
    })();
    assert!(
        result.is_err(),
        "the digest fixed by part zero cannot be replaced"
    );
}

#[test]
fn integrated_stage_phases_keep_status_receives_bounded() {
    use castle_wall_daemon::business_profile::signer_peer;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    const TICK: u64 = 10 * state::NS_PER_MS;
    for (phase_ms, d_delay_ms, wal_delay_ms, validation_ms, s_delay_ms) in [
        (0, 0, 0, 0, 0),
        (239, 990, 40, 4, 100),
        (240, 990, 50, 9, 200),
    ] {
        let (f, mut m, mut report) = fixture();
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let send = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let receive = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        signer_peer::passcred(receive.as_raw_fd()).unwrap();
        let clock = f.now.clone();
        let port = support::scripted_signer(&mut m);
        let mut status =
            std::mem::replace(&mut port.status, Box::new(|| panic!("replaced status")));
        port.status = Box::new(move || {
            signer_peer::send(
                send.as_raw_fd(),
                &clock.load(Ordering::SeqCst).to_be_bytes(),
                &[],
            )
            .unwrap();
            status()
        });
        let mut arrivals = vec![f.now.load(Ordering::SeqCst)];
        let mut heartbeat = |m: &mut Machine| {
            m.heartbeat().unwrap();
            let p = signer_peer::receive(receive.as_raw_fd(), 8).unwrap();
            arrivals.push(u64::from_be_bytes(p.bytes.try_into().unwrap()));
        };
        let _ = query(&f, &mut m, &mut report, REQUEST);
        // These are independently delayed W observations. P continues servicing S while W waits.
        for delay in [d_delay_ms, wal_delay_ms] {
            let end = f.now.load(Ordering::SeqCst) + delay * state::NS_PER_MS;
            while f.now.load(Ordering::SeqCst) < end {
                f.now.fetch_add(
                    TICK.min(end - f.now.load(Ordering::SeqCst)),
                    Ordering::SeqCst,
                );
                if m.heartbeat_due().unwrap() {
                    heartbeat(&mut m);
                }
            }
            report["observed_boottime_ns"] =
                json!((f.now.load(Ordering::SeqCst) - wal_delay_ms * state::NS_PER_MS).to_string());
        }
        heartbeat(&mut m);
        f.now
            .fetch_add(phase_ms * state::NS_PER_MS, Ordering::SeqCst);
        for packet in packets(&report) {
            support::checkpoint_packet(&mut m, SESSION, &packet).unwrap();
        }
        if phase_ms >= 240 {
            for _ in 0..3 {
                support::checkpoint_step(&mut m).unwrap();
            }
            assert!(
                !support::has_candidate(&m),
                "a stage one tick before heartbeat must yield"
            );
            f.now.fetch_add(TICK, Ordering::SeqCst);
            heartbeat(&mut m);
        }
        for _ in 0..3 {
            let started = std::time::Instant::now();
            support::checkpoint_step(&mut m).unwrap();
            let measured = started.elapsed();
            f.now
                .fetch_add(validation_ms * state::NS_PER_MS + TICK, Ordering::SeqCst);
            if m.heartbeat_due().unwrap() {
                heartbeat(&mut m);
            }
            eprintln!("stage phase={phase_ms} elapsed_ns={}", measured.as_nanos());
        }
        // A deferred stage resumes after the ordinary due check, never in a same-pass chain.
        for _ in 0..3 {
            if support::awaiting(&m).is_none() {
                support::checkpoint_step(&mut m).unwrap();
            }
        }
        assert!(support::awaiting(&m).is_some());
        heartbeat(&mut m);
        f.now
            .fetch_add(s_delay_ms * state::NS_PER_MS, Ordering::SeqCst);
        let received = support::awaiting(&m).unwrap();
        assert!(support::adjudicate(&mut m, received).unwrap().is_some());
        let maximum = arrivals.windows(2).map(|p| p[1] - p[0]).max().unwrap();
        assert!(
            maximum < signer_contract::SIGNER_IDLE_DEADLINE_MS as u64 * state::NS_PER_MS,
            "actual STATUS receive gap remains below idle deadline"
        );
        eprintln!("phase={phase_ms} D={d_delay_ms} WAL={wal_delay_ms} validation={validation_ms} S={s_delay_ms} max_receive_gap_ns={maximum} heartbeat_lateness_ns={}",maximum.saturating_sub(wire::WRITER_HEARTBEAT_MS*state::NS_PER_MS));
    }
}

#[test]
fn ack_delivery_failure_is_terminal_after_grant_and_cancels() {
    accepting_serve_fixture(false, false, false, true, false);
}

#[test]
fn frozen_tick_expiry_while_awaiting_cancels_through_serve() {
    accepting_serve_fixture(false, false, false, false, true);
}

fn advancing_serve_schedule(last_tick: bool, slow_reread: bool, hold_ms: u64) {
    use castle_wall_daemon::business_profile::{
        signer_peer,
        signer_watchdog::WATCHDOG_TICK_MS,
        writer_peer::{HeldConfig, ListenerExpectations},
    };
    use std::{
        os::{fd::AsRawFd, unix::fs::PermissionsExt},
        time::Duration,
    };
    const TICK_MS: u64 = WATCHDOG_TICK_MS as u64;
    const _: () = assert!(TICK_MS < wire::WRITER_HEARTBEAT_MS);
    let (f, mut machine, mut report) = fixture();
    if last_tick {
        bounded_ordinary_report(&f, &mut report);
        machine.heartbeat().unwrap();
    }
    let mut bus = bus_fixture::Fixture::new();
    bus.config.fortress_id = "a".repeat(32);
    let config = HeldConfig::isolated(&bus.config_path(), unsafe { libc::geteuid() }).unwrap();
    let path = bus.root.path().join("records");
    let listener = signer_peer::listen(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let expect = ListenerExpectations::isolated(path.clone(), unsafe { libc::geteuid() }, unsafe {
        libc::getegid()
    });
    let clock = f.clock();
    // Every phase advances the same clock used by the machine, bus deadlines and S fixture.
    let pause = || std::thread::sleep(Duration::from_millis(state::BUS_SCHEDULING_SLACK_MS));
    let last_tick_start = || {
        let last = *f.status_times.lock().unwrap().last().unwrap();
        f.now.store(
            last + (wire::WRITER_HEARTBEAT_MS - TICK_MS) * state::NS_PER_MS,
            Ordering::SeqCst,
        );
    };
    let next_tick = || {
        pause();
        f.now
            .fetch_add(TICK_MS * state::NS_PER_MS, Ordering::SeqCst);
        pause();
    };
    std::thread::scope(|scope| {
        let target = &bus.target;
        let runner = scope.spawn(move || {
            let result = support::serve_accept(
                &mut machine,
                &config,
                target,
                &listener,
                &expect,
                unsafe { libc::geteuid() },
                &clock,
            );
            assert!(result.is_err());
            assert!(
                !support::checkpoint_owned(&machine),
                "completed heartbeat closure disposes every checkpoint owner"
            );
            result
        });
        let socket = signer_peer::connect(&path).unwrap();
        let hello = wire_receive(socket.as_raw_fd());
        let n = u32::from_be_bytes(hello[..4].try_into().unwrap()) as usize;
        let h: Value = serde_json::from_slice(&hello[4..4 + n]).unwrap();
        let session = h["session_id"].as_str().unwrap();
        let send = |op: &Operation, body: &[u8]| {
            signer_peer::send(
                socket.as_raw_fd(),
                &wire::encode(Direction::ToWriter, session, op, body).unwrap(),
                &[],
            )
            .unwrap()
        };
        send(&Operation::HelloAck, &[]);
        pause();
        if last_tick {
            last_tick_start();
        }
        f.status_delay
            .store(hold_ms * state::NS_PER_MS, Ordering::SeqCst);
        send(
            &Operation::CheckpointQuery {
                request_id: REQUEST.into(),
            },
            &[],
        );
        if last_tick {
            next_tick();
        }
        // A STATUS response provides an observable continuing-session control even if QUERY was lost.
        send(
            &Operation::Status {
                request_id: "c".repeat(32),
            },
            &[],
        );
        if hold_ms > 0 {
            pause();
            let mut readiness = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let available = unsafe { libc::poll(&mut readiness, 1, 0) };
            let second = signer_peer::connect(&path);
            let outcome = runner.join().unwrap();
            assert!(
                hold_ms == 980 || second.is_ok(),
                "heartbeat pass cannot retain the wall session: {outcome:?}"
            );
            assert_eq!(
                available, 1,
                "held query and STATUS progress after the completed heartbeat"
            );
            if hold_ms == 980 {
                assert!(
                    matches!(
                        outcome,
                        Err(
                            castle_wall_daemon::business_profile::writer_service::Error::Peer(
                                castle_wall_daemon::business_profile::writer_peer::Error::Deadline
                            )
                        )
                    ),
                    "expired STATUS admission closes with a typed deadline: {outcome:?}"
                );
                let bytes = wire_receive(socket.as_raw_fd());
                let response = wire::decode(&bytes, Direction::ToWall, session).unwrap();
                assert!(
                    matches!(response.operation, Operation::CheckpointChallenge { .. }),
                    "held query is processed after the completed heartbeat"
                );
                let mut tail = [0u8; 1];
                assert_eq!(
                    unsafe {
                        libc::recv(
                            socket.as_raw_fd(),
                            tail.as_mut_ptr().cast(),
                            tail.len(),
                            libc::MSG_DONTWAIT,
                        )
                    },
                    0,
                    "deadline closure sends no ACK or further response"
                );
                assert_eq!(
                    f.binds.load(Ordering::SeqCst),
                    0,
                    "deadline closure grants no authority or effect"
                );
                return;
            }
            for challenge in [true, false] {
                let bytes = wire_receive(socket.as_raw_fd());
                let response = wire::decode(&bytes, Direction::ToWall, session).unwrap();
                assert_eq!(
                    matches!(response.operation, Operation::CheckpointChallenge { .. }),
                    challenge,
                    "held query precedes STATUS response"
                );
            }
            assert_eq!(f.binds.load(Ordering::SeqCst), 0);
            return;
        }
        let response = wire_receive(socket.as_raw_fd());
        let response = wire::decode(&response, Direction::ToWall, session).unwrap();
        assert!(
            matches!(response.operation, Operation::CheckpointChallenge { .. }),
            "last-tick query is deferred intact through the heartbeat"
        );
        let Operation::CheckpointChallenge { nonce, .. } = response.operation else {
            unreachable!()
        };
        let status = wire_receive(socket.as_raw_fd());
        assert!(matches!(
            wire::decode(&status, Direction::ToWall, session)
                .unwrap()
                .operation,
            Operation::StatusReply { .. }
        ));
        report["session_id"] = json!(session);
        report["request_id"] = json!(REQUEST);
        report["nonce"] = json!(nonce);
        report["status_digest"] = json!(cp::digest(response.payload));
        report["observed_boottime_ns"] = json!(f.now.load(Ordering::SeqCst).to_string());
        let raw = bytes(&report);
        for (index, part) in raw.chunks(anchor::MAX_BYTES).enumerate() {
            if last_tick {
                last_tick_start();
            }
            if slow_reread {
                // The 1000 ms reply ceiling minus 15 ms is already beyond WRITER_HEARTBEAT_MS.
                f.status_delay
                    .store(985 * state::NS_PER_MS, Ordering::SeqCst);
            }
            send(
                &Operation::CheckpointPart(cp::Part {
                    request_id: REQUEST.into(),
                    nonce: report["nonce"].as_str().unwrap().into(),
                    part_index: index,
                    part_count: raw.len().div_ceil(anchor::MAX_BYTES),
                    total_length: raw.len(),
                    checkpoint_digest: cp::digest(&raw),
                }),
                part,
            );
            if last_tick {
                next_tick();
            }
        }
        pause();
        f.status_delay.store(0, Ordering::SeqCst);
        if slow_reread {
            assert_eq!(
                f.binds.load(Ordering::SeqCst),
                0,
                "serve-site preemption performs no adjudication after a 985 ms reread"
            );
        }
        send(
            &Operation::Status {
                request_id: "d".repeat(32),
            },
            &[],
        );
        let reply = wire_receive(socket.as_raw_fd());
        let reply = wire::decode(&reply, Direction::ToWall, session).unwrap();
        if slow_reread {
            assert!(matches!(reply.operation, Operation::StatusReply { .. }));
        } else {
            assert!(
                matches!(reply.operation, Operation::CheckpointAck { .. }),
                "all last-tick parts complete without timing cancellation"
            );
            assert_eq!(f.binds.load(Ordering::SeqCst), 1);
            let status = wire_receive(socket.as_raw_fd());
            assert!(matches!(
                wire::decode(&status, Direction::ToWall, session)
                    .unwrap()
                    .operation,
                Operation::StatusReply { .. }
            ));
        }
        drop(socket);
        let _ = runner.join().unwrap();
    });
}
#[test]
fn advancing_serve_defers_query_and_each_part_at_the_last_tick() {
    advancing_serve_schedule(true, false, 0);
}
#[test]
fn advancing_serve_preempts_adjudication_at_the_real_call_site() {
    advancing_serve_schedule(false, true, 0);
}

#[test]
fn checkpoint_bind_failure_is_immediately_terminal() {
    let (f, mut m, mut v) = fixture();
    let parts = query(&f, &mut m, &mut v, REQUEST);
    prepare(&mut m, &parts);
    support::scripted_signer(&mut m).bind =
        Box::new(|_| Err(castle_wall_daemon::business_profile::signer_client::Refusal::Grant));
    assert!(
        support::checkpoint_reread(&mut m).is_err(),
        "checkpoint bind failure is terminal at adjudication"
    );
    assert_eq!(m.state(), WriterState::Settling);
    assert!(!support::checkpoint_owned(&m));
}

#[test]
fn real_null_status_refuses_genesis_and_settled_with_populated_controls() {
    use castle_wall_daemon::business_profile::signer_client::StatusReply;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::process::Command::new(root.join("../server/node_modules/.bin/tsx"))
        .arg(root.join("tests/helpers/checkpoint-status.ts"))
        .current_dir(root.join("../server"))
        .env("VITEST", "true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "real S fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let real: StatusReply = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(real.state, "UNLOCKED");
    for settled in [false, true] {
        for populated in [false, true] {
            let f = state::Fixture::new();
            let mut report =
                append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"].clone();
            let g = serde_json::to_value(&real.grant).unwrap();
            for key in [
                "role",
                "epoch",
                "kid",
                "public_key",
                "identity_id",
                "machine_id",
            ] {
                report["wal_checkpoint"]["join_state"]["pin"][key] = g[key].clone();
            }
            for key in ["activation_id", "lease_id", "generation"] {
                report["wal_checkpoint"]["join_state"]["grant"][key] = g[key].clone();
            }
            for key in ["role", "machine_id", "activation_id"] {
                report["d_observation"]["anchor"][key] = g[key].clone();
            }
            report["d_observation"]["anchor"]["generation_high_water"] = g["generation"].clone();
            report["d_observation"]["anchor"]["boot_id"] = json!(real.boot_id);
            let join = &mut report["wal_checkpoint"]["join_state"];
            join["grant"]["boot_id"] = json!(real.boot_id);
            join["grant"]["expires_ns"] = json!(real.expires_boottime_ns);
            join["anchor"]["lease_id"] = g["lease_id"].clone();
            join["anchor"]["generation"] = g["generation"].clone();
            if settled {
                let commitment = format!("sha256:{}", "b".repeat(64));
                for key in [
                    "reserved_sequence",
                    "committed_sequence",
                    "drained_sequence",
                ] {
                    report["d_observation"]["anchor"][key] = json!(1);
                }
                for key in ["committed_sequence", "drained_sequence"] {
                    report["wal_checkpoint"][key] = json!(1);
                }
                for key in ["committed_digest", "drained_digest"] {
                    report["d_observation"]["anchor"][key] = json!(commitment);
                    report["wal_checkpoint"][key] = json!(commitment);
                }
                report["wal_checkpoint"]["join_state"]["anchor"]["sequence"] = json!(1);
                report["wal_checkpoint"]["join_state"]["anchor"]["commitment"] = json!(commitment);
            }
            let digest = anchor::anchor_digest(&report["d_observation"]["anchor"]).unwrap();
            report["d_observation"]["anchor_digest"] = json!(digest);
            let mut status = real.clone();
            if populated {
                status.anchor_revision = Some(1);
                status.anchor_digest = Some(digest);
            }
            let now = real.started_boottime_ns.parse::<u64>().unwrap();
            f.now.store(now, Ordering::SeqCst);
            *f.view.lock().unwrap() = status.clone();
            f.view.lock().unwrap().state = "LOCKED".into();
            let mut machine = WriterMachine::isolated(
                f.signer(),
                DrainReconciler::production(cp::OrdinaryCheckpointProvider::production()),
                real.boot_id.clone(),
                f.clock(),
            )
            .unwrap();
            support::checkpoint_identity(&mut machine, "a".repeat(32), 1);
            *f.view.lock().unwrap() = status;
            machine.heartbeat().unwrap();
            accepting_serve_case(
                false,
                false,
                false,
                false,
                false,
                Some((f, machine, report, populated)),
            );
        }
    }
}

#[test]
fn measured_heartbeat_hold_exempts_silence_but_never_age_or_lifetime() {
    for elapsed_ms in [
        cp::CHECKPOINT_AGE_MS,
        cp::CHECKPOINT_AGE_MS + 1,
        cp::CHECKPOINT_CHALLENGE_MS,
    ] {
        let (f, mut machine, mut report) = fixture();
        bounded_ordinary_report(&f, &mut report);
        machine.heartbeat().unwrap();
        let parts = query(&f, &mut machine, &mut report, REQUEST);
        assert!(parts.len() > 1);
        support::checkpoint_packet(&mut machine, SESSION, &parts[0]).unwrap();
        const HOLD_MS: u64 = 980;
        f.now.store(
            state::NOW + (elapsed_ms - HOLD_MS) * state::NS_PER_MS,
            Ordering::SeqCst,
        );
        f.status_delay
            .store(HOLD_MS * state::NS_PER_MS, Ordering::SeqCst);
        support::checkpoint_heartbeat(&mut machine).unwrap();
        f.status_delay.store(0, Ordering::SeqCst);
        // One completed heartbeat allows the held transfer to make progress on this pass.
        support::checkpoint_step_after_heartbeat(&mut machine).unwrap();
        for part in &parts[1..] {
            support::checkpoint_packet(&mut machine, SESSION, part).unwrap();
        }
        machine.heartbeat().unwrap();
        for _ in 0..3 {
            support::checkpoint_step(&mut machine).unwrap();
        }
        let granted = if support::awaiting(&machine).is_some() {
            support::checkpoint_reread(&mut machine).unwrap().is_some()
        } else {
            false
        };
        assert_eq!(
            granted,
            elapsed_ms == cp::CHECKPOINT_AGE_MS,
            "only measured heartbeat silence is exempt; original age and challenge govern"
        );
        assert_eq!(f.binds.load(Ordering::SeqCst), usize::from(granted));
    }
}

#[test]
fn ordinary_checkpoint_refusal_matrix_reaches_the_real_serve_consumer() {
    for case in [
        "absent",
        "reservation",
        "intent",
        "recovery",
        "retired",
        "uncertain",
        "wal-ahead",
        "d-ahead",
        "missing-head",
        "gap",
        "pin",
        "lease",
        "fortress",
        "revision",
        "superseded",
    ] {
        let (f, mut m, mut report) = fixture();
        let commitment = format!("sha256:{}", "b".repeat(64));
        if matches!(case, "wal-ahead" | "missing-head" | "gap") {
            let count = if case == "gap" { 2 } else { 1 };
            report["wal_checkpoint"]["committed_sequence"] = json!(count);
            report["wal_checkpoint"]["committed_digest"] = json!(commitment);
            report["wal_checkpoint"]["join_state"]["anchor"]["sequence"] = json!(count);
            report["wal_checkpoint"]["join_state"]["anchor"]["commitment"] = json!(commitment);
            if case != "missing-head" {
                report["wal_checkpoint"]["retained_originals"] = json!((1..=count).map(|sequence| json!({"sequence":sequence + i32::from(case == "gap"), "commitment":commitment})).collect::<Vec<_>>());
            }
        }
        if matches!(case, "d-ahead" | "missing-head" | "gap") {
            let count = if case == "gap" { 2 } else { 1 };
            report["d_observation"]["anchor"]["reserved_sequence"] = json!(count);
            report["d_observation"]["anchor"]["committed_sequence"] = json!(count);
            report["d_observation"]["anchor"]["committed_digest"] = json!(commitment);
        }
        match case {
            "absent" => {
                report["d_observation"]["state"] = json!("ABSENT");
                report["d_observation"]["anchor"] = Value::Null;
            }
            "reservation" => {
                report["d_observation"]["anchor"]["reserved_sequence"] = json!(1);
                report["d_observation"]["anchor"]["reserved_body_digest"] = json!(commitment);
            }
            "intent" => report["wal_checkpoint"]["unresolved_intent"] = json!(true),
            "recovery" => {
                report["d_observation"]["anchor"]["recovery_required"] = json!(true);
                report["d_observation"]["anchor"]["recovery_reason"] = json!("restart");
                report["d_observation"]["anchor"]["recovery_revision"] = json!(1);
                report["d_observation"]["latched"] = json!(true);
            }
            "retired" => report["d_observation"]["anchor"]["retired"] = json!(true),
            "uncertain" => report["d_observation"]["uncertain"] = json!(true),
            "pin" => {
                report["wal_checkpoint"]["join_state"]["pin"]["machine_id"] = json!("e".repeat(32))
            }
            "lease" => {
                report["wal_checkpoint"]["join_state"]["grant"]["lease_id"] = json!("e".repeat(32));
                report["wal_checkpoint"]["join_state"]["anchor"]["lease_id"] =
                    json!("e".repeat(32));
            }
            "fortress" => report["fortress_id"] = json!("e".repeat(32)),
            "revision" => report["enrollment_revision"] = json!(2),
            "superseded" => report["d_observation"]["anchor"]["generation_high_water"] = json!(1),
            _ => (),
        }
        let digest = anchor::anchor_digest(&report["d_observation"]["anchor"]);
        report["d_observation"]["anchor_digest"] = json!(digest);
        if let Some(digest) = digest {
            f.view.lock().unwrap().anchor_digest = Some(digest);
        }
        m.heartbeat().unwrap();
        // Every negative reaches the ordinary predicate with a structurally valid report.
        assert!(
            cp::Candidate::parse(&bytes(&report)).is_ok(),
            "ordinary negative has valid shape: {case}"
        );
        accepting_serve_case(
            false,
            false,
            false,
            false,
            false,
            Some((f, m, report, false)),
        );
    }
}

#[test]
fn held_query_replays_after_a_240ms_heartbeat_and_status_continues() {
    // Independent sessions keep each report within its original challenge lifetime.
    for _ in 0..3 {
        advancing_serve_schedule(true, false, 240);
    }
}

#[test]
fn heartbeat_hold_never_renews_an_issued_challenge_for_a_fresh_report() {
    let (f, mut machine, mut report) = fixture();
    bounded_ordinary_report(&f, &mut report);
    machine.heartbeat().unwrap();
    query(&f, &mut machine, &mut report, REQUEST);
    const HOLD_MS: u64 = 980;
    let observed = state::NOW + (cp::CHECKPOINT_CHALLENGE_MS - HOLD_MS) * state::NS_PER_MS;
    f.now.store(observed, Ordering::SeqCst);
    machine.heartbeat().unwrap();
    report["observed_boottime_ns"] = json!(observed.to_string());
    let parts = packets(&report);
    support::checkpoint_packet(&mut machine, SESSION, &parts[0]).unwrap();
    f.status_delay
        .store(HOLD_MS * state::NS_PER_MS, Ordering::SeqCst);
    support::checkpoint_heartbeat(&mut machine).unwrap();
    f.status_delay.store(0, Ordering::SeqCst);
    support::checkpoint_step_after_heartbeat(&mut machine).unwrap();
    for part in &parts[1..] {
        support::checkpoint_packet(&mut machine, SESSION, part).unwrap();
    }
    machine.heartbeat().unwrap();
    for _ in 0..3 {
        support::checkpoint_step(&mut machine).unwrap();
    }
    let ack = if support::awaiting(&machine).is_some() {
        support::checkpoint_reread(&mut machine).unwrap()
    } else {
        None
    };
    assert!(
        ack.is_none(),
        "original challenge deadline refuses a fresh report after heartbeat hold"
    );
    assert_eq!(f.binds.load(Ordering::SeqCst), 0);
}

#[test]
fn held_query_after_980ms_heartbeat_closes_and_disposes_ownership() {
    const SLOW_HEARTBEAT_MS: u64 = 980;
    const PASSES: usize = 3;
    for _ in 0..PASSES {
        advancing_serve_schedule(true, false, SLOW_HEARTBEAT_MS);
    }
}
