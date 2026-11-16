// fail-before-exempt: reachable release-order pair witnesses read native WAL rows, cursor checkpoints and authenticated fixture facts.
// fail-before-exempt: isolated disk publication and release witnesses consume native authenticated clients and shared signed vectors.
// W-WAL-STORE
// W-TS-SCHEMA
use super::append_clients::{authenticated_original, authenticated_read};
use castle_wall_daemon::business_profile::{
    append_clients::FrozenMutation, append_contract, business_wal::*, drain_protocol as d,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
const NOW: u64 = 1_000_000; // The correlated client fixture's observation clock.
const DEADLINE: u64 = 1_000_000_000;
const EXPIRY: u64 = 1_000_000_000_000;
fn canonical(v: &Value) -> Vec<u8> {
    castle_wall_daemon::smb::jcs::encode(v)
        .unwrap()
        .into_bytes()
}
fn digest(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}
#[derive(Clone, Default)]
struct Faults {
    fail: Arc<Mutex<Option<(WalStep, usize)>>>,
    corrupt: Arc<Mutex<Option<std::path::PathBuf>>>,
    events: Arc<Mutex<Vec<WalStep>>>,
}
impl WalHooks for Faults {
    fn before(&mut self, step: WalStep) -> Result<()> {
        self.events.lock().unwrap().push(step);
        if step == WalStep::Readback {
            if let Some(path) = self.corrupt.lock().unwrap().take() {
                fs::write(path, b"wrong persisted bytes").unwrap();
            }
        }
        let mut fault = self.fail.lock().unwrap();
        if let Some((wanted, left)) = fault.as_mut() {
            if *wanted == step {
                if *left == 0 {
                    *fault = None;
                    return Err(Refusal::Io);
                }
                *left -= 1;
            }
        }
        Ok(())
    }
}
struct Fixture {
    root: tempfile::TempDir,
    faults: Faults,
    records: Vec<Value>,
    initial: Value,
    anchor: Value,
}
impl Fixture {
    fn new() -> Self {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../src/business_profile/record_join_vectors.json"
        ))
        .unwrap();
        let case = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "listener-accept")
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            root,
            faults: Faults::default(),
            records: case["records"].as_array().unwrap().clone(),
            initial: case["initial"].clone(),
            anchor: append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"]
                ["d_observation"]["anchor"]
                .clone(),
        }
    }
    fn open(&self, initial: bool) -> Result<BusinessWal> {
        BusinessWal::open_isolated(
            self.root.path(),
            unsafe { libc::geteuid() },
            Box::new(self.faults.clone()),
            if initial {
                Some(
                    CheckpointSeed::checked(self.anchor.clone(), canonical(&self.initial)).unwrap(),
                )
            } else {
                None
            },
        )
    }
    fn fault(&self, step: WalStep, occurrence: usize) {
        *self.faults.fail.lock().unwrap() = Some((step, occurrence));
    }
    fn reserve(&self, wal: &BusinessWal, index: usize) -> FrozenMutation {
        let body = canonical(&self.records[index]["body"]);
        let expected = wal.committed_anchor().clone();
        let mut next = expected.clone();
        next["reserved_sequence"] = self.records[index]["body"]["sequence"].clone();
        next["reserved_body_digest"] = json!(digest(&body));
        mutation(
            json!({"version":1,"op":"RESERVE","request_id":"d".repeat(32),"expected":expected,"next":next,"body_digest":digest(&body)}),
            &[],
        )
    }
    fn begin(&self, wal: &mut BusinessWal, index: usize) -> FrozenMutation {
        let reserve = self.reserve(wal, index);
        wal.freeze_body(
            &canonical(&self.records[index]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary,
        )
        .unwrap();
        reserve
    }
    fn append(&self, wal: &mut BusinessWal, index: usize) -> Vec<u8> {
        let reserve = self.begin(wal, index);
        wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
            .unwrap();
        let envelope = canonical(&self.records[index]);
        wal.freeze_envelope(&envelope).unwrap();
        let identity = append_contract::identity(&envelope).unwrap();
        let mut next = reserve.next().clone();
        next["committed_sequence"] = identity["sequence"].clone();
        next["committed_digest"] = identity["commitment"].clone();
        next["reserved_body_digest"] = Value::Null;
        let commit = mutation(
            json!({"version":1,"op":"COMMIT","request_id":"e".repeat(32),"expected":reserve.next(),"next":next,"body_digest":digest(&canonical(&self.records[index]["body"]))}),
            &envelope,
        );
        wal.freeze_commit(&commit).unwrap();
        wal.confirm_commit(&authenticated_read(commit.next()))
            .unwrap();
        envelope
    }
}
fn mutation(message: Value, envelope: &[u8]) -> FrozenMutation {
    let bytes = canonical(&message);
    let mut h = d::header(
        "ANCHOR",
        message["request_id"].as_str().unwrap(),
        d::DRAIN_SLOTS[0].1,
    );
    h["message_length"] = json!(bytes.len());
    h["envelope_length"] = json!(envelope.len());
    FrozenMutation::checked(
        d::encode(
            &h,
            &[bytes.as_slice(), envelope].concat(),
            d::Direction::ToDrain,
        )
        .unwrap(),
    )
    .unwrap()
}
struct DiskSink {
    root: tempfile::TempDir,
    join: Value,
    last: Option<(Vec<u8>, Value)>,
}
impl TrustedBusinessSink for DiskSink {
    fn accept_durably(&mut self, envelope: &[u8]) -> Result<Value> {
        use castle_wall_daemon::business_profile::{records, writer_protocol};
        let identity = append_contract::identity(envelope).ok_or(Refusal::Shape)?;
        if let Some((last, ack)) = &self.last {
            if ack["identity"]["sequence"] == identity["sequence"] {
                if last != envelope {
                    return Err(Refusal::Conflict);
                }
                return Ok(ack.clone());
            }
        }
        let record = writer_protocol::decode_envelope(envelope).map_err(|_| Refusal::Shape)?;
        let checkpoint = records::advance(&self.join, &record).map_err(|_| Refusal::Conflict)?;
        let projection = append_contract::projection(&record).ok_or(Refusal::Shape)?;
        let bytes = canonical(
            &json!({"envelope":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,envelope),"identity":identity,"projection":projection,"checkpoint":checkpoint}),
        );
        let stage = self.root.path().join("stage");
        let path = self.root.path().join("last");
        fs::write(&stage, &bytes).map_err(|_| Refusal::Io)?;
        fs::File::open(&stage).unwrap().sync_all().unwrap();
        fs::rename(stage, &path).unwrap();
        fs::File::open(self.root.path())
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), bytes);
        self.join = checkpoint;
        let ack = json!({"version":1,"identity":identity});
        self.last = Some((envelope.to_vec(), ack.clone()));
        Ok(ack)
    }
}
fn sink() -> BusinessSinkAdapter<DiskSink> {
    let f = Fixture::new();
    BusinessSinkAdapter::from_trusted_sink(DiskSink {
        root: tempfile::tempdir().unwrap(),
        join: f.initial,
        last: None,
    })
}
#[test]
fn exact_bytes_two_facts_and_checkpoint_survive_both_release_orders() {
    for d_first in [false, true] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let envelope = f.append(&mut wal, 0);
        let seq = BusinessSequence(1);
        let stored: Value = serde_json::from_slice(
            &fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
        )
        .unwrap();
        assert!(
            stored["payload"].get("effect_status").is_none(),
            "2e1 writes no effect-consumption field"
        );
        let cursor: StorageCursor = wal.storage_cursor(seq).unwrap();
        assert_eq!(cursor, StorageCursor(1));
        let row = f.root.path().join("row-00000000000000000001.json");
        let mut sink = sink();
        if d_first {
            wal.persist_d_fact(seq, authenticated_original(&envelope))
                .unwrap();
        } else {
            wal.persist_ts_fact(
                seq,
                sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                    .unwrap(),
            )
            .unwrap();
        }
        let compacted = wal.compact_one();
        assert!(row.exists(), "one fact cannot delete the retained original");
        assert!(
            matches!(compacted, Ok(false)),
            "one fact never releases the original"
        );
        drop(wal);
        let mut wal = f.open(false).unwrap();
        if d_first {
            assert_eq!(wal.next_delivery().unwrap().unwrap().1, envelope);
            wal.persist_ts_fact(
                seq,
                sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                    .unwrap(),
            )
            .unwrap();
        } else {
            wal.persist_d_fact(seq, authenticated_original(&envelope))
                .unwrap();
        }
        assert!(wal.compact_one().unwrap());
        assert!(!row.exists());
        let join = wal.committed_join().unwrap();
        drop(wal);
        let wal = f.open(false).unwrap();
        assert_eq!(
            wal.committed_join().unwrap(),
            join,
            "compacted suffix never reconstructs genesis"
        );
        assert!(wal.next_delivery().unwrap().is_none());
    }
}
#[test]
fn delivery_cursor_waits_for_fact_and_checkpoint_readback() {
    for restart in [false, true] {
        for fault in [
            (WalStep::Readback, 0),
            (WalStep::Readback, 1),
            (WalStep::DirectorySync, 1),
        ] {
            let f = Fixture::new();
            let mut wal = f.open(true).unwrap();
            let first = f.append(&mut wal, 0);
            let second = f.append(&mut wal, 1);
            let mut sink = sink();
            assert_eq!(wal.next_delivery().unwrap().unwrap().1, first);
            f.fault(fault.0, fault.1);
            assert!(wal
                .persist_ts_fact(
                    BusinessSequence(1),
                    sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                        .unwrap()
                )
                .is_err());
            assert!(
                wal.next_delivery().is_err(),
                "uncertain local ACK persistence blocks n+1"
            );
            if restart {
                drop(wal);
                wal = f.open(false).unwrap();
            } else {
                wal.reconcile_publication().unwrap();
            }
            if let Some((sequence, envelope)) = wal.next_delivery().unwrap() {
                if sequence.0 == 1 {
                    assert_eq!(envelope, first);
                    wal.persist_ts_fact(
                        sequence,
                        sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                            .unwrap(),
                    )
                    .unwrap();
                }
            }
            assert_eq!(
                wal.next_delivery().unwrap().unwrap().1,
                second,
                "durable TS fact permits n+1 without D release"
            );
            assert!(f.root.path().join("row-00000000000000000001.json").exists());
        }
    }
}
#[test]
fn restart_and_first_envelope_freeze_never_authorize_resign() {
    for marked in [false, true] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let reserve = f.begin(&mut wal, 0);
        let observation = authenticated_read(reserve.next());
        if marked {
            wal.persist_sign_marker(&observation, NOW).unwrap();
            assert!(
                wal.persist_sign_marker(&observation, NOW).is_err(),
                "durable marker cannot authorize a second SIGN"
            );
            let envelope = canonical(&f.records[0]);
            wal.freeze_envelope(&envelope).unwrap();
            let mut changed = f.records[0].clone();
            changed["outer"]["signature"] = json!("A".repeat(86));
            assert!(
                wal.freeze_envelope(&canonical(&changed)).is_err(),
                "first exact E cannot be replaced"
            );
        }
        drop(wal);
        let mut wal = f.open(false).unwrap();
        assert!(
            wal.persist_sign_marker(&observation, NOW).is_err(),
            "restart never initiates SIGN for an outstanding reservation"
        );
    }
}
#[test]
fn publication_faults_retain_bytes_charges_and_exclusive_ownership() {
    for step in [
        WalStep::StageCreate,
        WalStep::Write,
        WalStep::FileSync,
        WalStep::Rename,
        WalStep::DirectorySync,
        WalStep::Readback,
    ] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let before = wal.charged_bytes();
        let reserve = f.reserve(&wal, 0);
        f.fault(step, 0);
        assert!(wal
            .freeze_body(
                &canonical(&f.records[0]["body"]),
                &reserve,
                DEADLINE,
                EXPIRY,
                Pool::Ordinary
            )
            .is_err());
        assert_eq!(wal.state(), WalState::PublicationHeld);
        assert!(
            wal.charged_bytes().0 > before.0,
            "possible publication retains charges"
        );
        assert!(
            matches!(f.open(false), Err(Refusal::Lock)),
            "lock precedes staging/accounting access"
        );
        assert!(
            wal.freeze_body(
                &canonical(&f.records[0]["body"]),
                &reserve,
                DEADLINE,
                EXPIRY,
                Pool::Ordinary
            )
            .is_err(),
            "held publication cannot start new work"
        );
        if matches!(
            step,
            WalStep::FileSync | WalStep::Rename | WalStep::DirectorySync | WalStep::Readback
        ) {
            wal.reconcile_publication().unwrap();
            assert!(f.root.path().join("row-00000000000000000001.json").exists());
        }
    }
}
#[test]
fn reload_refuses_missing_checkpoint_consumed_effect_and_rewritten_identity() {
    for change in [
        "checkpoint",
        "effect",
        "version",
        "identity",
        "body",
        "join",
        "checksum",
        "body_before_sign",
        "missing",
    ] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        if change == "body_before_sign" {
            f.begin(&mut wal, 0);
        } else {
            f.append(&mut wal, 0);
        }
        drop(wal);
        if change == "checkpoint" {
            fs::remove_file(f.root.path().join("checkpoint.json")).unwrap();
        } else {
            let path = f.root.path().join(if change == "join" {
                "checkpoint.json"
            } else {
                "row-00000000000000000001.json"
            });
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match change {
                "effect" => value["payload"]["effect_status"] = json!("consumed"),
                "version" => value["payload"]["version"] = json!(2),
                "identity" => {
                    value["payload"]["ts_fact"] = json!({"version":1,"sequence":2,"commitment":digest(b"other"),"envelope_sha256":digest(b"other")})
                }
                "body" => value["payload"]["body_digest"] = json!(digest(b"other")),
                "join" => value["payload"]["join_state"] = json!("e30"),
                "missing" => {
                    value["payload"].as_object_mut().unwrap().remove("d_fact");
                }
                "checksum" => value["storage_checksum"] = json!(digest(b"changed checksum")),
                "body_before_sign" => {
                    use base64::Engine;
                    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(value["payload"]["body"].as_str().unwrap())
                        .unwrap();
                    let mut body: Value = serde_json::from_slice(&decoded).unwrap();
                    body["captured_at_unix_ms"] = json!(2);
                    value["payload"]["body"] =
                        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(canonical(&body)));
                }
                _ => unreachable!(),
            }
            if change != "checksum" {
                value["storage_checksum"] = json!(digest(&canonical(&value["payload"])));
            }
            fs::write(path, canonical(&value)).unwrap();
        }
        assert!(
            f.open(false).is_err(),
            "{change} cannot reload as authority"
        );
    }
}
#[test]
fn nofollow_lock_and_private_metadata_are_required() {
    for kind in ["symlink", "hardlink", "mode"] {
        let f = Fixture::new();
        let outside = tempfile::tempdir().unwrap();
        let wal = f.open(true).unwrap();
        drop(wal);
        let lock = f.root.path().join("business-wal.lock");
        match kind {
            "symlink" => {
                fs::rename(&lock, f.root.path().join("held-lock")).unwrap();
                std::os::unix::fs::symlink("held-lock", &lock).unwrap();
            }
            "hardlink" => fs::hard_link(&lock, outside.path().join("other-lock")).unwrap(),
            "mode" => fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap(),
            _ => unreachable!(),
        };
        assert!(
            f.open(false).is_err(),
            "{kind} lock refuses before state reads"
        );
    }
}

#[test]
fn admission_charges_staging_and_never_borrows_control_space() {
    for (ordinary, control, entries) in [
        (BUSINESS_WAL_MAX_BYTES, 0, 0),
        (0, BUSINESS_WAL_CONTROL_MAX_BYTES, 0),
        (0, 0, BUSINESS_WAL_ENTRIES_MAX),
    ] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let reserve = f.reserve(&wal, 0);
        let checkpoint_charge = wal.charged_bytes().1;
        test_support::accounting(&mut wal, ordinary, control.max(checkpoint_charge), entries);
        assert!(
            wal.freeze_body(
                &canonical(&f.records[0]["body"]),
                &reserve,
                DEADLINE,
                EXPIRY,
                Pool::Ordinary
            )
            .is_err(),
            "capacity is charged before publication or further admission"
        );
        if ordinary > 0 || entries > 0 {
            assert!(!f.root.path().join("publication.stage").exists());
            assert!(!f.root.path().join("row-00000000000000000001.json").exists());
        }
    }
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let reserve = f.reserve(&wal, 0);
    assert!(
        wal.freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Control
        )
        .is_err(),
        "ordinary open cannot spend control reserve"
    );
}
#[test]
fn wrong_release_identity_and_unverified_envelope_do_not_publish() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let first = f.append(&mut wal, 0);
    let second = f.append(&mut wal, 1);
    let before = fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap();
    assert!(
        wal.persist_d_fact(BusinessSequence(1), authenticated_original(&second))
            .is_err(),
        "D fact belongs to its exact original"
    );
    let mut sink = sink();
    sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
        .unwrap();
    assert!(
        wal.persist_ts_fact(BusinessSequence(1), sink.deliver(&token_for(1)).unwrap())
            .is_err(),
        "TS fact belongs to its exact original"
    );
    assert_eq!(
        fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
        before
    );
    assert_eq!(wal.next_delivery().unwrap().unwrap().1, first);
    let g = Fixture::new();
    let mut wal = g.open(true).unwrap();
    let reserve = g.begin(&mut wal, 0);
    wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
        .unwrap();
    let mut forged = g.records[0].clone();
    forged["outer"]["signature"] = json!("A".repeat(86));
    assert!(
        wal.freeze_envelope(&canonical(&forged)).is_err(),
        "first E must verify against independent checkpoint enrollment"
    );
    wal.freeze_envelope(&canonical(&g.records[0])).unwrap();
}

#[test]
fn compaction_interruption_preserves_released_checkpoint_and_restarts_safely() {
    for fault in [WalStep::Readback, WalStep::Delete] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let envelope = f.append(&mut wal, 0);
        let mut sink = sink();
        wal.persist_ts_fact(
            BusinessSequence(1),
            sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                .unwrap(),
        )
        .unwrap();
        wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope))
            .unwrap();
        let join = wal.committed_join().unwrap();
        f.fault(fault, 0);
        assert!(wal.compact_one().is_err());
        assert_eq!(wal.state(), WalState::PublicationHeld);
        assert!(
            f.root.path().join("row-00000000000000000001.json").exists(),
            "released checkpoint readback precedes deletion"
        );
        drop(wal);
        let wal = f.open(false).unwrap();
        assert_eq!(wal.committed_join().unwrap(), join);
        assert!(!f.root.path().join("row-00000000000000000001.json").exists());
    }
}
#[test]
fn publication_reads_actual_bytes_before_reporting_durable() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let reserve = f.reserve(&wal, 0);
    *f.faults.corrupt.lock().unwrap() = Some(f.root.path().join("row-00000000000000000001.json"));
    assert!(
        wal.freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        )
        .is_err(),
        "durable result requires actual exact readback"
    );
    assert_eq!(wal.state(), WalState::PublicationHeld);
}

#[test]
fn missing_compacted_checkpoint_never_reconstructs_genesis() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let envelope = f.append(&mut wal, 0);
    let mut sink = sink();
    wal.persist_ts_fact(
        BusinessSequence(1),
        sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
            .unwrap(),
    )
    .unwrap();
    wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope))
        .unwrap();
    wal.compact_one().unwrap();
    drop(wal);
    fs::remove_file(f.root.path().join("checkpoint.json")).unwrap();
    assert!(
        f.open(false).is_err(),
        "empty compacted suffix cannot reconstruct genesis"
    );
}

#[test]
fn marker_requires_a_live_deadline_and_the_complete_reserved_observation() {
    for condition in ["deadline", "observation", "live"] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let reserve = f.begin(&mut wal, 0);
        let observation = authenticated_read(if condition == "observation" {
            reserve.expected()
        } else {
            reserve.next()
        });
        let result = wal.persist_sign_marker(
            &observation,
            if condition == "deadline" {
                DEADLINE
            } else {
                NOW
            },
        );
        match condition {
            "deadline" => assert_eq!(
                result,
                Err(Refusal::Deadline),
                "expired append cannot authorize its first SIGN"
            ),
            "observation" => assert_eq!(
                result,
                Err(Refusal::Authority),
                "complete reserve observation is required"
            ),
            _ => assert!(result.is_ok()),
        }
    }
}
#[test]
fn sink_adapter_retains_exact_delivery_across_wrong_acknowledgements() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct ReplyFault {
        inner: DiskSink,
        wrong: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }
    impl TrustedBusinessSink for ReplyFault {
        fn accept_durably(&mut self, e: &[u8]) -> Result<Value> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut ack = self.inner.accept_durably(e)?;
            if self.wrong.load(Ordering::SeqCst) {
                ack["identity"]["sequence"] = json!(2);
            }
            Ok(ack)
        }
    }
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    f.append(&mut wal, 0);
    let wrong = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut adapter = BusinessSinkAdapter::from_trusted_sink(ReplyFault {
        inner: DiskSink {
            root: tempfile::tempdir().unwrap(),
            join: f.initial.clone(),
            last: None,
        },
        wrong: wrong.clone(),
        calls: calls.clone(),
    });
    assert!(
        adapter
            .deliver(&wal.next_delivery().unwrap().unwrap().1)
            .is_err(),
        "wrong ACK identity never constructs the sealed TS fact"
    );
    assert!(
        matches!(adapter.deliver(&token_for(1)), Err(Refusal::Held)),
        "pending sink delivery owns exact E"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "changed E cannot reach the trusted sink while owned"
    );
    wrong.store(false, Ordering::SeqCst);
    wal.persist_ts_fact(
        BusinessSequence(1),
        adapter
            .deliver(&wal.next_delivery().unwrap().unwrap().1)
            .unwrap(),
    )
    .unwrap();
    assert!(wal.next_delivery().unwrap().is_none());
}

#[test]
fn reconciliation_republishes_exact_bytes_instead_of_trusting_a_later_sync() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let envelope = f.append(&mut wal, 0);
    let mut sink = sink();
    f.fault(WalStep::DirectorySync, 0);
    assert!(wal
        .persist_ts_fact(
            BusinessSequence(1),
            sink.deliver(&wal.next_delivery().unwrap().unwrap().1)
                .unwrap()
        )
        .is_err());
    f.faults.events.lock().unwrap().clear();
    wal.reconcile_publication().unwrap();
    let events = f.faults.events.lock().unwrap().clone();
    assert!(
        events.contains(&WalStep::StageCreate) && events.contains(&WalStep::Rename),
        "uncertain publication requires fresh staging and rename"
    );
    let path = f.root.path().join("row-00000000000000000001.json");
    let old = fs::File::open(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    drop(wal);
    let wal = f.open(false).unwrap();
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(&path).unwrap().ino(),
        "restart republishes retained bytes before exposing durable cursors"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(wal.next_delivery().unwrap().unwrap().1, envelope);
}

#[test]
fn a_confirmed_drain_refresh_permits_the_next_append_without_changing_authority() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let first = f.append(&mut wal, 0);
    let identity = append_contract::identity(&first).unwrap();
    let mut drained = wal.committed_anchor().clone();
    drained["drained_sequence"] = identity["sequence"].clone();
    drained["drained_digest"] = identity["commitment"].clone();
    assert!(
        wal.refresh_drained(&authenticated_read(&drained)).is_err(),
        "READ alone cannot replace the required original ACK fact"
    );
    wal.persist_d_fact(BusinessSequence(1), authenticated_original(&first))
        .unwrap();
    for (latched, uncertain) in [(true, false), (false, true)] {
        assert_eq!(
            wal.refresh_drained(&super::append_clients::authenticated_read_flags(
                &drained, latched, uncertain
            )),
            Err(Refusal::Authority),
            "uncertain or latched READ cannot refresh the durable anchor"
        );
    }
    let mut changed = drained.clone();
    changed["generation_high_water"] = json!(1);
    assert!(
        wal.refresh_drained(&authenticated_read(&changed)).is_err(),
        "drain refresh preserves the complete independent authority snapshot"
    );
    wal.refresh_drained(&authenticated_read(&drained)).unwrap();
    let second = f.append(&mut wal, 1);
    assert_eq!(wal.committed_anchor()["committed_sequence"], 2);
    assert_eq!(
        wal.next_delivery().unwrap().unwrap().1,
        first,
        "D progress does not skip the TS delivery barrier"
    );
    assert_eq!(append_contract::identity(&second).unwrap()["sequence"], 2);
    let held = Fixture::new();
    let mut pending = held.open(true).unwrap();
    held.begin(&mut pending, 0);
    let observation = authenticated_read(pending.committed_anchor());
    assert_eq!(
        pending.refresh_drained(&observation),
        Err(Refusal::Held),
        "drain refresh cannot replace an active intent snapshot"
    );
}

#[test]
fn forty_uncertain_publications_retain_one_intent_and_every_charge() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let journal_charge = wal.charged_bytes().0;
    let reserve = f.reserve(&wal, 0);
    f.fault(WalStep::DirectorySync, 0);
    assert!(wal
        .freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        )
        .is_err());
    let original = fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap();
    let allocation_charge = wal.charged_bytes().0;
    for _ in 0..40 {
        f.fault(WalStep::DirectorySync, 0);
        assert!(wal.reconcile_publication().is_err());
        assert_eq!(wal.state(), WalState::PublicationHeld);
        assert_eq!(
            wal.charged_bytes().0,
            2 * allocation_charge - journal_charge,
            "one publication retains at most target plus staging charge"
        );
        assert_eq!(
            fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
            original
        );
        assert!(wal
            .freeze_body(
                &canonical(&f.records[1]["body"]),
                &reserve,
                DEADLINE,
                EXPIRY,
                Pool::Ordinary
            )
            .is_err());
    }
    wal.reconcile_publication().unwrap();
    assert_eq!(wal.charged_bytes().0, allocation_charge);
    assert!(
        wal.freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        )
        .is_err(),
        "reconciled orphan intent cannot be replaced before its checkpoint"
    );
    assert_eq!(
        fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
        original
    );
}

#[test]
fn maximal_admission_preserves_rewrite_space_through_release() {
    use castle_wall_daemon::business_profile::{
        activation_anchor, drain_protocol, records, records_schema, writer_protocol,
    };
    // Same independent wire bounds as the generated row and checkpoint contracts.
    let row_max = (2 * 4 * drain_protocol::D_REQUEST_MAX_BYTES.div_ceil(3)
        + 4 * records_schema::MAX_BYTES.div_ceil(3)
        + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
        + 32 * 128) as u64;
    let checkpoint_max = (4 * records::JOIN_STATE_BYTES_MAX.div_ceil(3)
        + activation_anchor::MAX_BYTES
        + 32 * 128) as u64;
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    test_support::accounting(
        &mut wal,
        BUSINESS_WAL_MAX_BYTES - 2 * row_max,
        checkpoint_max,
        0,
    );
    let reserve = f.begin(&mut wal, 0);
    assert_eq!(
        wal.charged_bytes().0,
        BUSINESS_WAL_MAX_BYTES - row_max,
        "admission reserves the complete row footprint"
    );
    wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
        .unwrap();
    let envelope = canonical(&f.records[0]);
    assert_eq!(
        wal.freeze_envelope(&envelope),
        Ok(()),
        "signed E has guaranteed custody headroom"
    );
    let identity = append_contract::identity(&envelope).unwrap();
    let mut next = reserve.next().clone();
    next["committed_sequence"] = identity["sequence"].clone();
    next["committed_digest"] = identity["commitment"].clone();
    next["reserved_body_digest"] = Value::Null;
    let commit = mutation(
        json!({"version":1,"op":"COMMIT","request_id":"e".repeat(32),"expected":reserve.next(),"next":next,"body_digest":digest(&canonical(&f.records[0]["body"]))}),
        &envelope,
    );
    wal.freeze_commit(&commit).unwrap();
    wal.confirm_commit(&authenticated_read(commit.next()))
        .unwrap();
    let next_reserve = f.reserve(&wal, 1);
    assert_eq!(
        wal.freeze_body(
            &canonical(&f.records[1]["body"]),
            &next_reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        ),
        Err(Refusal::Capacity),
        "next admission cannot spend rewrite reserve"
    );
    assert_eq!(
        wal.persist_ts_fact(
            BusinessSequence(1),
            sink()
                .deliver(&wal.next_delivery().unwrap().unwrap().1)
                .unwrap()
        ),
        Ok(()),
        "TS fact retains rewrite headroom"
    );
    assert_eq!(
        wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope)),
        Ok(()),
        "D fact retains rewrite headroom"
    );
    drop(wal);
    let reopened = test_support::reopen_accounted(
        f.root.path(),
        unsafe { libc::geteuid() },
        Box::new(f.faults.clone()),
        [BUSINESS_WAL_MAX_BYTES - 2 * row_max, 0],
    );
    assert!(
        reopened.is_ok(),
        "near-full restart retains one maximal staging allocation"
    );
    let mut wal = reopened.unwrap();
    // Try another admission at the boundary before restarting again, with the same occupied pools.
    let _admitted = wal.freeze_body(
        &canonical(&f.records[1]["body"]),
        &next_reserve,
        DEADLINE,
        EXPIRY,
        Pool::Ordinary,
    );
    drop(wal);
    assert!(
        test_support::reopen_accounted(
            f.root.path(),
            unsafe { libc::geteuid() },
            Box::new(f.faults.clone()),
            [BUSINESS_WAL_MAX_BYTES - 2 * row_max, 0]
        )
        .is_ok(),
        "admission cannot consume near-full restart headroom"
    );
}

#[test]
fn admission_retains_near_full_restart_headroom() {
    use castle_wall_daemon::business_profile::{drain_protocol, records_schema, writer_protocol};
    let row_max = (2 * 4 * drain_protocol::D_REQUEST_MAX_BYTES.div_ceil(3)
        + 4 * records_schema::MAX_BYTES.div_ceil(3)
        + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
        + 32 * 128) as u64;
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let control = wal.charged_bytes().1;
    let occupied = BUSINESS_WAL_MAX_BYTES - 2 * row_max;
    test_support::accounting(&mut wal, occupied, control, 0);
    f.append(&mut wal, 0);
    let reserve = f.reserve(&wal, 1);
    assert_eq!(
        wal.freeze_body(
            &canonical(&f.records[1]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary,
        ),
        Err(Refusal::Capacity),
        "admission cannot consume near-full restart headroom"
    );
    drop(wal);
    assert!(
        test_support::reopen_accounted(
            f.root.path(),
            unsafe { libc::geteuid() },
            Box::new(f.faults.clone()),
            [occupied, 0]
        )
        .is_ok(),
        "admission cannot consume near-full restart headroom"
    );
}

#[test]
fn restart_without_active_intent_allows_the_next_sign_marker() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    f.append(&mut wal, 0);
    drop(wal);
    let mut wal = f.open(false).unwrap();
    let reserve = f.begin(&mut wal, 1);
    assert_eq!(
        wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW),
        Ok(()),
        "a body frozen in this process may mark its first SIGN after restart"
    );
    assert_eq!(
        wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW),
        Err(Refusal::Held)
    );
}

fn token_for(index: usize) -> DeliveryToken {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let mut sink = sink();
    for i in 0..=index {
        f.append(&mut wal, i);
        if i < index {
            let token = wal.next_delivery().unwrap().unwrap().1;
            wal.persist_ts_fact(
                BusinessSequence((i + 1) as u64),
                sink.deliver(&token).unwrap(),
            )
            .unwrap();
        }
    }
    wal.next_delivery().unwrap().unwrap().1
}

#[path = "wal_nits.rs"]
mod nits;

#[test]
fn ordinary_provider_uses_authenticated_d_and_durable_wal_readbacks() {
    use castle_wall_daemon::business_profile::{
        append_checkpoint as cp, append_clients::CheckpointChallenge, signer_client::StatusReply,
    };
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let clock: castle_wall_daemon::business_profile::writer_peer::Clock = Arc::new(|| Ok(NOW));
    for settled in [false, true] {
        if settled {
            f.append(&mut wal, 0);
        }
        let a = wal.committed_anchor();
        let j: Value = serde_json::from_slice(&wal.committed_join().unwrap()).unwrap();
        let mut grant = j["pin"].clone();
        for key in ["activation_id", "lease_id", "generation"] {
            grant[key] = j["grant"][key].clone();
        }
        let status = StatusReply {
            op: "STATUS".into(),
            state: "UNLOCKED".into(),
            grant: serde_json::from_value(grant).unwrap(),
            started_boottime_ns: "0".into(),
            expires_boottime_ns: j["grant"]["expires_ns"].as_str().unwrap().into(),
            boot_id: a["boot_id"].as_str().unwrap().into(),
            anchor_revision: a["enrollment_revision"].as_u64(),
            anchor_digest: castle_wall_daemon::business_profile::activation_anchor::anchor_digest(
                a,
            ),
        };
        let challenge = CheckpointChallenge {
            session: "a".repeat(32),
            request: "b".repeat(32),
            nonce: "c".repeat(32),
            issued: NOW,
            status,
        };
        let provider = cp::OrdinaryCheckpointProvider::production();
        let report = provider
            .report(
                &challenge,
                &authenticated_read(a),
                wal.ordinary_checkpoint(&clock).unwrap(),
                a["fortress_id"].as_str().unwrap(),
                a["enrollment_revision"].as_u64().unwrap(),
                NOW,
            )
            .unwrap();
        let v: Value = serde_json::from_slice(&report).unwrap();
        assert_eq!(
            v["wal_checkpoint"]["retained_originals"]
                .as_array()
                .unwrap()
                .len(),
            usize::from(settled)
        );
        assert_eq!(v["observed_boottime_ns"], NOW.to_string());
        let stale_clock: castle_wall_daemon::business_profile::writer_peer::Clock =
            Arc::new(|| Ok(NOW - 1));
        assert!(
            provider
                .report(
                    &challenge,
                    &authenticated_read(a),
                    wal.ordinary_checkpoint(&stale_clock).unwrap(),
                    a["fortress_id"].as_str().unwrap(),
                    a["enrollment_revision"].as_u64().unwrap(),
                    NOW
                )
                .is_err(),
            "older WAL completion must follow challenge issue"
        );
    }
    f.begin(&mut wal, 1);
    assert!(
        wal.ordinary_checkpoint(&clock).is_err(),
        "active intent never supplies ordinary evidence"
    );
}

#[test]
fn executor_retains_one_owned_fsync_across_forty_timeout_disconnect_waves() {
    use castle_wall_daemon::business_profile::wal_executor::{Operation, WalExecutor};
    use std::sync::mpsc;
    use std::time::Duration;
    struct HeldSync {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        held: bool,
    }
    impl WalHooks for HeldSync {
        fn before(&mut self, step: WalStep) -> Result<()> {
            if step == WalStep::FileSync && !self.held {
                self.held = true;
                self.entered.send(()).map_err(|_| Refusal::Io)?;
                self.release.recv().map_err(|_| Refusal::Io)?;
            }
            Ok(())
        }
    }
    let f = Fixture::new();
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, blocked) = mpsc::sync_channel(1);
    let mut executor = WalExecutor::start().unwrap();
    let owner = executor
        .submit(
            Operation::Open {
                path: f.root.path().into(),
                owner: unsafe { libc::geteuid() },
                hooks: Box::new(HeldSync {
                    entered,
                    release: blocked,
                    held: false,
                }),
                seed: Some(
                    CheckpointSeed::checked(f.anchor.clone(), canonical(&f.initial)).unwrap(),
                ),
            },
            NOW,
            DEADLINE,
        )
        .unwrap();
    waiting.recv_timeout(Duration::from_secs(5)).unwrap();
    // The hook is always released before assertions so failed fault schedules also reap the worker.
    let mut results = Vec::new();
    const WAVES: u64 = 40;
    for wave in 0..WAVES {
        let now = DEADLINE + wave;
        let pending = executor.poll(now).unwrap().is_none();
        executor.disconnect();
        let admission = executor.submit(Operation::NextDelivery, now, EXPIRY);
        let compaction = executor.submit(Operation::CompactOne, now, EXPIRY);
        results.push((pending, executor.owned(), admission, compaction));
    }
    release.send(()).unwrap();
    for (wave, (pending, owned, admission, compaction)) in results.into_iter().enumerate() {
        assert!(
            pending && owned,
            "wave {wave} retains the blocked operation"
        );
        assert_eq!(
            admission,
            Err(Refusal::Held),
            "wave {wave} admits no second disk operation"
        );
        assert_eq!(
            compaction,
            Err(Refusal::Held),
            "compaction never overlaps an owned operation"
        );
    }
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if executor.poll(DEADLINE + WAVES).unwrap().is_some() {
            break;
        }
        assert!(std::time::Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(executor.settle(owner + 1).err(), Some(Refusal::Held));
    let late = executor.settle(owner).unwrap();
    assert!(
        !late.eligible,
        "late completion never restores effect eligibility"
    );
    assert!(late.result.is_ok());
    assert!(!executor.owned());
    assert!(executor
        .submit(Operation::NextDelivery, DEADLINE + WAVES, EXPIRY)
        .is_ok());
}

#[test]
fn journal_retires_only_never_reserved_orphans_and_preserves_sequence() {
    for (reserved, stale) in [(false, false), (true, false), (false, true)] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let reserve = f.reserve(&wal, 0);
        f.fault(WalStep::Rename, 1);
        assert!(wal
            .freeze_body(
                &canonical(&f.records[0]["body"]),
                &reserve,
                DEADLINE,
                EXPIRY,
                Pool::Ordinary
            )
            .is_err());
        drop(wal);
        let observation = authenticated_read(if reserved { reserve.next() } else { &f.anchor });
        let recovered = BusinessWal::open_recovering(
            f.root.path(),
            unsafe { libc::geteuid() },
            Box::new(f.faults.clone()),
            None,
            &observation,
            &(Arc::new(move || {
                Ok(NOW
                    + if stale {
                        d::D_LEASE_MS as u64 * 1_000_000
                    } else {
                        0
                    })
            }) as castle_wall_daemon::business_profile::writer_peer::Clock),
        );
        if reserved || stale {
            assert!(
                recovered.is_err(),
                "reserved or stale-proof orphan stays owned"
            );
            assert!(f.root.path().join("row-00000000000000000001.json").exists());
        } else {
            let mut recovered = recovered.unwrap();
            assert!(
                !f.root.path().join("row-00000000000000000001.json").exists(),
                "never-reserved orphan retires without adoption"
            );
            assert_eq!(recovered.committed_anchor(), &f.anchor);
            assert_eq!(
                f.begin(&mut recovered, 0).bytes(),
                reserve.bytes(),
                "retirement preserves the next lawful append"
            );
        }
    }
}

#[test]
fn journal_recovers_complete_stages_and_initialization_under_same_lock() {
    for step in [WalStep::Write, WalStep::Rename, WalStep::DirectorySync] {
        let f = Fixture::new();
        f.fault(step, 0);
        assert!(f.open(true).is_err());
        assert!(f.root.path().join("publication.journal").exists());
        let before = fs::metadata(f.root.path().join("business-wal.lock")).unwrap();
        use std::os::unix::fs::MetadataExt;
        let recovered = f.open(true).unwrap();
        assert_eq!(recovered.committed_anchor(), &f.anchor);
        assert_eq!(
            before.ino(),
            fs::metadata(f.root.path().join("business-wal.lock"))
                .unwrap()
                .ino()
        );
        assert!(
            f.open(false).is_err(),
            "second opener cannot replace the held lock"
        );
    }
}

#[test]
fn journal_unknown_or_torn_proof_never_authorizes_recovery() {
    for invalid in [b"{".as_slice(), b"{}".as_slice()] {
        let f = Fixture::new();
        f.fault(WalStep::Rename, 0);
        assert!(f.open(true).is_err());
        fs::write(f.root.path().join("publication.journal"), invalid).unwrap();
        assert!(f.open(true).is_err());
        assert!(f.root.path().join("publication.stage").exists());
    }
}

#[test]
fn current_row_unknown_marker_precedes_one_live_permit_and_restart_never_mints() {
    use castle_wall_daemon::business_profile::effect_permit::{EffectIntent, EffectPermit};
    for restart in [false, true] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let envelope = f.append(&mut wal, 0);
        if restart {
            drop(wal);
            wal = f.open(false).unwrap();
        }
        let marker = test_support::mark_effect(&mut wal, BusinessSequence(1));
        if restart {
            assert!(
                marker.is_err(),
                "outstanding-at-open rows never mint effects"
            );
        } else {
            let marker = marker.unwrap();
            let row: Value = serde_json::from_slice(
                &fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                row["payload"]["effect_status"], "unknown",
                "marker readback precedes permit construction"
            );
            let body = &f.records[0]["body"];
            let intent = EffectIntent::OpenAdmission {
                flow: body["payload"]["context"]["flow"].clone(),
                payload: body["payload"].clone(),
            };
            assert!(EffectPermit::from_marker_for_test(
                marker,
                &intent,
                &envelope,
                "a".repeat(32),
                NOW,
                DEADLINE
            )
            .is_some());
            assert!(
                test_support::mark_effect(&mut wal, BusinessSequence(1)).is_err(),
                "live marker completion is one-shot"
            );
            drop(wal);
            let mut reopened = f.open(false).unwrap();
            assert!(test_support::mark_effect(&mut reopened, BusinessSequence(1)).is_err());
        }
    }
}

#[test]
fn marker_readback_failure_loses_effect_eligibility_after_reconciliation() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    f.append(&mut wal, 0);
    f.fault(WalStep::Readback, 0);
    assert!(
        test_support::mark_effect(&mut wal, BusinessSequence(1)).is_err(),
        "no marker completion before durable readback"
    );
    wal.reconcile_publication().unwrap();
    assert!(
        test_support::mark_effect(&mut wal, BusinessSequence(1)).is_err(),
        "reconciliation never recreates the live completion"
    );
}

#[test]
fn journal_reservation_preserves_both_reviewed_retention_ceilings() {
    use castle_wall_daemon::business_profile::{
        activation_anchor, drain_protocol, records, records_schema, writer_protocol,
    };
    let row = (2 * 4 * drain_protocol::D_REQUEST_MAX_BYTES.div_ceil(3)
        + 4 * records_schema::MAX_BYTES.div_ceil(3)
        + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
        + 32 * 128) as u64;
    let checkpoint = (4 * records::JOIN_STATE_BYTES_MAX.div_ceil(3)
        + activation_anchor::MAX_BYTES
        + 32 * 128) as u64;
    let journal = test_support::journal_reserve();
    assert_eq!((BUSINESS_WAL_MAX_BYTES - journal) / row - 1, 243);
    assert_eq!(
        (BUSINESS_WAL_CONTROL_MAX_BYTES - journal - 2 * checkpoint - row) / row,
        12
    );
    assert!(
        journal <= 3264,
        "journal copies fit the reviewed Control slack"
    );
}

#[test]
fn polled_delivery_wait_retains_one_token_without_blocking_appends() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Absent {
        ready: Arc<AtomicBool>,
        envelope: Option<Vec<u8>>,
    }
    impl PolledBusinessSink for Absent {
        fn offer(&mut self, envelope: &[u8]) -> Result<()> {
            self.envelope = Some(envelope.to_vec());
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<Value>> {
            Ok(if self.ready.load(Ordering::SeqCst) {
                Some(
                    json!({"version":1,"identity":append_contract::identity(self.envelope.as_ref().unwrap()).unwrap()}),
                )
            } else {
                None
            })
        }
        fn refused(&mut self) -> Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let first = f.append(&mut wal, 0);
    let ready = Arc::new(AtomicBool::new(false));
    let mut sink = PolledSinkAdapter::new(Absent {
        ready: ready.clone(),
        envelope: None,
    });
    let token = wal.next_delivery().unwrap().unwrap().1;
    sink.offer(&token).unwrap();
    for _ in 0..40 {
        assert!(sink.poll().unwrap().is_none());
    }
    let second = f.append(&mut wal, 1);
    wal.persist_d_fact(BusinessSequence(1), authenticated_original(&first))
        .unwrap();
    wal.persist_d_fact(BusinessSequence(2), authenticated_original(&second))
        .unwrap();
    assert_eq!(wal.next_delivery().unwrap().unwrap().1.envelope(), first);
    ready.store(true, Ordering::SeqCst);
    wal.persist_ts_fact(BusinessSequence(1), sink.poll().unwrap().unwrap())
        .unwrap();
    assert_eq!(wal.next_delivery().unwrap().unwrap().1.envelope(), second);
}

#[test]
fn refused_polled_ack_mints_no_fact_and_releases_the_sink() {
    struct Mismatched {
        envelope: Option<Vec<u8>>,
        acks: usize,
        refused: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl PolledBusinessSink for Mismatched {
        fn offer(&mut self, envelope: &[u8]) -> Result<()> {
            self.envelope = Some(envelope.to_vec());
            Ok(())
        }
        fn poll(&mut self) -> Result<Option<Value>> {
            let mut identity = append_contract::identity(self.envelope.as_ref().unwrap()).unwrap();
            self.acks += 1;
            if self.acks == 1 {
                identity["sequence"] = json!(2);
            }
            Ok(Some(json!({"version":1,"identity":identity})))
        }
        fn refused(&mut self) -> Result<()> {
            self.refused
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    f.append(&mut wal, 0);
    let refused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut sink = PolledSinkAdapter::new(Mismatched {
        envelope: None,
        acks: 0,
        refused: refused.clone(),
    });
    let token = wal.next_delivery().unwrap().unwrap().1;
    sink.offer(&token).unwrap();
    assert!(matches!(sink.poll(), Err(Refusal::Conflict)));
    assert_eq!(
        refused.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter releases the sink after a refused ACK"
    );
    let fact = sink
        .poll()
        .unwrap()
        .expect("the same wait accepts a correlated ACK");
    wal.persist_ts_fact(BusinessSequence(1), fact).unwrap();
    assert!(sink.poll().unwrap().is_none(), "one wait mints one fact");
    assert_eq!(
        refused.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a correlated ACK reports no refusal"
    );
    assert!(wal.next_delivery().unwrap().is_none());
}

#[test]
fn initialization_journal_requires_empty_layout_and_exact_partial_source() {
    for populated in [false, true] {
        let f = Fixture::new();
        f.fault(WalStep::Rename, 0);
        assert!(f.open(true).is_err());
        if populated {
            let other = Fixture::new();
            let mut wal = other.open(true).unwrap();
            other.begin(&mut wal, 0);
            fs::copy(
                other.root.path().join("row-00000000000000000001.json"),
                f.root.path().join("row-00000000000000000001.json"),
            )
            .unwrap();
        } else {
            let path = f.root.path().join("publication.stage");
            let mut changed = fs::read(&path).unwrap();
            changed[0] ^= 1;
            fs::write(path, changed).unwrap();
        }
        assert!(
            f.open(true).is_err(),
            "initialization cannot replace foreign stage bytes or populated history"
        );
        assert!(!f.root.path().join("checkpoint.json").exists());
        assert!(f.root.path().join("publication.stage").exists());
    }
}

#[test]
fn partial_envelope_without_exact_source_retains_unique_lost_bytes() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let reserve = f.begin(&mut wal, 0);
    wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
        .unwrap();
    f.fault(WalStep::Rename, 0);
    assert!(wal.freeze_envelope(&canonical(&f.records[0])).is_err());
    let stage = f.root.path().join("publication.stage");
    let bytes = fs::read(&stage).unwrap();
    fs::write(&stage, &bytes[..bytes.len() / 2]).unwrap();
    drop(wal);
    assert!(
        f.open(false).is_err(),
        "missing exact envelope source stays held for recovery"
    );
    assert_eq!(fs::read(stage).unwrap(), bytes[..bytes.len() / 2]);
}

#[test]
fn reloaded_unknown_row_never_mints_a_marker_completion() {
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    f.append(&mut wal, 0);
    assert!(test_support::mark_effect(&mut wal, BusinessSequence(1)).is_ok());
    drop(wal);
    let mut reopened = f.open(false).unwrap();
    use castle_wall_daemon::business_profile::effect_permit::{EffectIntent, EffectPermit};
    let body = &f.records[0]["body"];
    let intent = EffectIntent::OpenAdmission {
        flow: body["payload"]["context"]["flow"].clone(),
        payload: body["payload"].clone(),
    };
    let permit = test_support::mark_effect(&mut reopened, BusinessSequence(1))
        .ok()
        .and_then(|marker| {
            EffectPermit::from_marker_for_test(
                marker,
                &intent,
                &canonical(&f.records[0]),
                "a".repeat(32),
                NOW,
                DEADLINE,
            )
        });
    assert!(
        permit.is_none(),
        "reloaded unknown row never mints an effect permit"
    );
}

#[test]
fn second_store_cannot_replace_the_live_lock_inode() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let owner = f.open(true).unwrap();
    let before = fs::metadata(f.root.path().join("business-wal.lock"))
        .unwrap()
        .ino();
    let other = f.open(false);
    assert!(
        matches!(other, Err(Refusal::Lock)),
        "second opener cannot replace a live lock owner"
    );
    assert_eq!(
        fs::metadata(f.root.path().join("business-wal.lock"))
            .unwrap()
            .ino(),
        before
    );
    assert_eq!(owner.committed_anchor(), &f.anchor);
}

#[test]
fn startup_recovery_retries_exact_commit_and_original_without_resign_or_effect() {
    use castle_wall_daemon::business_profile::writer_peer::Clock;
    let clock: Clock = Arc::new(|| Ok(NOW));
    for phase in 0..=3 {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let reserve = f.begin(&mut wal, 0);
        let reserved = authenticated_read(reserve.next());
        if phase >= 1 {
            wal.persist_sign_marker(&reserved, NOW).unwrap();
        }
        let envelope = canonical(&f.records[0]);
        if phase >= 2 {
            wal.freeze_envelope(&envelope).unwrap();
        }
        let original_id = original_request_id(&envelope);
        let mut frozen = None;
        if phase == 3 {
            assert!(matches!(
                wal.recovery_action(&reserved, &clock),
                Ok(RecoveryAction::Observe)
            ));
            let RecoveryAction::Retry(commit) = wal.recovery_action(&reserved, &clock).unwrap()
            else {
                panic!("exact commit plan");
            };
            frozen = Some(commit.bytes().to_vec());
        }
        drop(wal);
        let mut wal = f.open(false).unwrap();
        assert!(
            wal.persist_sign_marker(&reserved, NOW).is_err(),
            "outstanding-at-open never signs"
        );
        if phase < 2 {
            assert!(
                matches!(wal.recovery_action(&reserved, &clock), Err(Refusal::Held)),
                "missing E remains owned without a recovery SIGN"
            );
            continue;
        }
        if phase == 2 {
            assert!(matches!(
                wal.recovery_action(&reserved, &clock),
                Ok(RecoveryAction::Observe)
            ));
        }
        let mut proposed = None;
        for _ in 0..40 {
            let RecoveryAction::Retry(commit) = wal.recovery_action(&reserved, &clock).unwrap()
            else {
                panic!("retained exact commit");
            };
            if let Some(bytes) = &frozen {
                assert_eq!(
                    commit.bytes(),
                    bytes,
                    "every retry preserves exact COMMIT bytes and id"
                );
            } else {
                frozen = Some(commit.bytes().to_vec());
            }
            proposed = Some(commit.next().clone());
        }
        let proposed = proposed.unwrap();
        assert!(matches!(
            wal.recovery_action(&authenticated_read(&proposed), &clock),
            Ok(RecoveryAction::Observe)
        ));
        let RecoveryAction::Original {
            sequence,
            envelope: retained,
        } = wal
            .recovery_action(&authenticated_read(&proposed), &clock)
            .unwrap()
        else {
            panic!("retained exact original");
        };
        assert_eq!(sequence, BusinessSequence(1));
        assert_eq!(retained, envelope);
        assert_eq!(original_request_id(&retained), original_id);
        assert!(
            test_support::mark_effect(&mut wal, sequence).is_err(),
            "rediscovered COMMIT never revives a permit"
        );
        wal.persist_d_fact(sequence, authenticated_original(&retained))
            .unwrap();
        assert!(
            matches!(
                wal.recovery_action(&authenticated_read(&proposed), &clock),
                Err(Refusal::Conflict)
            ),
            "a stale drained cursor cannot override the durable ORIGINAL fact"
        );
        let mut drained = proposed;
        drained["drained_sequence"] = json!(1);
        drained["drained_digest"] =
            append_contract::identity(&retained).unwrap()["commitment"].clone();
        assert!(matches!(
            wal.recovery_action(&authenticated_read(&drained), &clock),
            Ok(RecoveryAction::Ready)
        ));
        assert_eq!(wal.committed_anchor(), &drained);
        assert!(
            f.root.path().join("row-00000000000000000001.json").exists(),
            "startup settlement never infers a missing TS fact"
        );
    }
}

#[test]
fn control_reserve_preserves_fact_completion_after_refused_admission_and_reopen() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use castle_wall_daemon::business_profile::{records, signer_contract, writer_protocol};
    use ed25519_dalek::{Signer, SigningKey};
    let row_max = (2 * 4 * d::D_REQUEST_MAX_BYTES.div_ceil(3)
        + 4 * castle_wall_daemon::business_profile::records_schema::MAX_BYTES.div_ceil(3)
        + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
        + 32 * 128) as u64;
    let checkpoint_max = (4 * records::JOIN_STATE_BYTES_MAX.div_ceil(3)
        + castle_wall_daemon::business_profile::activation_anchor::MAX_BYTES
        + 32 * 128) as u64;
    let mut f = Fixture::new();
    let vectors: Value = serde_json::from_str(include_str!(
        "../../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "control-branch-23-accept")
        .unwrap();
    f.initial = case["initial"].clone();
    let key = SigningKey::from_bytes(&[7; 32]); // Public synthetic fixture seed.
    let kid = castle_wall_daemon::business_profile::role_kid(
        d::DRAIN_SLOTS[0].1,
        1,
        &key.verifying_key().to_bytes(),
    )
    .unwrap();
    f.initial["pin"]["kid"] = json!(kid);
    f.initial["pin"]["public_key"] = json!(URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()));
    f.records.clear();
    let mut relying = f.initial.clone();
    // Three real rows suffice; the other eleven retained rows enter only the bounded accounting seam.
    for sequence in 1..=3 {
        let mut body = case["records"][0]["body"].clone();
        body["kid"] = json!(kid);
        body["sequence"] = json!(sequence);
        body["prior_commitment"] = relying["anchor"]["commitment"].clone();
        let bytes = canonical(&body);
        let signature = key
            .sign(&[signer_contract::ROLE_REGISTRY[0].1.as_bytes(), &bytes].concat())
            .to_bytes();
        let record = writer_protocol::decode_envelope(
            &writer_protocol::envelope(&bytes, &signature).unwrap(),
        )
        .unwrap();
        relying = records::advance(&relying, &record).unwrap();
        f.records.push(record);
    }
    let complete = |wal: &mut BusinessWal, index: usize, reserve: &FrozenMutation| {
        wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
            .unwrap();
        let envelope = canonical(&f.records[index]);
        assert_eq!(
            wal.freeze_envelope(&envelope),
            Ok(()),
            "Control E freeze completes in reserved headroom"
        );
        let identity = append_contract::identity(&envelope).unwrap();
        let mut next = reserve.next().clone();
        next["committed_sequence"] = identity["sequence"].clone();
        next["committed_digest"] = identity["commitment"].clone();
        next["reserved_body_digest"] = Value::Null;
        let commit = mutation(
            json!({"version":1,"op":"COMMIT","request_id":format!("{:032x}", 2 * index + 2),"expected":reserve.next(),"next":next,"body_digest":digest(&canonical(&f.records[index]["body"]))}),
            &envelope,
        );
        wal.freeze_commit(&commit).unwrap();
        wal.confirm_commit(&authenticated_read(commit.next()))
            .unwrap();
        envelope
    };
    let mut wal = f.open(true).unwrap();
    let reserve = f.reserve(&wal, 0);
    wal.freeze_body(
        &canonical(&f.records[0]["body"]),
        &reserve,
        DEADLINE,
        EXPIRY,
        Pool::Control,
    )
    .unwrap();
    let envelope = complete(&mut wal, 0, &reserve);
    let retained_other_rows = 11 * row_max;
    let journal = test_support::journal_reserve();
    test_support::accounting(
        &mut wal,
        journal,
        checkpoint_max + retained_other_rows + row_max + journal,
        12,
    );
    // Continue any extra admitted row so the following completion assertion, not an admission check, discriminates headroom.
    for _ in 0..2 {
        let index = wal.committed_anchor()["committed_sequence"]
            .as_u64()
            .unwrap() as usize;
        let reserve = f.reserve(&wal, index);
        match wal.freeze_body(
            &canonical(&f.records[index]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Control,
        ) {
            Ok(_) => {
                complete(&mut wal, index, &reserve);
            }
            Err(Refusal::Capacity) => {}
            other => panic!("Control admission has a typed capacity boundary: {other:?}"),
        }
    }
    assert_eq!(
        wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope)),
        Ok(()),
        "Control D fact completion survives refused admission"
    );
    let token = wal.next_delivery().unwrap().unwrap().1;
    assert_eq!(
        wal.persist_ts_fact(BusinessSequence(1), sink().deliver(&token).unwrap()),
        Ok(()),
        "Control TS fact completion survives refused admission"
    );
    assert!(
        !f.root.path().join("row-00000000000000000002.json").exists(),
        "refused Control admission leaves no orphan"
    );
    drop(wal);
    assert!(
        test_support::reopen_accounted(
            f.root.path(),
            unsafe { libc::geteuid() },
            Box::new(f.faults.clone()),
            [journal, retained_other_rows + journal]
        )
        .is_ok(),
        "near-full Control reopen retains completion headroom"
    );
}

#[test]
fn journal_recovers_exact_envelope_and_fact_successors_without_old_effects() {
    for successor in ["envelope", "d_fact", "ts_fact"] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let envelope = if successor == "envelope" {
            let reserve = f.begin(&mut wal, 0);
            wal.persist_sign_marker(&authenticated_read(reserve.next()), NOW)
                .unwrap();
            canonical(&f.records[0])
        } else {
            f.append(&mut wal, 0)
        };
        f.fault(WalStep::Rename, 0);
        let result = match successor {
            "envelope" => wal.freeze_envelope(&envelope),
            "d_fact" => wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope)),
            _ => {
                let token = wal.next_delivery().unwrap().unwrap().1;
                wal.persist_ts_fact(BusinessSequence(1), sink().deliver(&token).unwrap())
            }
        };
        assert!(result.is_err());
        drop(wal);
        let mut reopened = f.open(false).unwrap();
        assert!(
            test_support::mark_effect(&mut reopened, BusinessSequence(1)).is_err(),
            "recovered successor never revives an effect"
        );
        let row: Value = serde_json::from_slice(
            &fs::read(f.root.path().join("row-00000000000000000001.json")).unwrap(),
        )
        .unwrap();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(row["payload"]["envelope"].as_str().unwrap())
                .unwrap(),
            envelope,
            "journal successor retains exact first envelope bytes"
        );
        if successor != "envelope" {
            assert!(
                row["payload"][successor].is_object(),
                "complete owned fact successor is recovered"
            );
        }
    }
}

#[test]
fn near_full_pools_retire_only_proven_orphan_and_preserve_next_append() {
    use castle_wall_daemon::business_profile::{
        activation_anchor, records, records_schema, writer_protocol,
    };
    let row = (2 * 4 * d::D_REQUEST_MAX_BYTES.div_ceil(3)
        + 4 * records_schema::MAX_BYTES.div_ceil(3)
        + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
        + 32 * 128) as u64;
    let checkpoint = (4 * records::JOIN_STATE_BYTES_MAX.div_ceil(3)
        + activation_anchor::MAX_BYTES
        + 32 * 128) as u64;
    let f = Fixture::new();
    let mut wal = f.open(true).unwrap();
    let journal = test_support::journal_reserve();
    // One new Ordinary row reaches the accepted 243 ceiling while all twelve Control charges remain retained.
    let occupied = [242 * row + journal, 12 * row + journal];
    test_support::accounting(&mut wal, occupied[0], occupied[1] + checkpoint, 242 + 12);
    let reserve = f.reserve(&wal, 0);
    f.fault(WalStep::Rename, 1);
    assert!(wal
        .freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        )
        .is_err());
    drop(wal);
    let observation = authenticated_read(&f.anchor);
    let mut reopened = test_support::reopen_recovering_accounted(
        f.root.path(),
        unsafe { libc::geteuid() },
        Box::new(f.faults.clone()),
        occupied,
        &observation,
        &(Arc::new(|| Ok(NOW)) as castle_wall_daemon::business_profile::writer_peer::Clock),
    )
    .unwrap();
    assert!(
        !f.root.path().join("row-00000000000000000001.json").exists(),
        "near-full retirement removes only proven unreserved orphan"
    );
    assert_eq!(
        reopened.charged_bytes(),
        (occupied[0], occupied[1] + checkpoint)
    );
    assert_eq!(
        f.begin(&mut reopened, 0).bytes(),
        reserve.bytes(),
        "near-full retirement preserves exact next append authority"
    );
}

fn journal_owner_mismatch(field: &str) {
    let f = Fixture::new();
    f.fault(WalStep::Rename, 0);
    assert!(f.open(true).is_err());
    let path = f.root.path().join("publication.journal");
    let original = fs::read(&path).unwrap();
    let mut journal: Value = serde_json::from_slice(&original).unwrap();
    journal["payload"][field] = json!(journal["payload"][field].as_u64().unwrap() + 1);
    journal["storage_checksum"] = json!(digest(&canonical(&journal["payload"])));
    fs::write(&path, canonical(&journal)).unwrap();
    assert!(
        f.open(true).is_err(),
        "journal owner/version mismatch remains held: {field}"
    );
    fs::write(&path, original).unwrap();
    assert!(
        f.open(true).is_ok(),
        "restored exact journal resumes initialization"
    );
}
#[test]
fn journal_version_is_independent_recovery_authority() {
    journal_owner_mismatch("version");
}
#[test]
fn journal_root_device_is_independent_recovery_authority() {
    journal_owner_mismatch("root_device");
}
#[test]
fn journal_root_inode_is_independent_recovery_authority() {
    journal_owner_mismatch("root_inode");
}
#[test]
fn journal_lock_inode_is_independent_recovery_authority() {
    journal_owner_mismatch("lock_inode");
}

#[test]
fn journal_does_not_trust_a_well_formed_but_unmatched_staged_checkpoint() {
    let f = Fixture::new();
    f.fault(WalStep::Rename, 0);
    assert!(f.open(true).is_err());
    let path = f.root.path().join("publication.stage");
    let original = fs::read(&path).unwrap();
    let mut stage: Value = serde_json::from_slice(&original).unwrap();
    stage["payload"]["next_cursor"] = json!(2); // Genesis owns cursor one; this stage proposes the next cursor without its row.
    stage["storage_checksum"] = json!(digest(&canonical(&stage["payload"])));
    fs::write(&path, canonical(&stage)).unwrap();
    assert!(
        f.open(true).is_err(),
        "unverified staged checkpoint cannot expose a cursor"
    );
    fs::write(&path, original).unwrap();
    assert!(
        f.open(true).is_ok(),
        "restored exact stage can finish initialization"
    );
}
