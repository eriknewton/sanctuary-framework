// fail-before-exempt: maximal allocation and restart witnesses use native isolated WAL files and authenticated fixture observations.
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
        assert!(
            matches!(wal.compact_one(), Ok(false)),
            "one fact never releases the original"
        );
        assert!(row.exists());
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
            2 * allocation_charge,
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
    let _ = wal.freeze_body(
        &canonical(&f.records[1]["body"]),
        &reserve,
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
