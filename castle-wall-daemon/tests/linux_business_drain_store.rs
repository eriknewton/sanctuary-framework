// fail-before-exempt: the durable store is new; isolated predicate mutations supply evidence.
#![cfg(target_os = "linux")]
mod isolation;
use castle_wall_daemon::business_profile::{
    activation_anchor as anchor, drain_store::*, records, writer_protocol,
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
const SLOT: &str = DRAIN_SLOTS[0].0;
const FORTRESS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static SERIAL: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    seam: PathBuf,
    held: HeldRoot,
    lock: StateLock,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "drain-store-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let seam = root.with_extension("seam");
        fs::create_dir(&seam).unwrap();
        fs::set_permissions(&seam, fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: geteuid only observes this test process; expected ownership is identical under root CI and this box.
        let owner = unsafe { libc::geteuid() };
        let held = HeldRoot::isolated_under(&root, owner).unwrap();
        let lock = StateLock::acquire(&held).unwrap();
        Self {
            root,
            seam,
            held,
            lock,
        }
    }
    fn store(&self) -> Store<'_> {
        self.try_store().unwrap()
    }
    fn try_store(&self) -> Result<Store<'_>, StoreRefusal> {
        // SAFETY: the test's euid supplies required ownership evidence, never a production root path.
        Store::open(
            &self.held,
            FORTRESS,
            &self.lock,
            unsafe { libc::geteuid() },
            StoreFaults::from_seam_root(&self.seam).unwrap(),
            EventSink::from_seam_root(&self.seam).unwrap(),
        )
    }
    fn fault(&self, publication: &str, step: StoreStep, position: &str, action: &str, times: u64) {
        fs::write(self.seam.join("store-faults.json"),serde_json::to_vec(&json!([{"slot":SLOT,"publication":publication,"step":format!("{step:?}"),"position":position,"action":action,"value":null,"times":times}])).unwrap()).unwrap();
    }
    fn clear(&self) {
        fs::write(self.seam.join("store-faults.json"), "[]").unwrap();
    }
    fn record_path(&self) -> PathBuf {
        self.root
            .join(FORTRESS)
            .join("anchors")
            .join(format!("{SLOT}.json"))
    }
    fn copies_path(&self) -> PathBuf {
        self.root.join(FORTRESS).join("originals").join(SLOT)
    }
    fn events(&self) -> Vec<Value> {
        fs::read_to_string(self.seam.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Cleanup removes leaves from the fixed fixture layout, then each empty directory explicitly.
        for dir in [
            self.copies_path(),
            self.root.join(FORTRESS).join("anchors"),
            self.root.join(FORTRESS).join("originals"),
            self.root.join(FORTRESS),
            self.seam.clone(),
            self.root.clone(),
        ] {
            if let Ok(entries) = fs::read_dir(&dir) {
                for e in entries.flatten() {
                    if e.file_type().is_ok_and(|t| !t.is_dir()) {
                        let _ = fs::remove_file(e.path());
                    } else {
                        // Failure fixtures may leave an empty staging directory; remove only that empty leaf.
                        let _ = fs::remove_dir(e.path());
                    }
                }
                let _ = fs::remove_dir(dir);
            }
        }
    }
}
fn closure() -> Value {
    serde_json::from_str(include_str!("../src/business_profile/closure_vectors.json")).unwrap()
}
fn record(a: Value, phase: Phase) -> DrainRecord {
    let count = (a["committed_sequence"].as_u64().unwrap()
        - a["drained_sequence"].as_u64().unwrap()) as usize;
    DrainRecord {
        ledger: vec![a["committed_digest"].as_str().unwrap().into(); count],
        anchor: a,
        last: LastOp {
            authority: Authority::for_phase(phase),
            phase,
            request_id: "c".repeat(32),
            request_sha256: format!("sha256:{}", "d".repeat(64)),
        },
    }
}
fn genesis() -> DrainRecord {
    record(closure()["anchor"].clone(), Phase::PREPARE)
}
fn envelope(sequence: u64) -> Vec<u8> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    let mut body = corpus["cases"][0]["records"][0]["body"].clone();
    body["sequence"] = json!(sequence);
    let body = castle_wall_daemon::smb::jcs::encode(&body).unwrap();
    writer_protocol::envelope(body.as_bytes(), &[0; 64]).unwrap()
}
fn committed(bytes: &[u8]) -> DrainRecord {
    let mut r = genesis();
    let digest =
        records::join_commitment(&writer_protocol::decode_envelope(bytes).unwrap()).unwrap();
    r.anchor["reserved_sequence"] = json!(1);
    r.anchor["committed_sequence"] = json!(1);
    r.anchor["committed_digest"] = json!(digest);
    r.ledger = vec![digest];
    r.last.phase = Phase::RECORD_COMMIT;
    r.last.authority = Authority::W;
    r
}
fn drained(mut r: DrainRecord) -> DrainRecord {
    r.anchor["drained_sequence"] = r.anchor["committed_sequence"].clone();
    r.anchor["drained_digest"] = r.anchor["committed_digest"].clone();
    r.ledger.clear();
    r.last.phase = Phase::DRAIN;
    r
}
const STEPS: [StoreStep; 6] = [
    StoreStep::Stage,
    StoreStep::Write,
    StoreStep::FileSync,
    StoreStep::Rename,
    StoreStep::DirSync,
    StoreStep::Readback,
];
fn post_rename(step: StoreStep, position: &str) -> bool {
    matches!(step, StoreStep::DirSync | StoreStep::Readback)
        || step == StoreStep::Rename && position == "after"
}
#[test]
fn every_record_image_cut_preserves_observation_and_recovers() {
    let _guard = isolation::guard();
    let corpus = closure();
    for (id, phase) in [
        ("prepare", Phase::PREPARE),
        ("custody-commit", Phase::CUSTODY_COMMIT),
        ("reserve", Phase::RESERVE),
        ("commit", Phase::RECORD_COMMIT),
        ("latch", Phase::LATCH),
        ("advance_generation", Phase::ADVANCE_GENERATION),
    ] {
        let c = corpus["anchors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        let old = record(c["old"].clone(), Phase::PREPARE);
        let next = record(c["next"].clone(), phase);
        for step in STEPS {
            for position in ["before", "after"] {
                let fixture = Fixture::new();
                let mut store = fixture.store();
                assert_eq!(store.publish_record(SLOT, &old), PublishOutcome::Durable);
                let before = fixture.events().len();
                fixture.fault("record", step, position, "fail", 1);
                let outcome = store.publish_record(SLOT, &next);
                assert_eq!(
                    matches!(outcome, PublishOutcome::Uncertain(_)),
                    post_rename(step, position),
                    "{id} {step:?} {position}: {outcome:?}"
                );
                assert!(fixture.events()[before..]
                    .iter()
                    .any(|e| e["event"] == "StoreEntered"));
                assert_eq!(
                    store.observe(SLOT).anchor,
                    Some(old.anchor.clone()),
                    "{id} {step:?} {position}"
                );
                if post_rename(step, position) {
                    assert!(
                        matches!(outcome, PublishOutcome::Uncertain(_)),
                        "{id} {step:?} {position}: {outcome:?}"
                    );
                    assert!(store.observe(SLOT).uncertain);
                    assert!(matches!(
                        store.publish_record(SLOT, &next),
                        PublishOutcome::Uncertain(StoreRefusal::UNCERTAIN)
                    ));
                    fixture.fault("record", StoreStep::DirSync, "before", "fail", 2);
                    assert!(store.reconcile(SLOT).is_err());
                    assert!(store.observe(SLOT).uncertain);
                    fixture.clear();
                    store.reconcile(SLOT).unwrap();
                    assert_eq!(store.observe(SLOT).anchor, Some(next.anchor.clone()));
                } else {
                    assert!(
                        matches!(outcome, PublishOutcome::PrePublication(_)),
                        "{id} {step:?} {position}: {outcome:?}"
                    );
                    assert!(!store.observe(SLOT).uncertain);
                    assert_eq!(
                        fs::read(fixture.record_path()).unwrap(),
                        encode_record(&old).unwrap()
                    );
                }
                let disk = validate_role_state(&fixture.held, FORTRESS).unwrap();
                assert_eq!(
                    disk.record.as_ref().map(|r| &r.anchor),
                    Some(if post_rename(step, position) {
                        &next.anchor
                    } else {
                        &old.anchor
                    })
                );
                let observation = store.observe(SLOT);
                drop(store);
                fixture.clear();
                let restarted = fixture.store();
                assert_eq!(restarted.observe(SLOT), observation);
                assert!(fs::read_dir(fixture.record_path().parent().unwrap())
                    .unwrap()
                    .all(|e| !e
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".staging")));
            }
        }
    }
}
#[test]
fn every_copy_cut_and_orphan_reuse_preserves_the_anchor() {
    let _guard = isolation::guard();
    let bytes = envelope(1);
    let r = committed(&bytes);
    for step in STEPS {
        for position in ["before", "after"] {
            let fixture = Fixture::new();
            let mut store = fixture.store();
            assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
            fixture.fault("copy", step, position, "fail", 1);
            let outcome = store.publish_original(SLOT, 1, &bytes);
            assert_eq!(store.observe(SLOT).anchor, Some(r.anchor.clone()));
            if post_rename(step, position) {
                assert!(matches!(outcome, PublishOutcome::Uncertain(_)));
                assert!(matches!(
                    store.publish_record(SLOT, &drained(r.clone())),
                    PublishOutcome::Uncertain(_)
                ));
                fixture.clear();
                store.reconcile(SLOT).unwrap();
                assert_eq!(store.copy(SLOT, 1), Some(bytes.as_slice()));
            } else {
                assert!(matches!(outcome, PublishOutcome::PrePublication(_)));
                assert_eq!(store.usage(), CopyUsage::default());
            }
            drop(store);
            fixture.clear();
            let mut store = fixture.store();
            assert_eq!(
                store.publish_original(SLOT, 1, &bytes),
                PublishOutcome::Durable
            );
            assert_eq!(
                store.usage(),
                CopyUsage {
                    bytes: bytes.len() as u64,
                    entries: 1
                }
            );
            let before = fixture.events().len();
            let mut different = bytes.clone();
            different[0] ^= 1;
            assert_eq!(
                store.publish_original(SLOT, 1, &different),
                PublishOutcome::PrePublication(StoreRefusal::ORPHAN)
            );
            assert!(!store.observe(SLOT).uncertain);
            assert_eq!(
                store.publish_original(SLOT, 1, &bytes),
                PublishOutcome::Durable
            );
            assert!(!fixture.events()[before..]
                .iter()
                .any(|e| e["step"] == "Stage"));
            assert_eq!(
                store.publish_record(SLOT, &drained(r.clone())),
                PublishOutcome::Durable
            );
            drop(store);
            let store = fixture.store();
            assert_eq!(store.copy(SLOT, 1), Some(bytes.as_slice()));
        }
    }
}
#[test]
fn readback_mismatch_and_directory_sync_are_independent_predicates() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let old = genesis();
    assert_eq!(store.publish_record(SLOT, &old), PublishOutcome::Durable);
    let mut next = old.clone();
    next.anchor["generation_high_water"] = json!(1);
    fixture.fault("record", StoreStep::Readback, "before", "alter_readback", 1);
    assert_eq!(
        store.publish_record(SLOT, &next),
        PublishOutcome::Uncertain(StoreRefusal::READBACK)
    );
    fixture.fault("record", StoreStep::DirSync, "before", "fail", 3);
    assert!(store.reconcile(SLOT).is_err());
    assert!(store.observe(SLOT).uncertain);
    fixture.clear();
    store.reconcile(SLOT).unwrap();
    assert!(!store.observe(SLOT).uncertain);
    store.mark_uncertain(SLOT);
    assert!(store.observe(SLOT).uncertain);
    store.reconcile(SLOT).unwrap();
    // A matching old image clears only after directory sync, while unrelated bytes keep the role uncertain.
    store.mark_uncertain(SLOT);
    fs::write(fixture.record_path(), b"unrelated").unwrap();
    assert!(store.reconcile(SLOT).is_err());
    assert!(store.observe(SLOT).uncertain);
    fs::write(fixture.record_path(), encode_record(&old).unwrap()).unwrap();
    store.reconcile(SLOT).unwrap();
    assert_eq!(store.observe(SLOT).anchor, Some(old.anchor));
}
#[test]
fn original_record_prepublication_failure_keeps_a_verified_charged_orphan() {
    let _guard = isolation::guard();
    for step in [
        StoreStep::Stage,
        StoreStep::Write,
        StoreStep::FileSync,
        StoreStep::Rename,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let bytes = envelope(1);
        let r = committed(&bytes);
        assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
        assert_eq!(
            store.publish_original(SLOT, 1, &bytes),
            PublishOutcome::Durable
        );
        let usage = store.usage();
        fixture.fault("record", step, "before", "fail", 1);
        assert!(matches!(
            store.publish_record(SLOT, &drained(r.clone())),
            PublishOutcome::PrePublication(_)
        ));
        assert!(!store.observe(SLOT).uncertain);
        assert_eq!(store.record(SLOT), Some(&r));
        assert_eq!(store.copy(SLOT, 1), Some(bytes.as_slice()));
        assert_eq!(store.usage(), usage);
        assert!(!fixture
            .record_path()
            .with_file_name(format!(".{SLOT}.json.staging"))
            .exists());
        let mut conflict = bytes.clone();
        conflict[0] ^= 1;
        assert_eq!(
            store.publish_original(SLOT, 1, &conflict),
            PublishOutcome::PrePublication(StoreRefusal::ORPHAN)
        );
        fixture.clear();
        assert_eq!(
            store.publish_original(SLOT, 1, &bytes),
            PublishOutcome::Durable
        );
        assert_eq!(
            store.publish_record(SLOT, &drained(r)),
            PublishOutcome::Durable
        );
        assert_eq!(store.usage(), usage);
    }
}

#[test]
fn startup_rejects_bad_ledger_orphan_strays_and_lock_contention() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let g = genesis();
    assert_eq!(store.observe(SLOT).state, ObservationState::Absent);
    assert_eq!(store.publish_record(SLOT, &g), PublishOutcome::Durable);
    drop(store);
    assert_eq!(
        fixture.store().observe(SLOT).state,
        ObservationState::Present
    );
    let staging = fixture
        .record_path()
        .with_file_name(format!(".{SLOT}.json.staging"));
    fs::write(&staging, b"unfinished").unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        StateLock::acquire(&fixture.held),
        Err(StoreRefusal::LOCK)
    ));
    assert!(staging.exists());
    drop(fixture.store());
    assert!(!staging.exists());
    let bytes = envelope(1);
    let r = committed(&bytes);
    let mut store = fixture.store();
    assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Durable
    );
    drop(store);
    assert_eq!(fixture.store().usage().entries, 1);
    let copy = fixture.copies_path().join(format!("{:020}.env", 1));
    fs::write(&copy, envelope(2)).unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::ORPHAN)
    ));
    fs::write(&copy, &bytes).unwrap();
    let mut malformed =
        serde_json::from_slice::<Value>(&fs::read(fixture.record_path()).unwrap()).unwrap();
    malformed["ledger"][0] = json!(format!("sha256:{}", "f".repeat(64)));
    fs::write(
        fixture.record_path(),
        castle_wall_daemon::smb::jcs::encode(&malformed).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::RECORD_LEDGER)
    ));
    fs::write(fixture.record_path(), encode_record(&r).unwrap()).unwrap();
    let stray = fixture.root.join("unknown");
    fs::write(&stray, b"x").unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::CAP) | Err(StoreRefusal::ENTRY)
    ));
    assert!(stray.exists());
    fs::remove_file(stray).unwrap();
    let mut store = fixture.store();
    assert_eq!(
        store.publish_record(SLOT, &drained(r)),
        PublishOutcome::Durable
    );
    drop(store);
    fs::write(&copy, envelope(2)).unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::COPY_TAIL)
    ));
}
#[test]
fn absent_means_no_copies_and_directory_sentinels_bound_startup() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    assert_eq!(
        store.publish_record(SLOT, &genesis()),
        PublishOutcome::Durable
    );
    drop(store);
    fs::remove_file(fixture.record_path()).unwrap();
    assert_eq!(
        fixture.store().observe(SLOT).state,
        ObservationState::Absent
    );
    let leaf = fixture.copies_path().join(format!("{:020}.env", 1));
    fs::write(&leaf, envelope(1)).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::COPY_SET)
    ));
    fs::remove_file(&leaf).unwrap();
    // Three root leaves exceed the permitted lock and fortress plus the one refusal sentinel.
    fs::write(fixture.root.join("stray"), b"").unwrap();
    assert!(matches!(
        validate_role_state(&fixture.held, FORTRESS),
        Err(StoreRefusal::CAP)
    ));
}
#[test]
fn phase_is_derived_from_request_and_authority_pairs_are_exact() {
    for phase in [
        Phase::PREPARE,
        Phase::CUSTODY_COMMIT,
        Phase::LATCH,
        Phase::ADVANCE_GENERATION,
        Phase::ADVANCE_ACTIVATION,
        Phase::ADVANCE_BOOT,
    ] {
        assert_eq!(Authority::for_phase(phase), Authority::S);
    }
    for phase in [Phase::RESERVE, Phase::RECORD_COMMIT, Phase::DRAIN] {
        assert_eq!(Authority::for_phase(phase), Authority::W);
    }
    assert_eq!(
        Phase::of_message(
            &json!({"op":"COMMIT","expected":{"transaction_id":"a"},"next":{"transaction_id":null}})
        ),
        Some(Phase::CUSTODY_COMMIT)
    );
    assert_eq!(
        Phase::of_message(
            &json!({"op":"COMMIT","expected":{"transaction_id":null},"next":{"transaction_id":"a"}})
        ),
        Some(Phase::RECORD_COMMIT)
    );
    for op in ["READ", "DRAIN", "RECOVERY_COMMIT"] {
        assert_eq!(Phase::of_message(&json!({"op":op})), None);
    }
}
fn maximal_anchor() -> Value {
    let mut a = closure()["anchor"].clone();
    for (key, domain) in anchor::ANCHOR_DOMAINS {
        a[*key] = match *domain {
            "id" | "nullableId" => json!("f".repeat(anchor::ID_HEX_LENGTH)),
            "digest" | "nullableDigest" | "commitment" => {
                json!(format!("sha256:{}", "f".repeat(anchor::DIGEST_HEX_LENGTH)))
            }
            "safeInteger" | "positiveInteger" => json!(D_EPOCH_MAX),
            "boolean" => json!(false),
            "nullableReason" => json!("storage_fault"),
            _ => a[*key].clone(),
        };
    }
    a["committed_sequence"] = json!(D_EPOCH_MAX - 1);
    a["drained_sequence"] = json!(D_EPOCH_MAX - 1 - D_UNDRAINED_MAX as u64);
    a["recovery_required"] = json!(true);
    a
}
#[test]
fn maximal_record_bounds_are_measured_from_canonical_images() {
    let a = maximal_anchor();
    assert!(anchor::valid(&a));
    let last = LastOp {
        authority: Authority::S,
        phase: Phase::ADVANCE_GENERATION,
        request_id: "f".repeat(32),
        request_sha256: format!("sha256:{}", "f".repeat(64)),
    };
    let encode = |v: &Value| castle_wall_daemon::smb::jcs::encode(v).unwrap().len();
    let anchor_size = encode(&a);
    let last_size = encode(&serde_json::to_value(&last).unwrap());
    let fixed = encode(&json!({"version":1,"anchor":a,"last":last,"ledger":[]}));
    let message = encode(
        &json!({"version":1,"op":"ADVANCE_GENERATION","request_id":"f".repeat(32),"expected":a,"next":a,"body_digest":format!("sha256:{}","f".repeat(64))}),
    );
    let r = DrainRecord {
        anchor: a.clone(),
        last,
        ledger: vec![format!("sha256:{}", "f".repeat(64)); D_UNDRAINED_MAX],
    };
    let bytes = encode_record(&r).unwrap();
    eprintln!(
        "MEASURED anchor={anchor_size} message={message} last={last_size} fixed={fixed} record={}",
        bytes.len()
    );
    assert_eq!(anchor_size, D_ANCHOR_MAX_BYTES);
    assert_eq!(message, D_ANCHOR_MESSAGE_MAX_BYTES);
    assert_eq!(last_size, D_LAST_MAX_BYTES);
    assert_eq!(fixed, D_RECORD_FIXED_BYTES);
    assert_eq!(bytes.len(), D_RECORD_MAX_BYTES);
    assert_eq!(decode_record(&bytes).unwrap(), r);
    let double = encode(
        &json!({"version":1,"anchor":a,"last":r.last,"ledger":vec![format!("sha256:{}","f".repeat(64));D_UNDRAINED_MAX*2]}),
    );
    assert!(double > anchor::MAX_BYTES);
}
#[test]
fn seams_are_feature_gated_and_no_service_calls_the_store() {
    let source = include_str!("../src/business_profile/drain_store.rs");
    assert!(
        source.contains("#[cfg(feature=\"test-isolation\")]\n    pub fn from_seam_root")
            || source.contains("#[cfg(feature = \"test-isolation\")]\n    pub fn from_seam_root")
    );
    assert!(!include_str!("../src/business_profile/writer_service.rs").contains("drain_store"));
    assert!(!include_str!("../src/business_profile/signer_service.rs").contains("drain_store"));
}

#[test]
fn rename_syscall_error_with_same_verified_inode_stays_open() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let old = genesis();
    assert_eq!(store.publish_record(SLOT, &old), PublishOutcome::Durable);
    let mut next = old.clone();
    next.anchor["generation_high_water"] = json!(1);
    fs::write(fixture.seam.join("store-faults.json"),serde_json::to_vec(&json!([{"slot":SLOT,"publication":"record","step":"FileSync","position":"after","action":"hold","value":"rename","times":1}])).unwrap()).unwrap();
    let staged = fixture
        .record_path()
        .with_file_name(format!(".{SLOT}.json.staging"));
    let release = fixture.seam.join("release-rename");
    std::thread::scope(|scope| {
        let driver = scope.spawn(|| {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis((D_REQUEST_DEADLINE_MS * 5) as u64);
            while !staged.exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Removing only the staged name forces renameat itself to fail while the old target inode remains intact.
            fs::remove_file(&staged).unwrap();
            fs::write(release, b"release").unwrap();
        });
        assert_eq!(
            store.publish_record(SLOT, &next),
            PublishOutcome::PrePublication(StoreRefusal::RENAME)
        );
        driver.join().unwrap();
    });
    assert!(!store.observe(SLOT).uncertain);
    assert_eq!(store.observe(SLOT).anchor, Some(old.anchor));
    assert!(fixture
        .events()
        .iter()
        .any(|e| e["event"] == "StoreResumed"));
}

#[test]
fn copy_caps_refuse_without_eviction_and_oversize_records_do_no_io() {
    let _guard = isolation::guard();
    for entries_cap in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        assert_eq!(
            store.publish_record(SLOT, &genesis()),
            PublishOutcome::Durable
        );
        drop(store);
        let count = if entries_cap {
            D_COPY_ENTRIES_MAX
        } else {
            D_COPY_MAX_BYTES as usize / writer_protocol::WRITER_ENVELOPE_MAX_BYTES + 1
        };
        let tail = envelope(count as u64);
        let next = envelope(count as u64 + 1);
        let desired = if entries_cap {
            tail.len() as u64
        } else {
            D_COPY_MAX_BYTES - next.len() as u64 + 1
        };
        let mut remaining = desired - tail.len() as u64;
        for seq in 1..count {
            let f = fs::File::create(fixture.copies_path().join(format!("{seq:020}.env"))).unwrap();
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .unwrap();
            let len = remaining.min(writer_protocol::WRITER_ENVELOPE_MAX_BYTES as u64);
            f.set_len(len).unwrap();
            remaining -= len;
        }
        assert_eq!(remaining, 0);
        let tail_path = fixture.copies_path().join(format!("{count:020}.env"));
        fs::write(&tail_path, &tail).unwrap();
        fs::set_permissions(&tail_path, fs::Permissions::from_mode(0o600)).unwrap();
        let tail_digest =
            records::join_commitment(&writer_protocol::decode_envelope(&tail).unwrap()).unwrap();
        let next_digest =
            records::join_commitment(&writer_protocol::decode_envelope(&next).unwrap()).unwrap();
        let mut r = genesis();
        r.anchor["drained_sequence"] = json!(count);
        r.anchor["drained_digest"] = json!(tail_digest);
        r.anchor["reserved_sequence"] = json!(count + 1);
        r.anchor["committed_sequence"] = json!(count + 1);
        r.anchor["committed_digest"] = json!(next_digest);
        r.ledger = vec![next_digest];
        fs::write(fixture.record_path(), encode_record(&r).unwrap()).unwrap();
        let mut store = fixture.store();
        let before = store.usage();
        assert_eq!(
            store.publish_original(SLOT, count as u64 + 1, &next),
            PublishOutcome::PrePublication(StoreRefusal::CAP)
        );
        assert_eq!(store.usage(), before);
        assert_eq!(
            before,
            CopyUsage {
                bytes: desired,
                entries: count
            }
        );
        assert_eq!(fs::read(tail_path).unwrap(), tail);
    }
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let mut oversized = genesis();
    oversized.ledger = vec![format!("sha256:{}", "f".repeat(64)); D_UNDRAINED_MAX * 2];
    assert_eq!(
        store.publish_record(SLOT, &oversized),
        PublishOutcome::PrePublication(StoreRefusal::STAGE)
    );
    assert!(!fixture.record_path().exists());
    assert!(!fixture
        .events()
        .iter()
        .any(|e| e["event"] == "StoreEntered"));
}

#[test]
fn genesis_cuts_reopen_without_inventing_a_proposal() {
    let _guard = isolation::guard();
    for step in STEPS {
        for position in ["before", "after"] {
            let fixture = Fixture::new();
            let mut store = fixture.store();
            fixture.fault("record", step, position, "fail", 1);
            let outcome = store.publish_record(SLOT, &genesis());
            assert_eq!(store.observe(SLOT).state, ObservationState::Absent);
            assert_eq!(store.observe(SLOT).uncertain, post_rename(step, position));
            assert_eq!(
                matches!(outcome, PublishOutcome::Uncertain(_)),
                post_rename(step, position)
            );
            drop(store);
            // Restart must obtain fresh durability evidence; the fault remains armed until explicitly cleared.
            if step == StoreStep::DirSync {
                assert!(matches!(fixture.try_store(), Err(StoreRefusal::DIR_SYNC)));
            }
            fixture.clear();
            let restarted = fixture.store();
            assert_eq!(
                restarted.observe(SLOT).state,
                if post_rename(step, position) {
                    ObservationState::Present
                } else {
                    ObservationState::Absent
                }
            );
            assert_eq!(restarted.usage(), CopyUsage::default());
            assert!(!restarted.observe(SLOT).uncertain);
        }
    }
}

#[test]
fn failed_staging_cleanup_blocks_until_verified_reconciliation() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let old = genesis();
    assert_eq!(store.publish_record(SLOT, &old), PublishOutcome::Durable);
    let mut next = old.clone();
    next.anchor["generation_high_water"] = json!(1);
    fs::write(fixture.seam.join("store-faults.json"), serde_json::to_vec(&json!([
        {"slot":SLOT,"publication":"record","step":"FileSync","position":"after","action":"hold","value":"cleanup","times":1},
        {"slot":SLOT,"publication":"record","step":"Rename","position":"before","action":"fail","value":null,"times":1}
    ])).unwrap()).unwrap();
    let staged = fixture
        .record_path()
        .with_file_name(format!(".{SLOT}.json.staging"));
    let release = fixture.seam.join("release-cleanup");
    std::thread::scope(|scope| {
        let driver = scope.spawn(|| {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis((D_REQUEST_DEADLINE_MS * 5) as u64);
            while !staged.exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // An unexpected directory at the staging leaf makes unlinkat refuse without deleting any directory.
            fs::remove_file(&staged).unwrap();
            fs::create_dir(&staged).unwrap();
            fs::write(release, b"release").unwrap();
        });
        assert!(matches!(
            store.publish_record(SLOT, &next),
            PublishOutcome::Uncertain(_)
        ));
        driver.join().unwrap();
    });
    assert_eq!(store.observe(SLOT).anchor, Some(old.anchor.clone()));
    assert!(store.reconcile(SLOT).is_err());
    assert!(store.observe(SLOT).uncertain);
    fs::remove_dir(staged).unwrap();
    fixture.clear();
    store.reconcile(SLOT).unwrap();
    assert_eq!(store.observe(SLOT).anchor, Some(old.anchor));
    assert!(!store.observe(SLOT).uncertain);
}

#[test]
fn rename_error_with_changed_or_untrusted_target_is_uncertain() {
    let _guard = isolation::guard();
    for change_bytes in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let old = genesis();
        assert_eq!(store.publish_record(SLOT, &old), PublishOutcome::Durable);
        let mut next = old.clone();
        next.anchor["generation_high_water"] = json!(1);
        fs::write(fixture.seam.join("store-faults.json"), serde_json::to_vec(&json!([
            {"slot":SLOT,"publication":"record","step":"FileSync","position":"after","action":"hold","value":"target","times":1}
        ])).unwrap()).unwrap();
        let staged = fixture
            .record_path()
            .with_file_name(format!(".{SLOT}.json.staging"));
        let release = fixture.seam.join("release-target");
        std::thread::scope(|scope| {
            let driver = scope.spawn(|| {
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_millis((D_REQUEST_DEADLINE_MS * 5) as u64);
                while !staged.exists() {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                fs::remove_file(&staged).unwrap();
                if change_bytes {
                    fs::write(fixture.record_path(), encode_record(&next).unwrap()).unwrap();
                } else {
                    fs::set_permissions(fixture.record_path(), fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                fs::write(release, b"release").unwrap();
            });
            assert_eq!(
                store.publish_record(SLOT, &next),
                PublishOutcome::Uncertain(StoreRefusal::RENAME)
            );
            driver.join().unwrap();
        });
        assert_eq!(store.observe(SLOT).anchor, Some(old.anchor.clone()));
        assert!(store.observe(SLOT).uncertain);
        fixture.clear();
        if !change_bytes {
            assert!(store.reconcile(SLOT).is_err());
            assert!(store.observe(SLOT).uncertain);
            fs::set_permissions(fixture.record_path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        store.reconcile(SLOT).unwrap();
        assert_eq!(
            store.observe(SLOT).anchor,
            Some(if change_bytes {
                next.anchor
            } else {
                old.anchor
            })
        );
        assert!(!store.observe(SLOT).uncertain);
    }
}

#[test]
fn startup_sync_failure_refuses_until_durability_is_reestablished() {
    let _guard = isolation::guard();
    for publication in ["root", "fortress", "record", "originals", "copy"] {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let attempted = genesis();
        fixture.fault("record", StoreStep::DirSync, "before", "fail", 1);
        assert_eq!(
            store.publish_record(SLOT, &attempted),
            PublishOutcome::Uncertain(StoreRefusal::DIR_SYNC)
        );
        drop(store);
        fixture.fault(publication, StoreStep::DirSync, "before", "fail", 1);
        assert!(
            matches!(fixture.try_store(), Err(StoreRefusal::DIR_SYNC)),
            "{publication}"
        );
        fixture.clear();
        let before = fixture.events().len();
        let store = fixture.store();
        assert!(!store.observe(SLOT).uncertain);
        assert_eq!(store.record(SLOT), Some(&attempted));
        let synced: Vec<_> = fixture.events()[before..]
            .iter()
            .filter(|e| e["event"] == "StepCompleted" && e["step"] == "DirSync")
            .map(|e| e["publication"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(synced, ["root", "fortress", "record", "originals", "copy"]);
    }
}

#[test]
fn directory_creation_and_chain_sync_failures_are_retry_safe() {
    let _guard = isolation::guard();
    for component in ["fortress", "anchors", "originals", "copies"] {
        for boundary in ["mkdir", "child", "parent"] {
            for position in ["before", "after"] {
                let fixture = Fixture::new();
                let mut store = fixture.store();
                let (label, step, refusal) = if boundary == "mkdir" {
                    (
                        format!("mkdir:{component}"),
                        StoreStep::HoldDirectory,
                        StoreRefusal::ROOT,
                    )
                } else {
                    (
                        format!("chain:{component}:{boundary}"),
                        StoreStep::DirSync,
                        StoreRefusal::DIR_SYNC,
                    )
                };
                fixture.fault(&label, step, position, "fail", 1);
                let before = fixture.events().len();
                assert_eq!(
                    store.publish_record(SLOT, &genesis()),
                    PublishOutcome::PrePublication(refusal)
                );
                assert!(!fixture.record_path().exists());
                assert!(!fixture.events()[before..]
                    .iter()
                    .any(|e| e["step"] == "Stage"));
                assert!(!store.observe(SLOT).uncertain);
                fixture.clear();
                let before = fixture.events().len();
                assert_eq!(
                    store.publish_record(SLOT, &genesis()),
                    PublishOutcome::Durable
                );
                assert_chain_before_stage(&fixture.events()[before..]);
                drop(store);
                fixture.fault("root", StoreStep::DirSync, "before", "fail", 1);
                assert!(matches!(fixture.try_store(), Err(StoreRefusal::DIR_SYNC)));
                fixture.clear();
                assert!(!fixture.store().observe(SLOT).uncertain);
            }
        }
    }
}
fn assert_chain_before_stage(events: &[Value]) {
    let staged = events.iter().position(|e| e["step"] == "Stage").unwrap();
    let synced: Vec<_> = events[..staged]
        .iter()
        .filter(|e| e["event"] == "StepCompleted" && e["step"] == "DirSync")
        .map(|e| e["publication"].as_str().unwrap())
        .collect();
    assert_eq!(
        synced,
        [
            "chain:fortress:child",
            "chain:fortress:parent",
            "chain:anchors:child",
            "chain:anchors:parent",
            "chain:originals:child",
            "chain:originals:parent",
            "chain:copies:child",
            "chain:copies:parent"
        ]
    );
}

#[test]
fn precreated_empty_directories_are_synced_before_staging() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    for path in [
        fixture.root.join(FORTRESS),
        fixture.root.join(FORTRESS).join("anchors"),
        fixture.root.join(FORTRESS).join("originals"),
        fixture.copies_path(),
    ] {
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut store = fixture.store();
    let before = fixture.events().len();
    assert_eq!(
        store.publish_record(SLOT, &genesis()),
        PublishOutcome::Durable
    );
    assert_chain_before_stage(&fixture.events()[before..]);
}

fn remove_staging_at_rename(
    fixture: &Fixture,
    publication: &str,
    target: PathBuf,
    publish: impl FnOnce() -> PublishOutcome,
) -> PublishOutcome {
    fs::write(fixture.seam.join("store-faults.json"), serde_json::to_vec(&json!([
        {"slot":SLOT,"publication":publication,"step":"FileSync","position":"after","action":"hold","value":"absent","times":1}
    ])).unwrap()).unwrap();
    let staging = target.with_file_name(format!(
        ".{}.staging",
        target.file_name().unwrap().to_str().unwrap()
    ));
    let release = fixture.seam.join("release-absent");
    std::thread::scope(|scope| {
        let driver = scope.spawn(|| {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis((D_REQUEST_DEADLINE_MS * 5) as u64);
            while !staging.exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Removing the staged leaf makes the real rename syscall fail without changing the target.
            fs::remove_file(&staging).unwrap();
            fs::write(release, b"release").unwrap();
        });
        let result = publish();
        driver.join().unwrap();
        assert!(!staging.exists());
        assert!(fixture
            .events()
            .iter()
            .any(|e| e["event"] == "StoreResumed" && e["step"] == "FileSync"));
        result
    })
}
#[test]
fn first_record_and_copy_rename_errors_preserve_verified_absence() {
    let _guard = isolation::guard();
    for copy in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let bytes = envelope(1);
        let r = committed(&bytes);
        if copy {
            assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
        }
        let (publication, target) = if copy {
            ("copy", fixture.copies_path().join(format!("{:020}.env", 1)))
        } else {
            ("record", fixture.record_path())
        };
        let outcome = remove_staging_at_rename(&fixture, publication, target.clone(), || {
            if copy {
                store.publish_original(SLOT, 1, &bytes)
            } else {
                store.publish_record(SLOT, &r)
            }
        });
        assert_eq!(
            outcome,
            PublishOutcome::PrePublication(StoreRefusal::RENAME)
        );
        assert!(!target.exists());
        assert!(!store.observe(SLOT).uncertain);
        assert_eq!(store.usage(), CopyUsage::default());
        fixture.clear();
        assert_eq!(
            if copy {
                store.publish_original(SLOT, 1, &bytes)
            } else {
                store.publish_record(SLOT, &r)
            },
            PublishOutcome::Durable
        );
    }
}
#[test]
fn record_rename_error_after_durable_copy_preserves_the_orphan() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let bytes = envelope(1);
    let r = committed(&bytes);
    assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Durable
    );
    let usage = store.usage();
    assert_eq!(
        remove_staging_at_rename(&fixture, "record", fixture.record_path(), || store
            .publish_record(SLOT, &drained(r.clone()))),
        PublishOutcome::PrePublication(StoreRefusal::RENAME)
    );
    assert!(!store.observe(SLOT).uncertain);
    assert_eq!(store.record(SLOT), Some(&r));
    assert_eq!(store.copy(SLOT, 1), Some(bytes.as_slice()));
    assert_eq!(store.usage(), usage);
    fixture.clear();
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Durable
    );
    assert_eq!(
        store.publish_record(SLOT, &drained(r)),
        PublishOutcome::Durable
    );
}
#[test]
fn drained_tail_retry_and_certain_reconcile_have_explicit_io_bounds() {
    let _guard = isolation::guard();
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let bytes = envelope(1);
    let r = committed(&bytes);
    assert_eq!(store.publish_record(SLOT, &r), PublishOutcome::Durable);
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Durable
    );
    assert_eq!(
        store.publish_record(SLOT, &drained(r)),
        PublishOutcome::Durable
    );
    let usage = store.usage();
    let before = fixture.events().len();
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Durable
    );
    let events = fixture.events();
    assert!(!events[before..].iter().any(|e| e["step"] == "Stage"));
    assert!(events[before..]
        .iter()
        .any(|e| e["publication"] == "copy" && e["step"] == "Readback"));
    assert_eq!(store.usage(), usage);
    let mut conflict = bytes.clone();
    conflict[0] ^= 1;
    assert_eq!(
        store.publish_original(SLOT, 1, &conflict),
        PublishOutcome::PrePublication(StoreRefusal::ORPHAN)
    );
    assert!(!store.observe(SLOT).uncertain);
    fixture.fault("copy", StoreStep::DirSync, "before", "fail", 1);
    let before = fixture.events();
    let refusals = fs::read(fixture.seam.join("refusals.jsonl")).unwrap();
    store.reconcile(SLOT).unwrap();
    assert_eq!(fixture.events(), before);
    assert_eq!(
        fs::read(fixture.seam.join("refusals.jsonl")).unwrap(),
        refusals
    );
    assert_eq!(
        store.publish_original(SLOT, 1, &bytes),
        PublishOutcome::Uncertain(StoreRefusal::DIR_SYNC)
    );
    assert!(store.observe(SLOT).uncertain);
}
