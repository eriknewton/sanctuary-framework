// fail-before-exempt: private-file and persisted-cursor witnesses exercise isolated native filesystem state.
// W-WAL-STORE
use super::*;
#[test]
fn created_private_files_ignore_restrictive_umask() {
    const CHILD: &str = "K1_WAL_PRIVATE_MODE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let image_root = tempfile::tempdir().unwrap();
        let image = image_root.path().join("witness");
        fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let status = std::process::Command::new(&image)
            .args([
                "--exact",
                "business_wal::nits::created_private_files_ignore_restrictive_umask",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "created private files retain usable descriptor modes"
        );
        return;
    }
    // This private one-test process owns its umask; no concurrent fixture inherits it.
    unsafe {
        libc::umask(0o777);
    }
    let f = Fixture::new();
    let opened = f.open(true);
    assert!(
        opened.is_ok(),
        "created lock and initial stage are set to 0600"
    );
    let mut wal = opened.unwrap();
    let reserve = f.reserve(&wal, 0);
    assert!(
        wal.freeze_body(
            &canonical(&f.records[0]["body"]),
            &reserve,
            DEADLINE,
            EXPIRY,
            Pool::Ordinary
        )
        .is_ok(),
        "created row stage is set to 0600"
    );
    drop(wal);
    assert!(f.open(false).is_ok());
}
#[test]
fn checkpoint_original_and_release_identities_match_retained_facts() {
    for field in ["originals", "released"] {
        let f = Fixture::new();
        let mut wal = f.open(true).unwrap();
        let envelope = f.append(&mut wal, 0);
        let token = wal.next_delivery().unwrap().unwrap().1;
        wal.persist_ts_fact(BusinessSequence(1), sink().deliver(&token).unwrap())
            .unwrap();
        wal.persist_d_fact(BusinessSequence(1), authenticated_original(&envelope))
            .unwrap();
        drop(wal);
        let path = f.root.path().join("checkpoint.json");
        let mut checkpoint: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if field == "released" {
            checkpoint["payload"][field] = checkpoint["payload"]["originals"].clone();
        }
        checkpoint["payload"][field]["envelope_sha256"] =
            json!(digest(b"different exact envelope"));
        checkpoint["storage_checksum"] = json!(digest(&canonical(&checkpoint["payload"])));
        fs::write(path, canonical(&checkpoint)).unwrap();
        assert!(
            matches!(f.open(false), Err(Refusal::Conflict)),
            "checkpoint {field} identity must match the retained row fact"
        );
    }
}
#[test]
fn fifo_entry_is_refused_without_a_blocking_open() {
    let f = Fixture::new();
    drop(f.open(true).unwrap());
    let path = std::ffi::CString::new(
        f.root
            .path()
            .join("row-00000000000000000001.json")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(
        matches!(f.open(false), Err(Refusal::Root)),
        "non-regular entry is refused before reading"
    );
}
