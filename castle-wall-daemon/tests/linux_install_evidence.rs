//! Public evidence accepts only complete, continuous WAL prefixes.
#![cfg(target_os = "linux")]
use castle_wall_daemon::{
    audit::WalEntry,
    linux_install::{evidence::verify_wal, transaction::sha256},
};
fn row(seq: u64, prior: Option<String>) -> WalEntry {
    WalEntry {
        seq,
        captured_at_unix_ms: 1,
        event_canonical_json: castle_wall_daemon::manifest::canonical_json::canonicalize(
            &serde_json::json!({"details":{"seq":seq,"prior_sha256_hex":prior}}),
        )
        .unwrap(),
        prior_sha256_hex: prior,
        critical: true,
        acked_anchor: false,
    }
}
fn bytes(rows: &[WalEntry]) -> Vec<u8> {
    rows.iter()
        .flat_map(|r| {
            let mut b = serde_json::to_vec(r).unwrap();
            b.push(b'\n');
            b
        })
        .collect()
}
#[test]
fn complete_continuous_prefix_or_retained_anchor_is_required() {
    let a = row(0, None);
    let b = row(1, Some(sha256(a.event_canonical_json.as_bytes())));
    assert_eq!(verify_wal(&bytes(&[a.clone(), b.clone()])).unwrap(), 2);
    let mut anchor = row(12, Some(sha256(b"before")));
    anchor.acked_anchor = true;
    assert_eq!(verify_wal(&bytes(&[anchor.clone()])).unwrap(), 1);
    anchor.acked_anchor = false;
    assert!(verify_wal(&bytes(&[anchor])).is_err());
    assert!(verify_wal(b"").is_err());
    let mut partial = bytes(std::slice::from_ref(&a));
    partial.pop();
    assert!(verify_wal(&partial).is_err());
    for bad in [
        row(3, b.prior_sha256_hex.clone()),
        row(1, Some("0".repeat(64))),
        row(1, None),
    ] {
        assert!(verify_wal(&bytes(&[a.clone(), bad])).is_err());
    }
    let mut mid = b;
    mid.acked_anchor = true;
    assert!(verify_wal(&bytes(&[a.clone(), mid])).is_err());
    let decorated = format!(" {}\n", serde_json::to_string(&a).unwrap());
    assert!(verify_wal(decorated.as_bytes()).is_err());
    assert!(verify_wal(&bytes(&[row(0, Some(sha256(b"x")))])).is_err());
    let mut malformed = row(1, Some("A".repeat(64)));
    malformed.acked_anchor = true;
    assert!(verify_wal(&bytes(&[malformed])).is_err());
}

#[test]
fn embedded_event_identity_and_canonical_encoding_agree_with_outer_chain() {
    for event in [
        "{}",
        "null",
        "[]",
        "not json",
        r#"{"details":{"seq":1,"prior_sha256_hex":null}}"#,
        r#"{"details":{"seq":0,"prior_sha256_hex":"wrong"}}"#,
        r#" {"details":{"prior_sha256_hex":null,"seq":0}}"#,
    ] {
        let mut a = row(0, None);
        a.event_canonical_json = event.into();
        assert!(
            verify_wal(&bytes(&[a])).is_err(),
            "accepted malformed embedded event"
        );
    }
    let mut end = row(u64::MAX, Some(sha256(b"prior")));
    end.acked_anchor = true;
    assert!(verify_wal(&bytes(&[end])).is_err());
}
