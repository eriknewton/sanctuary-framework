// fail-before-exempt: complete native call-site sets pin the settlement barrier.
// Call-site parity keeps frozen mutations separate from drain and Business peers on checked credentials.
use std::{fs, path::Path};

fn calls(root: &Path, path: &Path, needle: &str, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            calls(root, &path, needle, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            // Ignore whitespace so formatting cannot hide a call from the full-set comparison.
            let compact: String = source
                .replace("fn ", "@function@")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            for (offset, _) in compact.match_indices(needle) {
                let before = &compact[..offset];
                let function = before
                    .rsplit("@function@")
                    .next()
                    .unwrap()
                    .split('(')
                    .next()
                    .unwrap();
                found.push((
                    path.strip_prefix(root).unwrap().display().to_string(),
                    function.into(),
                ));
            }
        }
    }
}

#[test]
fn original_and_refresh_call_site_full_set_parity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (needle, expected) in [
        (
            ".original(",
            vec![
                ("business_profile/append_actor.rs", "continue_checked"),
                ("business_profile/compose.rs", "settle_startup"),
            ],
        ),
        (
            ".refresh_drained(",
            vec![
                ("business_profile/business_wal.rs", "recovery_action"),
                ("business_profile/wal_executor.rs", "execute"),
            ],
        ),
    ] {
        let mut found = Vec::new();
        calls(&root, &root, needle, &mut found);
        found.sort();
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(p, f)| (p.to_string(), f.to_string()))
            .collect();
        assert_eq!(found, expected, "complete drain caller set remains pinned");
    }
    let wal = fs::read_to_string(root.join("business_profile/business_wal.rs")).unwrap();
    let recovery = wal
        .split("pub fn recovery_action(")
        .nth(1)
        .unwrap()
        .split("pub fn active_body_digest")
        .next()
        .unwrap();
    let active = recovery
        .split("// Only this no-active-intent branch")
        .next()
        .unwrap();
    assert!(
        !active.contains("RecoveryAction::Original"),
        "active recovery cannot drain a frozen COMMIT"
    );
    assert!(active.contains("return Err(Refusal::Held);"));
    assert_eq!(recovery.matches("RecoveryAction::Original").count(), 1);
}

#[test]
fn business_accept_arm_uses_checked_peer_credentials() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    calls(&root, &root, "business_peer_uid_for_stream(", &mut found);
    found.sort();
    // The scanner names a definition's own `fn` header as the empty function.
    let expected: Vec<_> = [
        "",
        "business_peer_credentials_refuse_short_and_nonpositive_pid",
        "run_accept_loop",
    ]
    .into_iter()
    .map(|f| ("ipc/server.rs".to_string(), f.to_string()))
    .collect();
    // The definition, its credential test and the accept loop are the whole set; a second
    // production caller or a lost accept-loop call changes this set.
    assert_eq!(found, expected, "complete checked peer reader call set");
    let server = fs::read_to_string(root.join("ipc/server.rs")).unwrap();
    let accept: String = server
        .split("fn run_accept_loop(")
        .nth(1)
        .unwrap()
        .split("\nfn ")
        .next()
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    // Only the Business composition requires complete live kernel credentials; Legacy keeps its reader.
    assert!(
        accept.contains("letcredentials=ifmatches!(&state.composition,Composition::Business(..)){business_peer_uid_for_stream(&stream)}else{peer_uid_for_stream(&stream)};"),
        "Business accept arm reads checked peer credentials"
    );
    assert_eq!(
        accept.matches("letcredentials=").count(),
        2,
        "one Linux and one non-Linux credential selection"
    );
}
