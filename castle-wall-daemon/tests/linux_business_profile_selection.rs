// fail-before-exempt: profile selection and its isolated entrypoints are new; predicate removal is mutation evidence.
#![cfg(target_os = "linux")]
#[path = "support/checked_corpus.rs"]
mod checked_corpus;
mod isolation;
use castle_wall_daemon::config::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

// Must match profile_selector_vectors.json and the TS runner's complete element refusal set.
fn exact(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == names.len() && names.iter().all(|k| m.contains_key(*k)))
}
fn relative(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        !s.is_empty()
            && !s.contains('\0')
            && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
    })
}
fn validate(v: &Value) -> bool {
    if !exact(v, &["version", "reasons", "inventory", "cases"]) || v["version"] != 1 {
        return false;
    }
    if v["reasons"]
        != json!([
            "Explicit",
            "NoBusinessEvidence",
            "SelectorInvalid",
            "InventoryAmbiguous",
            "LegacyWithEnrollment",
            "RawInventoryPresent"
        ])
    {
        return false;
    }
    let Some(cases) = v["cases"].as_array() else {
        return false;
    };
    let mut ids = BTreeSet::new();
    for c in cases {
        if !exact(
            c,
            &[
                "id",
                "caller",
                "layout",
                "owners",
                "deny",
                "candidates",
                "expect",
            ],
        ) || !c["id"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && ids.insert(s))
            || !matches!(c["caller"].as_str(), Some("owner" | "unprivileged"))
        {
            return false;
        }
        let Some(layout) = c["layout"].as_array() else {
            return false;
        };
        let mut paths = BTreeSet::new();
        let mut regular = BTreeSet::new();
        let mut non_directories = BTreeSet::new();
        for n in layout {
            let fields: &[&str] = match n["type"].as_str() {
                Some("file") => &["type", "path", "mode", "content"],
                Some("dir" | "fifo") => &["type", "path", "mode"],
                Some("symlink" | "hardlink") => &["type", "path", "mode", "target"],
                _ => return false,
            };
            if !exact(n, fields)
                || !relative(&n["path"])
                || !paths.insert(n["path"].as_str().unwrap())
                || !n["mode"].as_u64().is_some_and(|m| m <= 0o7777)
            {
                return false;
            }
            let path = n["path"].as_str().unwrap();
            if Path::new(path)
                .ancestors()
                .skip(1)
                .any(|p| non_directories.contains(p))
            {
                return false;
            }
            if n["type"] != "dir" {
                non_directories.insert(Path::new(path));
            }
            if n["type"] == "file" {
                if !n["content"].is_string() {
                    return false;
                }
                regular.insert(n["path"].as_str().unwrap());
            }
            if n["type"] == "symlink" || n["type"] == "hardlink" {
                if !relative(&n["target"]) {
                    return false;
                }
                if n["type"] == "hardlink" && !regular.contains(n["target"].as_str().unwrap()) {
                    return false;
                }
            }
        }
        let Some(owners) = c["owners"].as_object() else {
            return false;
        };
        if owners
            .iter()
            .any(|(p, o)| !relative(&json!(p)) || !matches!(o.as_str(), Some("self" | "other")))
        {
            return false;
        }
        if !exact(&c["deny"], &["lookup", "open"]) {
            return false;
        }
        for a in [&c["deny"]["lookup"], &c["deny"]["open"], &c["candidates"]] {
            if !a.as_array().is_some_and(|a| a.iter().all(relative)) {
                return false;
            }
        }
        if c["candidates"].as_array().unwrap().len() > MAX_RAW_CANDIDATES
            || !exact(&c["expect"], &["kind", "reason"])
        {
            return false;
        }
        let valid = match c["expect"]["kind"].as_str() {
            Some("Business") => c["expect"]["reason"].is_null(),
            Some("LegacyV1") => matches!(
                c["expect"]["reason"].as_str(),
                Some("Explicit" | "NoBusinessEvidence")
            ),
            Some("Refused") => matches!(
                c["expect"]["reason"].as_str(),
                Some(
                    "SelectorInvalid"
                        | "InventoryAmbiguous"
                        | "LegacyWithEnrollment"
                        | "RawInventoryPresent"
                )
            ),
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    true
}
fn snapshot(root: &Path) -> Vec<(PathBuf, u32, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, rows: &mut Vec<(PathBuf, u32, Vec<u8>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let data = if meta.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else if meta.is_file() {
                fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            rows.push((
                path.strip_prefix(root).unwrap().to_path_buf(),
                meta.mode(),
                data,
            ));
            if meta.is_dir() {
                visit(root, &path, rows);
            }
        }
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows);
    rows.sort();
    rows
}
fn fixture(root: &Path, c: &Value) -> SelectorRoots {
    for n in c["layout"].as_array().unwrap() {
        let path = root.join(n["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match n["type"].as_str().unwrap() {
            "file" => fs::write(&path, n["content"].as_str().unwrap()).unwrap(),
            "dir" => fs::create_dir_all(&path).unwrap(),
            "symlink" => symlink(root.join(n["target"].as_str().unwrap()), &path).unwrap(),
            "hardlink" => {
                let target = root.join(n["target"].as_str().unwrap());
                assert!(target.is_file());
                fs::hard_link(target, &path).unwrap();
            }
            "fifo" => nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
            _ => panic!("validated node"),
        }
        if n["type"] != "symlink" {
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(n["mode"].as_u64().unwrap() as u32),
            )
            .unwrap();
        }
    }
    let mut roots = SelectorRoots::isolated_under(root);
    for (path, owner) in c["owners"].as_object().unwrap() {
        const OTHER_OWNER_OFFSET: u32 = 1; // Smallest offset distinct from the creating euid.
        roots = roots.expect_owner_at(
            Path::new(path),
            nix::unistd::geteuid().as_raw()
                + if owner == "other" {
                    OTHER_OWNER_OFFSET
                } else {
                    0
                },
        );
    }
    for path in c["deny"]["lookup"].as_array().unwrap() {
        roots = roots.deny_lookup(Path::new(path.as_str().unwrap()));
    }
    for path in c["deny"]["open"].as_array().unwrap() {
        roots = roots.deny_open(Path::new(path.as_str().unwrap()));
    }
    roots
}
fn project(selection: ProfileSelection) -> Value {
    match selection {
        ProfileSelection::LegacyV1(t) => {
            json!({"kind":"LegacyV1","reason":format!("{:?}",t.reason())})
        }
        ProfileSelection::Business(_) => json!({"kind":"Business","reason":null}),
        ProfileSelection::Refused(r) => json!({"kind":"Refused","reason":r.to_string()}),
    }
}
#[test]
fn shared_vectors_are_complete_immutable_and_match_constants() {
    let _guard = isolation::guard();
    let corpus = checked_corpus::corpus("profile_selector_vectors.json");
    assert!(validate(&corpus));
    assert_eq!(
        corpus["inventory"],
        json!({"evidence":BUSINESS_EVIDENCE.iter().enumerate().map(|(i,p)|json!({"id":(i+1).to_string(),"path":p})).collect::<Vec<_>>(),"raw_roots":[RAW_STATE_ROOT,RAW_RUNTIME_ROOT],"raw_relative":{"state":RAW_STATE_RELATIVE,"runtime":RAW_RUNTIME_RELATIVE}})
    );
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let root = TempDir::new().unwrap();
        let roots = fixture(root.path(), case);
        if case["id"] == "selector-two-links" {
            assert_eq!(
                fs::metadata(root.path().join(&BUSINESS_PROFILE_SELECTOR[1..]))
                    .unwrap()
                    .nlink(),
                2
            );
        }
        if case["id"] == "maximal-selector" {
            let size = fs::metadata(root.path().join(&BUSINESS_PROFILE_SELECTOR[1..]))
                .unwrap()
                .len();
            assert_eq!(size, 463);
            assert!(size <= SELECTOR_MAX_BYTES as u64);
        }
        let before = snapshot(root.path());
        let candidates: Vec<_> = case["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| root.path().join(p.as_str().unwrap()))
            .collect();
        let result = project(select_profile(
            &roots,
            &candidates.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
        ));
        assert_eq!(result, case["expect"], "{}", case["id"]);
        assert_eq!(
            snapshot(root.path()),
            before,
            "{} changed inventory",
            case["id"]
        );
        actual.push(json!([case["id"], result]));
        expected.push(json!([case["id"], case["expect"]]));
    }
    actual.sort_by_key(|row| row[0].as_str().unwrap().to_string());
    expected.sort_by_key(|row| row[0].as_str().unwrap().to_string());
    assert_eq!(actual, expected);
}
#[test]
fn malformed_elements_refuse_before_execution() {
    let corpus = checked_corpus::corpus("profile_selector_vectors.json");
    let bads = vec![
        json!({"path":["caller"],"value":"unknown"}),
        json!({"path":["expect","kind"],"value":"unknown"}),
        json!({"path":["expect","reason"],"value":"unknown"}),
        json!({"path":["layout"],"value":[{"type":"unknown"}]}),
        json!({"path":["owners"],"value":{"x":"foreign"}}),
        json!({"path":["deny","lookup"],"value":["../escape"]}),
        json!({"path":["candidates"],"value":["/absolute"]}),
        json!({"path":["layout"],"value":[{"type":"hardlink","path":"alias","target":"missing","mode":384}]}),
    ];
    for bad in bads {
        let mut copy = corpus.clone();
        let mut at = &mut copy["cases"][0];
        for key in bad["path"].as_array().unwrap() {
            at = &mut at[key.as_str().unwrap()];
        }
        *at = bad["value"].clone();
        assert!(!validate(&copy), "{bad}");
    }
    let mut duplicate = corpus.clone();
    let first = duplicate["cases"][0].clone();
    duplicate["cases"].as_array_mut().unwrap().push(first);
    assert!(!validate(&duplicate));
}
fn evidence(root: &Path) {
    fs::create_dir_all(root.join(&BUSINESS_CUSTODY_ROOT[1..])).unwrap();
}
#[test]
fn main_refuses_before_all_routes_and_paths_but_legacy_continues() {
    let _guard = isolation::guard();
    let root = TempDir::new().unwrap();
    let corpus = checked_corpus::corpus("profile_selector_vectors.json");
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "business-selector")
        .unwrap();
    fixture(root.path(), case);
    let effects = TempDir::new().unwrap();
    let binary = env!("CARGO_BIN_EXE_castle-wall-daemon");
    for route in [
        vec!["--preflight-manifest", "absent.json"],
        vec!["--disarm"],
        vec!["--agent-start-gate", "1"],
        vec!["--fortress-id", "deadbeef", "--profile", "legacy-v1"],
    ] {
        let output = Command::new(binary)
            .arg("--test-profile-root")
            .arg(root.path())
            .args(isolation::subprocess_args())
            .args(&route)
            .arg("--producer-key")
            .arg(effects.path().join("k/key"))
            .arg("--producer-pub-key")
            .arg(effects.path().join("q/pub"))
            .arg("--wal-path")
            .arg(effects.path().join("wal"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78));
        assert_eq!(String::from_utf8(output.stderr).unwrap(),"castle-wall-daemon: business profile selected; installed business signing is not enabled in this build\n");
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(effects.path()).unwrap().count(), 0);
    }
    let empty = TempDir::new().unwrap();
    let output = Command::new(binary)
        .arg("--test-profile-root")
        .arg(empty.path())
        .args(["--preflight-manifest", "absent.json"])
        .output()
        .unwrap();
    assert_ne!(output.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&output.stderr).contains("preflight"));
    let missing = Command::new(binary)
        .arg("--test-profile-root")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&missing.stderr).contains("panicked"));
}
fn boot_config(root: &Path) -> DaemonConfig {
    use ed25519_dalek::SigningKey;
    let mut config = DaemonConfig::defaults_for_fortress("deadbeef");
    config.test_selector_roots = Some(SelectorRoots::isolated_under(root));
    config.linux_runtime_paths = LinuxRuntimePaths::isolated_under(root);
    config.pinned_public_key_path = root.join("pinned.key");
    fs::write(
        &config.pinned_public_key_path,
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    config.producer_key_path = root.join("key/producer.key");
    config.producer_pub_key_path = root.join("public/producer.pub");
    config.wal_path = root.join("events.wal");
    config.policy_dir = root.join("policy");
    config.socket_path = root.join("wall.sock");
    config.trusted_service_uid = Some(nix::unistd::geteuid().as_raw());
    config
}
#[test]
fn boot_reselects_before_pin_wal_and_key_and_includes_config_candidates() {
    use castle_wall_daemon::daemon::{boot, DaemonError};
    let _guard = isolation::guard();
    let root = TempDir::new().unwrap();
    evidence(root.path());
    let config = boot_config(root.path());
    assert!(matches!(
        boot(config.clone()),
        Err(DaemonError::BusinessProfileNotEnabled)
    ));
    assert!(!config.wal_path.exists());
    assert!(!config.producer_key_path.parent().unwrap().exists());
    fs::create_dir(config.producer_key_path.parent().unwrap()).unwrap();
    fs::write(&config.producer_key_path, b"untouched").unwrap();
    assert!(matches!(
        boot(config.clone()),
        Err(DaemonError::ProfileRefused(
            ProfileRefusal::RawInventoryPresent
        ))
    ));
    assert_eq!(fs::read(&config.producer_key_path).unwrap(), b"untouched");
    let empty = TempDir::new().unwrap();
    let config = boot_config(empty.path());
    let key = config.producer_key_path.clone();
    let result = boot(config);
    assert!(
        key.exists(),
        "the continuing legacy boot reaches raw key creation"
    );
    if let Ok(handle) = result {
        handle.stop().unwrap();
    }
}

#[test]
fn candidate_caps_and_descriptor_lifetime_are_bounded() {
    let _guard = isolation::guard();
    let root = TempDir::new().unwrap();
    evidence(root.path());
    let roots = SelectorRoots::isolated_under(root.path());
    let before = fs::read_dir("/proc/self/fd").unwrap().count();
    let outside = Path::new("/outside-selection-anchor");
    let dot = root.path().join("x/../key");
    let long = root.path().join("x".repeat(CANDIDATE_MAX_BYTES));
    for candidate in [outside, dot.as_path(), long.as_path()] {
        assert_eq!(
            project(select_profile(&roots, &[candidate])),
            json!({"kind":"Refused","reason":"RawInventoryPresent"})
        );
    }
    assert_eq!(
        project(select_profile(&roots, &[outside; MAX_RAW_CANDIDATES + 1])),
        json!({"kind":"Refused","reason":"RawInventoryPresent"})
    );
    assert_eq!(fs::read_dir("/proc/self/fd").unwrap().count(), before);
}

#[test]
fn drain_inventory_matches_shared_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../src/business_profile/drain_schema.json")).unwrap();
    let paths: Vec<_> = schema["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(BUSINESS_EVIDENCE, paths);
    assert_eq!(BUSINESS_EVIDENCE[0], BUSINESS_PROFILE_SELECTOR);
}

#[test]
fn drain_config_only_selects_business() {
    let _guard = isolation::guard();
    let corpus = checked_corpus::corpus("profile_selector_vectors.json");
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "drain-config-only")
        .unwrap();
    let root = TempDir::new().unwrap();
    let roots = fixture(root.path(), case);
    assert_eq!(project(select_profile(&roots, &[])), case["expect"]);
}
