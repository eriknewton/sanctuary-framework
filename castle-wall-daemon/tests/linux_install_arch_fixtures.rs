//! Arch parser fixtures replay pure readers and the one reachable shared unit reader. ARCH-CLI-FIXTURES-01.
//! The synthetic-show key=value parse is a test-side copy of properties_until's inline parse because brief 16.2 forbids a seam into the Ubuntu file; its duplicate-key wording is intentionally a test-parser case, not a differential reader verdict.
#![cfg(all(target_os = "linux", feature = "arch-install"))]

use castle_wall_daemon::linux_install::{
    arch::{command as arch_command, login_defs, pacman},
    command as ubuntu_command,
    contract::WORKSPACE_MOUNT_UNIT,
    transaction::sha256,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const SUBSTRATE: &str = "tests/fixtures/substrate";
const PACKAGE_VERSION: &str = "0.1.0-1";
const QO_PATH: &str = "usr/bin/sanctuary-linux";
const GUARD_BODY: &[u8] = b"PACKAGE_VERSION = '0.1.0-1'\n";
const CLEAN_IDENTITY: &str = "clean";
const IDENTITY_EDITED: &str = "identity-edited";
const GENERATED: &str = "generated";
const ARCH_CI_REQUIRED_READERS: &[&str] = &[
    "login.defs",
    "pacman-Q-retired",
    "pacman-Q-running",
    "pacman-Qo-cli-retired",
    "pacman-Qo-cli-running",
    "systemctl-show-agent-retired",
    "systemctl-show-agent-running",
    "systemctl-show-mount-retired",
    "systemctl-show-mount-running",
    "systemctl-show-wall-retired",
    "systemctl-show-wall-running",
];

#[derive(Debug, Clone)]
enum Expected {
    Accept,
    Refuse(String),
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(SUBSTRATE).join(name)
}

fn expectation_path(path: &Path) -> PathBuf {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        panic!("fixture path has no file name: {}", path.display());
    };
    path.with_file_name(format!("{name}.expect"))
}

fn expectation(path: &Path) -> Expected {
    let expect_path = expectation_path(path);
    let text = fs::read_to_string(&expect_path)
        .unwrap_or_else(|error| panic!("missing expectation {}: {error}", expect_path.display()));
    let text = text.trim();
    if text == "accept" {
        Expected::Accept
    } else if let Some(rest) = text.strip_prefix("refuse ") {
        Expected::Refuse(rest.to_owned())
    } else {
        panic!("bad expectation {}: {text}", expect_path.display());
    }
}

fn assert_expected(result: castle_wall_daemon::linux_install::Result<()>, expected: Expected) {
    match (result, expected) {
        (Ok(()), Expected::Accept) => {}
        (Err(error), Expected::Refuse(needle)) => {
            let message = error.to_string();
            assert!(
                message.contains(&needle),
                "expected refusal containing {needle:?}, got {message:?}"
            );
        }
        (Ok(()), Expected::Refuse(needle)) => panic!("expected refusal containing {needle:?}"),
        (Err(error), Expected::Accept) => panic!("expected accept, got {error}"),
    }
}

fn assert_every_fixture_has_expectation(dir: &Path) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == "PROVENANCE"
            || name.ends_with(".expect")
            || matches!(
                arch_ci_capture_kind(name),
                Some(ArchCiCaptureKind::RawSystemctlShow)
            )
        {
            continue;
        }
        let _ = expectation(&path);
    }
}

fn guard_static_sha256(guard: &[u8]) -> String {
    let mut lines = guard.split_inclusive(|byte| *byte == b'\n');
    let shebang = lines.next().unwrap_or_default();
    let identity = lines.next().unwrap_or_default();
    sha256(&guard[shebang.len() + identity.len()..])
}

fn fixture_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            name != "PROVENANCE" && !name.ends_with(".expect")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn fixture_dirs_with_prefix(prefix: &str) -> Vec<PathBuf> {
    let mut dirs = fs::read_dir(SUBSTRATE)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    dirs.sort();
    dirs
}

#[test]
fn login_defs_accepts_recon_and_recorded_synthetic_verdicts() {
    let captured_dir = fixture_dir("omarchy-4.0.4-systemd-261.2-nft-1.1.7");
    assert_every_fixture_has_expectation(&captured_dir);
    let captured = captured_dir.join("login.defs");
    assert_expected(
        login_defs::parse(&fs::read(&captured).unwrap()).map(|_| ()),
        expectation(&captured),
    );

    // The whole stock file from shadow 4.20.0.arch1-1 (the recon host's version); the recon file above is an excerpt.
    let stock_dir = fixture_dir("archlinux-image-shadow-4.20.0.arch1-1");
    assert_every_fixture_has_expectation(&stock_dir);
    let stock = stock_dir.join("login.defs");
    assert_expected(
        login_defs::parse(&fs::read(&stock).unwrap()).map(|_| ()),
        expectation(&stock),
    );
    let ranges = login_defs::parse(&fs::read(&stock).unwrap()).unwrap();
    assert_eq!(
        (
            ranges.sys_gid_min,
            ranges.sys_gid_max,
            ranges.gid_min,
            ranges.gid_max
        ),
        (500, 999, 1000, 60000),
        "stock Arch ranges as recon read them on the Omarchy host"
    );

    let dir = fixture_dir("synthetic-login-defs");
    assert_every_fixture_has_expectation(&dir);
    for path in fixture_files(&dir) {
        assert_expected(
            login_defs::parse(&fs::read(&path).unwrap()).map(|_| ()),
            expectation(&path),
        );
    }
}

#[test]
fn pacman_query_parsers_match_recorded_verdicts() {
    let dir = fixture_dir("synthetic-pacman-q");
    assert_every_fixture_has_expectation(&dir);
    for path in fixture_files(&dir) {
        assert_expected(
            pacman::parse_q(&fs::read(&path).unwrap(), PACKAGE_VERSION),
            expectation(&path),
        );
    }

    let dir = fixture_dir("synthetic-pacman-qo");
    assert_every_fixture_has_expectation(&dir);
    for path in fixture_files(&dir) {
        assert_expected(
            pacman::parse_qo(&fs::read(&path).unwrap(), QO_PATH, PACKAGE_VERSION),
            expectation(&path),
        );
    }
}

#[test]
fn guard_verification_matches_recorded_verdicts() {
    let dir = fixture_dir("synthetic-guard");
    assert_every_fixture_has_expectation(&dir);
    let files = fixture_files(&dir);
    for path in files
        .iter()
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("guard"))
    {
        let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap();
        let identity = fs::read(dir.join(format!(
            "{}.identity",
            if stem == GENERATED {
                GENERATED
            } else if stem == IDENTITY_EDITED {
                IDENTITY_EDITED
            } else {
                CLEAN_IDENTITY
            }
        )))
        .unwrap();
        let identity_hash = sha256(&identity);
        let guard = fs::read(path).unwrap();
        let static_hash = if stem == GENERATED {
            generated_static_pin(&dir)
        } else {
            sha256(GUARD_BODY)
        };
        assert_expected(
            pacman::verified_guard_bytes(&guard, &identity_hash, &static_hash),
            expectation(path),
        );
    }
    for path in files.iter().filter(|path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("identity")
    }) {
        let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap();
        let identity = fs::read(path).unwrap();
        let guard = fs::read(dir.join(format!("{stem}.guard"))).unwrap();
        let static_hash = if stem == GENERATED {
            generated_static_pin(&dir)
        } else {
            sha256(GUARD_BODY)
        };
        assert_expected(
            pacman::verified_guard_bytes(&guard, &sha256(&identity), &static_hash),
            expectation(path),
        );
    }
    let generated: Value =
        serde_json::from_slice(&fs::read(dir.join("generated.identity")).unwrap()).unwrap();
    assert_eq!(
        pacman::payload_pin_from_identity(&generated).unwrap(),
        generated["cli_pins"]["payload_sha256"].as_str().unwrap(),
        "Python-generated identity payload pin must match the Rust canonical form"
    );
    // The static pin comes from the Python builder (cli_pins); the Rust region split must hash to the same value.
    assert_eq!(
        guard_static_sha256(&fs::read(dir.join("generated.guard")).unwrap()),
        generated_static_pin(&dir),
        "Rust guard static-region split must match the Python builder's guard_static_sha256 pin"
    );
}

fn generated_static_pin(dir: &Path) -> String {
    let generated: Value =
        serde_json::from_slice(&fs::read(dir.join("generated.identity")).unwrap()).unwrap();
    generated["cli_pins"]["guard_static_sha256"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn parse_show_fixture(
    path: &Path,
) -> castle_wall_daemon::linux_install::Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path)?;
    let mut values = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed systemctl property at line {}", index + 1))?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err("duplicate systemctl property".into());
        }
    }
    Ok(values)
}

fn unit_for(path: &Path) -> (&'static str, &'static str) {
    let mut name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    // Must match save_raw_captures in packaging/arch/ci-arch-lifecycle.sh: harness captures include the reader prefix.
    if let Some(rest) = name.strip_prefix("systemctl-show-") {
        name = rest;
    }
    if name.starts_with("mount-") {
        (
            WORKSPACE_MOUNT_UNIT,
            r"/etc/systemd/system/var-lib-sanctuary\x2dagent\x2dworkspace.mount",
        )
    } else if name.starts_with("agent-") {
        (
            "sanctuary-agent@60123.service",
            "/etc/systemd/system/sanctuary-agent@.service",
        )
    } else {
        (
            "sanctuary-castle-wall.service",
            "/etc/systemd/system/sanctuary-castle-wall.service",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchCiCaptureKind {
    LoginDefs,
    PacmanQ,
    PacmanQo,
    SystemctlShow,
    RawSystemctlShow,
}

fn arch_ci_capture_kind(name: &str) -> Option<ArchCiCaptureKind> {
    if name.ends_with(".err") || name.ends_with(".rc") || name.ends_with(".combined") {
        return None;
    }
    if name == "login.defs" {
        Some(ArchCiCaptureKind::LoginDefs)
    } else if name.starts_with("pacman-Qo-cli-") {
        Some(ArchCiCaptureKind::PacmanQo)
    } else if name.starts_with("pacman-Q-") && !name.starts_with("pacman-Qkk-") {
        Some(ArchCiCaptureKind::PacmanQ)
    } else if name.starts_with("systemctl-show-") {
        Some(ArchCiCaptureKind::SystemctlShow)
    } else if name.starts_with("raw-systemctl-show-") && name.ends_with(".full") {
        Some(ArchCiCaptureKind::RawSystemctlShow)
    } else {
        None
    }
}

fn assert_arch_ci_shape(dir: &Path, files: &[PathBuf]) {
    if files.is_empty() {
        return;
    }
    let names = files
        .iter()
        .map(|path| path.file_name().and_then(|name| name.to_str()).unwrap())
        .collect::<BTreeSet<_>>();
    for name in &names {
        assert!(
            arch_ci_capture_kind(name).is_some(),
            "unrecognised arch-ci capture kind in {}: {name}",
            dir.display()
        );
    }
    for required in ARCH_CI_REQUIRED_READERS {
        assert!(
            names.contains(required),
            "arch-ci fixture {} is missing required reader-shaped capture {required}",
            dir.display()
        );
    }
}

#[test]
fn synthetic_show_maps_are_differential_witnesses_for_shared_unit_reader() {
    let dir = fixture_dir("synthetic-show");
    assert_every_fixture_has_expectation(&dir);
    for path in fixture_files(&dir) {
        let expected = expectation(&path);
        let parsed = match parse_show_fixture(&path) {
            Ok(values) => Ok(values),
            Err(error) => Err(error.to_string()),
        };
        let ubuntu_result = match &parsed {
            Ok(values) => {
                let (unit, expected_path) = unit_for(&path);
                ubuntu_command::verify_unit_observation(values, unit, expected_path)
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error.clone()),
        };
        let arch_result = match &parsed {
            Ok(values) => {
                let (unit, expected_path) = unit_for(&path);
                arch_command::verify_unit_observation(values, unit, expected_path)
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error.clone()),
        };
        assert_eq!(
            ubuntu_result
                .as_ref()
                .map(|_| ())
                .map_err(|error| error.to_string()),
            arch_result
                .as_ref()
                .map(|_| ())
                .map_err(|error| error.to_string()),
            "Ubuntu/Arch verdict drift for {}",
            path.display()
        );
        assert_expected(arch_result.map_err(Into::into), expected);
    }
}

#[test]
fn arch_ci_capture_directories_replay_recorded_readers_when_present() {
    for dir in fixture_dirs_with_prefix("arch-ci-") {
        assert_every_fixture_has_expectation(&dir);
        let files = fixture_files(&dir);
        assert_arch_ci_shape(&dir, &files);
        for path in files {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            match arch_ci_capture_kind(name).expect("shape checked above") {
                ArchCiCaptureKind::LoginDefs => {
                    assert_expected(
                        login_defs::parse(&fs::read(&path).unwrap()).map(|_| ()),
                        expectation(&path),
                    );
                }
                ArchCiCaptureKind::PacmanQo => {
                    assert_expected(
                        pacman::parse_qo(&fs::read(&path).unwrap(), QO_PATH, PACKAGE_VERSION),
                        expectation(&path),
                    );
                }
                ArchCiCaptureKind::PacmanQ => {
                    assert_expected(
                        pacman::parse_q(&fs::read(&path).unwrap(), PACKAGE_VERSION),
                        expectation(&path),
                    );
                }
                ArchCiCaptureKind::SystemctlShow => {
                    let expected = expectation(&path);
                    let values = parse_show_fixture(&path)
                        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                    let (unit, expected_path) = unit_for(&path);
                    let ubuntu_result =
                        ubuntu_command::verify_unit_observation(&values, unit, expected_path)
                            .map_err(|error| error.to_string());
                    let arch_result =
                        arch_command::verify_unit_observation(&values, unit, expected_path)
                            .map_err(|error| error.to_string());
                    assert_eq!(
                        ubuntu_result.as_ref().map(|_| ()).map_err(String::clone),
                        arch_result.as_ref().map(|_| ()).map_err(String::clone),
                        "Ubuntu/Arch verdict drift for {}",
                        path.display()
                    );
                    assert_expected(arch_result.map_err(Into::into), expected);
                }
                ArchCiCaptureKind::RawSystemctlShow => {}
            }
        }
    }
}

#[test]
fn arch_ci_harness_names_route_to_their_units_and_unknowns_fail_shape() {
    let agent = Path::new("systemctl-show-agent-running");
    let mount = Path::new("systemctl-show-mount-running");
    let unknown = PathBuf::from("nft-table-running.json");
    assert_eq!(unit_for(agent).0, "sanctuary-agent@60123.service");
    assert_eq!(unit_for(mount).0, WORKSPACE_MOUNT_UNIT);
    assert!(
        arch_ci_capture_kind(unknown.to_str().unwrap()).is_none(),
        "unknown top-level arch-ci captures must fail once any capture is committed"
    );
}
