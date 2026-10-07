//! Arch parser fixtures replay file-backed verdicts for pure readers and unit observations. ARCH-CLI-FIXTURES-01.
#![cfg(all(target_os = "linux", feature = "arch-install"))]

use castle_wall_daemon::linux_install::{
    arch::{command as arch_command, login_defs, pacman},
    command as ubuntu_command,
    contract::WORKSPACE_MOUNT_UNIT,
    transaction::sha256,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const SUBSTRATE: &str = "tests/fixtures/substrate";
const PACKAGE_VERSION: &str = "0.1.0-1";
const QO_PATH: &str = "usr/bin/sanctuary-linux";
const GUARD_BODY: &[u8] = b"PACKAGE_VERSION = '0.1.0-1'\n";
const CLEAN_IDENTITY: &str = "clean";
const IDENTITY_EDITED: &str = "identity-edited";

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
        if name == "PROVENANCE" || name.ends_with(".expect") {
            continue;
        }
        let _ = expectation(&path);
    }
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
    let static_hash = sha256(GUARD_BODY);
    let files = fixture_files(&dir);
    for path in files
        .iter()
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("guard"))
    {
        let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap();
        let identity = fs::read(dir.join(format!(
            "{}.identity",
            if stem == IDENTITY_EDITED {
                IDENTITY_EDITED
            } else {
                CLEAN_IDENTITY
            }
        )))
        .unwrap();
        let identity_hash = sha256(&identity);
        assert_expected(
            pacman::verified_guard_bytes(&fs::read(path).unwrap(), &identity_hash, &static_hash),
            expectation(path),
        );
    }
    for path in files.iter().filter(|path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("identity")
    }) {
        let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap();
        let identity = fs::read(path).unwrap();
        let guard = fs::read(dir.join(format!("{stem}.guard"))).unwrap();
        assert_expected(
            pacman::verified_guard_bytes(&guard, &sha256(&identity), &static_hash),
            expectation(path),
        );
    }
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
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
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
