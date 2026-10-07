//! Pacman-backed package verification for the pinned Arch CLI.
use super::{
    transaction::{checked, sha256, Root, RECORD_MAX_BYTES},
    Result,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, io::ErrorKind, os::unix::fs::MetadataExt};

const PACMAN: &str = "/usr/bin/pacman";
const PACKAGE: &str = "sanctuary-castle-wall";
const DB_PATH: &str = "/var/lib/pacman";
const DB_LOCK_BASENAME: &str = "db.lck";
const LOCAL_DB_BASENAME: &str = "local";
// Must match GUARD in packaging/arch/build-arch-package.py.
const GUARD_PATH: &str = "usr/share/libalpm/scripts/sanctuary-castle-wall-guard";
const KIB: usize = 1024;
const SHA256_BYTES: usize = 32;
const HEX_CHARS_PER_BYTE: usize = 2;
const SHA256_HEX_LEN: usize = SHA256_BYTES * HEX_CHARS_PER_BYTE;
const MAX_VERSION_PIN_BYTES: usize = SHA256_HEX_LEN * HEX_CHARS_PER_BYTE;
const GUARD_CURRENT_UPPER_BOUND_BYTES: usize = 32 * KIB;
const GUARD_GROWTH_HEADROOM_BYTES: usize = 16 * KIB;
const GUARD_MAX_BYTES: usize = GUARD_CURRENT_UPPER_BOUND_BYTES + GUARD_GROWTH_HEADROOM_BYTES;

// Must match "/" + BINARIES["sanctuary-linux"] in packaging/arch/build-arch-package.py.
pub const ARCH_CLI_PATH: &str = "/usr/bin/sanctuary-linux";
// Must match IDENTITY in packaging/arch/build-arch-package.py.
pub const ARCH_BUILD_IDENTITY: &str = "usr/lib/sanctuary-castle-wall/build-identity";

fn relative(path: &str) -> &str {
    path.trim_start_matches('/')
}

fn db_lock() -> String {
    format!("{DB_PATH}/{DB_LOCK_BASENAME}")
}

fn local_db() -> String {
    format!("{DB_PATH}/{LOCAL_DB_BASENAME}")
}

fn ensure_db_unlocked(lock_path: &str, present_reason: &'static str) -> Result<()> {
    match fs::symlink_metadata(lock_path) {
        Ok(_) => Err(present_reason.into()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect pacman database lock: {error}").into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbEntry {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    package_line: Vec<u8>,
    desc: DbEntry,
    files: DbEntry,
    identity: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Pins {
    version: &'static str,
    payload_sha256: &'static str,
    guard_static_sha256: &'static str,
}

fn env_pin(name: &str, value: Option<&'static str>, hex: bool) -> Result<&'static str> {
    let value = value.ok_or("Arch CLI built without package pins")?;
    let valid = if hex {
        value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        !value.is_empty()
            && value.len() <= MAX_VERSION_PIN_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-' | b':')
            })
    };
    if !valid {
        return Err(format!("Arch CLI built without package pins: {name}").into());
    }
    Ok(value)
}

fn pins() -> Result<Pins> {
    Ok(Pins {
        // Must match the SANCTUARY_ARCH_PIN_* exports in packaging/arch/PKGBUILD.
        version: env_pin(
            "SANCTUARY_ARCH_PIN_PACKAGE_VERSION",
            option_env!("SANCTUARY_ARCH_PIN_PACKAGE_VERSION"),
            false,
        )?,
        payload_sha256: env_pin(
            "SANCTUARY_ARCH_PIN_PAYLOAD_SHA256",
            option_env!("SANCTUARY_ARCH_PIN_PAYLOAD_SHA256"),
            true,
        )?,
        guard_static_sha256: env_pin(
            "SANCTUARY_ARCH_PIN_GUARD_STATIC_SHA256",
            option_env!("SANCTUARY_ARCH_PIN_GUARD_STATIC_SHA256"),
            true,
        )?,
    })
}

pub fn require_pins() -> Result<()> {
    pins().map(|_| ())
}

pub fn pins_for_status() -> Value {
    match pins() {
        Ok(pins) => json!({
            "package_version": pins.version,
            "payload_sha256": pins.payload_sha256,
            "guard_static_sha256": pins.guard_static_sha256,
        }),
        Err(_) => Value::Null,
    }
}

fn db_entry(path: &str) -> Result<DbEntry> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err("pinned package database entry absent".into())
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err("pinned package database entry absent".into());
    }
    Ok(DbEntry {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

fn snapshot_for(version: &str) -> Result<(DbEntry, DbEntry)> {
    let base = format!("{}/{PACKAGE}-{version}", local_db());
    Ok((
        db_entry(&format!("{base}/desc"))?,
        db_entry(&format!("{base}/files"))?,
    ))
}

pub fn parse_q(bytes: &[u8], version: &str) -> Result<()> {
    let expected = format!("{PACKAGE} {version}\n");
    if bytes == expected.as_bytes() {
        Ok(())
    } else {
        Err("installed package version mismatch".into())
    }
}

pub fn parse_qo(bytes: &[u8], path: &str, version: &str) -> Result<()> {
    let expected = format!("/{path} is owned by {PACKAGE} {version}\n");
    if bytes == expected.as_bytes() {
        Ok(())
    } else {
        Err("installed path owner mismatch".into())
    }
}

pub fn installed(_root: &Root, package: &str) -> Result<Snapshot> {
    let pins = pins()?;
    if package != PACKAGE {
        return Err("unexpected Arch package name".into());
    }
    ensure_db_unlocked(
        &db_lock(),
        "a pacman transaction holds the database lock; wait for it, or if no package manager is running remove the stale lock as pacman's own message says",
    )?;
    let (desc, files) = snapshot_for(pins.version)?;
    let package_line = checked(PACMAN, &["--root", "/", "--dbpath", DB_PATH, "-Q", PACKAGE])?;
    parse_q(&package_line, pins.version)?;
    for path in expected_payloads_with_identity_and_guard() {
        let owner = checked(
            PACMAN,
            &[
                "--root",
                "/",
                "--dbpath",
                DB_PATH,
                "-Qo",
                "--",
                &format!("/{path}"),
            ],
        )?;
        parse_qo(&owner, path, pins.version)?;
    }
    Ok(Snapshot {
        package_line,
        desc,
        files,
        identity: None,
    })
}

fn expected_payloads() -> BTreeSet<&'static str> {
    // Must match PAYLOAD_MODES in packaging/arch/build-arch-package.py, excluding the identity and guard records.
    BTreeSet::from([
        "usr/local/libexec/sanctuary/castle-wall-daemon",
        "usr/local/libexec/sanctuary/protected-agent-v1",
        "usr/local/libexec/sanctuary/network-agent-standin",
        relative(ARCH_CLI_PATH),
        "etc/systemd/system/sanctuary-castle-wall.service",
        "etc/systemd/system/sanctuary-agent@.service",
        r"etc/systemd/system/var-lib-sanctuary\x2dagent\x2dworkspace.mount",
        "usr/share/sanctuary-castle-wall/schemas/contract.rs",
        "usr/share/sanctuary-castle-wall/operator-guide.md",
        "usr/share/libalpm/hooks/00-sanctuary-castle-wall-upgrade-guard.hook",
        "usr/share/libalpm/hooks/00-sanctuary-castle-wall-remove-guard.hook",
    ])
}

fn expected_payloads_with_identity_and_guard() -> BTreeSet<&'static str> {
    let mut paths = expected_payloads();
    paths.insert(ARCH_BUILD_IDENTITY);
    paths.insert(GUARD_PATH);
    paths
}

fn payload_pin(hashes: &serde_json::Map<String, Value>) -> Result<String> {
    let mut canonical = Vec::new();
    for path in expected_payloads() {
        if path == relative(ARCH_CLI_PATH) {
            continue;
        }
        let digest = hashes
            .get(path)
            .and_then(Value::as_str)
            .ok_or("missing payload identity")?;
        if digest.len() != SHA256_HEX_LEN || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("payload digest shape".into());
        }
        // Must match payload_pin_from_hashes in packaging/arch/build-arch-package.py: path, NUL, lowercase SHA-256 hex, newline.
        canonical.extend_from_slice(path.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(digest.as_bytes());
        canonical.push(b'\n');
    }
    Ok(sha256(&canonical))
}

pub fn payload_pin_from_identity(value: &Value) -> Result<String> {
    let hashes = value["payload_sha256"]
        .as_object()
        .ok_or("missing payload identity")?;
    payload_pin(hashes)
}

fn required_binary_features() -> Value {
    // Must match binary_features' expected map in packaging/arch/build-arch-package.py.
    json!({
        "castle-wall-daemon": [],
        "network-agent-standin": [],
        "protected-agent-v1": [],
        "sanctuary-linux-arch": ["arch-install"],
    })
}

pub fn verified_identity(root: &Root, snapshot: &mut Snapshot) -> Result<Value> {
    let pins = pins()?;
    let identity = root.read(ARCH_BUILD_IDENTITY, RECORD_MAX_BYTES)?;
    let identity_sha = sha256(&identity);
    let value: Value = serde_json::from_slice(&identity)?;
    let hashes = value["payload_sha256"]
        .as_object()
        .ok_or("missing payload identity")?;
    let observed: BTreeSet<_> = hashes.keys().map(String::as_str).collect();
    if value["artifact_kind"] != "arch-install-pkg-v1"
        || value["install_ready"] != true
        || value["package"] != PACKAGE
        || value["package_version"] != pins.version
        || value["target"] != "x86_64-unknown-linux-gnu"
        || value["cli_path_deviation"]["arch_path"] != relative(ARCH_CLI_PATH)
        || value["cli_source_bin"] != "sanctuary-linux-arch"
        || value["binary_features"] != required_binary_features()
        || value["cli_pins"] != pins_for_status()
        || value.get("guard_sha256").is_some()
        || observed != expected_payloads()
        || payload_pin(hashes)? != pins.payload_sha256
    {
        return Err("install build identity mismatch".into());
    }
    verified_guard(root, &identity_sha, pins.guard_static_sha256)?;
    snapshot.identity = Some(identity);
    Ok(value)
}

pub fn verified_guard(root: &Root, identity_sha256: &str, static_sha256: &str) -> Result<()> {
    let guard = root.read(GUARD_PATH, GUARD_MAX_BYTES)?;
    verified_guard_bytes(&guard, identity_sha256, static_sha256)
}

pub fn verified_guard_bytes(
    guard: &[u8],
    identity_sha256: &str,
    static_sha256: &str,
) -> Result<()> {
    let mut lines = guard.split_inclusive(|byte| *byte == b'\n');
    let shebang = lines.next().ok_or("guard header absent")?;
    let identity = lines.next().ok_or("guard identity header absent")?;
    let static_region = &guard[shebang.len() + identity.len()..];
    let expected_identity = format!("IDENTITY_SHA256 = '{identity_sha256}'\n");
    if shebang != b"#!/usr/bin/python3 -I\n" || identity != expected_identity.as_bytes() {
        return Err("guard identity header mismatch".into());
    }
    if sha256(static_region) != static_sha256 {
        return Err("guard static payload mismatch".into());
    }
    Ok(())
}

pub fn recheck(root: &Root, snapshot: &Snapshot) -> Result<()> {
    let pins = pins()?;
    ensure_db_unlocked(
        &db_lock(),
        "package database or identity changed during verification",
    )?;
    let package_line = checked(PACMAN, &["--root", "/", "--dbpath", DB_PATH, "-Q", PACKAGE])?;
    let (desc, files) = snapshot_for(pins.version)?;
    if package_line != snapshot.package_line || desc != snapshot.desc || files != snapshot.files {
        return Err("package database or identity changed during verification".into());
    }
    let identity = snapshot
        .identity
        .as_ref()
        .ok_or("package database or identity changed during verification")?;
    let now = root.read(ARCH_BUILD_IDENTITY, RECORD_MAX_BYTES)?;
    if &now != identity {
        return Err("package database or identity changed during verification".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn db_entry_names_absent_pinned_database_entry() {
        let error = db_entry("/definitely-absent-sanctuary-pacman-entry")
            .unwrap_err()
            .to_string();
        assert!(error.contains("pinned package database entry absent"));
    }

    #[test]
    fn lock_probe_admits_only_absence() {
        ensure_db_unlocked("/definitely-absent-sanctuary-pacman-lock", "lock present").unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let file = std::env::temp_dir().join(format!("sanctuary-lock-parent-{unique}"));
        fs::write(&file, b"not a directory").unwrap();
        let child = file.join("db.lck");
        let error = ensure_db_unlocked(child.to_str().unwrap(), "lock present")
            .unwrap_err()
            .to_string();
        fs::remove_file(file).unwrap();
        assert!(error.contains("cannot inspect pacman database lock"));
    }
}
