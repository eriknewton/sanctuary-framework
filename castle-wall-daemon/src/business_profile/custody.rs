//! Fixed launch closure and public custody configuration; this module never handles factors.
use super::signer_peer::PeerPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

// Must match sanctuary-business-signer.service and server/src/signing/service.ts.
pub const SIGNER_BINARY: &str = "/usr/libexec/sanctuary-business-signer";
pub const UNLOCK_BINARY: &str = "/usr/libexec/sanctuary-business-unlock";
pub const NODE_BINARY: &str = "/usr/lib/sanctuary/k1/node";
pub const WORKER_BINARY: &str = "/usr/lib/sanctuary/k1/signing-worker.cjs";
pub const CONFIG_PATH: &str = "/etc/sanctuary/business-signer.json";
// Must match RuntimeDirectory= in systemd/sanctuary-business-signer.service.
pub const CONTROL_ROOT: &str = "/run/sanctuary-business-signer";
pub const CUSTODY_ROOT: &str = "/var/lib/sanctuary-business-signer";
pub const PRODUCER_ROLE_SLOT: &str = "linux-business-producer";
pub const FORTRESS_ID_MAX_BYTES: usize = 128;
pub const CONFIG_MAX_BYTES: usize = 65_536;
pub const ARTIFACT_MAX_BYTES: u64 = 256 * 1024 * 1024;
// Must match TTY_FD in server/src/signing/worker.ts.
pub const TTY_FD: i32 = 3;
pub const DIRECTORY_MODE: u32 = 0o700;
pub const PRIVATE_MODE: u32 = 0o600;
pub const ROOT_UID: u32 = 0;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub controller: PeerPolicy,
    pub launcher: PeerPolicy,
    pub node_sha256: String,
    pub worker_sha256: String,
    pub grant: serde_json::Value,
    pub fortress_id: String,
    pub roster_digest: String,
    pub binding_high_water: u64,
    pub runtime: Vec<RuntimeArtifact>,
}
pub fn production_custody_path(config: &Config) -> io::Result<std::path::PathBuf> {
    // A package-pinned role slot and one validated identifier keep production custody beneath the unit's writable root.
    if config.fortress_id.is_empty()
        || config.fortress_id.len() > FORTRESS_ID_MAX_BYTES
        || !config
            .fortress_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || config.grant["role"] != "extension:linux-business-producer-v0"
    {
        return Err(refused());
    }
    Ok(Path::new(CUSTODY_ROOT)
        .join(&config.fortress_id)
        .join(PRODUCER_ROLE_SLOT))
}
pub fn refused() -> io::Error {
    io::Error::other("K1_REFUSED")
}
pub fn read_pinned(path: &Path, owner: u32, max: usize, mode: u32) -> io::Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // A bounded single-link owner-controlled file cannot be substituted by a device or a mutable caller path.
    if !meta.is_file()
        || meta.uid() != owner
        || meta.nlink() != 1
        || meta.mode() & 0o777 != mode
        || meta.len() > max as u64
    {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(refused());
    }
    Ok(bytes)
}
pub fn artifact(path: &Path, digest: &str, owner: u32) -> io::Result<File> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > ARTIFACT_MAX_BYTES
    {
        return Err(refused());
    }
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash)?;
    if hex::encode(hash.finalize()) != digest {
        return Err(refused());
    }
    Ok(file)
}
pub fn closed_environment() -> BTreeMap<String, String> {
    // Empty inheritance excludes NODE_OPTIONS, loader paths, HOME discovery and all factor variables.
    BTreeMap::from([
        ("LANG".into(), "C.UTF-8".into()),
        ("TZ".into(), "UTC".into()),
    ])
}
pub fn worker_command(node: &Path, worker: &Path) -> Command {
    let mut cmd = Command::new(node);
    // The pinned Node runtime must support this flag because SIGUSR1 must never open an inspector.
    cmd.args(["--disable-sigusr1", "--no-addons"])
        .arg(worker)
        .env_clear()
        .envs(closed_environment());
    cmd
}
pub fn check_root(path: &Path, owner: u32) -> io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.uid() != owner || meta.mode() & 0o777 != DIRECTORY_MODE {
        return Err(refused());
    }
    Ok(file)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifact {
    pub path: String,
    pub sha256: String,
}
pub const RUNTIME_FILES_MAX: usize = 64;
pub fn verify_runtime(config: &Config, node: &Path) -> io::Result<()> {
    // Every loaded shared library is independently pinned because hashing the Node executable alone does not close its runtime.
    if config.runtime.is_empty() || config.runtime.len() > RUNTIME_FILES_MAX {
        return Err(refused());
    }
    let _node = artifact(node, &config.node_sha256, ROOT_UID)?;
    let mut expected = Vec::new();
    for entry in &config.runtime {
        let path = Path::new(&entry.path);
        if !path.is_absolute() || std::fs::canonicalize(path)? != path {
            return Err(refused());
        }
        let _held = artifact(path, &entry.sha256, ROOT_UID)?;
        expected.push(entry.path.clone());
    }
    expected.sort();
    expected.dedup();
    if expected.len() != config.runtime.len() {
        return Err(refused());
    }
    let mut child = Command::new(node).args(["--disable-sigusr1", "--no-addons", "-e", "if(require('node:inspector').url())process.exit(1);process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects.filter(p=>p!=='linux-vdso.so.1').map(p=>require('node:fs').realpathSync(p)).sort()))"])
        .env_clear().envs(closed_environment()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn()?;
    let start = super::signer_watchdog::boottime_ns()?;
    let end = start + super::signer_watchdog::NS_PER_SECOND;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(refused());
            }
            break;
        }
        if super::signer_watchdog::boottime_ns()? >= end {
            child.kill()?;
            child.wait()?;
            return Err(refused());
        }
        std::thread::sleep(std::time::Duration::from_millis(
            super::signer_watchdog::WATCHDOG_TICK_MS as u64,
        ));
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(refused)?
        .take(CONFIG_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > CONFIG_MAX_BYTES {
        return Err(refused());
    }
    let actual: Vec<String> = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if actual != expected {
        return Err(refused());
    }
    Ok(())
}

pub fn verify_host_memory_policy() -> io::Result<()> {
    // Secret residency cannot rely on process death while host swap or hibernation can retain its pages.
    let swaps = std::fs::read_to_string("/proc/swaps")?;
    let power = std::fs::read_to_string("/sys/power/state")?;
    let command = std::fs::read_to_string("/proc/cmdline")?;
    if swaps.lines().skip(1).any(|line| !line.trim().is_empty())
        || (power.split_whitespace().any(|state| state == "disk")
            && !command.split_whitespace().any(|arg| arg == "nohibernate"))
    {
        return Err(refused());
    }
    Ok(())
}

// Must match fixture cleanup in server/test/fixtures/k1-service.ts.
pub const UNCLEAN_MARKER: &str = "worker-unclean";
pub fn mark_unclean(root: &Path) -> io::Result<()> {
    // Exclusive creation and directory fsync make secret-worker uncertainty survive a service restart.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join(UNCLEAN_MARKER))?;
    file.sync_all()?;
    File::open(root)?.sync_all()
}
pub fn verify_artifact_identity(path: &Path, held: &File) -> io::Result<()> {
    let current = std::fs::symlink_metadata(path)?;
    let original = held.metadata()?;
    // Owner-only runtime paths must still name the hashed inode immediately before spawning.
    if !current.is_file() || current.dev() != original.dev() || current.ino() != original.ino() {
        return Err(refused());
    }
    Ok(())
}

pub fn close_worker_descriptors() -> io::Result<()> {
    // Marking descriptors CLOEXEC preserves Rust's spawn error channel while denying inheritance to the worker.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            (TTY_FD + 1) as u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(refused());
    }
    Ok(())
}
