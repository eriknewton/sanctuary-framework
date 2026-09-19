//! Fixed root-installed launch artifacts. They are required inputs for a later
//! gated release, not created by the shipped daemon or replaced by a fixture.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

pub const PROFILE_PATH: &str = "/etc/sanctuary/launcher/agent-v1.json";
pub const REGISTRY_PATH: &str = "/etc/sanctuary/launcher/account-registry-v1.json";
pub const EXECUTABLE_PATH: &str = "/usr/local/libexec/sanctuary/protected-agent-v1";
const MAX_PROFILE: usize = 4096;
const MAX_EXECUTABLE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedProfile {
    pub schema: u32,
    pub profile_id: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub source_package: String,
    pub build_id: String,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistry {
    pub schema: u32,
    pub account_name: String,
    pub uid: u32,
    pub gid: u32,
    pub profile_id: String,
    pub profile_sha256: String,
}

pub struct ValidatedProfile {
    pub profile: FixedProfile,
    pub registry: AccountRegistry,
    pub profile_sha256: String,
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(unix)]
fn exact_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_dir() || m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != mode {
        return Err(bad("profile parent custody"));
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_file(path: &Path, mode: u32, max: usize) -> io::Result<Vec<u8>> {
    super::receipt::read_custodied_file(path, 0, &[0], mode, max)
}

#[cfg(unix)]
pub fn validate_installed() -> io::Result<ValidatedProfile> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    for (p, mode) in [
        ("/etc", 0o755),
        ("/etc/sanctuary", 0o755),
        ("/etc/sanctuary/launcher", 0o755),
        ("/usr", 0o755),
        ("/usr/local", 0o755),
        ("/usr/local/libexec", 0o755),
        ("/usr/local/libexec/sanctuary", 0o755),
    ] {
        exact_dir(Path::new(p), 0, 0, mode)?;
    }
    let raw = read_exact_file(Path::new(PROFILE_PATH), 0o644, MAX_PROFILE)?;
    let profile: FixedProfile = serde_json::from_slice(&raw).map_err(|_| bad("profile JSON"))?;
    if serde_json::to_vec(&profile).map_err(|_| bad("profile canonicalization"))? != raw {
        return Err(bad("profile bytes not canonical"));
    }
    if profile.schema != 1
        || profile.profile_id != "agent-v1"
        || profile.executable != EXECUTABLE_PATH
        || profile.argv != [EXECUTABLE_PATH]
        || profile.env != ["LANG=C"]
        || profile.cwd != "/"
        || profile.stdin != "/dev/null"
        || profile.stdout != "/dev/null"
        || profile.stderr != "/dev/null"
        || profile.source_package.is_empty()
        || profile.build_id.is_empty()
    {
        return Err(bad("profile not fixed agent-v1"));
    }
    let registry_raw = read_exact_file(Path::new(REGISTRY_PATH), 0o644, MAX_PROFILE)?;
    let registry: AccountRegistry =
        serde_json::from_slice(&registry_raw).map_err(|_| bad("registry JSON"))?;
    if serde_json::to_vec(&registry).map_err(|_| bad("registry canonicalization"))? != registry_raw
    {
        return Err(bad("registry bytes not canonical"));
    }
    let profile_hash = hex::encode(Sha256::digest(&raw));
    if registry.schema != 1
        || registry.profile_id != "agent-v1"
        || registry.profile_sha256 != profile_hash
        || registry.uid == 0
        || registry.gid == 0
        || registry.account_name.is_empty()
    {
        return Err(bad("registry/profile binding"));
    }
    let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(registry.gid))?
        .ok_or_else(|| bad("account group missing"))?;
    let user = nix::unistd::User::from_name(&registry.account_name)?
        .ok_or_else(|| bad("account user missing"))?;
    if user.uid.as_raw() != registry.uid
        || user.gid.as_raw() != registry.gid
        || group.gid.as_raw() != registry.gid
    {
        return Err(bad("registry/NSS mismatch"));
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut elf = opts.open(EXECUTABLE_PATH)?;
    let m = elf.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o755
        || m.len() == 0
        || m.len() > MAX_EXECUTABLE
    {
        return Err(bad("executable custody"));
    }
    let mut magic = [0u8; 4];
    elf.read_exact(&mut magic)?;
    if magic != *b"\x7fELF" {
        return Err(bad("executable is not ELF"));
    }
    use std::io::Seek;
    elf.rewind()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = elf.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    if hex::encode(h.finalize()) != profile.executable_sha256 {
        return Err(bad("executable digest mismatch"));
    }
    Ok(ValidatedProfile {
        profile,
        registry,
        profile_sha256: profile_hash,
    })
}

#[cfg(not(unix))]
pub fn validate_installed() -> io::Result<ValidatedProfile> {
    Err(bad("unsupported platform"))
}
