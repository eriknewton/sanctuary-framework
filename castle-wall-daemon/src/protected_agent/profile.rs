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
    validate_executable(Path::new(EXECUTABLE_PATH), &profile.executable_sha256)?;
    Ok(ValidatedProfile {
        profile,
        registry,
        profile_sha256: profile_hash,
    })
}

#[cfg(unix)]
fn validate_executable(path: &Path, expected_sha256: &str) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut opts = fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let mut elf = opts.open(path)?;
    let m = elf.metadata()?;
    if !m.file_type().is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o755
        || m.len() == 0
        || m.len() > MAX_EXECUTABLE
    {
        return Err(bad("executable custody"));
    }
    let digest = hash_executable(&mut elf, MAX_EXECUTABLE)?;
    if hex::encode(digest) != expected_sha256 {
        return Err(bad("executable digest mismatch"));
    }
    Ok(())
}

#[cfg(unix)]
fn hash_executable(
    reader: &mut (impl Read + std::io::Seek),
    max_bytes: u64,
) -> io::Result<[u8; 32]> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != *b"\x7fELF" {
        return Err(bad("executable is not ELF"));
    }
    reader.rewind()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 16384];
    let mut total = 0u64;
    loop {
        let remaining_plus_one = max_bytes
            .checked_add(1)
            .and_then(|max| max.checked_sub(total))
            .ok_or_else(|| bad("executable oversized"))?;
        let take = usize::try_from(remaining_plus_one.min(buf.len() as u64))
            .map_err(|_| bad("executable oversized"))?;
        let n = reader.read(&mut buf[..take])?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| bad("executable oversized"))?;
        if total > max_bytes {
            return Err(bad("executable oversized"));
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn profile_registry_and_executable_fifo_paths_refuse_promptly() {
        use std::{ffi::CString, os::fd::FromRawFd, time::Instant};
        const CHILD: &str = "B1A_PROFILE_FIFO_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "protected_agent::profile::tests::profile_registry_and_executable_fifo_paths_refuse_promptly",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "profile FIFO child failed with {status}");
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("profile FIFO child exceeded five seconds and was killed");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        let dir = tempfile::tempdir().unwrap();
        for name in ["profile", "registry", "executable"] {
            let path = dir.path().join(name);
            let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            let started = Instant::now();
            let result = if name == "executable" {
                validate_executable(&path, "00")
            } else {
                read_exact_file(&path, 0o644, MAX_PROFILE).map(|_| ())
            };
            let error = result.expect_err(&format!("{name} FIFO unexpectedly accepted"));
            assert_eq!(
                error.to_string(),
                if name == "executable" {
                    "executable custody"
                } else {
                    "unsafe custody"
                },
                "{name} FIFO did not fail at custody/type validation"
            );
            assert!(
                started.elapsed().as_secs() < 5,
                "{name} FIFO did not refuse promptly"
            );
            let held_writer = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            assert!(held_writer >= 0);
            let held_writer = unsafe { fs::File::from_raw_fd(held_writer) };
            let held_result = if name == "executable" {
                validate_executable(&path, "00")
            } else {
                read_exact_file(&path, 0o644, MAX_PROFILE).map(|_| ())
            };
            let held_error = held_result.expect_err("held-writer FIFO unexpectedly accepted");
            assert_eq!(
                held_error.to_string(),
                if name == "executable" {
                    "executable custody"
                } else {
                    "unsafe custody"
                }
            );
            drop(held_writer);
        }

        let zero = Path::new("/dev/zero");
        if zero.exists() {
            assert_eq!(
                validate_executable(zero, "00").unwrap_err().to_string(),
                "executable custody"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn executable_validation_keeps_elf_and_digest_checks() {
        use std::os::unix::fs::PermissionsExt;
        // The production contract requires root:root ownership, which only root can create.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("elf");
        let mut bytes = vec![b'x'; MAX_EXECUTABLE as usize];
        bytes[..4].copy_from_slice(b"\x7fELF");
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let expected = hex::encode(Sha256::digest(&bytes));
        validate_executable(&path, &expected).unwrap();
        assert!(validate_executable(&path, "00").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn executable_hasher_rejects_growth_after_prefix_and_accepts_exact_limit() {
        use std::io::{Cursor, Read, Seek, SeekFrom};

        struct GrowingAfterRewind {
            bytes: Vec<u8>,
            position: usize,
            rewinds: usize,
        }
        impl Read for GrowingAfterRewind {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let count = out
                    .len()
                    .min(self.bytes.len().saturating_sub(self.position));
                out[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
                self.position += count;
                Ok(count)
            }
        }
        impl Seek for GrowingAfterRewind {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                match position {
                    SeekFrom::Start(0) => {
                        if self.rewinds == 0 {
                            self.bytes.extend_from_slice(b"-grew");
                        }
                        self.rewinds += 1;
                        self.position = 0;
                    }
                    SeekFrom::Current(0) => {}
                    _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek")),
                }
                Ok(self.position as u64)
            }
        }

        let mut exact = vec![b'x'; 16];
        exact[..4].copy_from_slice(b"\x7fELF");
        let expected: [u8; 32] = Sha256::digest(&exact).into();
        assert_eq!(
            hash_executable(&mut Cursor::new(exact.clone()), 16).unwrap(),
            expected
        );
        hash_executable(&mut Cursor::new(exact), MAX_EXECUTABLE).unwrap();

        let mut exact_cap = vec![b'x'; MAX_EXECUTABLE as usize];
        exact_cap[..4].copy_from_slice(b"\x7fELF");
        let exact_cap_hash: [u8; 32] = Sha256::digest(&exact_cap).into();
        assert_eq!(
            hash_executable(&mut Cursor::new(exact_cap), MAX_EXECUTABLE).unwrap(),
            exact_cap_hash
        );

        let mut growing = GrowingAfterRewind {
            bytes: b"\x7fELF".to_vec(),
            position: 0,
            rewinds: 0,
        };
        assert_eq!(
            hash_executable(&mut growing, 8).unwrap_err().to_string(),
            "executable oversized"
        );
    }
}

#[cfg(not(unix))]
pub fn validate_installed() -> io::Result<ValidatedProfile> {
    Err(bad("unsupported platform"))
}
