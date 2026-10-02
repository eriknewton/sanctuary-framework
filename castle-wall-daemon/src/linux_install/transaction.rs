//! Descriptor-relative custody, atomic records, and bounded helper execution.
use super::Result;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const RECORD_MAX_BYTES: usize = 32 * 1024; // One transaction and one recovery record, each capped at 32 KiB.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(5); // Fixed NSS/account observation deadline.
pub const HELPER_MAX_BYTES: usize = 256 * 1024; // Bounds both NSS enumeration and retained command output.
const HELPER_POLL: Duration = Duration::from_millis(10); // At most 100 output/deadline polls per second.

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
fn component(value: &str) -> Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err("invalid path component".into());
    }
    Ok(CString::new(value)?)
}
fn owned(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    // Root custody is checked on opened descriptors, never on a raced pathname.
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o022 != 0
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
    {
        return Err("unsafe file custody".into());
    }
    Ok(())
}
fn openat(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = component(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_snapshot(file: &File, cap: usize) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    if before.len() > cap as u64 {
        return Err("file quota exceeded".into());
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    // Growth and replacement-in-place invalidate the observation, including same-size rewrites.
    if bytes.len() > cap
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.ctime() != after.ctime()
    {
        return Err("file changed during read".into());
    }
    Ok(bytes)
}

/// A caller-selected trust anchor; the production CLI always opens `/`.
/// Library tests may anchor at a temporary directory without exposing a CLI seam.
pub struct Root {
    dir: File,
}
impl Root {
    pub fn open(path: &Path) -> Result<Self> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        owned(&dir, true)?;
        Ok(Self { dir })
    }
    fn parent(&self, path: &str) -> Result<(File, String)> {
        if path.starts_with('/') {
            return Err("relative path required".into());
        }
        let mut parts: Vec<_> = path.split('/').collect();
        let name = parts.pop().ok_or("empty path")?;
        component(name)?;
        let mut dir = self.dir.try_clone()?;
        for part in parts {
            dir = openat(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            owned(&dir, true)?;
        }
        Ok((dir, name.into()))
    }
    fn operator_parent(&self, path: &str, operator: u32, create: bool) -> Result<(File, String)> {
        let mut parts: Vec<_> = path.split('/').collect();
        let name = parts.pop().ok_or("empty path")?;
        component(name)?;
        let mut dir = self.dir.try_clone()?;
        for part in parts {
            component(part)?;
            if create {
                let rc =
                    unsafe { libc::mkdirat(dir.as_raw_fd(), component(part)?.as_ptr(), 0o700) };
                if rc != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if rc == 0 {
                    dir.sync_all()?;
                }
            }
            dir = openat(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let m = dir.metadata()?;
            // Explicit operator inputs/exports may live in that operator's home, but never in a U-controlled ancestor.
            if ![unsafe { libc::geteuid() }, operator].contains(&m.uid()) || m.mode() & 0o022 != 0 {
                return Err("unsafe operator path custody".into());
            }
        }
        Ok((dir, name.into()))
    }
    /// Snapshot caller-selected public input; installed authority continues to use `read`'s root-only custody.
    pub fn input(&self, path: &str, cap: usize, operator: u32) -> Result<Vec<u8>> {
        let (dir, name) = self.operator_parent(path, operator, false)?;
        let file = openat(&dir, &name, libc::O_RDONLY, 0)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || ![unsafe { libc::geteuid() }, operator].contains(&m.uid())
            || m.mode() & 0o022 != 0
        {
            return Err("unsafe input custody".into());
        }
        read_snapshot(&file, cap)
    }
    /// Create a fresh export directory through pinned descriptors; existing destinations are never adopted.
    pub fn output(&self, path: &str, operator: u32) -> Result<Self> {
        let (parent, name) = self.operator_parent(path, operator, true)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), component(&name)?.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dir = openat(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        owned(&dir, true)?;
        if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        parent.sync_all()?;
        Ok(Self { dir })
    }
    /// Classify a directory, including a leaf link's target, without opening its contents.
    /// Traversal still refuses links and rechecks custody through `entries`.
    pub fn is_directory(&self, path: &str) -> Result<bool> {
        let (parent, name) = self.parent(path)?;
        let name = component(&name)?;
        let mut meta = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                meta.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let kind = unsafe { meta.assume_init() }.st_mode & libc::S_IFMT;
        if kind != libc::S_IFLNK {
            return Ok(kind == libc::S_IFDIR);
        }
        // Must match install-lifecycle-guard.py's symlinked-directory refusal;
        // classify the target only so an unwalked directory cannot hide unit links.
        if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), meta.as_mut_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(false); // A dangling unit-file alias has no directory to inventory.
            }
            return Err(error.into());
        }
        Ok(unsafe { meta.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }
    pub fn mkdir(&self, path: &str, mode: u32) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        let c = component(&name)?;
        let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) };
        if rc != 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(std::io::Error::last_os_error().into());
        }
        let child = openat(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        owned(&child, true)?;
        if rc == 0 && unsafe { libc::fchmod(child.as_raw_fd(), mode) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if child.metadata()?.mode() & 0o7777 != mode {
            return Err("directory mode mismatch".into());
        }
        dir.sync_all()?;
        Ok(())
    }
    pub fn link_target(&self, path: &str) -> Result<Option<String>> {
        let (dir, name) = self.parent(path)?;
        let name = component(&name)?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return Ok(None);
        }
        if stat.st_uid != unsafe { libc::geteuid() } {
            return Err("foreign enablement link".into());
        }
        let mut bytes = vec![0; super::contract::STRING_MAX_BYTES + 1];
        let n = unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if n as usize >= bytes.len() {
            return Err("link target quota".into());
        }
        bytes.truncate(n as usize);
        Ok(Some(String::from_utf8(bytes)?))
    }
    pub fn entries(&self, path: &str, cap: usize) -> Result<Vec<String>> {
        let (parent, name) = self.parent(path)?;
        let dir = openat(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        owned(&dir, true)?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 directory entry")?;
            bytes += name.len();
            if bytes > cap {
                return Err("directory quota exceeded".into());
            }
            entries.push(name);
        }
        Ok(entries)
    }
    pub fn file(&self, path: &str) -> Result<File> {
        let (dir, name) = self.parent(path)?;
        let file = openat(&dir, &name, libc::O_RDONLY, 0)?;
        owned(&file, false)?;
        Ok(file)
    }
    pub fn read(&self, path: &str, cap: usize) -> Result<Vec<u8>> {
        let file = self.file(path)?;
        read_snapshot(&file, cap)
    }
    pub fn optional(&self, path: &str, cap: usize) -> Result<Option<Vec<u8>>> {
        match self.read(path, cap) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    pub fn write(&self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        // Refuse foreign destinations before rename; only our regular single-link files are replaceable.
        match openat(&dir, &name, libc::O_RDONLY, 0) {
            Ok(f) => owned(&f, false)?,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(e) => return Err(e),
        }
        let tmp = format!(".{name}.install-tmp");
        // One fixed scratch inode per destination bounds crash debris; it is never silently adopted.
        self.remove_relative(&dir, &tmp)?;
        let mut file = openat(
            &dir,
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            mode,
        )?;
        // Explicit modes do not depend on the invoking shell's umask.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        let rc = unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                component(&tmp)?.as_ptr(),
                dir.as_raw_fd(),
                component(&name)?.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dir.sync_all()?;
        Ok(())
    }
    fn remove_relative(&self, dir: &File, name: &str) -> Result<()> {
        match openat(dir, name, libc::O_RDONLY, 0) {
            Ok(file) => {
                owned(&file, false)?;
                if unsafe { libc::unlinkat(dir.as_raw_fd(), component(name)?.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                dir.sync_all()?;
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
    pub fn remove(&self, path: &str) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        self.remove_relative(&dir, &name)
    }
    pub fn lock(&self, path: &str) -> Result<File> {
        let (dir, name) = self.parent(path)?;
        let file = openat(&dir, &name, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        owned(&file, false)?;
        // Death releases flock; deleting a lock inode would let concurrent mutators split authority.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("mutation already in progress".into());
        }
        // The helper inherits this lease across exec. If the coordinator dies,
        // no retry can overlap an account helper that still holds the inode.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(file)
    }
}

#[derive(Debug)]
pub struct HelperOutput {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
/// Fixed-argv callers supply a single finite deadline and combined output cap.
pub fn run_bounded(
    program: &str,
    args: &[&str],
    timeout: Duration,
    cap: usize,
) -> Result<HelperOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent = std::process::id();
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Close the fork-to-prctl race: a helper whose parent already died never begins its mutation.
            if libc::getppid() as u32 != parent {
                return Err(std::io::Error::other("helper parent disappeared"));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let mut out = child.stdout.take().ok_or("missing helper stdout")?;
    let mut err = child.stderr.take().ok_or("missing helper stderr")?;
    let work = (|| -> Result<HelperOutput> {
        for fd in [out.as_raw_fd(), err.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let deadline = Instant::now() + timeout;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exited = false;
        let mut code = None;
        let mut ends = [false; 2];
        loop {
            for (index, reader, bytes) in [
                (0, &mut out as &mut dyn Read, &mut stdout),
                (1, &mut err as &mut dyn Read, &mut stderr),
            ] {
                let mut buf = [0u8; 1024]; // One KiB per stream per poll bounds deadline work even under a flood.
                match reader.read(&mut buf) {
                    Ok(0) => ends[index] = true,
                    Ok(n) => bytes.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => return Err(e.into()),
                }
            }
            if stdout.len() + stderr.len() > cap {
                return Err("helper output quota exceeded".into());
            }
            if !exited {
                // Keep the child waitable until group cleanup, preventing PID reuse from redirecting SIGKILL.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id(),
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if unsafe { info.si_pid() } != 0 {
                    exited = true;
                    if info.si_code == libc::CLD_EXITED {
                        code = Some(unsafe { info.si_status() });
                    }
                }
            }
            if exited && ends.iter().all(|v| *v) {
                return Ok(HelperOutput {
                    code,
                    stdout,
                    stderr,
                });
            }
            if Instant::now() >= deadline {
                return Err("helper deadline exceeded".into());
            }
            std::thread::sleep(HELPER_POLL);
        }
    })();
    // Kill the entire helper group even after parent exit, then reap before admitting another helper.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let reaped = child.wait();
    reaped?;
    work
}
pub fn checked(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = run_bounded(program, args, HELPER_TIMEOUT, HELPER_MAX_BYTES)?;
    if out.code != Some(0) {
        return Err(format!("helper refused: {program}").into());
    }
    Ok(out.stdout)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Absent,
    AccountsCreated,
    CommandStaged,
    PolicyInstalled,
    Configured,
    Enabled,
    Running,
    Stopped,
    RepairRequired,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub version: u32,
    pub request_sha256: String,
    pub state: State,
    pub agent_uid: u32,
    pub service_uid: u32,
    pub operator_uid: u32,
    pub fortress_id: String,
    pub sanctuary_gid: Option<u32>,
    pub account_step: super::account::AccountStep,
    pub policy_generation: u64,
    pub policy_request_sha256: Option<String>,
    pub policy_complete: bool,
}
impl Transaction {
    pub fn save(&self, root: &Root) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > RECORD_MAX_BYTES {
            return Err("transaction quota".into());
        }
        root.write("etc/sanctuary/install-transaction.json", &bytes, 0o600)
    }
    pub fn load(root: &Root) -> Result<Option<Self>> {
        let Some(bytes) =
            root.optional("etc/sanctuary/install-transaction.json", RECORD_MAX_BYTES)?
        else {
            return Ok(None);
        };
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err("transaction must be an object".into());
        }
        let value: Self = serde_json::from_slice(&bytes)?;
        value.validate()?;
        Ok(Some(value))
    }
    pub fn validate(&self) -> Result<()> {
        crate::config::validate_fortress_id(&self.fortress_id)?;
        if self.version != super::contract::VERSION
            || [0, u32::MAX, self.operator_uid].contains(&self.agent_uid)
        {
            return Err("transaction version or agent identity".into());
        }
        let digest = |s: &str| {
            s.len() == super::contract::SHA256_HEX_BYTES
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !digest(&self.request_sha256)
            || self
                .policy_request_sha256
                .as_ref()
                .is_some_and(|s| !digest(s))
            || self.service_uid == 0
            || self.service_uid == u32::MAX
            || self.service_uid == self.agent_uid
            || self.operator_uid == u32::MAX
        {
            return Err("transaction identity malformed".into());
        }
        if self.account_step != super::account::AccountStep::Fresh && self.sanctuary_gid.is_none() {
            return Err("transaction account intent absent".into());
        }
        if self.policy_complete
            && (self.policy_generation == 0
                || self.policy_request_sha256.is_none()
                || self.account_step != super::account::AccountStep::Complete)
        {
            return Err("transaction completion is inconsistent".into());
        }
        Ok(())
    }
}
