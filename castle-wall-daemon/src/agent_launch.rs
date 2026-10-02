//! The install-profile second exec. Root-authored records select literal argv;
//! they do not replace the unit's READY and live kernel admission checks.

use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::agent_start::{
    credential_verdict, parse_status_credentials, CredentialSnapshot, CredentialVerdict,
};
use crate::linux_install::contract::*;
use sha2::{Digest, Sha256};

fn refused(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn require(ok: bool, reason: &'static str) -> io::Result<()> {
    if !ok {
        return Err(refused(reason));
    }
    Ok(())
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| refused("NUL in path or argument"))
}

fn protected_directory(m: &Metadata) -> bool {
    m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0
}

/// Walk from a pinned root descriptor: neither a symlink nor a writable parent
/// may redirect a Configured record or executable after custody was checked.
fn open_custodied(path: &str, directory: bool) -> io::Result<File> {
    require(path.starts_with('/'), "absolute custody path required")?;
    let parts: Vec<_> = path[1..].split('/').collect();
    require(
        parts
            .iter()
            .all(|p| !p.is_empty() && *p != "." && *p != ".."),
        "noncanonical custody path",
    )?;
    let mut parent = File::open("/")?;
    require(protected_directory(&parent.metadata()?), "root custody")?;
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let name = cstr(OsStr::new(part))?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if !last || directory {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: parent and name live through openat; a successful fd is owned once.
        let fd = cvt(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) })?;
        let next = unsafe { File::from_raw_fd(fd) };
        if !last {
            require(protected_directory(&next.metadata()?), "parent custody")?;
        }
        parent = next;
    }
    Ok(parent)
}

fn regular_custody(m: &Metadata) -> bool {
    m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o7022 == 0
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
}

pub(crate) fn read_record(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    read_open_record(open_custodied(path, false)?, limit)
}

fn read_open_record(mut file: File, limit: usize) -> io::Result<Vec<u8>> {
    let before = file.metadata()?;
    // Custody and the encoded limit are checked before any potentially blocking read.
    require(
        regular_custody(&before) && before.len() <= limit as u64,
        "record custody or size",
    )?;
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= limit
            && bytes.len() as u64 == before.len()
            && same_file(&before, &file.metadata()?),
        "record changed during read",
    )?;
    Ok(bytes)
}

fn kernel_text(path: &str) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(COMMAND_MAX_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    require(
        text.len() <= COMMAND_MAX_BYTES,
        "kernel observation exceeds bound",
    )?;
    Ok(text)
}

fn status_ids(text: &str, field: &str, uid: u32) -> bool {
    let prefix = format!("{field}:");
    let rows: Vec<_> = text
        .lines()
        .filter_map(|s| s.strip_prefix(&prefix))
        .collect();
    rows.len() == 1
        && rows[0]
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            == Ok(vec![uid; 4])
}

fn credentials(uid: u32) -> io::Result<()> {
    require(uid != 0 && uid != u32::MAX, "nonroot identity required")?;
    let u = nix::unistd::getresuid()?;
    let g = nix::unistd::getresgid()?;
    let status = kernel_text("/proc/self/status")?;
    let snapshot = CredentialSnapshot {
        uids: [u.real.as_raw(), u.effective.as_raw(), u.saved.as_raw()],
        gids: [g.real.as_raw(), g.effective.as_raw(), g.saved.as_raw()],
        groups: nix::unistd::getgroups()?
            .into_iter()
            .map(|v| v.as_raw())
            .collect(),
        status: parse_status_credentials(&status),
    };
    require(
        credential_verdict(uid, &snapshot) == CredentialVerdict::Match,
        "credential confinement",
    )?;
    // Filesystem ids and inheritable capabilities also survive decisions the old
    // precheck cannot observe; all four ids must name the configured principal.
    require(
        status_ids(&status, "Uid", uid) && status_ids(&status, "Gid", uid),
        "filesystem identity",
    )?;
    let inh: Vec<_> = status
        .lines()
        .filter_map(|l| l.strip_prefix("CapInh:"))
        .collect();
    require(
        inh.len() == 1 && u64::from_str_radix(inh[0].trim(), 16) == Ok(0),
        "inheritable capabilities",
    )
}

fn record_binding(
    command: &CommandV1,
    marker: &ConfiguredV1,
    command_bytes: &[u8],
    endpoint_bytes: &[u8],
) -> io::Result<()> {
    // Configured is root testimony about these exact bytes and principal, not an
    // authority to pick a different uid or skip the wall's kernel gate.
    require(
        command.agent_uid == marker.agent_uid && command.fortress_id == marker.fortress_id,
        "Configured identity differs",
    )?;
    require(
        format!("{:x}", Sha256::digest(command_bytes)) == marker.command_sha256
            && format!("{:x}", Sha256::digest(endpoint_bytes)) == marker.endpoints_sha256,
        "Configured digest differs",
    )
}

fn native_elf(header: &[u8; 64]) -> bool {
    // ELFCLASS64, ELFDATA2LSB, EV_CURRENT; ET_EXEC/ET_DYN and EM_X86_64.
    &header[..7] == b"\x7fELF\x02\x01\x01"
        && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        && u16::from_le_bytes([header[18], header[19]]) == 62
}

fn executable(path: &str) -> io::Result<File> {
    let mut file = open_custodied(path, false)?;
    let before = file.metadata()?;
    require(
        regular_custody(&before) && before.mode() & 0o111 != 0,
        "executable custody",
    )?;
    let mut header = [0u8; 64]; // ELF64_Ehdr length, not a file-size limit.
    file.read_exact(&mut header)?;
    require(native_elf(&header), "native amd64 ELF required")?;
    let attr = CString::new("security.capability").expect("literal");
    // Capability-bearing files are outside this profile even with NoNewPrivs;
    // querying the held fd avoids inspecting a different executable pathname.
    let cap = unsafe { libc::fgetxattr(file.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0) };
    require(
        cap < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
            ),
        "file capabilities",
    )?;
    require(
        same_file(&before, &file.metadata()?),
        "executable changed during inspection",
    )?;
    Ok(file)
}

fn workspace() -> io::Result<File> {
    let file = open_custodied(WORKSPACE_PATH, true)?;
    let meta = file.metadata()?;
    require(
        meta.uid() == 0 && meta.mode() & 0o7777 == 0o1777,
        "workspace custody",
    )?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    cvt(unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) })?;
    cvt(unsafe { libc::fstatvfs(file.as_raw_fd(), vfs.as_mut_ptr()) })?;
    let fs = unsafe { fs.assume_init() };
    let vfs = unsafe { vfs.assume_init() };
    let safety_flags = libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    // The root-owned unmounted directory cannot serve as a writable fallback.
    require(
        fs.f_type == libc::TMPFS_MAGIC
            && vfs.f_flag & safety_flags == safety_flags
            && vfs.f_blocks > 0
            && vfs.f_frsize > 0
            && vfs
                .f_blocks
                .checked_mul(vfs.f_frsize)
                .is_some_and(|n| n <= WORKSPACE_MAX_BYTES as u64)
            && vfs.f_files > 0
            && vfs.f_files <= WORKSPACE_MAX_INODES as u64,
        "mandatory workspace limits",
    )?;
    Ok(file)
}

fn exec_second(file: File, command: &CommandV1) -> io::Result<()> {
    let argv: Vec<CString> = std::iter::once(&command.executable)
        .chain(command.argv.iter())
        .map(|s| cstr(OsStr::new(s)))
        .collect::<io::Result<_>>()?;
    let environment: Vec<CString> = std::iter::once(format!("HOME={WORKSPACE_PATH}"))
        .chain(command.env.iter().map(|(k, v)| format!("{k}={v}")))
        .map(|s| cstr(OsStr::new(&s)))
        .collect::<io::Result<_>>()?;
    let argv_ptrs: Vec<_> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_ptrs: Vec<_> = environment
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // fd 3 is the sole temporary exec descriptor and CLOEXEC removes it in the
    // workload. close_range closes arbitrary inherited sockets, not only known fds.
    let source = file.into_raw_fd();
    let exec_fd = 3; // First descriptor above stdin/stdout/stderr.
    if source != exec_fd {
        cvt(unsafe { libc::dup3(source, exec_fd, libc::O_CLOEXEC) })?;
    } else {
        cvt(unsafe { libc::fcntl(exec_fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    }
    let null = CString::new("/dev/null").expect("literal");
    let opened_null = cvt(unsafe {
        libc::open(
            null.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })?;
    // Even a caller with closed standard fds receives three non-CLOEXEC null
    // streams: keep the source above them so dup2 never degenerates to a no-op.
    let null_fd = cvt(unsafe { libc::fcntl(opened_null, libc::F_DUPFD_CLOEXEC, 4) })?;
    if opened_null != null_fd {
        unsafe {
            libc::close(opened_null);
        }
    }
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    cvt(unsafe { libc::fstat(null_fd, st.as_mut_ptr()) })?;
    let st = unsafe { st.assume_init() };
    require(
        st.st_mode & libc::S_IFMT == libc::S_IFCHR
            && libc::major(st.st_rdev) == 1
            && libc::minor(st.st_rdev) == 3,
        "null device identity",
    )?;
    for target in 0..=2 {
        cvt(unsafe { libc::dup2(null_fd, target) })?;
    }
    // Linux >=5.9 is part of the Ubuntu 24.04 floor; ENOSYS is fatal, never a
    // best-effort fd loop whose ceiling could leave a foreign socket alive.
    let closed = unsafe { libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) };
    require(closed == 0, "close inherited descriptors")?;
    unsafe { libc::fexecve(exec_fd, argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
    Err(io::Error::last_os_error())
}

/// No arguments or path overrides exist in the production trampoline. Successful
/// return is impossible: direct fexecve preserves the manager's MainPID/start ticks.
pub fn launch() -> io::Result<()> {
    // state RECORDS: every required record is descriptor-bounded and root-custodied.
    require(
        std::env::args_os().len() == 1,
        "launcher takes no arguments",
    )?;
    let command_bytes = read_record(COMMAND_PATH, COMMAND_MAX_BYTES)?;
    let endpoint_bytes = read_record(ENDPOINTS_PATH, ENDPOINTS_MAX_BYTES)?;
    let marker = ConfiguredV1::parse(&read_record(CONFIGURED_PATH, CONFIGURED_MAX_BYTES)?)
        .map_err(io::Error::other)?;
    let command = CommandV1::parse(&command_bytes).map_err(io::Error::other)?;
    EndpointsV1::parse(&endpoint_bytes).map_err(io::Error::other)?;
    record_binding(&command, &marker, &command_bytes, &endpoint_bytes)?;
    // state IDENTITY: Configured never authorizes a credential transition.
    credentials(command.agent_uid)?;
    let fortress =
        std::env::var("SANCTUARY_FORTRESS_ID").map_err(|_| refused("unit fortress absent"))?;
    let service = std::env::var("SANCTUARY_TRUSTED_SERVICE_UID")
        .ok()
        .and_then(|s| crate::agent_start::parse_instance_uid(&s))
        .ok_or_else(|| refused("unit service uid absent"))?;
    let overflow: u32 = kernel_text("/proc/sys/kernel/overflowuid")?
        .trim()
        .parse()
        .map_err(|_| refused("overflow uid unavailable"))?;
    require(
        command.fortress_id == fortress
            && command.agent_uid != service
            && command.agent_uid != overflow,
        "unit identity differs",
    )?;
    // state PREPARED: cwd and ELF descriptors are retained through the second exec.
    let program = executable(&command.executable)?;
    let work = workspace()?;
    cvt(unsafe { libc::fchdir(work.as_raw_fd()) })?;
    drop(work);
    // state EXEC: no subprocess, shell, PATH search or inherited environment.
    exec_second(program, &command)
}

/// The stand-in consumes the same descriptor-bounded endpoint parser as launch.
/// A partial provision cannot become a network schedule even when invoked directly.
pub fn installed_endpoints() -> io::Result<EndpointsV1> {
    let bytes = read_record(ENDPOINTS_PATH, ENDPOINTS_MAX_BYTES)?;
    let marker = ConfiguredV1::parse(&read_record(CONFIGURED_PATH, CONFIGURED_MAX_BYTES)?)
        .map_err(io::Error::other)?;
    require(
        format!("{:x}", Sha256::digest(&bytes)) == marker.endpoints_sha256,
        "Configured endpoint digest differs",
    )?;
    EndpointsV1::parse(&bytes).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn configured_binds_exact_bytes_and_principal() {
        let cb = serde_json::to_vec(&json!({"version":1,"agent_uid":60123,"fortress_id":"0123456789abcdef","executable":STANDIN_PATH,"argv":[],"env":{},"resource_profile":RESOURCE_PROFILE})).unwrap();
        let command = CommandV1::parse(&cb).unwrap();
        let eb = b"endpoint bytes";
        let mut marker = ConfiguredV1 {
            version: 1,
            agent_uid: command.agent_uid,
            fortress_id: command.fortress_id.clone(),
            command_sha256: format!("{:x}", Sha256::digest(&cb)),
            endpoints_sha256: format!("{:x}", Sha256::digest(eb)),
            public_pin_sha256: "0".repeat(64),
            policy_generation: 1,
            policy_signature_b64url: String::new(),
            policy_sha256: "0".repeat(64),
        };
        assert!(record_binding(&command, &marker, &cb, eb).is_ok());
        for field in ["uid", "fortress", "command", "endpoints"] {
            let mut bad = marker.clone();
            match field {
                "uid" => bad.agent_uid += 1,
                "fortress" => bad.fortress_id.push('0'),
                "command" => bad.command_sha256 = "0".repeat(64),
                _ => bad.endpoints_sha256 = "0".repeat(64),
            }
            assert!(record_binding(&command, &bad, &cb, eb).is_err(), "{field}");
        }
        marker.command_sha256 = format!("{:x}", Sha256::digest(&cb));
        assert!(record_binding(&command, &marker, &[cb.as_slice(), b" "].concat(), eb).is_err());
    }

    #[test]
    fn status_requires_filesystem_ids_and_single_rows() {
        assert!(status_ids("Uid:\t42 42 42 42\n", "Uid", 42));
        for text in [
            "Uid: 42 42 42 0",
            "Uid: 42 42 42",
            "Uid: 42 42 42 42\nUid: 42 42 42 42",
            "Uid: 42 42 42 unknown",
        ] {
            assert!(!status_ids(text, "Uid", 42));
        }
    }

    #[test]
    fn custody_refuses_symlinks_writable_parents_and_special_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("record");
        std::fs::write(&file, b"{}").unwrap();
        // /tmp is writable regardless of file ownership; no launch input may
        // be smuggled through such a parent even on a root-run test worker.
        assert!(open_custodied(file.to_str().unwrap(), false).is_err());
        let root_file = regular_custody(&std::fs::metadata(&file).unwrap());
        assert_eq!(root_file, unsafe { libc::geteuid() } == 0);
        for mode in [0o666, 0o4755, 0o2755, 0o1755] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(!regular_custody(&std::fs::metadata(&file).unwrap()));
        }
        assert!(!regular_custody(&std::fs::metadata(dir.path()).unwrap()));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&file, dir.path().join("alias")).unwrap();
        assert!(!regular_custody(&std::fs::metadata(&file).unwrap()));
        assert!(open_custodied("/dev/null", false).is_ok());
        assert!(executable("/dev/null").is_err());
        assert!(!protected_directory(&std::fs::metadata(&file).unwrap()));
        let fifo = dir.path().join("fifo");
        let fifo_name = cstr(fifo.as_os_str()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(!regular_custody(&std::fs::metadata(&fifo).unwrap()));
        if unsafe { libc::geteuid() } == 0 {
            assert!(protected_directory(&std::fs::metadata(dir.path()).unwrap()));
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(!protected_directory(
                &std::fs::metadata(dir.path()).unwrap()
            ));
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let parent = File::open(dir.path()).unwrap();
            assert_eq!(unsafe { libc::fchown(parent.as_raw_fd(), 1, 1) }, 0);
            assert!(!protected_directory(&parent.metadata().unwrap()));
        }

        assert!(open_custodied("/proc/self/exe", false).is_err());
    }
    #[test]
    fn elf_admission_requires_native_binary_shape() {
        let mut good = [0u8; 64];
        good[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        good[16] = 3;
        good[18] = 62;
        assert!(native_elf(&good));
        good[16] = 2;
        assert!(native_elf(&good));
        for (index, value) in [
            (0, b'#'),
            (4, 1),
            (5, 2),
            (6, 0),
            (16, 1),
            (17, 1),
            (18, 3),
            (19, 1),
        ] {
            let mut bad = good;
            bad[index] = value;
            assert!(!native_elf(&bad), "ELF field {index}");
        }
    }

    #[test]
    fn encoded_read_and_mutation_detection_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record");
        std::fs::write(&path, b"four").unwrap();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(
                read_open_record(File::open(&path).unwrap(), 4).unwrap(),
                b"four"
            );
            assert!(read_open_record(File::open(&path).unwrap(), 3).is_err());
            let fd = File::open(&path).unwrap();
            assert_eq!(unsafe { libc::fchown(fd.as_raw_fd(), 1, 1) }, 0);
            assert!(!regular_custody(&fd.metadata().unwrap()));
        }
        let before = std::fs::metadata(&path).unwrap();
        std::fs::write(&path, b"longer").unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert!(!same_file(&before, &after));
        assert!(same_file(&after, &after));
    }
}
