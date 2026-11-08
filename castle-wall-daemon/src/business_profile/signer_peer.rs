//! AF_UNIX identity is kernel supplied on every message, never a field in a request.
use std::{fs, io, mem, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}, path::Path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{custody::{refused, ARTIFACT_MAX_BYTES}, signer_contract::SIGNER_FRAME_MAX_BYTES};
use std::io::Read;
pub const SO_PEERPIDFD: i32 = 77;
pub const ANCILLARY_WORDS: usize = 32;
pub const MAX_RIGHTS: usize = 8;
pub const PROC_MAX_BYTES: u64 = 65_536;
pub const KERNEL_MIN: (u32, u32) = (6, 5);
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy { pub uid: u32, pub executable_sha256: String, pub cgroup: String }
pub struct Peer { pub pid: i32, pub uid: u32, pub gid: u32, pub start: String, pidfd: OwnedFd }
impl Peer {
    pub fn capture(fd: RawFd, policy: &PeerPolicy) -> io::Result<Self> {
        let mut cred: libc::ucred = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut len) } != 0 { return Err(refused()); }
        let mut pidfd = -1;
        len = mem::size_of::<i32>() as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_PEERPIDFD, &mut pidfd as *mut _ as *mut _, &mut len) } != 0 { return Err(refused()); }
        let held = unsafe { OwnedFd::from_raw_fd(pidfd) };
        // A UID claim cannot authorize a connection because executable, cgroup and retained process identity must also agree.
        if cred.uid != policy.uid { return Err(refused()); }
        let start = process_start(cred.pid)?;
        let group = bounded_text(&format!("/proc/{}/cgroup", cred.pid))?;
        if group.trim() != policy.cgroup { return Err(refused()); }
        let file = fs::File::open(format!("/proc/{}/exe", cred.pid))?;
        if file.metadata()?.len() > ARTIFACT_MAX_BYTES { return Err(refused()); }
        let mut hash = Sha256::new(); io::copy(&mut file.take(ARTIFACT_MAX_BYTES + 1), &mut hash)?;
        if hex::encode(hash.finalize()) != policy.executable_sha256 { return Err(refused()); }
        let peer = Self { pid: cred.pid, uid: cred.uid, gid: cred.gid, start, pidfd: held };
        if !peer.live() || process_start(peer.pid)? != peer.start { return Err(refused()); } Ok(peer)
    }
    pub fn live(&self) -> bool {
        let mut poll = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut poll, 1, 0) == 0 }
    }
    pub fn matches(&self, cred: &libc::ucred) -> bool {
        // Passed sockets lose authority because SCM_CREDENTIALS identifies the process that actually sent this packet.
        self.live() && cred.pid == self.pid && cred.uid == self.uid && cred.gid == self.gid
    }
}
fn bounded_text(path: &str) -> io::Result<String> {
    let mut data = String::new(); fs::File::open(path)?.take(PROC_MAX_BYTES + 1).read_to_string(&mut data)?;
    if data.len() as u64 > PROC_MAX_BYTES { return Err(refused()); } Ok(data)
}
fn process_start(pid: i32) -> io::Result<String> {
    let text = bounded_text(&format!("/proc/{pid}/stat"))?;
    // Fields after the closing command parenthesis start at field three; starttime is field twenty two.
    const START_OFFSET: usize = 19;
    text.rsplit_once(')').and_then(|(_, tail)| tail.split_whitespace().nth(START_OFFSET)).map(str::to_owned).ok_or_else(refused)
}
pub fn passcred(fd: RawFd) -> io::Result<()> {
    let yes: i32 = 1;
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_PASSCRED, &yes as *const _ as *const _, mem::size_of_val(&yes) as _) } != 0 { return Err(refused()); } Ok(())
}
pub struct Packet { pub bytes: Vec<u8>, pub rights: Vec<OwnedFd>, pub cred: libc::ucred }
pub fn receive(fd: RawFd, max: usize) -> io::Result<Packet> {
    if max > SIGNER_FRAME_MAX_BYTES { return Err(refused()); }
    let mut bytes = vec![0u8; max];
    let mut control = [0usize; ANCILLARY_WORDS];
    let mut iov = libc::iovec { iov_base: bytes.as_mut_ptr() as _, iov_len: bytes.len() };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov; msg.msg_iovlen = 1; msg.msg_control = control.as_mut_ptr() as _; msg.msg_controllen = mem::size_of_val(&control);
    let size = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    if size <= 0 { return Err(refused()); }
    let mut rights = Vec::new(); let mut cred = None; let mut invalid = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let h = &*header;
            if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                let count = (h.cmsg_len - libc::CMSG_LEN(0) as usize) / mem::size_of::<i32>();
                for index in 0..count { rights.push(OwnedFd::from_raw_fd(*(libc::CMSG_DATA(header) as *const i32).add(index))); }
            } else if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_CREDENTIALS && h.cmsg_len == libc::CMSG_LEN(mem::size_of::<libc::ucred>() as _) as usize && cred.is_none() {
                cred = Some(*(libc::CMSG_DATA(header) as *const libc::ucred));
            } else { invalid = true; }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    // Truncated data or ancillary records refuse before parsing while RAII closes every received descriptor.
    if invalid || rights.len() > MAX_RIGHTS || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 { return Err(refused()); }
    bytes.truncate(size as usize);
    Ok(Packet { bytes, rights, cred: cred.ok_or_else(refused)? })
}
pub fn send(fd: RawFd, bytes: &[u8], rights: &[RawFd]) -> io::Result<()> {
    if bytes.len() > SIGNER_FRAME_MAX_BYTES || rights.len() > MAX_RIGHTS { return Err(refused()); }
    let mut iov = libc::iovec { iov_base: bytes.as_ptr() as _, iov_len: bytes.len() };
    let mut control = [0usize; ANCILLARY_WORDS];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov; msg.msg_iovlen = 1;
    if !rights.is_empty() { unsafe {
        msg.msg_control = control.as_mut_ptr() as _;
        msg.msg_controllen = libc::CMSG_SPACE(mem::size_of_val(rights) as _) as usize;
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET; (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(rights) as _) as usize;
        std::ptr::copy_nonoverlapping(rights.as_ptr(), libc::CMSG_DATA(header) as *mut i32, rights.len());
    } }
    if unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) } != bytes.len() as isize { return Err(refused()); } Ok(())
}
pub fn socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 { return Err(refused()); }
    let result = unsafe { OwnedFd::from_raw_fd(fd) }; passcred(fd)?; Ok(result)
}
fn address(path: &Path) -> io::Result<libc::sockaddr_un> {
    use std::os::unix::ffi::OsStrExt;
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() }; let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) { return Err(refused()); }
    addr.sun_family = libc::AF_UNIX as _;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) { *dst = *src as _; } Ok(addr)
}
pub fn connect(path: &Path) -> io::Result<OwnedFd> {
    let fd = socket()?; let addr = address(path)?;
    if unsafe { libc::connect(fd.as_raw_fd(), &addr as *const _ as _, mem::size_of_val(&addr) as _) } != 0 { return Err(refused()); } Ok(fd)
}
pub fn listen(path: &Path) -> io::Result<OwnedFd> {
    let fd = socket()?; let addr = address(path)?;
    // A zero backlog reserves at most one pending connection, accounted for by the service accepted-slot limit.
    if unsafe { libc::bind(fd.as_raw_fd(), &addr as *const _ as _, mem::size_of_val(&addr) as _) } != 0 || unsafe { libc::chmod(std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| refused())?.as_ptr(), super::custody::PRIVATE_MODE) } != 0 || unsafe { libc::listen(fd.as_raw_fd(), 0) } != 0 { return Err(refused()); } Ok(fd)
}
pub fn accept(fd: RawFd) -> io::Result<OwnedFd> {
    let accepted = unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) };
    if accepted < 0 { return Err(refused()); } let result = unsafe { OwnedFd::from_raw_fd(accepted) }; passcred(accepted)?; Ok(result)
}
pub fn tty_check(fd: RawFd, pid: i32) -> io::Result<libc::termios> {
    let mut stat: libc::stat = unsafe { mem::zeroed() }; let mut term: libc::termios = unsafe { mem::zeroed() };
    // TIOCGDEV identifies the held terminal across sessions without granting the supervisor a controlling terminal.
    const TIOCGDEV: libc::c_ulong = 0x80045432;
    const SESSION_OFFSET: usize = 3;
    const TTY_OFFSET: usize = 4;
    const FOREGROUND_OFFSET: usize = 5;
    let mut device: u32 = 0;
    let text = bounded_text(&format!("/proc/{pid}/stat"))?;
    let fields: Vec<&str> = text.rsplit_once(')').ok_or_else(refused)?.1.split_whitespace().collect();
    let field = |i: usize| fields.get(i).and_then(|s| s.parse::<i64>().ok()).ok_or_else(refused);
    // Kernel terminal device, session and foreground group must name the actual sender, never message claims.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFCHR || unsafe { libc::isatty(fd) } != 1 ||
        unsafe { libc::ioctl(fd, TIOCGDEV, &mut device) } != 0 || device == 0 || device != field(TTY_OFFSET)? as u32 ||
        field(SESSION_OFFSET)? != unsafe { libc::getsid(pid) } as i64 || field(FOREGROUND_OFFSET)? != unsafe { libc::getpgid(pid) } as i64 ||
        unsafe { libc::tcgetattr(fd, &mut term) } != 0 { return Err(refused()); }
    Ok(term)
}
pub fn kernel_probe() -> io::Result<()> {
    let mut uts: libc::utsname = unsafe { mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 { return Err(refused()); }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_str().map_err(|_| refused())?;
    let mut parts = release.split('.');
    let version = (parts.next().and_then(|s| s.parse::<u32>().ok()).ok_or_else(refused)?, parts.next().and_then(|s| s.parse::<u32>().ok()).ok_or_else(refused)?);
    if version < KERNEL_MIN { return Err(refused()); }
    let mut pair = [-1; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 { return Err(refused()); }
    let first = unsafe { OwnedFd::from_raw_fd(pair[0]) }; let _second = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let mut pidfd = -1; let mut len = mem::size_of::<i32>() as libc::socklen_t;
    if unsafe { libc::getsockopt(first.as_raw_fd(), libc::SOL_SOCKET, SO_PEERPIDFD, &mut pidfd as *mut _ as _, &mut len) } != 0 { return Err(refused()); }
    let _held = unsafe { OwnedFd::from_raw_fd(pidfd) }; Ok(())
}
