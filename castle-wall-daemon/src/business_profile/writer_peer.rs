//! Holds one wall MainPID and authenticates its systemd owner on each exchange.
mod bus;
use super::{custody, signer_peer, signer_watchdog::WATCHDOG_TICK_MS};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
pub const BUS_MESSAGE_MAX_BYTES: usize = signer_peer::PROC_MAX_BYTES as usize;
pub const BUS_LINE_MAX_BYTES: usize = 512; // Bounded SASL line, with room above the fixed exchange.
pub const BUS_UNSOLICITED_MAX: usize = 8; // NameAcquired plus bounded signal headroom.
pub const BUS_HEADER_FIELDS_MAX: usize = 9; // D-Bus field codes 1 through 9.
pub const BUS_NESTING_MAX: usize = 4; // Variant, array, ExecStart struct, argv array.
pub const BUS_ARRAY_ELEMENTS_MAX: usize = 16; // Registry arrays only, above the shipped five-element argv.
pub const INVOCATION_ID_HEX_LEN: usize = 32; // systemd 128-bit InvocationID encoded as two hex digits per byte.
pub const WALL_DROPINS_MAX: usize = BUS_ARRAY_ELEMENTS_MAX;
// Must match sanctuary-business-writer.socket: path, descriptor name and mode.
pub const RECORD_SOCKET: &str = "/run/sanctuary-business-writer/record.sock";
// Must match sanctuary-business-writer.service: wall dependency and argument-free writer executable.
pub const WALL_UNIT: &str = "sanctuary-castle-wall.service";
// Must match ExecStart in systemd/sanctuary-castle-wall.service; systemd_unit::writer_wall_exec_matches_shipped_unit executes the reverse pin.
pub const WALL_EXEC: &str = "/usr/local/libexec/sanctuary/castle-wall-daemon";
pub const WRITER_EXEC: &str = "/usr/libexec/sanctuary-business-writer";
pub const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
pub const RECORD_FD_NAME: &str = "records";
pub const RECORD_MODE: u32 = 0o660; // Owner and socket group may exchange records.
pub const NS_PER_MS: u64 = 1_000_000;
const SAFE_INTEGER_MAX: u64 = (1u64 << 53) - 1; // Exact JSON integer limit.
pub type Clock = Arc<dyn Fn() -> io::Result<u64> + Send + Sync>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Io,
    Deadline,
    Cap(&'static str),
    Framing,
    Signature,
    Header,
    Descriptors,
    Sasl,
    Signals,
    MessageType,
    Serial,
    Sender,
    Destination,
    Owner,
    Unit,
    Exec,
    Config,
    Artifact,
    Listener,
    Peer,
    Process,
    Group,
    Identity,
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}
#[derive(Clone)]
pub struct Deadline {
    clock: Clock,
    end: u64,
    wall: Instant,
}
impl Deadline {
    pub fn new(clock: Clock, end: u64) -> Result<Self> {
        let now = clock()?;
        let remaining = end.checked_sub(now).ok_or(Error::Deadline)?;
        Ok(Self {
            clock,
            end,
            wall: Instant::now() + Duration::from_nanos(remaining),
        })
    }
    pub fn check(&self) -> Result<()> {
        if (self.clock)()? >= self.end || Instant::now() >= self.wall {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
#[cfg_attr(feature = "test-isolation", derive(Deserialize))]
#[cfg_attr(feature = "test-isolation", serde(deny_unknown_fields))]
pub struct BusTarget {
    socket: PathBuf,
    socket_owner_uid: u32,
    expected_manager_uid: u32,
    expected_manager_pid: u32,
    wall_unit: String,
}
impl BusTarget {
    pub fn production() -> Self {
        Self {
            socket: SYSTEM_BUS_SOCKET.into(),
            socket_owner_uid: custody::ROOT_UID,
            expected_manager_uid: custody::ROOT_UID,
            expected_manager_pid: 1,
            wall_unit: WALL_UNIT.into(),
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(socket: PathBuf, owner: u32, pid: u32, wall_unit: String) -> Self {
        Self {
            socket,
            socket_owner_uid: owner,
            expected_manager_uid: owner,
            expected_manager_pid: pid,
            wall_unit,
        }
    }
    pub fn exchange(&self, end: Deadline) -> Result<UnitSnapshot> {
        bus::exchange(self, end)
    }
}
pub struct Property {
    pub interface: &'static str,
    pub subject: &'static str,
    pub member: &'static str,
    pub signature: &'static str,
}
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
/// This registry drives every request and the corpus coverage set.
pub const PROPERTY_REGISTRY: &[Property] = &[
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "Id",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "LoadState",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "ActiveState",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "SubState",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "InvocationID",
        signature: "ay",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "FragmentPath",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: UNIT,
        member: "DropInPaths",
        signature: "as",
    },
    Property {
        interface: PROPERTIES,
        subject: SERVICE,
        member: "ControlGroup",
        signature: "s",
    },
    Property {
        interface: PROPERTIES,
        subject: SERVICE,
        member: "MainPID",
        signature: "u",
    },
    Property {
        interface: PROPERTIES,
        subject: SERVICE,
        member: "ExecStart",
        signature: "a(sasbttttuii)",
    },
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSnapshot {
    pub owner: String,
    pub id: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub invocation: Vec<u8>,
    pub fragment: String,
    pub dropins: Vec<String>,
    pub cgroup: String,
    pub pid: u32,
    pub exec: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropIn {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterConfig {
    pub version: u8,
    pub wall_unit: String,
    pub wall_exec: PathBuf,
    pub wall_sha256: String,
    pub wall_argv_sha256: String,
    pub wall_unit_sha256: String,
    pub wall_dropins: Vec<DropIn>,
    pub wall_gid: u32,
    pub writer_socket_gid: u32,
    pub writer_sha256: String,
    pub fortress_id: String,
    pub enrollment_revision: u64,
    pub signer: signer_peer::PeerPolicy,
}
fn digest_shape(s: &str) -> bool {
    s.len() == 32 * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub struct HeldConfig {
    pub value: WriterConfig,
    file: File,
    path: PathBuf,
    owner: u32,
}
impl HeldConfig {
    pub fn production() -> Result<Self> {
        Self::load(
            Path::new(crate::config::BUSINESS_WRITER_CONFIG),
            custody::ROOT_UID,
            true,
        )
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(path: &Path, owner: u32) -> Result<Self> {
        Self::load(path, owner, false)
    }
    fn load(path: &Path, owner: u32, production: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != owner
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() > custody::CONFIG_MAX_BYTES as u64
        {
            return Err(Error::Config);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(custody::CONFIG_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > custody::CONFIG_MAX_BYTES {
            return Err(Error::Config);
        }
        let value: WriterConfig = serde_json::from_slice(&bytes).map_err(|_| Error::Config)?;
        if value.version != 1
            || value.wall_unit.is_empty()
            || !value.wall_exec.is_absolute()
            || (production
                && (value.wall_unit != WALL_UNIT || value.wall_exec != Path::new(WALL_EXEC)))
            || value.enrollment_revision == 0
            || value.enrollment_revision > SAFE_INTEGER_MAX
            || value.fortress_id.is_empty()
            || value.fortress_id.len() > custody::FORTRESS_ID_MAX_BYTES
            || value.wall_dropins.len() > WALL_DROPINS_MAX
            || [
                &value.wall_sha256,
                &value.wall_argv_sha256,
                &value.wall_unit_sha256,
                &value.writer_sha256,
                &value.signer.executable_sha256,
            ]
            .iter()
            .any(|s| !digest_shape(s))
        {
            return Err(Error::Config);
        }
        let mut paths = BTreeSet::new();
        for item in &value.wall_dropins {
            if !item.path.is_absolute() || !digest_shape(&item.sha256) || !paths.insert(&item.path)
            {
                return Err(Error::Config);
            }
        }
        Ok(Self {
            value,
            file,
            path: path.to_owned(),
            owner,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        let held = self.file.metadata()?;
        let live = fs::symlink_metadata(&self.path)?;
        if !live.is_file()
            || live.uid() != self.owner
            || live.mode() & 0o7777 != 0o600
            || live.nlink() != 1
            || live.dev() != held.dev()
            || live.ino() != held.ino()
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}
pub(crate) fn read_proc(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(signer_peer::PROC_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > signer_peer::PROC_MAX_BYTES {
        return Err(Error::Cap("proc"));
    }
    String::from_utf8(bytes).map_err(|_| Error::Process)
}
fn process_start(pid: i32) -> Result<String> {
    let text = read_proc(Path::new(&format!("/proc/{pid}/stat")))?;
    let (_, tail) = text.rsplit_once(')').ok_or(Error::Process)?;
    // Field 22 follows the comm field, which itself can contain parentheses and spaces.
    let start = tail.split_whitespace().nth(22 - 3).ok_or(Error::Process)?;
    start.parse::<u64>().map_err(|_| Error::Process)?;
    Ok(start.into())
}
// PeerPolicy retains raw proc text; signer_peer::Peer::capture uses this same parser on both comparison operands.
pub fn normalized_cgroup(text: &str) -> Result<String> {
    signer_peer::normalized_cgroup(text).map_err(|_| Error::Group)
}
fn process_cgroup(pid: i32) -> Result<String> {
    normalized_cgroup(&read_proc(Path::new(&format!("/proc/{pid}/cgroup")))?)
}
pub(crate) fn held_artifact(path: &Path, owner: u32, pin: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != owner
        || m.mode() & 0o022 != 0
        || m.len() > custody::ARTIFACT_MAX_BYTES
    {
        return Err(Error::Artifact);
    }
    let mut hash = Sha256::new();
    let size = io::copy(
        &mut (&file).take(custody::ARTIFACT_MAX_BYTES + 1),
        &mut hash,
    )?;
    if size > custody::ARTIFACT_MAX_BYTES || hex::encode(hash.finalize()) != pin {
        return Err(Error::Artifact);
    }
    Ok(file)
}
fn held_socket(path: &Path, owner: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if m.mode() & libc::S_IFMT != libc::S_IFSOCK || m.uid() != owner {
        return Err(Error::Artifact);
    }
    Ok(file)
}
#[derive(Clone)]
#[cfg_attr(feature = "test-isolation", derive(Deserialize))]
#[cfg_attr(feature = "test-isolation", serde(deny_unknown_fields))]
pub struct ListenerExpectations {
    path: PathBuf,
    owner: u32,
    group: u32,
    peer_uid: u32,
}
impl ListenerExpectations {
    pub fn production(group: u32) -> Self {
        Self {
            path: RECORD_SOCKET.into(),
            owner: custody::ROOT_UID,
            group,
            peer_uid: custody::ROOT_UID,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(path: PathBuf, owner: u32, group: u32) -> Self {
        Self {
            path,
            owner,
            group,
            peer_uid: owner,
        }
    }
}
fn option(fd: RawFd, name: i32) -> Result<i32> {
    let mut value = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &mut value as *mut _ as _,
            &mut len,
        )
    } != 0
        || len as usize != std::mem::size_of::<i32>()
    {
        return Err(Error::Listener);
    }
    Ok(value)
}
/// Validates the inherited descriptor without changing the socket unit's lifetime.
pub fn listener(
    fd: RawFd,
    expect: &ListenerExpectations,
    pid: &str,
    fds: &str,
    names: &str,
) -> Result<()> {
    if pid != unsafe { libc::getpid() }.to_string()
        || fds != "1"
        || names != RECORD_FD_NAME
        || fd != 3
    {
        return Err(Error::Listener);
    }
    if option(fd, libc::SO_TYPE)? != libc::SOCK_SEQPACKET || option(fd, libc::SO_ACCEPTCONN)? != 1 {
        return Err(Error::Listener);
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    if unsafe { libc::getsockname(fd, &mut addr as *mut _ as _, &mut len) } != 0
        || addr.sun_family as i32 != libc::AF_UNIX
    {
        return Err(Error::Listener);
    }
    let bytes: Vec<u8> = addr
        .sun_path
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    if bytes != expect.path.as_os_str().as_bytes() {
        return Err(Error::Listener);
    }
    let held = held_socket(&expect.path, expect.owner)?;
    let m = held.metadata()?;
    if m.gid() != expect.group || m.mode() & 0o7777 != RECORD_MODE {
        return Err(Error::Listener);
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(Error::Listener);
    }
    signer_peer::passcred(fd).map_err(|_| Error::Listener)
}
pub struct WallMainBinding {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pidfd: OwnedFd,
    start: String,
    cgroup: String,
    unit: UnitSnapshot,
    artifacts: Vec<File>,
}
impl WallMainBinding {
    pub fn capture(
        fd: RawFd,
        config: &WriterConfig,
        target: &BusTarget,
        expect: &ListenerExpectations,
        artifact_owner: u32,
        end: Deadline,
    ) -> Result<Self> {
        // the writer binds each record connection to the wall unit's main process; executing-image equality of the wall is not established at this boundary; it rests on the root-owned install.
        end.check()?;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as _,
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&cred)
            || cred.pid <= 0
            || cred.uid != expect.peer_uid
        {
            return Err(Error::Peer);
        }
        // the supplementary group on the record socket narrows who can connect, but it is not a bound against a uid 0 peer; the MainPID equality is that bound.
        if cred.gid != config.wall_gid {
            return Err(Error::Peer);
        }
        let raw = option(fd, signer_peer::SO_PEERPIDFD)?;
        if raw < 0 {
            return Err(Error::Process);
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        if !pidfd_subject(pidfd.as_raw_fd(), cred.pid) {
            return Err(Error::Process);
        }
        let start = process_start(cred.pid)?;
        let cgroup = process_cgroup(cred.pid)?;
        let unit = target.exchange(end.clone())?;
        validate_unit(&unit, config, cred.pid, &cgroup)?;
        let mut artifacts = vec![
            held_artifact(&config.wall_exec, artifact_owner, &config.wall_sha256)?,
            held_artifact(
                Path::new(&unit.fragment),
                artifact_owner,
                &config.wall_unit_sha256,
            )?,
        ];
        for dropin in &config.wall_dropins {
            artifacts.push(held_artifact(&dropin.path, artifact_owner, &dropin.sha256)?);
        }
        let binding = Self {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
            pidfd,
            start,
            cgroup,
            unit,
            artifacts,
        };
        binding.revalidate(target, end)?;
        Ok(binding)
    }
    pub fn live(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut poll, 1, 0) == 0 }
    }
    pub fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }
    pub fn packet(&self, packet: &signer_peer::Packet) -> Result<()> {
        if !packet.rights.is_empty()
            || packet.cred.pid != self.pid
            || packet.cred.uid != self.uid
            || packet.cred.gid != self.gid
            || !self.live()
            || !pidfd_subject(packet.pidfd.as_raw_fd(), self.pid)
            || !same_descriptor(self.pidfd.as_raw_fd(), packet.pidfd.as_raw_fd())
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub fn revalidate(&self, target: &BusTarget, end: Deadline) -> Result<()> {
        if !self.process_identity()? {
            return Err(Error::Process);
        }
        let now = target.exchange(end.clone())?;
        if now.owner != self.unit.owner
            || now.pid != self.unit.pid
            || now.invocation != self.unit.invocation
            || now.cgroup != self.unit.cgroup
        {
            return Err(Error::Identity);
        }
        if !self.process_identity()? {
            return Err(Error::Process);
        }
        end.check()?;
        Ok(())
    }
    fn process_identity(&self) -> Result<bool> {
        Ok(self.live()
            && pidfd_subject(self.pidfd.as_raw_fd(), self.pid)
            && process_start(self.pid)? == self.start
            && process_cgroup(self.pid)? == self.cgroup)
    }
    pub fn held_artifacts(&self) -> usize {
        self.artifacts.len()
    }
}
fn pidfd_subject(fd: RawFd, pid: i32) -> bool {
    signer_peer::pidfd_pid(fd) == Some(pid)
}
fn same_descriptor(a: RawFd, b: RawFd) -> bool {
    signer_peer::same_pidfd(a, b)
}
fn validate_unit(unit: &UnitSnapshot, config: &WriterConfig, pid: i32, cgroup: &str) -> Result<()> {
    if unit.id != config.wall_unit
        || unit.load != "loaded"
        || !matches!(
            (unit.active.as_str(), unit.sub.as_str()),
            ("active", "running") | ("activating", "start")
        )
        || unit.invocation.len() != INVOCATION_ID_HEX_LEN / 2
        || !Path::new(&unit.fragment).is_absolute()
    {
        return Err(Error::Unit);
    }
    if unit.pid != pid as u32 || unit.cgroup != cgroup {
        return Err(Error::Identity);
    }
    if unit.exec != config.wall_exec.to_string_lossy() || unit.argv.len() > BUS_ARRAY_ELEMENTS_MAX {
        return Err(Error::Exec);
    }
    let argv = crate::smb::jcs::encode(&serde_json::json!(unit.argv)).map_err(|_| Error::Exec)?;
    if hex::encode(Sha256::digest(argv.as_bytes())) != config.wall_argv_sha256 {
        return Err(Error::Exec);
    }
    if unit.dropins.len() != config.wall_dropins.len()
        || unit
            .dropins
            .iter()
            .zip(&config.wall_dropins)
            .any(|(a, b)| Path::new(a) != b.path)
    {
        return Err(Error::Artifact);
    }
    Ok(())
}
#[cfg(feature = "test-isolation")]
pub mod test_support {
    use super::*;
    use crate::business_profile::signer_watchdog::boottime_ns;
    pub fn pidfd_subject_matches(fd: RawFd, pid: i32) -> bool {
        pidfd_subject(fd, pid)
    }
    pub fn same_descriptor_matches(a: RawFd, b: RawFd) -> bool {
        same_descriptor(a, b)
    }
    pub fn changed_saved_identity(mut binding: WallMainBinding, field: &str) -> Result<bool> {
        match field {
            "start" => binding.start.push('0'),
            "cgroup" => binding.cgroup.push('x'),
            _ => return Err(Error::Identity),
        }
        binding.process_identity()
    }
    pub fn validate_snapshot(
        unit: &UnitSnapshot,
        config: &WriterConfig,
        pid: i32,
        cgroup: &str,
    ) -> Result<()> {
        validate_unit(unit, config, pid, cgroup)
    }
    #[derive(Debug)]
    pub struct ParseObservation {
        pub fields: usize,
        pub depth: usize,
        pub bytes: usize,
        pub first_cap: Option<&'static str>,
        pub result: Result<()>,
    }
    pub fn parse_response(
        bytes: &[u8],
        registry: bool,
        serial: u32,
        sender: &str,
        dest: &str,
        sig: &str,
    ) -> ParseObservation {
        let mut obs = bus::Observer::default();
        let result = bus::parse(bytes, registry, &mut obs)
            .and_then(|m| bus::response(&m, serial, sender, dest, sig));
        ParseObservation {
            fields: obs.fields,
            depth: obs.depth,
            bytes: obs.bytes,
            first_cap: obs.first_cap,
            result,
        }
    }
    pub fn parse_property(
        bytes: &[u8],
        serial: u32,
        sender: &str,
        dest: &str,
        member: &str,
    ) -> ParseObservation {
        let mut obs = bus::Observer::default();
        let result = bus::parse(bytes, true, &mut obs).and_then(|m| {
            bus::response(&m, serial, sender, dest, "v")?;
            let expected = PROPERTY_REGISTRY
                .iter()
                .find(|p| p.member == member)
                .ok_or(Error::Unit)?;
            match m.body.as_slice() {
                [bus::Item::Variant(sig, _)] if sig == expected.signature => Ok(()),
                _ => Err(Error::Signature),
            }
        });
        ParseObservation {
            fields: obs.fields,
            depth: obs.depth,
            bytes: obs.bytes,
            first_cap: obs.first_cap,
            result,
        }
    }
    pub fn decode_request(bytes: &[u8]) -> Result<(String, Vec<String>)> {
        let message = bus::parse(bytes, false, &mut bus::Observer::default())?;
        if message.kind != 1 {
            return Err(Error::MessageType);
        }
        let member = match message.fields.get(&3) {
            Some(bus::Item::Text(s)) => s.clone(),
            _ => return Err(Error::Header),
        };
        let args = message
            .body
            .iter()
            .map(|v| match v {
                bus::Item::Text(s) => Ok(s.clone()),
                _ => Err(Error::Signature),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((member, args))
    }
    pub fn check_artifact(path: &Path, owner: u32, pin: &str) -> Result<()> {
        held_artifact(path, owner, pin).map(|_| ())
    }
    pub fn production_values() -> (PathBuf, u32, u32, u32, String) {
        let t = BusTarget::production();
        (
            t.socket,
            t.socket_owner_uid,
            t.expected_manager_uid,
            t.expected_manager_pid,
            t.wall_unit,
        )
    }
    pub fn deadline_ms(ms: u64) -> Result<Deadline> {
        Deadline::new(
            Arc::new(boottime_ns),
            boottime_ns()?
                .checked_add(ms.checked_mul(NS_PER_MS).ok_or(Error::Deadline)?)
                .ok_or(Error::Deadline)?,
        )
    }
}
