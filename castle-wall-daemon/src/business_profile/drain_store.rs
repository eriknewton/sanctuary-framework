//! Durable drain records and copies; no service, signing or acknowledgment caller is installed.
use super::{activation_anchor as anchor, custody, records, signer_contract::*, writer_protocol};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

// Must match D interface contract v1 in both drain briefs; d2 consumes these caps unchanged.
pub const LENGTH_BYTES: usize = writer_protocol::LENGTH_BYTES;
pub const SEQUENCE_FILENAME_DIGITS: usize = 20; // Decimal width of u64::MAX.
pub use anchor::{D_DESCRIPTOR_EPOCHS_MAX, D_DESCRIPTOR_MAX_BYTES, D_EPOCH_MAX};
pub const D_ANCHOR_MAX_BYTES: usize = 1172; // 22 keys, six 16-digit counters, four 32-hex ids, six 71-byte digests, nullable transaction id, role and maximal reason; measured by maximal_record_bounds.
pub const D_ANCHOR_MESSAGE_MAX_BYTES: usize = 2539; // Two maximal anchors plus longest operation, request id and body digest; measured by maximal_record_bounds.
pub const D_LAST_MAX_BYTES: usize = 185; // Authority, longest phase, 32-hex request id and 71-byte digest; measured by maximal_record_bounds.
pub const D_LEDGER_ENTRY_BYTES: usize = 71 + 2 + 1; // Digest plus quotes and comma.
pub const D_RECORD_FIXED_BYTES: usize = 1400; // Maximal anchor and last with empty ledger and record keys; measured by maximal_record_bounds.
pub const D_UNDRAINED_MAX: usize = 512; // Largest power of two fitting the strict JSON parse cap; no eviction.
pub const D_RECORD_MAX_BYTES: usize =
    D_RECORD_FIXED_BYTES + D_UNDRAINED_MAX * D_LEDGER_ENTRY_BYTES - 1;
pub const D_COPY_MAX_BYTES: u64 = 64 * 1024 * 1024; // Ordinary WAL64MiB bound, with no finalization headroom.
pub const D_COPY_ENTRIES_MAX: usize = 65536; // Policy: 64 MiB at an average of at least 1 KiB per copy.
pub const D_DIRECTORY_SENTINEL: usize = 1;
pub const DESCRIPTOR_MODE: u32 = 0o644; // Historical descriptors are public.
pub const D_HEADER_MAX_BYTES: usize = SIGNER_HEADER_MAX_BYTES;
pub const D_REQUEST_MAX_BYTES: usize = SIGNER_FRAME_MAX_BYTES;
pub const D_ANCHOR_PAYLOAD_MAX_BYTES: usize =
    D_ANCHOR_MESSAGE_MAX_BYTES + writer_protocol::WRITER_ENVELOPE_MAX_BYTES;
pub const D_REPLY_MAX_BYTES: usize = LENGTH_BYTES + D_HEADER_MAX_BYTES + anchor::MAX_BYTES;
pub const D_CONNECTIONS_MAX: usize = 3; // One S, one W, one classifying connection.
pub const D_CLASSIFY_DEADLINE_MS: usize = SIGNER_HANDSHAKE_DEADLINE_MS;
pub const D_REQUEST_DEADLINE_MS: usize = SIGNER_REQUEST_DEADLINE_MS;
pub const D_HEARTBEAT_MS: usize = 5000; // Design heartbeat; the store never reads it.
pub const D_LEASE_MS: usize = 10000; // Design lease; the store never reads it.
const _: () = assert!(D_RECORD_MAX_BYTES <= anchor::MAX_BYTES);
const _: () =
    assert!(D_ANCHOR_PAYLOAD_MAX_BYTES <= D_REQUEST_MAX_BYTES - LENGTH_BYTES - D_HEADER_MAX_BYTES);
const _: () = assert!(D_REPLY_MAX_BYTES == SIGNER_FRAME_MAX_BYTES);
pub const DRAIN_SLOTS: &[(&str, &str)] = &[(custody::PRODUCER_ROLE_SLOT, anchor::PRODUCER_ROLE)];
const SLOT: &str = DRAIN_SLOTS[0].0;
const WIRE_ROLE: &str = DRAIN_SLOTS[0].1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authority {
    W,
    S,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Phase {
    PREPARE,
    CUSTODY_COMMIT,
    LATCH,
    ADVANCE_GENERATION,
    ADVANCE_ACTIVATION,
    ADVANCE_BOOT,
    RESERVE,
    RECORD_COMMIT,
    DRAIN,
}
impl Phase {
    pub fn of_message(m: &Value) -> Option<Self> {
        // Phase and authority come from the request bytes; whole-tuple compare-and-swap binds expected to the durable anchor, so a fresh request cannot pick a phase the durable state does not have.
        match m["op"].as_str()? {
            "COMMIT"
                if m["expected"].is_object() && m["expected"].get("transaction_id").is_some() =>
            {
                Some(if m["expected"]["transaction_id"].is_null() {
                    Self::RECORD_COMMIT
                } else {
                    Self::CUSTODY_COMMIT
                })
            }
            "PREPARE" => Some(Self::PREPARE),
            "RESERVE" => Some(Self::RESERVE),
            "LATCH" => Some(Self::LATCH),
            "ADVANCE_GENERATION" => Some(Self::ADVANCE_GENERATION),
            "ADVANCE_ACTIVATION" => Some(Self::ADVANCE_ACTIVATION),
            "ADVANCE_BOOT" => Some(Self::ADVANCE_BOOT),
            _ => None,
        }
    }
}
impl Authority {
    pub fn for_phase(phase: Phase) -> Self {
        match phase {
            Phase::RESERVE | Phase::RECORD_COMMIT | Phase::DRAIN => Self::W,
            _ => Self::S,
        }
    }
}
/// Retry evidence names the authenticated authority's exact packet; d2 verifies the peer and packet hash before consuming it as a retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastOp {
    pub authority: Authority,
    pub phase: Phase,
    pub request_id: String,
    pub request_sha256: String,
}
/// Ledger entries are commit-verified join commitments, published atomically with their anchor and retry evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct DrainRecord {
    pub anchor: Value,
    pub last: LastOp,
    pub ledger: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum StoreRefusal {
    LOCK,
    ROOT,
    ENUMERATE,
    ENTRY,
    STAGING,
    RECORD_SHAPE,
    RECORD_ANCHOR,
    RECORD_LAST,
    RECORD_LEDGER,
    COPY_SET,
    COPY_TAIL,
    ORPHAN,
    CAP,
    STAGE,
    WRITE,
    FILE_SYNC,
    RENAME,
    DIR_SYNC,
    READBACK,
    UNCERTAIN,
}
pub type StartRefusal = StoreRefusal;
type Result<T> = std::result::Result<T, StoreRefusal>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Durable,
    PrePublication(StoreRefusal),
    Uncertain(StoreRefusal),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    Planned,
    Staged,
    RenameAttempted,
    DirSynced,
    Verified,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStep {
    HoldDirectory,
    Stage,
    Write,
    FileSync,
    Rename,
    DirSync,
    Readback,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationState {
    Absent,
    Present,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub state: ObservationState,
    pub anchor: Option<Value>,
    pub anchor_digest: Option<String>,
    pub latched: bool,
    pub uncertain: bool,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CopyUsage {
    pub bytes: u64,
    pub entries: usize,
}
fn hex_shape(s: &str, prefix: &str, width: usize) -> bool {
    s.strip_prefix(prefix).is_some_and(|s| {
        s.len() == width
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn record_valid(r: &DrainRecord) -> Result<()> {
    if !anchor::valid(&r.anchor) {
        return Err(StoreRefusal::RECORD_ANCHOR);
    }
    if Authority::for_phase(r.last.phase) != r.last.authority
        || !hex_shape(&r.last.request_id, "", anchor::ID_HEX_LENGTH)
        || !hex_shape(&r.last.request_sha256, "sha256:", anchor::DIGEST_HEX_LENGTH)
    {
        return Err(StoreRefusal::RECORD_LAST);
    }
    let committed = r.anchor["committed_sequence"]
        .as_u64()
        .ok_or(StoreRefusal::RECORD_ANCHOR)?;
    let drained = r.anchor["drained_sequence"]
        .as_u64()
        .ok_or(StoreRefusal::RECORD_ANCHOR)?;
    // The published tail and length bind the ledger to this anchor; no entry may be silently evicted.
    if r.ledger.len() > D_UNDRAINED_MAX
        || committed.checked_sub(drained) != Some(r.ledger.len() as u64)
        || r.ledger
            .iter()
            .any(|s| !hex_shape(s, "sha256:", anchor::DIGEST_HEX_LENGTH))
        || match r.ledger.last() {
            Some(last) => r.anchor["committed_digest"] != *last,
            None => r.anchor["committed_digest"] != r.anchor["drained_digest"],
        }
    {
        return Err(StoreRefusal::RECORD_LEDGER);
    }
    Ok(())
}
pub fn encode_record(r: &DrainRecord) -> Result<Vec<u8>> {
    // Bound the typed components before canonical encoding can allocate from caller-controlled state.
    if r.ledger.len() > D_UNDRAINED_MAX {
        return Err(StoreRefusal::STAGE);
    }
    record_valid(r)?;
    let bytes = crate::smb::jcs::encode(
        &json!({"version":1,"anchor":r.anchor,"last":r.last,"ledger":r.ledger}),
    )
    .map_err(|_| StoreRefusal::RECORD_SHAPE)?
    .into_bytes();
    if bytes.len() > D_RECORD_MAX_BYTES {
        return Err(StoreRefusal::STAGE);
    }
    Ok(bytes)
}
pub fn decode_record(bytes: &[u8]) -> Result<DrainRecord> {
    if bytes.len() > D_RECORD_MAX_BYTES {
        return Err(StoreRefusal::RECORD_SHAPE);
    }
    let v = crate::smb::strict_json::parse(bytes, D_RECORD_MAX_BYTES)
        .map_err(|_| StoreRefusal::RECORD_SHAPE)?;
    if crate::smb::jcs::encode(&v)
        .map_err(|_| StoreRefusal::RECORD_SHAPE)?
        .as_bytes()
        != bytes
    {
        return Err(StoreRefusal::RECORD_SHAPE);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| StoreRefusal::RECORD_SHAPE)?;
    if !v.as_object().is_some_and(|o| {
        o.len() == 4
            && ["version", "anchor", "last", "ledger"]
                .iter()
                .all(|k| o.contains_key(*k))
    }) || v["version"] != 1
    {
        return Err(StoreRefusal::RECORD_SHAPE);
    }
    let r = DrainRecord {
        anchor: v["anchor"].clone(),
        last: serde_json::from_value(v["last"].clone()).map_err(|_| StoreRefusal::RECORD_LAST)?,
        ledger: serde_json::from_value(v["ledger"].clone())
            .map_err(|_| StoreRefusal::RECORD_LEDGER)?,
    };
    record_valid(&r)?;
    Ok(r)
}

fn name(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| StoreRefusal::ENTRY)
}
fn open_at(parent: RawFd, leaf: &str, flags: i32, mode: u32) -> Result<File> {
    let leaf = name(leaf)?;
    // SAFETY: the borrowed parent and NUL-terminated leaf stay valid through openat.
    let fd = unsafe {
        libc::openat(
            parent,
            leaf.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(StoreRefusal::ENTRY);
    }
    // SAFETY: openat returned a fresh descriptor owned only by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn meta(file: &File) -> Result<Metadata> {
    file.metadata().map_err(|_| StoreRefusal::ENTRY)
}
fn trusted(m: &Metadata, owner: u32, directory: bool) -> bool {
    m.uid() == owner
        && m.mode() & 0o7777
            == if directory {
                custody::DIRECTORY_MODE
            } else {
                custody::PRIVATE_MODE
            }
        && if directory {
            m.is_dir()
        } else {
            m.is_file() && m.nlink() == 1
        }
}
fn directory(parent: &File, leaf: &str, owner: u32) -> Result<File> {
    let f = open_at(
        parent.as_raw_fd(),
        leaf,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    if !trusted(&meta(&f)?, owner, true) {
        return Err(StoreRefusal::ROOT);
    }
    Ok(f)
}
fn exists(parent: &File, leaf: &str) -> Result<bool> {
    let leaf = name(leaf)?;
    // SAFETY: stat is initialized by fstatat on success; only the return code is used.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(true)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(StoreRefusal::ENTRY)
    }
}
fn mkdir(
    parent: &File,
    leaf: &str,
    owner: u32,
    label: &str,
    faults: &mut StoreFaults,
    events: &EventSink,
) -> Result<File> {
    if !exists(parent, leaf)? {
        faults.hit(label, StoreStep::HoldDirectory, "before", events, None)?;
        let n = name(leaf)?;
        // SAFETY: the held parent and fixed leaf remain valid for this descriptor-relative creation.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), custody::DIRECTORY_MODE) } != 0 {
            return Err(StoreRefusal::ROOT);
        }
        events.emit(
            "StepCompleted",
            None,
            Some(label),
            Some(StoreStep::HoldDirectory),
            None,
        )?;
        faults.hit(label, StoreStep::HoldDirectory, "after", events, None)?;
        // Creation alone proves no durability; destination syncs every child and parent on every publication, including retries.
        directory(parent, leaf, owner)
    } else {
        directory(parent, leaf, owner)
    }
}
fn unlink(parent: &File, leaf: &str) -> Result<()> {
    let n = name(leaf)?;
    // SAFETY: only a validated fixed staging leaf is removed through its held directory.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), n.as_ptr(), 0) } != 0 {
        return Err(StoreRefusal::STAGING);
    }
    if exists(parent, leaf)? {
        return Err(StoreRefusal::STAGING);
    }
    Ok(())
}
struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred this stream's ownership once.
        unsafe { libc::closedir(self.0) };
    }
}
fn enumerate(parent: &File, cap: usize) -> Result<Vec<String>> {
    let stream_file = open_at(
        parent.as_raw_fd(),
        ".",
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    use std::os::fd::IntoRawFd;
    let fd = stream_file.into_raw_fd();
    // SAFETY: fd is a fresh directory descriptor and transfers to the stream on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed without taking ownership.
        unsafe { libc::close(fd) };
        return Err(StoreRefusal::ENUMERATE);
    }
    let stream = DirectoryStream(stream);
    let mut entries = Vec::new();
    loop {
        // SAFETY: errno is thread-local and the stream is exclusively held until drop.
        unsafe {
            *libc::__errno_location() = 0;
        }
        let item = unsafe { libc::readdir(stream.0) };
        if item.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(StoreRefusal::ENUMERATE);
            }
            break;
        }
        // SAFETY: readdir's entry remains valid until the next call; d_name is NUL-terminated.
        let bytes = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Read at most cap plus one sentinel; never sort or collect an unbounded directory.
        if entries.len() >= cap {
            return Err(StoreRefusal::CAP);
        }
        entries.push(
            std::str::from_utf8(bytes)
                .map_err(|_| StoreRefusal::ENTRY)?
                .to_owned(),
        );
    }
    Ok(entries)
}
#[derive(Clone)]
struct Image {
    bytes: Vec<u8>,
    dev: u64,
    ino: u64,
}
fn read_image(dir: &File, leaf: &str, owner: u32, cap: usize) -> Result<Option<Image>> {
    if !exists(dir, leaf)? {
        return Ok(None);
    }
    let file = open_at(dir.as_raw_fd(), leaf, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let before = meta(&file)?;
    if !trusted(&before, owner, false) || before.len() > cap as u64 {
        return Err(StoreRefusal::ENTRY);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreRefusal::READBACK)?;
    let after = meta(&file)?;
    // A metadata change during the bounded read cannot supply stable evidence for a durable image.
    if !trusted(&after, owner, false)
        || after.len() != before.len()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
        || bytes.len() > cap
        || bytes.len() as u64 != before.len()
    {
        return Err(StoreRefusal::READBACK);
    }
    Ok(Some(Image {
        bytes,
        dev: before.dev(),
        ino: before.ino(),
    }))
}
/// The validated state root is the trust anchor; callers cannot choose a role-derived path.
pub struct HeldRoot {
    file: File,
    owner: u32,
}
impl HeldRoot {
    /// Production's fixed state root is separate from every custody and runtime root.
    pub fn production() -> Result<Self> {
        Self::open(
            Path::new(crate::config::BUSINESS_DRAIN_ROOT),
            custody::ROOT_UID,
        )
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated_under(path: &Path, owner: u32) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| StoreRefusal::ROOT)?;
        // SAFETY: this explicit seam pins the caller-owned private temp root, with no production path substitution.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(StoreRefusal::ROOT);
        }
        // SAFETY: open returned a fresh descriptor and File owns its closure.
        let file = unsafe { File::from_raw_fd(fd) };
        if !trusted(&meta(&file)?, owner, true) {
            return Err(StoreRefusal::ROOT);
        }
        Ok(Self { file, owner })
    }
    pub fn open(path: &Path, owner: u32) -> Result<Self> {
        // Walk every component without following links, then pin the private state root inode.
        let mut file = open_at(libc::AT_FDCWD, "/", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        if !path.is_absolute() {
            return Err(StoreRefusal::ROOT);
        }
        const PARENT_MODE: u32 = 0o755; // Public search ancestors of the private production state root.
        let root_metadata = meta(&file)?;
        if root_metadata.uid() != custody::ROOT_UID || root_metadata.mode() & 0o7777 != PARENT_MODE
        {
            return Err(StoreRefusal::ROOT);
        }
        let parts: Vec<_> = path.components().collect();
        for (i, part) in parts.iter().enumerate().skip(1) {
            let leaf = part.as_os_str().to_str().ok_or(StoreRefusal::ROOT)?;
            if leaf == ".." || leaf == "." {
                return Err(StoreRefusal::ROOT);
            }
            file = open_at(
                file.as_raw_fd(),
                leaf,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            let m = meta(&file)?;
            if i + 1 == parts.len() {
                if !trusted(&m, owner, true) {
                    return Err(StoreRefusal::ROOT);
                }
            } else if m.uid() != custody::ROOT_UID || m.mode() & 0o7777 != PARENT_MODE {
                return Err(StoreRefusal::ROOT);
            }
        }
        if !trusted(&meta(&file)?, owner, true) {
            return Err(StoreRefusal::ROOT);
        }
        Ok(Self { file, owner })
    }
}
/// The lock inode is never replaced or unlinked, so another process cannot acquire a different lock for this root.
pub struct StateLock {
    file: File,
    root_dev: u64,
    root_ino: u64,
}
impl StateLock {
    pub fn acquire(root: &HeldRoot) -> Result<Self> {
        if !trusted(&meta(&root.file)?, root.owner, true) {
            return Err(StoreRefusal::ROOT);
        }
        let file = open_at(
            root.file.as_raw_fd(),
            "drain.lock",
            libc::O_RDWR | libc::O_CREAT,
            custody::PRIVATE_MODE,
        )
        .map_err(|_| StoreRefusal::LOCK)?;
        if !trusted(&meta(&file)?, root.owner, false) {
            return Err(StoreRefusal::LOCK);
        }
        // SAFETY: flock borrows the validated file; its lifetime is retained in StateLock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(StoreRefusal::LOCK);
        }
        let m = meta(&root.file)?;
        Ok(Self {
            file,
            root_dev: m.dev(),
            root_ino: m.ino(),
        })
    }
}

#[derive(Default)]
pub struct StoreFaults {
    #[cfg(feature = "test-isolation")]
    seam: Option<std::path::PathBuf>,
    #[cfg(feature = "test-isolation")]
    consumed: BTreeMap<String, u64>,
    #[cfg(feature = "test-isolation")]
    schedule: Vec<u8>,
}
impl StoreFaults {
    pub fn none() -> Self {
        Self::default()
    }
    #[cfg(feature = "test-isolation")]
    pub fn from_seam_root(dir: &Path) -> Result<Self> {
        Ok(Self {
            seam: Some(dir.to_owned()),
            consumed: BTreeMap::new(),
            schedule: Vec::new(),
        })
    }
    fn hit(
        &mut self,
        publication: &str,
        step: StoreStep,
        position: &str,
        events: &EventSink,
        request_id: Option<&str>,
    ) -> Result<bool> {
        #[cfg(not(feature = "test-isolation"))]
        {
            let _ = (publication, step, position, events, request_id);
            Ok(false)
        }
        #[cfg(feature = "test-isolation")]
        {
            use std::time::{Duration, Instant};
            const SEAM_BYTES_MAX: u64 = 65536; // One bounded test schedule, independent of production packets.
            const SEAM_RULES_MAX: usize = 128; // Two positions for six steps across the bounded publication matrix.
            const SEAM_WAIT_MAX_MS: u64 = (D_REQUEST_DEADLINE_MS * 10) as u64;
            let dir = match &self.seam {
                Some(dir) => dir,
                None => return Ok(false),
            };
            let file = match File::open(dir.join("store-faults.json")) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(_) => return Err(StoreRefusal::STAGING),
            };
            let mut bytes = Vec::new();
            file.take(SEAM_BYTES_MAX + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| StoreRefusal::STAGING)?;
            if bytes.len() as u64 > SEAM_BYTES_MAX {
                return Err(StoreRefusal::CAP);
            }
            let rules: Vec<Value> =
                serde_json::from_slice(&bytes).map_err(|_| StoreRefusal::STAGING)?;
            if rules.len() > SEAM_RULES_MAX {
                return Err(StoreRefusal::CAP);
            }
            if bytes != self.schedule {
                self.consumed.clear();
                self.schedule = bytes;
            }
            for (i, r) in rules.iter().enumerate() {
                if r["slot"] != SLOT
                    || r["publication"] != publication
                    || r["step"] != format!("{step:?}")
                    || r["position"] != position
                {
                    continue;
                }
                let key = format!(
                    "{i}:{}",
                    crate::smb::jcs::encode(r).map_err(|_| StoreRefusal::STAGING)?
                );
                let used = self.consumed.entry(key).or_default();
                if *used >= r["times"].as_u64().ok_or(StoreRefusal::STAGING)? {
                    continue;
                }
                *used += 1;
                match r["action"].as_str() {
                    Some("fail") => return Err(step_refusal(step)),
                    Some("alter_readback") => return Ok(true),
                    Some("delay_ms") => {
                        let ms = r["value"].as_u64().ok_or(StoreRefusal::STAGING)?;
                        if ms > SEAM_WAIT_MAX_MS {
                            return Err(StoreRefusal::CAP);
                        }
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                    Some("hold") => {
                        let value = r["value"].as_str().ok_or(StoreRefusal::STAGING)?;
                        if value.len() > anchor::ID_HEX_LENGTH
                            || !value.bytes().all(|b| b.is_ascii_alphanumeric())
                        {
                            return Err(StoreRefusal::STAGING);
                        }
                        let end = Instant::now() + Duration::from_millis(SEAM_WAIT_MAX_MS);
                        while !dir.join(format!("release-{value}")).exists() {
                            if Instant::now() >= end {
                                return Err(step_refusal(step));
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    _ => return Err(StoreRefusal::STAGING),
                }
                events.emit(
                    "StoreResumed",
                    request_id,
                    Some(publication),
                    Some(step),
                    None,
                )?;
            }
            Ok(false)
        }
    }
}
#[derive(Default)]
pub struct EventSink {
    #[cfg(feature = "test-isolation")]
    seam: Option<std::path::PathBuf>,
}
impl EventSink {
    pub fn none() -> Self {
        Self::default()
    }
    #[cfg(feature = "test-isolation")]
    pub fn from_seam_root(dir: &Path) -> Result<Self> {
        Ok(Self {
            seam: Some(dir.to_owned()),
        })
    }
    pub fn emit(
        &self,
        event: &str,
        request_id: Option<&str>,
        publication: Option<&str>,
        step: Option<StoreStep>,
        settlement: Option<&str>,
    ) -> Result<()> {
        let value = json!({"event":event,"slot":SLOT,"request_id":request_id,"publication":publication,"step":step.map(|s|format!("{s:?}")),"settlement":settlement,"active":1});
        self.append("events.jsonl", &value)
    }
    fn refusal(&self, stage: StoreRefusal, request_id: Option<&str>) -> Result<()> {
        self.append(
            "refusals.jsonl",
            &json!({"stage":format!("{stage:?}"),"slot":SLOT,"request_id":request_id}),
        )
    }
    fn append(&self, file: &str, value: &Value) -> Result<()> {
        #[cfg(not(feature = "test-isolation"))]
        {
            let _ = (file, value);
            Ok(())
        }
        #[cfg(feature = "test-isolation")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(dir) = &self.seam {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(custody::PRIVATE_MODE)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(dir.join(file))
                    .map_err(|_| StoreRefusal::ENTRY)?;
                let line = crate::smb::jcs::encode(value).map_err(|_| StoreRefusal::ENTRY)?;
                writeln!(f, "{line}").map_err(|_| StoreRefusal::ENTRY)?;
            }
            Ok(())
        }
    }
}
#[cfg(feature = "test-isolation")]
fn step_refusal(step: StoreStep) -> StoreRefusal {
    match step {
        StoreStep::HoldDirectory => StoreRefusal::ROOT,
        StoreStep::Stage => StoreRefusal::STAGE,
        StoreStep::Write => StoreRefusal::WRITE,
        StoreStep::FileSync => StoreRefusal::FILE_SYNC,
        StoreStep::Rename => StoreRefusal::RENAME,
        StoreStep::DirSync => StoreRefusal::DIR_SYNC,
        StoreStep::Readback => StoreRefusal::READBACK,
    }
}
fn sequence_name(sequence: u64) -> String {
    format!("{sequence:0width$}.env", width = SEQUENCE_FILENAME_DIGITS)
}
fn parse_sequence(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".env")?;
    let n = digits.parse::<u64>().ok()?;
    (n > 0 && sequence_name(n) == name).then_some(n)
}
fn record_name() -> String {
    format!("{}.json", SLOT)
}
fn check_names(dir: &File, allowed: &[&str]) -> Result<()> {
    for n in enumerate(dir, allowed.len())? {
        if !allowed.contains(&n.as_str()) {
            return Err(StoreRefusal::ENTRY);
        }
    }
    Ok(())
}

/// One bounded validation path owns both startup and reconciliation's continuing state.
#[derive(Default)]
pub struct RoleState {
    pub record: Option<DrainRecord>,
    record_image: Option<Image>,
    pub usage: CopyUsage,
    copies: BTreeMap<u64, Vec<u8>>,
}
fn check_copy(bytes: &[u8], sequence: u64, commitment: &str, stage: StoreRefusal) -> Result<()> {
    let envelope = writer_protocol::decode_envelope(bytes).map_err(|_| stage)?;
    // The retained original proves this slot's sequence and join commitment, never the candidate's asserted history.
    if envelope["body"]["role"] != WIRE_ROLE
        || envelope["body"]["sequence"].as_u64() != Some(sequence)
        || records::join_commitment(&envelope).as_deref() != Some(commitment)
    {
        return Err(stage);
    }
    Ok(())
}
pub fn validate_role_state(root: &HeldRoot, fortress: &str) -> Result<RoleState> {
    validate_layout(root, fortress, false)
}
// Continuing effect | Evidence | Refusal
// Open PRESENT | trusted locked layout, canonical record, ledger and copy checks | any invalid entry or bound
// Open ABSENT | no record and no originals | any retained original
// Remove known staging | complete layout validated first | unknown leaf, metadata or cleanup failure
// Keep orphan | sequence and role join ledger head | conflicting orphan
// These arms must match startup and cut witnesses in tests/linux_business_drain_store.rs.
fn validate_layout(root: &HeldRoot, fortress: &str, cleanup: bool) -> Result<RoleState> {
    if !trusted(&meta(&root.file)?, root.owner, true) {
        return Err(StoreRefusal::ROOT);
    }
    if !hex_shape(fortress, "", anchor::ID_HEX_LENGTH) {
        return Err(StoreRefusal::ROOT);
    }
    check_names(&root.file, &["drain.lock", fortress])?;
    if !exists(&root.file, fortress)? {
        return Ok(RoleState::default());
    }
    let fort = directory(&root.file, fortress, root.owner)?;
    check_names(&fort, &["anchors", "originals"])?;
    let mut staging: Vec<(File, String)> = Vec::new();
    let mut state = RoleState::default();
    if exists(&fort, "anchors")? {
        let anchors = directory(&fort, "anchors", root.owner)?;
        let target = record_name();
        let stage = format!(".{target}.staging");
        check_names(&anchors, &[&target, &stage])?;
        if let Some(image) = read_image(&anchors, &target, root.owner, D_RECORD_MAX_BYTES)? {
            let r = decode_record(&image.bytes)?;
            if r.anchor["fortress_id"] != fortress || r.anchor["role"] != WIRE_ROLE {
                return Err(StoreRefusal::RECORD_ANCHOR);
            }
            state.record = Some(r);
            state.record_image = Some(image);
        }
        if exists(&anchors, &stage)? {
            read_image(&anchors, &stage, root.owner, D_RECORD_MAX_BYTES)?
                .ok_or(StoreRefusal::STAGING)?;
            staging.push((anchors, stage));
        }
    }
    let drained = state
        .record
        .as_ref()
        .and_then(|r| r.anchor["drained_sequence"].as_u64())
        .unwrap_or(0);
    let mut sequences = std::collections::BTreeSet::new();
    if exists(&fort, "originals")? {
        let originals = directory(&fort, "originals", root.owner)?;
        check_names(&originals, &[SLOT])?;
        if exists(&originals, SLOT)? {
            let copies = directory(&originals, SLOT, root.owner)?;
            let mut copy_staging = None;
            let mut staging_bytes = 0;
            // One serialized publication permits one staging copy in addition to the capped retained set.
            for leaf in enumerate(&copies, D_COPY_ENTRIES_MAX + 1)? {
                if let Some(target) = leaf
                    .strip_prefix('.')
                    .and_then(|s| s.strip_suffix(".staging"))
                {
                    if copy_staging.is_some() || parse_sequence(target) != drained.checked_add(1) {
                        return Err(StoreRefusal::STAGING);
                    }
                    let f = open_at(
                        copies.as_raw_fd(),
                        &leaf,
                        libc::O_RDONLY | libc::O_NONBLOCK,
                        0,
                    )?;
                    let m = meta(&f)?;
                    if !trusted(&m, root.owner, false)
                        || m.len() > writer_protocol::WRITER_ENVELOPE_MAX_BYTES as u64
                    {
                        return Err(StoreRefusal::STAGING);
                    }
                    staging_bytes = m.len();
                    copy_staging = Some(leaf);
                    continue;
                }
                let seq = parse_sequence(&leaf).ok_or(StoreRefusal::ENTRY)?;
                let f = open_at(
                    copies.as_raw_fd(),
                    &leaf,
                    libc::O_RDONLY | libc::O_NONBLOCK,
                    0,
                )?;
                let m = meta(&f)?;
                if !trusted(&m, root.owner, false)
                    || m.len() > writer_protocol::WRITER_ENVELOPE_MAX_BYTES as u64
                {
                    return Err(StoreRefusal::ENTRY);
                }
                state.usage.bytes = state
                    .usage
                    .bytes
                    .checked_add(m.len())
                    .ok_or(StoreRefusal::CAP)?;
                state.usage.entries += 1;
                if state.usage.bytes > D_COPY_MAX_BYTES || state.usage.entries > D_COPY_ENTRIES_MAX
                {
                    return Err(StoreRefusal::CAP);
                }
                if seq > drained.saturating_add(1) {
                    return Err(StoreRefusal::COPY_SET);
                }
                sequences.insert(seq);
                // Only the drained tail and optional orphan require envelope reads; earlier copies receive metadata checks.
                if seq == drained || seq == drained.saturating_add(1) {
                    state.copies.insert(
                        seq,
                        read_image(
                            &copies,
                            &leaf,
                            root.owner,
                            writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
                        )?
                        .ok_or(StoreRefusal::COPY_SET)?
                        .bytes,
                    );
                }
            }
            if let Some(stage) = copy_staging {
                if state.usage.bytes.saturating_add(staging_bytes) > D_COPY_MAX_BYTES
                    || state.usage.entries >= D_COPY_ENTRIES_MAX
                {
                    return Err(StoreRefusal::CAP);
                }
                staging.push((copies, stage));
            }
        }
    }
    if let Some(r) = &state.record {
        if drained > D_COPY_ENTRIES_MAX as u64
            || sequences.iter().filter(|s| **s <= drained).count() as u64 != drained
        {
            return Err(StoreRefusal::COPY_SET);
        }
        if drained == 0 {
            if r.anchor["drained_digest"] != "GENESIS" {
                return Err(StoreRefusal::COPY_TAIL);
            }
        } else {
            check_copy(
                state.copies.get(&drained).ok_or(StoreRefusal::COPY_SET)?,
                drained,
                r.anchor["drained_digest"]
                    .as_str()
                    .ok_or(StoreRefusal::COPY_TAIL)?,
                StoreRefusal::COPY_TAIL,
            )?;
        }
        if let Some(bytes) = state.copies.get(&drained.saturating_add(1)) {
            check_copy(
                bytes,
                drained + 1,
                r.ledger.first().ok_or(StoreRefusal::ORPHAN)?,
                StoreRefusal::ORPHAN,
            )?;
        }
        // Intermediate ledger entries were verified at commit and published in the same rename as the anchor; D holds no other evidence for them at start, and only the tail, an orphan and the length are re-checked.
    } else if !sequences.is_empty() {
        return Err(StoreRefusal::COPY_SET);
    }
    if !staging.is_empty() && !cleanup {
        return Err(StoreRefusal::STAGING);
    }
    // Validate the complete bounded layout before cleaning known staging leaves; unknown entries never get deleted to make a directory fit.
    for (dir, leaf) in staging {
        unlink(&dir, &leaf)?;
        dir.sync_all().map_err(|_| StoreRefusal::DIR_SYNC)?;
    }
    Ok(state)
}

struct Attempt {
    directory: File,
    target: String,
    publication: &'static str,
    old: Option<Image>,
    bytes: Vec<u8>,
    state: PublicationState,
    request_id: Option<String>,
}
pub struct Store<'a> {
    root: &'a HeldRoot,
    fortress: String,
    _lock: &'a StateLock,
    state: RoleState,
    uncertain: bool,
    attempts: Vec<Attempt>,
    copy_pending: bool,
    faults: StoreFaults,
    events: EventSink,
}
impl<'a> Store<'a> {
    pub fn open(
        root: &'a HeldRoot,
        fortress: &str,
        lock: &'a StateLock,
        owner: u32,
        mut faults: StoreFaults,
        events: EventSink,
    ) -> std::result::Result<Self, StartRefusal> {
        let m = meta(&root.file)?;
        // A lock for another root cannot authorize this state, and its fd must remain held for the store's lifetime.
        if !trusted(&m, owner, true)
            || owner != root.owner
            || m.dev() != lock.root_dev
            || m.ino() != lock.root_ino
            || !trusted(&meta(&lock.file)?, owner, false)
        {
            return Err(StoreRefusal::LOCK);
        }
        // A restart cannot infer persistence from visible bytes; sync all present paths before bounded readback and validation.
        let state = match sync_existing_chain(root, fortress, &mut faults, &events)
            .and_then(|()| validate_layout(root, fortress, true))
        {
            Ok(state) => state,
            Err(stage) => {
                events.refusal(stage, None)?;
                return Err(stage);
            }
        };
        Ok(Self {
            root,
            fortress: fortress.into(),
            _lock: lock,
            state,
            uncertain: false,
            attempts: Vec::new(),
            copy_pending: false,
            faults,
            events,
        })
    }
    pub fn observe(&self, slot: &str) -> Observation {
        let record = if slot == SLOT {
            self.state.record.as_ref()
        } else {
            None
        };
        Observation {
            state: if record.is_some() {
                ObservationState::Present
            } else {
                ObservationState::Absent
            },
            anchor: record.map(|r| r.anchor.clone()),
            anchor_digest: record.and_then(|r| anchor::anchor_digest(&r.anchor)),
            latched: record.is_some_and(|r| r.anchor["recovery_required"] == true),
            uncertain: self.uncertain || slot != SLOT,
        }
    }
    pub fn record(&self, slot: &str) -> Option<&DrainRecord> {
        (slot == SLOT)
            .then_some(self.state.record.as_ref())
            .flatten()
    }
    pub fn copy(&self, slot: &str, sequence: u64) -> Option<&[u8]> {
        if slot != SLOT {
            return None;
        }
        self.state.copies.get(&sequence).map(Vec::as_slice)
    }
    pub fn usage(&self) -> CopyUsage {
        self.state.usage
    }
    fn destination(&mut self, copy: bool) -> Result<File> {
        if !trusted(&meta(&self.root.file)?, self.root.owner, true) {
            return Err(StoreRefusal::ROOT);
        }
        let fort = mkdir(
            &self.root.file,
            &self.fortress,
            self.root.owner,
            "mkdir:fortress",
            &mut self.faults,
            &self.events,
        )?;
        let anchors = mkdir(
            &fort,
            "anchors",
            self.root.owner,
            "mkdir:anchors",
            &mut self.faults,
            &self.events,
        )?;
        let originals = mkdir(
            &fort,
            "originals",
            self.root.owner,
            "mkdir:originals",
            &mut self.faults,
            &self.events,
        )?;
        let copies = mkdir(
            &originals,
            SLOT,
            self.root.owner,
            "mkdir:copies",
            &mut self.faults,
            &self.events,
        )?;
        // Existence is not persistence: each child and its parent must sync successfully before anything is staged, even after a failed prior attempt.
        for (child, parent, child_label, parent_label) in [
            (
                &fort,
                &self.root.file,
                "chain:fortress:child",
                "chain:fortress:parent",
            ),
            (
                &anchors,
                &fort,
                "chain:anchors:child",
                "chain:anchors:parent",
            ),
            (
                &originals,
                &fort,
                "chain:originals:child",
                "chain:originals:parent",
            ),
            (
                &copies,
                &originals,
                "chain:copies:child",
                "chain:copies:parent",
            ),
        ] {
            sync_directory(child, child_label, None, &mut self.faults, &self.events)?;
            sync_directory(parent, parent_label, None, &mut self.faults, &self.events)?;
        }
        Ok(if copy { copies } else { anchors })
    }
    fn same_destination(&self, attempt: &Attempt) -> Result<()> {
        let fort = directory(&self.root.file, &self.fortress, self.root.owner)?;
        let current = if attempt.publication == "record" {
            directory(&fort, "anchors", self.root.owner)?
        } else {
            let originals = directory(&fort, "originals", self.root.owner)?;
            directory(&originals, SLOT, self.root.owner)?
        };
        let held = meta(&attempt.directory)?;
        let now = meta(&current)?;
        // Readback through an unlinked old directory cannot authorize a replacement path's state.
        if held.dev() != now.dev() || held.ino() != now.ino() {
            return Err(StoreRefusal::UNCERTAIN);
        }
        Ok(())
    }
    fn refuse(&mut self, stage: StoreRefusal) -> PublishOutcome {
        let _ = self.events.refusal(stage, None);
        // A verified orphan is charged evidence, not an uncertain record publication.
        if self.uncertain {
            self.uncertain = true;
            PublishOutcome::Uncertain(stage)
        } else {
            PublishOutcome::PrePublication(stage)
        }
    }
    pub fn publish_record(&mut self, slot: &str, record: &DrainRecord) -> PublishOutcome {
        if self.uncertain {
            return self.refuse(StoreRefusal::UNCERTAIN);
        }
        if slot != SLOT
            || record.anchor["fortress_id"] != self.fortress
            || record.anchor["role"] != WIRE_ROLE
        {
            return self.refuse(StoreRefusal::RECORD_ANCHOR);
        }
        let bytes = match encode_record(record) {
            Ok(b) => b,
            Err(e) => return self.refuse(e),
        };
        if !self.copy_pending {
            self.attempts.clear();
        }
        let dir = match self.destination(false) {
            Ok(d) => d,
            Err(e) => return self.refuse(e),
        };
        let outcome = self.publish(
            dir,
            record_name(),
            "record",
            bytes,
            Some(record.last.request_id.clone()),
        );
        if outcome == PublishOutcome::Durable {
            match validate_role_state(self.root, &self.fortress) {
                Ok(state) => {
                    self.state = state;
                    self.copy_pending = false;
                }
                Err(e) => {
                    self.uncertain = true;
                    return self.refuse(e);
                }
            }
        }
        outcome
    }
    // Continuing effect | Evidence | Refusal
    // Reverify drained tail | identical bytes, DirSync and Readback, no Stage | conflicting bytes refuse with the slot certain
    // Reuse orphan | identical bytes, DirSync and Readback, no new charge | conflicting bytes refuse with the slot certain
    // These arms must match drained_tail_retry_and_certain_reconcile in tests/linux_business_drain_store.rs.
    pub fn publish_original(&mut self, slot: &str, sequence: u64, bytes: &[u8]) -> PublishOutcome {
        if self.uncertain {
            return self.refuse(StoreRefusal::UNCERTAIN);
        }
        if slot != SLOT {
            return self.refuse(StoreRefusal::ORPHAN);
        }
        let record = match &self.state.record {
            Some(r) => r,
            None => return self.refuse(StoreRefusal::ORPHAN),
        };
        let drained = record.anchor["drained_sequence"].as_u64().unwrap_or(0);
        // Conflicting originals concern the writer's bytes, not uncertainty about an unchanged record.
        if let Some(existing) = self.state.copies.get(&sequence) {
            if existing != bytes {
                let _ = self.events.refusal(StoreRefusal::ORPHAN, None);
                return PublishOutcome::PrePublication(StoreRefusal::ORPHAN);
            }
        }
        if sequence != drained.saturating_add(1) && !(sequence == drained && sequence > 0) {
            return self.refuse(StoreRefusal::COPY_SET);
        }
        let commitment = if sequence == drained {
            record.anchor["drained_digest"].as_str()
        } else {
            record.ledger.first().map(String::as_str)
        };
        if bytes.len() > writer_protocol::WRITER_ENVELOPE_MAX_BYTES
            || check_copy(
                bytes,
                sequence,
                match commitment {
                    Some(c) => c,
                    None => return self.refuse(StoreRefusal::ORPHAN),
                },
                StoreRefusal::ORPHAN,
            )
            .is_err()
        {
            return self.refuse(StoreRefusal::ORPHAN);
        }
        let present = self.state.copies.contains_key(&sequence);
        if !present
            && (self.state.usage.bytes.saturating_add(bytes.len() as u64) > D_COPY_MAX_BYTES
                || self.state.usage.entries >= D_COPY_ENTRIES_MAX)
        {
            return self.refuse(StoreRefusal::CAP);
        }
        self.attempts.clear();
        self.copy_pending = false;
        let dir = match self.destination(true) {
            Ok(d) => d,
            Err(e) => return self.refuse(e),
        };
        let target = sequence_name(sequence);
        if present {
            let old = match read_image(
                &dir,
                &target,
                self.root.owner,
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            ) {
                Ok(Some(i)) if i.bytes == bytes => i,
                _ => return self.refuse(StoreRefusal::READBACK),
            };
            self.attempts.push(Attempt {
                directory: dir,
                target,
                publication: "copy",
                old: Some(old),
                bytes: bytes.into(),
                state: PublicationState::RenameAttempted,
                request_id: None,
            });
            self.copy_pending = sequence > drained;
            let verified = self.finish_last().and_then(|()| {
                self.same_destination(self.attempts.last().ok_or(StoreRefusal::ROOT)?)
            });
            return match verified {
                Ok(()) => PublishOutcome::Durable,
                Err(e) => {
                    self.uncertain = true;
                    self.refuse(e)
                }
            };
        }
        // Prospective copies remain charged through uncertain publication and are released only after verified cleanup or reconciliation.
        self.state.usage.bytes += bytes.len() as u64;
        self.state.usage.entries += 1;
        let outcome = self.publish(dir, target, "copy", bytes.into(), None);
        match outcome {
            PublishOutcome::Durable => {
                self.state.copies.insert(sequence, bytes.into());
                self.copy_pending = true;
            }
            PublishOutcome::PrePublication(_) => {
                self.state.usage.bytes -= bytes.len() as u64;
                self.state.usage.entries -= 1;
            }
            PublishOutcome::Uncertain(_) => {}
        }
        outcome
    }
    // Continuing effect | Evidence | Refusal
    // Durable | synced file, rename, synced directory, exact readback and held path | uncertain after rename
    // Keep old and open | no rename, or failed rename with verified old inode and bytes; cleanup verified | uncertain cleanup
    // Publish record after copy | verified copy retained in this request | uncertain copy blocks record
    // These arms must match every_record_image_cut and every_copy_cut witnesses in tests/linux_business_drain_store.rs.
    fn publish(
        &mut self,
        dir: File,
        target: String,
        publication: &'static str,
        bytes: Vec<u8>,
        request_id: Option<String>,
    ) -> PublishOutcome {
        let cap = if publication == "record" {
            D_RECORD_MAX_BYTES
        } else {
            writer_protocol::WRITER_ENVELOPE_MAX_BYTES
        };
        let old = match read_image(&dir, &target, self.root.owner, cap) {
            Ok(v) => v,
            Err(e) => return self.refuse(e),
        };
        if publication == "copy" && old.is_some() {
            return self.refuse(StoreRefusal::ORPHAN);
        }
        if publication == "record" {
            // A rename error is compared with the last verified inode and bytes, not an unchecked replacement read at admission.
            let matches = match (&old, &self.state.record_image) {
                (Some(current), Some(verified)) => {
                    current.dev == verified.dev
                        && current.ino == verified.ino
                        && current.bytes == verified.bytes
                }
                (None, None) => true,
                _ => false,
            };
            if !matches {
                return self.refuse(StoreRefusal::READBACK);
            }
        }
        self.attempts.push(Attempt {
            directory: dir,
            target,
            publication,
            old,
            bytes,
            state: PublicationState::Planned,
            request_id,
        });
        let result = self
            .write_last()
            .and_then(|()| self.same_destination(self.attempts.last().ok_or(StoreRefusal::ROOT)?));
        if let Err(stage) = result {
            let i = self.attempts.len() - 1;
            let a = &self.attempts[i];
            let unchanged = stage == StoreRefusal::RENAME
                && a.state == PublicationState::RenameAttempted
                && match read_image(&a.directory, &a.target, self.root.owner, cap) {
                    Ok(Some(now)) => a.old.as_ref().is_some_and(|old| {
                        now.dev == old.dev && now.ino == old.ino && now.bytes == old.bytes
                    }),
                    // Verified absence is the unchanged image for a first publication.
                    Ok(None) => a.old.is_none(),
                    Err(_) => false,
                };
            let renamed = matches!(
                a.state,
                PublicationState::RenameAttempted
                    | PublicationState::DirSynced
                    | PublicationState::Verified
            );
            if !renamed || unchanged {
                let stage_name = format!(".{}.staging", a.target);
                let cleanup: Result<()> = (|| {
                    if exists(&a.directory, &stage_name)? {
                        unlink(&a.directory, &stage_name)?;
                        a.directory.sync_all().map_err(|_| StoreRefusal::DIR_SYNC)?;
                    }
                    Ok(())
                })();
                if cleanup.is_err() {
                    self.uncertain = true;
                } else if !self.copy_pending {
                    self.attempts.clear();
                } else {
                    // A cleaned record attempt contributes no uncertainty; retain only the verified copy for an identical retry.
                    self.attempts.pop();
                }
            } else {
                self.uncertain = true;
            }
            return self.refuse(stage);
        }
        PublishOutcome::Durable
    }
    fn write_last(&mut self) -> Result<()> {
        let a = self.attempts.last_mut().ok_or(StoreRefusal::STAGE)?;
        self.events.emit(
            "StoreEntered",
            a.request_id.as_deref(),
            Some(a.publication),
            Some(StoreStep::HoldDirectory),
            None,
        )?;
        if !trusted(&meta(&a.directory)?, self.root.owner, true) {
            return Err(StoreRefusal::ROOT);
        }
        let staging = format!(".{}.staging", a.target);
        self.faults.hit(
            a.publication,
            StoreStep::Stage,
            "before",
            &self.events,
            a.request_id.as_deref(),
        )?;
        let mut file = open_at(
            a.directory.as_raw_fd(),
            &staging,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            custody::PRIVATE_MODE,
        )
        .map_err(|_| StoreRefusal::STAGE)?;
        a.state = PublicationState::Staged;
        self.events.emit(
            "StepCompleted",
            a.request_id.as_deref(),
            Some(a.publication),
            Some(StoreStep::Stage),
            None,
        )?;
        self.faults.hit(
            a.publication,
            StoreStep::Stage,
            "after",
            &self.events,
            a.request_id.as_deref(),
        )?;
        for step in [StoreStep::Write, StoreStep::FileSync, StoreStep::Rename] {
            self.faults.hit(
                a.publication,
                step,
                "before",
                &self.events,
                a.request_id.as_deref(),
            )?;
            match step {
                StoreStep::Write => file.write_all(&a.bytes).map_err(|_| StoreRefusal::WRITE)?,
                StoreStep::FileSync => file.sync_all().map_err(|_| StoreRefusal::FILE_SYNC)?,
                StoreStep::Rename => {
                    a.state = PublicationState::RenameAttempted;
                    let from = name(&staging)?;
                    let to = name(&a.target)?;
                    // SAFETY: both fixed leaves are in the same held destination directory.
                    if unsafe {
                        libc::renameat(
                            a.directory.as_raw_fd(),
                            from.as_ptr(),
                            a.directory.as_raw_fd(),
                            to.as_ptr(),
                        )
                    } != 0
                    {
                        return Err(StoreRefusal::RENAME);
                    }
                }
                _ => return Err(StoreRefusal::STAGE),
            }
            self.events.emit(
                "StepCompleted",
                a.request_id.as_deref(),
                Some(a.publication),
                Some(step),
                None,
            )?;
            self.faults.hit(
                a.publication,
                step,
                "after",
                &self.events,
                a.request_id.as_deref(),
            )?;
        }
        self.finish_last()
    }
    fn finish_last(&mut self) -> Result<()> {
        let a = self.attempts.last_mut().ok_or(StoreRefusal::READBACK)?;
        sync_directory(
            &a.directory,
            a.publication,
            a.request_id.as_deref(),
            &mut self.faults,
            &self.events,
        )?;
        a.state = PublicationState::DirSynced;
        let alter_before = self.faults.hit(
            a.publication,
            StoreStep::Readback,
            "before",
            &self.events,
            a.request_id.as_deref(),
        )?;
        let cap = if a.publication == "record" {
            D_RECORD_MAX_BYTES
        } else {
            writer_protocol::WRITER_ENVELOPE_MAX_BYTES
        };
        let mut image = read_image(&a.directory, &a.target, self.root.owner, cap)
            .map_err(|_| StoreRefusal::READBACK)?
            .ok_or(StoreRefusal::READBACK)?;
        let alter_after = self.faults.hit(
            a.publication,
            StoreStep::Readback,
            "after",
            &self.events,
            a.request_id.as_deref(),
        )?;
        if alter_before || alter_after {
            image.bytes.push(0);
        }
        // An acknowledgment is evidence that the bytes are on disk; it is sent only after the readback equals what was written.
        if image.bytes != a.bytes {
            return Err(StoreRefusal::READBACK);
        }
        self.events.emit(
            "StepCompleted",
            a.request_id.as_deref(),
            Some(a.publication),
            Some(StoreStep::Readback),
            None,
        )?;
        a.state = PublicationState::Verified;
        Ok(())
    }
    pub fn mark_uncertain(&mut self, slot: &str) {
        if slot == SLOT {
            self.uncertain = true;
        }
    }
    pub fn reconcile(&mut self, slot: &str) -> Result<()> {
        let result = self.reconcile_inner(slot);
        if let Err(stage) = result {
            self.events.refusal(stage, None)?;
        }
        result
    }
    // Continuing effect | Evidence | Refusal
    // Clear durable | every affected directory synced and every target equals an attempted or verified old image, layout valid | any mismatch stays uncertain
    // Clear lost | same independent sync and layout proof with old bytes or verified absence | unknown bytes stay uncertain
    // Keep open | already certain, no IO | unknown slot refuses
    // These arms must match readback_mismatch_and_directory_sync and original_record_failure witnesses in tests/linux_business_drain_store.rs.
    fn reconcile_inner(&mut self, slot: &str) -> Result<()> {
        if slot != SLOT {
            return Err(StoreRefusal::RECORD_ANCHOR);
        }
        if !self.uncertain {
            return Ok(());
        }
        if self.attempts.is_empty() {
            return Err(StoreRefusal::UNCERTAIN);
        }
        for a in &self.attempts {
            self.same_destination(a)?;
            let stage = format!(".{}.staging", a.target);
            if exists(&a.directory, &stage)? {
                unlink(&a.directory, &stage)?;
            }
            // Matching page-cache bytes alone cannot clear uncertainty; successful directory sync is independently required for each affected file.
            sync_directory(
                &a.directory,
                a.publication,
                a.request_id.as_deref(),
                &mut self.faults,
                &self.events,
            )?;
            let cap = if a.publication == "record" {
                D_RECORD_MAX_BYTES
            } else {
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES
            };
            let alter = self.faults.hit(
                a.publication,
                StoreStep::Readback,
                "before",
                &self.events,
                a.request_id.as_deref(),
            )?;
            let current = read_image(&a.directory, &a.target, self.root.owner, cap)?;
            let alter = alter
                || self.faults.hit(
                    a.publication,
                    StoreStep::Readback,
                    "after",
                    &self.events,
                    a.request_id.as_deref(),
                )?;
            let matches = match current {
                Some(ref image) => {
                    image.bytes == a.bytes
                        || a.old.as_ref().is_some_and(|old| old.bytes == image.bytes)
                }
                None => a.old.is_none(),
            };
            if alter || !matches {
                return Err(StoreRefusal::UNCERTAIN);
            }
        }
        // Reconcile all files before adopting a new observation; one successful readback never clears another publication's uncertainty.
        let state = validate_role_state(self.root, &self.fortress)?;
        self.events.emit("Reconciled", None, None, None, None)?;
        self.state = state;
        self.uncertain = false;
        self.copy_pending = false;
        Ok(())
    }
}

fn sync_directory(
    directory: &File,
    publication: &str,
    request_id: Option<&str>,
    faults: &mut StoreFaults,
    events: &EventSink,
) -> Result<()> {
    faults.hit(
        publication,
        StoreStep::DirSync,
        "before",
        events,
        request_id,
    )?;
    directory.sync_all().map_err(|_| StoreRefusal::DIR_SYNC)?;
    events.emit(
        "StepCompleted",
        request_id,
        Some(publication),
        Some(StoreStep::DirSync),
        None,
    )?;
    faults.hit(publication, StoreStep::DirSync, "after", events, request_id)?;
    Ok(())
}

// Only fixed, validated path components are visited, so startup sync work is bounded independently of directory contents.
fn sync_existing_chain(
    root: &HeldRoot,
    fortress: &str,
    faults: &mut StoreFaults,
    events: &EventSink,
) -> Result<()> {
    if !hex_shape(fortress, "", anchor::ID_HEX_LENGTH) {
        return Err(StoreRefusal::ROOT);
    }
    sync_directory(&root.file, "root", None, faults, events)?;
    if exists(&root.file, fortress)? {
        let fort = directory(&root.file, fortress, root.owner)?;
        sync_directory(&fort, "fortress", None, faults, events)?;
        if exists(&fort, "anchors")? {
            let anchors = directory(&fort, "anchors", root.owner)?;
            sync_directory(&anchors, "record", None, faults, events)?;
        }
        if exists(&fort, "originals")? {
            let originals = directory(&fort, "originals", root.owner)?;
            sync_directory(&originals, "originals", None, faults, events)?;
            if exists(&originals, SLOT)? {
                let copies = directory(&originals, SLOT, root.owner)?;
                sync_directory(&copies, "copy", None, faults, events)?;
            }
        }
    }
    Ok(())
}
