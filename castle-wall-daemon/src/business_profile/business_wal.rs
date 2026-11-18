//! Exact business envelopes in an isolated held store. Installed root selection remains disabled.
use super::{
    activation_anchor as anchor,
    append_clients::{CommitHold, DrainObservation, DrainReleaseFact, FrozenMutation},
    append_contract, drain_protocol, drain_store, records, records_schema, writer_protocol,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path},
};

pub const BUSINESS_WAL_MAX_BYTES: u64 = drain_store::D_COPY_MAX_BYTES;
pub const BUSINESS_WAL_CONTROL_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BUSINESS_WAL_TOTAL_MAX_BYTES: u64 =
    BUSINESS_WAL_MAX_BYTES + BUSINESS_WAL_CONTROL_MAX_BYTES;
pub const BUSINESS_WAL_ENTRIES_MAX: usize = drain_store::D_COPY_ENTRIES_MAX;
pub const ACTIVE_INTENTS_MAX: usize = 1;
const _: () = assert!(BUSINESS_WAL_TOTAL_MAX_BYTES == 71_303_168);
// Row metadata has at most 15 fields, two four-field identities and the three-field wrapper.
// Checkpoint metadata has eight fields, three four-field identities and that wrapper.
// Each fixed field is below 128 bytes: key at most 23, quoted digest at most 73, syntax at most 5.
const METADATA_FIELDS_MAX: usize = 32;
const METADATA_FIELD_MAX_BYTES: usize = 128;
const METADATA_MAX_BYTES: usize = METADATA_FIELDS_MAX * METADATA_FIELD_MAX_BYTES;
const _: () =
    assert!(15 + 2 * 4 + 3 <= METADATA_FIELDS_MAX && 23 + 73 + 5 <= METADATA_FIELD_MAX_BYTES);
// Two exact D requests, B, E, base64 expansion, and the derived metadata allowance.
const ROW_MAX_BYTES: usize = 2 * 4 * drain_protocol::D_REQUEST_MAX_BYTES.div_ceil(3)
    + 4 * records_schema::MAX_BYTES.div_ceil(3)
    + 4 * writer_protocol::WRITER_ENVELOPE_MAX_BYTES.div_ceil(3)
    + METADATA_MAX_BYTES;
// Each separately encoded byte string is rounded independently; unpadded base64 fits the padded bound.
const CHECKPOINT_MAX_BYTES: usize =
    4 * records::JOIN_STATE_BYTES_MAX.div_ceil(3) + anchor::MAX_BYTES + METADATA_MAX_BYTES;
// Admission leaves a complete row staging allocation in either pool and a checkpoint
// staging allocation in Control. Ordinary custody never borrows the control pool.
const ROW_REWRITE_RESERVE: u64 = ROW_MAX_BYTES as u64;
const CONTROL_REWRITE_RESERVE: u64 = ROW_REWRITE_RESERVE + CHECKPOINT_MAX_BYTES as u64;
const _: () = assert!(
    ROW_REWRITE_RESERVE < BUSINESS_WAL_MAX_BYTES
        && CONTROL_REWRITE_RESERVE < BUSINESS_WAL_CONTROL_MAX_BYTES
);
fn allocation(name: &str) -> u64 {
    if name == CHECKPOINT {
        CHECKPOINT_MAX_BYTES as u64
    } else {
        ROW_MAX_BYTES as u64
    }
}
const LOCK: &str = "business-wal.lock";
const CHECKPOINT: &str = "checkpoint.json";
const STAGING: &str = "publication.stage";
const JOURNAL: &str = "publication.journal";
const JOURNAL_STAGE: &str = "journal.stage";
// Eleven bounded fields plus the checksum wrapper fit 1024 bytes: target <=29,
// four digests <=71 each, four decimal u64s <=20 each and fixed syntax <=201.
const JOURNAL_MAX_BYTES: usize = 1024;
const JOURNAL_RESERVE: u64 = 2 * JOURNAL_MAX_BYTES as u64;
const _: () = assert!(JOURNAL_RESERVE <= 3264);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationJournal {
    version: u8,
    target: String,
    length: u64,
    checksum: String,
    predecessor: Option<String>,
    checkpoint_checksum: Option<String>,
    root_device: u64,
    root_inode: u64,
    lock_inode: u64,
    control: bool,
    retire: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Root,
    Lock,
    Shape,
    Missing,
    Capacity,
    Held,
    Conflict,
    Deadline,
    Authority,
    Io,
}
pub type Result<T> = std::result::Result<T, Refusal>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyDigest(String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinCommitment(String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageChecksum(String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusinessSequence(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCursor(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalStep {
    JournalPrepare,
    JournalDurable,
    StageCreate,
    Write,
    FileSync,
    Rename,
    DirectorySync,
    Readback,
    Delete,
}
pub trait WalHooks: Send {
    fn before(&mut self, step: WalStep) -> Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalState {
    Ready,
    PublicationHeld,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    Ordinary,
    Control,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    sequence: u64,
    commitment: String,
    envelope_sha256: String,
}
impl Identity {
    fn from_envelope(bytes: &[u8]) -> Result<Self> {
        serde_json::from_value(append_contract::identity(bytes).ok_or(Refusal::Shape)?)
            .map_err(|_| Refusal::Shape)
    }
    fn value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| Refusal::Shape)
    }
    fn valid(&self) -> bool {
        self.version == 1
            && self.sequence > 0
            && self.sequence <= anchor::SAFE_INTEGER
            && drain_protocol::digest(&self.commitment)
            && drain_protocol::digest(&self.envelope_sha256)
    }
}
// BODY_FROZEN, SIGN_MARKED, E_FROZEN and COMMIT_FROZEN are the persisted intent lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentState {
    BodyFrozen,
    SignMarked,
    EnvelopeFrozen,
    CommitFrozen,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    version: u8,
    sequence: u64,
    storage_cursor: u64,
    control: bool,
    body: String,
    body_digest: String,
    reserve: String,
    commit: Option<String>,
    append_deadline: String,
    grant_expiry: String,
    sign_may_have_been_sent: bool,
    envelope: Option<String>,
    d_fact: Option<Identity>,
    ts_fact: Option<Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effect_status: Option<String>,
}
impl Row {
    fn intent_state(&self) -> IntentState {
        if self.commit.is_some() {
            IntentState::CommitFrozen
        } else if self.envelope.is_some() {
            IntentState::EnvelopeFrozen
        } else if self.sign_may_have_been_sent {
            IntentState::SignMarked
        } else {
            IntentState::BodyFrozen
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    anchor: Value,
    join_state: String,
    active: Option<u64>,
    released: Option<Identity>,
    delivered: Option<Identity>,
    originals: Option<Identity>,
    next_cursor: u64,
}
/// An owned readback for ordinary reconciliation. Only the locked WAL constructs it.
pub struct OrdinaryWalCheckpoint {
    pub(crate) value: Value,
    pub(crate) observed: u64,
}
pub struct CheckpointSeed {
    anchor: Value,
    join_bytes: Vec<u8>,
}
impl CheckpointSeed {
    /// The composition supplies independent initial state; an empty suffix is never a seed.
    pub fn checked(anchor: Value, join_bytes: Vec<u8>) -> Result<Self> {
        let join = records::decode_join_state(&join_bytes).ok_or(Refusal::Shape)?;
        if !anchor::valid(&anchor)
            || anchor["committed_sequence"] != join["anchor"]["sequence"]
            || anchor["committed_digest"] != join["anchor"]["commitment"]
        {
            return Err(Refusal::Conflict);
        }
        Ok(Self { anchor, join_bytes })
    }
}
/// This dependency is a trusted durable business sink, not an IPC ACK parser.
/// It returns only after exact E, projection, join checkpoint and identity are atomically persisted and read back.
/// Must match BusinessDurableSink in server/src/castle-wall/runtime/business-record-consumer.ts.
pub(crate) mod sink_seal {
    pub trait Sealed {}
    // Isolated fixtures supply synthetic durable sinks; installed composition has no implementor yet.
    #[cfg(feature = "test-isolation")]
    impl<T> Sealed for T {}
}
pub trait TrustedBusinessSink: sink_seal::Sealed + Send {
    fn accept_durably(&mut self, exact_envelope: &[u8]) -> Result<Value>;
}
pub struct BusinessSinkAdapter<T: TrustedBusinessSink> {
    sink: T,
    pending: Option<Vec<u8>>,
}
/// Only next_delivery mints this read-only capability after durable cursor validation.
#[derive(Debug)]
pub struct DeliveryToken {
    envelope: Vec<u8>,
}
impl DeliveryToken {
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}
#[cfg(feature = "test-isolation")]
impl PartialEq<Vec<u8>> for DeliveryToken {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.envelope == other
    }
}
pub struct TsReleaseFact {
    identity: Identity,
}
impl<T: TrustedBusinessSink> BusinessSinkAdapter<T> {
    pub fn from_trusted_sink(sink: T) -> Self {
        Self {
            sink,
            pending: None,
        }
    }
    /// Offer one exact token without waiting for a peer; the caller polls outside the WAL worker.
    pub fn offer(&mut self, token: &DeliveryToken) -> Result<()> {
        let envelope = token.envelope();
        Identity::from_envelope(envelope)?;
        if self.pending.as_ref().is_some_and(|b| b != envelope) {
            return Err(Refusal::Held);
        }
        self.pending = Some(envelope.to_vec());
        Ok(())
    }
    /// Poll the trusted sink after offer. Only its durable correlated acceptance mints a fact.
    pub fn complete(&mut self) -> Result<TsReleaseFact> {
        let envelope = self.pending.as_ref().ok_or(Refusal::Missing)?;
        let identity = Identity::from_envelope(envelope)?;
        let ack = self.sink.accept_durably(envelope)?;
        if !append_contract::shape("ack", &ack) || ack["identity"] != identity.value()? {
            return Err(Refusal::Conflict);
        }
        self.pending = None;
        Ok(TsReleaseFact { identity })
    }
    /// Synchronous fixture compatibility; composition uses offer/complete outside the store slot.
    pub fn deliver(&mut self, envelope: &DeliveryToken) -> Result<TsReleaseFact> {
        self.offer(envelope)?;
        self.complete()
    }
}
/// A trusted native adapter offers bytes and polls authenticated durable acceptance without blocking W.
/// Must match BusinessSinkAdapter's exact-identity contract; only local fact persistence belongs in the WAL slot.
pub trait PolledBusinessSink: sink_seal::Sealed + Send {
    fn offer(&mut self, exact_envelope: &[u8]) -> Result<()>;
    fn poll(&mut self) -> Result<Option<Value>>;
    /// The last polled ACK was refused and minted no fact; the wait stays pending for a correlated ACK.
    fn refused(&mut self) -> Result<()>;
}
/// One bounded peer wait retains exact E independently of the serialized store executor.
pub struct PolledSinkAdapter<T: PolledBusinessSink> {
    sink: T,
    pending: Option<Vec<u8>>,
}
impl<T: PolledBusinessSink> PolledSinkAdapter<T> {
    /// The native composition supplies the sealed authenticated sink.
    pub fn new(sink: T) -> Self {
        Self {
            sink,
            pending: None,
        }
    }
    /// Re-offer only the same owned token; a deadline does not permit another delivery.
    pub fn offer(&mut self, token: &DeliveryToken) -> Result<()> {
        if let Some(pending) = &self.pending {
            return if pending == token.envelope() {
                self.sink.offer(token.envelope())
            } else {
                Err(Refusal::Held)
            };
        }
        Identity::from_envelope(token.envelope())?;
        self.pending = Some(token.envelope().to_vec());
        self.sink.offer(token.envelope())
    }
    /// Only a correlated durable acceptance can consume this wait into a release fact.
    pub fn poll(&mut self) -> Result<Option<TsReleaseFact>> {
        let Some(envelope) = &self.pending else {
            return Ok(None);
        };
        let Some(ack) = self.sink.poll()? else {
            return Ok(None);
        };
        let identity = Identity::from_envelope(envelope)?;
        if !append_contract::shape("ack", &ack) || ack["identity"] != identity.value()? {
            // pending is still held, so no fact exists for this ACK; a sink latch taken for it must not wedge the wait.
            // Must match NativeSink::refused in business_delivery.rs.
            self.sink.refused()?;
            return Err(Refusal::Conflict);
        }
        // Must stay paired with the fact_pending guards in business_delivery.rs: consuming pending prevents a second fact.
        self.pending = None;
        Ok(Some(TsReleaseFact { identity }))
    }
}
struct RecoveryRead<'a> {
    observation: &'a DrainObservation,
    clock: &'a super::writer_peer::Clock,
}
struct PendingPublication {
    name: String,
    bytes: Vec<u8>,
    old_size: u64,
    pool: Pool,
}
pub struct BusinessWal {
    root: File,
    _lock: File,
    owner: u32,
    hooks: Box<dyn WalHooks>,
    checkpoint: Checkpoint,
    usage: [u64; 2],
    entries: usize,
    opened_active: Option<u64>,
    live_effect: Option<u64>,
    state: WalState,
    pending: Option<PendingPublication>,
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    crate::smb::jcs::encode(&serde_json::to_value(value).map_err(|_| Refusal::Shape)?)
        .map(String::into_bytes)
        .map_err(|_| Refusal::Shape)
}
fn body_digest(bytes: &[u8]) -> BodyDigest {
    BodyDigest(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
fn checksum(bytes: &[u8]) -> StorageChecksum {
    StorageChecksum(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
fn pack<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_value(value).map_err(|_| Refusal::Shape)?;
    canonical(
        &json!({"version":1,"payload":payload,"storage_checksum":checksum(&canonical(&payload)?).0}),
    )
}
fn unpack<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8], cap: usize) -> Result<T> {
    let strict = crate::smb::strict_json::parse(bytes, cap).map_err(|_| Refusal::Shape)?;
    if canonical(&strict)? != bytes {
        return Err(Refusal::Shape);
    }
    // The strict parser establishes canonical bytes; typed integer fields use the original JSON number domain.
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Refusal::Shape)?;
    if value.as_object().map_or(true, |v| v.len() != 3)
        || value["version"] != 1
        || value["storage_checksum"] != checksum(&canonical(&value["payload"])?).0
    {
        return Err(Refusal::Shape);
    }
    let parsed: T = serde_json::from_value(value["payload"].clone()).map_err(|_| Refusal::Shape)?;
    // Optional evidence is explicitly null; only absent effect_status has an omitted-field representation.
    if canonical(&parsed)? != canonical(&value["payload"])? {
        return Err(Refusal::Shape);
    }
    Ok(parsed)
}
fn decode_bytes(value: &str, cap: usize) -> Result<Vec<u8>> {
    if value.len() > (4 * cap).div_ceil(3) {
        return Err(Refusal::Capacity);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Refusal::Shape)?;
    if bytes.len() > cap || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Refusal::Shape);
    }
    Ok(bytes)
}
fn pool_index(pool: Pool) -> usize {
    if pool == Pool::Ordinary {
        0
    } else {
        1
    }
}
fn row_name(sequence: u64) -> String {
    format!("row-{sequence:020}.json")
}
fn private_file(file: &File, owner: u32) -> Result<u64> {
    let m = file.metadata().map_err(|_| Refusal::Io)?;
    if !m.is_file() || m.uid() != owner || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 {
        return Err(Refusal::Root);
    }
    Ok(m.len())
}
fn set_private_mode(file: &File) -> Result<()> {
    // Creation mode is independent of the caller's umask before any private-file validation.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(Refusal::Io);
    }
    Ok(())
}
fn open_at(root: &File, leaf: &str, flags: i32) -> Result<File> {
    let leaf = CString::new(leaf).map_err(|_| Refusal::Root)?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            leaf.as_ptr(),
            // A non-regular entry must reach the type check without blocking on open.
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Refusal::Missing
            } else {
                Refusal::Io
            },
        );
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn held_root(path: &Path, owner: u32) -> Result<File> {
    if !path.is_absolute() {
        return Err(Refusal::Root);
    }
    let mut current = File::open("/").map_err(|_| Refusal::Root)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(leaf) => {
                let next = open_at(
                    &current,
                    leaf.to_str().ok_or(Refusal::Root)?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                // Each existing directory link is synchronized before the isolated store can claim durable publication.
                current.sync_all().map_err(|_| Refusal::Io)?;
                current = next;
            }
            _ => return Err(Refusal::Root),
        }
    }
    let m = current.metadata().map_err(|_| Refusal::Root)?;
    if !m.is_dir() || m.uid() != owner || m.mode() & 0o7777 != 0o700 {
        return Err(Refusal::Root);
    }
    current.sync_all().map_err(|_| Refusal::Io)?;
    Ok(current)
}
/// Startup can settle exact retained evidence, but this result never contains a SIGN or effect capability.
pub enum RecoveryAction {
    Held(CommitHold),
    Ready,
    Retry(FrozenMutation),
    Original {
        sequence: BusinessSequence,
        envelope: Vec<u8>,
    },
    Observe,
}
/// ORIGINAL retries derive their stable request identity from exact retained E across a restart.
pub fn original_request_id(envelope: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"sanctuary-business-original-v1");
    hash.update(envelope);
    // The wire request id is the first 128 bits of a domain-separated exact-envelope digest.
    hex::encode(&hash.finalize()[..16])
}
impl BusinessWal {
    pub fn open_isolated(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
    ) -> Result<Self> {
        Self::open_accounted(path, owner, hooks, seed, [0, 0], None)
    }
    /// Recovery may retire only an independently confirmed never-reserved orphan under this lock.
    pub fn open_recovering(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
        observation: &DrainObservation,
        clock: &super::writer_peer::Clock,
    ) -> Result<Self> {
        let evidence = RecoveryRead { observation, clock };
        Self::open_accounted(path, owner, hooks, seed, [0, 0], Some(&evidence))
    }
    fn open_accounted(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
        occupied: [u64; 2],
        recovery: Option<&RecoveryRead<'_>>,
    ) -> Result<Self> {
        let root = held_root(path, owner)?;
        // Lock acquisition precedes enumeration, staging inspection and checkpoint reads. The inode is never unlinked.
        let (lock, created) =
            match open_at(&root, LOCK, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL) {
                Ok(file) => {
                    set_private_mode(&file)?;
                    (file, true)
                }
                Err(_) => (open_at(&root, LOCK, libc::O_RDWR)?, false),
            };
        private_file(&lock, owner)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Refusal::Lock);
        }
        root.sync_all().map_err(|_| Refusal::Io)?;
        let initial = seed.map(|s| Checkpoint {
            version: 1,
            anchor: s.anchor,
            join_state: URL_SAFE_NO_PAD.encode(s.join_bytes),
            active: None,
            released: None,
            delivered: None,
            originals: None,
            next_cursor: 1,
        });
        let mut store = Self {
            root,
            _lock: lock,
            owner,
            hooks,
            checkpoint: initial.clone().unwrap_or(Checkpoint {
                version: 1,
                anchor: Value::Null,
                join_state: String::new(),
                active: None,
                released: None,
                delivered: None,
                originals: None,
                next_cursor: 1,
            }),
            usage: [occupied[0] + JOURNAL_RESERVE, occupied[1] + JOURNAL_RESERVE],
            entries: 0,
            opened_active: None,
            live_effect: None,
            state: WalState::Ready,
            pending: None,
        };
        store.recover_journal(initial.as_ref(), recovery)?;
        let mut rows = BTreeMap::new();
        // The cap counts stored rows; lock, checkpoint and one staging file are the only fixed entries.
        let directory = std::fs::read_dir(format!("/proc/self/fd/{}", store.root.as_raw_fd()))
            .map_err(|_| Refusal::Root)?;
        for (index, entry) in directory.enumerate() {
            if index >= BUSINESS_WAL_ENTRIES_MAX + 5 {
                return Err(Refusal::Capacity);
            }
            let name = entry
                .map_err(|_| Refusal::Io)?
                .file_name()
                .into_string()
                .map_err(|_| Refusal::Shape)?;
            match name.as_str() {
                LOCK => {}
                STAGING | JOURNAL | JOURNAL_STAGE => return Err(Refusal::Held),
                CHECKPOINT => {
                    let bytes = store.read(CHECKPOINT, CHECKPOINT_MAX_BYTES)?;
                    store.checkpoint = unpack(&bytes, CHECKPOINT_MAX_BYTES)?;
                    store.usage[1] = store.usage[1]
                        .checked_add(allocation(CHECKPOINT))
                        .ok_or(Refusal::Capacity)?;
                }
                _ => {
                    let bytes = store.read(&name, ROW_MAX_BYTES)?;
                    let row: Row = unpack(&bytes, ROW_MAX_BYTES)?;
                    store.validate_row(&row)?;
                    if name != row_name(row.sequence)
                        || rows.insert(row.sequence, row.clone()).is_some()
                    {
                        return Err(Refusal::Shape);
                    }
                    let index = usize::from(row.control);
                    store.usage[index] = store.usage[index]
                        .checked_add(ROW_MAX_BYTES as u64)
                        .ok_or(Refusal::Capacity)?;
                    store.entries += 1;
                }
            }
        }
        if created {
            if store.entries != 0 || store.usage != [JOURNAL_RESERVE, JOURNAL_RESERVE] {
                return Err(Refusal::Conflict);
            }
            let initial = initial.ok_or(Refusal::Missing)?;
            store.validate_checkpoint(&initial)?;
            store.save_checkpoint(initial)?;
        } else {
            if store.usage[1] == JOURNAL_RESERVE {
                return Err(Refusal::Missing);
            }
            store.validate_checkpoint(&store.checkpoint)?;
        }
        store.capacity(0, Pool::Ordinary)?;
        store.capacity(0, Pool::Control)?;
        store.retire_orphan(&mut rows, recovery)?;
        store.validate_rows(&rows)?;
        store.opened_active = store.checkpoint.active;
        if !created {
            // A later fsync of an old inode cannot clear an earlier writeback error. Restart
            // republishes the validated exact bytes through fresh staging before exposing any cursor.
            for row in rows.values() {
                store.save_row(row)?;
            }
            store.save_checkpoint(store.checkpoint.clone())?;
        }
        // A crash may leave an already released row. Only its read-back checkpoint and both exact facts permit cleanup.
        let released = store.checkpoint.released.as_ref().map_or(0, |i| i.sequence);
        for (sequence, row) in &rows {
            if *sequence <= released {
                store.delete_released(row)?;
            }
        }
        Ok(store)
    }
    fn ready(&self) -> Result<()> {
        if self.state == WalState::Ready {
            Ok(())
        } else {
            Err(Refusal::Held)
        }
    }
    pub fn state(&self) -> WalState {
        self.state
    }
    pub fn charged_bytes(&self) -> (u64, u64) {
        (self.usage[0], self.usage[1])
    }
    pub fn committed_join(&self) -> Result<Vec<u8>> {
        decode_bytes(&self.checkpoint.join_state, records::JOIN_STATE_BYTES_MAX)
    }
    pub fn committed_anchor(&self) -> &Value {
        &self.checkpoint.anchor
    }
    /// Read the durable ordinary evidence on the store worker, outside the wall poll loop.
    /// The completion stamp follows every disk read; report assembly uses the older D/WAL stamp.
    pub fn ordinary_checkpoint(
        &self,
        clock: &super::writer_peer::Clock,
    ) -> Result<OrdinaryWalCheckpoint> {
        self.ready()?;
        let durable: Checkpoint = unpack(
            &self.read(CHECKPOINT, CHECKPOINT_MAX_BYTES)?,
            CHECKPOINT_MAX_BYTES,
        )?;
        if canonical(&durable)? != canonical(&self.checkpoint)? || durable.active.is_some() {
            return Err(Refusal::Held);
        }
        self.validate_checkpoint(&durable)?;
        let committed = durable.anchor["committed_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        let drained = durable.anchor["drained_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        let count = committed.checked_sub(drained).ok_or(Refusal::Conflict)?;
        if count > super::drain_store::D_UNDRAINED_MAX as u64 {
            return Err(Refusal::Capacity);
        }
        let mut retained = Vec::with_capacity(count as usize);
        for sequence in drained + 1..=committed {
            let row = self.row(sequence)?;
            self.validate_row(&row)?;
            if row.effect_status.is_some() || row.commit.is_none() {
                return Err(Refusal::Held);
            }
            let envelope = decode_bytes(
                row.envelope.as_ref().ok_or(Refusal::Missing)?,
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            )?;
            let record = writer_protocol::decode_envelope(&envelope).map_err(|_| Refusal::Shape)?;
            retained.push(json!({"sequence":sequence,"commitment":records::join_commitment(&record).ok_or(Refusal::Shape)?}));
        }
        let join = records::decode_join_state(&decode_bytes(
            &durable.join_state,
            records::JOIN_STATE_BYTES_MAX,
        )?)
        .ok_or(Refusal::Shape)?;
        let value = json!({"committed_sequence":committed,"committed_digest":durable.anchor["committed_digest"],
            "drained_sequence":drained,"drained_digest":durable.anchor["drained_digest"],
            "join_state":join,"retained_originals":retained,"unresolved_intent":false});
        if !append_contract::shape("wal_checkpoint", &value) {
            return Err(Refusal::Shape);
        }
        Ok(OrdinaryWalCheckpoint {
            value,
            observed: clock().map_err(|_| Refusal::Io)?,
        })
    }
    fn read(&self, name: &str, cap: usize) -> Result<Vec<u8>> {
        let file = open_at(&self.root, name, libc::O_RDONLY)?;
        if private_file(&file, self.owner)? > cap as u64 {
            return Err(Refusal::Capacity);
        }
        let mut bytes = Vec::new();
        file.take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::Io)?;
        if bytes.len() > cap {
            return Err(Refusal::Capacity);
        }
        Ok(bytes)
    }
    fn row(&self, seq: u64) -> Result<Row> {
        let row = unpack(&self.read(&row_name(seq), ROW_MAX_BYTES)?, ROW_MAX_BYTES)?;
        self.validate_row(&row)?;
        Ok(row)
    }
    fn capacity(&self, extra: u64, pool: Pool) -> Result<()> {
        let i = pool_index(pool);
        let cap = if i == 0 {
            BUSINESS_WAL_MAX_BYTES
        } else {
            BUSINESS_WAL_CONTROL_MAX_BYTES
        };
        if self.usage[i].checked_add(extra).ok_or(Refusal::Capacity)? > cap
            || self.usage[0]
                .checked_add(self.usage[1])
                .and_then(|n| n.checked_add(extra))
                .ok_or(Refusal::Capacity)?
                > BUSINESS_WAL_TOTAL_MAX_BYTES
        {
            return Err(Refusal::Capacity);
        }
        Ok(())
    }
    fn validate_checkpoint(&self, c: &Checkpoint) -> Result<()> {
        let bytes = decode_bytes(&c.join_state, records::JOIN_STATE_BYTES_MAX)?;
        let j = records::decode_join_state(&bytes).ok_or(Refusal::Shape)?;
        if c.version != 1
            || !anchor::valid(&c.anchor)
            || c.anchor["committed_sequence"] != j["anchor"]["sequence"]
            || c.anchor["committed_digest"] != j["anchor"]["commitment"]
            || c.next_cursor == 0
            || c.next_cursor > anchor::SAFE_INTEGER
        {
            return Err(Refusal::Shape);
        }
        let committed = c.anchor["committed_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        let released = c.released.as_ref().map_or(0, |i| i.sequence);
        let delivered = c.delivered.as_ref().map_or(0, |i| i.sequence);
        let originals = c.originals.as_ref().map_or(0, |i| i.sequence);
        // Either missing fact leaves its cursor behind, so released cannot pass delivered or originals.
        // Paired with the exact-fact predicate `(Some(d), Some(ts))` in BusinessWal::compact_one in business_wal.rs.
        if released > delivered
            || released > originals
            || originals > committed
            || delivered > committed
            || c.released
                .iter()
                .chain(c.delivered.iter())
                .chain(c.originals.iter())
                .any(|i| !i.valid())
            || c.active
                .is_some_and(|n| Some(n) != committed.checked_add(1))
        {
            return Err(Refusal::Shape);
        }
        Ok(())
    }
    fn validate_row(&self, r: &Row) -> Result<()> {
        let b = decode_bytes(&r.body, records_schema::MAX_BYTES)?;
        let body = records::decode(&b).ok_or(Refusal::Shape)?;
        let reserve = FrozenMutation::checked(decode_bytes(
            &r.reserve,
            drain_protocol::D_REQUEST_MAX_BYTES,
        )?)
        .map_err(|_| Refusal::Shape)?;
        if r.version != 1
            || r.sequence == 0
            || r.sequence != body["sequence"].as_u64().ok_or(Refusal::Shape)?
            || r.storage_cursor == 0
            || r.storage_cursor > anchor::SAFE_INTEGER
            || r.body_digest != body_digest(&b).0
            || reserve.next()["reserved_sequence"] != r.sequence
            || reserve.next()["reserved_body_digest"] != r.body_digest
            || writer_protocol::canonical_deadline(&r.append_deadline).ok_or(Refusal::Shape)?
                > writer_protocol::canonical_deadline(&r.grant_expiry).ok_or(Refusal::Shape)?
            || r.effect_status.as_deref().is_some_and(|v| v != "unknown")
        {
            return Err(Refusal::Shape);
        }
        if r.control
            && !matches!(
                body["record_kind"].as_str(),
                Some("control" | "terminal" | "denial_overflow")
            )
        {
            return Err(Refusal::Authority);
        }
        if let Some(envelope) = &r.envelope {
            let e = decode_bytes(envelope, writer_protocol::WRITER_ENVELOPE_MAX_BYTES)?;
            let record = writer_protocol::decode_envelope(&e).map_err(|_| Refusal::Shape)?;
            let id = Identity::from_envelope(&e)?;
            if canonical(&record["body"])? != b
                || !r.sign_may_have_been_sent
                || r.d_fact.iter().chain(r.ts_fact.iter()).any(|f| f != &id)
            {
                return Err(Refusal::Conflict);
            }
            if let Some(commit) = &r.commit {
                let raw = decode_bytes(commit, drain_protocol::D_REQUEST_MAX_BYTES)?;
                let proposal = FrozenMutation::checked(raw.clone()).map_err(|_| Refusal::Shape)?;
                let decoded = drain_protocol::decode(&raw, drain_protocol::Direction::ToDrain)
                    .map_err(|_| Refusal::Shape)?;
                if !matches!(decoded.operation,drain_protocol::Operation::Anchor{envelope,..} if envelope==e)
                    || proposal.expected() != reserve.next()
                    || proposal.next()["committed_sequence"] != r.sequence
                    || proposal.next()["committed_digest"] != id.commitment
                {
                    return Err(Refusal::Conflict);
                }
            }
        } else if matches!(r.intent_state(), IntentState::CommitFrozen)
            || r.d_fact.is_some()
            || r.ts_fact.is_some()
        {
            return Err(Refusal::Shape);
        }
        Ok(())
    }
    fn validate_rows(&self, rows: &BTreeMap<u64, Row>) -> Result<()> {
        let released = self.checkpoint.released.as_ref().map_or(0, |i| i.sequence);
        let committed = self.checkpoint.anchor["committed_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        let expected = committed.checked_sub(released).ok_or(Refusal::Shape)?;
        if expected > BUSINESS_WAL_ENTRIES_MAX as u64
            || rows
                .keys()
                .filter(|n| **n > released && **n <= committed)
                .count() as u64
                != expected
        {
            return Err(Refusal::Missing);
        }
        for (sequence, row) in rows {
            if *sequence > committed && self.checkpoint.active != Some(*sequence) {
                return Err(Refusal::Held);
            }
            if *sequence <= committed && (row.envelope.is_none() || row.commit.is_none()) {
                return Err(Refusal::Missing);
            }
            if *sequence <= released && (row.d_fact.is_none() || row.ts_fact.is_none()) {
                return Err(Refusal::Conflict);
            }
            if *sequence <= self.checkpoint.delivered.as_ref().map_or(0, |i| i.sequence)
                && row.ts_fact.is_none()
            {
                return Err(Refusal::Missing);
            }
            if *sequence <= self.checkpoint.originals.as_ref().map_or(0, |i| i.sequence)
                && row.d_fact.is_none()
            {
                return Err(Refusal::Missing);
            }
            if row.storage_cursor >= self.checkpoint.next_cursor {
                return Err(Refusal::Conflict);
            }
        }
        if self
            .checkpoint
            .active
            .is_some_and(|n| !rows.contains_key(&n))
        {
            return Err(Refusal::Missing);
        }
        if let Some(delivered) = &self.checkpoint.delivered {
            if delivered.sequence > released
                && rows
                    .get(&delivered.sequence)
                    .and_then(|r| r.ts_fact.as_ref())
                    != Some(delivered)
            {
                return Err(Refusal::Conflict);
            }
        }
        // Each persisted cursor names the exact evidence in a retained row, not merely its sequence.
        if let Some(original) = &self.checkpoint.originals {
            if original.sequence > released
                && rows.get(&original.sequence).and_then(|r| r.d_fact.as_ref()) != Some(original)
            {
                return Err(Refusal::Conflict);
            }
        }
        if let Some(release) = &self.checkpoint.released {
            if rows.get(&release.sequence).is_some_and(|r| {
                r.d_fact.as_ref() != Some(release) || r.ts_fact.as_ref() != Some(release)
            }) {
                return Err(Refusal::Conflict);
            }
            for cursor in [&self.checkpoint.delivered, &self.checkpoint.originals]
                .into_iter()
                .flatten()
            {
                if cursor.sequence == release.sequence && cursor != release {
                    return Err(Refusal::Conflict);
                }
            }
        }
        Ok(())
    }
    fn remove_private(&self, name: &str) -> Result<()> {
        let file = open_at(&self.root, name, libc::O_RDONLY)?;
        private_file(&file, self.owner)?;
        let leaf = CString::new(name).map_err(|_| Refusal::Root)?;
        if unsafe { libc::unlinkat(self.root.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
            return Err(Refusal::Io);
        }
        self.root.sync_all().map_err(|_| Refusal::Io)?;
        if !matches!(
            open_at(&self.root, name, libc::O_RDONLY),
            Err(Refusal::Missing)
        ) {
            return Err(Refusal::Held);
        }
        Ok(())
    }
    fn clear_journal(&self) -> Result<()> {
        self.remove_private(JOURNAL)
    }
    fn write_stage(&self, bytes: &[u8]) -> Result<()> {
        let mut stage = open_at(
            &self.root,
            STAGING,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        set_private_mode(&stage)?;
        private_file(&stage, self.owner)?;
        stage.write_all(bytes).map_err(|_| Refusal::Io)?;
        stage.sync_all().map_err(|_| Refusal::Io)
    }
    fn write_journal(
        &mut self,
        target: &str,
        bytes: &[u8],
        pool: Pool,
        retire: bool,
    ) -> Result<()> {
        let root = self.root.metadata().map_err(|_| Refusal::Io)?;
        let lock = self._lock.metadata().map_err(|_| Refusal::Io)?;
        let predecessor = match self.read(target, allocation(target) as usize) {
            Ok(previous) => Some(checksum(&previous).0),
            Err(Refusal::Missing) => None,
            Err(e) => return Err(e),
        };
        let journal = PublicationJournal {
            version: 1,
            target: target.into(),
            length: bytes.len() as u64,
            checksum: checksum(bytes).0,
            predecessor,
            checkpoint_checksum: self
                .read(CHECKPOINT, CHECKPOINT_MAX_BYTES)
                .ok()
                .map(|b| checksum(&b).0),
            root_device: root.dev(),
            root_inode: root.ino(),
            lock_inode: lock.ino(),
            control: pool == Pool::Control,
            retire,
        };
        let bytes = pack(&journal)?;
        if bytes.len() > JOURNAL_MAX_BYTES {
            return Err(Refusal::Capacity);
        }
        // Journal durability precedes every guarded mutation; its two copies are reserved in both reviewed pools.
        self.hooks.before(WalStep::JournalPrepare)?;
        let mut stage = open_at(
            &self.root,
            JOURNAL_STAGE,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        set_private_mode(&stage)?;
        stage.write_all(&bytes).map_err(|_| Refusal::Io)?;
        stage.sync_all().map_err(|_| Refusal::Io)?;
        let from = CString::new(JOURNAL_STAGE).map_err(|_| Refusal::Root)?;
        let to = CString::new(JOURNAL).map_err(|_| Refusal::Root)?;
        if unsafe {
            libc::renameat(
                self.root.as_raw_fd(),
                from.as_ptr(),
                self.root.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(Refusal::Io);
        }
        self.root.sync_all().map_err(|_| Refusal::Io)?;
        if self.read(JOURNAL, JOURNAL_MAX_BYTES)? != bytes {
            return Err(Refusal::Conflict);
        }
        self.hooks.before(WalStep::JournalDurable)?;
        Ok(())
    }
    fn recover_journal(
        &mut self,
        seed: Option<&Checkpoint>,
        observation: Option<&RecoveryRead<'_>>,
    ) -> Result<()> {
        let journal: PublicationJournal = match self.read(JOURNAL, JOURNAL_MAX_BYTES) {
            Ok(bytes) => unpack(&bytes, JOURNAL_MAX_BYTES)?,
            Err(Refusal::Missing) => return Ok(()),
            Err(e) => return Err(e),
        };
        let root = self.root.metadata().map_err(|_| Refusal::Io)?;
        let lock = self._lock.metadata().map_err(|_| Refusal::Io)?;
        if journal.version != 1
            || journal.root_device != root.dev()
            || journal.root_inode != root.ino()
            || journal.lock_inode != lock.ino()
            || journal.length > allocation(&journal.target)
            || !(journal.target == CHECKPOINT
                || journal
                    .target
                    .strip_prefix("row-")
                    .and_then(|s| s.strip_suffix(".json"))
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| row_name(n) == journal.target))
            || !drain_protocol::digest(&journal.checksum)
        {
            return Err(Refusal::Held);
        }
        // A bounded scan charges every existing source and staging copy before recovery mutates the directory.
        let mut usage = [JOURNAL_RESERVE; 2];
        let mut has_rows = false;
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", self.root.as_raw_fd()))
            .map_err(|_| Refusal::Root)?;
        for (index, entry) in entries.enumerate() {
            if index >= BUSINESS_WAL_ENTRIES_MAX + 5 {
                return Err(Refusal::Capacity);
            }
            let name = entry
                .map_err(|_| Refusal::Io)?
                .file_name()
                .into_string()
                .map_err(|_| Refusal::Shape)?;
            let file = open_at(&self.root, &name, libc::O_RDONLY)?;
            private_file(&file, self.owner)?;
            match name.as_str() {
                LOCK | JOURNAL => {}
                JOURNAL_STAGE => return Err(Refusal::Held),
                STAGING => usage[usize::from(journal.control)] += allocation(&journal.target),
                CHECKPOINT => usage[1] += allocation(CHECKPOINT),
                _ => {
                    has_rows = true;
                    let row: Row = unpack(&self.read(&name, ROW_MAX_BYTES)?, ROW_MAX_BYTES)?;
                    self.validate_row(&row)?;
                    if name != row_name(row.sequence) {
                        return Err(Refusal::Shape);
                    }
                    usage[usize::from(row.control)] += ROW_MAX_BYTES as u64;
                }
            }
        }
        if usage[0] > BUSINESS_WAL_MAX_BYTES || usage[1] > BUSINESS_WAL_CONTROL_MAX_BYTES {
            return Err(Refusal::Capacity);
        }
        let target = match self.read(&journal.target, allocation(&journal.target) as usize) {
            Ok(bytes) => Some(bytes),
            Err(Refusal::Missing) => None,
            Err(e) => return Err(e),
        };
        // An initialization journal cannot turn a compacted or populated layout back into genesis.
        if journal.target == CHECKPOINT && journal.predecessor.is_none() && has_rows {
            return Err(Refusal::Held);
        }
        let hash = target.as_ref().map(|b| checksum(b).0);
        if !(journal.retire && target.is_none())
            && hash != journal.predecessor
            && hash.as_ref() != Some(&journal.checksum)
        {
            return Err(Refusal::Held);
        }
        if journal.retire {
            let cp: Checkpoint = unpack(
                &self.read(CHECKPOINT, CHECKPOINT_MAX_BYTES)?,
                CHECKPOINT_MAX_BYTES,
            )?;
            self.validate_checkpoint(&cp)?;
            if journal.checkpoint_checksum
                != Some(checksum(&self.read(CHECKPOINT, CHECKPOINT_MAX_BYTES)?).0)
                || Some(journal.target.clone())
                    != cp.anchor["committed_sequence"]
                        .as_u64()
                        .and_then(|n| n.checked_add(1))
                        .map(row_name)
            {
                return Err(Refusal::Held);
            }
            let observation = observation.ok_or(Refusal::Held)?;
            if !Self::unreserved(&cp, observation) {
                return Err(Refusal::Held);
            }
            if let Some(bytes) = target {
                let row: Row = unpack(&bytes, ROW_MAX_BYTES)?;
                self.check_orphan(&cp, &row)?;
                self.remove_private(&journal.target)?;
            }
            return self.clear_journal();
        }
        let staged = match self.read(STAGING, allocation(&journal.target) as usize) {
            Ok(bytes) => Some(bytes),
            Err(Refusal::Missing) => None,
            Err(e) => return Err(e),
        };
        let exact = |bytes: &Vec<u8>| {
            bytes.len() as u64 == journal.length && checksum(bytes).0 == journal.checksum
        };
        let source = staged
            .as_ref()
            .filter(|b| exact(b))
            .or_else(|| target.as_ref().filter(|b| exact(b)))
            .cloned()
            .or_else(|| {
                if journal.target == CHECKPOINT && journal.predecessor.is_none() {
                    seed.and_then(|c| pack(c).ok()).filter(exact)
                } else {
                    None
                }
            })
            .ok_or(Refusal::Held)?;
        if journal.target == CHECKPOINT {
            if !journal.control {
                return Err(Refusal::Held);
            }
            let next: Checkpoint = unpack(&source, CHECKPOINT_MAX_BYTES)?;
            self.validate_checkpoint(&next)?;
            if hash.as_ref() != Some(&journal.checksum) && next.active.is_some() {
                // Unpublished intent activation grants no reservation authority; retain the old checkpoint for orphan retirement.
                if staged.is_some() {
                    self.remove_private(STAGING)?;
                }
                return self.clear_journal();
            }
        } else {
            let row: Row = unpack(&source, ROW_MAX_BYTES)?;
            self.validate_row(&row)?;
            if row_name(row.sequence) != journal.target || row.control != journal.control {
                return Err(Refusal::Held);
            }
        }
        if staged.as_ref().is_some_and(|b| !exact(b)) {
            let partial = staged.as_ref().ok_or(Refusal::Held)?;
            // Only a strict prefix of the owned complete source is a recoverable partial stage.
            if partial.len() >= source.len() || !source.starts_with(partial) {
                return Err(Refusal::Conflict);
            }
            self.remove_private(STAGING)?;
        }
        if !staged.as_ref().is_some_and(exact) {
            self.write_stage(&source)?;
        }
        // Complete owned stages are reverified and renamed, never truncated by a retry.
        open_at(&self.root, STAGING, libc::O_RDONLY)?
            .sync_all()
            .map_err(|_| Refusal::Io)?;
        let from = CString::new(STAGING).map_err(|_| Refusal::Root)?;
        let to = CString::new(journal.target.as_str()).map_err(|_| Refusal::Root)?;
        if unsafe {
            libc::renameat(
                self.root.as_raw_fd(),
                from.as_ptr(),
                self.root.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(Refusal::Io);
        }
        self.root.sync_all().map_err(|_| Refusal::Io)?;
        if self.read(&journal.target, source.len())? != source {
            return Err(Refusal::Conflict);
        }
        self.clear_journal()
    }
    fn unreserved(cp: &Checkpoint, evidence: &RecoveryRead<'_>) -> bool {
        // Disk/journal evidence cannot renew D authority; retirement uses the original authenticated READ lease.
        let fresh = (evidence.clock)()
            .ok()
            .and_then(|now| now.checked_sub(evidence.observation.observed()))
            .is_some_and(|age| {
                age < drain_protocol::D_LEASE_MS as u64 * super::writer_peer::NS_PER_MS
            });
        let d = evidence.observation.value();
        fresh
            && d["state"] == "PRESENT"
            && d["uncertain"] == false
            && d["latched"] == false
            && d["anchor"] == cp.anchor
            && cp.active.is_none()
            && cp.anchor["reserved_sequence"] == cp.anchor["committed_sequence"]
    }
    fn check_orphan(&self, cp: &Checkpoint, row: &Row) -> Result<()> {
        self.validate_row(row)?;
        if Some(row.sequence)
            != cp.anchor["committed_sequence"]
                .as_u64()
                .and_then(|n| n.checked_add(1))
            || row.storage_cursor != cp.next_cursor
            || cp.active.is_some()
            || row.sign_may_have_been_sent
            || row.envelope.is_some()
            || row.commit.is_some()
            || row.effect_status.is_some()
            || row.d_fact.is_some()
            || row.ts_fact.is_some()
        {
            return Err(Refusal::Held);
        }
        let reserve = FrozenMutation::checked(decode_bytes(
            &row.reserve,
            drain_protocol::D_REQUEST_MAX_BYTES,
        )?)
        .map_err(|_| Refusal::Shape)?;
        if reserve.expected() != &cp.anchor {
            return Err(Refusal::Held);
        }
        Ok(())
    }
    fn retire_orphan(
        &mut self,
        rows: &mut BTreeMap<u64, Row>,
        observation: Option<&RecoveryRead<'_>>,
    ) -> Result<()> {
        let committed = self.checkpoint.anchor["committed_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        if self.checkpoint.active.is_some() {
            return Ok(());
        }
        let Some(row) = rows
            .range(committed + 1..)
            .next()
            .map(|(_, row)| row.clone())
        else {
            return Ok(());
        };
        self.check_orphan(&self.checkpoint, &row)?;
        if !Self::unreserved(&self.checkpoint, observation.ok_or(Refusal::Held)?) {
            return Err(Refusal::Held);
        }
        let name = row_name(row.sequence);
        let pool = if row.control {
            Pool::Control
        } else {
            Pool::Ordinary
        };
        let bytes = self.read(&name, ROW_MAX_BYTES)?;
        // Fresh independent D evidence proves no reservation; neither journal nor local row may authorize adoption.
        self.write_journal(&name, &bytes, pool, true)?;
        self.remove_private(&name)?;
        self.clear_journal()?;
        self.usage[pool_index(pool)] -= ROW_MAX_BYTES as u64;
        self.entries -= 1;
        rows.remove(&row.sequence);
        Ok(())
    }
    fn publish(&mut self, name: String, bytes: Vec<u8>, pool: Pool) -> Result<()> {
        self.ready()?;
        self.capacity(allocation(&name), pool)?;
        let old_size = match open_at(&self.root, &name, libc::O_RDONLY) {
            Ok(f) => {
                private_file(&f, self.owner)?;
                allocation(&name)
            }
            Err(Refusal::Missing) => 0,
            Err(e) => return Err(e),
        };
        // Both the old target and the complete staging allocation are charged before any write.
        self.usage[pool_index(pool)] += allocation(&name);
        self.pending = Some(PendingPublication {
            name,
            bytes,
            old_size,
            pool,
        });
        self.state = WalState::PublicationHeld;
        let result = (|| {
            let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
            let (name, bytes, pool) = (pending.name.clone(), pending.bytes.clone(), pending.pool);
            self.write_journal(&name, &bytes, pool, false)?;
            self.hooks.before(WalStep::StageCreate)?;
            let mut stage = open_at(
                &self.root,
                STAGING,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            set_private_mode(&stage)?;
            private_file(&stage, self.owner)?;
            self.hooks.before(WalStep::Write)?;
            stage
                .write_all(&self.pending.as_ref().ok_or(Refusal::Held)?.bytes)
                .map_err(|_| Refusal::Io)?;
            self.hooks.before(WalStep::FileSync)?;
            stage.sync_all().map_err(|_| Refusal::Io)?;
            self.finish_publication()
        })();
        result
    }
    fn finish_publication(&mut self) -> Result<()> {
        let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
        let name = CString::new(pending.name.as_str()).map_err(|_| Refusal::Root)?;
        let stage = CString::new(STAGING).map_err(|_| Refusal::Root)?;
        self.hooks.before(WalStep::Rename)?;
        if unsafe {
            libc::renameat(
                self.root.as_raw_fd(),
                stage.as_ptr(),
                self.root.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(Refusal::Io);
        }
        self.hooks.before(WalStep::DirectorySync)?;
        self.root.sync_all().map_err(|_| Refusal::Io)?;
        self.hooks.before(WalStep::Readback)?;
        if self.read(&pending.name, pending.bytes.len())? != pending.bytes {
            return Err(Refusal::Conflict);
        }
        self.clear_journal()?;
        self.complete_publication()
    }
    /// Reconcile only the exact owned publication. No new request, cursor or permission is inferred.
    pub fn reconcile_publication(&mut self) -> Result<()> {
        let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
        if self.read(&pending.name, pending.bytes.len()).ok().as_ref() == Some(&pending.bytes)
            && matches!(
                open_at(&self.root, STAGING, libc::O_RDONLY),
                Err(Refusal::Missing)
            )
        {
            // Reissue the same owned bytes as a new publication. A later successful sync alone
            // does not establish durability of the earlier possibly published directory change.
            let bytes = pending.bytes.clone();
            let pool = pending.pool;
            // A renamed target plus one fixed staging file is the entire physical footprint.
            // Repeated reconciliation reuses this charge, including after another sync failure.
            if pending.old_size == 0 {
                self.capacity(allocation(&pending.name), pool)?;
                self.usage[pool_index(pool)] += allocation(&pending.name);
                let pending = self.pending.as_mut().ok_or(Refusal::Held)?;
                pending.old_size = allocation(&pending.name);
            }
            self.hooks.before(WalStep::StageCreate)?;
            let mut stage = open_at(
                &self.root,
                STAGING,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            set_private_mode(&stage)?;
            private_file(&stage, self.owner)?;
            self.hooks.before(WalStep::Write)?;
            stage.write_all(&bytes).map_err(|_| Refusal::Io)?;
        }
        let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
        let staged = self.read(STAGING, pending.bytes.len())?;
        if staged != pending.bytes {
            if staged.len() >= pending.bytes.len() || !pending.bytes.starts_with(&staged) {
                return Err(Refusal::Conflict);
            }
            let bytes = pending.bytes.clone();
            // The durable journal and retained exact source distinguish an owned partial write from foreign bytes.
            let journal: PublicationJournal =
                unpack(&self.read(JOURNAL, JOURNAL_MAX_BYTES)?, JOURNAL_MAX_BYTES)?;
            if journal.checksum != checksum(&bytes).0 {
                return Err(Refusal::Conflict);
            }
            self.remove_private(STAGING)?;
            self.write_stage(&bytes)?;
        }
        self.hooks.before(WalStep::FileSync)?;
        open_at(&self.root, STAGING, libc::O_RDONLY)?
            .sync_all()
            .map_err(|_| Refusal::Io)?;
        self.finish_publication()
    }
    fn complete_publication(&mut self) -> Result<()> {
        let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
        if pending.name == CHECKPOINT {
            let checkpoint: Checkpoint = unpack(&pending.bytes, CHECKPOINT_MAX_BYTES)?;
            self.validate_checkpoint(&checkpoint)?;
            self.checkpoint = checkpoint;
        }
        self.usage[pool_index(pending.pool)] = self.usage[pool_index(pending.pool)]
            .checked_sub(pending.old_size)
            .ok_or(Refusal::Capacity)?;
        self.pending = None;
        self.state = WalState::Ready;
        Ok(())
    }
    fn save_checkpoint(&mut self, c: Checkpoint) -> Result<()> {
        self.validate_checkpoint(&c)?;
        let bytes = pack(&c)?;
        if bytes.len() > CHECKPOINT_MAX_BYTES {
            return Err(Refusal::Capacity);
        }
        self.publish(CHECKPOINT.into(), bytes, Pool::Control)?;
        self.checkpoint = c;
        Ok(())
    }
    fn save_row(&mut self, row: &Row) -> Result<()> {
        self.validate_row(row)?;
        let bytes = pack(row)?;
        if bytes.len() > ROW_MAX_BYTES {
            return Err(Refusal::Capacity);
        }
        self.publish(
            row_name(row.sequence),
            bytes,
            if row.control {
                Pool::Control
            } else {
                Pool::Ordinary
            },
        )
    }
    pub fn freeze_body(
        &mut self,
        body: &[u8],
        reserve: &FrozenMutation,
        append_deadline: u64,
        grant_expiry: u64,
        pool: Pool,
    ) -> Result<BusinessSequence> {
        self.ready()?;
        if self.checkpoint.active.is_some() || self.entries >= BUSINESS_WAL_ENTRIES_MAX {
            return Err(Refusal::Held);
        }
        let b = records::decode(body).ok_or(Refusal::Shape)?;
        let sequence = b["sequence"].as_u64().ok_or(Refusal::Shape)?;
        // Admission checks the complete shared join against durable relying state before RESERVE or SIGN.
        // The shape-only placeholder is discarded and never treated as a signature or persisted commitment.
        let unsigned = writer_protocol::envelope(body, &[0; 64]).map_err(|_| Refusal::Shape)?;
        let unsigned = writer_protocol::decode_envelope(&unsigned).map_err(|_| Refusal::Shape)?;
        let join = records::decode_join_state(&self.committed_join()?).ok_or(Refusal::Shape)?;
        records::advance(&join, &unsigned).map_err(|_| Refusal::Authority)?;
        if reserve.expected() != &self.checkpoint.anchor
            || Some(sequence)
                != self.checkpoint.anchor["committed_sequence"]
                    .as_u64()
                    .and_then(|n| n.checked_add(1))
        {
            return Err(Refusal::Conflict);
        }
        let row = Row {
            version: 1,
            sequence,
            storage_cursor: self.checkpoint.next_cursor,
            control: pool == Pool::Control,
            body: URL_SAFE_NO_PAD.encode(body),
            body_digest: body_digest(body).0,
            reserve: URL_SAFE_NO_PAD.encode(reserve.bytes()),
            commit: None,
            append_deadline: append_deadline.to_string(),
            grant_expiry: grant_expiry.to_string(),
            sign_may_have_been_sent: false,
            envelope: None,
            d_fact: None,
            ts_fact: None,
            effect_status: None,
        };
        // An unpublished checkpoint cannot make an orphan intent available for replacement.
        if open_at(&self.root, &row_name(sequence), libc::O_RDONLY).is_ok() {
            return Err(Refusal::Held);
        }
        // The full intent footprint remains charged until release; no later SIGN completion
        // or fact publication can compete with a new admission for its staging space.
        self.capacity(
            ROW_MAX_BYTES as u64
                + match pool {
                    Pool::Ordinary => ROW_REWRITE_RESERVE,
                    Pool::Control => CONTROL_REWRITE_RESERVE,
                },
            pool,
        )?;
        self.capacity(CONTROL_REWRITE_RESERVE, Pool::Control)?;
        self.save_row(&row)?;
        self.entries += 1;
        let mut c = self.checkpoint.clone();
        c.active = Some(sequence);
        c.next_cursor = c.next_cursor.checked_add(1).ok_or(Refusal::Capacity)?;
        self.save_checkpoint(c)?;
        self.live_effect = Some(sequence);
        Ok(BusinessSequence(sequence))
    }
    fn active(&self) -> Result<Row> {
        self.ready()?;
        self.row(self.checkpoint.active.ok_or(Refusal::Missing)?)
    }
    pub fn persist_sign_marker(&mut self, observation: &DrainObservation, now: u64) -> Result<()> {
        let mut row = self.active()?;
        let proposal = FrozenMutation::checked(decode_bytes(
            &row.reserve,
            drain_protocol::D_REQUEST_MAX_BYTES,
        )?)
        .map_err(|_| Refusal::Shape)?;
        // Only the intent outstanding at open is restart-frozen; new live appends retain first-SIGN authority.
        if self.opened_active == Some(row.sequence) || row.sign_may_have_been_sent {
            return Err(Refusal::Held);
        }
        if now >= writer_protocol::canonical_deadline(&row.append_deadline).ok_or(Refusal::Shape)?
            || now
                >= writer_protocol::canonical_deadline(&row.grant_expiry).ok_or(Refusal::Shape)?
            || observation.observed() > now
        {
            return Err(Refusal::Deadline);
        }
        if !observation.confirms(&proposal) {
            return Err(Refusal::Authority);
        }
        row.sign_may_have_been_sent = true;
        self.save_row(&row)
    }
    pub fn freeze_envelope(&mut self, envelope: &[u8]) -> Result<()> {
        let mut row = self.active()?;
        if let Some(first) = &row.envelope {
            return if decode_bytes(first, writer_protocol::WRITER_ENVELOPE_MAX_BYTES)? == envelope {
                Ok(())
            } else {
                Err(Refusal::Conflict)
            };
        }
        let record = writer_protocol::decode_envelope(envelope).map_err(|_| Refusal::Shape)?;
        let join = records::decode_join_state(&self.committed_join()?).ok_or(Refusal::Shape)?;
        let mut pin = join["pin"].clone();
        for key in ["activation_id", "lease_id", "generation"] {
            pin[key] = join["grant"][key].clone();
        }
        let signature = URL_SAFE_NO_PAD
            .decode(
                record["outer"]["signature"]
                    .as_str()
                    .ok_or(Refusal::Shape)?,
            )
            .map_err(|_| Refusal::Shape)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(pin["public_key"].as_str().ok_or(Refusal::Shape)?)
            .map_err(|_| Refusal::Shape)?;
        if !records::verify(&canonical(&record["body"])?, &signature, &pin, &public_key) {
            return Err(Refusal::Authority);
        }
        if !row.sign_may_have_been_sent {
            return Err(Refusal::Held);
        }
        row.envelope = Some(URL_SAFE_NO_PAD.encode(envelope));
        self.save_row(&row)
    }
    pub fn freeze_commit(&mut self, proposal: &FrozenMutation) -> Result<()> {
        let mut row = self.active()?;
        let encoded = URL_SAFE_NO_PAD.encode(proposal.bytes());
        if row.commit.as_ref().is_some_and(|old| old != &encoded) {
            return Err(Refusal::Conflict);
        }
        row.commit = Some(encoded);
        self.save_row(&row)
    }
    pub fn confirm_commit(&mut self, observation: &DrainObservation) -> Result<()> {
        let row = self.active()?;
        let proposal = FrozenMutation::checked(decode_bytes(
            row.commit.as_ref().ok_or(Refusal::Missing)?,
            drain_protocol::D_REQUEST_MAX_BYTES,
        )?)
        .map_err(|_| Refusal::Shape)?;
        if !observation.confirms(&proposal) {
            return Err(Refusal::Authority);
        }
        let bytes = decode_bytes(
            row.envelope.as_ref().ok_or(Refusal::Missing)?,
            writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
        )?;
        let record = writer_protocol::decode_envelope(&bytes).map_err(|_| Refusal::Shape)?;
        let join = records::decode_join_state(&self.committed_join()?).ok_or(Refusal::Shape)?;
        let next = records::advance(&join, &record).map_err(|_| Refusal::Conflict)?;
        let mut c = self.checkpoint.clone();
        c.anchor = proposal.next().clone();
        c.join_state = URL_SAFE_NO_PAD.encode(canonical(&next)?);
        c.active = None;
        self.save_checkpoint(c)
    }
    /// Between appends, a correlated READ may advance only the drained tuple proved by durable ORIGINAL_ACK facts.
    pub fn refresh_drained(&mut self, observation: &DrainObservation) -> Result<()> {
        self.ready()?;
        if self.checkpoint.active.is_some() {
            return Err(Refusal::Held);
        }
        let value = observation.value();
        if value["state"] != "PRESENT" || value["latched"] != false || value["uncertain"] != false {
            return Err(Refusal::Authority);
        }
        let mut expected = self.checkpoint.anchor.clone();
        if let Some(identity) = &self.checkpoint.originals {
            expected["drained_sequence"] = json!(identity.sequence);
            expected["drained_digest"] = json!(identity.commitment);
        }
        if value["anchor"] != expected {
            return Err(Refusal::Conflict);
        }
        let mut checkpoint = self.checkpoint.clone();
        checkpoint.anchor = expected;
        self.save_checkpoint(checkpoint)
    }
    /// Only the current live append can consume its durable unknown marker completion.
    pub(crate) fn mark_effect_unknown(
        &mut self,
        sequence: BusinessSequence,
    ) -> Result<super::effect_permit::MarkerCompletion> {
        self.ready()?;
        let mut row = self.row(sequence.0)?;
        if self.live_effect != Some(sequence.0)
            || row.effect_status.is_some()
            || self.checkpoint.anchor["committed_sequence"] != sequence.0
            || self.checkpoint.active.is_some()
        {
            return Err(Refusal::Held);
        }
        let envelope = decode_bytes(
            row.envelope.as_ref().ok_or(Refusal::Missing)?,
            writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
        )?;
        let identity = Identity::from_envelope(&envelope)?;
        // Persist/read back the existing current-format unknown marker before releasing the live-only completion.
        row.effect_status = Some("unknown".into());
        self.live_effect = None;
        self.save_row(&row)?;
        Ok(super::effect_permit::MarkerCompletion::from_wal(
            sequence.0,
            identity.commitment,
            identity.envelope_sha256,
        ))
    }
    pub fn next_delivery(&self) -> Result<Option<(BusinessSequence, DeliveryToken)>> {
        self.ready()?;
        let next = self
            .checkpoint
            .delivered
            .as_ref()
            .map_or(0, |i| i.sequence)
            .checked_add(1)
            .ok_or(Refusal::Capacity)?;
        if next
            > self.checkpoint.anchor["committed_sequence"]
                .as_u64()
                .ok_or(Refusal::Shape)?
        {
            return Ok(None);
        }
        let row = self.row(next)?;
        Ok(Some((
            BusinessSequence(next),
            DeliveryToken {
                envelope: decode_bytes(
                    row.envelope.as_ref().ok_or(Refusal::Missing)?,
                    writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
                )?,
            },
        )))
    }
    pub fn persist_ts_fact(
        &mut self,
        sequence: BusinessSequence,
        fact: impl std::borrow::Borrow<TsReleaseFact>,
    ) -> Result<()> {
        let fact = fact.borrow();
        self.ready()?;
        let mut row = self.row(sequence.0)?;
        let expected = self
            .checkpoint
            .delivered
            .as_ref()
            .map_or(0, |i| i.sequence)
            .checked_add(1)
            .ok_or(Refusal::Capacity)?;
        if sequence.0 != expected
            || sequence.0
                > self.checkpoint.anchor["committed_sequence"]
                    .as_u64()
                    .ok_or(Refusal::Shape)?
        {
            return Err(Refusal::Conflict);
        }
        row.ts_fact = Some(fact.identity.clone());
        self.save_row(&row)?;
        // Must match BusinessDeliveryAck's W barrier: n+1 is unavailable until both fact and cursor read back.
        let mut c = self.checkpoint.clone();
        c.delivered = Some(fact.identity.clone());
        self.save_checkpoint(c)
    }
    pub fn persist_d_fact(
        &mut self,
        sequence: BusinessSequence,
        fact: DrainReleaseFact,
    ) -> Result<()> {
        self.ready()?;
        let mut row = self.row(sequence.0)?;
        let expected = self
            .checkpoint
            .originals
            .as_ref()
            .map_or(0, |i| i.sequence)
            .checked_add(1)
            .ok_or(Refusal::Capacity)?;
        if sequence.0 != expected
            || sequence.0
                > self.checkpoint.anchor["committed_sequence"]
                    .as_u64()
                    .ok_or(Refusal::Shape)?
        {
            return Err(Refusal::Conflict);
        }
        let identity =
            serde_json::from_value(fact.identity().clone()).map_err(|_| Refusal::Shape)?;
        row.d_fact = Some(identity);
        self.save_row(&row)?;
        let mut c = self.checkpoint.clone();
        c.originals = row.d_fact;
        self.save_checkpoint(c)
    }
    pub fn compact_one(&mut self) -> Result<bool> {
        self.ready()?;
        let sequence = self
            .checkpoint
            .released
            .as_ref()
            .map_or(0, |i| i.sequence)
            .checked_add(1)
            .ok_or(Refusal::Capacity)?;
        if sequence
            > self.checkpoint.anchor["committed_sequence"]
                .as_u64()
                .ok_or(Refusal::Shape)?
        {
            return Ok(false);
        }
        let row = self.row(sequence)?;
        // On reachable paths the cursor-order checks dominate a missing fact; keep both barriers.
        // Paired with `released > delivered || released > originals` in BusinessWal::validate_checkpoint in business_wal.rs.
        let (Some(d), Some(ts)) = (&row.d_fact, &row.ts_fact) else {
            return Ok(false);
        };
        if d != ts || self.checkpoint.active == Some(sequence) {
            return Err(Refusal::Conflict);
        }
        let mut c = self.checkpoint.clone();
        c.released = Some(d.clone());
        self.save_checkpoint(c)?;
        self.delete_released(&row)?;
        Ok(true)
    }
    fn delete_released(&mut self, row: &Row) -> Result<()> {
        let name = row_name(row.sequence);
        self.read(&name, ROW_MAX_BYTES)?;
        let bytes = ROW_MAX_BYTES as u64;
        // Any ambiguous deletion retains charges and closes this executor until a locked restart reconciles the directory.
        self.state = WalState::PublicationHeld;
        self.hooks.before(WalStep::Delete)?;
        let name = CString::new(name).map_err(|_| Refusal::Root)?;
        if unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(Refusal::Io);
        }
        self.hooks.before(WalStep::DirectorySync)?;
        self.root.sync_all().map_err(|_| Refusal::Io)?;
        self.usage[usize::from(row.control)] = self.usage[usize::from(row.control)]
            .checked_sub(bytes)
            .ok_or(Refusal::Capacity)?;
        self.entries -= 1;
        self.state = WalState::Ready;
        Ok(())
    }
    pub fn storage_cursor(&self, sequence: BusinessSequence) -> Result<StorageCursor> {
        Ok(StorageCursor(self.row(sequence.0)?.storage_cursor))
    }
    /// Settlement reads the durable active-intent bit on the owned worker before selecting a reconnect continuation.
    pub(crate) fn settlement_active(&self) -> Result<bool> {
        self.ready()?;
        let durable: Checkpoint = unpack(
            &self.read(CHECKPOINT, CHECKPOINT_MAX_BYTES)?,
            CHECKPOINT_MAX_BYTES,
        )?;
        // Local confirmation is proved by exact durable checkpoint bytes, never inferred from a D ACK.
        if canonical(&durable)? != canonical(&self.checkpoint)? {
            return Err(Refusal::Held);
        }
        Ok(durable.active.is_some())
    }
    /// Reconcile a fresh authenticated producer view with loaded exact bytes without granting a new effect.
    pub fn recovery_action(
        &mut self,
        observation: &DrainObservation,
        clock: &super::writer_peer::Clock,
    ) -> Result<RecoveryAction> {
        self.ready()?;
        let now = clock().map_err(|_| Refusal::Deadline)?;
        if now < observation.observed()
            || now - observation.observed()
                >= drain_protocol::D_LEASE_MS as u64 * super::writer_peer::NS_PER_MS
        {
            return Err(Refusal::Deadline);
        }
        let value = observation.value();
        if value["state"] != "PRESENT" || value["uncertain"] != false {
            return Err(Refusal::Authority);
        }
        if self.checkpoint.active.is_some() {
            let row = self.active()?;
            // Outstanding-at-open bodies never acquire first-SIGN authority. Missing exact E remains held for recovery.
            let envelope = decode_bytes(
                row.envelope.as_ref().ok_or(Refusal::Held)?,
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            )?;
            if row.commit.is_none() {
                let reserve = FrozenMutation::checked(decode_bytes(
                    &row.reserve,
                    drain_protocol::D_REQUEST_MAX_BYTES,
                )?)
                .map_err(|_| Refusal::Shape)?;
                if !observation.confirms(&reserve) {
                    return Err(Refusal::Held);
                }
                let identity = Identity::from_envelope(&envelope)?;
                let mut next = reserve.next().clone();
                next["committed_sequence"] = json!(identity.sequence);
                next["committed_digest"] = json!(identity.commitment);
                next["reserved_body_digest"] = Value::Null;
                let body = decode_bytes(&row.body, records_schema::MAX_BYTES)?;
                let mut hash = Sha256::new();
                hash.update(b"sanctuary-business-commit-v1");
                hash.update(&envelope);
                // A first COMMIT is frozen durably before send; retries thereafter use these exact stored bytes.
                let id = hex::encode(&hash.finalize()[..16]);
                let proposal = super::append_actor::mutation(
                    &id,
                    "COMMIT",
                    reserve.next(),
                    &next,
                    &body,
                    &envelope,
                )?;
                self.freeze_commit(&proposal)?;
                return Ok(RecoveryAction::Observe);
            }
            let commit = FrozenMutation::checked(decode_bytes(
                row.commit.as_ref().ok_or(Refusal::Held)?,
                drain_protocol::D_REQUEST_MAX_BYTES,
            )?)
            .map_err(|_| Refusal::Shape)?;
            let reserve = FrozenMutation::checked(decode_bytes(
                &row.reserve,
                drain_protocol::D_REQUEST_MAX_BYTES,
            )?)
            .map_err(|_| Refusal::Shape)?;
            let body = decode_bytes(&row.body, records_schema::MAX_BYTES)?;
            if let Some(report) = CommitHold::changed_predecessor(
                observation,
                &reserve,
                &commit,
                &body,
                "startup READ",
            ) {
                // Loaded requests remain exact; a changed predecessor cannot license a drain or a replacement CAS.
                return Ok(RecoveryAction::Held(report));
            }
            if value["latched"] != false {
                return Err(Refusal::Held);
            }
            if !row.sign_may_have_been_sent || envelope.is_empty() {
                return Err(Refusal::Held);
            }
            if observation.confirms(&commit) {
                self.confirm_commit(observation)?;
                return Ok(RecoveryAction::Observe);
            }
            if &value["anchor"] == commit.expected() {
                return Ok(RecoveryAction::Retry(commit));
            }
            return Err(Refusal::Held);
        }
        if value["latched"] != false {
            return Err(Refusal::Held);
        }
        // Only this no-active-intent branch may produce ORIGINAL; draining a frozen COMMIT would stale its predecessor, with no proved renewal.
        let next = self
            .checkpoint
            .originals
            .as_ref()
            .map_or(0, |i| i.sequence)
            .checked_add(1)
            .ok_or(Refusal::Capacity)?;
        let committed = self.checkpoint.anchor["committed_sequence"]
            .as_u64()
            .ok_or(Refusal::Shape)?;
        if next <= committed {
            let row = self.row(next)?;
            let envelope = decode_bytes(
                row.envelope.as_ref().ok_or(Refusal::Held)?,
                writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            )?;
            let identity = Identity::from_envelope(&envelope)?;
            let mut accepted = self.checkpoint.anchor.clone();
            accepted["drained_sequence"] = json!(next);
            accepted["drained_digest"] = json!(identity.commitment);
            // Lost ORIGINAL_ACK permits only exact replay at the immediate head, never a later-cursor release inference.
            if value["anchor"] != self.checkpoint.anchor && value["anchor"] != accepted {
                return Err(Refusal::Held);
            }
            return Ok(RecoveryAction::Original {
                sequence: BusinessSequence(next),
                envelope,
            });
        }
        // A drain under a frozen COMMIT would stale its predecessor, and no proved renewal exists.
        self.refresh_drained(observation)?;
        Ok(RecoveryAction::Ready)
    }
    pub fn active_body_digest(&self) -> Result<BodyDigest> {
        Ok(BodyDigest(self.active()?.body_digest))
    }
    pub fn retained_commitment(&self, sequence: BusinessSequence) -> Result<JoinCommitment> {
        let r = self.row(sequence.0)?;
        let e = decode_bytes(
            r.envelope.as_ref().ok_or(Refusal::Missing)?,
            writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
        )?;
        Ok(JoinCommitment(Identity::from_envelope(&e)?.commitment))
    }
}

#[cfg(feature = "test-isolation")]
pub mod test_support {
    use super::*;
    /// Exercise the same live marker completion without constructing one from test data.
    pub fn mark_effect(
        wal: &mut BusinessWal,
        sequence: BusinessSequence,
    ) -> Result<super::super::effect_permit::MarkerCompletion> {
        wal.mark_effect_unknown(sequence)
    }
    /// Return the reviewed metadata reservation for independent pool accounting assertions.
    pub fn journal_reserve() -> u64 {
        JOURNAL_RESERVE
    }

    /// Reopen with isolated occupancy representing other retained rows in the same pools.
    pub fn reopen_accounted(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        occupied: [u64; 2],
    ) -> Result<BusinessWal> {
        // The injected total already includes fixed journal reservation; avoid charging it twice on reopen.
        BusinessWal::open_accounted(
            path,
            owner,
            hooks,
            None,
            [
                occupied[0].saturating_sub(JOURNAL_RESERVE),
                occupied[1].saturating_sub(JOURNAL_RESERVE),
            ],
            None,
        )
    }
    /// Combine bounded occupancy with the same authenticated orphan-retirement authority used at startup.
    pub fn reopen_recovering_accounted(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        occupied: [u64; 2],
        observation: &DrainObservation,
        clock: &super::super::writer_peer::Clock,
    ) -> Result<BusinessWal> {
        BusinessWal::open_accounted(
            path,
            owner,
            hooks,
            None,
            occupied.map(|bytes| bytes.saturating_sub(JOURNAL_RESERVE)),
            Some(&RecoveryRead { observation, clock }),
        )
    }
    /// Isolated accounting boundary stimulus; it cannot select an installed root.
    pub fn accounting(wal: &mut BusinessWal, ordinary: u64, control: u64, entries: usize) {
        wal.usage = [ordinary, control];
        wal.entries = entries;
    }
}
