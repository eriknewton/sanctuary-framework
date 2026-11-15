//! Exact business envelopes in an isolated held store. Installed root selection remains disabled.
use super::{
    activation_anchor as anchor,
    append_clients::{DrainObservation, DrainReleaseFact, FrozenMutation},
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
mod sink_seal {
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
    pub fn deliver(&mut self, envelope: &DeliveryToken) -> Result<TsReleaseFact> {
        // The token proves that W's previous delivery fact and cursor were read back.
        let envelope = envelope.envelope();
        let identity = Identity::from_envelope(envelope)?;
        if self.pending.as_ref().is_some_and(|b| b != envelope) {
            return Err(Refusal::Held);
        }
        self.pending = Some(envelope.to_vec());
        let ack = self.sink.accept_durably(envelope)?;
        if !append_contract::shape("ack", &ack) || ack["identity"] != identity.value()? {
            return Err(Refusal::Conflict);
        }
        self.pending = None;
        Ok(TsReleaseFact { identity })
    }
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
fn open_at(root: &File, leaf: &str, flags: i32) -> Result<File> {
    let leaf = CString::new(leaf).map_err(|_| Refusal::Root)?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            leaf.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
impl BusinessWal {
    pub fn open_isolated(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
    ) -> Result<Self> {
        Self::open_accounted(path, owner, hooks, seed, [0, 0])
    }
    fn open_accounted(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
        occupied: [u64; 2],
    ) -> Result<Self> {
        let root = held_root(path, owner)?;
        // Lock acquisition precedes enumeration, staging inspection and checkpoint reads. The inode is never unlinked.
        let (lock, created) =
            match open_at(&root, LOCK, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL) {
                Ok(file) => (file, true),
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
            usage: occupied,
            entries: 0,
            opened_active: None,
            state: WalState::Ready,
            pending: None,
        };
        let mut rows = BTreeMap::new();
        // The cap counts stored rows; lock, checkpoint and one staging file are the only fixed entries.
        let directory = std::fs::read_dir(format!("/proc/self/fd/{}", store.root.as_raw_fd()))
            .map_err(|_| Refusal::Root)?;
        for (index, entry) in directory.enumerate() {
            if index >= BUSINESS_WAL_ENTRIES_MAX + 3 {
                return Err(Refusal::Capacity);
            }
            let name = entry
                .map_err(|_| Refusal::Io)?
                .file_name()
                .into_string()
                .map_err(|_| Refusal::Shape)?;
            match name.as_str() {
                LOCK => {}
                STAGING => return Err(Refusal::Held),
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
            if store.entries != 0 || store.usage != [0, 0] {
                return Err(Refusal::Conflict);
            }
            let initial = initial.ok_or(Refusal::Missing)?;
            store.validate_checkpoint(&initial)?;
            store.save_checkpoint(initial)?;
        } else {
            if store.usage[1] == 0 {
                return Err(Refusal::Missing);
            }
            store.validate_checkpoint(&store.checkpoint)?;
        }
        store.capacity(0, Pool::Ordinary)?;
        store.capacity(0, Pool::Control)?;
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
        } else if r.commit.is_some() || r.d_fact.is_some() || r.ts_fact.is_some() {
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
            self.hooks.before(WalStep::StageCreate)?;
            let mut stage = open_at(
                &self.root,
                STAGING,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
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
            private_file(&stage, self.owner)?;
            self.hooks.before(WalStep::Write)?;
            stage.write_all(&bytes).map_err(|_| Refusal::Io)?;
        }
        let pending = self.pending.as_ref().ok_or(Refusal::Held)?;
        if self.read(STAGING, pending.bytes.len())? != pending.bytes {
            return Err(Refusal::Conflict);
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
        fact: TsReleaseFact,
    ) -> Result<()> {
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
        c.delivered = Some(fact.identity);
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
    /// Reopen with isolated occupancy representing other retained rows in the same pools.
    pub fn reopen_accounted(
        path: &Path,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        occupied: [u64; 2],
    ) -> Result<BusinessWal> {
        BusinessWal::open_accounted(path, owner, hooks, None, occupied)
    }
    /// Isolated accounting boundary stimulus; it cannot select an installed root.
    pub fn accounting(wal: &mut BusinessWal, ordinary: u64, control: u64, entries: usize) {
        wal.usage = [ordinary, control];
        wal.entries = entries;
    }
}
