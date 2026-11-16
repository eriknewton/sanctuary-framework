//! W owns each exchange through completion or explicit closure. Peer pins come from enrollment.
use super::{
    activation_anchor, append_checkpoint as cp, append_contract, drain_protocol as d,
    drain_store::{self, Phase},
    frame,
    signer_peer::{self, Peer, PeerPolicy},
    writer_peer::{Clock, NS_PER_MS},
    writer_protocol as p,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Root,
    Peer,
    Transport,
    Busy,
    Deadline,
    Correlation,
    Protocol,
    Authority,
    Held,
}
pub type Result<T> = std::result::Result<T, Refusal>;
/// Both independent server policies are required by both clients; wire observations cannot enroll peers.
pub struct ServerPins {
    pub writer: PeerPolicy,
    pub drain: PeerPolicy,
}
pub trait ClientHooks: Send {
    fn before_send(&mut self) -> Result<()>;
    fn closed(&mut self);
}
pub struct HeldSocketRoot {
    directory: File,
    owner: u32,
}
impl HeldSocketRoot {
    pub fn checked(directory: File, owner: u32) -> Result<Self> {
        let m = directory.metadata().map_err(|_| Refusal::Root)?;
        if !m.is_dir() || m.uid() != owner || m.mode() & 0o022 != 0 {
            return Err(Refusal::Root);
        }
        Ok(Self { directory, owner })
    }
    fn connect(
        &self,
        leaf: &str,
        policy: &PeerPolicy,
    ) -> Result<(OwnedFd, Peer, File, File, String)> {
        if leaf.is_empty() || leaf.contains('/') || leaf == "." || leaf == ".." {
            return Err(Refusal::Root);
        }
        let name_text = leaf.to_owned();
        let path = format!("/proc/self/fd/{}/{}", self.directory.as_raw_fd(), leaf);
        let name = std::ffi::CString::new(leaf).map_err(|_| Refusal::Root)?;
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(Refusal::Root);
        }
        let leaf = unsafe { File::from_raw_fd(raw) };
        let before = leaf.metadata().map_err(|_| Refusal::Root)?;
        if before.mode() & libc::S_IFMT != libc::S_IFSOCK
            || before.uid() != self.owner
            || before.mode() & 0o002 != 0
        {
            return Err(Refusal::Root);
        }
        let socket = signer_peer::connect(Path::new(&path)).map_err(|_| Refusal::Transport)?;
        signer_peer::passcred(socket.as_raw_fd()).map_err(|_| Refusal::Transport)?;
        let peer = Peer::capture(socket.as_raw_fd(), policy).map_err(|_| Refusal::Peer)?;
        let after = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Root)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Refusal::Root);
        }
        Ok((
            socket,
            peer,
            leaf,
            self.directory.try_clone().map_err(|_| Refusal::Root)?,
            name_text,
        ))
    }
}
#[cfg(feature = "test-isolation")]
#[derive(Clone, Copy)]
pub(super) enum TransportObservation {
    Process,
    Device,
    Inode,
    Liveness,
}
#[cfg(feature = "test-isolation")]
pub(super) fn record_observed_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Bounded protocol bytes are captured once at the actual send boundary, before peer refusal can mask them.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(super::custody::PRIVATE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .write_all(bytes)
}
/// Sealed isolated settlement observations preserve the real authenticated socket exchange.
#[cfg(feature = "test-isolation")]
pub struct SettlementFixture {
    kind: SettlementKind,
    observed: std::path::PathBuf,
    audit: File,
}
#[cfg(feature = "test-isolation")]
#[derive(serde::Deserialize)]
enum SettlementKind {
    Observe,
    DrainedOnly,
    Authority,
}
#[cfg(feature = "test-isolation")]
impl SettlementFixture {
    /// Load one bounded private selector and exclusively create its bounded send audit.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let bytes = super::custody::read_pinned(
            path,
            unsafe { libc::geteuid() },
            super::custody::CONFIG_MAX_BYTES,
            super::custody::PRIVATE_MODE,
        )?;
        let kind = serde_json::from_slice(&bytes).map_err(|_| super::custody::refused())?;
        let audit = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(super::custody::PRIVATE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.with_extension("sends"))?;
        Ok(Self {
            kind,
            observed: path.with_extension("observed"),
            audit,
        })
    }
    fn observe(&self, observation: &mut DrainObservation) -> Result<()> {
        let Some(anchor) = observation.anchor.as_mut() else {
            return Ok(());
        };
        if anchor["reserved_body_digest"].is_string()
            && !matches!(self.kind, SettlementKind::Observe)
        {
            match self.kind {
                SettlementKind::DrainedOnly => {
                    anchor["drained_digest"] = json!(format!("sha256:{}", "a".repeat(64)))
                }
                SettlementKind::Authority => {
                    anchor["recovery_required"] = json!(true);
                    observation.latched = true;
                }
                SettlementKind::Observe => {}
            }
            if !self.observed.exists() {
                record_observed_bytes(&self.observed, b"decoded authenticated READ")
                    .map_err(|_| Refusal::Transport)?;
            }
        }
        Ok(())
    }
}
struct Connection {
    socket: Option<OwnedFd>,
    peer: Peer,
    clock: Clock,
    hooks: Box<dyn ClientHooks>,
    held_socket: File,
    held_directory: File,
    leaf: String,
    policy: PeerPolicy,
    #[cfg(feature = "test-isolation")]
    observation: std::cell::Cell<Option<TransportObservation>>,
    #[cfg(feature = "test-isolation")]
    send_observer: Option<std::path::PathBuf>,
    #[cfg(feature = "test-isolation")]
    settlement_audit: Option<File>,
}
impl Connection {
    fn new(
        root: &HeldSocketRoot,
        leaf: &str,
        policy: &PeerPolicy,
        clock: Clock,
        hooks: Box<dyn ClientHooks>,
    ) -> Result<Self> {
        let (socket, peer, held_socket, held_directory, leaf) = root.connect(leaf, policy)?;
        Ok(Self {
            socket: Some(socket),
            peer,
            clock,
            hooks,
            held_socket,
            held_directory,
            leaf,
            policy: policy.clone(),
            #[cfg(feature = "test-isolation")]
            observation: std::cell::Cell::new(None),
            #[cfg(feature = "test-isolation")]
            send_observer: None,
            #[cfg(feature = "test-isolation")]
            settlement_audit: None,
        })
    }
    fn reconnect(&mut self) -> Result<()> {
        self.close();
        let root = HeldSocketRoot::checked(
            self.held_directory.try_clone().map_err(|_| Refusal::Root)?,
            self.held_directory
                .metadata()
                .map_err(|_| Refusal::Root)?
                .uid(),
        )?;
        let (socket, peer, held_socket, _, _) = root.connect(&self.leaf, &self.policy)?;
        let original = self.held_socket.metadata().map_err(|_| Refusal::Root)?;
        let current = held_socket.metadata().map_err(|_| Refusal::Root)?;
        // Reconnect authenticates the same pinned endpoint; replacing its held inode requires a new composition.
        if original.dev() != current.dev() || original.ino() != current.ino() {
            return Err(Refusal::Root);
        }
        self.socket = Some(socket);
        self.peer = peer;
        Ok(())
    }
    fn recheck(&self) -> Result<()> {
        // Kernel process liveness and the held socket inode independently bind every post-wait use.
        #[cfg(feature = "test-isolation")]
        let observation = self.observation.take();
        let process_live = self.peer.live();
        #[cfg(feature = "test-isolation")]
        let process_live =
            process_live && !matches!(observation, Some(TransportObservation::Process));
        if !process_live {
            return Err(Refusal::Peer);
        }
        let before = self.held_socket.metadata().map_err(|_| Refusal::Root)?;
        let after = std::fs::symlink_metadata(format!(
            "/proc/self/fd/{}/{}",
            self.held_directory.as_raw_fd(),
            self.leaf
        ))
        .map_err(|_| Refusal::Root)?;
        let (device, inode) = (after.dev(), after.ino());
        #[cfg(feature = "test-isolation")]
        let (device, inode) = (
            device ^ u64::from(matches!(observation, Some(TransportObservation::Device))),
            inode ^ u64::from(matches!(observation, Some(TransportObservation::Inode))),
        );
        if before.dev() != device || before.ino() != inode {
            return Err(Refusal::Root);
        }
        let mut readiness = libc::pollfd {
            fd: self.fd()?,
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut readiness, 1, 0) };
        #[cfg(feature = "test-isolation")]
        if matches!(observation, Some(TransportObservation::Liveness)) {
            readiness.revents |= libc::POLLHUP;
        }
        if polled < 0 || readiness.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Refusal::Transport);
        }
        Ok(())
    }
    fn now(&self) -> Result<u64> {
        (self.clock)().map_err(|_| Refusal::Deadline)
    }
    fn fd(&self) -> Result<RawFd> {
        self.socket
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or(Refusal::Held)
    }
    fn close(&mut self) {
        if self.socket.take().is_some() {
            self.hooks.closed();
        }
    }
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        #[cfg(feature = "test-isolation")]
        if let Some(audit) = &mut self.settlement_audit {
            use std::io::Write;
            // The isolated audit has a fixed one-megabyte ceiling and records only bounded request identities.
            const AUDIT_MAX: u64 = 1024 * 1024;
            if audit.metadata().map_err(|_| Refusal::Transport)?.len() >= AUDIT_MAX {
                return Err(Refusal::Transport);
            }
            let frame = d::decode(bytes, d::Direction::ToDrain).map_err(|_| Refusal::Protocol)?;
            let operation = match frame.operation {
                d::Operation::Anchor { ref message, .. } => {
                    message["op"].as_str().ok_or(Refusal::Protocol)?
                }
                d::Operation::Read => "READ",
                d::Operation::Original { .. } => "ORIGINAL",
                _ => "other",
            };
            writeln!(audit, "{}", json!({"op":operation,"id":frame.request_id,"sha256":hex::encode(Sha256::digest(bytes))})).map_err(|_| Refusal::Transport)?;
        }
        self.hooks.before_send()?;
        #[cfg(feature = "test-isolation")]
        if let Some(path) = self.send_observer.take() {
            record_observed_bytes(&path, bytes).map_err(|_| Refusal::Transport)?;
        }
        if !self.peer.live() {
            return Err(Refusal::Peer);
        }
        signer_peer::send(self.fd()?, bytes, &[]).map_err(|_| Refusal::Transport)
    }
    fn poll(&self, end: u64, cap: usize) -> Result<Option<signer_peer::Packet>> {
        if self.now()? >= end {
            return Err(Refusal::Deadline);
        }
        if !self.peer.live() {
            return Err(Refusal::Peer);
        }
        let fd = self.fd()?;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready < 0 {
            return Err(Refusal::Transport);
        }
        if ready == 0 {
            return Ok(None);
        }
        let packet = signer_peer::receive(fd, cap).map_err(|_| Refusal::Transport)?;
        if !packet.rights.is_empty() || !self.peer.matches(&packet) {
            return Err(Refusal::Peer);
        }
        if self.now()? >= end {
            return Err(Refusal::Deadline);
        }
        Ok(Some(packet))
    }
    fn idle(&self) -> Result<()> {
        let mut p = libc::pollfd {
            fd: self.fd()?,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, 0) } != 0 {
            return Err(Refusal::Correlation);
        }
        Ok(())
    }
    fn completed(&self, end: u64) -> Result<()> {
        if self.now()? >= end {
            return Err(Refusal::Deadline);
        }
        self.idle()
    }
    fn deadline(&self, limit: u64, ms: u64) -> Result<u64> {
        let now = self.now()?;
        let end = now
            .checked_add(ms * NS_PER_MS)
            .ok_or(Refusal::Deadline)?
            .min(limit);
        if end <= now {
            return Err(Refusal::Deadline);
        }
        Ok(end)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}
/// Only a correlated authenticated READ_REPLY constructs this observation.
pub struct DrainObservation {
    anchor: Option<Value>,
    latched: bool,
    uncertain: bool,
    observed: u64,
}
impl DrainObservation {
    pub fn value(&self) -> Value {
        json!({"state":if self.anchor.is_some(){"PRESENT"}else{"ABSENT"},
        "anchor":self.anchor,"anchor_digest":self.anchor.as_ref().and_then(activation_anchor::anchor_digest),
        "latched":self.latched,"uncertain":self.uncertain})
    }
    pub fn observed(&self) -> u64 {
        self.observed
    }
    pub fn pending(&self) -> Option<u64> {
        let a = self.anchor.as_ref()?;
        a["committed_sequence"]
            .as_u64()?
            .checked_sub(a["drained_sequence"].as_u64()?)
    }
    pub fn confirms(&self, proposal: &FrozenMutation) -> bool {
        !self.latched && !self.uncertain && self.anchor.as_ref() == Some(&proposal.next)
    }
    pub fn ordinary_room(&self) -> bool {
        // Must match drain_service::process RECORD_COMMIT: count committed minus drained before COMMIT; RESERVE adds no pending head.
        // Changing either side's reservation accounting reopens the no-renewal proof.
        !self.latched
            && !self.uncertain
            && self
                .pending()
                .is_some_and(|n| n < drain_store::D_UNDRAINED_MAX as u64)
    }
}
/// A bounded diagnostic identifies retained settlement evidence without exposing B or E.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitHold {
    pub sequence: u64,
    pub reserve_sha256: String,
    pub commit_sha256: String,
    pub reason: &'static str,
    pub stage: &'static str,
}
impl CommitHold {
    /// A fresh authenticated observation classifies a changed predecessor only while B's reservation remains.
    pub(crate) fn changed_predecessor(
        observation: &DrainObservation,
        reserve: &FrozenMutation,
        commit: &FrozenMutation,
        body: &[u8],
        stage: &'static str,
    ) -> Option<Self> {
        let anchor = observation.anchor.as_ref()?;
        let reserved = anchor["committed_sequence"].as_u64()?.checked_add(1)?;
        // D's authenticated reservation must still name W's exact frozen B; a consumed reservation is settlement.
        if observation.uncertain
            || anchor == commit.expected()
            || anchor["reserved_sequence"].as_u64() != Some(reserved)
            || anchor["reserved_body_digest"]
                != format!("sha256:{}", hex::encode(Sha256::digest(body)))
        {
            return None;
        }
        let mut without_drain = anchor.clone();
        without_drain["drained_sequence"] = commit.expected()["drained_sequence"].clone();
        without_drain["drained_digest"] = commit.expected()["drained_digest"].clone();
        let reason = if !observation.latched && &without_drain == commit.expected() {
            "invariant breach (unreachable by construction)"
        } else {
            "superseding authority, owner 2g"
        };
        Some(Self::new(reserve, commit, reason, stage))
    }
    pub(crate) fn new(
        reserve: &FrozenMutation,
        commit: &FrozenMutation,
        reason: &'static str,
        stage: &'static str,
    ) -> Self {
        Self {
            sequence: commit.next()["committed_sequence"].as_u64().unwrap_or(0),
            reserve_sha256: hex::encode(Sha256::digest(reserve.bytes())),
            commit_sha256: hex::encode(Sha256::digest(commit.bytes())),
            reason,
            stage,
        }
    }
}
impl std::fmt::Display for CommitHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "COMMIT held; effects disabled; {}; sequence={}; reserve_sha256={}; commit_sha256={}; proof_stage={}", self.reason, self.sequence, self.reserve_sha256, self.commit_sha256, self.stage)
    }
}
/// Exact request bytes remain owned across refused delivery and observation-only reconciliation.
#[derive(Clone)]
pub struct FrozenMutation {
    bytes: Vec<u8>,
    request: String,
    expected: Value,
    next: Value,
}
impl FrozenMutation {
    pub fn checked(bytes: Vec<u8>) -> Result<Self> {
        let frame = d::decode(&bytes, d::Direction::ToDrain).map_err(|_| Refusal::Protocol)?;
        let d::Operation::Anchor { message, envelope } = frame.operation else {
            return Err(Refusal::Authority);
        };
        if !matches!(
            Phase::of_message(&message),
            Some(Phase::RESERVE | Phase::RECORD_COMMIT)
        ) || !message["expected"]["transaction_id"].is_null()
        {
            return Err(Refusal::Authority);
        }
        if Phase::of_message(&message) == Some(Phase::RECORD_COMMIT) {
            p::decode_envelope(envelope).map_err(|_| Refusal::Protocol)?;
        }
        let request = frame.request_id;
        let expected = message["expected"].clone();
        let next = message["next"].clone();
        if activation_anchor::propose(activation_anchor::Prior::Present(&expected), &message)
            .as_ref()
            != Some(&next)
        {
            return Err(Refusal::Authority);
        }
        Ok(Self {
            bytes,
            request,
            expected,
            next,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expected(&self) -> &Value {
        &self.expected
    }
    pub fn next(&self) -> &Value {
        &self.next
    }
}
/// The authenticated ORIGINAL_ACK is the sole constructor; parsing a wrapper never creates this fact.
pub struct DrainReleaseFact {
    identity: Value,
}
impl DrainReleaseFact {
    pub fn identity(&self) -> &Value {
        &self.identity
    }
}
pub enum DrainReply {
    Read(DrainObservation),
    Acknowledged(Value),
    Released(DrainReleaseFact),
    Refused,
}
enum DrainPending {
    Read(String),
    Mutation(String),
    Original(String, Value),
}
/// Isolated reserve replies retain transport authentication and change only the decoded observation.
#[cfg(feature = "test-isolation")]
pub(super) enum ReserveReplyObservation {
    Refused,
    Missing,
    WrongId,
    Uncertain,
    Superseding,
}
/// One request owns its reply slot. Any transport ambiguity closes that connection without claiming mutation failure.
pub struct DrainClient {
    connection: Connection,
    pending: Option<(DrainPending, u64)>,
    lease_at: Option<u64>,
    retained_mutation: Option<FrozenMutation>,
    #[cfg(feature = "test-isolation")]
    reserve_observation: Option<(ReserveReplyObservation, Option<std::path::PathBuf>)>,
    #[cfg(feature = "test-isolation")]
    settlement_fixture: Option<SettlementFixture>,
}
impl DrainClient {
    /// Install an isolated decoded observation plus a bounded observer at the actual W send boundary.
    #[cfg(feature = "test-isolation")]
    pub fn settlement_fixture_for_test(&mut self, fixture: SettlementFixture) -> Result<()> {
        self.connection.settlement_audit =
            Some(fixture.audit.try_clone().map_err(|_| Refusal::Transport)?);
        self.settlement_fixture = Some(fixture);
        Ok(())
    }
    #[cfg(feature = "test-isolation")]
    pub(super) fn send_observer_for_test(&mut self, path: std::path::PathBuf) {
        self.connection.send_observer = Some(path);
    }
    // AppendActor installs this only from its sealed private fixture loader.
    #[cfg(feature = "test-isolation")]
    pub(super) fn reserve_reply_for_test(
        &mut self,
        observation: ReserveReplyObservation,
        path: Option<std::path::PathBuf>,
    ) {
        self.reserve_observation = Some((observation, path));
    }
    /// Reauthenticate a disconnected session without discarding the exact possibly committed mutation.
    pub fn reconnect(&mut self) -> Result<()> {
        self.connection.reconnect()?;
        self.pending = None;
        self.lease_at = None;
        Ok(())
    }
    // The actor supplies one typed observation only after its sealed fixture selects this wait.
    #[cfg(feature = "test-isolation")]
    pub(super) fn transport_observation_for_test(&self, observation: TransportObservation) {
        self.connection.observation.set(Some(observation));
    }
    /// Recheck independently held process and socket identities without waiting for peer traffic.
    pub fn recheck_transport(&self) -> Result<()> {
        self.connection.recheck()
    }
    pub fn connect(
        root: &HeldSocketRoot,
        leaf: &str,
        pins: ServerPins,
        clock: Clock,
        hooks: Box<dyn ClientHooks>,
    ) -> Result<Self> {
        // Validate both configured policies before opening either independent server session.
        signer_peer::normalized_cgroup(&pins.writer.cgroup).map_err(|_| Refusal::Peer)?;
        Ok(Self {
            connection: Connection::new(root, leaf, &pins.drain, clock, hooks)?,
            pending: None,
            lease_at: None,
            retained_mutation: None,
            #[cfg(feature = "test-isolation")]
            reserve_observation: None,
            #[cfg(feature = "test-isolation")]
            settlement_fixture: None,
        })
    }
    fn begin(&mut self, bytes: &[u8], pending: DrainPending, limit: u64) -> Result<()> {
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        if let Err(e) = self.connection.idle() {
            self.connection.close();
            return Err(e);
        }
        let end = self
            .connection
            .deadline(limit, d::D_REQUEST_DEADLINE_MS as u64)?;
        self.pending = Some((pending, end));
        if let Err(e) = self.connection.send(bytes) {
            self.connection.close();
            return Err(e);
        }
        Ok(())
    }
    pub fn read(&mut self, id: &str, limit: u64) -> Result<()> {
        let bytes = d::encode(
            &d::header("READ", id, d::DRAIN_SLOTS[0].1),
            &[],
            d::Direction::ToDrain,
        )
        .map_err(|_| Refusal::Protocol)?;
        self.begin(&bytes, DrainPending::Read(id.into()), limit)
    }
    pub fn mutation(&mut self, proposal: &FrozenMutation, limit: u64) -> Result<()> {
        if self
            .retained_mutation
            .as_ref()
            .is_some_and(|held| held.bytes != proposal.bytes)
        {
            return Err(Refusal::Busy);
        }
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        // Own exact bytes and both complete anchors before the first possibly successful send.
        self.retained_mutation = Some(proposal.clone());
        self.begin(
            &proposal.bytes,
            DrainPending::Mutation(proposal.request.clone()),
            limit,
        )
    }
    pub fn retained_mutation(&self) -> Option<&FrozenMutation> {
        self.retained_mutation.as_ref()
    }
    pub fn original(&mut self, id: &str, envelope: &[u8], limit: u64) -> Result<()> {
        // A drain under a frozen COMMIT would stale its predecessor, and no proved renewal exists.
        if self.retained_mutation.is_some() {
            return Err(Refusal::Busy);
        }
        let identity = append_contract::identity(envelope).ok_or(Refusal::Protocol)?;
        let mut h = d::header("ORIGINAL", id, d::DRAIN_SLOTS[0].1);
        h["sequence"] = identity["sequence"].clone();
        h["payload_length"] = json!(envelope.len());
        let bytes =
            d::encode(&h, envelope, d::Direction::ToDrain).map_err(|_| Refusal::Protocol)?;
        self.begin(&bytes, DrainPending::Original(id.into(), identity), limit)
    }
    pub fn read_due(&self, now: u64) -> bool {
        self.lease_at
            .and_then(|at| now.checked_sub(at))
            .map_or(true, |age| age >= d::D_HEARTBEAT_MS as u64 * NS_PER_MS)
    }
    pub fn lease_live(&self, now: u64) -> bool {
        self.lease_at
            .and_then(|t| now.checked_sub(t))
            .is_some_and(|age| age < d::D_LEASE_MS as u64 * NS_PER_MS)
    }
    pub fn poll(&mut self) -> Result<Option<DrainReply>> {
        let outcome = self.poll_inner();
        if outcome.is_err() {
            self.connection.close();
        }
        outcome
    }
    fn poll_inner(&mut self) -> Result<Option<DrainReply>> {
        let Some((pending, end)) = self.pending.as_ref() else {
            self.connection.idle()?;
            return Ok(None);
        };
        let Some(packet) = self.connection.poll(*end, d::D_REPLY_MAX_BYTES)? else {
            return Ok(None);
        };
        let reply =
            d::decode(&packet.bytes, d::Direction::FromDrain).map_err(|_| Refusal::Protocol)?;
        #[cfg(feature = "test-isolation")]
        let reply = {
            let mut reply = reply;
            let reserve = self
                .retained_mutation
                .as_ref()
                .is_some_and(|m| m.next()["reserved_body_digest"].is_string());
            let applicable = reserve
                && self
                    .reserve_observation
                    .as_ref()
                    .is_some_and(|(kind, _)| match kind {
                        ReserveReplyObservation::Uncertain
                        | ReserveReplyObservation::Superseding => {
                            matches!(pending, DrainPending::Read(_))
                        }
                        _ => matches!(pending, DrainPending::Mutation(_)),
                    });
            if applicable {
                let (kind, path) = self.reserve_observation.take().ok_or(Refusal::Protocol)?;
                if let Some(path) = path {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(super::custody::PRIVATE_MODE)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(path)
                        .map_err(|_| Refusal::Transport)?;
                }
                match kind {
                    ReserveReplyObservation::Refused => reply.operation = d::Operation::Refused,
                    ReserveReplyObservation::Missing => return Ok(None),
                    ReserveReplyObservation::WrongId => reply.request_id = "f".repeat(32),
                    ReserveReplyObservation::Uncertain => {
                        if let d::Operation::ReadReply { uncertain, .. } = &mut reply.operation {
                            *uncertain = true;
                        }
                    }
                    ReserveReplyObservation::Superseding => {
                        if let d::Operation::ReadReply {
                            anchor: Some(anchor),
                            ..
                        } = &mut reply.operation
                        {
                            anchor["generation"] = json!(u64::MAX);
                        }
                    }
                }
            }
            reply
        };
        let request = match pending {
            DrainPending::Read(id) | DrainPending::Mutation(id) | DrainPending::Original(id, _) => {
                id
            }
        };
        if reply.request_id != *request || reply.role != d::DRAIN_SLOTS[0].1 {
            return Err(Refusal::Correlation);
        }
        let reply = match (pending, reply.operation) {
            (_, d::Operation::Refused) => DrainReply::Refused,
            (
                DrainPending::Read(_),
                d::Operation::ReadReply {
                    anchor,
                    latched,
                    uncertain,
                },
            ) => {
                let observed = self.connection.now()?;
                let observation = DrainObservation {
                    anchor,
                    latched,
                    uncertain,
                    observed,
                };
                if observation.anchor.is_some() && observation.pending().is_none() {
                    return Err(Refusal::Protocol);
                }
                #[cfg(feature = "test-isolation")]
                let observation = {
                    let mut observation = observation;
                    if let Some(fixture) = &self.settlement_fixture {
                        fixture.observe(&mut observation)?;
                    }
                    observation
                };
                DrainReply::Read(observation)
            }
            (DrainPending::Mutation(_), d::Operation::AnchorAck { anchor }) => {
                DrainReply::Acknowledged(anchor)
            }
            (
                DrainPending::Original(_, identity),
                d::Operation::OriginalAck {
                    sequence,
                    drained_digest,
                },
            ) => {
                if identity["sequence"] != sequence || identity["commitment"] != drained_digest {
                    return Err(Refusal::Correlation);
                }
                DrainReply::Released(DrainReleaseFact {
                    identity: identity.clone(),
                })
            }
            _ => return Err(Refusal::Correlation),
        };
        self.connection.completed(*end)?;
        if let DrainReply::Read(observation) = &reply {
            self.lease_at = Some(observation.observed);
            if self
                .retained_mutation
                .as_ref()
                .is_some_and(|proposal| observation.confirms(proposal))
            {
                self.retained_mutation = None;
            }
        }
        self.pending = None;
        Ok(Some(reply))
    }
}

pub struct CheckpointChallenge {
    pub session: String,
    pub request: String,
    pub nonce: String,
    pub issued: u64,
    pub status: super::signer_client::StatusReply,
}
pub enum WriterReply {
    Ready,
    Status(p::StatusPayload),
    Verified(Vec<u8>),
    Refused,
    Challenge(CheckpointChallenge),
    CheckpointAcknowledged(String),
}
enum WriterPending {
    Hello,
    Status(String),
    Sign(String, Vec<u8>),
    Query {
        request: String,
        sent: u64,
        limit: u64,
    },
    Report(CheckpointChallenge),
    Parts {
        challenge: CheckpointChallenge,
        bytes: Vec<u8>,
        digest: String,
        next: usize,
        packet: Option<Vec<u8>>,
    },
    Ack(String, String),
}
pub struct WriterClient {
    connection: Connection,
    session: Option<String>,
    pending: Option<(WriterPending, u64)>,
    checkpoint_enabled: bool,
    checkpoint_ends: Option<u64>,
}
impl WriterClient {
    pub(crate) fn status_pending(&self) -> bool {
        matches!(self.pending, Some((WriterPending::Status(_), _)))
    }
    // The actor supplies one typed observation only after its sealed fixture selects this wait.
    #[cfg(feature = "test-isolation")]
    pub(super) fn transport_observation_for_test(&self, observation: TransportObservation) {
        self.connection.observation.set(Some(observation));
    }
    /// Recheck independently held process and socket identities without waiting for peer traffic.
    pub fn recheck_transport(&self) -> Result<()> {
        self.connection.recheck()
    }
    pub fn connect(
        root: &HeldSocketRoot,
        leaf: &str,
        pins: ServerPins,
        clock: Clock,
        hooks: Box<dyn ClientHooks>,
    ) -> Result<Self> {
        signer_peer::normalized_cgroup(&pins.drain.cgroup).map_err(|_| Refusal::Peer)?;
        let connection = Connection::new(root, leaf, &pins.writer, clock, hooks)?;
        let end = connection.deadline(u64::MAX, p::WRITER_HANDSHAKE_DEADLINE_MS)?;
        let checkpoint_enabled = probe_checkpoint_socket(connection.fd()?)?;
        if !checkpoint_enabled {
            // SAFETY: startup reports only the fixed transport refusal, with no peer or packet data.
            eprintln!("business checkpoint transport unavailable");
        }
        Ok(Self {
            connection,
            session: None,
            pending: Some((WriterPending::Hello, end)),
            checkpoint_enabled,
            checkpoint_ends: None,
        })
    }
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }
    fn begin(
        &mut self,
        op: p::Operation,
        body: &[u8],
        pending: WriterPending,
        limit: u64,
    ) -> Result<()> {
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        if let Err(e) = self.connection.idle() {
            self.connection.close();
            return Err(e);
        }
        let session = self.session.as_ref().ok_or(Refusal::Held)?;
        let bytes =
            p::encode(p::Direction::ToWriter, session, &op, body).map_err(|_| Refusal::Protocol)?;
        let end = self.connection.deadline(
            limit,
            super::signer_contract::SIGNER_REQUEST_DEADLINE_MS as u64,
        )?;
        self.pending = Some((pending, end));
        if let Err(e) = self.connection.send(&bytes) {
            self.connection.close();
            return Err(e);
        }
        Ok(())
    }
    pub fn status(&mut self, id: &str, limit: u64) -> Result<()> {
        self.begin(
            p::Operation::Status {
                request_id: id.into(),
            },
            &[],
            WriterPending::Status(id.into()),
            limit,
        )
    }
    pub fn sign(
        &mut self,
        header: super::signer_service::Header,
        body: &[u8],
        expiry: u64,
    ) -> Result<()> {
        let deadline =
            p::canonical_deadline(&header.deadline_boottime_ns).ok_or(Refusal::Deadline)?;
        let now = self.connection.now()?;
        if deadline <= now
            || deadline >= expiry
            || deadline - now > p::WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS
        {
            return Err(Refusal::Deadline);
        }
        let id = header.request_id.clone();
        self.begin(
            p::Operation::Sign(header),
            body,
            WriterPending::Sign(id, body.to_vec()),
            deadline,
        )
    }
    pub fn checkpoint_query(&mut self, id: &str, limit: u64) -> Result<()> {
        if !self.checkpoint_enabled {
            return Err(Refusal::Transport);
        }
        if self.pending.is_some() {
            return Err(Refusal::Busy);
        }
        let sent = self.connection.now()?;
        // Must match writer_service::writer_next_request_bound_ns: W cannot wait beyond P's next request bound.
        let query_end = super::writer_service::writer_next_request_bound_ns(sent)
            .ok_or(Refusal::Deadline)?
            .min(limit);
        self.checkpoint_ends = None;
        self.begin(
            p::Operation::CheckpointQuery {
                request_id: id.into(),
            },
            &[],
            WriterPending::Query {
                request: id.into(),
                sent,
                limit,
            },
            query_end,
        )
    }
    pub fn checkpoint_report(&mut self, bytes: Vec<u8>) -> Result<()> {
        if !matches!(self.pending, Some((WriterPending::Report(_), _))) {
            return Err(Refusal::Busy);
        }
        let Some((WriterPending::Report(challenge), end)) = self.pending.take() else {
            return Err(Refusal::Busy);
        };
        let now = match self.connection.now() {
            Ok(now) => now,
            Err(error) => {
                self.connection.close();
                return Err(error);
            }
        };
        if now >= end {
            // An early caller cancellation cannot leave P holding a challenge on a reusable session.
            if self.checkpoint_ends.map_or(true, |expires| now < expires) {
                self.connection.close();
            }
            return Err(Refusal::Deadline);
        }
        let result = (|| {
            let candidate = cp::Candidate::parse(&bytes).map_err(|_| Refusal::Protocol)?;
            candidate
                .echo(&challenge.session, &challenge.request, &challenge.nonce)
                .map_err(|_| Refusal::Correlation)?;
            let digest = cp::digest(&bytes);
            Ok((
                WriterPending::Parts {
                    challenge,
                    bytes,
                    digest,
                    next: 0,
                    packet: None,
                },
                end,
            ))
        })();
        match result {
            Ok(p) => {
                self.pending = Some(p);
                Ok(())
            }
            Err(e) => {
                self.connection.close();
                Err(e)
            }
        }
    }
    pub fn poll(&mut self) -> Result<Option<WriterReply>> {
        let result = self.poll_inner();
        if result.is_err() {
            self.connection.close();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Option<WriterReply>> {
        let Some((pending, end)) = self.pending.as_mut() else {
            self.connection.idle()?;
            return Ok(None);
        };
        // Read at most one authenticated frame before considering checkpoint expiry. Late frames
        // are terminal; only an empty socket after P's known lifetime permits session reuse.
        let received = if matches!(
            pending,
            WriterPending::Query { .. }
                | WriterPending::Ack(..)
                | WriterPending::Report(_)
                | WriterPending::Parts { .. }
        ) {
            self.connection
                .poll(u64::MAX, p::WRITER_REPLY_PACKET_MAX_BYTES)?
        } else {
            None
        };
        let now = self.connection.now()?;
        if now >= *end {
            if received.is_some() {
                return Err(Refusal::Deadline);
            }
            // The checkpoint protocol has no refusal opcode. Only a known, ended challenge
            // can be forgotten without leaving P and W with different session ownership.
            if matches!(
                pending,
                WriterPending::Query { .. }
                    | WriterPending::Report(_)
                    | WriterPending::Parts { .. }
                    | WriterPending::Ack(..)
            ) {
                if self.checkpoint_ends.map_or(true, |expires| now < expires) {
                    return Err(Refusal::Deadline);
                }
                self.pending = None;
                self.checkpoint_ends = None;
                return Ok(Some(WriterReply::Refused));
            }
            return Err(Refusal::Deadline);
        }
        if received.is_some()
            && matches!(
                pending,
                WriterPending::Report(_) | WriterPending::Parts { .. }
            )
        {
            return Err(Refusal::Correlation);
        }
        if let WriterPending::Report(_) = pending {
            return Ok(None);
        }
        if let WriterPending::Parts {
            challenge,
            bytes,
            digest,
            next,
            packet,
        } = pending
        {
            if packet.is_none() {
                let count = bytes.len().div_ceil(activation_anchor::MAX_BYTES);
                let start = *next * activation_anchor::MAX_BYTES;
                let stop = (start + activation_anchor::MAX_BYTES).min(bytes.len());
                let op = p::Operation::CheckpointPart(cp::Part {
                    request_id: challenge.request.clone(),
                    nonce: challenge.nonce.clone(),
                    part_index: *next,
                    part_count: count,
                    total_length: bytes.len(),
                    checkpoint_digest: digest.clone(),
                });
                *packet = Some(
                    p::encode(
                        p::Direction::ToWriter,
                        &challenge.session,
                        &op,
                        &bytes[start..stop],
                    )
                    .map_err(|_| Refusal::Protocol)?,
                );
            }
            // Only checkpoint parts retain their exact packet on EAGAIN. Other sends still refuse.
            let bytes_to_send = packet.as_ref().ok_or(Refusal::Held)?;
            self.connection.hooks.before_send()?;
            if !self.connection.peer.live() {
                return Err(Refusal::Peer);
            }
            let sent = unsafe {
                libc::send(
                    self.connection.fd()?,
                    bytes_to_send.as_ptr() as _,
                    bytes_to_send.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            if sent != bytes_to_send.len() as isize {
                return Err(Refusal::Transport);
            }
            packet.take();
            *next += 1;
            if *next == bytes.len().div_ceil(activation_anchor::MAX_BYTES) {
                *pending = WriterPending::Ack(challenge.request.clone(), digest.clone());
            }
            return Ok(None);
        }
        let packet = if matches!(
            pending,
            WriterPending::Query { .. } | WriterPending::Ack(..)
        ) {
            received
        } else {
            self.connection
                .poll(*end, p::WRITER_REPLY_PACKET_MAX_BYTES)?
        };
        let Some(packet) = packet else {
            return Ok(None);
        };
        if matches!(pending, WriterPending::Hello) {
            let (h, _) = frame::split(
                &packet.bytes,
                p::WRITER_HEADER_MAX_BYTES,
                p::WRITER_REPLY_PACKET_MAX_BYTES,
            )
            .map_err(|_| Refusal::Protocol)?;
            let session = h["session_id"]
                .as_str()
                .ok_or(Refusal::Protocol)?
                .to_owned();
            let frame = p::decode(&packet.bytes, p::Direction::ToWall, &session)
                .map_err(|_| Refusal::Protocol)?;
            if !matches!(frame.operation, p::Operation::Hello) {
                return Err(Refusal::Correlation);
            }
            let ack = p::encode(
                p::Direction::ToWriter,
                &session,
                &p::Operation::HelloAck,
                &[],
            )
            .map_err(|_| Refusal::Protocol)?;
            self.connection.completed(*end)?;
            self.connection.send(&ack)?;
            self.session = Some(session);
            self.pending = None;
            return Ok(Some(WriterReply::Ready));
        }
        let session = self.session.as_ref().ok_or(Refusal::Held)?;
        let frame = p::decode(&packet.bytes, p::Direction::ToWall, session)
            .map_err(|_| Refusal::Protocol)?;
        let request = match pending {
            WriterPending::Status(id) | WriterPending::Sign(id, _) | WriterPending::Ack(id, _) => {
                id.clone()
            }
            WriterPending::Query { request, .. } => request.clone(),
            _ => return Err(Refusal::Held),
        };
        let reply = match frame.operation {
            p::Operation::Refused { request_id } if request_id == request => WriterReply::Refused,
            p::Operation::StatusReply { request_id }
                if request_id == request && matches!(pending, WriterPending::Status(_)) =>
            {
                WriterReply::Status(
                    p::StatusPayload::decode(frame.payload).map_err(|_| Refusal::Protocol)?,
                )
            }
            p::Operation::Verified { request_id }
                if request_id == request && matches!(pending, WriterPending::Sign(..)) =>
            {
                let envelope = p::decode_envelope(frame.payload).map_err(|_| Refusal::Protocol)?;
                let WriterPending::Sign(_, body) = pending else {
                    return Err(Refusal::Held);
                };
                if crate::smb::jcs::encode(&envelope["body"])
                    .map_err(|_| Refusal::Protocol)?
                    .as_bytes()
                    != body
                {
                    return Err(Refusal::Correlation);
                }
                WriterReply::Verified(frame.payload.to_vec())
            }
            p::Operation::CheckpointAck {
                request_id,
                checkpoint_digest,
            } if request_id == request => {
                if !matches!(pending,WriterPending::Ack(_,expected) if *expected==checkpoint_digest)
                {
                    return Err(Refusal::Correlation);
                }
                WriterReply::CheckpointAcknowledged(checkpoint_digest)
            }
            p::Operation::CheckpointChallenge {
                request_id,
                nonce,
                issued_boottime_ns,
            } if request_id == request && matches!(pending, WriterPending::Query { .. }) => {
                let value = frame::canonical(frame.payload, p::WRITER_STATUS_MAX_BYTES)
                    .map_err(|_| Refusal::Protocol)?;
                let encoded =
                    super::signer_service::encode(&value, &[]).map_err(|_| Refusal::Protocol)?;
                let status = super::signer_client::parse_status_packet(&encoded)
                    .map_err(|_| Refusal::Protocol)?;
                let now = self.connection.now()?;
                let WriterPending::Query { sent, limit, .. } = pending else {
                    return Err(Refusal::Held);
                };
                // An authenticated issue time is still bounded by W's own send/receive interval.
                if issued_boottime_ns < *sent || issued_boottime_ns > now {
                    return Err(Refusal::Deadline);
                }
                let challenge_end = issued_boottime_ns
                    .checked_add(cp::CHECKPOINT_CHALLENGE_MS * NS_PER_MS)
                    .ok_or(Refusal::Deadline)?;
                let expires = issued_boottime_ns
                    .checked_add(cp::CHECKPOINT_ACK_MS * NS_PER_MS)
                    .ok_or(Refusal::Deadline)?
                    .min(*limit);
                if now >= expires {
                    return Err(Refusal::Deadline);
                }
                self.checkpoint_ends = Some(challenge_end);
                let challenge = CheckpointChallenge {
                    session: session.clone(),
                    request: request_id,
                    nonce,
                    issued: issued_boottime_ns,
                    status,
                };
                let returned = CheckpointChallenge {
                    session: challenge.session.clone(),
                    request: challenge.request.clone(),
                    nonce: challenge.nonce.clone(),
                    issued: challenge.issued,
                    status: challenge.status.clone(),
                };
                self.connection.completed(*end)?;
                self.pending = Some((WriterPending::Report(challenge), expires));
                return Ok(Some(WriterReply::Challenge(returned)));
            }
            _ => return Err(Refusal::Correlation),
        };
        self.connection.completed(*end)?;
        self.pending = None;
        Ok(Some(reply))
    }
}
/// A private pair measures the actual one-frame prerequisite with the session's buffer settings.
fn probe_checkpoint_socket(session: RawFd) -> Result<bool> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(Refusal::Transport);
    }
    let send = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let _receive = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        let mut size = 0i32;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                session,
                libc::SOL_SOCKET,
                option,
                &mut size as *mut _ as _,
                &mut len,
            )
        } != 0
        {
            return Err(Refusal::Transport);
        }
        // Linux returns twice the configured value, including kernel bookkeeping.
        size /= 2;
        for fd in fds {
            if unsafe {
                libc::setsockopt(fd, libc::SOL_SOCKET, option, &size as *const _ as _, len)
            } != 0
            {
                return Err(Refusal::Transport);
            }
        }
    }
    let bytes = vec![0; cp::CHECKPOINT_PART_PACKET_MAX_BYTES];
    let sent = unsafe {
        libc::send(
            send.as_raw_fd(),
            bytes.as_ptr() as _,
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent == bytes.len() as isize {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::EMSGSIZE | libc::ENOBUFS) => Ok(false),
        _ => Err(Refusal::Transport),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximal_part_probe_refuses_insufficient_socket_capacity() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let socket = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert!(probe_checkpoint_socket(socket.as_raw_fd()).unwrap());
        // A buffer below one required packet is the negative host prerequisite control.
        let small = (cp::CHECKPOINT_PART_PACKET_MAX_BYTES / 4) as i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &small as *const _ as _,
                    std::mem::size_of_val(&small) as _,
                )
            },
            0
        );
        assert!(
            !probe_checkpoint_socket(socket.as_raw_fd()).unwrap(),
            "host probe disables an unsupported checkpoint path"
        );
    }
}

#[cfg(feature = "test-isolation")]
pub mod test_support {
    use super::*;
    /// The isolated driver uses the actual sender descriptor to force kernel EAGAIN.
    pub fn checkpoint_socket(client: &WriterClient) -> RawFd {
        // Safety: the isolated driver calls this only after its successful HELLO exchange.
        client.connection.fd().expect("live test connection")
    }
    pub fn pending_packet(client: &WriterClient) -> Option<Vec<u8>> {
        match &client.pending {
            Some((WriterPending::Parts { packet, .. }, _)) => packet.clone(),
            _ => None,
        }
    }
}
