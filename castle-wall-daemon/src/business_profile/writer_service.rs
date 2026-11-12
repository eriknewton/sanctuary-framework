//! Closed-start writer composition with required signer and reconciliation ports.
use super::{
    custody, records,
    signer_client::{self, BusinessSignerClient, CurrentGrantView, SignedReply, StatusReply},
    signer_contract::SIGNER_PROTOCOL,
    signer_peer,
    signer_service::{self, Header},
    signer_watchdog::WATCHDOG_TICK_MS,
    writer_peer::{
        self, BusTarget, Clock, Deadline, HeldConfig, ListenerExpectations, WallMainBinding,
        NS_PER_MS,
    },
    writer_protocol::{self, Direction, Handshake, Operation, StatusPayload, *},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
#[cfg(feature = "test-isolation")]
use serde::Deserialize;
#[cfg(feature = "test-isolation")]
use std::path::Path;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};
pub const WRITER_MAPPINGS_MAX: usize = custody::RUNTIME_FILES_MAX;
pub const STOP_STATUS:&str="STATUS=writer stopped; the wall stays closed and nothing restarts the writer until the wall unit is restarted";
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Peer(writer_peer::Error),
    Signer(signer_client::Refusal),
    Protocol(writer_protocol::Refusal),
    Start,
    State,
    Grant,
    Expired,
    Deadline,
    Signature,
    Closure,
    Io,
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<writer_peer::Error> for Error {
    fn from(e: writer_peer::Error) -> Self {
        Self::Peer(e)
    }
}
impl From<signer_client::Refusal> for Error {
    fn from(e: signer_client::Refusal) -> Self {
        Self::Signer(e)
    }
}
impl From<writer_protocol::Refusal> for Error {
    fn from(e: writer_protocol::Refusal) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}
/// The writer owns one synchronous signer slot and never queues another operation.
pub trait SignerPort {
    fn initial_status(&self) -> StatusReply;
    fn status(&mut self) -> signer_client::Result<StatusReply>;
    fn bind(&mut self, view: &CurrentGrantView) -> signer_client::Result<()>;
    fn sign_record(&mut self, header: Header, body: &[u8]) -> signer_client::Result<SignedReply>;
    fn close_and_settle(&mut self);
}
pub struct ClientSignerPort {
    client: BusinessSignerClient,
}
impl ClientSignerPort {
    pub fn bootstrap(policy: signer_peer::PeerPolicy) -> signer_client::Result<Self> {
        Ok(Self {
            client: BusinessSignerClient::bootstrap(policy)?,
        })
    }
    #[cfg(feature = "test-isolation")]
    pub fn bootstrap_at(
        path: &Path,
        policy: signer_peer::PeerPolicy,
    ) -> signer_client::Result<Self> {
        Ok(Self {
            client: BusinessSignerClient::bootstrap_at(path, policy)?,
        })
    }
    #[cfg(feature = "test-isolation")]
    pub fn bootstrap_at_with_clock(
        path: &Path,
        policy: signer_peer::PeerPolicy,
        clock: Clock,
    ) -> signer_client::Result<Self> {
        Ok(Self {
            client: BusinessSignerClient::bootstrap_at_with_clock(path, policy, clock)?,
        })
    }
}
impl SignerPort for ClientSignerPort {
    fn initial_status(&self) -> StatusReply {
        self.client.latest_status().clone()
    }
    fn status(&mut self) -> signer_client::Result<StatusReply> {
        self.client.status()
    }
    fn bind(&mut self, view: &CurrentGrantView) -> signer_client::Result<()> {
        self.client.bind(view)
    }
    fn sign_record(&mut self, h: Header, b: &[u8]) -> signer_client::Result<SignedReply> {
        self.client.sign_record(h, b)
    }
    fn close_and_settle(&mut self) {
        self.client.close_and_settle();
    }
}
pub struct ReconcileEvidence<'a> {
    pub observation: &'a StatusReply,
    pub fortress_id: &'a str,
    pub enrollment_revision: u64,
}
pub enum Reconciliation {
    NotReconciled,
    Reconciled(Box<StatusReply>),
}
// Only the closed production reconciler and the gated script can supply reconciliation evidence.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ClosedReconciler {}
    #[cfg(feature = "test-isolation")]
    impl Sealed for super::test_support::TestReconciler {}
}
pub trait Reconciler: sealed::Sealed {
    fn reconcile(&mut self, evidence: ReconcileEvidence<'_>) -> Reconciliation;
}
pub struct ClosedReconciler;
impl ClosedReconciler {
    pub fn production() -> Self {
        Self
    }
}
impl Reconciler for ClosedReconciler {
    fn reconcile(&mut self, _evidence: ReconcileEvidence<'_>) -> Reconciliation {
        // reconciliation with the drain and the wall's log is the only edge to a grant; until that evidence exists the writer serves status but never a signature.
        Reconciliation::NotReconciled
    }
}
pub trait Notifier {
    fn notify(&mut self, message: &str) -> io::Result<()>;
}
pub struct SystemNotifier;
impl Notifier for SystemNotifier {
    fn notify(&mut self, message: &str) -> io::Result<()> {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(());
        };
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_bytes();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty()
            || bytes.len() >= addr.sun_path.len()
            || !matches!(bytes[0], b'/' | b'@')
        {
            return Err(io::Error::other("K1_REFUSED"));
        }
        addr.sun_family = libc::AF_UNIX as _;
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = if i == 0 && *b == b'@' { 0 } else { *b as _ };
        }
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let length =
            std::mem::size_of::<libc::sa_family_t>() + bytes.len() + usize::from(bytes[0] != b'@');
        if unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                message.as_ptr() as _,
                message.len(),
                libc::MSG_NOSIGNAL,
                &addr as *const _ as _,
                length as _,
            )
        } != message.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterState {
    Starting,
    ClosedLocked,
    ClosedRecovery,
    WallBound,
    Reconciled,
    Granted,
    SignInFlight,
    EnvelopeVerified,
    Settling,
    Stopped,
}
#[derive(Default)]
struct Recovery {
    closed_by_recovery: bool,
    locked_after_recovery_at: Option<u64>,
}
/// The production transition to WallBound is private to the authenticated run loop.
pub struct WriterMachine<P: SignerPort, R: Reconciler> {
    signer: P,
    reconciler: R,
    state: WriterState,
    history: Recovery,
    latest: StatusReply,
    reconciled: Option<StatusReply>,
    frozen: Option<StatusReply>,
    wall: bool,
    boot: String,
    clock: Clock,
    last_status: u64,
    fortress: String,
    revision: u64,
}
impl<P: SignerPort, R: Reconciler> WriterMachine<P, R> {
    fn new(
        signer: P,
        reconciler: R,
        boot: String,
        clock: Clock,
        fortress: String,
        revision: u64,
        bootstrapped_at: u64,
    ) -> Self {
        let latest = signer.initial_status();
        Self {
            signer,
            reconciler,
            state: WriterState::Starting,
            history: Recovery::default(),
            latest,
            reconciled: None,
            frozen: None,
            wall: false,
            boot,
            clock,
            last_status: bootstrapped_at,
            fortress,
            revision,
        }
    }
    pub fn state(&self) -> WriterState {
        self.state
    }
    fn now(&self) -> Result<u64> {
        Ok((self.clock)()?)
    }
    fn start(&mut self) -> Result<&'static str> {
        match self.latest.state.as_str() {
            "LOCKED" => {
                self.state = WriterState::ClosedLocked;
                Ok("READY=1\nSTATUS=writer closed")
            }
            "WIPE_UNCONFIRMED" | "RECOVERY_REQUIRED" => {
                self.history.closed_by_recovery = true;
                self.state = WriterState::ClosedRecovery;
                Ok("READY=1\nSTATUS=writer closed for recovery")
            }
            _ => Err(Error::Start),
        }
    }
    fn bind_wall(&mut self) {
        // The accept guard owns the one-pidfd rule; this transition preserves the pre-bind recovery history.
        self.wall = true;
        self.state = WriterState::WallBound;
    }
    fn closed_state(&self) -> WriterState {
        if self.wall {
            WriterState::WallBound
        } else if self.history.closed_by_recovery {
            WriterState::ClosedRecovery
        } else {
            WriterState::ClosedLocked
        }
    }
    fn live(view: &StatusReply, now: u64) -> bool {
        match (
            view.started_boottime_ns.parse::<u64>(),
            view.expires_boottime_ns.parse::<u64>(),
        ) {
            (Ok(start), Ok(end)) => start <= now && now < end,
            _ => false,
        }
    }
    fn same(a: &StatusReply, b: &StatusReply) -> bool {
        a == b
    }
    fn eligible(&self, view: &StatusReply, now: u64) -> bool {
        view.state == "UNLOCKED"
            && !self.history.closed_by_recovery
            && view.boot_id == self.boot
            && Self::live(view, now)
            && self
                .history
                .locked_after_recovery_at
                .map_or(true, |locked| {
                    view.started_boottime_ns
                        .parse::<u64>()
                        .is_ok_and(|start| start > locked)
                })
    }
    pub fn tick(&mut self) -> Result<()> {
        if let Some(frozen) = &self.frozen {
            // expiry is fixed by the signer's grant; heartbeats prove liveness and never extend it.
            if !Self::live(frozen, self.now()?) {
                self.state = WriterState::Settling;
                return Err(Error::Expired);
            }
        }
        Ok(())
    }
    fn observe(&mut self, observation: StatusReply) -> Result<()> {
        let now = self.now()?;
        if let Some(frozen) = &self.frozen {
            if observation.state != "UNLOCKED"
                || observation.boot_id != self.boot
                || !Self::same(frozen, &observation)
            {
                self.state = WriterState::Settling;
                return Err(Error::Grant);
            }
            self.tick()?;
            self.latest = observation;
            return Ok(());
        }
        self.latest = observation.clone();
        // Recovery history survives every pre-bind state, including observations before the wall connects.
        match observation.state.as_str() {
            "WIPE_UNCONFIRMED" | "RECOVERY_REQUIRED" => {
                self.history.closed_by_recovery = true;
                self.history.locked_after_recovery_at = None;
                self.reconciled = None;
                self.state = self.closed_state();
                return Ok(());
            }
            "LOCKED" => {
                if self.history.closed_by_recovery {
                    self.history.closed_by_recovery = false;
                    self.history.locked_after_recovery_at = Some(now);
                }
                self.reconciled = None;
                self.state = self.closed_state();
                return Ok(());
            }
            "UNLOCKING" | "LOCKING" => {
                self.reconciled = None;
                self.state = self.closed_state();
                return Ok(());
            }
            "UNLOCKED" => {}
            _ => {
                self.state = WriterState::Settling;
                return Err(Error::State);
            }
        }
        if let Some(view) = self.reconciled.take() {
            if !Self::same(&view, &observation) || !self.eligible(&observation, now) {
                self.state = self.closed_state();
                return Ok(());
            }
            if observation.anchor_revision.is_none() || observation.anchor_digest.is_none() {
                self.reconciled = Some(view);
                self.state = WriterState::Reconciled;
                return Ok(());
            }
            if let Err(error) = self.signer.bind(&view.grant) {
                self.state = WriterState::Settling;
                return Err(error.into());
            }
            self.frozen = Some(view);
            self.state = WriterState::Granted;
            return Ok(());
        }
        if !self.wall || !self.eligible(&observation, now) {
            self.state = self.closed_state();
            return Ok(());
        }
        match self.reconciler.reconcile(ReconcileEvidence {
            observation: &observation,
            fortress_id: &self.fortress,
            enrollment_revision: self.revision,
        }) {
            Reconciliation::Reconciled(view) if Self::same(&view, &observation) => {
                self.reconciled = Some(*view);
                self.state = WriterState::Reconciled;
            }
            _ => self.state = WriterState::WallBound,
        }
        Ok(())
    }
    pub fn heartbeat_due(&self) -> Result<bool> {
        Ok(self.now()?.saturating_sub(self.last_status) >= WRITER_HEARTBEAT_MS * NS_PER_MS)
    }
    pub fn heartbeat(&mut self) -> Result<()> {
        let result = self.heartbeat_inner();
        if result.is_err() {
            self.state = WriterState::Settling;
        }
        result
    }
    fn heartbeat_inner(&mut self) -> Result<()> {
        let admitted = self.now()?;
        let observation = self.signer.status()?;
        // A scripted port cannot extend the production client's fixed request deadline.
        if self.now()?.saturating_sub(admitted)
            >= super::signer_contract::SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS
        {
            return Err(Error::Deadline);
        }
        self.last_status = admitted;
        self.observe(observation)
    }
    pub fn status_payload(&self) -> StatusPayload {
        StatusPayload::from_signer(&self.latest, self.state == WriterState::Granted)
    }
    fn expiry(&self) -> Result<u64> {
        self.frozen
            .as_ref()
            .map(|v| {
                v.expires_boottime_ns
                    .parse::<u64>()
                    .map_err(|_| Error::Grant)
            })
            .unwrap_or(Ok(u64::MAX))
    }
    // Caller freshness is admitted before bus work; serve uses this same predicate before REFUSED.
    fn admit_deadline(deadline: u64, now: u64, expiry: u64) -> Result<()> {
        if deadline <= now
            || deadline
                > now
                    .checked_add(WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS)
                    .ok_or(Error::Deadline)?
            || deadline >= expiry
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub fn sign(
        &mut self,
        header: Header,
        body: &[u8],
        post_wait: impl FnOnce(u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let result = self.sign_inner(header, body, post_wait);
        if result.is_err() {
            self.state = WriterState::Settling;
        }
        result
    }
    fn sign_inner(
        &mut self,
        header: Header,
        body: &[u8],
        post_wait: impl FnOnce(u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.tick()?;
        if self.state != WriterState::Granted {
            return Err(Error::State);
        }
        let frozen = self.frozen.clone().ok_or(Error::Grant)?;
        let now = self.now()?;
        let g = &frozen.grant;
        let deadline = canonical_deadline(&header.deadline_boottime_ns).ok_or(Error::Deadline)?;
        if header.v != 1
            || header.protocol != SIGNER_PROTOCOL
            || header.activation_id != g.activation_id
            || header.lease_id != g.lease_id
            || header.generation != g.generation
            || header.epoch != g.epoch
            || header.role != g.role
            || header.preimage_length != body.len()
        {
            return Err(Error::Grant);
        }
        Self::admit_deadline(deadline, now, self.expiry()?)?;
        writer_protocol::measured_envelope(body)?;
        let request_id = header.request_id.clone();
        self.state = WriterState::SignInFlight;
        let reply = self.signer.sign_record(header, body)?;
        if self.now()? > deadline {
            return Err(Error::Deadline);
        }
        // The coalesced heartbeat precedes the completion exchange so a full-budget SIGN cannot exhaust the signer's idle window.
        if self.heartbeat_due()? {
            self.heartbeat()?;
        }
        self.tick()?;
        let end = self
            .now()?
            .checked_add(WRITER_HANDSHAKE_DEADLINE_MS * NS_PER_MS)
            .ok_or(Error::Deadline)?
            .min(self.expiry()?);
        post_wait(end)?;
        self.tick()?;
        if self.frozen.as_ref() != Some(&frozen)
            || reply.request_id != request_id
            || reply.kid != g.kid
        {
            return Err(Error::Grant);
        }
        let pin = serde_json::to_value(g).map_err(|_| Error::Grant)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(&g.public_key)
            .map_err(|_| Error::Signature)?;
        // The returned signature must authenticate the admitted bytes under the bound producer subject and key.
        if !records::verify(body, &reply.signature, &pin, &public_key) {
            return Err(Error::Signature);
        }
        let envelope = writer_protocol::envelope(body, &reply.signature)?;
        self.state = WriterState::EnvelopeVerified;
        Ok(envelope)
    }
    fn sent_verified(&mut self) {
        self.state = WriterState::Granted;
    }
    pub fn settle(&mut self) {
        self.state = WriterState::Settling;
        self.signer.close_and_settle();
        self.state = WriterState::Stopped;
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(signer: P, reconciler: R, boot: String, clock: Clock) -> Result<Self> {
        let bootstrapped_at = clock()?;
        let mut m = Self::new(
            signer,
            reconciler,
            boot,
            clock,
            "fixture".into(),
            1,
            bootstrapped_at,
        );
        m.start()?;
        Ok(m)
    }
    #[cfg(feature = "test-isolation")]
    pub fn captured_wall_for_test(&mut self) -> Result<()> {
        self.bind_wall();
        Ok(())
    }
    #[cfg(feature = "test-isolation")]
    pub fn verified_sent_for_test(&mut self) {
        self.sent_verified();
    }
}
#[cfg_attr(feature = "test-isolation", derive(Deserialize))]
#[cfg_attr(feature = "test-isolation", serde(deny_unknown_fields))]
pub struct ClosurePaths {
    exec: PathBuf,
    status: PathBuf,
    maps: PathBuf,
    self_exe: PathBuf,
    boot_id: PathBuf,
    owner: u32,
    library_owner: u32,
}
impl ClosurePaths {
    pub fn production() -> Self {
        Self {
            exec: writer_peer::WRITER_EXEC.into(),
            status: "/proc/self/status".into(),
            maps: "/proc/self/maps".into(),
            self_exe: "/proc/self/exe".into(),
            boot_id: "/proc/sys/kernel/random/boot_id".into(),
            owner: custody::ROOT_UID,
            library_owner: custody::ROOT_UID,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn isolated(
        exec: PathBuf,
        status: PathBuf,
        maps: PathBuf,
        self_exe: PathBuf,
        boot_id: PathBuf,
        owner: u32,
    ) -> Self {
        Self {
            exec,
            status,
            maps,
            self_exe,
            boot_id,
            owner,
            library_owner: owner,
        }
    }
    #[cfg(feature = "test-isolation")]
    pub fn with_library_owner_for_test(mut self, owner: u32) -> Self {
        self.library_owner = owner;
        self
    }
}
fn trusted_mapping(meta: &fs::Metadata, owner: u32) -> bool {
    meta.is_file() && meta.uid() == owner && meta.mode() & 0o022 == 0
}
fn closure(
    paths: &ClosurePaths,
    config: &HeldConfig,
    environment: &[OsString],
) -> Result<Vec<File>> {
    let status = writer_peer::read_proc(&paths.status)?;
    signer_peer::validate_capability_status(&status, true).map_err(|_| Error::Closure)?;
    if environment
        .iter()
        .any(|key| key.to_string_lossy().starts_with("LD_"))
    {
        return Err(Error::Closure);
    }
    let image = writer_peer::held_artifact(&paths.exec, paths.owner, &config.value.writer_sha256)?;
    let m = image.metadata()?;
    let own = fs::metadata(&paths.self_exe)?;
    if (m.dev(), m.ino()) != (own.dev(), own.ino()) {
        return Err(Error::Closure);
    }
    let text = writer_peer::read_proc(&paths.maps)?;
    let mut seen = BTreeSet::new();
    let mut held = vec![image];
    let mut image_seen = false;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let _address = fields.next().ok_or(Error::Closure)?;
        let perms = fields.next().ok_or(Error::Closure)?;
        let _offset = fields.next().ok_or(Error::Closure)?;
        let device = fields.next().ok_or(Error::Closure)?;
        let inode = fields
            .next()
            .ok_or(Error::Closure)?
            .parse::<u64>()
            .map_err(|_| Error::Closure)?;
        let path = fields.collect::<Vec<_>>().join(" ");
        if path.ends_with(" (deleted)")
            || (inode != 0 && perms.contains('w') && perms.contains('x'))
        {
            return Err(Error::Closure);
        }
        if inode == 0 {
            continue;
        }
        let (major, minor) = device.split_once(':').ok_or(Error::Closure)?;
        let major = u32::from_str_radix(major, 16).map_err(|_| Error::Closure)?;
        let minor = u32::from_str_radix(minor, 16).map_err(|_| Error::Closure)?;
        let identity = (major, minor, inode);
        if seen.contains(&identity) {
            continue;
        }
        if seen.len() >= WRITER_MAPPINGS_MAX {
            return Err(Error::Closure);
        }
        seen.insert(identity);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        let own_image = (meta.dev(), meta.ino()) == (m.dev(), m.ino());
        let owner = if own_image {
            paths.owner
        } else {
            paths.library_owner
        };
        if !trusted_mapping(&meta, owner)
            || libc::major(meta.dev()) != major
            || libc::minor(meta.dev()) != minor
            || meta.ino() != inode
        {
            return Err(Error::Closure);
        }
        image_seen |= own_image;
        held.push(file);
    }
    if !image_seen {
        return Err(Error::Closure);
    }
    config.recheck()?;
    Ok(held)
}
/// Activation metadata is passed explicitly so no test inherits ambient listener authority.
pub struct Activation {
    pub pid: String,
    pub fds: String,
    pub names: String,
}
pub struct Dependencies<P: SignerPort, R: Reconciler, N: Notifier> {
    pub bootstrap: Box<dyn FnOnce() -> Result<P> + Send>,
    pub reconciler: R,
    pub notifier: N,
    pub config: HeldConfig,
    pub bus: BusTarget,
    pub listener: OwnedFd,
    pub expectations: ListenerExpectations,
    pub activation: Activation,
    pub clock: Clock,
    pub paths: ClosurePaths,
    pub environment: Vec<OsString>,
}
/// Owns the sole record lifetime and settles S on every refusal after readiness.
pub fn run<P: SignerPort, R: Reconciler, N: Notifier>(
    mut deps: Dependencies<P, R, N>,
) -> Result<()> {
    let setup = (|| {
        let held = closure(&deps.paths, &deps.config, &deps.environment)?;
        writer_peer::listener(
            deps.listener.as_raw_fd(),
            &deps.expectations,
            &deps.activation.pid,
            &deps.activation.fds,
            &deps.activation.names,
        )?;
        // The boot identity comes from the kernel; the signer cannot supply its own comparison reference.
        let raw = writer_peer::read_proc(&deps.paths.boot_id)?;
        let boot = signer_service::parse_boot_id(raw.as_bytes())?;
        deps.config.recheck()?;
        Ok((held, boot))
    })();
    let (_held, boot) = match setup {
        Ok(v) => v,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=writer refused at start");
            return Err(e);
        }
    };
    // Closure, activation and config admission precede any signer session; execute supplies this required bootstrap.
    let mut signer = match (deps.bootstrap)() {
        Ok(signer) => signer,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=writer refused at start");
            return Err(e);
        }
    };
    // Bootstrap is an external wait; preserve its admission time through the final held-config check and settle any setup refusal.
    let admission = (|| -> Result<u64> {
        let bootstrapped_at = (deps.clock)()?;
        deps.config.recheck()?;
        Ok(bootstrapped_at)
    })();
    let bootstrapped_at = match admission {
        Ok(time) => time,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=writer refused at start");
            signer.close_and_settle();
            return Err(e);
        }
    };
    let mut machine = WriterMachine::new(
        signer,
        deps.reconciler,
        boot,
        deps.clock.clone(),
        deps.config.value.fortress_id.clone(),
        deps.config.value.enrollment_revision,
        bootstrapped_at,
    );
    let ready = match machine.start() {
        Ok(text) => text,
        Err(e) => {
            let _ = deps.notifier.notify("STATUS=writer refused at start");
            machine.settle();
            return Err(e);
        }
    };
    if let Err(e) = deps.notifier.notify(ready) {
        machine.settle();
        return Err(e.into());
    }
    let outcome = serve(
        &mut machine,
        &deps.config,
        &deps.bus,
        &deps.listener,
        &deps.expectations,
        deps.paths.owner,
        &deps.clock,
    );
    // a writer exit with a live wall restarts nothing; the wall stays fail-closed until an operator restarts the wall unit, which starts a fresh writer.
    let _ = deps.notifier.notify(STOP_STATUS);
    let _ = deps.notifier.notify("STOPPING=1");
    machine.settle();
    outcome
}
fn readable(fd: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) > 0 }
}
fn accepted(fd: i32) -> Result<OwnedFd> {
    let raw = unsafe {
        libc::accept4(
            fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::Io);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn exchange_deadline(clock: &Clock, limit: u64) -> Result<Deadline> {
    Ok(Deadline::new(
        clock.clone(),
        clock()?
            .checked_add(WRITER_HANDSHAKE_DEADLINE_MS * NS_PER_MS)
            .ok_or(Error::Deadline)?
            .min(limit),
    )?)
}
fn send(fd: i32, session: &str, op: &Operation, body: &[u8]) -> Result<()> {
    signer_peer::send(
        fd,
        &writer_protocol::encode(Direction::ToWall, session, op, body)?,
        &[],
    )?;
    Ok(())
}
struct Wall {
    fd: OwnedFd,
    binding: WallMainBinding,
    handshake: Handshake,
    session: String,
}
fn serve<P: SignerPort, R: Reconciler>(
    machine: &mut WriterMachine<P, R>,
    config: &HeldConfig,
    bus: &BusTarget,
    listener: &OwnedFd,
    expect: &ListenerExpectations,
    owner: u32,
    clock: &Clock,
) -> Result<()> {
    // One bound wall plus a terminal second accept implements the connection cap in writer_protocol.
    const _: () = assert!(writer_protocol::WRITER_CONNECTIONS_MAX == 2);
    // Synchronous SIGN owns the only work slot; serve retains no queue between iterations.
    const _: () = assert!(writer_protocol::WRITER_WORK_MAX == 1);
    const _: () = assert!(writer_protocol::WRITER_QUEUE_MAX == 0);
    let mut wall: Option<Wall> = None;
    loop {
        machine.tick()?;
        if let Some(w) = &wall {
            if !w.binding.live() {
                return Err(Error::Peer(writer_peer::Error::Process));
            }
        }
        if readable(listener.as_raw_fd()) {
            let fd = accepted(listener.as_raw_fd())?;
            // A second accept is terminal even while the original wall remains alive and its socket stays open.
            if wall.is_some() {
                return Err(Error::State);
            }
            let end = exchange_deadline(clock, u64::MAX)?;
            let binding = WallMainBinding::capture(
                fd.as_raw_fd(),
                &config.value,
                bus,
                expect,
                owner,
                end.clone(),
            )?;
            signer_peer::passcred(fd.as_raw_fd())?;
            let mut bytes = [0; SESSION_ID_BYTES];
            OsRng.try_fill_bytes(&mut bytes).map_err(|_| Error::Io)?;
            let session = hex::encode(bytes);
            let mut handshake = Handshake::new(session.clone())?;
            signer_peer::send(fd.as_raw_fd(), &handshake.hello()?, &[])?;
            loop {
                end.check()?;
                if !binding.live() {
                    return Err(Error::Peer(writer_peer::Error::Process));
                }
                if readable(listener.as_raw_fd()) {
                    let _second = accepted(listener.as_raw_fd())?;
                    return Err(Error::State);
                }
                if readable(fd.as_raw_fd()) {
                    let packet = writer_protocol::receive(fd.as_raw_fd(), Direction::ToWriter)?;
                    binding.packet(&packet)?;
                    binding.revalidate(bus, end.clone())?;
                    handshake.receive(&packet.bytes)?;
                    end.check()?;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(WATCHDOG_TICK_MS as u64));
            }
            machine.bind_wall();
            wall = Some(Wall {
                fd,
                binding,
                handshake,
                session,
            });
        }
        if machine.heartbeat_due()? {
            machine.heartbeat()?;
        }
        if let Some(w) = &mut wall {
            if readable(w.fd.as_raw_fd()) {
                let packet = writer_protocol::receive(w.fd.as_raw_fd(), Direction::ToWriter)?;
                let frame = w.handshake.receive(&packet.bytes)?;
                w.binding.packet(&packet)?;
                let now = clock()?;
                if let Operation::Sign(h) = &frame.operation {
                    let admission = canonical_deadline(&h.deadline_boottime_ns)
                        .ok_or(Error::Deadline)
                        .and_then(|deadline| {
                            WriterMachine::<P, R>::admit_deadline(deadline, now, machine.expiry()?)
                        });
                    if let Err(e) = admission {
                        let _ = send(
                            w.fd.as_raw_fd(),
                            &w.session,
                            &Operation::Refused {
                                request_id: h.request_id.clone(),
                            },
                            &[],
                        );
                        return Err(e);
                    }
                }
                // Packet admission follows a heartbeat check: now - last_status < WRITER_HEARTBEAT_MS.
                // Anchoring to both clocks retains at least WRITER_SIGN_DEADLINE_MAX_MS - WRITER_HEARTBEAT_MS
                // of bus budget; the next heartbeat leaves inside SIGNER_IDLE_DEADLINE_MS of the last exchange.
                // The caller deadline never selects this local identity window.
                let end = now
                    .checked_add(WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS)
                    .ok_or(Error::Deadline)?
                    .min(
                        machine
                            .last_status
                            .checked_add(WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS)
                            .ok_or(Error::Deadline)?,
                    )
                    .min(machine.expiry()?);
                w.binding
                    .revalidate(bus, Deadline::new(clock.clone(), end)?)?;
                match frame.operation {
                    Operation::Status { request_id } => send(
                        w.fd.as_raw_fd(),
                        &w.session,
                        &Operation::StatusReply { request_id },
                        &machine.status_payload().encode()?,
                    )?,
                    Operation::Sign(header) => {
                        let request_id = header.request_id.clone();
                        let result = machine.sign(header, frame.payload, |end| {
                            w.binding
                                .revalidate(bus, Deadline::new(clock.clone(), end)?)?;
                            Ok(())
                        });
                        match result {
                            Ok(body) => {
                                send(
                                    w.fd.as_raw_fd(),
                                    &w.session,
                                    &Operation::Verified { request_id },
                                    &body,
                                )?;
                                machine.sent_verified();
                            }
                            Err(e) => {
                                let _ = send(
                                    w.fd.as_raw_fd(),
                                    &w.session,
                                    &Operation::Refused { request_id },
                                    &[],
                                );
                                return Err(e);
                            }
                        }
                    }
                    _ => return Err(Error::State),
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(WATCHDOG_TICK_MS as u64));
    }
}
#[cfg(feature = "test-isolation")]
pub mod test_support {
    use super::*;
    /// Typed scripting is confined to writer-state witnesses and is not evidence of client parsing.
    pub type BindScript = Box<dyn FnMut(&CurrentGrantView) -> signer_client::Result<()> + Send>;
    pub type SignScript =
        Box<dyn FnMut(Header, &[u8]) -> signer_client::Result<SignedReply> + Send>;
    pub struct ScriptedSigner {
        pub initial: StatusReply,
        pub status: Box<dyn FnMut() -> signer_client::Result<StatusReply> + Send>,
        pub bind: BindScript,
        pub sign: SignScript,
        pub close: Box<dyn FnMut() + Send>,
    }
    impl SignerPort for ScriptedSigner {
        fn initial_status(&self) -> StatusReply {
            self.initial.clone()
        }
        fn status(&mut self) -> signer_client::Result<StatusReply> {
            (self.status)()
        }
        fn bind(&mut self, v: &CurrentGrantView) -> signer_client::Result<()> {
            (self.bind)(v)
        }
        fn sign_record(&mut self, h: Header, b: &[u8]) -> signer_client::Result<SignedReply> {
            (self.sign)(h, b)
        }
        fn close_and_settle(&mut self) {
            (self.close)();
        }
    }
    pub struct TestReconciler {
        pub reconcile: Box<dyn FnMut(ReconcileEvidence<'_>) -> Reconciliation + Send>,
    }
    impl Reconciler for TestReconciler {
        fn reconcile(&mut self, e: ReconcileEvidence<'_>) -> Reconciliation {
            (self.reconcile)(e)
        }
    }
    pub fn mapping_owner(path: &Path, owner: u32) -> Result<()> {
        if trusted_mapping(&fs::metadata(path)?, owner) {
            Ok(())
        } else {
            Err(Error::Closure)
        }
    }
    pub fn closure_check(
        paths: &ClosurePaths,
        config: &HeldConfig,
        environment: &[OsString],
    ) -> Result<()> {
        closure(paths, config, environment).map(|_| ())
    }
}

impl Activation {
    pub fn environment() -> io::Result<Self> {
        Ok(Self {
            pid: std::env::var("LISTEN_PID").map_err(|_| custody::refused())?,
            fds: std::env::var("LISTEN_FDS").map_err(|_| custody::refused())?,
            names: std::env::var("LISTEN_FDNAMES").map_err(|_| custody::refused())?,
        })
    }
}

#[cfg(feature = "test-isolation")]
pub const WRITER_TEST_SEAM_MARKER: &str = "SANCTUARY_WRITER_TEST_ISOLATION_V1";
#[cfg(feature = "test-isolation")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSeam {
    config: PathBuf,
    exec: PathBuf,
    status: PathBuf,
    maps: PathBuf,
    self_exe: PathBuf,
    boot_id: PathBuf,
    bus: BusTarget,
    listener: ListenerExpectations,
    artifact_owner: u32,
    library_owner: u32,
    signer_socket: PathBuf,
}
#[cfg(feature = "test-isolation")]
pub fn test_entry(path: &Path) -> io::Result<()> {
    let setup = (|| {
        let bytes = custody::read_pinned(
            path,
            unsafe { libc::geteuid() },
            custody::CONFIG_MAX_BYTES,
            custody::PRIVATE_MODE,
        )?;
        let seam: TestSeam = serde_json::from_slice(&bytes).map_err(|_| custody::refused())?;
        let config = HeldConfig::isolated(&seam.config, seam.artifact_owner)
            .map_err(|_| custody::refused())?;
        let policy = config.value.signer.clone();
        if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
            return Err(custody::refused());
        }
        Ok(Dependencies {
            bootstrap: Box::new(move || {
                Ok(ClientSignerPort::bootstrap_at(&seam.signer_socket, policy)?)
            }),
            reconciler: ClosedReconciler::production(),
            notifier: SystemNotifier,
            config,
            bus: seam.bus,
            listener: unsafe { OwnedFd::from_raw_fd(3) },
            expectations: seam.listener,
            activation: Activation::environment()?,
            clock: std::sync::Arc::new(super::signer_watchdog::boottime_ns),
            paths: ClosurePaths::isolated(
                seam.exec,
                seam.status,
                seam.maps,
                seam.self_exe,
                seam.boot_id,
                seam.artifact_owner,
            )
            .with_library_owner_for_test(seam.library_owner),
            environment: std::env::vars_os().map(|(k, _)| k).collect(),
        })
    })();
    match setup {
        Ok(deps) => run(deps).map_err(|_| custody::refused()),
        Err(e) => {
            let _ = SystemNotifier.notify("STATUS=writer refused at start");
            Err(e)
        }
    }
}
