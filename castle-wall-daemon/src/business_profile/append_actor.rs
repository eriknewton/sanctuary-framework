//! One wall owner separates durable settlement from live effect eligibility.
use super::{
    append_budget::{self, AppendWindow, CutObligation, HExpiry, ProducerExpiry, RecheckInputs},
    append_clients::{
        CommitHold, DrainClient, DrainObservation, DrainReply, FrozenMutation, WriterClient,
        WriterReply,
    },
    business_wal::{BusinessSequence, DeliveryToken, Pool, Refusal, Result, TsReleaseFact},
    drain_protocol,
    effect_permit::{EffectIntent, EffectPermit, EffectSink, MarkerCompletion},
    records,
    signer_service::Header,
    wal_executor::{Operation, Output, WalExecutor},
    writer_peer::{Clock, NS_PER_MS},
    writer_protocol::{self, StatusPayload},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Independently observed local policy and H completion evidence, never decoded from B or E.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEvidence {
    pub h_expiry_ns: u64,
    pub policy_digest: String,
    pub runtime_digest: String,
    pub config_digest: String,
}
/// Required composition evidence provider must re-read its held configuration and H observation.
pub trait EvidenceSource: Send {
    fn observe(&mut self) -> Result<LocalEvidence>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Handshake,
    CheckpointQuery,
    CheckpointRead,
    CheckpointReport,
    CheckpointAck,
    Checking,
    Ready,
    Disk,
    Reserve,
    Sign,
    Commit,
    Original,
    Held,
    DeliveryRead,
    StartupDeliveryRead,
    CommittedDeliveryRead,
    CommittedDeliveryReady,
    Compacting,
    DeliveryFact,
    SettlementRead,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Ready,
    Reserve,
    SignMarker,
    Sign,
    CommitFreeze,
    CommitSend,
    Confirm,
    EffectMarker,
    Deliver,
    Original,
    Refresh,
}
struct Intent {
    id: String,
    body: Vec<u8>,
    envelope: Option<Vec<u8>>,
    reserve: FrozenMutation,
    commit: Option<FrozenMutation>,
    window: AppendWindow,
    status: StatusPayload,
    local: LocalEvidence,
    effect: Option<EffectIntent>,
    eligible: bool,
    sequence: BusinessSequence,
    marker: Option<MarkerCompletion>,
    cut: Option<([u8; 16], u64)>,
}
/// Isolated count observations exercise W's boundary without fabricating live joins or D authority.
#[cfg(feature = "test-isolation")]
#[derive(Clone, Copy)]
pub struct PendingCount(u64);
#[cfg(feature = "test-isolation")]
impl PendingCount {
    /// The count is bounded by D's protocol ceiling and never alters an authenticated anchor.
    pub fn checked(count: u64) -> Option<Self> {
        (count <= super::drain_store::D_UNDRAINED_MAX as u64).then_some(Self(count))
    }
}
/// A fixture consumes each observed exact envelope without receiving append authority.
#[cfg(feature = "test-isolation")]
pub type VerifiedObserver = Box<dyn FnMut(&[u8]) + Send>;
/// Isolated observers expose the boundaries after each independent equality, without changing WAL validation.
#[cfg(feature = "test-isolation")]
pub struct VerifiedObservers {
    pub after_client: VerifiedObserver,
    pub after_actor: VerifiedObserver,
    pub actor_reply: Option<Vec<u8>>,
}
/// An isolated observation changes one relying-party input at one completed wait.
#[cfg(feature = "test-isolation")]
pub struct TestObservations {
    point: ObservationPoint,
    field: ObservationField,
    observed: Option<std::path::PathBuf>,
    trace: Option<std::path::PathBuf>,
    probe_sent: bool,
}
#[cfg(feature = "test-isolation")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationFixture {
    point: ObservationPoint,
    field: ObservationField,
}
#[cfg(feature = "test-isolation")]
#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]
enum ObservationPoint {
    Reserve,
    SignMarker,
    Sign,
    CommitFreeze,
    CommitSend,
    Confirm,
    EffectMarker,
    Deliver,
    Original,
    Refresh,
    Ready,
}
#[cfg(feature = "test-isolation")]
#[derive(Clone, Copy, serde::Deserialize)]
enum ObservationField {
    Policy,
    Runtime,
    Config,
    H,
    Status,
    Grant,
    MissingGrant,
    LeaseId,
    Lease,
    Certain,
    Latch,
    WriterTransport,
    WriterProcess,
    WriterDevice,
    WriterInode,
    WriterLiveness,
    DrainProcess,
    DrainDevice,
    DrainInode,
    DrainLiveness,

    DrainTransport,
    PermitTime,
    WindowBudget,
    WindowGrant,
    WindowProducer,
    WindowH,
    Trace,
    AppendIdentity,
    AppendReplay,
    CommitIdentity,
    CommitReplay,
    MarkerSequence,
    MarkerCommitment,
    MarkerEnvelope,
    Anchor,
    Role,
    Epoch,
    PublicKey,
    Kid,
    Identity,
    Machine,
    Activation,
    Started,
    Expires,
    AnchorRevision,
    AnchorDigest,
    State,
    Absent,

    CasIdentity,
    SendSecondEnvelope,
    ReserveRefused,
    ReserveMissing,
    ReserveWrongId,
    ReserveUncertain,
    ReserveSuperseding,
}
#[cfg(feature = "test-isolation")]
impl TestObservations {
    /// Read a private bounded fixture; callers cannot construct a dependency from unchecked fields.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let bytes = super::custody::read_pinned(
            path,
            unsafe { libc::geteuid() },
            super::custody::CONFIG_MAX_BYTES,
            super::custody::PRIVATE_MODE,
        )?;
        let value: ObservationFixture =
            serde_json::from_slice(&bytes).map_err(|_| super::custody::refused())?;
        Ok(Self {
            point: value.point,
            field: value.field,
            observed: Some(path.with_extension("observed")),
            trace: Some(path.with_extension("trace")),
            probe_sent: false,
        })
    }
    fn trace_path(&self, extension: &str) -> Option<std::path::PathBuf> {
        matches!(
            self.field,
            ObservationField::Trace | ObservationField::SendSecondEnvelope
        )
        .then(|| self.trace.as_ref().map(|p| p.with_extension(extension)))
        .flatten()
    }
    fn applies(&self, next: Next) -> bool {
        let point = match next {
            Next::Reserve => ObservationPoint::Reserve,
            Next::SignMarker => ObservationPoint::SignMarker,
            Next::Sign => ObservationPoint::Sign,
            Next::CommitFreeze => ObservationPoint::CommitFreeze,
            Next::CommitSend => ObservationPoint::CommitSend,
            Next::Confirm => ObservationPoint::Confirm,
            Next::EffectMarker => ObservationPoint::EffectMarker,
            Next::Deliver => ObservationPoint::Deliver,
            Next::Original => ObservationPoint::Original,
            Next::Refresh => ObservationPoint::Refresh,
            Next::Ready => ObservationPoint::Ready,
        };
        self.point == point
    }
    fn record(&mut self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(path) = self.observed.take() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(super::custody::PRIVATE_MODE)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| Refusal::Io)?;
        }
        Ok(())
    }
}
/// Every dependency is required; absence never selects an accepting fallback.
pub struct Dependencies {
    pub writer: WriterClient,
    pub drain: DrainClient,
    pub store: WalExecutor,
    pub clock: Clock,
    pub evidence: Box<dyn EvidenceSource>,
    pub sink: Box<dyn EffectSink>,
    pub fortress: String,
    pub revision: u64,
}
/// Owns one append, one disk operation and one bounded checkpoint exchange.
pub struct AppendActor {
    dependencies: Dependencies,
    state: State,
    next: Next,
    disk: Option<u64>,
    intent: Option<Intent>,
    status: Option<StatusPayload>,
    drain: Option<DrainObservation>,
    checkpoint: Option<super::append_clients::CheckpointChallenge>,
    serial: u64,
    cut: CutObligation,
    cut_closed: bool,
    commit_hold: Option<CommitHold>,
    resume_after_disk: bool,
    cut_window: Option<AppendWindow>,
    #[cfg(feature = "test-isolation")]
    pending_count: Option<PendingCount>,
    #[cfg(feature = "test-isolation")]
    verified_observers: Option<VerifiedObservers>,
    #[cfg(feature = "test-isolation")]
    observations: Option<TestObservations>,
    delivery: Option<(BusinessSequence, DeliveryToken)>,
    delivery_resume: Option<(State, Next)>,
    delivery_fact: Option<std::sync::Arc<TsReleaseFact>>,
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    crate::smb::jcs::encode(value)
        .map(String::into_bytes)
        .map_err(|_| Refusal::Shape)
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
pub(crate) fn mutation(
    id: &str,
    operation: &str,
    expected: &Value,
    next: &Value,
    body: &[u8],
    envelope: &[u8],
) -> Result<FrozenMutation> {
    let message = canonical(
        &json!({"version":1,"op":operation,"request_id":id,"expected":expected,"next":next,"body_digest":digest(body)}),
    )?;
    let mut header = drain_protocol::header("ANCHOR", id, drain_protocol::DRAIN_SLOTS[0].1);
    // Must match DrainClient::mutation and D's exact COMMIT framing; E is never reconstructed from B.
    header["message_length"] = json!(message.len());
    header["envelope_length"] = json!(envelope.len());
    FrozenMutation::checked(
        drain_protocol::encode(
            &header,
            &[message.as_slice(), envelope].concat(),
            drain_protocol::Direction::ToDrain,
        )
        .map_err(|_| Refusal::Shape)?,
    )
    .map_err(|_| Refusal::Shape)
}
impl AppendActor {
    /// The supplied store must have completed its Open operation before this constructor is used.
    pub fn new(dependencies: Dependencies) -> Result<Self> {
        if dependencies.store.owned()
            || dependencies.fortress.len() != 32
            || dependencies.revision == 0
        {
            return Err(Refusal::Held);
        }
        Ok(Self {
            dependencies,
            state: State::Handshake,
            next: Next::Ready,
            disk: None,
            intent: None,
            status: None,
            drain: None,
            checkpoint: None,
            serial: 1,
            cut: CutObligation::default(),
            cut_closed: false,
            commit_hold: None,
            resume_after_disk: false,
            cut_window: None,
            #[cfg(feature = "test-isolation")]
            pending_count: None,
            #[cfg(feature = "test-isolation")]
            verified_observers: None,
            #[cfg(feature = "test-isolation")]
            observations: None,
            delivery: None,
            delivery_resume: None,
            delivery_fact: None,
        })
    }
    /// State is observational; only Ready permits a new admission.
    pub fn state(&self) -> State {
        self.state
    }
    /// The token remains owned while the trusted consumer is absent, without holding the store slot.
    pub fn pending_delivery(&self) -> Option<&DeliveryToken> {
        self.delivery.as_ref().map(|(_, token)| token)
    }
    /// The delivery pump transfers one fact only when this actor can own its disk operation.
    pub fn can_complete_delivery(&self) -> bool {
        // Must match BusinessDelivery::pump: no consumed fact may be lost behind another disk owner.
        self.delivery.is_some()
            && self.delivery_resume.is_none()
            && !self.dependencies.store.owned()
            // Evaluate eligible effect recheck replies without interposing a disk wait.
            && !(self.state == State::Checking
                && self.intent.as_ref().is_some_and(|i| i.eligible && i.effect.is_some()))
            && matches!(
                self.state,
                State::Ready | State::Checking | State::CommittedDeliveryReady
            )
    }
    /// Persist a sealed consumer fact independently of ORIGINAL, retaining its token through readback.
    pub fn complete_delivery(&mut self, fact: &mut Option<TsReleaseFact>) -> Result<()> {
        if !self.can_complete_delivery() {
            return Err(Refusal::Held);
        }
        // Check the clock before taking the capability; submit failure must return the same fact.
        let now = self.now()?;
        let deadline = self.limit(now)?;
        if now >= deadline {
            return Err(Refusal::Deadline);
        }
        let sequence = self.delivery.as_ref().ok_or(Refusal::Missing)?.0;
        let resume = (self.state, self.next);
        let retained = std::sync::Arc::new(fact.take().ok_or(Refusal::Missing)?);
        let operation = Operation::TsFact {
            sequence,
            fact: retained.clone(),
        };
        match self.dependencies.store.submit(operation, now, deadline) {
            Ok(id) => self.disk = Some(id),
            Err(error) => {
                *fact = std::sync::Arc::try_unwrap(retained).ok();
                return Err(error);
            }
        }
        self.delivery_fact = Some(retained);
        self.delivery_resume = Some(resume);
        self.state = State::DeliveryFact;
        Ok(())
    }
    /// The pump recovers the one failed fact only after the worker has released its reference.
    pub fn take_failed_delivery(&mut self) -> Option<TsReleaseFact> {
        if self.delivery_resume.is_some() || self.dependencies.store.owned() {
            return None;
        }
        let fact = self.delivery_fact.take()?;
        match std::sync::Arc::try_unwrap(fact) {
            Ok(fact) => Some(fact),
            Err(fact) => {
                self.delivery_fact = Some(fact);
                None
            }
        }
    }
    /// Isolated observers can inspect ownership without obtaining a capability or modifying the state machine.
    #[cfg(feature = "test-isolation")]
    pub fn ownership_for_test(&self) -> (bool, bool, bool) {
        (
            self.intent.is_some(),
            self.dependencies.store.owned(),
            self.intent.as_ref().is_some_and(|i| i.envelope.is_some()),
        )
    }
    /// Isolated schedules replace only the independently observed local evidence source.
    #[cfg(feature = "test-isolation")]
    pub fn evidence_for_test(&mut self, source: Box<dyn EvidenceSource>) {
        self.dependencies.evidence = source;
    }
    /// A refused effect retains a bounded obligation; only a matching committed control discharges it.
    pub fn pending_cut(&self) -> Option<([u8; 16], u64)> {
        self.cut.pending()
    }
    fn retain_cut(&mut self) {
        let status = self
            .intent
            .as_ref()
            .map(|i| &i.status)
            .or(self.status.as_ref());
        if let Some(grant) = status.and_then(|s| s.grant.as_ref()) {
            if let Ok(bytes) = hex::decode(&grant.lease_id) {
                if let Ok(id) = bytes.try_into() {
                    // Overflow or another grant never replaces the already owned obligation.
                    if !self.cut.retain(id, 1) {
                        self.cut_closed = true;
                    }
                }
            }
        }
    }
    /// Install bounded fixture observations; the optional reply replaces only the actor's received input.
    #[cfg(feature = "test-isolation")]
    pub fn verified_observers_for_test(&mut self, observers: VerifiedObservers) -> Result<()> {
        if observers
            .actor_reply
            .as_ref()
            .is_some_and(|bytes| writer_protocol::decode_envelope(bytes).is_err())
        {
            return Err(Refusal::Shape);
        }
        self.verified_observers = Some(observers);
        Ok(())
    }
    /// Inspect the most recent authenticated D view without creating authority.
    #[cfg(feature = "test-isolation")]
    pub fn drain_observation_for_test(&self) -> Option<Value> {
        self.drain.as_ref().map(DrainObservation::value)
    }
    /// Observe the named continuation without changing its owner or state.
    #[cfg(feature = "test-isolation")]
    pub fn continuation_for_test(&self) -> &'static str {
        match self.next {
            Next::CommitSend => "CommitSend",
            Next::Confirm => "Confirm",
            Next::EffectMarker => "EffectMarker",
            Next::Reserve => "Reserve",
            _ => "other",
        }
    }
    /// Attach the sealed settlement fixture to the real D client.
    #[cfg(feature = "test-isolation")]
    pub fn settlement_fixture_for_test(
        &mut self,
        fixture: super::append_clients::SettlementFixture,
    ) -> Result<()> {
        self.dependencies
            .drain
            .settlement_fixture_for_test(fixture)
            .map_err(|_| Refusal::Held)
    }
    /// Inspect the frozen COMMIT request without changing its identity or granting retry authority.
    #[cfg(feature = "test-isolation")]
    pub fn commit_for_test(&self) -> Option<&FrozenMutation> {
        self.intent.as_ref().and_then(|i| i.commit.as_ref())
    }
    /// Override only W's typed pending-count input; all peer and WAL checks remain active.
    #[cfg(feature = "test-isolation")]
    pub fn pending_count_for_test(&mut self, count: PendingCount) {
        self.pending_count = Some(count);
    }
    /// Install a sealed single-observation fixture before admitting an append.
    #[cfg(feature = "test-isolation")]
    pub fn observations_for_test(&mut self, mut observations: TestObservations) {
        use super::append_clients::ReserveReplyObservation as Reply;
        let reply = match observations.field {
            ObservationField::ReserveRefused => Some(Reply::Refused),
            ObservationField::ReserveMissing => Some(Reply::Missing),
            ObservationField::ReserveWrongId => Some(Reply::WrongId),
            ObservationField::ReserveUncertain => Some(Reply::Uncertain),
            ObservationField::ReserveSuperseding => Some(Reply::Superseding),
            _ => None,
        };
        if let Some(reply) = reply {
            self.dependencies
                .drain
                .reserve_reply_for_test(reply, observations.observed.take());
        }
        self.observations = Some(observations);
    }
    fn ordinary_room(&self, observation: &DrainObservation) -> bool {
        #[cfg(feature = "test-isolation")]
        if let Some(count) = self.pending_count {
            return observation.ordinary_room()
                && count.0 < super::drain_store::D_UNDRAINED_MAX as u64;
        }
        observation.ordinary_room()
    }
    fn now(&self) -> Result<u64> {
        (self.dependencies.clock)().map_err(|_| Refusal::Deadline)
    }
    fn id(&mut self) -> Result<String> {
        let id = format!("{:032x}", self.serial);
        self.serial = self.serial.checked_add(1).ok_or(Refusal::Capacity)?;
        Ok(id)
    }
    fn limit(&self, now: u64) -> Result<u64> {
        let local = now
            .checked_add(drain_protocol::D_REQUEST_DEADLINE_MS as u64 * NS_PER_MS)
            .ok_or(Refusal::Deadline)?;
        // Settlement can continue after eligibility expires, but never renews the original append window.
        Ok(self
            .intent
            .as_ref()
            .filter(|i| i.eligible)
            .map_or(local, |i| local.min(i.window.deadline_ms() * NS_PER_MS)))
    }
    fn disk(&mut self, operation: Operation, next: Next) -> Result<()> {
        let now = self.now()?;
        self.disk = Some(
            self.dependencies
                .store
                .submit(operation, now, self.limit(now)?)?,
        );
        self.next = next;
        self.state = State::Disk;
        Ok(())
    }
    fn check(&mut self, next: Next) -> Result<()> {
        let now = self.now()?;
        let limit = self.limit(now)?;
        let p = self.id()?;
        let d = self.id()?;
        self.status = None;
        self.drain = None;
        // A failed D send can leave the already owned STATUS outstanding; never overlap or replace that request.
        if !self.dependencies.writer.status_pending() {
            self.dependencies
                .writer
                .status(&p, limit)
                .map_err(|_| Refusal::Held)?;
        }
        self.dependencies
            .drain
            .read(&d, limit)
            .map_err(|_| Refusal::Held)?;
        self.next = next;
        self.state = State::Checking;
        Ok(())
    }
    fn independent(&mut self, now: u64) -> Result<bool> {
        #[cfg(feature = "test-isolation")]
        if let Some(observation) = self
            .observations
            .as_mut()
            .filter(|o| self.intent.is_some() && o.applies(self.next))
        {
            use super::append_clients::TransportObservation as Transport;
            observation.record()?;
            match observation.field {
                ObservationField::WriterProcess => self
                    .dependencies
                    .writer
                    .transport_observation_for_test(Transport::Process),
                ObservationField::WriterDevice => self
                    .dependencies
                    .writer
                    .transport_observation_for_test(Transport::Device),
                ObservationField::WriterInode => self
                    .dependencies
                    .writer
                    .transport_observation_for_test(Transport::Inode),
                ObservationField::WriterLiveness => self
                    .dependencies
                    .writer
                    .transport_observation_for_test(Transport::Liveness),
                ObservationField::DrainProcess => self
                    .dependencies
                    .drain
                    .transport_observation_for_test(Transport::Process),
                ObservationField::DrainDevice => self
                    .dependencies
                    .drain
                    .transport_observation_for_test(Transport::Device),
                ObservationField::DrainInode => self
                    .dependencies
                    .drain
                    .transport_observation_for_test(Transport::Inode),
                ObservationField::DrainLiveness => self
                    .dependencies
                    .drain
                    .transport_observation_for_test(Transport::Liveness),
                _ => {}
            }
        }
        let writer_transport = self.dependencies.writer.recheck_transport().is_ok();
        let drain_transport = self.dependencies.drain.recheck_transport().is_ok();
        #[cfg(feature = "test-isolation")]
        let (writer_transport, drain_transport) = {
            let observation = self
                .observations
                .as_mut()
                .filter(|o| self.intent.is_some() && o.applies(self.next));
            if let Some(observation) = observation {
                observation.record()?;
                (
                    writer_transport
                        && !matches!(observation.field, ObservationField::WriterTransport),
                    drain_transport
                        && !matches!(observation.field, ObservationField::DrainTransport),
                )
            } else {
                (writer_transport, drain_transport)
            }
        };
        // Each pinned transport is independent evidence; neither peer can vouch for the other's liveness.
        if !writer_transport || !drain_transport {
            return Err(Refusal::Authority);
        }
        let local = self.dependencies.evidence.observe()?;
        let status = self.status.as_ref().ok_or(Refusal::Held)?;
        let d = self.drain.as_ref().ok_or(Refusal::Held)?;
        let value = d.value();
        let lease_live = self.dependencies.drain.lease_live(now);
        #[cfg(feature = "test-isolation")]
        let (local, status, value, lease_live) = {
            let mut local = local;
            let mut status = status.clone();
            let mut value = value;
            let mut lease_live = lease_live;
            if self.intent.is_some() {
                if let Some(observation) =
                    self.observations.as_mut().filter(|o| o.applies(self.next))
                {
                    observation.record()?;
                    match observation.field {
                        ObservationField::Policy => local.policy_digest.push('x'),
                        ObservationField::Runtime => local.runtime_digest.push('x'),
                        ObservationField::Config => local.config_digest.push('x'),
                        ObservationField::H => local.h_expiry_ns ^= 1,
                        ObservationField::Status => status.boot_id.push('x'),
                        ObservationField::Grant => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.generation += 1;
                            }
                        }
                        ObservationField::MissingGrant => status.grant = None,
                        ObservationField::LeaseId => {
                            if let Some(grant) = status.grant.as_mut() {
                                let mut id =
                                    hex::decode(&grant.lease_id).map_err(|_| Refusal::Shape)?;
                                id[0] ^= 1;
                                grant.lease_id = hex::encode(id);
                            }
                        }
                        ObservationField::Role => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.role.push('x');
                            }
                        }
                        ObservationField::PublicKey => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.public_key.push('x');
                            }
                        }
                        ObservationField::Kid => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.kid.push('x');
                            }
                        }
                        ObservationField::Identity => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.identity_id.push('x');
                            }
                        }
                        ObservationField::Machine => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.machine_id.push('x');
                            }
                        }
                        ObservationField::Activation => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.activation_id.push('x');
                            }
                        }
                        ObservationField::Epoch => {
                            if let Some(grant) = status.grant.as_mut() {
                                grant.epoch += 1;
                            }
                        }
                        ObservationField::Started => {
                            status.started_boottime_ns = (status
                                .started_boottime_ns
                                .parse::<u64>()
                                .map_err(|_| Refusal::Shape)?
                                ^ 1)
                            .to_string()
                        }
                        ObservationField::Expires => {
                            status.expires_boottime_ns = (status
                                .expires_boottime_ns
                                .parse::<u64>()
                                .map_err(|_| Refusal::Shape)?
                                ^ 1)
                            .to_string()
                        }
                        ObservationField::AnchorRevision => {
                            status.anchor_revision = status.anchor_revision.map(|v| v + 1)
                        }
                        ObservationField::AnchorDigest => {
                            status.anchor_digest = Some("sha256:".to_owned() + &"f".repeat(64))
                        }
                        ObservationField::State => status.state = "LOCKING".into(),
                        ObservationField::Absent => value["state"] = json!("ABSENT"),
                        ObservationField::Lease => lease_live = false,
                        ObservationField::Certain => value["uncertain"] = json!(true),
                        ObservationField::Latch => value["latched"] = json!(true),
                        ObservationField::WriterProcess
                        | ObservationField::WriterDevice
                        | ObservationField::WriterInode
                        | ObservationField::WriterLiveness
                        | ObservationField::DrainProcess
                        | ObservationField::DrainDevice
                        | ObservationField::DrainInode
                        | ObservationField::DrainLiveness
                        | ObservationField::WriterTransport
                        | ObservationField::DrainTransport
                        | ObservationField::CasIdentity
                        | ObservationField::SendSecondEnvelope
                        | ObservationField::AppendIdentity
                        | ObservationField::AppendReplay
                        | ObservationField::CommitIdentity
                        | ObservationField::CommitReplay
                        | ObservationField::Trace
                        | ObservationField::MarkerSequence
                        | ObservationField::MarkerCommitment
                        | ObservationField::MarkerEnvelope
                        | ObservationField::WindowBudget
                        | ObservationField::WindowGrant
                        | ObservationField::WindowProducer
                        | ObservationField::WindowH
                        | ObservationField::PermitTime
                        | ObservationField::Anchor
                        | ObservationField::ReserveRefused
                        | ObservationField::ReserveMissing
                        | ObservationField::ReserveWrongId
                        | ObservationField::ReserveUncertain
                        | ObservationField::ReserveSuperseding => {}
                    }
                }
            }
            (local, status, value, lease_live)
        };
        #[cfg(feature = "test-isolation")]
        let status = &status;
        if !lease_live
            || value["state"] != "PRESENT"
            || value["uncertain"] != false
            || value["latched"] != false
        {
            return Ok(false);
        }
        let Some(intent) = self.intent.as_ref() else {
            return Ok(status.grant.is_some());
        };
        // ProducerExpiry in append_budget.rs requires this concrete grant, which must stay paired with complete-status absent-grant equality below.
        let grant = status.grant.as_ref().ok_or(Refusal::Authority)?;
        let id: [u8; 16] = hex::decode(&grant.lease_id)
            .map_err(|_| Refusal::Shape)?
            .try_into()
            .map_err(|_| Refusal::Shape)?;
        let Some(producer) = ProducerExpiry::checked(
            id,
            status
                .expires_boottime_ns
                .parse::<u64>()
                .map_err(|_| Refusal::Shape)?
                / NS_PER_MS,
            now / NS_PER_MS,
        ) else {
            return Ok(false);
        };
        let Some(h) = HExpiry::checked(local.h_expiry_ns / NS_PER_MS, now / NS_PER_MS) else {
            return Ok(false);
        };
        // The u64 nanosecond clock becomes milliseconds here; this range and the bounded remaining cost must stay paired with append_budget.rs::BudgetSnapshot::recheck's checked addition.
        let Some(input) = RecheckInputs::checked(now / NS_PER_MS, producer, h) else {
            return Ok(false);
        };
        // P's complete status, independently held local digests, H and original window are separate relying predicates.
        let remaining = match self.next {
            Next::Reserve => {
                3 * drain_protocol::D_REQUEST_DEADLINE_MS as u64
                    + writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS
                    + super::signer_contract::LINUX_RECORD_DURABILITY_DEADLINE_MS as u64
            }
            Next::SignMarker | Next::Sign => {
                2 * drain_protocol::D_REQUEST_DEADLINE_MS as u64
                    + writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS
                    + super::signer_contract::LINUX_RECORD_DURABILITY_DEADLINE_MS as u64
            }
            Next::CommitFreeze | Next::CommitSend => {
                2 * drain_protocol::D_REQUEST_DEADLINE_MS as u64
            }
            _ => 0,
        };
        #[cfg(feature = "test-isolation")]
        let input = if let Some(observation) =
            self.observations.as_ref().filter(|o| o.applies(self.next))
        {
            let observed = match observation.field {
                ObservationField::WindowBudget if remaining > 0 => {
                    intent.window.deadline_ms().saturating_sub(remaining) + 1
                }
                ObservationField::WindowBudget => intent.window.deadline_ms(),
                _ => now / NS_PER_MS,
            };
            let mut observed_id = id;
            if matches!(observation.field, ObservationField::WindowGrant) {
                observed_id[0] ^= 1;
            }
            let producer_end = status
                .expires_boottime_ns
                .parse::<u64>()
                .map_err(|_| Refusal::Shape)?
                / NS_PER_MS
                + u64::from(matches!(
                    observation.field,
                    ObservationField::WindowProducer
                ));
            let h_end = local.h_expiry_ns / NS_PER_MS
                + u64::from(matches!(observation.field, ObservationField::WindowH));
            RecheckInputs::checked(
                observed,
                ProducerExpiry::checked(observed_id, producer_end, observed)
                    .ok_or(Refusal::Deadline)?,
                HExpiry::checked(h_end, observed).ok_or(Refusal::Deadline)?,
            )
            .ok_or(Refusal::Deadline)?
        } else {
            input
        };
        // Lease-id equality is dominated by append_budget.rs::BudgetSnapshot::recheck's consumed identity; changing that guard reopens this predicate's evidence obligation.
        // Absent-grant equality is dominated by the concrete ProducerExpiry type in append_budget.rs; changing its grant requirement reopens this predicate's evidence obligation.
        Ok(status == &intent.status
            && local.h_expiry_ns == intent.local.h_expiry_ns
            && local.policy_digest == intent.local.policy_digest
            && local.runtime_digest == intent.local.runtime_digest
            && local.config_digest == intent.local.config_digest
            && intent.window.recheck(input, remaining))
    }
    /// Admission freezes W's own exact canonical body and a separately supplied matching effect intent.
    pub fn begin(
        &mut self,
        body: Vec<u8>,
        effect: Option<EffectIntent>,
        caller_end: u64,
        flows: u64,
    ) -> Result<()> {
        if self.state != State::Ready || self.intent.is_some() || self.dependencies.store.owned() {
            return Err(Refusal::Held);
        }
        let is_control = records::decode(&body).is_some_and(|b| b["record_kind"] == "control");
        let result = self.begin_inner(body, effect, caller_end, flows);
        if result.is_err() && !is_control {
            self.retain_cut();
        }
        result
    }
    fn begin_inner(
        &mut self,
        body: Vec<u8>,
        effect: Option<EffectIntent>,
        caller_end: u64,
        flows: u64,
    ) -> Result<()> {
        if self.cut_closed {
            return Err(Refusal::Held);
        }
        let now = self.now()?;
        if !self.independent(now)? {
            return Err(Refusal::Authority);
        }
        let d = self.drain.as_ref().ok_or(Refusal::Held)?;
        if !self.ordinary_room(d) {
            return Err(Refusal::Capacity);
        }
        let status = self.status.as_ref().ok_or(Refusal::Held)?.clone();
        let grant = status.grant.as_ref().ok_or(Refusal::Authority)?;
        let local = self.dependencies.evidence.observe()?;
        let expiry = status
            .expires_boottime_ns
            .parse::<u64>()
            .map_err(|_| Refusal::Shape)?;
        let id: [u8; 16] = hex::decode(&grant.lease_id)
            .map_err(|_| Refusal::Shape)?
            .try_into()
            .map_err(|_| Refusal::Shape)?;
        let input = RecheckInputs::checked(
            now / NS_PER_MS,
            ProducerExpiry::checked(id, expiry / NS_PER_MS, now / NS_PER_MS)
                .ok_or(Refusal::Deadline)?,
            HExpiry::checked(local.h_expiry_ns / NS_PER_MS, now / NS_PER_MS)
                .ok_or(Refusal::Deadline)?,
        )
        .ok_or(Refusal::Deadline)?;
        if self.cut.pending().is_some() && self.cut_window.is_none() {
            return Err(Refusal::Held);
        }
        if self.cut_window.is_none() {
            // A failed admission retains this consumed snapshot; control completion cannot restart its clock.
            self.cut_window = Some(
                append_budget::admit(input, flows)
                    .and_then(|b| b.begin_append(now / NS_PER_MS, caller_end / NS_PER_MS))
                    .ok_or(Refusal::Deadline)?,
            );
        }
        let parsed = records::decode(&body).ok_or(Refusal::Shape)?;
        let cut = self.cut.pending();
        if let Some((owner, count)) = cut {
            // A pending refusal permits only an independently authorized control, never the failed effect.
            if owner != id
                || effect.is_some()
                || parsed["record_kind"] != "control"
                || parsed["payload"]["type"] != "activation_stop"
                || parsed["payload"]["unresolved_flows"] != count
            {
                return Err(Refusal::Held);
            }
        }
        if !self
            .cut_window
            .as_ref()
            .ok_or(Refusal::Held)?
            .recheck(input, append_budget::APPEND_BUDGET_MS)
        {
            return Err(Refusal::Deadline);
        }
        if effect.as_ref().is_some_and(|e| !e.matches(&parsed)) {
            return Err(Refusal::Authority);
        }
        for (key, value) in [
            ("policy_digest", &local.policy_digest),
            ("runtime_digest", &local.runtime_digest),
            ("config_digest", &local.config_digest),
        ] {
            if parsed[key] != *value {
                return Err(Refusal::Authority);
            }
        }
        let expected = d.value()["anchor"].clone();
        let mut next = expected.clone();
        next["reserved_sequence"] = parsed["sequence"].clone();
        next["reserved_body_digest"] = json!(digest(&body));
        let request = self.id()?;
        let reserve = mutation(&request, "RESERVE", &expected, &next, &body, &[])?;
        let window = self.cut_window.take().ok_or(Refusal::Held)?;
        let deadline = window.deadline_ms() * NS_PER_MS;
        let sequence = BusinessSequence(parsed["sequence"].as_u64().ok_or(Refusal::Shape)?);
        let pool = if parsed["record_kind"] == "control" {
            Pool::Control
        } else {
            Pool::Ordinary
        };
        self.intent = Some(Intent {
            id: request,
            body: body.clone(),
            envelope: None,
            reserve: reserve.clone(),
            commit: None,
            window,
            status,
            local,
            effect,
            eligible: true,
            sequence,
            marker: None,
            cut,
        });
        self.disk(
            Operation::FreezeBody {
                body,
                reserve,
                deadline,
                grant_expiry: expiry,
                pool,
            },
            Next::Reserve,
        )
    }
    /// Disconnect permanently loses effect eligibility and retains both actor and worker ownership.
    pub fn disconnect(&mut self) {
        if self
            .intent
            .as_ref()
            .is_some_and(|intent| intent.eligible && intent.effect.is_some())
        {
            self.retain_cut();
        }
        if let Some(intent) = self.intent.as_mut() {
            intent.eligible = false;
        }
        self.dependencies.store.disconnect();
        self.state = State::Held;
    }
    /// The bounded report names the retained requests and proof stage; it grants no retry authority.
    pub fn commit_hold(&self) -> Option<&CommitHold> {
        self.commit_hold.as_ref()
    }
    /// Retry exact retained settlement after a refusal or uncertain read, with effect eligibility revoked.
    pub fn resume_settlement(&mut self) -> Result<()> {
        if self.state != State::Held || self.commit_hold.is_some() {
            return Err(Refusal::Held);
        }
        let intent = self.intent.as_mut().ok_or(Refusal::Held)?;
        intent.eligible = false;
        if intent.envelope.is_none() || intent.commit.is_none() {
            return Err(Refusal::Held);
        }
        if self.disk.is_some() {
            self.resume_after_disk = true;
            self.state = State::Disk;
            Ok(())
        } else {
            self.resume_read()
        }
    }
    fn resume_read(&mut self) -> Result<()> {
        self.dependencies
            .drain
            .reconnect()
            .map_err(|_| Refusal::Held)?;
        let now = self.now()?;
        let id = self.id()?;
        self.drain = None;
        // Reconnect learns D's fresh authenticated anchor before any retained COMMIT can be sent.
        self.dependencies
            .drain
            .read(&id, self.limit(now)?)
            .map_err(|_| Refusal::Held)?;
        self.state = State::SettlementRead;
        self.resume_after_disk = false;
        Ok(())
    }
    fn resume_observed(&mut self, active: bool, now: u64) -> Result<()> {
        let intent = self.intent.as_ref().ok_or(Refusal::Held)?;
        let commit = intent.commit.as_ref().ok_or(Refusal::Held)?;
        let observation = self.drain.as_ref().ok_or(Refusal::Held)?;
        let value = observation.value();
        // Both D evidence and the worker's durable active bit govern continuation; neither grants an old effect.
        let fresh = self.dependencies.drain.lease_live(now);
        let next = if fresh
            && value["uncertain"] == false
            && value["latched"] == false
            && &value["anchor"] == commit.expected()
        {
            Next::Confirm
        } else if fresh && observation.confirms(commit) {
            if active {
                Next::Confirm
            } else {
                Next::Original
            }
        } else {
            self.commit_hold = Some(
                if fresh {
                    CommitHold::changed_predecessor(
                        observation,
                        &intent.reserve,
                        commit,
                        &intent.body,
                        "resume READ",
                    )
                } else {
                    None
                }
                .unwrap_or_else(|| {
                    CommitHold::new(
                        &intent.reserve,
                        commit,
                        "unresolved settlement, owner 2g",
                        "resume READ",
                    )
                }),
            );
            return Err(Refusal::Held);
        };
        // The normal post-wait checks still apply; an unchanged predecessor retries only the frozen C0.
        self.check(next)
    }
    /// One nonblocking pass polls the existing owners. Errors retain the intent for settlement.
    pub fn poll(&mut self) -> Result<()> {
        let result = self.poll_inner();
        if result.is_err() {
            self.disconnect();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<()> {
        let now = self.now()?;
        if self.intent.as_ref().is_some_and(|i| {
            i.eligible && i.effect.is_some() && now >= i.window.deadline_ms() * NS_PER_MS
        }) {
            self.retain_cut();
        }
        if let Some(intent) = self.intent.as_mut() {
            // The original-window eligibility bound must stay paired with append_budget.rs's typed freshness constructors before effect delivery.
            if now >= intent.window.deadline_ms() * NS_PER_MS {
                intent.eligible = false;
            }
        }
        match self.state {
            State::SettlementRead => {
                if let Some(reply) = self.dependencies.drain.poll().map_err(|_| Refusal::Held)? {
                    let DrainReply::Read(observation) = reply else {
                        return Err(Refusal::Held);
                    };
                    self.drain = Some(observation);
                    self.disk(Operation::SettlementActive, Next::Confirm)?;
                }
            }
            State::Ready => return Ok(()),
            State::CommittedDeliveryReady => {
                // COMMIT readback permits export, but only the unchanged recheck path may deliver an effect.
                self.check(Next::EffectMarker)?;
            }
            State::Held => {
                // Closed ownership still monitors both pinned peers and polls the original worker without admitting work.
                self.dependencies
                    .writer
                    .recheck_transport()
                    .map_err(|_| Refusal::Authority)?;
                self.dependencies
                    .drain
                    .recheck_transport()
                    .map_err(|_| Refusal::Authority)?;
                if self.disk.is_some() {
                    let _ = self.dependencies.store.poll(now)?;
                }
                return Ok(());
            }
            State::Handshake => {
                if matches!(
                    self.dependencies.writer.poll().map_err(|_| Refusal::Held)?,
                    Some(WriterReply::Ready)
                ) {
                    let id = self.id()?;
                    self.dependencies
                        .writer
                        .checkpoint_query(&id, self.limit(now)?)
                        .map_err(|_| Refusal::Held)?;
                    self.state = State::CheckpointQuery;
                }
            }
            State::CheckpointQuery => {
                if let Some(WriterReply::Challenge(challenge)) =
                    self.dependencies.writer.poll().map_err(|_| Refusal::Held)?
                {
                    self.checkpoint = Some(challenge);
                    let id = self.id()?;
                    self.dependencies
                        .drain
                        .read(&id, self.limit(now)?)
                        .map_err(|_| Refusal::Held)?;
                    self.state = State::CheckpointRead;
                }
            }
            State::CheckpointRead => {
                if let Some(DrainReply::Read(observation)) =
                    self.dependencies.drain.poll().map_err(|_| Refusal::Held)?
                {
                    let operation = Operation::Report {
                        challenge: Box::new(self.checkpoint.take().ok_or(Refusal::Held)?),
                        observation,
                        fortress: self.dependencies.fortress.clone(),
                        revision: self.dependencies.revision,
                        clock: self.dependencies.clock.clone(),
                    };
                    self.disk(operation, Next::Ready)?;
                    self.state = State::CheckpointReport;
                }
            }
            State::CheckpointReport
            | State::Disk
            | State::DeliveryRead
            | State::StartupDeliveryRead
            | State::DeliveryFact
            | State::CommittedDeliveryRead
            | State::Compacting => {
                if self.dependencies.store.poll(now)?.is_some() {
                    let completion = self
                        .dependencies
                        .store
                        .settle(self.disk.take().ok_or(Refusal::Held)?)?;
                    if let Some(intent) = self.intent.as_mut() {
                        intent.eligible &= completion.eligible;
                    }
                    if completion.result.is_err() && self.delivery_fact.is_some() {
                        // Must match BusinessDelivery::pump: failed readback returns the retained fact and token.
                        self.delivery_resume = None;
                    }
                    let output = completion.result?;
                    if let Output::SettlementActive(active) = output {
                        return self.resume_observed(active, now);
                    }
                    if matches!(
                        self.state,
                        State::DeliveryRead
                            | State::StartupDeliveryRead
                            | State::CommittedDeliveryRead
                    ) {
                        let Output::Delivery(delivery) = output else {
                            return Err(Refusal::Shape);
                        };
                        self.delivery = delivery;
                        if self.state == State::StartupDeliveryRead && self.delivery.is_none() {
                            self.disk(Operation::CompactOne, Next::Ready)?;
                            self.state = State::Compacting;
                            return Ok(());
                        }
                        self.state = if self.state == State::CommittedDeliveryRead {
                            State::CommittedDeliveryReady
                        } else {
                            State::Ready
                        };
                    } else if self.state == State::DeliveryFact {
                        // Only successful exact fact and cursor readback retire n's token; failure keeps it held.
                        self.delivery = None;
                        self.delivery_fact = None;
                        let (state, next) = self.delivery_resume.take().ok_or(Refusal::Held)?;
                        self.state = state;
                        self.next = next;
                        if state == State::Ready {
                            self.disk(Operation::CompactOne, Next::Ready)?;
                            self.state = State::Compacting;
                        }
                    } else if self.state == State::Compacting {
                        // Must match WalExecutor::CompactOne: deletion follows both exact facts and durable release.
                        if self.delivery.is_none() {
                            self.disk(Operation::NextDelivery, Next::Ready)?;
                            self.state = State::DeliveryRead;
                        } else {
                            self.state = State::Ready;
                        }
                    } else if self.state == State::CheckpointReport {
                        let Output::Report(bytes) = output else {
                            return Err(Refusal::Shape);
                        };
                        self.dependencies
                            .writer
                            .checkpoint_report(bytes)
                            .map_err(|_| Refusal::Held)?;
                        self.state = State::CheckpointAck;
                    } else {
                        if let Output::Marker(marker) = output {
                            self.intent.as_mut().ok_or(Refusal::Held)?.marker = Some(marker);
                        }
                        #[cfg(feature = "test-isolation")]
                        if let Some(observation) = self
                            .observations
                            .as_mut()
                            .filter(|o| !o.probe_sent && o.applies(self.next))
                        {
                            let append = matches!(
                                observation.field,
                                ObservationField::AppendIdentity
                                    | ObservationField::AppendReplay
                                    | ObservationField::SendSecondEnvelope
                            );
                            let commit = matches!(
                                observation.field,
                                ObservationField::CommitIdentity | ObservationField::CommitReplay
                            );
                            if append || commit {
                                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                                observation.probe_sent = true;
                                observation.record()?;
                                let intent = self.intent.as_ref().ok_or(Refusal::Held)?;
                                let mut envelope =
                                    intent.envelope.as_ref().ok_or(Refusal::Held)?.clone();
                                if matches!(
                                    observation.field,
                                    ObservationField::AppendIdentity
                                        | ObservationField::SendSecondEnvelope
                                        | ObservationField::CommitIdentity
                                ) {
                                    // This decoded candidate has the same canonical body, without claiming a second valid signature.
                                    let record = writer_protocol::decode_envelope(&envelope)
                                        .map_err(|_| Refusal::Shape)?;
                                    let mut signature: [u8; writer_protocol::SIGNATURE_BYTES] =
                                        URL_SAFE_NO_PAD
                                            .decode(
                                                record["outer"]["signature"]
                                                    .as_str()
                                                    .ok_or(Refusal::Shape)?,
                                            )
                                            .map_err(|_| Refusal::Shape)?
                                            .try_into()
                                            .map_err(|_| Refusal::Shape)?;
                                    signature[0] ^= 1;
                                    envelope = writer_protocol::envelope(&intent.body, &signature)
                                        .map_err(|_| Refusal::Shape)?;
                                }
                                let operation = if append {
                                    Operation::Envelope(envelope)
                                } else {
                                    let original = intent.commit.as_ref().ok_or(Refusal::Held)?;
                                    let frame = drain_protocol::decode(
                                        original.bytes(),
                                        drain_protocol::Direction::ToDrain,
                                    )
                                    .map_err(|_| Refusal::Shape)?;
                                    Operation::Commit(mutation(
                                        &frame.request_id,
                                        "COMMIT",
                                        original.expected(),
                                        original.next(),
                                        &intent.body,
                                        &envelope,
                                    )?)
                                };
                                return self.disk(operation, self.next);
                            }
                        }
                        if self.resume_after_disk {
                            if self.delivery_resume.take().is_some() {
                                // A successful TS completion retires delivery before READ-first settlement resumes.
                                self.delivery = None;
                                self.delivery_fact = None;
                            }
                            self.resume_read()?;
                        } else if self.next == Next::EffectMarker && self.delivery.is_none() {
                            // The confirmed COMMIT is sufficient for a token; ORIGINAL does not dominate TS delivery.
                            self.disk(Operation::NextDelivery, Next::EffectMarker)?;
                            self.state = State::CommittedDeliveryRead;
                        } else {
                            self.check(self.next)?;
                        }
                    }
                }
            }
            State::CheckpointAck => {
                if matches!(
                    self.dependencies.writer.poll().map_err(|_| Refusal::Held)?,
                    Some(WriterReply::CheckpointAcknowledged(_))
                ) {
                    self.check(Next::Ready)?;
                }
            }
            State::Checking => {
                if self.status.is_none() {
                    if let Some(WriterReply::Status(status)) =
                        self.dependencies.writer.poll().map_err(|_| Refusal::Held)?
                    {
                        self.status = Some(status);
                    }
                }
                if self.drain.is_none() {
                    if let Some(DrainReply::Read(observation)) =
                        self.dependencies.drain.poll().map_err(|_| Refusal::Held)?
                    {
                        self.drain = Some(observation);
                    }
                }
                if self.status.is_some() && self.drain.is_some() {
                    self.continue_checked(now)?;
                }
            }
            State::Reserve | State::Commit => {
                if self
                    .dependencies
                    .drain
                    .poll()
                    .map_err(|_| Refusal::Held)?
                    .is_some()
                {
                    #[cfg(feature = "test-isolation")]
                    if self.state == State::Commit
                        && self.observations.as_ref().is_some_and(|o| {
                            matches!(o.field, ObservationField::CasIdentity) && !o.probe_sent
                        })
                    {
                        let observation = self.observations.as_mut().ok_or(Refusal::Held)?;
                        observation.probe_sent = true;
                        observation.record()?;
                        let path = observation
                            .trace
                            .as_ref()
                            .ok_or(Refusal::Held)?
                            .with_extension("candidate");
                        let intent = self.intent.as_ref().ok_or(Refusal::Held)?;
                        let original = intent.commit.as_ref().ok_or(Refusal::Held)?;
                        let frame = drain_protocol::decode(
                            original.bytes(),
                            drain_protocol::Direction::ToDrain,
                        )
                        .map_err(|_| Refusal::Shape)?;
                        let expected = original.expected().clone();
                        let mut next = original.next().clone();
                        next["committed_digest"] = json!(digest(b"isolated changed commitment"));
                        let candidate = mutation(
                            &frame.request_id,
                            "COMMIT",
                            &expected,
                            &next,
                            &intent.body,
                            intent.envelope.as_ref().ok_or(Refusal::Held)?,
                        )?;
                        self.dependencies.drain.send_observer_for_test(path);
                        // This decoded same-id candidate reaches the real client boundary; D's later refusal is not evidence here.
                        return self
                            .dependencies
                            .drain
                            .mutation(&candidate, self.limit(now)?)
                            .map_err(|_| Refusal::Conflict);
                    }
                    self.check(if self.state == State::Reserve {
                        Next::SignMarker
                    } else {
                        Next::Confirm
                    })?;
                }
            }
            State::Sign => {
                if let Some(reply) = self.dependencies.writer.poll().map_err(|_| Refusal::Held)? {
                    let WriterReply::Verified(envelope) = reply else {
                        return Err(Refusal::Held);
                    };
                    #[cfg(feature = "test-isolation")]
                    let envelope = if let Some(observers) = self.verified_observers.as_mut() {
                        (observers.after_client)(&envelope);
                        observers.actor_reply.take().unwrap_or(envelope)
                    } else {
                        envelope
                    };
                    let record =
                        writer_protocol::decode_envelope(&envelope).map_err(|_| Refusal::Shape)?;
                    let intent = self.intent.as_mut().ok_or(Refusal::Held)?;
                    // The wall appends only an envelope verified against bytes it froze itself; P's equality is defense in depth.
                    if canonical(&record["body"])? != intent.body {
                        return Err(Refusal::Conflict);
                    }
                    #[cfg(feature = "test-isolation")]
                    if let Some(observers) = self.verified_observers.as_mut() {
                        (observers.after_actor)(&envelope);
                    }
                    #[cfg(feature = "test-isolation")]
                    if let Some(path) = self
                        .observations
                        .as_ref()
                        .and_then(|o| o.trace_path("append"))
                    {
                        super::append_clients::record_observed_bytes(&path, &envelope)
                            .map_err(|_| Refusal::Io)?;
                    }
                    intent.envelope = Some(envelope.clone());
                    self.disk(Operation::Envelope(envelope), Next::CommitFreeze)?;
                }
            }
            State::Original => {
                if let Some(reply) = self.dependencies.drain.poll().map_err(|_| Refusal::Held)? {
                    let DrainReply::Released(fact) = reply else {
                        return Err(Refusal::Held);
                    };
                    let sequence = self.intent.as_ref().ok_or(Refusal::Held)?.sequence;
                    self.disk(Operation::DFact { sequence, fact }, Next::Refresh)?;
                }
            }
        }
        Ok(())
    }
    fn continue_checked(&mut self, now: u64) -> Result<()> {
        if let (Some(intent), Some(observation)) = (&self.intent, &self.drain) {
            if let Some(commit) = &intent.commit {
                if self.dependencies.drain.lease_live(now) {
                    if let Some(report) = CommitHold::changed_predecessor(
                        observation,
                        &intent.reserve,
                        commit,
                        &intent.body,
                        "live READ",
                    ) {
                        // A changed predecessor has no proved renewal; retain every owner and disable every effect.
                        self.commit_hold = Some(report);
                        return Err(Refusal::Held);
                    }
                }
            }
        }
        let live = self.independent(now)?;
        if !live
            && self
                .intent
                .as_ref()
                .is_some_and(|i| i.eligible && i.effect.is_some())
        {
            self.retain_cut();
        }
        if let Some(intent) = self.intent.as_mut() {
            intent.eligible &= live;
        }
        if matches!(self.next, Next::Ready) {
            // Ready checks govern settlement after Next::Deliver's by-value transfer, so they cannot revoke a prior permit and must stay paired with that delivery boundary.
            // Durable settlement is independent of effect liveness; an expired completed intent is disposed only here.
            if !live && self.intent.is_none() {
                return Err(Refusal::Authority);
            }
            let completed = self.intent.take();
            let completed_append = completed.is_some();
            if let Some(intent) = completed {
                if self.cut.pending().is_some() {
                    // Settlement releases the row owner, never the refused effect's absolute budget origin.
                    self.cut_window = Some(intent.window);
                }
            }
            if completed_append && self.delivery.is_some() {
                // A retained token means its cursor still lags; append settlement must not try to release it.
                self.state = State::Ready;
            } else if completed_append {
                // Serialized compaction retains incomplete rows; it never resets the sequence or reissues an effect.
                self.disk(Operation::CompactOne, Next::Ready)?;
                self.state = State::Compacting;
            } else if self.delivery.is_none() {
                // Replay an unread-back TS cursor before compaction can try to release its row.
                self.disk(Operation::NextDelivery, Next::Ready)?;
                self.state = State::StartupDeliveryRead;
            } else {
                self.state = State::Ready;
            }
            return Ok(());
        }
        if matches!(self.next, Next::Refresh) {
            // Refresh checks govern settlement after Next::Deliver's by-value transfer, so they cannot revoke a prior permit and must stay paired with that delivery boundary.
            let observation = self.drain.take().ok_or(Refusal::Held)?;
            return self.disk(Operation::Refresh(observation), Next::Ready);
        }
        let intent = self.intent.as_ref().ok_or(Refusal::Held)?;
        let d = self.drain.as_ref().ok_or(Refusal::Held)?;
        let expected = match self.next {
            Next::Reserve => intent.reserve.expected(),
            Next::SignMarker | Next::Sign | Next::CommitFreeze | Next::CommitSend => {
                intent.reserve.next()
            }
            _ => intent.commit.as_ref().ok_or(Refusal::Held)?.next(),
        };
        // Certain whole-anchor equality is required on every continuing path, even after an ACK or REFUSED.
        let observation = d.value();
        #[cfg(feature = "test-isolation")]
        let observation = {
            let mut observation = observation;
            if self.observations.as_ref().is_some_and(|o| {
                o.applies(self.next) && matches!(o.field, ObservationField::Anchor)
            }) {
                observation["anchor"]["generation"] = json!(u64::MAX);
            }
            observation
        };
        if observation["uncertain"] == false && observation["latched"] == false {
            let retry = match self.next {
                Next::SignMarker
                    if intent.eligible && &observation["anchor"] == intent.reserve.expected() =>
                {
                    Some((&intent.reserve, State::Reserve))
                }
                Next::Confirm
                    if &observation["anchor"]
                        == intent.commit.as_ref().ok_or(Refusal::Held)?.expected() =>
                {
                    Some((intent.commit.as_ref().ok_or(Refusal::Held)?, State::Commit))
                }
                _ => None,
            };
            if let Some((proposal, state)) = retry {
                if state == State::Commit && !self.ordinary_room(d) {
                    // A full D fails closed; no at-cap renewal exists.
                    return Err(Refusal::Capacity);
                }
                // A certain unchanged predecessor permits only the frozen CAS under its original request identity.
                self.dependencies
                    .drain
                    .mutation(proposal, self.limit(now)?)
                    .map_err(|_| Refusal::Held)?;
                self.state = state;
                return Ok(());
            }
        }
        if observation["uncertain"] != false
            || observation["latched"] != false
            || &observation["anchor"] != expected
        {
            return Err(Refusal::Held);
        }
        match self.next {
            Next::Reserve => {
                if !intent.eligible {
                    return Err(Refusal::Deadline);
                }
                // freeze_body checkpoint publication was read back by the worker before this RESERVE send.
                self.dependencies
                    .drain
                    .mutation(&intent.reserve, self.limit(now)?)
                    .map_err(|_| Refusal::Held)?;
                self.state = State::Reserve;
            }
            Next::SignMarker => {
                if !intent.eligible {
                    return Err(Refusal::Deadline);
                }
                let observation = self.drain.take().ok_or(Refusal::Held)?;
                self.disk(Operation::SignMarker { observation, now }, Next::Sign)?;
            }
            Next::Sign => {
                if !intent.eligible {
                    return Err(Refusal::Deadline);
                }
                let grant = intent.status.grant.as_ref().ok_or(Refusal::Held)?;
                let expiry = intent
                    .status
                    .expires_boottime_ns
                    .parse::<u64>()
                    .map_err(|_| Refusal::Shape)?;
                let deadline = self
                    .limit(now)?
                    .min(now + writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS)
                    .min(expiry.saturating_sub(1));
                self.dependencies
                    .writer
                    .sign(
                        Header {
                            v: 1,
                            protocol: super::signer_contract::SIGNER_PROTOCOL.into(),
                            request_id: intent.id.clone(),
                            activation_id: grant.activation_id.clone(),
                            lease_id: grant.lease_id.clone(),
                            generation: grant.generation,
                            epoch: grant.epoch,
                            role: grant.role.clone(),
                            deadline_boottime_ns: deadline.to_string(),
                            preimage_length: intent.body.len(),
                        },
                        &intent.body,
                        expiry,
                    )
                    .map_err(|_| Refusal::Held)?;
                self.state = State::Sign;
            }
            Next::CommitFreeze => {
                let envelope = intent.envelope.as_ref().ok_or(Refusal::Held)?;
                let identity = super::append_contract::identity(envelope).ok_or(Refusal::Shape)?;
                let mut next = intent.reserve.next().clone();
                next["committed_sequence"] = identity["sequence"].clone();
                next["committed_digest"] = identity["commitment"].clone();
                next["reserved_body_digest"] = Value::Null;
                let id = format!("{:032x}", self.serial);
                self.serial += 1;
                let commit = mutation(
                    &id,
                    "COMMIT",
                    intent.reserve.next(),
                    &next,
                    &intent.body,
                    envelope,
                )?;
                self.intent.as_mut().ok_or(Refusal::Held)?.commit = Some(commit.clone());
                self.disk(Operation::Commit(commit), Next::CommitSend)?;
            }
            Next::CommitSend => {
                #[cfg(feature = "test-isolation")]
                if let Some(path) = self
                    .observations
                    .as_ref()
                    .and_then(|o| o.trace_path("commit"))
                {
                    self.dependencies.drain.send_observer_for_test(path);
                }
                self.dependencies
                    .drain
                    .mutation(
                        intent.commit.as_ref().ok_or(Refusal::Held)?,
                        self.limit(now)?,
                    )
                    .map_err(|_| Refusal::Held)?;
                self.state = State::Commit;
            }
            Next::Confirm => {
                let observation = self.drain.take().ok_or(Refusal::Held)?;
                self.disk(Operation::Confirm(observation), Next::EffectMarker)?;
            }
            Next::EffectMarker => {
                if let Some((grant, count)) = intent.cut {
                    // Confirm completed local publication before the control is called durable.
                    if !self.cut.discharge(grant, count) {
                        return Err(Refusal::Conflict);
                    }
                }
                if intent.eligible && intent.effect.is_some() {
                    self.disk(Operation::EffectMarker(intent.sequence), Next::Deliver)?;
                } else {
                    self.next = Next::Original;
                    self.continue_checked(now)?;
                }
            }
            Next::Deliver => {
                let intent = self.intent.as_mut().ok_or(Refusal::Held)?;
                if intent.eligible {
                    #[cfg(feature = "test-isolation")]
                    let now = if self.observations.as_ref().is_some_and(|o| {
                        o.applies(Next::Deliver) && matches!(o.field, ObservationField::PermitTime)
                    }) {
                        intent.window.deadline_ms() * NS_PER_MS
                    } else {
                        now
                    };
                    let marker = intent.marker.take().ok_or(Refusal::Held)?;
                    #[cfg(feature = "test-isolation")]
                    let marker = {
                        let mut marker = marker;
                        if let Some(observation) = &self.observations {
                            let field = match observation.field {
                                ObservationField::MarkerSequence => {
                                    Some(super::effect_permit::MarkerObservation::Sequence)
                                }
                                ObservationField::MarkerCommitment => {
                                    Some(super::effect_permit::MarkerObservation::Commitment)
                                }
                                ObservationField::MarkerEnvelope => {
                                    Some(super::effect_permit::MarkerObservation::Envelope)
                                }
                                _ => None,
                            };
                            if let Some(field) = field {
                                marker.observe_for_test(field);
                            }
                            if let Some(path) = observation.trace_path("permit") {
                                super::append_clients::record_observed_bytes(
                                    &path,
                                    intent.envelope.as_ref().ok_or(Refusal::Held)?,
                                )
                                .map_err(|_| Refusal::Io)?;
                            }
                        }
                        marker
                    };
                    let permit = EffectPermit::construct(
                        marker,
                        intent.effect.as_ref().ok_or(Refusal::Held)?,
                        intent.envelope.as_ref().ok_or(Refusal::Held)?,
                        intent.id.clone(),
                        now,
                        intent.window.deadline_ms() * NS_PER_MS,
                    )
                    .ok_or(Refusal::Authority)?;
                    // No wait occurs between the final independent recheck, token construction and by-value delivery.
                    // This transfer must stay paired with the Original, Refresh and Ready settlement-only checks; later checks cannot revoke this delivered capability.
                    self.dependencies.sink.deliver(permit);
                }
                self.next = Next::Original;
                self.continue_checked(now)?;
            }
            Next::Original => {
                // Original checks govern settlement after Next::Deliver's by-value transfer, so they cannot revoke a prior permit and must stay paired with that delivery boundary.
                let envelope = intent.envelope.as_ref().ok_or(Refusal::Held)?.clone();
                if expected["drained_sequence"]
                    .as_u64()
                    .and_then(|n| n.checked_add(1))
                    != Some(intent.sequence.0)
                {
                    return Err(Refusal::Held);
                }
                let id = super::business_wal::original_request_id(&envelope);
                #[cfg(feature = "test-isolation")]
                if let Some(path) = self
                    .observations
                    .as_ref()
                    .and_then(|o| o.trace_path("original"))
                {
                    self.dependencies.drain.send_observer_for_test(path);
                }
                // A drain under a frozen COMMIT would stale its predecessor, and no proved renewal exists.
                self.dependencies
                    .drain
                    .original(&id, &envelope, self.limit(now)?)
                    .map_err(|_| Refusal::Held)?;
                self.state = State::Original;
            }
            Next::Ready | Next::Refresh => return Err(Refusal::Held),
        }
        Ok(())
    }
}
