//! Serialized disk work with one retained operation and one polled completion.
use super::{
    append_clients::{DrainObservation, DrainReleaseFact, FrozenMutation},
    business_wal::{
        BusinessSequence, BusinessWal, CheckpointSeed, DeliveryToken, OrdinaryWalCheckpoint, Pool,
        Refusal, Result, TsReleaseFact, WalHooks,
    },
    drain_protocol, records_schema, writer_protocol,
};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::{self, JoinHandle},
};

/// Disk requests carry their exact evidence by value. Peer delivery waits never enter this enum.
pub enum Operation {
    Open {
        path: PathBuf,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
    },
    OpenRecovering {
        path: PathBuf,
        owner: u32,
        hooks: Box<dyn WalHooks>,
        seed: Option<CheckpointSeed>,
        observation: DrainObservation,
        clock: super::writer_peer::Clock,
    },
    FreezeBody {
        body: Vec<u8>,
        reserve: FrozenMutation,
        deadline: u64,
        grant_expiry: u64,
        pool: Pool,
    },
    SignMarker {
        observation: DrainObservation,
        now: u64,
    },
    Envelope(Vec<u8>),
    Commit(FrozenMutation),
    Confirm(DrainObservation),
    Refresh(DrainObservation),
    NextDelivery,
    CompactOne,
    TsFact {
        sequence: BusinessSequence,
        fact: std::sync::Arc<TsReleaseFact>,
    },
    DFact {
        sequence: BusinessSequence,
        fact: DrainReleaseFact,
    },
    Report {
        challenge: Box<super::append_clients::CheckpointChallenge>,
        observation: DrainObservation,
        fortress: String,
        revision: u64,
        clock: super::writer_peer::Clock,
    },
    Recover {
        observation: DrainObservation,
        clock: super::writer_peer::Clock,
    },
    Reconcile,
    SettlementActive,
    EffectMarker(BusinessSequence),
    Checkpoint(super::writer_peer::Clock),
}
impl Operation {
    fn bounded(&self) -> bool {
        match self {
            Self::FreezeBody { body, reserve, .. } => {
                body.len() <= records_schema::MAX_BYTES
                    && reserve.bytes().len() <= drain_protocol::D_REQUEST_MAX_BYTES
            }
            Self::Envelope(bytes) => bytes.len() <= writer_protocol::WRITER_ENVELOPE_MAX_BYTES,
            Self::Commit(proposal) => proposal.bytes().len() <= drain_protocol::D_REQUEST_MAX_BYTES,
            _ => true,
        }
    }
}
/// Only actual worker completion exposes a disk result; expiry affects eligibility separately.
pub enum Output {
    SettlementActive(bool),
    Recovery(super::business_wal::RecoveryAction),
    Done,
    Sequence(BusinessSequence),
    Delivery(Option<(BusinessSequence, DeliveryToken)>),
    Checkpoint(OrdinaryWalCheckpoint),
    Report(Vec<u8>),
    Marker(super::effect_permit::MarkerCompletion),
}
struct Request {
    id: u64,
    operation: Operation,
}
/// A completion retains the original identity until its owner explicitly acknowledges settlement.
pub struct Completion {
    pub id: u64,
    pub result: Result<Output>,
    pub eligible: bool,
}
struct Owned {
    id: u64,
    deadline: u64,
    eligible: bool,
}
/// One worker owns the WAL and its lock for its entire lifetime, including blocked syscalls.
pub struct WalExecutor {
    sender: Option<SyncSender<Request>>,
    receiver: Option<Receiver<Completion>>,
    worker: Option<JoinHandle<()>>,
    owned: Option<Owned>,
    completed: Option<Completion>,
    next_id: u64,
}
impl WalExecutor {
    /// Start an empty worker; readiness requires an acknowledged successful Open operation.
    pub fn start() -> Result<Self> {
        const ONE_COMPLETION: usize = 1;
        let (sender, requests) = mpsc::sync_channel::<Request>(ONE_COMPLETION);
        let (results, receiver) = mpsc::sync_channel(ONE_COMPLETION);
        let worker = thread::Builder::new()
            .name("business-wal".into())
            .spawn(move || {
                let mut wal = None;
                while let Ok(request) = requests.recv() {
                    let result = execute(&mut wal, request.operation);
                    if results
                        .send(Completion {
                            id: request.id,
                            result,
                            eligible: false,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|_| Refusal::Io)?;
        Ok(Self {
            sender: Some(sender),
            receiver: Some(receiver),
            worker: Some(worker),
            owned: None,
            completed: None,
            next_id: 1,
        })
    }
    /// Admission is closed while any previous request or completion remains owned.
    pub fn submit(&mut self, operation: Operation, now: u64, deadline: u64) -> Result<u64> {
        // Neither caller expiry nor disconnect proves that an underlying disk operation ended.
        if self.owned.is_some() {
            return Err(Refusal::Held);
        }
        if now >= deadline {
            return Err(Refusal::Deadline);
        }
        if !operation.bounded() {
            return Err(Refusal::Capacity);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Refusal::Capacity)?;
        self.owned = Some(Owned {
            id,
            deadline,
            eligible: true,
        });
        self.sender
            .as_ref()
            .ok_or(Refusal::Held)?
            .try_send(Request { id, operation })
            .map_err(|_| Refusal::Held)?;
        Ok(id)
    }
    /// Poll without waiting. A late result settles only its original request and cannot regain eligibility.
    pub fn poll(&mut self, now: u64) -> Result<Option<&Completion>> {
        let Some(owned) = self.owned.as_mut() else {
            return Ok(None);
        };
        if now >= owned.deadline {
            owned.eligible = false;
        }
        if self.completed.is_none() {
            match self.receiver.as_ref().ok_or(Refusal::Held)?.try_recv() {
                Ok(mut completion) => {
                    if completion.id != owned.id {
                        return Err(Refusal::Conflict);
                    }
                    completion.eligible = owned.eligible;
                    self.completed = Some(completion);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(Refusal::Held),
            }
        }
        if let Some(completion) = self.completed.as_mut() {
            completion.eligible &= owned.eligible;
        }
        Ok(self.completed.as_ref())
    }
    /// Cancellation revokes effect eligibility while preserving the worker, lock and exact operation.
    pub fn disconnect(&mut self) {
        if let Some(owned) = self.owned.as_mut() {
            owned.eligible = false;
        }
        if let Some(completion) = self.completed.as_mut() {
            completion.eligible = false;
        }
    }
    /// Explicit settlement consumes the matching completion; a timeout alone can never reach this transition.
    pub fn settle(&mut self, id: u64) -> Result<Completion> {
        if self.completed.as_ref().map(|c| c.id) != Some(id) {
            return Err(Refusal::Held);
        }
        let result = self.completed.take().ok_or(Refusal::Held)?;
        self.owned = None;
        Ok(result)
    }
    /// Monitoring can inspect ownership without blocking on disk work.
    pub fn owned(&self) -> bool {
        self.owned.is_some()
    }
}
impl Drop for WalExecutor {
    fn drop(&mut self) {
        // Closing admission and joining keeps the held store from outliving its owner.
        self.sender.take();
        self.receiver.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn execute(store: &mut Option<BusinessWal>, operation: Operation) -> Result<Output> {
    if let Operation::Open {
        path,
        owner,
        hooks,
        seed,
    } = operation
    {
        if store.is_some() {
            return Err(Refusal::Held);
        }
        *store = Some(BusinessWal::open_isolated(&path, owner, hooks, seed)?);
        return Ok(Output::Done);
    }
    if let Operation::OpenRecovering {
        path,
        owner,
        hooks,
        seed,
        observation,
        clock,
    } = operation
    {
        if store.is_some() {
            return Err(Refusal::Held);
        }
        *store = Some(BusinessWal::open_recovering(
            &path,
            owner,
            hooks,
            seed,
            &observation,
            &clock,
        )?);
        return Ok(Output::Done);
    }
    let wal = store.as_mut().ok_or(Refusal::Missing)?;
    match operation {
        Operation::Open { .. } | Operation::OpenRecovering { .. } => Err(Refusal::Held),
        Operation::FreezeBody {
            body,
            reserve,
            deadline,
            grant_expiry,
            pool,
        } => wal
            .freeze_body(&body, &reserve, deadline, grant_expiry, pool)
            .map(Output::Sequence),
        Operation::SignMarker { observation, now } => wal
            .persist_sign_marker(&observation, now)
            .map(|_| Output::Done),
        Operation::Envelope(bytes) => wal.freeze_envelope(&bytes).map(|_| Output::Done),
        Operation::Commit(proposal) => wal.freeze_commit(&proposal).map(|_| Output::Done),
        Operation::Confirm(observation) => wal.confirm_commit(&observation).map(|_| Output::Done),
        // A drain under a frozen COMMIT would stale its predecessor, and no proved renewal exists.
        Operation::Refresh(observation) => wal.refresh_drained(&observation).map(|_| Output::Done),
        Operation::NextDelivery => wal.next_delivery().map(Output::Delivery),
        // Must match AppendActor::Compacting: the owned worker reads both facts and durably checkpoints release before deletion.
        Operation::CompactOne => wal.compact_one().map(|_| Output::Done),
        Operation::TsFact { sequence, fact } => wal
            .persist_ts_fact(sequence, fact.as_ref())
            .map(|_| Output::Done),
        Operation::DFact { sequence, fact } => {
            wal.persist_d_fact(sequence, fact).map(|_| Output::Done)
        }
        Operation::EffectMarker(sequence) => wal.mark_effect_unknown(sequence).map(Output::Marker),
        Operation::Report {
            challenge,
            observation,
            fortress,
            revision,
            clock,
        } => {
            let checkpoint = wal.ordinary_checkpoint(&clock)?;
            super::append_checkpoint::OrdinaryCheckpointProvider::production()
                .report(
                    &challenge,
                    &observation,
                    checkpoint,
                    &fortress,
                    revision,
                    clock().map_err(|_| Refusal::Deadline)?,
                )
                .map(Output::Report)
                .map_err(|_| Refusal::Authority)
        }
        Operation::Recover { observation, clock } => wal
            .recovery_action(&observation, &clock)
            .map(Output::Recovery),
        Operation::SettlementActive => wal.settlement_active().map(Output::SettlementActive),
        Operation::Reconcile => wal.reconcile_publication().map(|_| Output::Done),
        Operation::Checkpoint(clock) => wal.ordinary_checkpoint(&clock).map(Output::Checkpoint),
    }
}
