//! Policy decision engine shared by daemon lifecycle and kernel verdict loops.
//!
//! The daemon owns process lifetime and kernel resources. The decision engine
//! owns the smaller, cloneable security path: verified policy lookup, durable
//! audit emission, and fail-closed behavior when evidence cannot be written.
//! Keeping this object independent avoids a circular ownership relationship
//! when the daemon later owns an NFQUEUE thread whose callback must evaluate
//! packets through the daemon's policy state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant};

use crate::audit::{AuditRingBuffer, WalError, WalWriter};
use crate::failure::{default_disposition, FailureDisposition, FailureMode};
use crate::manifest::canonical_json::CanonicalJsonError;
use crate::manifest::store::AuthorizedReloadError;
use crate::manifest::LoadedManifest;
use crate::manifest::{ManifestStore, ManifestStoreError};
use crate::policy::{
    build_audit_event_canonical_json, DeniedReason, EvaluationRequest, PolicySnapshot, Verdict,
};

/// The operation string the boot manifest load audits under.
///
/// Pinned here rather than at the call site because the boot entry, not
/// `daemon.rs`, is now the only thing that may use it: the boot entry is what
/// freezes the armed identity, and an audit row carrying this operation name is
/// the claim that the freeze happened. Must match the `boot_manifest_load_authorized`
/// row the drill harness greps and the boot call in `crate::daemon::boot`.
const BOOT_MANIFEST_LOAD_OPERATION: &str = "boot_manifest_load_authorized";

/// The context string the boot manifest load audits under. Must match
/// `BOOT_MANIFEST_LOAD_OPERATION`'s row in `crate::daemon::boot`.
const BOOT_MANIFEST_LOAD_CONTEXT: &str = "boot";

/// How long a manifest reload waits for the store and audit mutexes before it
/// gives up.
///
/// DERIVATION: it is a SHUTDOWN budget, not a work deadline. The mutation it
/// guards is a signature verification plus a WAL append, all local, so a wait
/// this long means another holder is wedged rather than slow; two seconds is
/// short enough that a shutdown is not visibly delayed by it and long enough
/// that an fsync under load is not mistaken for a wedge. The boot load and the
/// IPC/watcher reloads share one value on purpose: a boot that timed out on a
/// budget the running daemon would have honoured would refuse to start for a
/// reason the same host tolerates a minute later.
const MANIFEST_RELOAD_LOCK_BUDGET: Duration = Duration::from_secs(2);

/// The identity this process is ARMED with: written once, at the boot manifest
/// load, and never again while the process lives.
///
/// `fortress_id` travels WITH the subject so no expectation reader has to reach
/// back into the manifest store for it. The store is behind a mutex a
/// control-plane operation can hold across an fsync, and every reader that used
/// to `try_lock` it had to treat contention as "not confined" — an indeterminate
/// answer where a definite one exists. The cell is the definite one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedIdentity {
    /// The fortress the boot snapshot was admitted under. Must match
    /// `PolicySnapshot::fortress_id` in `src/policy.rs` and
    /// `AgentRulesetId::fortress_id` in `src/nftables.rs`, which reads it from here.
    pub(crate) fortress_id: String,
    /// Who the manifest confines, if anyone.
    pub(crate) subject: AdmittedSubject,
}

/// Who a manifest confines. The two variants are not interchangeable: a kernel
/// binding is legitimate under exactly one of them, so collapsing them into an
/// `Option<u32>` would lose the difference between "this manifest confines
/// nobody" and "this manifest's confinement is unknown".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmittedSubject {
    /// The manifest admits no agent uid. No per-agent binding may be live.
    Unconfined,
    /// The manifest admits `agent_uid` under `ceiling`, optionally beside a
    /// distinct `gate_uid`. All three move together (see `PolicySnapshot`).
    Confined {
        agent_uid: u32,
        ceiling: u32,
        gate_uid: Option<u32>,
    },
}

impl AdmittedIdentity {
    /// Derive the armed identity from a COMMITTED policy snapshot.
    ///
    /// INVARIANT this enforces at the point of derivation, and it is SYMMETRIC:
    /// `confined_agent_uid` and `confined_agent_uid_ceiling` are `Some` together
    /// or not at all (`PolicySnapshot` states it;
    /// `snapshot_threads_the_whole_admitted_set` asserts it). A uid with no
    /// ceiling would mean sealing a uid into a kernel rule without the floor
    /// admission accepted it under. A ceiling with NO uid is the same defect seen
    /// from the other side: the snapshot carries an admission bound that no
    /// subject was derived from, so reading it as `Unconfined` would silently
    /// discard half of an inconsistent pair and arm a wall that confines nobody
    /// under a manifest that meant to confine someone. Both are refused here
    /// rather than defaulted.
    pub(crate) fn from_snapshot(snapshot: &PolicySnapshot) -> Result<Self, String> {
        let subject = match (
            snapshot.confined_agent_uid,
            snapshot.confined_agent_uid_ceiling,
        ) {
            (None, None) => AdmittedSubject::Unconfined,
            (Some(agent_uid), Some(ceiling)) => AdmittedSubject::Confined {
                agent_uid,
                ceiling,
                gate_uid: snapshot.confined_gate_uid,
            },
            (Some(agent_uid), None) => {
                return Err(format!(
                    "the policy snapshot confines uid {agent_uid} with no admission ceiling; \
                     the two are set together or not at all"
                ))
            }
            (None, Some(ceiling)) => {
                return Err(format!(
                    "the policy snapshot carries an admission ceiling {ceiling} with no confined \
                     uid; the two are set together or not at all"
                ))
            }
        };
        Ok(Self {
            fortress_id: snapshot.fortress_id.clone(),
            subject,
        })
    }
}

/// Which side of the identity freeze a reload is on.
///
/// The boot load is distinguished by THIS TYPE, never by the context string: a
/// context string is data an IPC caller could someday supply, and the whole
/// property rests on exactly one reload being allowed to write the cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityGate {
    /// The one boot-time load. It admits with the cell unset and WRITES the cell
    /// before returning.
    BootFreeze,
    /// Every other reload (watcher, IPC reload, IPC publish). It compares the
    /// candidate against the frozen cell and refuses any change.
    Frozen,
}

/// Fatal-loss reporting must never inherit the liveness failure it is trying
/// to report. Keep this short: the process still emits a loud diagnostic and
/// terminates nonzero when the receipt cannot be made durable in time.
pub(crate) const FAILURE_AUDIT_BUDGET: Duration = Duration::from_millis(50);

/// Cloneable decision surface used by both daemon compatibility methods and
/// the production NFQUEUE callback.
pub struct DecisionEngine {
    fortress_id: String,
    manifest_store: Option<Arc<Mutex<ManifestStore>>>,
    wal_writer: Option<Arc<Mutex<WalWriter>>>,
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    mutation_cancel: Arc<AtomicBool>,
    /// The write-once armed identity, SHARED by every clone of this engine.
    ///
    /// It is an `Arc<OnceLock<_>>` and not an `OnceLock<_>` for the same reason
    /// `mutation_cancel` is an `Arc<AtomicBool>`: the engine is constructed once
    /// at the composition root and handed to IPC, the watcher and the kernel
    /// verdict path, and a per-clone cell would be a freeze those paths cannot
    /// observe.
    armed_identity: Arc<OnceLock<AdmittedIdentity>>,
}

impl DecisionEngine {
    #[cfg(test)]
    pub(crate) fn new(
        fortress_id: String,
        manifest_store: Option<Arc<Mutex<ManifestStore>>>,
        wal_writer: Option<Arc<Mutex<WalWriter>>>,
        audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    ) -> Self {
        Self::new_with_mutation_cancel(
            fortress_id,
            manifest_store,
            wal_writer,
            audit_buffer,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub(crate) fn new_with_mutation_cancel(
        fortress_id: String,
        manifest_store: Option<Arc<Mutex<ManifestStore>>>,
        wal_writer: Option<Arc<Mutex<WalWriter>>>,
        audit_buffer: Arc<Mutex<AuditRingBuffer>>,
        mutation_cancel: Arc<AtomicBool>,
    ) -> Self {
        Self {
            fortress_id,
            manifest_store,
            wal_writer,
            audit_buffer,
            mutation_cancel,
            armed_identity: Arc::new(OnceLock::new()),
        }
    }

    /// The fortress this engine was constructed for.
    ///
    /// Exposed so an emission site can name the fortress in a kernel seal without
    /// reaching into the manifest store. Must match `AgentRulesetId::fortress_id`
    /// in `src/nftables.rs`, which is the seal input this value becomes.
    pub(crate) fn fortress_id(&self) -> &str {
        &self.fortress_id
    }

    /// The identity frozen at boot, or `None` before the boot load ran.
    ///
    /// INVARIANT for every caller: `None` is the FAIL-CLOSED reading. It means
    /// the boot entry has not written the cell yet, so nothing may be bound and
    /// no live binding may be blessed. It is never "unconfined".
    pub(crate) fn armed_identity(&self) -> Option<&AdmittedIdentity> {
        self.armed_identity.get()
    }

    /// Freeze an identity WITHOUT a manifest load. Available only to the test
    /// builds (`cfg(test)` and the `test-isolation` integration feature, the same
    /// gate `WriteAheadReceipt::for_isolated_test` uses), so no production path
    /// can freeze an identity the boot manifest load did not derive.
    #[cfg(any(test, feature = "test-isolation"))]
    pub(crate) fn freeze_armed_identity_for_test(&self, identity: AdmittedIdentity) -> bool {
        self.armed_identity.set(identity).is_ok()
    }

    /// The shared teardown MUTATION FENCE.
    ///
    /// Public for the same reason [`Self::wal_writer`] and
    /// [`Self::manifest_store`] are: an integration test must be able to drive
    /// the exact teardown race the fence exists for, and simulating it through a
    /// full `stop()` cannot land the flag inside the evaluation window. This is
    /// the SAME `Arc` the daemon lifecycle sets, not a copy — a second flag would
    /// be a fence the verdict path does not read.
    pub fn mutation_cancel_flag(&self) -> &Arc<AtomicBool> {
        &self.mutation_cancel
    }

    /// Verified manifest state shared with authenticated policy reloads.
    pub fn manifest_store(&self) -> Option<&Arc<Mutex<ManifestStore>>> {
        self.manifest_store.as_ref()
    }

    /// Durable WAL shared with authenticated audit drain and test injection.
    pub fn wal_writer(&self) -> Option<&Arc<Mutex<WalWriter>>> {
        self.wal_writer.as_ref()
    }

    /// Record that an already-durable verdict was OVERRIDDEN before the packet
    /// was released, so the audit trail cannot end on an `allow` receipt for a
    /// packet the kernel dropped.
    ///
    /// ## The divergence this closes
    ///
    /// `evaluate_attempt` makes the decision durable BEFORE the caller acts on
    /// it — deliberately, so a packet is never released ahead of its evidence.
    /// The NFQUEUE callback then re-checks the teardown mutation fence and, if
    /// shutdown began during evaluation, drops the packet. Fail-closed on the
    /// wire, but the WAL was left holding a canonical `egress_approved` receipt
    /// for a packet that never went anywhere. The audit log IS the product's
    /// evidence claim, so a receipt that describes an event which did not occur
    /// is a defect even though the enforcement direction is safe.
    ///
    /// ## Bounded, and never a new hang
    ///
    /// This runs on the NFQUEUE verdict thread DURING teardown, where the WAL
    /// mutex is contended by the shutdown path. It therefore takes the lock
    /// under a short wall-clock deadline and gives up rather than blocking; a
    /// blocking `lock()` here would be a liveness defect on the exact thread
    /// teardown is waiting to join. It deliberately does NOT consult
    /// `mutation_cancel`: that flag is SET on every path that reaches here, so
    /// honoring it would make this function a permanent no-op.
    ///
    /// Failure mode when the deadline is missed: the superseding record is not
    /// written and the divergence remains for that one packet. The caller still
    /// drops the packet (the wire stays fail-closed) and reports the miss
    /// loudly, because a silently-absent correction is exactly the shape of the
    /// original defect.
    pub(crate) fn append_superseding_verdict(
        &self,
        superseded_wal_seq: u64,
        final_verdict: &str,
        reason: &str,
        identity_id: &str,
        deadline: Duration,
    ) -> Result<u64, ControlAuditError> {
        let wal = self
            .wal_writer
            .as_ref()
            .ok_or(ControlAuditError::WalUnwired)?;
        let event_canonical_json = crate::policy::build_superseding_verdict_canonical_json(
            superseded_wal_seq,
            final_verdict,
            reason,
            &self.fortress_id,
            identity_id,
            &current_timestamp_iso8601(),
        )
        .map_err(ControlAuditError::Canonicalize)?;
        let seq = {
            let mut guard = bounded_lock(wal, deadline)?;
            guard
                .append_control_critical(&event_canonical_json)
                .map_err(ControlAuditError::WalAppend)?
        };
        // Strict sequence semantics, asserted rather than assumed: WAL sequences
        // are monotonic, so a superseding record always lands AFTER the record it
        // names. A reader resolves a final verdict by scanning forward from the
        // superseded seq, and a record naming a seq at or after itself would make
        // that scan unsound.
        debug_assert!(
            seq > superseded_wal_seq,
            "a superseding record must be appended after the verdict it overrides"
        );
        if let Ok(mut buffer) = self.audit_buffer.lock() {
            buffer.append(crate::audit::PendingAuditEvent {
                event_canonical_json,
                captured_at: std::time::SystemTime::now(),
                critical: true,
            });
        }
        Ok(seq)
    }

    /// Durably emit a critical control-plane audit event through the WAL and the
    /// ring buffer drained by the IPC surface. Watcher-driven policy changes use
    /// the returned durable receipt as a precommit gate; missing wiring, poisoned
    /// locks, and I/O failures are therefore surfaced rather than silently
    /// converting a critical mutation into an unaudited one.
    pub(crate) fn append_control_audit(
        &self,
        operation: &str,
        detail: &str,
    ) -> Result<u64, ControlAuditError> {
        let event = serde_json::json!({
            "layer": crate::constants::AUDIT_LAYER,
            "operation": operation,
            "schema_version": crate::constants::SCHEMA_VERSION_V1,
            "fortress_id": self.fortress_id,
            "detail": detail,
        });
        let event_canonical_json = crate::manifest::canonical_json::canonicalize(&event)
            .map_err(ControlAuditError::Canonicalize)?;
        let wal = self
            .wal_writer
            .as_ref()
            .ok_or(ControlAuditError::WalUnwired)?;
        let mut buffer = self
            .audit_buffer
            .lock()
            .map_err(|_| ControlAuditError::AuditBufferPoisoned)?;
        // Acquire every fallible in-memory gate before the durable append.
        // After append succeeds, ring insertion and exact prepared commit are
        // infallible, so a durable authorization receipt can never describe an
        // uncommitted snapshot.
        let seq = wal
            .lock()
            .map_err(|_| ControlAuditError::WalPoisoned)?
            .append_control_critical(&event_canonical_json)
            .map_err(ControlAuditError::WalAppend)?;
        buffer.append(crate::audit::PendingAuditEvent {
            event_canonical_json,
            captured_at: std::time::SystemTime::now(),
            critical: true,
        });
        Ok(seq)
    }

    /// Fatal-loss form of [`Self::append_control_audit`]. Every mutex is
    /// acquired under one shared deadline, so a stuck verdict/WAL owner cannot
    /// prevent the supervisor from reaching fail-stop termination.
    pub(crate) fn append_control_audit_bounded(
        &self,
        operation: &str,
        detail: &str,
        budget: Duration,
    ) -> Result<u64, ControlAuditError> {
        self.append_control_audit_bounded_with_safety_net(operation, detail, None, budget)
    }

    /// Keep the safety-net predicate as a structured sibling of `detail` in the
    /// canonical WAL body. The signed audit drain then covers the same field.
    pub(crate) fn append_control_audit_bounded_with_safety_net(
        &self,
        operation: &str,
        detail: &str,
        safety_net: Option<serde_json::Value>,
        budget: Duration,
    ) -> Result<u64, ControlAuditError> {
        let mut event = serde_json::json!({
            "layer": crate::constants::AUDIT_LAYER,
            "operation": operation,
            "schema_version": crate::constants::SCHEMA_VERSION_V1,
            "fortress_id": self.fortress_id,
            "detail": detail,
        });
        if let Some(state) = safety_net {
            event["safety_net"] = state;
        }
        let event_canonical_json = crate::manifest::canonical_json::canonicalize(&event)
            .map_err(ControlAuditError::Canonicalize)?;
        let wal = self
            .wal_writer
            .as_ref()
            .ok_or(ControlAuditError::WalUnwired)?;
        let deadline = Instant::now() + budget;
        let mut buffer =
            bounded_lock_until(&self.audit_buffer, deadline).map_err(|err| match err {
                LockAcquireError::Poisoned => ControlAuditError::AuditBufferPoisoned,
                LockAcquireError::Timeout => ControlAuditError::LockTimeout,
                LockAcquireError::Cancelled => unreachable!("bounded lock is not cancellable"),
            })?;
        let mut wal = bounded_lock_until(wal, deadline).map_err(|err| match err {
            LockAcquireError::Poisoned => ControlAuditError::WalPoisoned,
            LockAcquireError::Timeout => ControlAuditError::LockTimeout,
            LockAcquireError::Cancelled => unreachable!("bounded lock is not cancellable"),
        })?;
        let seq = wal
            .append_control_critical(&event_canonical_json)
            .map_err(ControlAuditError::WalAppend)?;
        buffer.append(crate::audit::PendingAuditEvent {
            event_canonical_json,
            captured_at: std::time::SystemTime::now(),
            critical: true,
        });
        Ok(seq)
    }

    fn append_control_audit_cancellable(
        &self,
        operation: &str,
        detail: &str,
        shutdown: &AtomicBool,
        deadline: Instant,
    ) -> Result<u64, ControlAuditError> {
        let event = serde_json::json!({
            "layer": crate::constants::AUDIT_LAYER,
            "operation": operation,
            "schema_version": crate::constants::SCHEMA_VERSION_V1,
            "fortress_id": self.fortress_id,
            "detail": detail,
        });
        let event_canonical_json = crate::manifest::canonical_json::canonicalize(&event)
            .map_err(ControlAuditError::Canonicalize)?;
        let wal = self
            .wal_writer
            .as_ref()
            .ok_or(ControlAuditError::WalUnwired)?;
        let mut buffer =
            cancellable_lock(&self.audit_buffer, shutdown, deadline).map_err(|err| match err {
                LockAcquireError::Poisoned => ControlAuditError::AuditBufferPoisoned,
                LockAcquireError::Cancelled => ControlAuditError::Cancelled,
                LockAcquireError::Timeout => ControlAuditError::LockTimeout,
            })?;
        let mut wal = cancellable_lock(wal, shutdown, deadline).map_err(|err| match err {
            LockAcquireError::Poisoned => ControlAuditError::WalPoisoned,
            LockAcquireError::Cancelled => ControlAuditError::Cancelled,
            LockAcquireError::Timeout => ControlAuditError::LockTimeout,
        })?;
        if shutdown.load(Ordering::SeqCst) {
            return Err(ControlAuditError::Cancelled);
        }
        // This append is the linearization point. Do not observe cancellation
        // after it: the ring insert and prepared snapshot commit must complete.
        let seq = wal
            .append_control_critical(&event_canonical_json)
            .map_err(ControlAuditError::WalAppend)?;
        buffer.append(crate::audit::PendingAuditEvent {
            event_canonical_json,
            captured_at: std::time::SystemTime::now(),
            critical: true,
        });
        Ok(seq)
    }

    /// Sole production chokepoint for making a newly read manifest live. The
    /// store mutex serializes watcher, IPC, and boot. Verification builds an
    /// owned exact candidate; the critical WAL receipt is required before the
    /// private commit step can run.
    pub(crate) fn reload_manifest_authorized(
        &self,
        operation: &str,
        context: &str,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        self.reload_manifest_authorized_cancellable(
            operation,
            context,
            self.mutation_cancel.as_ref(),
            MANIFEST_RELOAD_LOCK_BUDGET,
        )
    }

    /// THE BOOT LOAD, and the only reload that may write the armed identity.
    ///
    /// It is a separate entry point rather than a flag on the shared one because
    /// the distinction is a security property, not a mode: every other caller
    /// keeps its existing signature and passes [`IdentityGate::Frozen`], so no
    /// edit to `src/ipc/` or `src/manifest/` can reach the freeze.
    ///
    /// Ordering that makes the unset-cell admission safe: this runs at
    /// `daemon::boot` BEFORE `IpcServer::start` binds the socket and before the
    /// manifest watcher is acquired (the watcher is acquired only inside kernel
    /// activation), so no other reload can exist while the cell is unset.
    ///
    /// A repeat call is a composition-root bug, not an operator condition, and is
    /// refused BEFORE the reload so a second boot load cannot re-verify a
    /// manifest under an already-frozen identity.
    pub(crate) fn reload_manifest_authorized_at_boot(
        &self,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        if self.armed_identity.get().is_some() {
            return Err(ManifestReloadAuthorizationError::IdentityFreeze(
                "the boot manifest load ran twice in one process; the armed identity is \
                 write-once and a second boot load would read as a legitimate change"
                    .to_string(),
            ));
        }
        self.reload_manifest_authorized_gated(
            BOOT_MANIFEST_LOAD_OPERATION,
            BOOT_MANIFEST_LOAD_CONTEXT,
            self.mutation_cancel.as_ref(),
            MANIFEST_RELOAD_LOCK_BUDGET,
            IdentityGate::BootFreeze,
        )
    }

    /// Refuse a candidate manifest whose admitted identity differs from the one
    /// this process froze at boot.
    ///
    /// INVARIANT, and why it is here rather than after the commit: the kernel has
    /// a uid bound to it and nothing in this process can un-bind it atomically
    /// with a policy swap, so an identity change must be refused BEFORE the
    /// durable authorization receipt that licenses the commit. The refusal is
    /// therefore the callback's first act after the shutdown check.
    ///
    /// The derivation is `PolicySnapshot::from_loaded_manifest` over the exact
    /// bytes the store already prepared, so the comparison is against the
    /// candidate that would become live, never against a re-read of disk.
    fn refuse_identity_change(&self, loaded: &LoadedManifest) -> Result<(), ControlAuditError> {
        let Some(frozen) = self.armed_identity.get() else {
            // An unset cell on a NON-boot reload means the freeze has not happened
            // yet, so there is no identity to compare against. Absent evidence is
            // not passing evidence: refuse.
            return Err(ControlAuditError::IdentityChangeWhileArmed(
                "this process has not frozen an admitted identity yet, so a policy change \
                 cannot be proven to preserve it"
                    .to_string(),
            ));
        };
        let candidate = PolicySnapshot::from_loaded_manifest(loaded)
            .map_err(|err| {
                ControlAuditError::IdentityChangeWhileArmed(format!(
                    "the candidate manifest's admitted identity could not be derived ({err}), \
                     so it cannot be proven to preserve the armed identity"
                ))
            })
            .and_then(|snapshot| {
                AdmittedIdentity::from_snapshot(&snapshot)
                    .map_err(ControlAuditError::IdentityChangeWhileArmed)
            })?;
        if candidate.subject == frozen.subject {
            return Ok(());
        }
        Err(ControlAuditError::IdentityChangeWhileArmed(format!(
            "the candidate manifest changes the admitted identity this process armed \
             (armed={:?} candidate={:?}); the kernel binding cannot follow a live identity \
             change, so the reload is refused and the prior policy stays live. Repair order: \
             stop the wall, --disarm, start",
            frozen.subject, candidate.subject
        )))
    }

    /// IPC form of the same chokepoint. Mutex acquisition is polled under a
    /// short deadline and shutdown cancellation is checked after every
    /// potentially blocking filesystem/WAL step and immediately before commit.
    /// Thus teardown never waits behind another handler's mutex and a handler
    /// returning late from I/O cannot publish a candidate after stop began.
    pub(crate) fn reload_manifest_authorized_cancellable(
        &self,
        operation: &str,
        context: &str,
        shutdown: &AtomicBool,
        max_wait: Duration,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        self.reload_manifest_authorized_gated(
            operation,
            context,
            shutdown,
            max_wait,
            IdentityGate::Frozen,
        )
    }

    /// The shared implementation behind both reload entry points. `gate` is the
    /// only difference between them and it is a private type, so the boot
    /// behaviour cannot be reached from another module.
    fn reload_manifest_authorized_gated(
        &self,
        operation: &str,
        context: &str,
        shutdown: &AtomicBool,
        max_wait: Duration,
        gate: IdentityGate,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        let deadline = Instant::now() + max_wait;
        let store = self
            .manifest_store
            .as_ref()
            .ok_or(ManifestReloadAuthorizationError::StoreUnwired)?;
        let mut guard = cancellable_lock(store, shutdown, deadline).map_err(|err| match err {
            LockAcquireError::Poisoned => ManifestReloadAuthorizationError::StorePoisoned,
            LockAcquireError::Cancelled | LockAcquireError::Timeout => {
                ManifestReloadAuthorizationError::Cancelled
            }
        })?;
        let mut summary = None;
        // `map(|_| ())` DROPS the `&LoadedManifest` the store hands back. The
        // borrow is of `guard`, and the boot freeze below has to read
        // `guard.current_snapshot()` while still holding the same guard; keeping
        // the returned borrow alive across that read would not compile, and
        // releasing the guard first would open the window this whole design
        // closes.
        let outcome = guard
            .reload_with_authorization(|loaded| {
                if shutdown.load(Ordering::SeqCst) {
                    return Err(ControlAuditError::Cancelled);
                }
                // The identity comparison runs BEFORE the success audit append:
                // a refused reload must leave no `..._authorized` row claiming a
                // policy change this process did not make.
                if matches!(gate, IdentityGate::Frozen) {
                    self.refuse_identity_change(loaded)?;
                }
                let candidate = ManifestReloadSummary {
                    signature_b64url: loaded.manifest_signature_b64url.clone(),
                    rule_count: loaded.rule_count,
                };
                let detail = format!(
                    "context={context} signature={} rules={}",
                    candidate.signature_b64url, candidate.rule_count
                );
                self.append_control_audit_cancellable(operation, &detail, shutdown, deadline)?;
                summary = Some(candidate);
                Ok(())
            })
            .map(|_| ());
        let result = match outcome {
            // Safety: the Ok arm means the authorization callback ran to completion,
            // and its last statement assigns `summary`. Any early return inside the
            // callback yields Err, which the arms below handle.
            Ok(()) => Ok(summary.expect("authorization callback completed")),
            Err(AuthorizedReloadError::Verify(err)) => {
                Err(ManifestReloadAuthorizationError::Verify(err))
            }
            Err(AuthorizedReloadError::Authorization(ControlAuditError::Cancelled)) => {
                Err(ManifestReloadAuthorizationError::Cancelled)
            }
            // AHEAD of the catch-all below on purpose: a refused identity change is
            // a typed policy refusal, not a failure of the audit channel, and a
            // consumer that reads it as `Audit` would treat it as fatal.
            Err(AuthorizedReloadError::Authorization(
                ControlAuditError::IdentityChangeWhileArmed(detail),
            )) => Err(ManifestReloadAuthorizationError::IdentityChangeWhileArmed(
                detail,
            )),
            Err(AuthorizedReloadError::Authorization(err)) => {
                Err(ManifestReloadAuthorizationError::Audit(err))
            }
        };
        match gate {
            IdentityGate::Frozen => result,
            // THE FREEZE, under the store guard this function still holds, for
            // every outcome that lets boot continue. Returning before the write
            // would leave a window in which the daemon is running with no armed
            // identity, and `boot` refuses to start IPC in exactly that state.
            IdentityGate::BootFreeze => self.freeze_at_boot(&guard, result),
        }
    }

    /// Write the armed identity from the outcome of the boot load.
    ///
    /// Three outcomes, and each is a different claim about what is live:
    /// * `Ok`  — the snapshot COMMITTED, read back from the store rather than
    ///   from the candidate, so the frozen identity is the one being enforced.
    /// * `Verify` — nothing committed and the daemon continues deny-by-default
    ///   with no policy, which confines nobody: `Unconfined`, under this
    ///   engine's own fortress id.
    /// * anything else — boot aborts, so the cell stays unset and no later
    ///   reader can mistake a half-started process for an armed one.
    fn freeze_at_boot(
        &self,
        guard: &MutexGuard<'_, ManifestStore>,
        result: Result<ManifestReloadSummary, ManifestReloadAuthorizationError>,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        let identity = match &result {
            Ok(_) => {
                let Some(snapshot) = guard.current_snapshot() else {
                    // A committed reload with no snapshot is a composition bug in
                    // the store, not an operator condition. Continuing would freeze
                    // an implicit `Unconfined` over a policy that may confine.
                    return Err(ManifestReloadAuthorizationError::IdentityFreeze(
                        "the boot manifest load reported success but the store holds no \
                         policy snapshot to freeze an identity from"
                            .to_string(),
                    ));
                };
                match AdmittedIdentity::from_snapshot(snapshot) {
                    Ok(identity) => identity,
                    Err(detail) => {
                        return Err(ManifestReloadAuthorizationError::IdentityFreeze(detail))
                    }
                }
            }
            Err(ManifestReloadAuthorizationError::Verify(_)) => AdmittedIdentity {
                fortress_id: self.fortress_id().to_string(),
                subject: AdmittedSubject::Unconfined,
            },
            Err(_) => return result,
        };
        match self.armed_identity.set(identity) {
            Ok(()) => result,
            Err(_) => Err(ManifestReloadAuthorizationError::IdentityFreeze(
                "the armed identity was already frozen when the boot load tried to write it"
                    .to_string(),
            )),
        }
    }

    /// Authenticated broker publication: serialize on the same store mutex as
    /// watcher/reload, verify a complete byte bundle, durably audit the exact
    /// signature/count, and only then switch the active on-disk generation and
    /// in-memory evaluator snapshot.
    pub(crate) fn publish_manifest_bundle_authorized_cancellable(
        &self,
        manifest_bytes: &[u8],
        rules: &[(String, Vec<u8>)],
        context: &str,
        shutdown: &AtomicBool,
        max_wait: Duration,
    ) -> Result<ManifestReloadSummary, ManifestReloadAuthorizationError> {
        let deadline = Instant::now() + max_wait;
        let store = self
            .manifest_store
            .as_ref()
            .ok_or(ManifestReloadAuthorizationError::StoreUnwired)?;
        let mut guard = cancellable_lock(store, shutdown, deadline).map_err(|err| match err {
            LockAcquireError::Poisoned => ManifestReloadAuthorizationError::StorePoisoned,
            LockAcquireError::Cancelled | LockAcquireError::Timeout => {
                ManifestReloadAuthorizationError::Cancelled
            }
        })?;
        let mut summary = None;
        match guard.publish_bundle_with_authorization(manifest_bytes, rules, |loaded| {
            if shutdown.load(Ordering::SeqCst) {
                return Err(ControlAuditError::Cancelled);
            }
            // Publication is an ordinary armed caller: it gets the same refusal,
            // in the same place (before the success audit append). A publish that
            // arrives between the boot freeze and kernel activation is refused
            // against the cell, which is why activation can trust it.
            self.refuse_identity_change(loaded)?;
            let candidate = ManifestReloadSummary {
                signature_b64url: loaded.manifest_signature_b64url.clone(),
                rule_count: loaded.rule_count,
            };
            self.append_control_audit_cancellable(
                "ipc_policy_bundle_publish_authorized",
                &format!(
                    "context={context} signature={} rules={}",
                    candidate.signature_b64url, candidate.rule_count
                ),
                shutdown,
                deadline,
            )?;
            // Re-check after the durability write: shutdown may have begun
            // while fsync was in flight. Never switch the active pointer on a
            // mutation that became cancelled during authorization.
            if shutdown.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return Err(ControlAuditError::Cancelled);
            }
            summary = Some(candidate);
            Ok(())
        }) {
            // Safety: same invariant as `reload_manifest_authorized` above -- the Ok
            // arm is reachable only after the callback's final `summary = Some(..)`.
            Ok(_) => Ok(summary.expect("publication authorization callback completed")),
            Err(AuthorizedReloadError::Verify(err)) => {
                Err(ManifestReloadAuthorizationError::Verify(err))
            }
            Err(AuthorizedReloadError::Authorization(ControlAuditError::Cancelled)) => {
                Err(ManifestReloadAuthorizationError::Cancelled)
            }
            // AHEAD of the catch-all below, for the same reason as the reload
            // path: the typed identity refusal must not surface as an audit
            // failure, which consumers treat as fatal.
            Err(AuthorizedReloadError::Authorization(
                ControlAuditError::IdentityChangeWhileArmed(detail),
            )) => Err(ManifestReloadAuthorizationError::IdentityChangeWhileArmed(
                detail,
            )),
            Err(AuthorizedReloadError::Authorization(err)) => {
                Err(ManifestReloadAuthorizationError::Audit(err))
            }
        }
    }

    /// Evaluate one outbound attempt and durably record the decision.
    pub fn evaluate_attempt(
        &self,
        request: &EvaluationRequest,
    ) -> Result<EvaluationOutcome, AttemptError> {
        let store = self
            .manifest_store
            .as_ref()
            .ok_or(AttemptError::ManifestStoreUnwired)?;
        let wal = self.wal_writer.as_ref().ok_or(AttemptError::WalUnwired)?;

        // GF3 availability invariant: the verdict path must NEVER block
        // unboundedly on a mutex a control-plane operation (reload/drain/ACK) may
        // hold across an fsync. Acquire under one shared wall-clock deadline; on
        // contention, fail CLOSED (default-deny) rather than stall until the
        // NFQUEUE `verdict_deadline` fail-stops the whole daemon. The store guard
        // is a SHORT critical section (snapshot read only) and is dropped before
        // the WAL append below, so no fsync is ever held under it.
        let deadline = Instant::now() + EVALUATE_ATTEMPT_LOCK_BUDGET;
        let (verdict, audit_fortress_id, audit_confined_agent_uid) =
            match bounded_lock_until(store, deadline) {
                Ok(guard) => match guard.current_snapshot() {
                    Some(snapshot) => (
                        snapshot.evaluate(request),
                        snapshot.fortress_id.clone(),
                        snapshot.confined_agent_uid,
                    ),
                    None => (
                        Verdict::Deny {
                            reason: DeniedReason::DefaultDeny,
                        },
                        self.fortress_id.clone(),
                        None,
                    ),
                },
                Err(LockAcquireError::Poisoned) => return Err(AttemptError::ManifestStorePoisoned),
                // Timeout (a stalled control-plane holder): fail closed with a
                // default-deny verdict, then still durably record it below.
                Err(_) => (
                    Verdict::Deny {
                        reason: DeniedReason::DefaultDeny,
                    },
                    self.fortress_id.clone(),
                    None,
                ),
            };

        let timestamp_iso = current_timestamp_iso8601();
        let event_canonical_json = build_audit_event_canonical_json(
            &verdict,
            request,
            &audit_fortress_id,
            audit_confined_agent_uid,
            &timestamp_iso,
        )
        .map_err(AttemptError::AuditCanonicalize)?;

        // GF3: acquire the WAL under the SAME shared deadline. A control-plane
        // op holding the WAL mutex across a slow fsync must not stall the verdict
        // path. An acquisition timeout is treated exactly like an append failure
        // below (fail closed), so the audit-storage-unavailable case and the
        // audit-append-failed case both DENY. The normal path still fsyncs
        // synchronously under the guard, preserving durability and the
        // fail-closed-on-audit-failure property.
        let append_result: Result<u64, ()> = match bounded_lock_until(wal, deadline) {
            Ok(mut guard) => guard.append_critical(&event_canonical_json).map_err(|_| ()),
            Err(LockAcquireError::Poisoned) => return Err(AttemptError::WalPoisoned),
            Err(_) => Err(()),
        };

        match append_result {
            Ok(seq) => {
                // GF3 availability invariant: the ring-buffer insert is a
                // best-effort IPC-drain side effect AFTER the durable verdict, so
                // it must never stall the verdict thread. The WAL guard from the
                // `append_result` match above has already been dropped (its match
                // arm scope ended), so this acquires the ring with NO other lock
                // held; taking it under the SAME shared `deadline` (not an
                // unbounded `lock()`) keeps the ordering acyclic w.r.t.
                // `append_control_audit`'s buffer->WAL order AND caps the verdict
                // at `deadline` even when a control-plane drain holds the ring
                // across a slow write. A contended/poisoned ring is skipped (the
                // durable receipt already exists), never blocked on.
                if let Ok(mut buffer) = bounded_lock_until(&self.audit_buffer, deadline) {
                    buffer.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: event_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        critical: false,
                    });
                }
                Ok(EvaluationOutcome {
                    verdict,
                    wal_seq: Some(seq),
                    event_canonical_json,
                    timestamp_iso8601: timestamp_iso,
                })
            }
            Err(_wal_error) => {
                let disposition = default_disposition(FailureMode::RuntimeAuditWalAppendFailed);
                debug_assert!(
                    matches!(
                        disposition,
                        FailureDisposition::FailClosed {
                            emit_event: "egress_blocked",
                            reason: "audit_wal_append_failed",
                        }
                    ),
                    "RuntimeAuditWalAppendFailed must dispatch to FailClosed with the audit failure reason",
                );

                let fail_closed_verdict = Verdict::Deny {
                    reason: DeniedReason::AuditWalAppendFailed,
                };
                let fail_closed_canonical_json = build_audit_event_canonical_json(
                    &fail_closed_verdict,
                    request,
                    &audit_fortress_id,
                    audit_confined_agent_uid,
                    &timestamp_iso,
                )
                .map_err(AttemptError::AuditCanonicalize)?;

                // GF3: same bounded, no-lock-held acquisition as the success path
                // above (the WAL guard is already dropped). The fail-closed receipt
                // is durable via the ring's critical flag on drain; a contended ring
                // is skipped rather than allowed to stall the fail-closed verdict.
                if let Ok(mut buffer) = bounded_lock_until(&self.audit_buffer, deadline) {
                    buffer.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: fail_closed_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        critical: true,
                    });
                }

                Ok(EvaluationOutcome {
                    verdict: fail_closed_verdict,
                    wal_seq: None,
                    event_canonical_json: fail_closed_canonical_json,
                    timestamp_iso8601: timestamp_iso,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestReloadSummary {
    pub signature_b64url: String,
    pub rule_count: u32,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManifestReloadAuthorizationError {
    #[error("manifest store is not wired")]
    StoreUnwired,
    #[error("manifest store mutex is poisoned")]
    StorePoisoned,
    #[error("manifest verification failed: {0}")]
    Verify(ManifestStoreError),
    #[error("durable reload authorization failed: {0}")]
    Audit(ControlAuditError),
    #[error("manifest reload cancelled during daemon shutdown")]
    Cancelled,
    /// The candidate would change the identity this process armed at boot. A
    /// POLICY refusal: the prior snapshot stays live and the component that saw
    /// it keeps running, which is why it is not an `Audit` failure.
    ///
    /// CROSS-FILE CONTRACT: the variant NAME is part of the message on purpose.
    /// `src/ipc/server.rs` surfaces this error through an unchanged
    /// `to_string()`, so the identifying token is the only thing an operator or a
    /// drill leg can match on; removing it from the format string would silently
    /// empty the L-R evidence string while every type check still passed. Must
    /// match the needle in the L-R leg of
    /// `Review/Sanctuary/Linux_PR3b_Design_Packet_2026-09-19.md`.
    #[error("manifest reload refused: IdentityChangeWhileArmed: {0}")]
    IdentityChangeWhileArmed(String),
    /// The armed-identity cell could not be written or was already written. A
    /// composition-root bug rather than an operator condition; `boot` turns it
    /// into a refuse-to-start.
    #[error("armed identity could not be frozen: {0}")]
    IdentityFreeze(String),
}

impl ManifestReloadAuthorizationError {
    /// Publication crossed the on-disk active-pointer commit point but could
    /// not finish the in-process commit. The IPC layer must make the whole
    /// daemon non-green and let systemd restart/reconcile; an ordinary refusal
    /// response would leave disk and memory enforcing different generations.
    pub(crate) fn requires_supervised_restart(&self) -> bool {
        matches!(
            self,
            Self::Verify(err) if err.requires_supervised_restart()
        )
    }
}

/// Failures in the required durable control-audit path. Watcher callers treat
/// every variant as fatal to the pending mutation (and, after readiness, to the
/// watcher component) so systemd can restore a known-good process.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlAuditError {
    #[error("control-audit WAL writer is not wired")]
    WalUnwired,
    #[error("control-audit WAL writer mutex is poisoned")]
    WalPoisoned,
    #[error("control-audit WAL append failed: {0}")]
    WalAppend(WalError),
    #[error("control-audit ring buffer mutex is poisoned")]
    AuditBufferPoisoned,
    #[error("control-audit canonicalization failed: {0}")]
    Canonicalize(CanonicalJsonError),
    #[error("control-audit operation cancelled during daemon shutdown")]
    Cancelled,
    #[error("control-audit mutex acquisition exceeded shutdown budget")]
    LockTimeout,
    /// Carried through the authorization callback's error channel because that
    /// is the only channel the store's mutation primitive offers, NOT because it
    /// is an audit failure. Both engine match blocks map it to
    /// [`ManifestReloadAuthorizationError::IdentityChangeWhileArmed`] ahead of
    /// their catch-all so the distinction survives the boundary.
    /// CROSS-FILE CONTRACT: the variant name is part of the message for the same
    /// reason as on `ManifestReloadAuthorizationError`. A caller that surfaces
    /// THIS error's `to_string()` without the mapping above must still produce
    /// the identifying token.
    #[error("admitted identity change refused while armed: IdentityChangeWhileArmed: {0}")]
    IdentityChangeWhileArmed(String),
}

impl ControlAuditError {
    pub(crate) fn is_capacity_exceeded(&self) -> bool {
        matches!(self, Self::WalAppend(WalError::CapacityExceeded { .. }))
    }
}

enum LockAcquireError {
    Poisoned,
    Cancelled,
    Timeout,
}

/// Bounded wall-clock budget for the verdict path to ACQUIRE the manifest-store
/// and WAL mutexes in [`DecisionEngine::evaluate_attempt`]. Derived from what it
/// sits between: it must exceed a normal control-plane critical section (a
/// reload/drain/ACK briefly holding the mutex, single-digit ms) yet stay well
/// under the NFQUEUE per-verdict deadline (`NfqueueConfig::verdict_deadline`,
/// 2s), so a control-plane op that stalls a mutex across a slow fsync makes the
/// verdict FAIL CLOSED here (default-deny + audit-failure record) BEFORE the
/// queue deadline fail-stops the whole daemon. 1s keeps a full second of
/// headroom under the 2s queue deadline; the normal (uncontended) path acquires
/// in microseconds, so this budget only ever bites under a real stall.
const EVALUATE_ATTEMPT_LOCK_BUDGET: Duration = Duration::from_secs(1);

/// Acquire a mutex under a wall-clock deadline, IGNORING the shutdown flag.
///
/// Distinct from [`cancellable_lock`], and the difference is the whole reason it
/// exists: `cancellable_lock` gives up when shutdown begins, which is correct for
/// a control MUTATION. The superseding-verdict record is not a mutation, it is
/// EVIDENCE about the shutdown itself, and every path that writes it runs with
/// the shutdown flag already set. Reusing the cancellable helper there would
/// make the record unwritable exactly when it is needed.
fn bounded_lock<T>(
    mutex: &Mutex<T>,
    budget: Duration,
) -> Result<MutexGuard<'_, T>, ControlAuditError> {
    let deadline = Instant::now() + budget;
    bounded_lock_until(mutex, deadline).map_err(|err| match err {
        LockAcquireError::Poisoned => ControlAuditError::WalPoisoned,
        LockAcquireError::Timeout => ControlAuditError::LockTimeout,
        LockAcquireError::Cancelled => unreachable!("bounded lock is not cancellable"),
    })
}

fn bounded_lock_until<T>(
    mutex: &Mutex<T>,
    deadline: Instant,
) -> Result<MutexGuard<'_, T>, LockAcquireError> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(LockAcquireError::Poisoned),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return Err(LockAcquireError::Timeout),
        }
    }
}

fn cancellable_lock<'a, T>(
    mutex: &'a Mutex<T>,
    shutdown: &AtomicBool,
    deadline: Instant,
) -> Result<MutexGuard<'a, T>, LockAcquireError> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(LockAcquireError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(LockAcquireError::Timeout);
        }
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(LockAcquireError::Poisoned),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

// The daemon binds the uid a signed manifest admits, and holds that identity for
// as long as the process runs. These tests cover the freeze at boot, the refusal
// of any later identity change, and the structural facts the two must rest on.
// Register: defect.linux-readiness-precedes-confinement.
#[cfg(test)]
mod armed_identity_tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        policy_dir: std::path::PathBuf,
        signing: SigningKey,
        store: Arc<Mutex<ManifestStore>>,
        wal: Arc<Mutex<WalWriter>>,
        engine: DecisionEngine,
    }

    const FORTRESS: &str = "deadbeef";

    fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let store = Arc::new(Mutex::new(ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            FORTRESS.to_string(),
        )));
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            64 * 1024,
            Duration::from_secs(60),
        )));
        let engine = DecisionEngine::new(
            FORTRESS.to_string(),
            Some(Arc::clone(&store)),
            Some(Arc::clone(&wal)),
            ring,
        );
        Fixture {
            _dir: dir,
            policy_dir,
            signing,
            store,
            wal,
            engine,
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    /// One signed manifest bundle: the manifest bytes plus its rule files.
    /// The ceiling every fixture manifest admits unless a test asks for another.
    /// Named so a test that means to CHANGE the ceiling can, which a hard-coded
    /// literal in the helper quietly prevented.
    const FIXTURE_CEILING: u32 = 500;

    fn signed_bundle(
        signing: &SigningKey,
        generation: u64,
        agent_uid: Option<u32>,
        gate_uid: Option<u32>,
        rule_id: &str,
    ) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        signed_bundle_with_ceiling(
            signing,
            generation,
            agent_uid,
            gate_uid,
            FIXTURE_CEILING,
            rule_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_bundle_with_ceiling(
        signing: &SigningKey,
        generation: u64,
        agent_uid: Option<u32>,
        gate_uid: Option<u32>,
        ceiling: u32,
        rule_id: &str,
    ) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        use crate::manifest::verify::{
            AgentOrigin, AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
        };
        let rule_file = format!("{rule_id}.json");
        let rule_body = format!(
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-09-19T00:00:00Z\",\
             \"match\":{{\"ip\":[\"203.0.113.7\"]}},\"disposition\":\"allow\"}}"
        )
        .into_bytes();
        let habeas_file = format!("{}.json", crate::habeas::HABEAS_LOCAL_RULE_ID);
        let habeas_body = crate::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes().to_vec();
        let manifest = AllowlistManifest {
            schema_version: crate::constants::SCHEMA_VERSION_V1,
            fortress_id: FORTRESS.to_string(),
            issued_at: "2026-09-19T00:00:00Z".to_string(),
            generation,
            agent_origin: agent_uid.map(|uid| AgentOrigin {
                mode: "uid".to_string(),
                egress_helper_signing_id: None,
                egress_helper_team_id: None,
                agent_runtime_port_range: None,
                agent_uid: Some(uid),
                gate_uid,
                system_uid_allow_ceiling: ceiling,
            }),
            operator_baseline: None,
            rules: vec![
                ManifestRuleEntry {
                    rule_id: rule_id.to_string(),
                    file: rule_file.clone(),
                    sha256: sha256_hex(&rule_body),
                },
                ManifestRuleEntry {
                    rule_id: crate::habeas::HABEAS_LOCAL_RULE_ID.to_string(),
                    file: habeas_file.clone(),
                    sha256: sha256_hex(&habeas_body),
                },
            ],
        };
        let canonical = crate::manifest::canonical_json::canonicalize_to_bytes(
            &serde_json::to_value(&manifest).unwrap(),
        )
        .unwrap();
        let signature = signing.sign(&canonical);
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: crate::crypto::castle_wall_signing_key_id(
                    &signing.verifying_key().to_bytes(),
                )
                .unwrap(),
                signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.to_bytes()),
            },
        };
        (
            serde_json::to_vec_pretty(&signed).unwrap(),
            vec![(rule_file, rule_body), (habeas_file, habeas_body)],
        )
    }

    fn write_policy(
        policy_dir: &std::path::Path,
        signing: &SigningKey,
        generation: u64,
        agent_uid: Option<u32>,
        gate_uid: Option<u32>,
        rule_id: &str,
    ) {
        write_policy_with_ceiling(
            policy_dir,
            signing,
            generation,
            agent_uid,
            gate_uid,
            FIXTURE_CEILING,
            rule_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_policy_with_ceiling(
        policy_dir: &std::path::Path,
        signing: &SigningKey,
        generation: u64,
        agent_uid: Option<u32>,
        gate_uid: Option<u32>,
        ceiling: u32,
        rule_id: &str,
    ) {
        use crate::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
        let (manifest_bytes, rules) =
            signed_bundle_with_ceiling(signing, generation, agent_uid, gate_uid, ceiling, rule_id);
        std::fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
        for (name, body) in rules {
            std::fs::write(policy_dir.join(RULES_SUBDIR).join(name), body).unwrap();
        }
        std::fs::write(policy_dir.join(MANIFEST_FILENAME), manifest_bytes).unwrap();
    }

    fn audit_operations(wal: &Arc<Mutex<WalWriter>>) -> Vec<String> {
        wal.lock()
            .unwrap()
            .snapshot_after(None, 100)
            .unwrap()
            .iter()
            .map(|entry| {
                let row: serde_json::Value =
                    serde_json::from_str(&entry.event_canonical_json).unwrap();
                row["operation"].as_str().unwrap_or_default().to_string()
            })
            .collect()
    }

    #[test]
    fn a_verify_failure_at_boot_freezes_unconfined_before_anything_else_can_run() {
        let f = fixture();
        // No manifest on disk: the boot load fails verification and the daemon
        // continues deny-by-default with no policy, which confines nobody.
        let err = f.engine.reload_manifest_authorized_at_boot().unwrap_err();
        assert!(matches!(err, ManifestReloadAuthorizationError::Verify(_)));
        let identity = f.engine.armed_identity().expect("the cell must be written");
        assert_eq!(identity.subject, AdmittedSubject::Unconfined);
        assert_eq!(identity.fortress_id, FORTRESS);
    }

    #[test]
    fn a_successful_boot_freezes_the_committed_snapshot_identity() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), Some(60124), "r1");
        f.engine.reload_manifest_authorized_at_boot().unwrap();
        let identity = f.engine.armed_identity().unwrap();
        assert_eq!(
            identity.subject,
            AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: Some(60124),
            }
        );
        // The frozen identity is the COMMITTED snapshot's, not a candidate's.
        let guard = f.store.lock().unwrap();
        let snapshot = guard.current_snapshot().unwrap();
        assert_eq!(snapshot.confined_agent_uid, Some(60123));
        assert_eq!(identity.fortress_id, snapshot.fortress_id);
    }

    #[test]
    fn a_frozen_reload_with_an_unset_cell_is_refused() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        // No boot load has run, so nothing has been frozen.
        let err = f
            .engine
            .reload_manifest_authorized("watcher_reload", "watcher")
            .unwrap_err();
        assert!(
            matches!(
                err,
                ManifestReloadAuthorizationError::IdentityChangeWhileArmed(_)
            ),
            "an unset cell must refuse, never admit: {err}"
        );
    }

    #[test]
    fn a_reload_that_changes_the_admitted_uid_is_refused_and_keeps_the_prior_policy() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        f.engine.reload_manifest_authorized_at_boot().unwrap();
        // A valid, correctly signed manifest that admits a DIFFERENT uid.
        write_policy(&f.policy_dir, &f.signing, 2, Some(60125), None, "r2");
        let err = f
            .engine
            .reload_manifest_authorized("manifest_watcher_reload_authorized", "watcher")
            .unwrap_err();
        assert!(matches!(
            err,
            ManifestReloadAuthorizationError::IdentityChangeWhileArmed(_)
        ));
        // The prior snapshot is still live and the frozen identity is unchanged.
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .current_snapshot()
                .unwrap()
                .confined_agent_uid,
            Some(60123)
        );
        assert_eq!(
            f.engine.armed_identity().unwrap().subject,
            AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None
            }
        );
        // The refusal returns BEFORE the success audit append, so exactly one
        // authorized row exists: the boot one.
        let operations = audit_operations(&f.wal);
        assert_eq!(
            operations
                .iter()
                .filter(|op| op.as_str() == "manifest_watcher_reload_authorized")
                .count(),
            0,
            "a refused reload must leave no success row: {operations:?}"
        );
        assert_eq!(
            operations
                .iter()
                .filter(|op| op.as_str() == BOOT_MANIFEST_LOAD_OPERATION)
                .count(),
            1
        );
    }

    #[test]
    fn admitted_to_none_a_gate_uid_and_a_changed_ceiling_are_all_identity_changes() {
        // The third row is the one the helper used to make unreachable: the
        // bundle hard-coded ceiling 500, so a "changed ceiling" case was really a
        // second gate-uid case and the ceiling comparison was never exercised.
        for (agent_uid, gate_uid, ceiling) in [
            (None, None, FIXTURE_CEILING),
            (Some(60123), Some(60124), FIXTURE_CEILING),
            (Some(60123), None, FIXTURE_CEILING + 100),
        ] {
            let f = fixture();
            write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
            f.engine.reload_manifest_authorized_at_boot().unwrap();
            write_policy_with_ceiling(
                &f.policy_dir,
                &f.signing,
                2,
                agent_uid,
                gate_uid,
                ceiling,
                "r2",
            );
            let err = f
                .engine
                .reload_manifest_authorized("manifest_watcher_reload_authorized", "watcher")
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ManifestReloadAuthorizationError::IdentityChangeWhileArmed(_)
                ),
                "uid {agent_uid:?} gate {gate_uid:?} ceiling {ceiling} must be refused"
            );
        }
    }

    #[test]
    fn a_same_identity_rule_change_still_commits_with_its_audit_row() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        f.engine.reload_manifest_authorized_at_boot().unwrap();
        write_policy(&f.policy_dir, &f.signing, 2, Some(60123), None, "r2");
        f.engine
            .reload_manifest_authorized("manifest_watcher_reload_authorized", "watcher")
            .expect("a rule change that keeps the identity must commit");
        assert!(audit_operations(&f.wal)
            .iter()
            .any(|op| op == "manifest_watcher_reload_authorized"));
    }

    #[test]
    fn a_publish_arriving_before_activation_is_refused_against_the_frozen_cell() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        f.engine.reload_manifest_authorized_at_boot().unwrap();
        let (manifest_bytes, rules) = signed_bundle(&f.signing, 2, Some(60125), None, "r2");
        let shutdown = AtomicBool::new(false);
        let err = f
            .engine
            .publish_manifest_bundle_authorized_cancellable(
                &manifest_bytes,
                &rules,
                "ipc",
                &shutdown,
                Duration::from_secs(2),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                ManifestReloadAuthorizationError::IdentityChangeWhileArmed(_)
            ),
            "publication must surface the typed refusal, never an audit failure: {err}"
        );
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .current_snapshot()
                .unwrap()
                .confined_agent_uid,
            Some(60123)
        );
    }

    #[test]
    fn the_second_boot_load_is_refused_before_it_reloads_anything() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        f.engine.reload_manifest_authorized_at_boot().unwrap();
        // Plant a divergent manifest; the refusal must come from the cell check,
        // so this manifest is never read.
        write_policy(&f.policy_dir, &f.signing, 2, Some(60125), None, "r2");
        let err = f.engine.reload_manifest_authorized_at_boot().unwrap_err();
        assert!(matches!(
            err,
            ManifestReloadAuthorizationError::IdentityFreeze(_)
        ));
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .current_snapshot()
                .unwrap()
                .confined_agent_uid,
            Some(60123),
            "the refused second boot load must not have reloaded anything"
        );
    }

    #[test]
    fn every_clone_of_the_engine_observes_one_cell() {
        let f = fixture();
        write_policy(&f.policy_dir, &f.signing, 1, Some(60123), None, "r1");
        let shared = Arc::new(f.engine);
        let other = Arc::clone(&shared);
        shared.reload_manifest_authorized_at_boot().unwrap();
        assert_eq!(
            other.armed_identity().map(|identity| identity.subject),
            Some(AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None
            }),
            "a freeze the IPC-side handle cannot see is not a freeze"
        );
    }

    #[test]
    fn a_snapshot_with_a_uid_and_no_ceiling_is_refused_rather_than_defaulted() {
        let snapshot = PolicySnapshot {
            confined_agent_uid: Some(60123),
            confined_agent_uid_ceiling: None,
            ..PolicySnapshot::default()
        };
        assert!(AdmittedIdentity::from_snapshot(&snapshot).is_err());
    }

    // ---- structural facts the freeze rests on -------------------------------

    fn source(relative: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
            .unwrap_or_else(|err| panic!("read {relative}: {err}"))
    }

    /// A `#[cfg(test)]` block is not production code, so a token inside one must
    /// not count toward a production-call-site assertion.
    fn production_lines(body: &str) -> Vec<&str> {
        body.lines()
            .take_while(|line| !line.starts_with("#[cfg(test)]"))
            .collect()
    }

    #[test]
    fn the_boot_freeze_has_exactly_one_production_call_site_and_one_marker() {
        let daemon = source("src/daemon.rs");
        let callers = production_lines(&daemon)
            .iter()
            .filter(|line| line.contains("reload_manifest_authorized_at_boot("))
            .count();
        assert_eq!(
            callers, 1,
            "the boot entry must have exactly one production caller, the boot match in daemon.rs"
        );
        let decision = source("src/decision.rs");
        // The marker as an ARGUMENT (trailing comma), which is the form that
        // selects the freeze. The match arm that READS it is a different shape
        // and counting it would make this assertion meaningless.
        let production = production_lines(&decision);
        let marker_lines: Vec<usize> = production
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim() == "IdentityGate::BootFreeze,")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            marker_lines.len(),
            1,
            "the BootFreeze marker must be passed at exactly one site; a second would be a \
             second thing allowed to write the cell"
        );
        // And that one site is INSIDE the boot wrapper, not in some other call.
        let wrapper_at = production
            .iter()
            .position(|line| line.contains("fn reload_manifest_authorized_at_boot("))
            .expect("the boot wrapper must exist");
        let next_fn_at = production
            .iter()
            .enumerate()
            .skip(wrapper_at + 1)
            .find(|(_, line)| line.starts_with("    fn ") || line.starts_with("    pub(crate) fn "))
            .map(|(index, _)| index)
            .unwrap_or(production.len());
        assert!(
            marker_lines[0] > wrapper_at && marker_lines[0] < next_fn_at,
            "the BootFreeze argument must sit inside reload_manifest_authorized_at_boot"
        );
        for entry in [
            "reload_manifest_authorized_cancellable",
            "publish_manifest_bundle_authorized_cancellable",
        ] {
            assert!(
                decision.contains(entry),
                "{entry} must keep its signature so src/ipc/ needs no edit"
            );
        }
    }

    #[test]
    fn the_identity_refusal_arm_precedes_the_catch_all_in_both_engine_match_blocks() {
        let decision = source("src/decision.rs");
        let production = production_lines(&decision);
        let typed_positions: Vec<usize> = production
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.trim() == "ControlAuditError::IdentityChangeWhileArmed(detail),"
            })
            .map(|(index, _)| index)
            .collect();
        let catch_all_positions: Vec<usize> = production
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.trim() == "Err(AuthorizedReloadError::Authorization(err)) => {"
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(typed_positions.len(), 2, "one arm per engine match block");
        assert_eq!(catch_all_positions.len(), 2);
        for (typed_at, catch_all_at) in typed_positions.iter().zip(catch_all_positions.iter()) {
            assert!(
                typed_at < catch_all_at,
                "the typed identity arm must precede the catch-all, or the refusal reads as an \
                 audit failure"
            );
        }
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loss_audit_keeps_the_tagged_predicate_separate_from_detail() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(60),
        )));
        let engine = DecisionEngine::new("f".to_string(), None, Some(Arc::clone(&wal)), ring);
        engine
            .append_control_audit_bounded_with_safety_net(
                "kernel_runtime_lost",
                "reason=lost",
                Some(serde_json::json!({"state": "install_failed"})),
                FAILURE_AUDIT_BUDGET,
            )
            .unwrap();
        engine
            .append_control_audit_bounded_with_safety_net(
                "kernel_runtime_lost",
                "reason=retry",
                Some(serde_json::json!({"state": "not_attempted"})),
                FAILURE_AUDIT_BUDGET,
            )
            .unwrap();
        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        let states: Vec<String> = entries
            .iter()
            .map(|entry| {
                let row: serde_json::Value =
                    serde_json::from_str(&entry.event_canonical_json).unwrap();
                assert!(row["detail"].as_str().unwrap().starts_with("reason="));
                row["safety_net"]["state"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(states, ["install_failed", "not_attempted"]);
    }

    #[test]
    fn poisoned_ring_is_rejected_before_durable_authorization_receipt() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(60),
        )));
        let poison_target = Arc::clone(&ring);
        let _ = std::thread::spawn(move || {
            let _guard = poison_target.lock().unwrap();
            panic!("poison ring");
        })
        .join();
        let engine = DecisionEngine::new("f".to_string(), None, Some(Arc::clone(&wal)), ring);
        let err = engine
            .append_control_audit("policy_reload_authorized", "candidate=x")
            .unwrap_err();
        assert!(matches!(err, ControlAuditError::AuditBufferPoisoned));
        assert!(wal
            .lock()
            .unwrap()
            .snapshot_after(None, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fatal_loss_audit_refuses_a_never_returning_wal_owner_within_budget() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(60),
        )));
        let engine = DecisionEngine::new("f".to_string(), None, Some(Arc::clone(&wal)), ring);
        let _never_returning_owner = wal.lock().unwrap();
        let started = Instant::now();
        let err = engine
            .append_control_audit_bounded(
                "kernel_runtime_lost",
                "reason=test",
                FAILURE_AUDIT_BUDGET,
            )
            .unwrap_err();
        assert!(matches!(err, ControlAuditError::LockTimeout));
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "fatal-loss reporting must not inherit a stuck WAL owner"
        );
    }

    #[test]
    fn pre_linearization_cancellation_leaves_wal_untouched() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(60),
        )));
        let engine = DecisionEngine::new("f".to_string(), None, Some(Arc::clone(&wal)), ring);
        let cancelled = AtomicBool::new(true);
        let err = engine
            .append_control_audit_cancellable(
                "policy_reload_authorized",
                "candidate=x",
                &cancelled,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(matches!(err, ControlAuditError::Cancelled));
        assert!(wal
            .lock()
            .unwrap()
            .snapshot_after(None, 10)
            .unwrap()
            .is_empty());
    }

    // GF3 fault injection: hold the audit ring past the verdict budget during a
    // verdict. Before the fix the success path took an UNBOUNDED
    // `audit_buffer.lock()` in the opposite order from `append_control_audit`
    // (buffer->WAL), so a contended ring could stall the NFQUEUE verdict thread
    // until the 2s deadline fail-stopped the daemon (or deadlock via ABBA). The
    // verdict must now still return within the bounded acquisition budget: the
    // durable WAL receipt lands, the ring insert is skipped, no deadlock.
    #[test]
    fn verdict_returns_bounded_when_audit_ring_is_held_past_budget() {
        use crate::policy::EvaluationRequest;
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("audit.wal")).unwrap(),
        ));
        let ring = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(60),
        )));
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            dir.path().to_path_buf(),
            dir.path().join("pinned.key"),
            [0u8; 32],
            "f".to_string(),
        )));
        let engine = DecisionEngine::new(
            "f".to_string(),
            Some(store),
            Some(Arc::clone(&wal)),
            Arc::clone(&ring),
        );
        // Hold the ring from another thread for longer than the verdict budget.
        let held = Arc::clone(&ring);
        let (tx, rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(EVALUATE_ATTEMPT_LOCK_BUDGET + Duration::from_millis(500));
        });
        rx.recv().unwrap(); // the ring is now provably held before the verdict runs
        let request = EvaluationRequest {
            agent_id: "a".to_string(),
            agent_template: "t".to_string(),
            dest_host: None,
            dest_ip: Some("203.0.113.1".to_string()),
            dest_port: 443,
            dest_protocol: "tcp".to_string(),
            opaque: false,
        };
        let started = Instant::now();
        let outcome = engine
            .evaluate_attempt(&request)
            .expect("verdict must return, never block unboundedly on a contended ring");
        let elapsed = started.elapsed();
        assert!(
            outcome.wal_seq.is_some(),
            "the durable verdict receipt must still be written while the ring is contended"
        );
        assert!(
            elapsed < EVALUATE_ATTEMPT_LOCK_BUDGET + Duration::from_millis(400),
            "verdict must return within the bounded budget under ring contention (no stall to the \
             NFQUEUE deadline, no ABBA deadlock), took {elapsed:?}"
        );
        holder.join().unwrap();
    }
}

/// Policy decision plus its durable evidence receipt.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub verdict: Verdict,
    pub wal_seq: Option<u64>,
    pub event_canonical_json: String,
    pub timestamp_iso8601: String,
}

/// Errors returned before a kernel verdict can be produced.
#[derive(Debug, thiserror::Error)]
pub enum AttemptError {
    #[error("manifest store not wired into this decision engine")]
    ManifestStoreUnwired,
    #[error("WAL writer not wired into this decision engine")]
    WalUnwired,
    #[error("manifest store mutex poisoned")]
    ManifestStorePoisoned,
    #[error("WAL writer mutex poisoned")]
    WalPoisoned,
    #[error("audit-event canonicalization failed: {0}")]
    AuditCanonicalize(CanonicalJsonError),
    #[error("WAL append failed: {0}")]
    WalAppend(WalError),
}

fn current_timestamp_iso8601() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_ms = duration.as_millis() as i128;
    let seconds = (total_ms / 1000) as i64;
    let milliseconds = (total_ms % 1000) as i64;
    let (year, month, day, hour, minute, second) = ymd_hms_from_unix_seconds(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

fn ymd_hms_from_unix_seconds(unix_seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let seconds_per_day: i64 = 86_400;
    let mut days = unix_seconds.div_euclid(seconds_per_day);
    let mut seconds_of_day = unix_seconds.rem_euclid(seconds_per_day);
    if seconds_of_day < 0 {
        seconds_of_day += seconds_per_day;
        days -= 1;
    }
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = (if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    }) as u32;
    let calendar_year = (if month <= 2 { year + 1 } else { year }) as i32;
    let hour = (seconds_of_day / 3600) as u32;
    let minute = ((seconds_of_day % 3600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    (calendar_year, month, day, hour, minute, second)
}
