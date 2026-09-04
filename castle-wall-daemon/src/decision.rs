//! Policy decision engine shared by daemon lifecycle and kernel verdict loops.
//!
//! The daemon owns process lifetime and kernel resources. The decision engine
//! owns the smaller, cloneable security path: verified policy lookup, durable
//! audit emission, and fail-closed behavior when evidence cannot be written.
//! Keeping this object independent avoids a circular ownership relationship
//! when the daemon later owns an NFQUEUE thread whose callback must evaluate
//! packets through the daemon's policy state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use crate::audit::{AuditRingBuffer, WalError, WalWriter};
use crate::failure::{default_disposition, FailureDisposition, FailureMode};
use crate::manifest::canonical_json::CanonicalJsonError;
use crate::manifest::store::AuthorizedReloadError;
use crate::manifest::{ManifestStore, ManifestStoreError};
use crate::policy::{build_audit_event_canonical_json, DeniedReason, EvaluationRequest, Verdict};

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
        }
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
            Duration::from_secs(2),
        )
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
        match guard.reload_with_authorization(|loaded| {
            if shutdown.load(Ordering::SeqCst) {
                return Err(ControlAuditError::Cancelled);
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
        }) {
            Ok(_) => Ok(summary.expect("authorization callback completed")),
            Err(AuthorizedReloadError::Verify(err)) => {
                Err(ManifestReloadAuthorizationError::Verify(err))
            }
            Err(AuthorizedReloadError::Authorization(ControlAuditError::Cancelled)) => {
                Err(ManifestReloadAuthorizationError::Cancelled)
            }
            Err(AuthorizedReloadError::Authorization(err)) => {
                Err(ManifestReloadAuthorizationError::Audit(err))
            }
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
            Ok(_) => Ok(summary.expect("publication authorization callback completed")),
            Err(AuthorizedReloadError::Verify(err)) => {
                Err(ManifestReloadAuthorizationError::Verify(err))
            }
            Err(AuthorizedReloadError::Authorization(ControlAuditError::Cancelled)) => {
                Err(ManifestReloadAuthorizationError::Cancelled)
            }
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

#[cfg(test)]
mod mutation_tests {
    use super::*;
    use tempfile::TempDir;

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
