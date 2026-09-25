//! Daemon lifecycle orchestration.
//!
//! `run()` boots the daemon: installs signal handlers, opens the audit
//! WAL ring, binds the IPC UDS, starts the accept loop, and waits for a
//! shutdown signal (SIGTERM / SIGINT). On shutdown it asks the IPC server
//! to stop, drains in-flight audit events, and returns. The kernel-touching
//! modules (nftables, NFQUEUE bind, inotify watcher) are wired in by the
//! later checkpoints; this module is the orchestration spine they hang off.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::audit::{AuditRingBuffer, WalWriter};
use crate::config::DaemonConfig;
use crate::decision::{AttemptError, DecisionEngine, EvaluationOutcome};
use crate::enforcement::EnforcementRuntime;
use crate::failure::{FailureDisposition, FailureMode};
use crate::ipc::auth::{load_pinned_public_key, AuthError};
use crate::ipc::server::{IpcServer, IpcServerError};
use crate::live_status::{LifecyclePhase, LiveStatus};
use crate::manifest::{ManifestStore, ManifestStoreError};
use crate::policy::EvaluationRequest;
use crate::runtime_health::{RuntimeHealthState, RuntimeHealthView};

/// How often the supervision loop re-checks kernel-runtime health. Slower than
/// the shutdown tick so the bounded `nft` ownership proof is not run every tick.
/// Public because it is a CROSS-FILE contract: `main.rs` supervises with it, the
/// nft probe budget in `runtime_providers` is derived under it (a real proof must
/// run on every tick), and `runtime_health::STATUS_FRESHNESS_WINDOW` is three of
/// these. Changing it without re-deriving those is a defect a unit test catches.
pub const SUPERVISOR_HEALTH_INTERVAL: Duration = Duration::from_secs(2);

/// Shutdown-responsiveness tick for the supervision loop.
pub const SUPERVISOR_SHUTDOWN_TICK: Duration = Duration::from_millis(200);

/// Consecutive INDETERMINATE health readings the supervisor tolerates before it
/// treats the runtime as lost and exits for a systemd restart.
///
/// A no-answer (probe deadline, momentary runtime-mutex contention) proves
/// nothing, so acting on the first one restarted healthy daemons. Tolerating it
/// forever would be the opposite defect: a permanently wedged probe would keep a
/// possibly non-enforcing daemon alive reporting itself active.
///
/// Derivation, stated exactly because the obvious `3 * interval` reading of it is
/// wrong: three CONSECUTIVE readings span TWO intervals (readings at t, t+2s,
/// t+4s), and the fault can begin just after a tick, so worst-case detection is
/// `(MAX_CONSECUTIVE_UNAVAILABLE_HEALTH_READINGS - 1 + 1) *
/// SUPERVISOR_HEALTH_INTERVAL` = 6 seconds from onset, 4 seconds from the first
/// indeterminate reading.
///
/// This bound is SEPARATE from [`crate::runtime_health::STATUS_FRESHNESS_WINDOW`]
/// and must not be justified by it: the supervisor republishes on every tick
/// whatever it observed, so a reader's observation is ~2s old while supervision
/// runs at all. The freshness window catches a supervisor that stopped
/// publishing, not a slow loss decision.
///
/// This counter is NOT the only route to a fail-closed exit, and not the fastest
/// one. `kernel_runtime_health` reaches it on runtime-mutex contention
/// (`TryLockError::WouldBlock`), which never consults the nft probe. A wedged
/// `nft` instead exhausts the probe's own
/// `NFT_HEALTH_MAX_CONSECUTIVE_UNAVAILABLE` budget, which returns a PROVEN
/// `Lost` and is acted on immediately by the no-grace arm below. Both routes end
/// in `record_runtime_loss`; keep them both.
const MAX_CONSECUTIVE_UNAVAILABLE_HEALTH_READINGS: u32 = 3;

/// Errors emitted by the daemon lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("F-1 startup failure: {0}")]
    StartupConfig(String),
    /// The boot manifest load did not leave an armed identity behind. A
    /// composition-root bug, refused as a startup failure because a daemon with
    /// no armed identity cannot refuse an identity change it never recorded.
    #[error(
        "F-1 startup failure: the boot manifest load left no armed identity, so a policy \
         change could not be proven to preserve the kernel binding"
    )]
    ArmedIdentityNotFrozen,
    #[error("F-4 startup failure: pinned public key load failed: {0}")]
    PinnedKeyLoad(String),
    #[error("F-3 startup failure: IPC bind failed: {0}")]
    IpcBind(#[from] IpcServerError),
    #[error("F-8 startup failure: required platform primitive missing: {0}")]
    PlatformMissing(String),
    #[error("signal handler installation failed: {0}")]
    SignalSetup(String),
    #[error("auth subsystem error: {0}")]
    Auth(#[from] AuthError),
    #[error("WAL open failed: {0}")]
    WalOpen(String),
    #[error(
        "startup configuration missing explicit authenticated service UID (--trusted-service-uid)"
    )]
    TrustedServiceUidMissing,
    #[error("manifest store init failed: {0}")]
    ManifestStoreInit(String),
    #[error("F-4 startup failure: audit-producer key load/generate failed: {0}")]
    ProducerKeyLoad(String),
    /// F-8 startup failure: the kernel enforcement runtime could not be activated
    /// on a SUPPORTED platform (Linux). `EnforcementRuntime::start` already
    /// unwound every acquired userspace component in reverse order before this
    /// error was produced. The owned nftables table and authenticated journal
    /// are intentionally preserved if table acquisition completed before a
    /// later component failed; the next boot adopts that exact identity. `boot`
    /// returns this BEFORE the readiness beacon, so no `READY=1` is ever sent.
    /// Distinct from the non-fatal "no kernel adapter on this platform" case
    /// (macOS dev / non-Linux CI), which returns NO error and leaves the daemon
    /// control-plane-only. Servers-first fail-before: a host that should enforce
    /// must refuse to start rather than run live-but-non-enforcing.
    #[error("F-8 startup failure: kernel enforcement runtime activation failed: {0}")]
    KernelRuntimeActivation(String),
    /// F-8 startup failure: the daemon reached a ready kernel runtime but could
    /// not deliver `READY=1` to a CONFIGURED `NOTIFY_SOCKET`. Rather than leave a
    /// long-running process that systemd will hold in "activating" and eventually
    /// kill on `TimeoutStartSec`, `boot` unwinds enforcement-before-IPC and fails
    /// closed so the restart is prompt and ordered.
    #[error("F-8 startup failure: systemd readiness notification failed: {0}")]
    ReadinessNotify(String),
    /// The explicit `--disarm` recovery action could not complete. This is
    /// SEPARATE from ordinary shutdown: disarm is the only path that deletes an
    /// owned enforcement object, and it refuses (retaining the journal) on any
    /// ambiguity — a still-running daemon holding the host lock, a foreign or
    /// drifted table, a corrupt/unauthenticated proof, or a failed delete /
    /// absence check. Never produced by SIGTERM/systemd stop.
    #[error("disarm failed: {0}")]
    Disarm(String),
}

/// Explicitly DISARM the host castle runtime (the `--disarm` CLI action): delete
/// this daemon's owned `sanctuary-castle` table and clear its authenticated
/// ownership journal, under the host ownership lock. This is the ONLY path that
/// deletes an acquired enforcement object; ordinary shutdown NEVER does. It fails
/// closed (retaining the journal) on any ambiguity. See
/// [`crate::runtime_providers::disarm_castle_runtime`] for the full safety
/// contract and the honestly-documented TOCTOU boundary nftables permits.
pub fn disarm() -> Result<crate::runtime_providers::DisarmOutcome, DaemonError> {
    disarm_with(&crate::config::LinuxRuntimePaths::production())
}

/// [`disarm`] against an explicit path set. `main.rs`'s `--disarm` always passes
/// [`LinuxRuntimePaths::production`]; the parameter exists so the privileged test
/// suite can disarm the isolated runtime it created rather than the host's.
///
/// [`LinuxRuntimePaths::production`]: crate::config::LinuxRuntimePaths::production
pub fn disarm_with(
    paths: &crate::config::LinuxRuntimePaths,
) -> Result<crate::runtime_providers::DisarmOutcome, DaemonError> {
    let linux_runtime_config = crate::runtime_providers::LinuxRuntimeConfig {
        lock_path: paths.host_lock_path.clone(),
        journal_path: paths.ownership_journal_path.clone(),
        journal_key_path: paths.journal_auth_key_path.clone(),
        policy_dir: PathBuf::from("/var/lib/sanctuary"),
        poll_interval: KERNEL_RUNTIME_POLL_INTERVAL,
        nfqueue: crate::nfqueue::NfqueueConfig::default(),
        // `--disarm` is an explicit operator recovery action, never a boot
        // acquisition; it never reaches the A162 install sites this flag gates,
        // so a fresh unset flag (never "requested") is the honest value here.
        shutdown_requested: Arc::new(AtomicBool::new(false)),
    };
    crate::runtime_providers::disarm_castle_runtime(&linux_runtime_config)
        .map_err(|err| DaemonError::Disarm(err.to_string()))
}

/// Map a daemon error to a FailureMode for disposition routing.
pub fn mode_for_error(err: &DaemonError) -> FailureMode {
    match err {
        DaemonError::StartupConfig(_) => FailureMode::StartupPolicyParseFailed,
        DaemonError::PinnedKeyLoad(_) => FailureMode::StartupPolicyParseFailed,
        DaemonError::IpcBind(_) => FailureMode::StartupIpcBindFailed,
        DaemonError::PlatformMissing(_) => FailureMode::StartupFilterInstallFailed,
        DaemonError::SignalSetup(_) => FailureMode::StartupFilterInstallFailed,
        DaemonError::Auth(_) => FailureMode::StartupIpcBindFailed,
        DaemonError::WalOpen(_) => FailureMode::StartupFilterInstallFailed,
        DaemonError::TrustedServiceUidMissing => FailureMode::StartupPolicyParseFailed,
        DaemonError::ManifestStoreInit(_) => FailureMode::StartupPolicyParseFailed,
        DaemonError::ProducerKeyLoad(_) => FailureMode::StartupPolicyParseFailed,
        // A supported-platform runtime-activation failure and a failed readiness
        // delivery are both refuse-to-start (F-1) conditions: enforcement is not
        // live, so the daemon must not run.
        DaemonError::KernelRuntimeActivation(_) => FailureMode::StartupFilterInstallFailed,
        DaemonError::ReadinessNotify(_) => FailureMode::StartupFilterInstallFailed,
        // Disarm is an explicit operator recovery action, not a boot path; it is
        // routed through the filter-install failure mode for a consistent
        // fail-closed operator message when it refuses.
        DaemonError::ArmedIdentityNotFrozen => FailureMode::StartupPolicyParseFailed,
        DaemonError::Disarm(_) => FailureMode::StartupFilterInstallFailed,
    }
}

/// Render a refuse-to-start failure disposition into an operator-facing
/// message. Used by `main.rs` when the daemon refuses to come up. Mirrors the
/// scope-lock §7 F-1 / F-4 / F-8 message keys.
pub fn refuse_to_start_message(disposition: &FailureDisposition, detail: &str) -> String {
    let key = match disposition {
        FailureDisposition::RefuseToStart {
            operator_message_key,
        } => *operator_message_key,
        _ => "refuse_to_start_unknown",
    };
    let body = match key {
        "F-1" => {
            "The Castle Wall (egress enforcement) requires nftables and systemd. \
             Sanctuary refuses to start with broken enforcement. \
             Once the requirement is met, run `sanctuary start` to retry. \
             For more, see https://sanctuaryprotocol.ai/docs/castle-wall."
        }
        "F-4" => {
            "The Castle Wall allowlist failed signature verification or its pinned \
             public key could not be loaded. Sanctuary refuses to start with an \
             untrusted policy. Try `sanctuary castle reinstall-allowlist`."
        }
        "F-3-startup" => {
            "The Castle Wall could not bind its IPC socket. Another daemon may \
             already be running, or the socket directory permissions need fixing. \
             Sanctuary refuses to start without a clean control surface."
        }
        _ => "Sanctuary refuses to start. See systemctl status sanctuary-castle-wall.",
    };
    format!(
        "Sanctuary cannot start ({}).\n\n{}\n\nDetail: {}",
        key, body, detail
    )
}

/// Live daemon handle. Holding this guarantees the IPC server is bound and
/// the signal handlers are installed; dropping it triggers an orderly stop.
pub struct DaemonHandle {
    config: DaemonConfig,
    ipc_server: Option<IpcServer>,
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    /// Cloneable policy and audit surface used by kernel verdict callbacks.
    decision_engine: Arc<DecisionEngine>,
    /// Lifecycle state (ControlPlaneOnly / Stopping / Degraded). `Enforcing` is
    /// NEVER stored here; it is derived from `enforcement` so IPC/process
    /// liveness cannot be presented as kernel enforcement.
    runtime_state: Arc<Mutex<DaemonRuntimeState>>,
    /// Exact lifecycle truth projected over authenticated status IPC.
    live_status: Arc<LiveStatus>,
    /// Kernel-runtime health as last OBSERVED by the supervision loop. The
    /// supervisor is the sole writer; the IPC status handler is a reader. This is
    /// what lets a status query answer without locking the runtime or forking an
    /// `nft` proof, and what lets momentary contention read as indeterminate
    /// instead of as a loss. See [`crate::runtime_health`].
    runtime_health: Arc<RuntimeHealthView>,
    wal_control_progress: Arc<AtomicUsize>,
    /// Owned kernel-runtime handle, when the daemon activated one at boot. On a
    /// privileged Linux host `boot()` attaches a live runtime (table + bound
    /// NFQUEUE + watcher) and the daemon derives `KernelRuntimeReady`; on a host
    /// with no kernel adapter, an unprovisioned runtime dir, or where another
    /// daemon owns the host runtime, activation fails-before and this stays
    /// `None` (the daemon reports `ControlPlaneOnly`). Either way the daemon is
    /// never `Enforcing` in this slice: no agent is wrapped (ASSURANCE_MATRIX
    /// row 17). Owning the runtime here is what makes teardown release it BEFORE
    /// the IPC control surface (see [`teardown`](Self::teardown)).
    enforcement: Option<Arc<Mutex<EnforcementRuntime>>>,
    /// Daemon shutdown-REQUEST flag. Signal handlers and [`request_stop`] set
    /// ONLY this; it is what [`wait_for_shutdown`] / [`is_shutdown_requested`]
    /// observe and what drives the daemon's DECISION to begin teardown. It is
    /// deliberately NOT the IPC accept-loop stop flag: a shutdown request must
    /// never tear the IPC control surface down before enforcement is released
    /// (see [`teardown`]), so the accept loop is stopped by a distinct flag that
    /// only [`IpcServer::stop_and_join`] sets, and only AFTER
    /// `enforcement.shutdown()`.
    ///
    /// [`request_stop`]: Self::request_stop
    /// [`wait_for_shutdown`]: Self::wait_for_shutdown
    /// [`is_shutdown_requested`]: Self::is_shutdown_requested
    /// [`teardown`]: Self::teardown
    shutdown_flag: Arc<AtomicBool>,
    /// Fatal control-path withdrawal (for example a publication that committed
    /// but whose success receipt could not be durably recorded). Kept separate
    /// from ordinary shutdown so `Restart=on-failure` cannot be bypassed by a
    /// race between the two signals.
    fatal_control_path: Arc<AtomicBool>,
    /// Early mutation fence, set before enforcement release. Policy/WAL
    /// mutation observes this independently of the late IPC accept-loop stop.
    mutation_cancel_flag: Arc<AtomicBool>,
    /// IPC-owned accept-loop stop flag, retained here only so tests can prove
    /// the IPC server is still live (this flag observed `false`) at the instant
    /// enforcement is released. It is set EXCLUSIVELY by
    /// [`IpcServer::stop_and_join`] during `teardown`, AFTER enforcement
    /// shutdown — never by a signal or `request_stop`. Test-gated because
    /// production never reads it through the handle: the server owns its own
    /// clone.
    #[cfg(test)]
    ipc_stop_flag: Arc<AtomicBool>,
    /// TEST-ISOLATION ONLY (W1b, register id LINUX-STOP-LOSS-RACE-01). One-shot
    /// latch armed by `arm_test_shutdown_at_pre_recovery`; consumed on the
    /// first read of the live shutdown closure that
    /// `kernel_runtime_health_with_recovery` passes to
    /// `attempt_post_ready_recovery`. That closure is read only inside
    /// `recover_post_ready_loss`, which is reached only after the component's
    /// own probe returned Lost or Recovering, so a healthy poll never consumes
    /// the latch. On that read it flips `shutdown_flag`, so a wired
    /// integration test can prove the site-5 precedence fix (a first-entry
    /// proven loss still gets its one net-install attempt when a stop lands
    /// between the probe and the decision) without depending on OS
    /// signal-delivery timing.
    /// Compiled out of release builds: must match the CLI seam name
    /// `--test-shutdown-at=pre-recovery` in `main.rs`.
    #[cfg(feature = "test-isolation")]
    test_shutdown_at_pre_recovery: Arc<AtomicBool>,
    started_at: Instant,
}

/// Decide WAL rows from the prior published observation and this call's result.
/// A tag transition is recorded once; each actual install gets its own row even
/// when successive attempts have the same tag.
fn recovery_row_actions(
    previous: RuntimeHealthState,
    previous_tag: Option<&crate::nftables::SafetyNetAuditState>,
    current_tag: Option<&crate::nftables::SafetyNetAuditState>,
    result: crate::enforcement::PostReadyRecoveryResult,
) -> (bool, bool, bool) {
    let initial = !matches!(previous, RuntimeHealthState::Recovering(_));
    let attempted = matches!(
        result,
        crate::enforcement::PostReadyRecoveryResult::InstallSucceeded
            | crate::enforcement::PostReadyRecoveryResult::InstallFailed
    );
    // The supervisor supplies a blocking, poison-aware prior-tag snapshot;
    // None here is a real absence, never a contended status read.
    let transition = !initial && !attempted && previous_tag != current_tag;
    (initial, transition, attempted)
}

impl DaemonHandle {
    /// Current runtime truth. The boot path reports `ControlPlaneOnly` until it
    /// owns live nftables and NFQUEUE resources, then `KernelRuntimeReady`.
    ///
    /// `KernelRuntimeReady` is DERIVED, never stored: it is returned only when an
    /// owned [`EnforcementRuntime`] reports every required component ready. A
    /// poisoned lifecycle lock reads as `Degraded` (never promoted), and a
    /// runtime that has lost a component reads as `ControlPlaneOnly` — so
    /// process/IPC liveness alone can never present as a ready kernel runtime.
    pub fn runtime_state(&self) -> DaemonRuntimeState {
        let lifecycle = self
            .runtime_state
            .lock()
            .map(|state| *state)
            .unwrap_or(DaemonRuntimeState::Degraded);
        if matches!(
            lifecycle,
            DaemonRuntimeState::Stopping | DaemonRuntimeState::Degraded
        ) {
            return lifecycle;
        }
        match self
            .enforcement
            .as_ref()
            .and_then(|runtime| runtime.try_lock().ok())
        {
            Some(runtime) if runtime.is_kernel_runtime_ready() => {
                DaemonRuntimeState::KernelRuntimeReady
            }
            _ => DaemonRuntimeState::ControlPlaneOnly,
        }
    }

    /// True only in the explicit `Enforcing` state, which this slice NEVER
    /// derives: kernel-runtime readiness is not enforcement (module docs of
    /// [`crate::enforcement`]). Wrapping a real agent and gating its cgroup — the
    /// thing that flips this to true — is out of scope here, so `is_enforcing()`
    /// stays false even when the kernel runtime is fully `KernelRuntimeReady`.
    /// Keeping the predicate honest is what prevents a live-but-idle runtime, or
    /// a live socket, from being reported as an enforced agent.
    pub fn is_enforcing(&self) -> bool {
        self.runtime_state() == DaemonRuntimeState::Enforcing
    }

    /// Test/integration helper: hand back the manifest store handle so the
    /// caller can simulate operator-driven flows that the IPC layer carries
    /// in production.
    pub fn manifest_store(&self) -> Option<&Arc<Mutex<ManifestStore>>> {
        self.decision_engine.manifest_store()
    }

    /// Test/integration helper: hand back the WAL writer handle so the
    /// caller can append synthetic audit events without going through the
    /// kernel-touching emitter path.
    pub fn wal_writer(&self) -> Option<&Arc<Mutex<WalWriter>>> {
        self.decision_engine.wal_writer()
    }

    /// Share the policy decision surface without sharing daemon lifecycle
    /// ownership. The Linux verdict loop holds this while `DaemonHandle`
    /// retains responsibility for stopping threads and kernel resources.
    pub fn decision_engine(&self) -> Arc<DecisionEngine> {
        Arc::clone(&self.decision_engine)
    }

    /// Evaluate one outbound attempt against the verified ManifestStore
    /// snapshot, emit a canonical-JSON audit event into the WAL, and
    /// return the verdict + the assigned WAL seq.
    ///
    /// This is the in-process surface the kernel-binding modules
    /// (`nftables.rs` / `nfqueue.rs`) drive. It
    /// realizes the F-1 deny-by-default invariant and the per-attempt
    /// audit emission path called out in the Checkpoint 3 dispatch.
    ///
    /// Returned verdict is whatever [`PolicySnapshot::evaluate`] decides;
    /// when the daemon is configured in a transient mode without the
    /// manifest store or WAL wired, [`AttemptError::ManifestStoreUnwired`]
    /// or [`AttemptError::WalUnwired`] surfaces.
    pub fn evaluate_attempt(
        &self,
        request: &EvaluationRequest,
    ) -> Result<EvaluationOutcome, AttemptError> {
        self.decision_engine.evaluate_attempt(request)
    }
}

impl DaemonHandle {
    /// Returns true when the daemon has been asked to shut down by either
    /// a SIGTERM, SIGINT, or programmatic stop().
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }

    pub fn is_fatal_control_path_requested(&self) -> bool {
        self.fatal_control_path.load(Ordering::SeqCst)
    }

    /// Block until shutdown is requested, sweeping audit-buffer expirations
    /// every `tick`. Does NOT supervise kernel-runtime health; the production
    /// entry point uses [`supervise_until_shutdown`](Self::supervise_until_shutdown)
    /// so a component that dies after boot forces a restart. Retained for the
    /// control-plane-only / smoke paths that hold no kernel runtime.
    pub fn wait_for_shutdown(&self, tick: Duration) {
        while !self.is_shutdown_requested() {
            std::thread::sleep(tick);
            if let Ok(mut buf) = self.audit_buffer.lock() {
                buf.evict_expired(std::time::SystemTime::now());
            }
        }
    }

    /// Kernel-runtime health for the supervision loop, as a THREE-valued state.
    ///
    /// * [`RuntimeHealthState::NoRuntime`] — the daemon holds no kernel runtime
    ///   (control-plane only, macOS/unprivileged). There is nothing to lose, so a
    ///   control-plane boot is never a false failure.
    /// * [`RuntimeHealthState::Ready`] — an owned runtime is still fully ready.
    /// * [`RuntimeHealthState::Lost`] — a runtime that came up ready has PROVEN
    ///   loss of a required component (verdict thread died, table clobbered,
    ///   watcher thread exited). `EnforcementRuntime::start` only ever yields a
    ///   ready runtime, so `enforcement.is_some()` means it came up ready.
    /// * [`RuntimeHealthState::ProbeUnavailable`] — INDETERMINATE: the runtime
    ///   mutex was momentarily held (the supervisor's own bounded `nft` proof runs
    ///   under it) or the component probe returned no answer. This is deliberately
    ///   NOT a loss: collapsing contention into loss restarted healthy daemons.
    ///   The supervision loop retries it under a bounded budget instead.
    ///
    /// Re-polls live component health each call (never cached at this layer; the
    /// component's own probe owns rate limiting).
    ///
    /// [`RuntimeHealthState::NoRuntime`]: crate::runtime_health::RuntimeHealthState::NoRuntime
    /// [`RuntimeHealthState::Ready`]: crate::runtime_health::RuntimeHealthState::Ready
    /// [`RuntimeHealthState::Lost`]: crate::runtime_health::RuntimeHealthState::Lost
    /// [`RuntimeHealthState::ProbeUnavailable`]: crate::runtime_health::RuntimeHealthState::ProbeUnavailable
    /// The tagged `safety_net` state for the SIGNED status report.
    ///
    /// Exposed on the handle because the signed report is built from it, and the report
    /// must describe the predicate actually installed together with its coverage limit.
    /// A report emitted while an install has failed carries `InstallFailed`, so it never
    /// attests to a protection that is not in place.
    /// Must match the `safety_net` object on the `kernel_runtime_lost` WAL row.
    pub fn safety_net_audit_state(&self) -> Option<crate::nftables::SafetyNetAuditState> {
        match &self.enforcement {
            None => Some(crate::nftables::SafetyNetAuditState::NotAttempted),
            Some(runtime) => runtime
                .try_lock()
                .ok()
                .map(|runtime| runtime.safety_net_audit_state()),
        }
    }

    pub fn kernel_runtime_health(&self) -> RuntimeHealthState {
        self.kernel_runtime_health_with_recovery(false).0
    }

    /// `force_fresh` (R3, LINUX-STOP-LOSS-RACE-01, Claude F3): when true,
    /// bypasses the nft component's `NFT_HEALTH_MIN_INTERVAL` cache so the
    /// returned observation is a live proof, not a reading that may be up to
    /// `NFT_HEALTH_MIN_INTERVAL` old. Only `stop_final_health_outcome` passes
    /// true: `S_STOP_FINAL_HEALTH` runs exactly one pass and its exit-0 arm
    /// must never be reached on a cached `Ready` that predates a loss which
    /// happened inside the cache window.
    fn kernel_runtime_health_with_recovery(
        &self,
        force_fresh: bool,
    ) -> (
        RuntimeHealthState,
        crate::enforcement::PostReadyRecoveryResult,
    ) {
        use crate::enforcement::PostReadyRecoveryResult;
        match &self.enforcement {
            None => (
                RuntimeHealthState::NoRuntime,
                PostReadyRecoveryResult::NoInstall,
            ),
            Some(runtime) => {
                // The audit WAL is part of the enforcement transaction: a
                // runtime that can decide but cannot durably evidence the next
                // decision is not healthy. An ambiguous write/fsync/rename
                // failure latches poison in WalWriter and is a proven loss.
                match self.decision_engine.wal_writer() {
                    None => {
                        return (
                            RuntimeHealthState::Lost(
                                crate::enforcement::NotReadyReason::AuditWalPoisoned,
                            ),
                            PostReadyRecoveryResult::NoInstall,
                        );
                    }
                    Some(wal) => match wal.try_lock() {
                        Ok(wal) if wal.is_poisoned() => {
                            return (
                                RuntimeHealthState::Lost(
                                    crate::enforcement::NotReadyReason::AuditWalPoisoned,
                                ),
                                PostReadyRecoveryResult::NoInstall,
                            );
                        }
                        Ok(_) => {}
                        Err(std::sync::TryLockError::WouldBlock)
                            if self.wal_control_progress.load(Ordering::SeqCst) > 0 => {}
                        Err(std::sync::TryLockError::WouldBlock) => {
                            return (
                                RuntimeHealthState::ProbeUnavailable,
                                PostReadyRecoveryResult::NoInstall,
                            );
                        }
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            return (
                                RuntimeHealthState::Lost(
                                    crate::enforcement::NotReadyReason::AuditWalPoisoned,
                                ),
                                PostReadyRecoveryResult::NoInstall,
                            );
                        }
                    },
                }
                match runtime.try_lock() {
                    // Contention, not failure. The supervisor is the only other
                    // holder and it holds the lock only across a bounded proof.
                    Err(std::sync::TryLockError::WouldBlock) => (
                        RuntimeHealthState::ProbeUnavailable,
                        PostReadyRecoveryResult::NoInstall,
                    ),
                    // A poisoned runtime mutex means a component panicked while
                    // holding it: that IS a proven loss, and must fail closed.
                    Err(std::sync::TryLockError::Poisoned(_)) => (
                        RuntimeHealthState::Lost(crate::enforcement::NotReadyReason::ShuttingDown),
                        PostReadyRecoveryResult::NoInstall,
                    ),
                    Ok(runtime) => {
                        // BEFORE any exit arm: give a component that proved its resource
                        // lost one safety-net attempt while this process still holds the
                        // host lock. The status re-read below then observes whatever the
                        // attempt produced, so a successful install shows up as
                        // `Recovering` (not readiness) and the exit arm is not reached
                        // with an attempt outstanding.
                        //
                        // R2 (LINUX-STOP-LOSS-RACE-01, Grok 2 / Claude F2): the shutdown
                        // state is read LIVE, from inside this closure, by
                        // `recover_post_ready_loss` itself -- at the moment it actually
                        // decides -- rather than copied into a `bool` here before the
                        // component's own health probe (the call that decided Lost/
                        // Recovering and is what gates whether the runtime even reaches
                        // this closure) has run. A stop landing inside that probe is a
                        // stop `is_shutdown_requested()` now observes.
                        //
                        // TEST-ISOLATION ONLY (W1b, LINUX-STOP-LOSS-RACE-01): must match
                        // `arm_test_shutdown_at_pre_recovery`'s doc comment. The seam lives
                        // INSIDE this closure, not before the call, so it can only ever
                        // fire on an invocation `recover_post_ready_loss` actually reaches
                        // -- which happens only after this component's own health probe
                        // already returned a proven Lost or Recovering (the guard in
                        // `EnforcementRuntime::attempt_post_ready_recovery`, below). A
                        // health call whose probe saw a healthy table never calls this
                        // closure at all, so it cannot consume the one-shot latch. One-shot
                        // (swap-and-clear so a later retry poll is not re-armed).
                        let recovery = runtime.attempt_post_ready_recovery(
                            &|| {
                                #[cfg(feature = "test-isolation")]
                                if self
                                    .test_shutdown_at_pre_recovery
                                    .swap(false, Ordering::SeqCst)
                                {
                                    self.request_stop();
                                }
                                self.is_shutdown_requested()
                            },
                            force_fresh,
                        );
                        let observed = match if force_fresh {
                            runtime.status_fresh()
                        } else {
                            runtime.status()
                        } {
                            crate::enforcement::EnforcementStatus::KernelRuntimeReady => {
                                RuntimeHealthState::Ready
                            }
                            crate::enforcement::EnforcementStatus::NotReady {
                                reason: crate::enforcement::NotReadyReason::HealthProbeUnavailable,
                            } => RuntimeHealthState::ProbeUnavailable,
                            crate::enforcement::EnforcementStatus::NotReady {
                                reason: crate::enforcement::NotReadyReason::HealthProbeIndeterminate,
                            } => RuntimeHealthState::Indeterminate,
                            // The net is being installed or retried for a proven loss.
                            // Published as its own state so the supervisor's exit arm is not
                            // reached while the attempt is outstanding. Must match
                            // `ComponentHealth::Recovering`.
                            crate::enforcement::EnforcementStatus::NotReady {
                                reason:
                                    reason @ crate::enforcement::NotReadyReason::SafetyNetRecovering(_),
                            } => RuntimeHealthState::Recovering(reason),
                            crate::enforcement::EnforcementStatus::NotReady { reason } => {
                                RuntimeHealthState::Lost(reason)
                            }
                        };
                        (observed, recovery)
                    }
                }
            }
        }
    }

    /// The shared health view authenticated status IPC reads. Exposed so a
    /// composition test can prove the SAME view the supervisor publishes into is
    /// the one the IPC server was wired with (AGENTS rule 4: a capability with no
    /// production consumer is not shipped).
    pub fn runtime_health_view(&self) -> &Arc<crate::runtime_health::RuntimeHealthView> {
        &self.runtime_health
    }

    /// Run until shutdown is requested OR the kernel runtime is lost, whichever
    /// comes first. (blocker 4) Sweeps audit-buffer expirations every `tick`
    /// (shutdown responsiveness) and re-checks kernel-runtime health every
    /// `health_interval`. A `health_interval` of zero checks health on every
    /// tick (used by deterministic tests).
    ///
    /// Returns [`SupervisionOutcome::ShutdownRequested`] on a normal
    /// signal/`request_stop`, [`SupervisionOutcome::FatalControlPath`] when an
    /// already-committed control mutation loses its required durable evidence,
    /// or [`SupervisionOutcome::KernelRuntimeLost`] the first time a runtime
    /// that came up ready loses a required component. The
    /// caller (`main`) turns the latter into a LOUD failure, an ordered
    /// enforcement-before-IPC teardown via [`stop`](Self::stop), and a NONZERO
    /// process exit so systemd (`Restart=on-failure`) restarts the daemon rather
    /// than leaving a live-but-not-enforcing service reporting itself active.
    /// Before returning the loss outcome it attempts a critical, fsync-backed
    /// `kernel_runtime_lost` WAL record carrying the exact `NotReadyReason`.
    pub fn supervise_until_shutdown(
        &self,
        tick: Duration,
        health_interval: Duration,
    ) -> SupervisionOutcome {
        let mut last_health = Instant::now();
        // Consecutive INDETERMINATE health readings. A no-answer proves nothing,
        // so it must not restart a healthy daemon; but it must not be tolerated
        // forever either, or a permanently wedged probe would hold a possibly
        // non-enforcing daemon alive. The budget is the fail-closed bound: after
        // MAX_CONSECUTIVE_UNAVAILABLE_HEALTH_READINGS ticks with no answer the
        // daemon treats it as loss and exits for systemd to restart.
        let mut consecutive_unavailable: u32 = 0;
        // Publish the boot-time truth before the first tick so a status query
        // arriving in the first health interval reads a real observation rather
        // than "nothing published yet".
        let (initial_health, initial_recovery) = self.kernel_runtime_health_with_recovery(false);
        match recovery_call_decision(
            self.is_fatal_control_path_requested(),
            self.is_shutdown_requested(),
            initial_health,
            initial_recovery,
        ) {
            RecoveryCallDecision::FatalControlPath => return SupervisionOutcome::FatalControlPath,
            RecoveryCallDecision::ShutdownRequested => {
                return SupervisionOutcome::ShutdownRequested
            }
            RecoveryCallDecision::RepairRequired {
                reason,
                install_result,
            } => {
                self.record_recovery_attempt(reason, install_result);
                return SupervisionOutcome::RepairRequired {
                    reason,
                    install_result,
                };
            }
            RecoveryCallDecision::Inconsistent => {
                // SAFETY: stderr is the last-resort operator channel when a returned
                // install result conflicts with its health observation before READY.
                eprintln!("castle-wall-daemon: recovery install result returned without a Recovering observation; refusing READY");
                return SupervisionOutcome::FatalControlPath;
            }
            RecoveryCallDecision::Continue => {}
        }
        self.runtime_health.publish(initial_health);
        if initial_health == RuntimeHealthState::Ready {
            self.runtime_health.clear_safety_net();
        } else if let Some(safety_net) = self.safety_net_audit_state() {
            self.runtime_health.publish_safety_net(safety_net);
        } else {
            self.runtime_health.clear_safety_net();
        }
        if let RuntimeHealthState::Recovering(reason) = initial_health {
            self.record_runtime_loss(reason, true);
        }
        loop {
            // Fatal wins over normal shutdown even when the IPC handler sets
            // both atomics before this thread is scheduled.
            if self.is_fatal_control_path_requested() {
                return SupervisionOutcome::FatalControlPath;
            }
            if self.is_shutdown_requested() {
                // C2a1(a) site 2 (LINUX-STOP-LOSS-RACE-01): a bare shutdown check must
                // not exit 0 ahead of a final health pass, or a proven loss racing this
                // stop leaves the confined identity with no table and no net.
                return self.stop_final_health_outcome();
            }
            std::thread::sleep(tick);
            if self.is_fatal_control_path_requested() {
                return SupervisionOutcome::FatalControlPath;
            }
            if self.is_shutdown_requested() {
                // C2a1(a) site 3: same final-health requirement as site 2, shared via
                // the same helper so the logic cannot drift between the two call sites.
                return self.stop_final_health_outcome();
            }
            if let Ok(mut buf) = self.audit_buffer.lock() {
                buf.evict_expired(std::time::SystemTime::now());
            }
            if last_health.elapsed() >= health_interval {
                last_health = Instant::now();
                let (previous_health, previous_tag) = match self
                    .runtime_health
                    .supervisor_snapshot()
                {
                    Ok(snapshot) => snapshot,
                    Err(()) => {
                        // SAFETY: stderr is the operator channel for this fatal
                        // supervisor refusal; systemd journals it even when the
                        // published history cannot support an honest audit row.
                        eprintln!("castle-wall-daemon: unavailable or poisoned published runtime history; stopping supervision");
                        return SupervisionOutcome::FatalControlPath;
                    }
                };
                let (observed, recovery_result) = self.kernel_runtime_health_with_recovery(false);
                // A returned attempt is terminal before any observation publication or
                // retry; fresh control flags take precedence over that result.
                match recovery_call_decision(
                    self.is_fatal_control_path_requested(),
                    self.is_shutdown_requested(),
                    observed,
                    recovery_result,
                ) {
                    RecoveryCallDecision::FatalControlPath => {
                        return SupervisionOutcome::FatalControlPath
                    }
                    RecoveryCallDecision::ShutdownRequested => {
                        return SupervisionOutcome::ShutdownRequested
                    }
                    RecoveryCallDecision::RepairRequired {
                        reason,
                        install_result,
                    } => {
                        self.record_recovery_attempt(reason, install_result);
                        return SupervisionOutcome::RepairRequired {
                            reason,
                            install_result,
                        };
                    }
                    RecoveryCallDecision::Inconsistent => {
                        // SAFETY: systemd captures the protocol conflict even without a WAL row.
                        eprintln!("castle-wall-daemon: recovery install result returned without a Recovering observation; refusing READY");
                        return SupervisionOutcome::FatalControlPath;
                    }
                    RecoveryCallDecision::Continue => {}
                }
                let current_tag = self.safety_net_audit_state();
                if observed == RuntimeHealthState::Ready {
                    self.runtime_health.clear_safety_net();
                } else if let Some(safety_net) = current_tag.clone() {
                    self.runtime_health.publish_safety_net(safety_net);
                } else {
                    self.runtime_health.clear_safety_net();
                }
                // The supervisor is the SOLE writer of this view; status IPC only
                // reads it. That is what removes the per-status-request `nft` fork
                // and stops runtime-mutex contention from being read as loss.
                self.runtime_health.publish(observed);
                match observed {
                    RuntimeHealthState::NoRuntime | RuntimeHealthState::Ready => {
                        consecutive_unavailable = 0;
                        self.reconcile_recovered_live_status(previous_health, observed);
                    }
                    RuntimeHealthState::ProbeUnavailable => {
                        consecutive_unavailable = consecutive_unavailable.saturating_add(1);
                        if consecutive_unavailable >= MAX_CONSECUTIVE_UNAVAILABLE_HEALTH_READINGS {
                            let reason = crate::enforcement::NotReadyReason::HealthProbeUnavailable;
                            self.record_runtime_loss(reason, false);
                            return SupervisionOutcome::KernelRuntimeLost(reason);
                        }
                    }
                    RuntimeHealthState::Indeterminate => {
                        // No kernel mutation follows from an absent answer. The
                        // hook is nevertheless an ordered step before exit.
                        if let Some(runtime) = &self.enforcement {
                            if let Ok(runtime) = runtime.lock() {
                                runtime.hook_post_ready_indeterminate();
                            } else {
                                // SAFETY: stderr is the operator channel for the
                                // terminal dispatch record. These two branches are
                                // the cases where NO provider hook runs at all, and
                                // the distinction between a poisoned lock and an
                                // absent runtime is what tells an operator whether
                                // enforcement state is unknown or simply gone.
                                eprintln!(
                                    "castle-wall-daemon: terminal_dispatch=runtime_lock_poisoned"
                                );
                            }
                        } else {
                            // SAFETY: same operator channel and the same terminal
                            // record; no runtime exists to dispatch through.
                            eprintln!("castle-wall-daemon: terminal_dispatch=runtime_absent");
                        }
                        let reason = crate::enforcement::NotReadyReason::HealthProbeIndeterminate;
                        self.record_runtime_loss(reason, false);
                        return SupervisionOutcome::KernelRuntimeLost(reason);
                    }
                    // No attempt returned on this call. Preserve recovery observations
                    // and tag transitions without manufacturing another attempt row.
                    RuntimeHealthState::Recovering(reason) => {
                        let (initial_row, tag_transition_row, _) = recovery_row_actions(
                            previous_health,
                            previous_tag.as_ref(),
                            current_tag.as_ref(),
                            recovery_result,
                        );
                        if initial_row || tag_transition_row {
                            self.record_runtime_loss(reason, true);
                        }
                        consecutive_unavailable = 0;
                    }
                    RuntimeHealthState::Lost(reason) => {
                        // A PROVEN loss with no recovery attempt outstanding is acted on
                        // immediately: no grace, no budget. Only the indeterminate arm
                        // above and the recovering arm are retried.
                        self.record_runtime_loss(reason, false);
                        return SupervisionOutcome::KernelRuntimeLost(reason);
                    }
                }
            }
        }
    }

    /// `S_STOP_FINAL_HEALTH` (C2a1(a), register id LINUX-STOP-LOSS-RACE-01):
    /// the state a shutdown-requested supervision loop enters instead of
    /// exiting immediately. Runs exactly one `kernel_runtime_health_with_recovery`
    /// pass (the shutdown flag is already set, so the runtime's own recovery
    /// attempt runs with a closure reading `shutting_down=true`, giving a
    /// proven loss its one net-install ATTEMPT per `recover_post_ready_loss` --
    /// Grok 4 (LINUX-STOP-LOSS-RACE-01): an attempt, not a guaranteed install;
    /// the A155 host-wide skip is itself one such attempt that installs
    /// nothing and records a residual instead, per gate I4), classifies the
    /// result through [`recovery_call_decision`], and exits 0 only when the
    /// observation is genuinely healthy. A manager stop must never report a
    /// clean exit while a runtime loss is unresolved or unproven-safe; no
    /// retry budget applies here because this state runs the probe exactly
    /// once.
    fn stop_final_health_outcome(&self) -> SupervisionOutcome {
        // R3 (LINUX-STOP-LOSS-RACE-01, Claude F3): force_fresh=true bypasses the
        // nft component's NFT_HEALTH_MIN_INTERVAL cache, so this one stop-time
        // pass cannot read a loss younger than the cache window as a stale
        // cached Ready.
        let (observed, recovery_result) = self.kernel_runtime_health_with_recovery(true);
        match recovery_call_decision(
            self.is_fatal_control_path_requested(),
            self.is_shutdown_requested(),
            observed,
            recovery_result,
        ) {
            RecoveryCallDecision::FatalControlPath => return SupervisionOutcome::FatalControlPath,
            RecoveryCallDecision::RepairRequired {
                reason,
                install_result,
            } => {
                self.record_recovery_attempt(reason, install_result);
                return SupervisionOutcome::RepairRequired {
                    reason,
                    install_result,
                };
            }
            RecoveryCallDecision::Inconsistent => {
                // SAFETY: stderr is the last-resort operator channel when a returned
                // install result conflicts with its health observation at stop time.
                eprintln!("castle-wall-daemon: recovery install result returned without a Recovering observation; refusing READY");
                return SupervisionOutcome::FatalControlPath;
            }
            RecoveryCallDecision::ShutdownRequested | RecoveryCallDecision::Continue => {}
        }
        self.runtime_health.publish(observed);
        if observed == RuntimeHealthState::Ready {
            self.runtime_health.clear_safety_net();
        } else if let Some(safety_net) = self.safety_net_audit_state() {
            self.runtime_health.publish_safety_net(safety_net);
        } else {
            self.runtime_health.clear_safety_net();
        }
        match observed {
            // Exit 0 (the clean-stop path) only for a genuinely healthy observation.
            RuntimeHealthState::NoRuntime | RuntimeHealthState::Ready => {
                SupervisionOutcome::ShutdownRequested
            }
            RuntimeHealthState::Lost(reason) => {
                self.record_runtime_loss(reason, false);
                SupervisionOutcome::KernelRuntimeLost(reason)
            }
            RuntimeHealthState::Indeterminate => {
                if let Some(runtime) = &self.enforcement {
                    if let Ok(runtime) = runtime.lock() {
                        runtime.hook_post_ready_indeterminate();
                    } else {
                        // SAFETY: stderr is the operator channel for the terminal
                        // dispatch record when the runtime lock itself is poisoned.
                        eprintln!("castle-wall-daemon: terminal_dispatch=runtime_lock_poisoned");
                    }
                } else {
                    // SAFETY: same operator channel; no runtime exists to dispatch through.
                    eprintln!("castle-wall-daemon: terminal_dispatch=runtime_absent");
                }
                let reason = crate::enforcement::NotReadyReason::HealthProbeIndeterminate;
                self.record_runtime_loss(reason, false);
                SupervisionOutcome::KernelRuntimeLost(reason)
            }
            RuntimeHealthState::ProbeUnavailable => {
                // A stop-time pass gets no retry budget (S_STOP_FINAL_HEALTH runs the
                // probe exactly once); unresolved contention at stop is not proven
                // healthy, so it fails closed instead of exiting 0.
                let reason = crate::enforcement::NotReadyReason::HealthProbeUnavailable;
                self.record_runtime_loss(reason, false);
                SupervisionOutcome::KernelRuntimeLost(reason)
            }
            RuntimeHealthState::Recovering(reason) => {
                // Grok 4 (LINUX-STOP-LOSS-RACE-01): reachable whenever this
                // pass' own result did not win the RepairRequired match above
                // -- NOT only the throttled-retry case (a NoInstall while a
                // prior attempt's Recovering tag is still published), but also
                // a FIRST entry that hit the A155 host-wide skip on this same
                // pass (an install was attempted, Recovering was published,
                // and the skip itself returns NoInstall because there is no
                // known confined identity to scope it to). Neither is proven
                // healthy: fail closed rather than exit 0, in both cases.
                self.record_runtime_loss(reason, false);
                SupervisionOutcome::KernelRuntimeLost(reason)
            }
        }
    }

    fn reconcile_recovered_live_status(
        &self,
        previous: RuntimeHealthState,
        observed: RuntimeHealthState,
    ) {
        if observed == RuntimeHealthState::Ready
            && matches!(previous, RuntimeHealthState::Recovering(_))
        {
            self.live_status.update(
                LifecyclePhase::Running,
                DaemonRuntimeState::KernelRuntimeReady,
            );
        }
    }

    /// Mark the daemon degraded, publish the loss, and write the critical,
    /// fsync-backed `kernel_runtime_lost` WAL record. Shared by the proven-loss
    /// and exhausted-indeterminate-budget arms so both routes out of supervision
    /// leave identical evidence.
    fn record_runtime_loss(&self, reason: crate::enforcement::NotReadyReason, recovering: bool) {
        self.live_status
            .update(LifecyclePhase::Degraded, DaemonRuntimeState::Degraded);
        // Recovery retains the lock and owns the retry. The published state must
        // preserve that fact until an exit arm actually runs.
        self.runtime_health.publish(if recovering {
            RuntimeHealthState::Recovering(reason)
        } else {
            RuntimeHealthState::Lost(reason)
        });
        // The tagged `safety_net` state rides on the SAME row as the loss reason, so a
        // reader never has to infer the protection from the fact that a loss happened.
        // `NotAttempted` means no install was tried; `InstallFailed` means an
        // attempt did not take; `Unverified` withdraws a prior installed claim.
        // If the runtime is contended, omit the field
        // rather than claim a transition from a stale observation.
        let safety_net = self.safety_net_audit_state();
        if let Some(state) = &safety_net {
            self.runtime_health.publish_safety_net(state.clone());
        } else {
            self.runtime_health.clear_safety_net();
        }
        self.append_runtime_loss_row(reason, None, safety_net);
    }

    fn record_recovery_attempt(
        &self,
        reason: crate::enforcement::NotReadyReason,
        result: crate::enforcement::PostReadyRecoveryResult,
    ) {
        // Record the exact result and current safety-net tag without changing the
        // published observation; the caller owns this call's supervision disposition.
        self.append_runtime_loss_row(reason, Some(result), self.safety_net_audit_state());
    }

    fn append_runtime_loss_row(
        &self,
        reason: crate::enforcement::NotReadyReason,
        attempt: Option<crate::enforcement::PostReadyRecoveryResult>,
        safety_net: Option<crate::nftables::SafetyNetAuditState>,
    ) {
        if let Err(audit_err) = self
            .decision_engine
            .append_control_audit_bounded_with_safety_net(
                "kernel_runtime_lost",
                &match attempt {
                    Some(result) => format!("reason={reason:?}; recovery={result:?}"),
                    None => format!("reason={reason:?}"),
                },
                safety_net.map(|state| state.to_json()),
                crate::decision::FAILURE_AUDIT_BUDGET,
            )
        {
            // The capability is already lost, so there is no mutation to roll
            // back. Do not hide the audit failure: the caller preserves its exit
            // disposition and systemd captures this diagnostic.
            // SAFETY: stderr is the last-resort operator channel when the DURABLE audit
            // channel itself failed; there is no other place this loss can be recorded,
            // and systemd's journal is where an operator looks after a restart.
            eprintln!(
                "castle-wall-daemon: kernel runtime lost ({reason:?}) and durable loss audit failed: {audit_err}"
            );
        }
    }

    /// Programmatically request shutdown. Sets ONLY the daemon
    /// shutdown-request flag — so [`wait_for_shutdown`](Self::wait_for_shutdown)
    /// returns and [`teardown`](Self::teardown) begins — and deliberately does
    /// NOT stop the IPC accept loop. `teardown` stops IPC via
    /// [`IpcServer::stop_and_join`] only AFTER enforcement is released, so a
    /// programmatic (or signal-driven) stop can never terminate the control
    /// surface before enforcement teardown. Used by tests and by the
    /// signal-handler thread.
    pub fn request_stop(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
    }

    /// Hidden subprocess seam for the privileged integration binary. It is
    /// absent from release builds and exists only to prove the real CLI maps a
    /// fatal committed-control failure to loud stderr and nonzero exit.
    #[cfg(feature = "test-isolation")]
    pub fn request_fatal_control_path_for_test(&self) {
        self.fatal_control_path.store(true, Ordering::SeqCst);
    }

    /// TEST-ISOLATION ONLY (W1b, register id LINUX-STOP-LOSS-RACE-01). Arms the
    /// one-shot seam documented on the `test_shutdown_at_pre_recovery` field:
    /// the first live shutdown read inside `recover_post_ready_loss` (reached
    /// only after the component's probe saw a loss) flips the real shutdown
    /// flag, then disarms itself. This proves the site-5 precedence fix through the
    /// real `main` binary without racing an OS signal against the health call.
    /// Absent from release builds; must match the CLI seam name
    /// `--test-shutdown-at=pre-recovery` in `main.rs`.
    #[cfg(feature = "test-isolation")]
    pub fn arm_test_shutdown_at_pre_recovery(&self) {
        self.test_shutdown_at_pre_recovery
            .store(true, Ordering::SeqCst);
    }

    /// Test-only: attach an enforcement runtime so the readiness derivation can
    /// be exercised without a real kernel. Never compiled into the shipped
    /// daemon.
    ///
    /// The production boot path attaches a REAL runtime on a privileged Linux
    /// host (see the `enforcement` field docs and `activate_kernel_runtime`); it
    /// leaves `enforcement` `None` only where no kernel adapter exists (macOS
    /// dev, non-Linux CI). This helper exists because those hosts cannot acquire
    /// one, not because production never does.
    #[cfg(test)]
    pub(crate) fn set_enforcement_for_test(&mut self, runtime: EnforcementRuntime) {
        self.enforcement = Some(Arc::new(Mutex::new(runtime)));
        // Publish through the SAME path production uses, so a test never proves a
        // status projection the supervisor could not itself produce.
        self.runtime_health.publish(self.kernel_runtime_health());
    }

    /// Test-only: a clone of the IPC-owned accept-loop stop flag, so a test can
    /// prove the IPC server is still live (flag `false`) at the instant
    /// enforcement releases. Never compiled into the shipped daemon.
    #[cfg(test)]
    pub(crate) fn ipc_stop_flag_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ipc_stop_flag)
    }

    /// Shared, idempotent teardown used by BOTH [`stop`](Self::stop) and
    /// [`Drop`]. Tears kernel enforcement down BEFORE the IPC control surface:
    /// the NFQUEUE verdict thread routes through the decision engine and reports
    /// to the control surface, so it must stop (and be joined) before that
    /// surface goes away. `shutdown()` releases every component in reverse
    /// acquisition order and joins owned threads, so no resource-owning thread
    /// outlives this handle.
    ///
    /// Idempotent via `Option::take`: a `stop()` whose returned handle is then
    /// dropped, or any other double-invocation, does the enforcement/IPC
    /// teardown exactly once. This is the ONE ordered teardown path, so the
    /// enforcement-before-IPC invariant cannot drift between the explicit and
    /// implicit shutdown routes.
    fn teardown(&mut self) {
        if let Ok(mut state) = self.runtime_state.lock() {
            *state = DaemonRuntimeState::Stopping;
        }
        self.live_status
            .update(LifecyclePhase::Stopping, DaemonRuntimeState::Stopping);
        // Set the daemon shutdown-REQUEST flag. This is NOT the IPC accept-loop
        // stop flag, so it does not begin tearing the control surface down; it
        // only records that a stop was requested (idempotent with a prior
        // signal / request_stop).
        self.request_stop();
        // The mutation fence is deliberately earlier than enforcement release
        // and deliberately does not stop the IPC accept loop. Work that has not
        // crossed its durable WAL linearization point cancels; work that has
        // crossed it completes the infallible exact prepared commit.
        self.mutation_cancel_flag.store(true, Ordering::SeqCst);
        // Withdraw the readiness assertion BEFORE the components are released, so
        // a status query racing teardown can never read a `ready` observation
        // that is already being torn down. `ShuttingDown` is a PROVEN non-ready
        // state, not an indeterminate one.
        self.runtime_health.publish(RuntimeHealthState::Lost(
            crate::enforcement::NotReadyReason::ShuttingDown,
        ));
        // Enforcement BEFORE IPC. The NFQUEUE verdict thread routes through the
        // decision engine and reports to the IPC control surface, so it must
        // stop (and be joined) while that surface is still live. `shutdown()`
        // releases every component in reverse acquisition order and joins owned
        // threads.
        if let Some(enforcement) = self.enforcement.take() {
            if let Ok(mut enforcement) = enforcement.lock() {
                enforcement.shutdown();
            }
        }
        // ONLY now stop the IPC control surface. `stop_and_join` is the sole
        // setter of the IPC-owned accept-loop stop flag, so the accept loop was
        // guaranteed live throughout the enforcement release above.
        if let Some(server) = self.ipc_server.take() {
            server.stop_and_join();
        }
    }

    /// Stop the IPC server and wait for it to join, then return the exit
    /// report. Delegates the ordered enforcement-before-IPC teardown to the
    /// shared [`teardown`](Self::teardown) path so it matches the `Drop` route
    /// exactly.
    pub fn stop(mut self) -> Result<DaemonExitReport, DaemonError> {
        self.teardown();
        let buffer_overflow_count = self
            .audit_buffer
            .lock()
            .map(|b| b.overflow_count())
            .unwrap_or(0);
        let buffer_remaining = self.audit_buffer.lock().map(|b| b.len()).unwrap_or(0);
        Ok(DaemonExitReport {
            uptime: self.started_at.elapsed(),
            audit_overflow_count: buffer_overflow_count,
            audit_remaining: buffer_remaining,
            socket_path: self.config.socket_path.clone(),
        })
        // `self` drops here, running Drop -> teardown() again; idempotent, so
        // the second pass is a no-op.
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        // Last line of defense for the enforcement-before-IPC ordering: a caller
        // that drops the handle WITHOUT calling stop() must still tear
        // enforcement down before IPC. Rust's default field-declaration drop
        // order would drop `ipc_server` (declared before `enforcement`) FIRST,
        // inverting the required order and letting the verdict thread report to
        // an already-gone control surface; this explicit teardown overrides
        // that. After it, both fields are `None`, so the subsequent per-field
        // drops are no-ops.
        self.teardown();
    }
}

/// Operator-visible daemon state. Process liveness and authenticated IPC are
/// not a ready kernel runtime; `KernelRuntimeReady` is reserved for a boot path
/// that holds all required kernel resources (table + bound NFQUEUE + watcher).
///
/// `Enforcing` is a STRICTLY STRONGER claim than `KernelRuntimeReady` and is
/// NOT produced in this slice: it means a wrapped agent's egress is actually
/// being gated (a per-agent cgroup jump rule is installed and its packets
/// transit the NFQUEUE verdict path). A merely-ready kernel runtime with no
/// agent wrapped behind it is `KernelRuntimeReady`, never `Enforcing`; see
/// [`crate::enforcement`] and [`DaemonHandle::is_enforcing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonRuntimeState {
    ControlPlaneOnly,
    /// Every required kernel component is owned and ready. NOT enforcement.
    KernelRuntimeReady,
    /// A wrapped agent's egress is actively gated. Reserved; never set here.
    Enforcing,
    Degraded,
    Stopping,
}

impl DaemonRuntimeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlaneOnly => "control_plane_only",
            Self::KernelRuntimeReady => "kernel_runtime_ready",
            Self::Enforcing => "enforcing",
            Self::Degraded => "degraded",
            Self::Stopping => "stopping",
        }
    }
}

/// Why [`DaemonHandle::supervise_until_shutdown`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisionOutcome {
    /// A SIGTERM/SIGINT or programmatic `request_stop` asked the daemon to stop.
    /// The normal, clean exit path.
    ShutdownRequested,
    /// A mutation passed its commit point but the daemon could not preserve the
    /// required durable control/evidence invariant. Ordered teardown still
    /// runs, but process exit must be nonzero so systemd restarts the service.
    FatalControlPath,
    /// A kernel runtime that came up ready lost a required component after boot
    /// (verdict thread death, table clobbered/mutated, watcher thread exit). The
    /// daemon must NOT keep reporting itself active while non-enforcing: `main`
    /// tears down and exits nonzero so systemd restarts it.
    KernelRuntimeLost(crate::enforcement::NotReadyReason),
    /// A returned safety-net install needs operator repair before restart.
    RepairRequired {
        reason: crate::enforcement::NotReadyReason,
        install_result: crate::enforcement::PostReadyRecoveryResult,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryCallDecision {
    FatalControlPath,
    ShutdownRequested,
    Continue,
    Inconsistent,
    RepairRequired {
        reason: crate::enforcement::NotReadyReason,
        install_result: crate::enforcement::PostReadyRecoveryResult,
    },
}

fn recovery_call_decision(
    fatal: bool,
    shutdown: bool,
    observed: RuntimeHealthState,
    result: crate::enforcement::PostReadyRecoveryResult,
) -> RecoveryCallDecision {
    // C2a1(b) precedence (LINUX-STOP-LOSS-RACE-01): fatal always outranks
    // every install result; a returned InstallSucceeded/InstallFailed with a
    // Recovering observation outranks shutdown, because a stop that raced a
    // proven loss must still report the repair, not silently exit clean.
    // After both checks a shutdown request yields a clean stop only when the
    // observation is Ready or NoRuntime (the shutdown branch below).
    if fatal {
        return RecoveryCallDecision::FatalControlPath;
    }
    use crate::enforcement::PostReadyRecoveryResult::{InstallFailed, InstallSucceeded};
    if matches!(result, InstallSucceeded | InstallFailed) {
        if let RuntimeHealthState::Recovering(reason) = observed {
            return RecoveryCallDecision::RepairRequired {
                reason,
                install_result: result,
            };
        }
        // R1 (LINUX-STOP-LOSS-RACE-01, Claude F1 case 4 / gate I2): an install
        // result WITHOUT a Recovering observation is a protocol violation
        // (the caller that ran the install always publishes Recovering while
        // the attempt is in flight or just completed). That must read as
        // Inconsistent -> FatalControlPath(75) regardless of shutdown; a
        // stop in flight must never turn a protocol violation into a clean
        // exit. This is checked BEFORE the shutdown branch below so shutdown
        // can never route around it.
        return RecoveryCallDecision::Inconsistent;
    }
    if shutdown {
        // R1 (LINUX-STOP-LOSS-RACE-01, Claude F1 / Grok 1, gate I4): a
        // shutdown request reads as a clean stop ONLY when the observation is
        // genuinely healthy. No install was returned this call (the branch
        // above already handled every case where one was), so the only
        // question left is whether the daemon is actually up: Ready or
        // NoRuntime exits clean; Lost, Recovering (an outstanding attempt
        // this call did not win, e.g. a throttled retry or the A155
        // host-wide skip), Indeterminate and ProbeUnavailable must all end
        // on a nonzero arm, so this falls through to Continue and lets the
        // caller's own observation match decide. The one difference from
        // shutdown=false: under shutdown the next loop top runs
        // `stop_final_health_outcome`, which grants ProbeUnavailable no
        // consecutive-reading budget and fails closed on the first one.
        if matches!(
            observed,
            RuntimeHealthState::Ready | RuntimeHealthState::NoRuntime
        ) {
            return RecoveryCallDecision::ShutdownRequested;
        }
    }
    RecoveryCallDecision::Continue
}

/// Summary of a daemon run; surfaced to the operator on shutdown.
#[derive(Debug, Clone)]
pub struct DaemonExitReport {
    pub uptime: Duration,
    pub audit_overflow_count: u64,
    pub audit_remaining: usize,
    pub socket_path: PathBuf,
}

/// Boot the daemon. On success returns a handle; the caller is responsible
/// for calling `wait_for_shutdown` then `stop`.
pub fn boot(config: DaemonConfig) -> Result<DaemonHandle, DaemonError> {
    #[cfg(target_os = "linux")]
    config
        .validate_server_profile()
        .map_err(DaemonError::StartupConfig)?;
    let pinned_key_array = ManifestStore::load_pinned_key(&config.pinned_public_key_path)
        .map_err(|err: ManifestStoreError| DaemonError::PinnedKeyLoad(err.to_string()))?;
    // The IPC handshake uses raw bytes; the ManifestStore uses a fixed array.
    // Both views share the same key material loaded above.
    let pinned_key_bytes = pinned_key_array.to_vec();
    let trusted_service_uid = config
        .trusted_service_uid
        .ok_or(DaemonError::TrustedServiceUidMissing)?;
    // Sanity-check via the legacy auth helper as a second integrity gate.
    let _: Vec<u8> = load_pinned_public_key(&config.pinned_public_key_path)
        .map_err(|err| DaemonError::PinnedKeyLoad(err.to_string()))?;

    let audit_buffer = Arc::new(Mutex::new(AuditRingBuffer::new(
        config.wal_size_cap_bytes,
        config.wal_ttl,
    )));

    // Open the disk-backed WAL. Per scope-lock §8 the WAL is the durable
    // tier behind the in-memory ring buffer; failure to open it is a refuse-
    // to-start condition since Sanctuary main relies on durable drain.
    let wal_writer = match WalWriter::open_with_cap(&config.wal_path, config.wal_size_cap_bytes) {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(err) => return Err(DaemonError::WalOpen(err.to_string())),
    };

    // Construct the manifest store. The pinned key load above is the
    // refuse-to-start gate; the store is built around the loaded key.
    // First reload (manifest read from disk) is best-effort: an absent
    // manifest at boot is acceptable and the store stays in `current=None`
    // until Sanctuary main triggers the first policy.reload via IPC.
    let manifest_store = Arc::new(Mutex::new(ManifestStore::new(
        config.policy_dir.clone(),
        config.pinned_public_key_path.clone(),
        pinned_key_array,
        config.fortress_id.clone(),
    )));

    // Daemon shutdown-REQUEST flag: set by signal handlers and request_stop,
    // observed by wait_for_shutdown. It drives the DECISION to shut down.
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    // TEST-ISOLATION ONLY (LINUX-BOOT-STOP-HOSTWIDE-NET-01): pre-set the flag
    // before kernel activation runs, simulating a stop already requested
    // during the boot phase. This is a DIRECT set of the flag's state, not a
    // replayed signal: `install_shutdown_signal_handlers` (below, at the call
    // site that installs the real SIGTERM/SIGINT handlers) has not run yet at
    // this point, so an actual SIGTERM delivered this early would not be
    // caught by this daemon's own handler at all. What this seam reproduces is
    // the STATE the flag is in once a handler has observed a stop request --
    // the state every boot-phase site downstream reads -- so those sites can
    // be exercised without an actual signal race. This is the boot-phase
    // counterpart of `--test-shutdown-at pre-recovery` (which arms AFTER a
    // successful boot, through `DaemonHandle`): the acquisition path below has
    // no `DaemonHandle` to arm yet, so the seam pre-sets the flag `boot()`
    // itself threads into `LinuxRuntimeConfig::shutdown_requested`. Compiled
    // out of the shipped binary.
    #[cfg(feature = "test-isolation")]
    if config.test_boot_time_shutdown_requested {
        shutdown_flag.store(true, Ordering::SeqCst);
    }
    // IPC-owned accept-loop stop flag, DISTINCT from the daemon request flag
    // above. Only IpcServer::stop_and_join (called from teardown AFTER
    // enforcement.shutdown) sets it, so a signal or request_stop can never stop
    // the IPC control surface before enforcement is released. Must stay separate
    // from `shutdown_flag`; conflating them reintroduces the premature-IPC-stop
    // defect this separation fixes.
    let ipc_stop_flag = Arc::new(AtomicBool::new(false));
    let mutation_cancel_flag = Arc::new(AtomicBool::new(false));
    let fatal_control_path = Arc::new(AtomicBool::new(false));
    // TEST-ISOLATION ONLY (W1b, LINUX-STOP-LOSS-RACE-01): unarmed on every boot;
    // must match `arm_test_shutdown_at_pre_recovery`'s doc comment on the field.
    #[cfg(feature = "test-isolation")]
    let test_shutdown_at_pre_recovery = Arc::new(AtomicBool::new(false));

    // Slice L1: load (or first-boot generate) the daemon-held audit-producer
    // key. The private half stays in this process / a root-owned 0600 file and
    // is never sent over IPC; the public half is published world-readable for
    // the consumer to TOFU-pin. A failure to provision the key is a
    // refuse-to-start condition: a daemon that cannot sign its enforcement
    // events would silently downgrade the read-side authenticity basis, which
    // the fail-closed contract forbids.
    let producer_signer = crate::ipc::producer_sig::ProducerSigner::load_or_generate(
        &config.producer_key_path,
        &config.producer_pub_key_path,
    )
    .map(Arc::new)
    .map_err(|err| DaemonError::ProducerKeyLoad(err.to_string()))?;

    // ONE composition root owns policy truth. IPC reload, kernel watcher, and
    // verdict evaluation all receive clones of this exact DecisionEngine, whose
    // single ManifestStore Arc was created above. Construct it before IPC so the
    // server cannot be wired to a parallel store.
    let decision_engine = Arc::new(DecisionEngine::new_with_mutation_cancel(
        config.fortress_id.clone(),
        Some(Arc::clone(&manifest_store)),
        Some(Arc::clone(&wal_writer)),
        Arc::clone(&audit_buffer),
        Arc::clone(&mutation_cancel_flag),
    ));

    // Boot is not a privileged bypass: a present candidate becomes live only
    // through the same verify -> durable authorization receipt -> exact commit
    // chokepoint used by watcher and IPC. Invalid/absent policy remains a loud
    // deny-default boot; failure of the durable authorization path is fatal.
    // THE BOOT ENTRY, and the only reload that may write the armed identity. It
    // freezes the identity under the store guard before it returns, so the
    // check below is a real state assertion and not a hope.
    match decision_engine.reload_manifest_authorized_at_boot() {
        Ok(_) => {}
        Err(crate::decision::ManifestReloadAuthorizationError::Verify(err)) => {
            // SAFETY: stderr is the boot-diagnostic contract. A deny-by-default boot with
            // no policy is an operator-visible posture change, and this line is emitted
            // before the audit channel is trusted to carry it.
            eprintln!(
                "castle-wall-daemon: boot-time manifest load failed; running deny-by-default with NO policy until a valid manifest is reloaded: {err}"
            );
        }
        Err(err) => return Err(DaemonError::ManifestStoreInit(err.to_string())),
    }

    // A REAL CHECK, not a `debug_assert`: both continuing outcomes above write
    // the cell (a committed snapshot, or `Unconfined` on a verification
    // failure), so reaching here unset is a composition-root bug, and refusing
    // to start is the honest response rather than running a half-initialized
    // daemon. This is a SECOND, INDEPENDENT refusal, not the only barrier: an
    // authenticated publish that later reached the identity chokepoint with an
    // unset cell would already be refused there too
    // (`refuse_identity_change` in `src/decision.rs` treats an absent frozen
    // identity as unprovable and denies the reload). This check exists to fail
    // the boot loudly instead of letting the bug run until some other reader
    // interprets the unset cell a different way.
    if decision_engine.armed_identity().is_none() {
        return Err(DaemonError::ArmedIdentityNotFrozen);
    }

    let live_status = Arc::new(LiveStatus::activating());
    // ONE health view, shared by the supervision loop (sole writer) and the IPC
    // status handler (reader). Constructed here, before the IPC server, so the
    // server cannot be wired to a second, never-published view.
    let runtime_health = Arc::new(RuntimeHealthView::new());
    let wal_control_progress = Arc::new(AtomicUsize::new(0));
    let drain_recovery_only = Arc::new(AtomicBool::new(true));

    // Recovery-at-cap may wait for an authenticated client to reclaim WAL
    // space, so termination signals must already be observable during that
    // bounded-functionality boot phase.
    install_shutdown_signal_handlers(Arc::clone(&shutdown_flag))?;

    let ipc_server = IpcServer::start(crate::ipc::server::ServerConfig {
        socket_path: config.socket_path.clone(),
        pinned_public_key: pinned_key_bytes,
        prompt_timeout: config.prompt_timeout,
        audit_buffer: Arc::clone(&audit_buffer),
        daemon_shutdown_request: Arc::clone(&shutdown_flag),
        fatal_control_path: Arc::clone(&fatal_control_path),
        // The IPC accept loop stops on the IPC-owned flag, NOT the daemon
        // shutdown-request flag, so a signal/request_stop cannot terminate it
        // before enforcement teardown.
        shutdown_flag: Arc::clone(&ipc_stop_flag),
        fortress_id: config.fortress_id.clone(),
        decision_engine: Arc::clone(&decision_engine),
        wal_writer: Some(Arc::clone(&wal_writer)),
        producer_signer: Some(producer_signer),
        live_status: Arc::clone(&live_status),
        trusted_service_uid,
        runtime_health: Arc::clone(&runtime_health),
        wal_control_progress: Arc::clone(&wal_control_progress),
        drain_recovery_only: Arc::clone(&drain_recovery_only),
    })?;
    debug_assert!(Arc::ptr_eq(ipc_server.decision_engine(), &decision_engine));
    debug_assert!(Arc::ptr_eq(
        decision_engine
            .manifest_store()
            // Safety: debug-assert-only path. `boot` constructs the production decision
            // engine from `manifest_store` a few lines above, so the store is wired; a
            // None here would be a composition-root bug the assert is there to catch.
            .expect("production decision engine is store-wired"),
        &manifest_store
    ));

    // Startup evidence uses the same WAL-linearized critical path as control
    // mutations. At disk cap or on lock/fsync failure, refuse startup rather
    // than silently running without the durable boot record.
    loop {
        match decision_engine.append_control_audit("daemon_started", "control_surface_bound") {
            Ok(_) => {
                // Release control writes only after the startup lifecycle row
                // itself is durable. Kernel activation happens after this loop.
                drain_recovery_only.store(false, Ordering::SeqCst);
                break;
            }
            Err(err) if err.is_capacity_exceeded() => {
                if shutdown_flag.load(Ordering::SeqCst) {
                    return Err(DaemonError::WalOpen(
                        "shutdown requested during WAL drain recovery".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(DaemonError::WalOpen(err.to_string())),
        }
    }

    let runtime_state = Arc::new(Mutex::new(DaemonRuntimeState::ControlPlaneOnly));

    // Attempt to activate the kernel enforcement runtime. On a privileged Linux
    // host this installs the nftables table under the host ownership lock, binds
    // NFQUEUE (fail-open off) with a joined verdict thread, and starts the
    // manifest watcher thread — an ordered, all-or-nothing acquisition. The
    // outcome is THREE-WAY (servers-first fail-before contract):
    //
    // * `Activated`          — the whole ordered set acquired and is ready.
    // * `UnsupportedPlatform` — this host has no kernel adapter (macOS dev,
    //   non-Linux CI). The ONLY non-fatal miss: the daemon serves its IPC
    //   control plane only and never claims to enforce.
    // * `Failed`             — a SUPPORTED-Linux acquisition/readiness failure (a
    //   foreign pre-existing table, a host-lock conflict, an nft verify failure,
    //   an NFQUEUE or watcher bind failure, ...). This is FATAL: a host that
    //   should enforce must NOT boot a live-but-non-enforcing service.
    //   `EnforcementRuntime::start` already released every acquired userspace
    //   component in reverse order. If nftables acquisition completed before a
    //   later component failed, release deliberately preserves the exact owned
    //   table and authenticated journal for fail-closed restart adoption. We
    //   tear the boot-acquired IPC control surface down in order and return a
    //   typed error BEFORE the readiness beacon, so no `READY=1` is ever sent.
    let enforcement = match activate_kernel_runtime(
        &config,
        Arc::clone(&decision_engine),
        Arc::clone(&shutdown_flag),
    ) {
        KernelRuntimeActivation::Activated(runtime) => Some(runtime),
        KernelRuntimeActivation::UnsupportedPlatform => None,
        KernelRuntimeActivation::Failed(err) => {
            // Ordered unwind: userspace enforcement components are already
            // released by start()'s fail-before, so only the IPC control surface
            // remains to tear down. An acquired owned table may remain by design
            // with its authenticated journal for exact restart adoption.
            // Stop and join it (unlinking its socket) before returning, so no
            // partial state (a bound socket, a live accept loop) is left behind.
            // Returning here is BEFORE signal_systemd_readiness, so no `READY=1`
            // is emitted on the failed-acquisition path.
            ipc_server.stop_and_join();
            return Err(DaemonError::KernelRuntimeActivation(err.to_string()));
        }
    };

    // systemd `Type=notify` readiness beacon: send `READY=1` exactly once, and
    // ONLY now that BOTH the IPC control surface is bound (above) and the kernel
    // runtime is live. On a supported Linux host we only reach here when the
    // runtime activated (a `Failed` activation returned above), so a ready
    // runtime is the normal case; on a non-Linux host the runtime is `None` and
    // `READY=1` is withheld honestly. When `NOTIFY_SOCKET` is unset the send is a
    // silent no-op. If a CONFIGURED `NOTIFY_SOCKET` is present but delivery
    // FAILS, we must NOT leave a false-started long-running process: unwind
    // enforcement-before-IPC and fail closed so systemd restarts promptly.
    let readiness = signal_systemd_readiness(enforcement.as_ref());
    if let Err(err) = readiness {
        mutation_cancel_flag.store(true, Ordering::SeqCst);
        // Enforcement BEFORE IPC, matching the runtime teardown order: release
        // the kernel runtime (if any came up) first, then the control surface.
        if let Some(mut runtime) = enforcement {
            runtime.shutdown();
        }
        ipc_server.stop_and_join();
        return Err(err);
    }

    let enforcement = enforcement.map(|runtime| Arc::new(Mutex::new(runtime)));
    // Publish the boot-time health observation so a status query arriving before
    // the first supervisor tick reads a real observation rather than "nothing
    // published yet" (which is honest, but needlessly indeterminate).
    runtime_health.publish(if enforcement.is_some() {
        RuntimeHealthState::Ready
    } else {
        RuntimeHealthState::NoRuntime
    });
    runtime_health.publish_safety_net(
        enforcement
            .as_ref()
            .and_then(|runtime| runtime.lock().ok())
            .map(|runtime| runtime.safety_net_audit_state())
            .unwrap_or(crate::nftables::SafetyNetAuditState::NotAttempted),
    );

    // Activation includes supervisor readiness delivery. Do not publish the
    // Running phase until that final gate succeeds; authenticated status during
    // acquisition/notification remains explicitly Activating.
    let live_runtime_state = if enforcement.is_some() {
        DaemonRuntimeState::KernelRuntimeReady
    } else {
        DaemonRuntimeState::ControlPlaneOnly
    };
    live_status.update(LifecyclePhase::Running, live_runtime_state);

    Ok(DaemonHandle {
        config,
        ipc_server: Some(ipc_server),
        audit_buffer,
        decision_engine,
        runtime_state,
        live_status,
        runtime_health,
        wal_control_progress,
        enforcement,
        shutdown_flag,
        fatal_control_path,
        mutation_cancel_flag,
        #[cfg(test)]
        ipc_stop_flag,
        #[cfg(feature = "test-isolation")]
        test_shutdown_at_pre_recovery,
        started_at: Instant::now(),
    })
}

/// Poll cadence for the manifest watcher's degraded (non-inotify) fallback.
const KERNEL_RUNTIME_POLL_INTERVAL: Duration =
    Duration::from_millis(crate::failure::MANIFEST_WATCHER_POLL_INTERVAL_MS as u64);

/// Outcome of attempting to activate the kernel enforcement runtime at boot.
/// The three arms ARE the servers-first fail-before contract: a live runtime, a
/// platform with no kernel adapter (non-fatal, control-plane-only), or a
/// supported-Linux acquisition failure (FATAL — boot must refuse to start).
#[derive(Debug)]
enum KernelRuntimeActivation {
    /// The whole ordered set acquired and every component is ready.
    Activated(EnforcementRuntime),
    /// This host has no kernel adapter (macOS dev, non-Linux CI). The ONLY
    /// non-fatal activation miss: the daemon serves control-plane-only and never
    /// claims to enforce.
    UnsupportedPlatform,
    /// A supported-Linux acquisition/readiness failure. `EnforcementRuntime::start`
    /// already unwound every acquired userspace component in reverse order. An
    /// exactly identified owned nftables table may remain intentionally, with
    /// its authenticated journal, for fail-closed restart adoption. Boot must
    /// still fail-before rather than run non-enforcing.
    Failed(crate::enforcement::EnforcementStartError),
}

/// Classify a runtime `start` result into the fail-before contract. Pure so the
/// classification — which failures are FATAL versus the single non-fatal
/// no-adapter case — is unit-testable on the dev host, where a real acquisition
/// never fails-for-real (the providers always return `NotAvailableOnPlatform`).
fn classify_activation(
    result: Result<EnforcementRuntime, crate::enforcement::EnforcementStartError>,
) -> KernelRuntimeActivation {
    match result {
        Ok(runtime) => KernelRuntimeActivation::Activated(runtime),
        // The ONLY non-fatal miss: no kernel adapter on this platform. This
        // variant is produced SOLELY by the providers' `cfg(not(target_os =
        // "linux"))` branches, so it means exactly "this is not a supported
        // Linux enforcement host" — never a real Linux acquisition failure.
        Err(err) if is_platform_unsupported(&err) => KernelRuntimeActivation::UnsupportedPlatform,
        // Everything else is a genuine acquisition/readiness failure on a
        // platform that SHOULD enforce (a foreign table, a host-lock conflict, an
        // nft verify failure, an NFQUEUE/watcher bind failure, a plan mismatch).
        // FATAL: boot returns a typed error and refuses to start.
        Err(err) => KernelRuntimeActivation::Failed(err),
    }
}

/// Build the production Linux enforcement plan, attempt to start it, and
/// classify the result. A `Failed` outcome (a genuine acquisition failure on a
/// supported platform) is logged loudly here and turned into a fail-before by
/// `boot`; the expected "no kernel adapter on this platform" case (macOS dev)
/// stays quiet and non-fatal.
fn activate_kernel_runtime(
    config: &DaemonConfig,
    decision_engine: Arc<DecisionEngine>,
    // A162 (LINUX-BOOT-STOP-HOSTWIDE-NET-01): the SAME `Arc` as
    // `DaemonHandle::shutdown_flag`, threaded into the boot-phase acquisition
    // path so every pre-READY safety-net install site can see a stop requested
    // before kernel activation completes. `install_shutdown_signal_handlers`
    // (called above, before this function) is what actually flips it.
    shutdown_flag: Arc<AtomicBool>,
) -> KernelRuntimeActivation {
    #[cfg(test)]
    {
        // Unit tests exercise the control-plane lifecycle without acquiring
        // host-global kernel objects. The privileged integration targets build
        // the library without `cfg(test)` and opt into `test-isolation`, so they
        // still exercise this exact production activation path against an
        // isolated nftables table and isolated runtime paths.
        let _ = (config, decision_engine, shutdown_flag);
        KernelRuntimeActivation::UnsupportedPlatform
    }

    #[cfg(not(test))]
    {
        let linux_runtime_config = crate::runtime_providers::LinuxRuntimeConfig {
            // Host-global (fortress-independent) lock path: a second daemon, even one
            // with a different fortress id, contends here and refuses before touching
            // nftables (see `runtime_lock`).
            //
            // Read from the CONFIG, not from the default constants. Production still
            // resolves to `LinuxRuntimePaths::production()` (that is the field's
            // default), but the seam is what lets the privileged test suite point a
            // boot at a temporary root instead of the operator's live lock, journal,
            // and journal MAC key.
            lock_path: config.linux_runtime_paths.host_lock_path.clone(),
            // Durable, root-owned ownership journal under the systemd StateDirectory
            // (/var/lib/sanctuary): survives service restart and reboot so a crash
            // between atomic-create and finalize is reclaimed, not wedged (blocker 3).
            journal_path: config.linux_runtime_paths.ownership_journal_path.clone(),
            // Authenticated-journal MAC key, root-owned under the same StateDirectory
            // (blocker 3). Generated on first acquisition; a present-but-unsafe key or
            // a MAC mismatch fails the activation closed.
            journal_key_path: config.linux_runtime_paths.journal_auth_key_path.clone(),
            policy_dir: config.policy_dir.clone(),
            poll_interval: KERNEL_RUNTIME_POLL_INTERVAL,
            nfqueue: crate::nfqueue::NfqueueConfig::default(),
            shutdown_requested: shutdown_flag,
        };
        let plan =
            crate::runtime_providers::linux_production_plan(decision_engine, &linux_runtime_config);
        let activation = classify_activation(EnforcementRuntime::start(plan));
        if let KernelRuntimeActivation::Failed(err) = &activation {
            // SAFETY: stderr is the boot-time diagnostic channel (systemd captures
            // it); a real activation failure on a host that SHOULD enforce must be
            // loud AND fatal. Unlike the earlier behavior, this is NOT a silent
            // control-plane-only downgrade: `boot` returns a typed error and systemd
            // (Restart=on-failure) restarts the unit.
            eprintln!(
                "castle-wall-daemon: kernel runtime activation FAILED on a supported \
                 platform ({err}); refusing to start (servers-first fail-before)"
            );
        }
        activation
    }
}

/// True when a start failure is just "this platform has no kernel adapter"
/// (macOS dev host): expected, so it is not logged loudly. Any other failure —
/// a real acquisition error on a Linux host — is worth an operator's attention.
fn is_platform_unsupported(err: &crate::enforcement::EnforcementStartError) -> bool {
    matches!(
        err,
        crate::enforcement::EnforcementStartError::Component {
            reason: crate::enforcement::EnforcementError::NotAvailableOnPlatform(_),
            ..
        }
    )
}

/// Fire the systemd readiness beacon iff the kernel runtime is live.
///
/// Returns `Err(DaemonError::ReadinessNotify)` ONLY when a supervisor socket was
/// CONFIGURED (`NOTIFY_SOCKET` set) and the `READY=1` send failed: `boot` turns
/// that into an ordered unwind + nonzero exit rather than a false-started
/// long-running process. Withholds `READY=1` (honestly, `Ok`) when the runtime
/// did not come up under a `Type=notify` supervisor, and is a silent `Ok` no-op
/// when `NOTIFY_SOCKET` is unset.
fn signal_systemd_readiness(enforcement: Option<&EnforcementRuntime>) -> Result<(), DaemonError> {
    let status = crate::enforcement::enforcement_status(enforcement);
    let kernel_runtime_ready = matches!(
        status,
        crate::enforcement::EnforcementStatus::KernelRuntimeReady
    );
    // A component can die in the narrow activate-to-notify window. A present
    // runtime that is no longer ready is a supported-host activation failure,
    // not the benign non-Linux `None` case. This makes boot tear down in order
    // and makes `--boot-and-exit` fail instead of reporting a false green.
    if enforcement.is_some() && !kernel_runtime_ready {
        return Err(DaemonError::KernelRuntimeActivation(format!(
            "kernel runtime lost readiness before READY=1: {status:?}"
        )));
    }
    let notify_configured = std::env::var_os(crate::systemd_notify::NOTIFY_SOCKET_ENV).is_some();
    let mut beacon = crate::systemd_notify::ReadyBeacon::from_env();
    deliver_readiness(kernel_runtime_ready, notify_configured, &mut beacon)
}

/// Pure readiness-delivery decision over an injected beacon, so the
/// fail-on-configured-send-failure contract is unit-testable without touching the
/// process environment or standing up a real kernel runtime.
///
/// * runtime ready → send `READY=1`; a failed send to a CONFIGURED socket is
///   FATAL (do not leave a false-started process), an unset socket is a silent
///   success inside the beacon.
/// * runtime not ready, supervisor configured → withhold `READY=1` (honest, not
///   an error): systemd applies its own restart policy on the missing signal. On
///   a SUPPORTED Linux host we never reach here with a not-ready runtime — a
///   `Failed` activation returned earlier — so this is the non-Linux-under-
///   systemd path.
/// * otherwise → nothing to do.
fn deliver_readiness(
    kernel_runtime_ready: bool,
    notify_configured: bool,
    beacon: &mut crate::systemd_notify::ReadyBeacon,
) -> Result<(), DaemonError> {
    if kernel_runtime_ready {
        return beacon
            .signal_ready()
            .map(|_| ())
            .map_err(|err| DaemonError::ReadinessNotify(err.to_string()));
    }
    if notify_configured {
        // SAFETY: stderr is the boot-time diagnostic channel here (systemd
        // captures it), consistent with boot()'s other loud notices. Telling
        // systemd we are ready when the wall is not up would be a false
        // enforcement claim, so withhold the signal rather than lie.
        eprintln!(
            "castle-wall-daemon: NOTIFY_SOCKET set but kernel runtime not ready; \
             withholding READY=1"
        );
    }
    Ok(())
}

/// Process-wide handle to the shutdown flag installed at boot. Exposed so the
/// signal handler (which has only a `extern "C" fn(c_int)` API and cannot
/// take captured state) can flip the atomic when SIGTERM/SIGINT arrives.
static SHUTDOWN_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

#[cfg(unix)]
extern "C" fn handle_termination_signal(_signum: libc::c_int) {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

#[cfg(unix)]
fn install_shutdown_signal_handlers(shutdown_flag: Arc<AtomicBool>) -> Result<(), DaemonError> {
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

    // Install a process-wide shared shutdown flag once. A second boot in
    // the same process (uncommon outside tests) re-installs the handlers
    // but reuses the existing flag pointer.
    let _ = SHUTDOWN_FLAG.set(shutdown_flag);

    let action = SigAction::new(
        SigHandler::Handler(handle_termination_signal),
        SaFlags::empty(),
        SigSet::empty(),
    );
    for sig in [Signal::SIGTERM, Signal::SIGINT] {
        unsafe {
            sigaction(sig, &action).map_err(|e| DaemonError::SignalSetup(e.to_string()))?;
        }
    }
    // SIGHUP is reserved for manifest-reload in Checkpoint 2; ignore for now
    // so default termination behavior does not kill the daemon during a
    // benign tty hang-up.
    let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    unsafe {
        let _ = sigaction(Signal::SIGHUP, &ignore);
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_shutdown_signal_handlers(shutdown_flag: Arc<AtomicBool>) -> Result<(), DaemonError> {
    let _ = shutdown_flag;
    Err(DaemonError::PlatformMissing(
        "signal handling requires a Unix host".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DaemonConfig;
    use crate::crypto::castle_wall_signing_key_id;
    use crate::policy::{DeniedReason, Verdict};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::fs;
    use tempfile::TempDir;

    #[derive(Clone, Copy)]
    enum AttemptSideEffect {
        None,
        Fatal,
        Shutdown,
        FatalAndShutdown,
    }

    struct InitialAttemptComponent {
        kind: crate::enforcement::ComponentKind,
        health: Arc<Mutex<crate::enforcement::ComponentHealth>>,
        attempts: Arc<AtomicUsize>,
        tag: Arc<Mutex<crate::nftables::SafetyNetAuditState>>,
        result: crate::enforcement::PostReadyRecoveryResult,
        post_health: crate::enforcement::ComponentHealth,
        side_effect: AttemptSideEffect,
        later_interval: bool,
        fatal: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    }

    impl crate::enforcement::AcquiredComponent for InitialAttemptComponent {
        fn kind(&self) -> crate::enforcement::ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            self.health() == crate::enforcement::ComponentHealth::Ready
        }
        fn health(&self) -> crate::enforcement::ComponentHealth {
            *self.health.lock().unwrap()
        }
        fn safety_net_audit_state(&self) -> Option<crate::nftables::SafetyNetAuditState> {
            (self.kind == crate::enforcement::ComponentKind::NftablesTable)
                .then(|| self.tag.lock().unwrap().clone())
        }
        fn attempt_post_ready_recovery(
            &self,
            shutting_down: &dyn Fn() -> bool,
        ) -> crate::enforcement::PostReadyRecoveryResult {
            use crate::enforcement::{ComponentKind, PostReadyRecoveryResult as R};
            if self.kind != ComponentKind::NftablesTable {
                return R::NoInstall;
            }
            let shutting_down = shutting_down();
            let call = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            // C2a1(a) site 6 (LINUX-STOP-LOSS-RACE-01, F6): shutdown gates only
            // a retry -- any call after the first, whatever that first call
            // did -- never the first entry for a proven loss. `call` counts
            // every invocation of this method, including an early return below
            // that performs no install attempt, so "the first call" (not "the
            // first substantive attempt") is the literally true description.
            if shutting_down && call > 1 {
                return R::NoInstall;
            }
            if self.later_interval && call == 1 {
                // Survive the real initial poll with a prior recovery observation.
                *self.health.lock().unwrap() = crate::enforcement::ComponentHealth::Recovering;
                return R::NoInstall;
            }
            if self.later_interval && call > 2 {
                // Bound a regression that forgets to terminalize the interval call.
                self.shutdown.store(true, Ordering::SeqCst);
                return R::NoInstall;
            }
            *self.health.lock().unwrap() = self.post_health;
            match self.result {
                R::InstallSucceeded => {
                    *self.tag.lock().unwrap() = crate::nftables::SafetyNetAuditState::Installed {
                        shape: "v1-host-wide",
                        reason: "unknown-history",
                        deny_set_size: 0,
                        deny_set_max: 1,
                        rules: vec![],
                        denied_uids: vec![],
                        sources: crate::nftables::SafetyNetSources {
                            journal: false,
                            manifest: false,
                            live_table: false,
                        },
                        kernel_nd_accepted: vec![],
                        unattestable_packets: "drop-except-kernel-nd",
                        coverage: "inet output hook",
                    }
                }
                R::InstallFailed => {
                    *self.tag.lock().unwrap() =
                        crate::nftables::SafetyNetAuditState::InstallFailed {
                            attempted_scope: "v1-host-wide".into(),
                            error: "injected failure".into(),
                        }
                }
                R::NoInstall | R::OwnedWallReady => {}
            }
            match self.side_effect {
                AttemptSideEffect::None => {}
                AttemptSideEffect::Fatal => self.fatal.store(true, Ordering::SeqCst),
                AttemptSideEffect::Shutdown => self.shutdown.store(true, Ordering::SeqCst),
                AttemptSideEffect::FatalAndShutdown => {
                    self.shutdown.store(true, Ordering::SeqCst);
                    self.fatal.store(true, Ordering::SeqCst);
                }
            }
            self.result
        }
        fn release(&mut self) {}
    }

    struct InitialAttemptProvider(InitialAttemptComponent);
    impl crate::enforcement::ComponentProvider for InitialAttemptProvider {
        fn kind(&self) -> crate::enforcement::ComponentKind {
            self.0.kind
        }
        fn acquire(
            self: Box<Self>,
        ) -> Result<
            Box<dyn crate::enforcement::AcquiredComponent>,
            crate::enforcement::EnforcementError,
        > {
            Ok(Box::new(self.0))
        }
    }

    fn install_initial_attempt_fixture(
        handle: &mut DaemonHandle,
        result: crate::enforcement::PostReadyRecoveryResult,
        post_health: crate::enforcement::ComponentHealth,
        side_effect: AttemptSideEffect,
        later_interval: bool,
    ) -> Arc<AtomicUsize> {
        use crate::enforcement::{ComponentHealth, ComponentKind};
        let attempts = Arc::new(AtomicUsize::new(0));
        let health = Arc::new(Mutex::new(ComponentHealth::Ready));
        let tag = Arc::new(Mutex::new(
            crate::nftables::SafetyNetAuditState::NotAttempted,
        ));
        let providers = ComponentKind::REQUIRED_IN_ORDER
            .iter()
            .copied()
            .map(|kind| {
                Box::new(InitialAttemptProvider(InitialAttemptComponent {
                    kind,
                    health: if kind == ComponentKind::NftablesTable {
                        Arc::clone(&health)
                    } else {
                        Arc::new(Mutex::new(ComponentHealth::Ready))
                    },
                    attempts: Arc::clone(&attempts),
                    tag: Arc::clone(&tag),
                    result,
                    post_health,
                    side_effect,
                    later_interval,
                    fatal: Arc::clone(&handle.fatal_control_path),
                    shutdown: Arc::clone(&handle.shutdown_flag),
                })) as Box<dyn crate::enforcement::ComponentProvider>
            })
            .collect();
        handle.set_enforcement_for_test(EnforcementRuntime::start(providers).unwrap());
        *health.lock().unwrap() = ComponentHealth::Lost;
        attempts
    }

    #[test]
    fn recovery_wal_rows_cover_every_install_and_only_one_throttle_transition() {
        use crate::enforcement::{
            ComponentKind, NotReadyReason, PostReadyRecoveryResult as Result,
        };
        use crate::nftables::SafetyNetAuditState as Tag;
        let recovering = RuntimeHealthState::Recovering(NotReadyReason::SafetyNetRecovering(
            ComponentKind::NftablesTable,
        ));
        let installed = Tag::Installed {
            shape: "v1-host-wide",
            reason: "unknown-history",
            deny_set_size: 0,
            deny_set_max: 1,
            rules: vec![],
            denied_uids: vec![],
            sources: crate::nftables::SafetyNetSources {
                journal: false,
                manifest: false,
                live_table: false,
            },
            kernel_nd_accepted: vec![],
            unattestable_packets: "drop-except-kernel-nd",
            coverage: "inet output hook",
        };
        let failed = Tag::InstallFailed {
            attempted_scope: "v1-host-wide".into(),
            error: "injected".into(),
        };
        assert_eq!(
            recovery_row_actions(
                RuntimeHealthState::Ready,
                Some(&Tag::NotAttempted),
                Some(&installed),
                Result::InstallSucceeded
            ),
            (true, false, true)
        );
        assert_eq!(
            recovery_row_actions(
                recovering,
                Some(&installed),
                Some(&Tag::Unverified),
                Result::NoInstall
            ),
            (false, true, false)
        );
        assert_eq!(
            recovery_row_actions(
                recovering,
                Some(&Tag::Unverified),
                Some(&Tag::Unverified),
                Result::NoInstall
            ),
            (false, false, false)
        );
        assert_eq!(
            recovery_row_actions(recovering, None, Some(&Tag::Unverified), Result::NoInstall),
            (false, true, false),
            "a genuinely absent prior tag is a transition to Unverified"
        );
        assert_eq!(
            recovery_row_actions(
                recovering,
                Some(&Tag::Unverified),
                Some(&failed),
                Result::InstallFailed
            ),
            (false, false, true)
        );
        assert_eq!(
            recovery_row_actions(
                recovering,
                Some(&failed),
                Some(&failed),
                Result::InstallFailed
            ),
            (false, false, true)
        );
    }

    /// U1 decision matrix (LINUX-STOP-LOSS-RACE-01): fatal x shutdown x
    /// {none, InstallSucceeded, InstallFailed}. Fatal always wins; a returned
    /// InstallSucceeded/InstallFailed with a Recovering observation outranks
    /// shutdown (C2a1(b)); a shutdown with no returned install yields
    /// ShutdownRequested only for a Ready or NoRuntime observation, and every
    /// other observation falls through to Continue (R1).
    #[test]
    fn u1_recovery_call_decision_matrix() {
        use crate::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult as R};
        let recovering_reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let recovering = RuntimeHealthState::Recovering(recovering_reason);
        let ready = RuntimeHealthState::Ready;

        // Fatal outranks everything, in or out of shutdown, with or without a
        // returned install.
        for shutdown in [false, true] {
            for (observed, result) in [
                (ready, R::NoInstall),
                (recovering, R::InstallSucceeded),
                (recovering, R::InstallFailed),
            ] {
                assert_eq!(
                    recovery_call_decision(true, shutdown, observed, result),
                    RecoveryCallDecision::FatalControlPath,
                    "fatal must win regardless of shutdown={shutdown} or result={result:?}"
                );
            }
        }

        // Not fatal, not shutdown, no install returned: Continue.
        assert_eq!(
            recovery_call_decision(false, false, ready, R::NoInstall),
            RecoveryCallDecision::Continue
        );

        // Not fatal, shutdown, no install returned: ShutdownRequested.
        assert_eq!(
            recovery_call_decision(false, true, ready, R::NoInstall),
            RecoveryCallDecision::ShutdownRequested
        );

        // Not fatal, NOT shutdown, InstallSucceeded/InstallFailed with a
        // Recovering observation: RepairRequired (today's baseline behavior).
        for result in [R::InstallSucceeded, R::InstallFailed] {
            assert_eq!(
                recovery_call_decision(false, false, recovering, result),
                RecoveryCallDecision::RepairRequired {
                    reason: recovering_reason,
                    install_result: result,
                }
            );
        }

        // C2a1(b), the changed row: shutdown IS set, but a returned install with a
        // Recovering observation still outranks it and reports RepairRequired
        // rather than ShutdownRequested. Fails on dd2e5b06 (pre-fix returns
        // ShutdownRequested here).
        for result in [R::InstallSucceeded, R::InstallFailed] {
            assert_eq!(
                recovery_call_decision(false, true, recovering, result),
                RecoveryCallDecision::RepairRequired {
                    reason: recovering_reason,
                    install_result: result,
                },
                "an install result must outrank a bare shutdown flag"
            );
        }

        // R1 (LINUX-STOP-LOSS-RACE-01, Claude F1 case 4): a returned install
        // result WITHOUT a Recovering observation never wins the (b)
        // precedence (that precedence is keyed on the Recovering observation,
        // not merely on "some install result came back"); it is ALWAYS
        // Inconsistent -> FatalControlPath(75), in or out of shutdown. Before
        // the R1 fix, shutdown=true masked this protocol violation as a clean
        // ShutdownRequested exit-0; this assertion is that fail-before
        // witness (it fails on 75a779a1, which returns ShutdownRequested here).
        for shutdown in [false, true] {
            assert_eq!(
                recovery_call_decision(false, shutdown, ready, R::InstallSucceeded),
                RecoveryCallDecision::Inconsistent,
                "an install result without a Recovering observation must stay \
                 Inconsistent regardless of shutdown={shutdown}"
            );
        }

        // R1 case 1/2 (LINUX-STOP-LOSS-RACE-01, Claude F1 case 1 / Grok
        // finding 1, gate I4): a bare shutdown with NO returned install and an
        // observation that is NOT genuinely healthy must never read as a
        // clean stop. This is the A155 host-wide skip (Recovering published,
        // NoInstall returned) and the gated throttled-retry path (same
        // combination). Fails on 75a779a1, which returns ShutdownRequested
        // here (the bug both Claude F1 and Grok finding 1 report).
        assert_eq!(
            recovery_call_decision(false, true, recovering, R::NoInstall),
            RecoveryCallDecision::Continue,
            "an A155 host-wide skip or a throttled retry must not read as a clean stop"
        );

        // R1 case 3 (LINUX-STOP-LOSS-RACE-01, Claude F1 case 3): a proven Lost
        // with NO recovery call at all (e.g. AuditWalPoisoned, which never
        // reaches the runtime's recovery controller) must not read as a clean
        // stop either. Fails on 75a779a1 for the same reason as case 1/2.
        let lost = RuntimeHealthState::Lost(crate::enforcement::NotReadyReason::AuditWalPoisoned);
        assert_eq!(
            recovery_call_decision(false, true, lost, R::NoInstall),
            RecoveryCallDecision::Continue,
            "a proven loss with no recovery call must not read as a clean stop"
        );

        // The remaining not-genuinely-healthy observations, for completeness
        // (I7: enumerate every reachable combination, not just the named
        // examples).
        for observed in [
            RuntimeHealthState::Indeterminate,
            RuntimeHealthState::ProbeUnavailable,
        ] {
            assert_eq!(
                recovery_call_decision(false, true, observed, R::NoInstall),
                RecoveryCallDecision::Continue,
                "observed={observed:?} must not read as a clean stop under shutdown"
            );
        }
    }

    #[test]
    fn initial_poll_handles_attempt_precedence_protocol_and_audit_matrix() {
        run_attempt_precedence_protocol_and_audit_matrix(false);
    }

    #[test]
    fn later_interval_handles_attempt_precedence_protocol_and_audit_matrix() {
        run_attempt_precedence_protocol_and_audit_matrix(true);
    }

    fn run_attempt_precedence_protocol_and_audit_matrix(later_interval: bool) {
        use crate::enforcement::{
            ComponentHealth, ComponentKind, NotReadyReason, PostReadyRecoveryResult as R,
        };
        use crate::nftables::SafetyNetAuditState as Tag;

        #[derive(Clone, Copy, Debug)]
        enum Expected {
            Repair,
            Fatal,
            Shutdown,
        }
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let cases = [
            (
                R::InstallSucceeded,
                ComponentHealth::Recovering,
                AttemptSideEffect::None,
                false,
                Expected::Repair,
            ),
            (
                R::InstallFailed,
                ComponentHealth::Recovering,
                AttemptSideEffect::None,
                false,
                Expected::Repair,
            ),
            (
                R::InstallFailed,
                ComponentHealth::Recovering,
                AttemptSideEffect::Fatal,
                false,
                Expected::Fatal,
            ),
            (
                R::InstallFailed,
                ComponentHealth::Recovering,
                AttemptSideEffect::FatalAndShutdown,
                false,
                Expected::Fatal,
            ),
            (
                // C2a1(b) (LINUX-STOP-LOSS-RACE-01): a returned InstallFailed with a
                // Recovering observation now outranks a shutdown flag that flips true
                // during this same call (row 4a in the design memo: InstallFailed
                // under shutdown still reports RepairRequired, not a clean exit).
                // Pre-fix this case expected Shutdown; that was the bug.
                R::InstallFailed,
                ComponentHealth::Recovering,
                AttemptSideEffect::Shutdown,
                false,
                Expected::Repair,
            ),
            (
                R::InstallSucceeded,
                ComponentHealth::Ready,
                AttemptSideEffect::None,
                false,
                Expected::Fatal,
            ),
            (
                R::InstallFailed,
                ComponentHealth::Recovering,
                AttemptSideEffect::None,
                true,
                Expected::Repair,
            ),
            (
                R::NoInstall,
                ComponentHealth::Ready,
                AttemptSideEffect::None,
                false,
                Expected::Shutdown,
            ),
            (
                R::OwnedWallReady,
                ComponentHealth::Ready,
                AttemptSideEffect::None,
                false,
                Expected::Shutdown,
            ),
        ];
        for (result, post_health, side_effect, fail_audit, expected) in cases {
            let dir = TempDir::new().unwrap();
            let (config, _) = fresh_config_in(&dir);
            let mut handle = boot(config).unwrap();
            let attempts = install_initial_attempt_fixture(
                &mut handle,
                result,
                post_health,
                side_effect,
                later_interval,
            );
            if fail_audit {
                let buffer = Arc::clone(&handle.audit_buffer);
                assert!(std::thread::spawn(move || {
                    let _guard = buffer.lock().unwrap();
                    panic!("inject recovery audit append failure");
                })
                .join()
                .is_err());
            }
            let view = Arc::clone(handle.runtime_health_view());
            let shutdown_after_ready = matches!(result, R::NoInstall | R::OwnedWallReady);
            if matches!(result, R::NoInstall | R::OwnedWallReady) {
                view.publish(RuntimeHealthState::Recovering(reason));
                view.publish_safety_net(Tag::Unverified);
            }
            let shutdown_waiter = if shutdown_after_ready {
                let shutdown = Arc::clone(&handle.shutdown_flag);
                let ready_view = Arc::clone(&view);
                Some(std::thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    loop {
                        if ready_view.supervisor_snapshot().unwrap().0 == RuntimeHealthState::Ready
                        {
                            shutdown.store(true, Ordering::SeqCst);
                            break;
                        }
                        if Instant::now() >= deadline {
                            shutdown.store(true, Ordering::SeqCst);
                            panic!("initial READY was not published");
                        }
                        std::thread::yield_now();
                    }
                }))
            } else {
                None
            };
            let before = view.supervisor_snapshot().unwrap();
            let outcome = handle.supervise_until_shutdown(
                Duration::from_millis(1),
                if later_interval {
                    Duration::ZERO
                } else {
                    Duration::from_secs(60)
                },
            );
            if let Some(waiter) = shutdown_waiter {
                waiter.join().unwrap();
            }
            match expected {
                Expected::Repair => assert_eq!(
                    outcome,
                    SupervisionOutcome::RepairRequired {
                        reason,
                        install_result: result
                    }
                ),
                Expected::Fatal => assert_eq!(outcome, SupervisionOutcome::FatalControlPath),
                Expected::Shutdown => assert_eq!(outcome, SupervisionOutcome::ShutdownRequested),
            }
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                if later_interval { 2 } else { 1 }
            );
            let rows = handle
                .decision_engine()
                .wal_writer()
                .unwrap()
                .lock()
                .unwrap()
                .snapshot_after(None, 32)
                .unwrap()
                .into_iter()
                .filter(|entry| {
                    entry.event_canonical_json.contains("kernel_runtime_lost")
                        && entry.event_canonical_json.contains("recovery=")
                })
                .map(|entry| {
                    serde_json::from_str::<serde_json::Value>(&entry.event_canonical_json).unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                rows.len(),
                if matches!(expected, Expected::Repair) && !fail_audit {
                    1
                } else {
                    0
                }
            );
            if matches!(expected, Expected::Repair) && !fail_audit {
                assert!(rows[0]["detail"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("reason={reason:?}")));
                assert!(rows[0]["detail"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("recovery={result:?}")));
                assert_eq!(
                    rows[0]["safety_net"]["state"].as_str(),
                    Some(if result == R::InstallSucceeded {
                        "installed"
                    } else {
                        "install_failed"
                    })
                );
            }
            if !matches!(result, R::NoInstall | R::OwnedWallReady) {
                assert_eq!(
                    view.supervisor_snapshot().unwrap(),
                    if later_interval {
                        (
                            RuntimeHealthState::Recovering(reason),
                            Some(Tag::NotAttempted),
                        )
                    } else {
                        before
                    },
                    "terminal result must not publish a same-turn READY or synthetic health state"
                );
            }
            if later_interval {
                let status = handle.live_status.snapshot();
                assert_eq!(
                    status.lifecycle_state,
                    if matches!(result, R::NoInstall | R::OwnedWallReady) {
                        "running"
                    } else {
                        "degraded"
                    }
                );
            }
            assert!(
                !handle.is_fatal_control_path_requested()
                    || matches!(
                        side_effect,
                        AttemptSideEffect::Fatal | AttemptSideEffect::FatalAndShutdown
                    )
            );
            let _ = handle.stop();
        }
    }

    /// U3 (LINUX-STOP-LOSS-RACE-01): shutdown already set BEFORE the loop even
    /// starts (site 1, the initial pre-loop call), with a proven Lost
    /// component. The daemon must still take the C2a1(b) RepairRequired
    /// precedence: install once and leave a recovery WAL row, never report a
    /// bare `ShutdownRequested` (exit 0) while the loss is unresolved. Fails
    /// on dd2e5b06 (pre-fix: shutdown wins outright, no install, no WAL row).
    #[test]
    fn u3_shutdown_set_before_loop_top_with_lost_component_repairs() {
        use crate::enforcement::PostReadyRecoveryResult as R;
        use crate::enforcement::{ComponentHealth, ComponentKind, NotReadyReason};

        let dir = TempDir::new().unwrap();
        let (config, _) = fresh_config_in(&dir);
        let mut handle = boot(config).unwrap();
        let attempts = install_initial_attempt_fixture(
            &mut handle,
            R::InstallSucceeded,
            ComponentHealth::Recovering,
            AttemptSideEffect::None,
            false,
        );
        // Shutdown is requested before supervision even begins its first poll.
        handle.request_stop();

        let outcome =
            handle.supervise_until_shutdown(Duration::from_millis(1), Duration::from_secs(60));

        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        assert_eq!(
            outcome,
            SupervisionOutcome::RepairRequired {
                reason,
                install_result: R::InstallSucceeded,
            },
            "a shutdown set before the loop must not exit clean while a proven loss is unresolved"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "exactly one install attempt, even though shutdown was already requested"
        );

        let rows = handle
            .decision_engine()
            .wal_writer()
            .unwrap()
            .lock()
            .unwrap()
            .snapshot_after(None, 32)
            .unwrap()
            .into_iter()
            .filter(|entry| {
                entry.event_canonical_json.contains("kernel_runtime_lost")
                    && entry.event_canonical_json.contains("recovery=")
            })
            .count();
        assert_eq!(rows, 1, "the recovery attempt must leave a WAL row");

        let _ = handle.stop();
    }

    #[test]
    fn contended_prior_installed_tag_waits_then_records_one_unverified_row() {
        use crate::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult};
        use crate::nftables::{SafetyNetAuditState as Tag, SafetyNetSources};
        use std::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let (config, _) = fresh_config_in(&dir);
        let handle = boot(config).unwrap();
        let view = Arc::clone(handle.runtime_health_view());
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let recovering = RuntimeHealthState::Recovering(reason);
        let installed = Tag::Installed {
            shape: "v1-host-wide",
            reason: "unknown-history",
            deny_set_size: 0,
            deny_set_max: 1,
            rules: vec![],
            denied_uids: vec![],
            sources: SafetyNetSources {
                journal: false,
                manifest: false,
                live_table: false,
            },
            kernel_nd_accepted: vec![],
            unattestable_packets: "drop-except-kernel-nd",
            coverage: "inet output hook",
        };
        view.publish(recovering);
        view.publish_safety_net(installed);

        let held = view.hold_safety_net_for_test();
        let (started_tx, started_rx) = mpsc::channel();
        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let reader = std::thread::spawn({
            let view = Arc::clone(&view);
            move || {
                started_tx.send(()).unwrap();
                snapshot_tx.send(view.supervisor_snapshot()).unwrap();
            }
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            snapshot_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        let (prior_health, prior) = snapshot_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(prior_health, recovering);
        assert_eq!(prior.as_ref().map(Tag::tag), Some("installed"));

        let current = Tag::Unverified;
        let first = recovery_row_actions(
            recovering,
            prior.as_ref(),
            Some(&current),
            PostReadyRecoveryResult::NoInstall,
        );
        assert_eq!(first, (false, true, false));
        view.publish_safety_net(current.clone());
        if first.1 {
            handle.append_runtime_loss_row(reason, None, Some(current.clone()));
        }
        let (_, next_prior) = view.supervisor_snapshot().unwrap();
        let second = recovery_row_actions(
            recovering,
            next_prior.as_ref(),
            Some(&current),
            PostReadyRecoveryResult::NoInstall,
        );
        assert_eq!(second, (false, false, false));
        if second.1 {
            handle.append_runtime_loss_row(reason, None, Some(current));
        }

        let engine = handle.decision_engine();
        let wal = engine.wal_writer().unwrap();
        let rows: Vec<serde_json::Value> = wal
            .lock()
            .unwrap()
            .snapshot_after(None, 32)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.event_canonical_json.contains("kernel_runtime_lost"))
            .map(|entry| serde_json::from_str(&entry.event_canonical_json).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["safety_net"]["state"], "unverified");
    }

    #[test]
    fn contended_prior_health_waits_and_does_not_duplicate_unchanged_throttle_row() {
        use crate::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult};
        use crate::nftables::SafetyNetAuditState as Tag;
        use std::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let (config, _) = fresh_config_in(&dir);
        let handle = boot(config).unwrap();
        let view = Arc::clone(handle.runtime_health_view());
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let recovering = RuntimeHealthState::Recovering(reason);
        view.publish(recovering);
        view.publish_safety_net(Tag::Unverified);

        let held = view.hold_health_for_test();
        let (started_tx, started_rx) = mpsc::channel();
        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let reader = std::thread::spawn({
            let view = Arc::clone(&view);
            move || {
                started_tx.send(()).unwrap();
                snapshot_tx.send(view.supervisor_snapshot()).unwrap();
            }
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            snapshot_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        let (prior_health, prior_tag) = snapshot_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(prior_health, recovering);
        assert_eq!(prior_tag, Some(Tag::Unverified));
        let actions = recovery_row_actions(
            prior_health,
            prior_tag.as_ref(),
            Some(&Tag::Unverified),
            PostReadyRecoveryResult::NoInstall,
        );
        assert_eq!(actions, (false, false, false));
        let engine = handle.decision_engine();
        let wal = engine.wal_writer().unwrap();
        let rows = wal.lock().unwrap().snapshot_after(None, 32).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|entry| entry.event_canonical_json.contains("kernel_runtime_lost"))
                .count(),
            0
        );
    }

    #[test]
    fn stale_published_recovering_is_history_not_a_new_loss_and_repairs_ready_status() {
        use crate::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult};
        use crate::nftables::SafetyNetAuditState as Tag;

        let dir = TempDir::new().unwrap();
        let (config, _) = fresh_config_in(&dir);
        let handle = boot(config).unwrap();
        let view = handle.runtime_health_view();
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let recovering = RuntimeHealthState::Recovering(reason);
        view.publish(recovering);
        view.publish_safety_net(Tag::Unverified);
        *view.hold_health_for_test() = Some((
            Instant::now()
                - crate::runtime_health::STATUS_FRESHNESS_WINDOW
                - Duration::from_secs(1),
            recovering,
        ));
        assert_eq!(
            view.read(crate::runtime_health::STATUS_FRESHNESS_WINDOW)
                .state,
            RuntimeHealthState::ProbeUnavailable
        );
        let (prior_health, prior_tag) = view.supervisor_snapshot().unwrap();
        assert_eq!(prior_health, recovering);
        assert_eq!(prior_tag, Some(Tag::Unverified));
        assert_eq!(
            recovery_row_actions(
                prior_health,
                prior_tag.as_ref(),
                Some(&Tag::Unverified),
                PostReadyRecoveryResult::NoInstall,
            ),
            (false, false, false),
            "an unchanged throttle does not create an initial WAL row after a pause"
        );

        handle
            .live_status
            .update(LifecyclePhase::Degraded, DaemonRuntimeState::Degraded);
        handle.reconcile_recovered_live_status(prior_health, RuntimeHealthState::Ready);
        let repaired = handle.live_status.snapshot();
        assert_eq!(repaired.lifecycle_state, "running");
        assert_eq!(repaired.runtime_state, "kernel_runtime_ready");
    }

    #[test]
    fn poisoned_prior_field_stops_supervision_without_inventing_absence() {
        for poison_health in [false, true] {
            let dir = TempDir::new().unwrap();
            let (config, _) = fresh_config_in(&dir);
            let handle = boot(config).unwrap();
            let view = Arc::clone(handle.runtime_health_view());
            assert!(std::thread::spawn(move || {
                if poison_health {
                    let _held = view.hold_health_for_test();
                    panic!("poison the test health mutex");
                } else {
                    let _held = view.hold_safety_net_for_test();
                    panic!("poison the test tag mutex");
                }
            })
            .join()
            .is_err());
            assert_eq!(
                handle.supervise_until_shutdown(Duration::ZERO, Duration::ZERO),
                SupervisionOutcome::FatalControlPath
            );
        }
    }

    fn write_pinned_key(dir: &TempDir, signing: &SigningKey) -> PathBuf {
        let path = dir.path().join("pinned.key");
        fs::write(&path, signing.verifying_key().to_bytes()).unwrap();
        path
    }

    fn fresh_config_in(dir: &TempDir) -> (DaemonConfig, SigningKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let pinned = write_pinned_key(dir, &signing);
        let config = DaemonConfig {
            fortress_id: "deadbeef".to_string(),
            socket_path: dir.path().join("filter.sock"),
            policy_dir: dir.path().to_path_buf(),
            wal_path: dir.path().join("wal.jsonl"),
            pinned_public_key_path: pinned,
            producer_key_path: dir.path().join("audit-producer.key"),
            producer_pub_key_path: dir.path().join("audit-producer.pub"),
            prompt_timeout: Duration::from_secs(30),
            no_wall_max_duration: Duration::from_secs(3600),
            wal_ttl: Duration::from_secs(86_400),
            wal_size_cap_bytes: 16 * 1024 * 1024,
            trusted_service_uid: Some(unsafe { libc::geteuid() }),
            // ISOLATION (AGENTS.md, "the operator's machine is not a fixture"):
            // these unit tests drive the REAL `boot()`, whose Linux activation
            // path takes the host lock and writes the ownership journal + its MAC
            // key. Pointing them at the per-test temp dir is what stops a
            // `cargo test` on a Linux host from mutating operator-owned state.
            linux_runtime_paths: crate::config::LinuxRuntimePaths::isolated_under(dir.path()),
            #[cfg(feature = "test-isolation")]
            test_boot_time_shutdown_requested: false,
        };
        (config, signing)
    }

    #[test]
    fn boot_installs_handlers_and_emits_started_event() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        // Boot emitted the daemon_started event before returning.
        let buffer = handle.audit_buffer.lock().unwrap();
        assert_eq!(buffer.len(), 1);
        let event = buffer.iter().next().unwrap();
        assert!(event.event_canonical_json.contains("\"daemon_started\""));
        assert!(event.event_canonical_json.contains("\"l1\""));
        drop(buffer);
        let report = handle.stop().expect("stop");
        assert!(report.uptime > Duration::ZERO);
    }

    #[test]
    fn composition_root_shares_one_decision_engine_and_manifest_store() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        let ipc = handle.ipc_server.as_ref().expect("IPC server is live");
        assert!(
            Arc::ptr_eq(ipc.decision_engine(), &handle.decision_engine),
            "IPC and evaluation must share the exact DecisionEngine Arc"
        );
        let handle_store = handle.manifest_store().expect("store wired");
        let engine_store = handle
            .decision_engine
            .manifest_store()
            .expect("decision engine store wired");
        assert!(
            Arc::ptr_eq(handle_store, engine_store),
            "watcher/evaluation/IPC must reach the exact same ManifestStore Arc"
        );
        handle.stop().expect("stop");
    }

    #[test]
    fn boot_reports_control_plane_only_until_kernel_runtime_is_owned() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");

        assert_eq!(handle.runtime_state(), DaemonRuntimeState::ControlPlaneOnly);
        assert!(
            !handle.is_enforcing(),
            "IPC and policy liveness must never be presented as kernel enforcement"
        );

        handle.stop().expect("stop");
    }

    #[test]
    fn runtime_state_reports_kernel_runtime_ready_but_never_enforcing() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");

        // Baseline: no runtime owned -> control plane only, never enforcing.
        assert_eq!(handle.runtime_state(), DaemonRuntimeState::ControlPlaneOnly);
        assert!(!handle.is_enforcing());

        // Attach a fully-ready runtime: the derived state is KernelRuntimeReady,
        // NOT Enforcing. This slice wraps no agent, so a live kernel runtime is
        // ready-but-idle; is_enforcing() must stay false.
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());
        assert_eq!(
            handle.runtime_state(),
            DaemonRuntimeState::KernelRuntimeReady
        );
        assert!(
            !handle.is_enforcing(),
            "a ready kernel runtime with no wrapped agent must never read as enforcing"
        );

        // stop() tears the runtime down and reports Stopping.
        handle.stop().expect("stop");
    }

    /// What [`observe_ipc_liveness_at_enforcement_release`] captured. `_dir`
    /// keeps the temp directory alive for the caller's post-teardown
    /// socket-unlink assertion, so that assertion observes the daemon's unlink
    /// rather than the temp dir's own cleanup.
    struct ReleaseObservation {
        /// The IPC-owned accept-loop stop flag at the instant enforcement was
        /// released. `false` proves the control surface was still live.
        ipc_stopped_at_release: bool,
        /// Whether the IPC socket file existed at that same instant.
        socket_present_at_release: bool,
        /// A clone of the IPC stop flag, so the caller can assert it becomes
        /// `true` after teardown completes.
        ipc_stop_flag: Arc<AtomicBool>,
        socket_path: PathBuf,
        _dir: TempDir,
    }

    /// Boot a daemon, attach an all-ready enforcement runtime whose FIRST
    /// released component (the very start of enforcement teardown) runs a probe
    /// recording the IPC stop flag + socket existence at that instant, then run
    /// the supplied `teardown` (explicit `stop()` or implicit `Drop`). Shared by
    /// the stop() and Drop tests so the enforcement-before-IPC invariant is
    /// proven identically on BOTH routes through `teardown`.
    fn observe_ipc_liveness_at_enforcement_release(
        teardown: impl FnOnce(DaemonHandle),
    ) -> ReleaseObservation {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let socket_path = config.socket_path.clone();
        let mut handle = boot(config).expect("boot");
        assert!(socket_path.exists(), "IPC socket is bound after boot");

        let ipc_stop_flag = handle.ipc_stop_flag_for_test();
        assert!(
            !ipc_stop_flag.load(Ordering::SeqCst),
            "IPC stop flag is false while the daemon runs"
        );

        // The probe records IPC liveness (accept-loop stop flag still false)
        // and socket existence at the instant enforcement is released.
        let observed = Arc::new(Mutex::new(None::<(bool, bool)>));
        let cell = Arc::clone(&observed);
        let probe_flag = Arc::clone(&ipc_stop_flag);
        let probe_socket = socket_path.clone();
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_with_release_probe(
            Box::new(move || {
                *cell.lock().unwrap() =
                    Some((probe_flag.load(Ordering::SeqCst), probe_socket.exists()));
            }),
        ));

        teardown(handle);
        let (ipc_stopped_at_release, socket_present_at_release) = observed
            .lock()
            .unwrap()
            .expect("probe ran during enforcement release");
        ReleaseObservation {
            ipc_stopped_at_release,
            socket_present_at_release,
            ipc_stop_flag,
            socket_path,
            _dir: dir,
        }
    }

    #[test]
    fn drop_without_stop_tears_down_enforcement_before_ipc() {
        // The implicit Drop path must honor the enforcement-before-IPC ordering.
        // Rust would otherwise drop `ipc_server` (declared before `enforcement`)
        // first. The load-bearing assertion is the IPC-owned accept-loop stop
        // flag: at the instant enforcement releases it must still be `false`, so
        // the control surface the verdict thread reports to was provably live
        // throughout enforcement teardown. Socket existence is checked too but
        // is only corroborating — a lingering socket file could outlive a
        // stopped server, so socket existence ALONE is insufficient.
        let obs = observe_ipc_liveness_at_enforcement_release(drop);

        assert!(
            !obs.ipc_stopped_at_release,
            "IPC server must still be live (stop flag false) when enforcement releases"
        );
        assert!(
            obs.socket_present_at_release,
            "IPC socket must still exist when enforcement releases (corroborating)"
        );
        // After teardown the IPC server was stopped (flag set) and unlinked its
        // socket — proving IPC teardown ran, AFTER enforcement.
        assert!(
            obs.ipc_stop_flag.load(Ordering::SeqCst),
            "IPC stop flag must be set after teardown"
        );
        assert!(
            !obs.socket_path.exists(),
            "IPC teardown (socket unlink) must have run during Drop"
        );
    }

    #[test]
    fn explicit_stop_tears_down_enforcement_before_ipc() {
        // Same control-surface-liveness invariant as the Drop test, via the
        // EXPLICIT stop() route. Both funnel through the shared teardown() path;
        // proving it on stop() AND Drop guards the invariant against drift at
        // either entry point.
        let obs = observe_ipc_liveness_at_enforcement_release(|handle| {
            handle.stop().expect("stop");
        });

        assert!(
            !obs.ipc_stopped_at_release,
            "IPC server must still be live (stop flag false) when enforcement releases under stop()"
        );
        assert!(
            obs.socket_present_at_release,
            "IPC socket must still exist when enforcement releases under stop() (corroborating)"
        );
        assert!(
            obs.ipc_stop_flag.load(Ordering::SeqCst),
            "IPC stop flag must be set after stop()"
        );
        assert!(
            !obs.socket_path.exists(),
            "IPC teardown (socket unlink) must have run during stop()"
        );
    }

    #[test]
    fn kernel_runtime_health_reports_no_runtime_without_one() {
        // A control-plane-only boot holds no kernel runtime, so health reports
        // NoRuntime: a control-plane boot must never be a false supervision
        // failure, and must never be reported as a loss either.
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        assert_eq!(handle.runtime_state(), DaemonRuntimeState::ControlPlaneOnly);
        assert_eq!(
            handle.kernel_runtime_health(),
            RuntimeHealthState::NoRuntime
        );
        assert_eq!(
            handle
                .runtime_health_view()
                .supervisor_snapshot()
                .unwrap()
                .0,
            RuntimeHealthState::NoRuntime,
            "boot publishes history before a supervisor can take its first snapshot"
        );
        // Supervision on such a daemon ends only on shutdown request, never a
        // spurious loss.
        handle.request_stop();
        assert_eq!(
            handle.supervise_until_shutdown(Duration::from_millis(1), Duration::ZERO),
            SupervisionOutcome::ShutdownRequested
        );
        assert_eq!(
            handle
                .runtime_health_view()
                .supervisor_snapshot()
                .unwrap()
                .0,
            RuntimeHealthState::NoRuntime
        );
        handle.stop().expect("stop");
    }

    #[test]
    fn health_detects_verdict_table_or_watcher_death_after_ready() {
        use crate::enforcement::{ComponentKind, NotReadyReason};
        // For EACH required component, a runtime that came up ready and then lost
        // that component must (a) report the loss through kernel_runtime_health,
        // (b) stop reading as KernelRuntimeReady, and (c) never read as Enforcing
        // — no false active service.
        for target in [
            ComponentKind::NftablesTable,   // table clobbered
            ComponentKind::Nfqueue,         // verdict thread died
            ComponentKind::ManifestWatcher, // watcher thread exited
        ] {
            let dir = TempDir::new().unwrap();
            let (config, _signing) = fresh_config_in(&dir);
            let mut handle = boot(config).expect("boot");
            let (runtime, toggle) = EnforcementRuntime::all_ready_with_toggleable(target);
            handle.set_enforcement_for_test(runtime);

            // Came up ready: healthy, KernelRuntimeReady, not enforcing.
            assert_eq!(handle.kernel_runtime_health(), RuntimeHealthState::Ready);
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            assert!(!handle.is_enforcing());

            // The component dies.
            toggle.store(false, Ordering::SeqCst);

            // Loss is detected and attributed to the right component.
            assert_eq!(
                handle.kernel_runtime_health(),
                RuntimeHealthState::Lost(NotReadyReason::ComponentLost(target)),
                "loss of {target:?} must surface as a PROVEN ComponentLost, never as \
                 an indeterminate probe reading"
            );
            // No false active service: the daemon is control-plane-only, never
            // Enforcing, once a required component is lost.
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::ControlPlaneOnly,
                "a lost {target:?} must drop the daemon to ControlPlaneOnly"
            );
            assert!(!handle.is_enforcing());

            handle.stop().expect("stop");
        }
    }

    #[test]
    fn supervise_durably_audits_each_kernel_runtime_loss_before_teardown() {
        use crate::enforcement::{ComponentKind, NotReadyReason};

        // Every post-ready capability loss must receive the same critical WAL
        // evidence before the caller begins teardown. health_interval 0 keeps
        // the deterministic fake check immediate.
        for target in [
            ComponentKind::NftablesTable,
            ComponentKind::Nfqueue,
            ComponentKind::ManifestWatcher,
        ] {
            let dir = TempDir::new().unwrap();
            let (config, _signing) = fresh_config_in(&dir);
            let mut handle = boot(config).expect("boot");
            let (runtime, toggle) = EnforcementRuntime::all_ready_with_toggleable(target);
            handle.set_enforcement_for_test(runtime);
            toggle.store(false, Ordering::SeqCst);

            let outcome = handle.supervise_until_shutdown(Duration::from_millis(1), Duration::ZERO);
            assert_eq!(
                outcome,
                SupervisionOutcome::KernelRuntimeLost(NotReadyReason::ComponentLost(target))
            );

            let engine = handle.decision_engine();
            let wal = engine.wal_writer().expect("boot wires the durable WAL");
            let entries = wal.lock().unwrap().snapshot_after(None, 20).unwrap();
            let loss = entries
                .iter()
                .find(|entry| entry.event_canonical_json.contains("kernel_runtime_lost"))
                .expect("runtime loss must be durably recorded before stop");
            assert!(loss.critical);
            assert!(loss
                .event_canonical_json
                .contains(&format!("ComponentLost({target:?})")));
            // ITEM 10, consumer two: the tagged `safety_net` state rides on the SAME row
            // as the loss reason, so a reader never infers the protection from the fact
            // that a loss happened. This fixture holds no nftables component that can
            // install one, so the honest value is `not_attempted` — and asserting that
            // is what proves the row does not claim an install it never made.
            let row: serde_json::Value =
                serde_json::from_str(&loss.event_canonical_json).expect("canonical WAL row");
            assert_eq!(row["safety_net"]["state"], "not_attempted");
            assert_eq!(row["detail"], format!("reason=ComponentLost({target:?})"));

            handle.stop().expect("stop");
        }
    }

    #[test]
    fn terminal_nft_indeterminate_runs_its_hook_before_supervision_exits() {
        use crate::enforcement::{ComponentHealth, ComponentKind, NotReadyReason};

        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");
        let (runtime, probe, hook_calls) = EnforcementRuntime::all_ready_with_indeterminate_probe();
        handle.set_enforcement_for_test(runtime);
        *probe.lock().unwrap() = ComponentHealth::Recovering;
        assert_eq!(
            handle.kernel_runtime_health(),
            RuntimeHealthState::Recovering(NotReadyReason::SafetyNetRecovering(
                ComponentKind::NftablesTable
            )),
            "a transient no-answer during recovery stays on the Recovering consumer path"
        );
        assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
        *probe.lock().unwrap() = ComponentHealth::Indeterminate;

        assert_eq!(
            handle.kernel_runtime_health(),
            RuntimeHealthState::Indeterminate,
            "terminal indeterminate overrides Recovering before the exit arm"
        );

        assert_eq!(
            handle.supervise_until_shutdown(Duration::ZERO, Duration::ZERO),
            SupervisionOutcome::KernelRuntimeLost(NotReadyReason::HealthProbeIndeterminate)
        );
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
        handle.stop().expect("stop");
    }

    #[test]
    fn a_recovery_audit_preserves_the_published_recovering_state() {
        use crate::enforcement::{ComponentKind, NotReadyReason};

        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        handle.record_runtime_loss(reason, true);
        assert_eq!(
            handle
                .runtime_health
                .read(crate::runtime_health::STATUS_FRESHNESS_WINDOW)
                .state,
            RuntimeHealthState::Recovering(reason)
        );
        handle.stop().expect("stop");
    }

    #[test]
    fn poisoned_wal_is_a_proven_runtime_loss_and_supervision_returns_bounded() {
        use crate::audit::WalFaultPoint;
        use crate::enforcement::NotReadyReason;

        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());
        let wal = handle
            .decision_engine()
            .wal_writer()
            .expect("boot wires WAL")
            .clone();
        let fault = wal.lock().unwrap().fault_injection_handle();
        *fault.lock().unwrap() = Some(WalFaultPoint::AppendSyncFailure);
        assert!(matches!(
            wal.lock()
                .unwrap()
                .append_critical("{\"operation\":\"poison\"}"),
            Err(crate::audit::WalError::Poisoned { .. })
        ));

        assert_eq!(
            handle.kernel_runtime_health(),
            RuntimeHealthState::Lost(NotReadyReason::AuditWalPoisoned)
        );
        let started = Instant::now();
        assert_eq!(
            handle.supervise_until_shutdown(Duration::ZERO, Duration::ZERO),
            SupervisionOutcome::KernelRuntimeLost(NotReadyReason::AuditWalPoisoned)
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "a poisoned WAL must not block the fail-stop route"
        );
        handle.stop().expect("stop");
    }

    #[test]
    fn supervisor_reaches_fail_stop_when_a_wal_owner_never_returns() {
        use crate::enforcement::NotReadyReason;

        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());
        let wal = handle
            .decision_engine()
            .wal_writer()
            .expect("boot wires WAL")
            .clone();
        let never_returning_owner = wal.lock().unwrap();

        let started = Instant::now();
        assert_eq!(
            handle.supervise_until_shutdown(Duration::ZERO, Duration::ZERO),
            SupervisionOutcome::KernelRuntimeLost(NotReadyReason::HealthProbeUnavailable)
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "supervision and failure reporting must not block on a stuck WAL owner"
        );
        handle
            .stop()
            .expect("ordered teardown must also complete while the stale WAL owner remains");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "fatal-loss supervision plus teardown must reach the nonzero-exit boundary"
        );
        drop(never_returning_owner);
    }

    #[test]
    fn supervise_returns_shutdown_requested_on_request_stop() {
        // A ready runtime that stays healthy: supervise ends only when a stop is
        // requested, and reports ShutdownRequested (the clean exit path).
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());
        handle.request_stop();
        assert_eq!(
            handle.supervise_until_shutdown(Duration::from_millis(1), Duration::ZERO),
            SupervisionOutcome::ShutdownRequested
        );
        handle.stop().expect("stop");
    }

    #[test]
    fn fatal_control_path_wins_over_simultaneous_ordinary_shutdown() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");

        // This is the exact pair the post-commit IPC withdrawal path publishes.
        // Fatal must be observed first even if both writes complete before the
        // supervisor is scheduled.
        handle.fatal_control_path.store(true, Ordering::SeqCst);
        handle.shutdown_flag.store(true, Ordering::SeqCst);
        assert_eq!(
            handle.supervise_until_shutdown(Duration::ZERO, Duration::ZERO),
            SupervisionOutcome::FatalControlPath
        );
        handle.stop().expect("ordered fatal teardown");
    }

    #[test]
    fn poisoned_state_lock_never_reads_as_enforcing() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");
        // Even with a fully-ready runtime attached, a poisoned lifecycle lock
        // must degrade rather than promote to Enforcing.
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());

        let state_lock = Arc::clone(&handle.runtime_state);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state_lock.lock().unwrap();
            panic!("poison the lifecycle lock");
        }));
        assert!(state_lock.is_poisoned(), "lock should be poisoned");

        // Derivation sees Degraded (poison fallback) and refuses to promote it.
        assert_ne!(handle.runtime_state(), DaemonRuntimeState::Enforcing);
        assert_eq!(handle.runtime_state(), DaemonRuntimeState::Degraded);
        assert!(!handle.is_enforcing());

        // The poisoned lock also blocks a clean stop()'s state write, but stop
        // must still tear down without panicking.
        let _ = handle.stop();
    }

    #[test]
    fn decision_engine_is_shareable_without_daemon_lifecycle_ownership() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        let engine = handle.decision_engine();

        let outcome = engine
            .evaluate_attempt(&req_for(Some("unlisted.example"), 443))
            .expect("evaluate through shared engine");
        assert!(matches!(
            outcome.verdict,
            Verdict::Deny {
                reason: DeniedReason::DefaultDeny
            }
        ));

        drop(engine);
        handle.stop().expect("stop");
    }

    #[test]
    fn boot_refuses_with_missing_pinned_key() {
        use crate::failure::default_disposition;
        let dir = TempDir::new().unwrap();
        let (mut config, _signing) = fresh_config_in(&dir);
        config.pinned_public_key_path = dir.path().join("does-not-exist");
        let err = match boot(config) {
            Ok(_handle) => panic!("boot should have refused with missing pinned key"),
            Err(err) => err,
        };
        assert!(matches!(err, DaemonError::PinnedKeyLoad(_)));
        let mode = mode_for_error(&err);
        assert!(matches!(
            default_disposition(mode),
            FailureDisposition::RefuseToStart { .. }
        ));
    }

    #[test]
    fn refuse_to_start_message_renders_known_keys() {
        let f1 = FailureDisposition::RefuseToStart {
            operator_message_key: "F-1",
        };
        let msg = refuse_to_start_message(&f1, "nft missing");
        assert!(msg.contains("F-1"));
        assert!(msg.contains("nftables"));
        assert!(msg.contains("nft missing"));

        let f4 = FailureDisposition::RefuseToStart {
            operator_message_key: "F-4",
        };
        let msg = refuse_to_start_message(&f4, "bad sig");
        assert!(msg.contains("F-4"));
        assert!(msg.contains("allowlist"));
        assert!(msg.contains("bad sig"));
    }

    // ----- kernel-runtime activation fail-before classification --------------
    //
    // These are DETERMINISTIC and platform-independent: on the dev host a real
    // acquisition never fails-for-real (the providers return
    // NotAvailableOnPlatform), so the fail-before decision is proven by driving
    // the pure `classify_activation` over constructed `EnforcementStartError`s.
    // The end-to-end Linux boot fail-before is proven by
    // `tests/integration_linux_runtime_activation.rs`.

    #[test]
    fn classify_activation_treats_no_kernel_adapter_as_nonfatal() {
        use crate::enforcement::{ComponentKind, EnforcementError, EnforcementStartError};
        // The single non-fatal miss: a host with no kernel adapter (macOS dev,
        // non-Linux CI). Must classify as UnsupportedPlatform so the daemon
        // stays control-plane-only WITHOUT pretending enforcement is available.
        let err = EnforcementStartError::Component {
            failed: ComponentKind::NftablesTable,
            evidence: None,
            reason: EnforcementError::NotAvailableOnPlatform(ComponentKind::NftablesTable.as_str()),
        };
        assert!(matches!(
            classify_activation(Err(err)),
            KernelRuntimeActivation::UnsupportedPlatform
        ));
    }

    #[test]
    fn classify_activation_treats_real_acquisition_failures_as_fatal() {
        use crate::enforcement::{ComponentKind, EnforcementError, EnforcementStartError};
        // Every genuine acquisition/readiness failure on a platform that SHOULD
        // enforce must be FATAL — a foreign pre-existing table, a host-lock
        // conflict, an nft verify failure, an NFQUEUE/watcher bind failure — so
        // the daemon fails-before instead of running live-but-non-enforcing.
        let fatal_reasons = [
            EnforcementError::AcquireFailed {
                kind: ComponentKind::NftablesTable.as_str(),
                detail: "a sanctuary-castle nftables table already exists".to_string(),
            },
            EnforcementError::AcquireFailed {
                kind: ComponentKind::Nfqueue.as_str(),
                detail: "NFQUEUE bind failed".to_string(),
            },
            EnforcementError::NotReadyAfterAcquire(ComponentKind::ManifestWatcher.as_str()),
            EnforcementError::ComponentKindMismatch {
                expected: ComponentKind::Nfqueue.as_str(),
                actual: ComponentKind::NftablesTable.as_str(),
            },
        ];
        for reason in fatal_reasons {
            let err = EnforcementStartError::Component {
                failed: ComponentKind::NftablesTable,
                evidence: None,
                reason,
            };
            assert!(
                matches!(
                    classify_activation(Err(err)),
                    KernelRuntimeActivation::Failed(_)
                ),
                "a real acquisition/readiness failure on a supported platform must be fatal"
            );
        }
        // A plan-shape mismatch (never on the happy path) is a fatal defect too.
        let mismatch = EnforcementStartError::PlanMismatch {
            expected: ComponentKind::REQUIRED_IN_ORDER.to_vec(),
            actual: vec![],
        };
        assert!(matches!(
            classify_activation(Err(mismatch)),
            KernelRuntimeActivation::Failed(_)
        ));
    }

    #[test]
    fn classify_activation_passes_a_ready_runtime_through() {
        // A fully-ready runtime classifies as Activated and stays ready.
        match classify_activation(Ok(EnforcementRuntime::all_ready_for_test())) {
            KernelRuntimeActivation::Activated(runtime) => {
                assert!(runtime.is_kernel_runtime_ready());
            }
            other => panic!("expected Activated, got {other:?}"),
        }
    }

    // ----- readiness delivery: fatal on a configured-socket send failure -----

    #[test]
    fn deliver_readiness_is_fatal_when_a_configured_socket_send_fails() {
        // Runtime ready + a CONFIGURED NOTIFY_SOCKET whose send fails (path has no
        // bound listener) must NOT leave a false-started process: fail closed so
        // main exits nonzero and systemd restarts.
        let dir = TempDir::new().unwrap();
        let unbound = dir.path().join("no-listener.sock");
        let mut beacon = crate::systemd_notify::ReadyBeacon::for_socket(Some(unbound));
        let out = deliver_readiness(true, true, &mut beacon);
        assert!(
            matches!(out, Err(DaemonError::ReadinessNotify(_))),
            "a failed READY=1 send to a configured socket must be a fatal boot error, got {out:?}"
        );
    }

    #[test]
    fn deliver_readiness_is_ok_when_ready_with_no_supervisor() {
        // Ready runtime, no NOTIFY_SOCKET: signaling is a silent success (there is
        // no supervisor to tell), never an error.
        let mut beacon = crate::systemd_notify::ReadyBeacon::for_socket(None);
        assert!(deliver_readiness(true, false, &mut beacon).is_ok());
    }

    #[test]
    fn deliver_readiness_withholds_but_does_not_fail_when_not_ready_under_supervisor() {
        // Not-ready runtime under a supervisor: withhold READY=1 (honest) but do
        // NOT fail — systemd applies its own restart policy on the missing signal.
        // (Supported Linux fails-before earlier; this is the non-Linux path.)
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("notify.sock");
        let _listener = std::os::unix::net::UnixDatagram::bind(&sock).unwrap();
        let mut beacon = crate::systemd_notify::ReadyBeacon::for_socket(Some(sock));
        assert!(deliver_readiness(false, true, &mut beacon).is_ok());
    }

    #[test]
    fn present_runtime_that_loses_readiness_before_notify_is_fatal() {
        let mut runtime = EnforcementRuntime::all_ready_for_test();
        runtime.shutdown();
        let out = signal_systemd_readiness(Some(&runtime));
        assert!(
            matches!(out, Err(DaemonError::KernelRuntimeActivation(_))),
            "a present runtime lost before READY=1 must fail boot, got {out:?}"
        );
    }

    #[test]
    fn stop_drains_buffer_overflow_count() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        // Force overflow by appending a large event with a tiny cap.
        {
            let mut buf = handle.audit_buffer.lock().unwrap();
            buf.append(crate::audit::PendingAuditEvent {
                event_canonical_json: "x".repeat(1024),
                captured_at: std::time::SystemTime::now(),
                // Test-only synthetic event; classify as metric so it
                // exercises the standard overflow path.
                critical: false,
            });
        }
        let report = handle.stop().expect("stop");
        assert!(report.audit_remaining >= 1);
    }

    // ----- evaluate_attempt path: F-1 deny-by-default, allow-list match,
    // ----- per-attempt audit emission via WalWriter ------------------------

    use crate::manifest::canonical_json::canonicalize_to_bytes;
    use crate::manifest::verify::{
        AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
    };
    use crate::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut s = String::with_capacity(out.len() * 2);
        for b in out.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Write a signed manifest containing a single rule with `disposition`
    /// targeting a deterministic test IP on port 443 over tcp. Used by the
    /// evaluate_attempt tests below.
    fn write_single_rule_policy(
        policy_dir: &std::path::Path,
        signing: &SigningKey,
        rule_id: &str,
        host: &str,
        disposition: &str,
    ) {
        fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
        let dest_ip = if host == "pastebin.com" {
            "203.0.113.11"
        } else {
            "203.0.113.10"
        };
        let body = format!(
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{\"ip\":[\"{dest_ip}\"],\"port\":[443],\"protocol\":\"tcp\"}},\"disposition\":\"{disposition}\"}}"
        );
        let body_bytes = body.into_bytes();
        let file = format!("{rule_id}.json");
        fs::write(policy_dir.join(RULES_SUBDIR).join(&file), &body_bytes).unwrap();
        // Every composed manifest must carry the genuine habeas local lane
        // (always-on-lane gate); include it so the snapshot builds.
        let habeas_bytes = crate::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes().to_vec();
        let habeas_file = format!("{}.json", crate::habeas::HABEAS_LOCAL_RULE_ID);
        fs::write(
            policy_dir.join(RULES_SUBDIR).join(&habeas_file),
            &habeas_bytes,
        )
        .unwrap();
        let manifest = AllowlistManifest {
            schema_version: 1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            generation: 1,
            agent_origin: None,
            operator_baseline: None,
            rules: vec![
                ManifestRuleEntry {
                    rule_id: rule_id.to_string(),
                    file,
                    sha256: sha256_hex(&body_bytes),
                },
                ManifestRuleEntry {
                    rule_id: crate::habeas::HABEAS_LOCAL_RULE_ID.to_string(),
                    file: habeas_file,
                    sha256: sha256_hex(&habeas_bytes),
                },
            ],
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let sig = signing.sign(&canonical);
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: "ed25519-v1".to_string(),
                signing_key_id: castle_wall_signing_key_id(&signing.verifying_key().to_bytes())
                    .unwrap(),
                signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sig.to_bytes()),
            },
        };
        let serialized = serde_json::to_string_pretty(&signed).unwrap();
        fs::write(policy_dir.join(MANIFEST_FILENAME), serialized).unwrap();
    }

    fn boot_with_single_rule(
        rule_id: &str,
        host: &str,
        disposition: &str,
    ) -> (DaemonHandle, TempDir) {
        let dir = TempDir::new().unwrap();
        let (config, signing) = fresh_config_in(&dir);
        write_single_rule_policy(&config.policy_dir, &signing, rule_id, host, disposition);
        let handle = boot(config).expect("boot");
        (handle, dir)
    }

    fn req_for(host: Option<&str>, port: u16) -> EvaluationRequest {
        EvaluationRequest {
            agent_id: "agent-1".to_string(),
            agent_template: "claude-code".to_string(),
            dest_host: host.map(|h| h.to_string()),
            dest_ip: Some(if host == Some("pastebin.com") {
                "203.0.113.11".to_string()
            } else {
                "203.0.113.10".to_string()
            }),
            dest_port: port,
            dest_protocol: "tcp".to_string(),
            opaque: host.is_none(),
        }
    }

    #[test]
    fn evaluate_attempt_default_denies_when_no_snapshot_loaded() {
        // No manifest on disk; ManifestStore::current_snapshot() = None;
        // F-1 deny-by-default invariant.
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");
        let outcome = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate");
        assert!(matches!(
            outcome.verdict,
            Verdict::Deny {
                reason: crate::policy::DeniedReason::DefaultDeny
            }
        ));
        // The audit body matches the canonical egress_blocked + default_deny shape.
        assert!(outcome.event_canonical_json.contains("\"egress_blocked\""));
        assert!(outcome.event_canonical_json.contains("\"default_deny\""));
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_allow_path_emits_egress_approved_audit() {
        let (handle, _dir) =
            boot_with_single_rule("rule-allow-anthropic", "api.anthropic.com", "allow");
        let outcome = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate");
        match &outcome.verdict {
            Verdict::Allow { rule_id } => assert_eq!(rule_id, "rule-allow-anthropic"),
            other => panic!("expected Allow verdict; got {:?}", other),
        }
        // The WAL seq monotonically increases past the daemon_started seq=0.
        assert!(outcome.wal_seq.expect("wal_seq present on success") >= 1);
        assert!(outcome.event_canonical_json.contains("\"egress_approved\""));
        assert!(outcome
            .event_canonical_json
            .contains("\"rule-allow-anthropic\""));
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_default_deny_path_emits_egress_blocked_audit() {
        // Allow rule for api.anthropic.com; attempt against a different host
        // hits default-deny.
        let (handle, _dir) =
            boot_with_single_rule("rule-allow-anthropic", "api.anthropic.com", "allow");
        let outcome = handle
            .evaluate_attempt(&req_for(Some("pastebin.com"), 443))
            .expect("evaluate");
        assert!(matches!(
            outcome.verdict,
            Verdict::Deny {
                reason: crate::policy::DeniedReason::DefaultDeny
            }
        ));
        assert!(outcome.event_canonical_json.contains("\"egress_blocked\""));
        assert!(outcome.event_canonical_json.contains("\"default_deny\""));
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_explicit_deny_rule_emits_blocked_with_static_rule_provenance() {
        let (handle, _dir) = boot_with_single_rule("rule-deny-pastebin", "pastebin.com", "deny");
        let outcome = handle
            .evaluate_attempt(&req_for(Some("pastebin.com"), 443))
            .expect("evaluate");
        match &outcome.verdict {
            Verdict::Deny {
                reason: crate::policy::DeniedReason::ExplicitRule { rule_id },
            } => assert_eq!(rule_id, "rule-deny-pastebin"),
            other => panic!("expected explicit deny; got {:?}", other),
        }
        assert!(outcome.event_canonical_json.contains("\"egress_blocked\""));
        assert!(outcome.event_canonical_json.contains("\"static_rule\""));
        assert!(outcome
            .event_canonical_json
            .contains("\"rule-deny-pastebin\""));
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_writes_durable_wal_seq_visible_through_handle() {
        let (handle, _dir) = boot_with_single_rule("rule-allow", "api.anthropic.com", "allow");
        let first = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate");
        let second = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate");
        // Each evaluation produces a distinct WAL seq, in order.
        let first_seq = first.wal_seq.expect("first wal_seq present on success");
        let second_seq = second.wal_seq.expect("second wal_seq present on success");
        assert!(second_seq > first_seq);
        // Mirror appears in the in-memory ring too (one daemon_started + two
        // evaluation events = at least 3 entries).
        let ring = handle.audit_buffer.lock().unwrap();
        assert!(ring.len() >= 3);
        drop(ring);
        // Drain via the WAL handle directly to confirm the events landed in
        // the durable tier.
        let wal = handle.wal_writer().expect("wal wired");
        let mut wal_guard = wal.lock().unwrap();
        let snapshot = wal_guard.snapshot_after(None, 100).expect("snapshot");
        let bodies: Vec<String> = snapshot
            .iter()
            .map(|e| e.event_canonical_json.clone())
            .collect();
        let approved_count = bodies
            .iter()
            .filter(|b| b.contains("\"egress_approved\""))
            .count();
        assert!(approved_count >= 2);
        drop(wal_guard);
        let _ = handle.stop();
    }

    // ----- RuntimeAuditWalAppendFailed real-injection coverage --------------
    //
    // Closes the v1.x housekeeping (2) gap: the failure-mode dispatch table
    // was already covered at the unit tier (failure.rs) and the integration
    // tier (integration_failure_modes.rs:audit_wal_append_failure_dispatch_is_fail_closed),
    // but no test exercised the end-to-end path through evaluate_attempt
    // when the WAL really fails. The companion injection seam at
    // `audit::WalWriter::injection_handle` bypasses the file write and
    // synthesizes a `WalError::Io` shape byte-for-byte indistinguishable
    // from a real OS-side error from the daemon evaluator's perspective.

    #[test]
    fn evaluate_attempt_fails_closed_when_wal_append_errors() {
        // Allow rule for api.anthropic.com so the unforced verdict would be
        // Allow. With WAL append injected to fail, the dispatch must
        // override that verdict to FailClosed (Deny + audit_wal_append_failed)
        // per scope-lock section 7 / section 8.
        let (handle, _dir) =
            boot_with_single_rule("rule-allow-anthropic", "api.anthropic.com", "allow");

        // Snapshot ring-buffer baseline (boot path persisted daemon_started).
        let baseline_ring_len = handle.audit_buffer.lock().unwrap().len();

        // Snapshot WAL baseline so we can confirm no new entry landed on disk.
        let wal_arc = handle.wal_writer().expect("wal wired").clone();
        let baseline_wal_count = {
            let mut guard = wal_arc.lock().unwrap();
            guard
                .snapshot_after(None, 1024)
                .expect("baseline snapshot")
                .len()
        };
        let baseline_next_seq = wal_arc.lock().unwrap().next_seq();
        let baseline_chain = wal_arc
            .lock()
            .unwrap()
            .last_chain_hash_hex()
            .map(|s| s.to_string());

        // Arm the injection: the next append_critical inside evaluate_attempt
        // will short-circuit with a synthesized WalError::Io.
        let injection = wal_arc.lock().unwrap().injection_handle();
        injection.store(true, std::sync::atomic::Ordering::SeqCst);

        let outcome = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate_attempt must Ok-with-fail-closed, not propagate Err");

        // Disarm so the daemon can shut down cleanly.
        injection.store(false, std::sync::atomic::Ordering::SeqCst);

        // 1) Verdict is the synthesized fail-closed shape, NOT the original Allow.
        match &outcome.verdict {
            Verdict::Deny {
                reason: DeniedReason::AuditWalAppendFailed,
            } => {}
            other => panic!("expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"),
        }

        // 2) wal_seq is None: no durable record landed.
        assert!(
            outcome.wal_seq.is_none(),
            "wal_seq must be None on fail-closed dispatch; got {:?}",
            outcome.wal_seq
        );

        // 3) Audit body reflects the fail-closed shape (egress_blocked +
        //    audit_wal_append_failed provenance), NOT the original
        //    egress_approved that would have been emitted on the Allow path.
        assert!(
            outcome.event_canonical_json.contains("\"egress_blocked\""),
            "fail-closed audit body must contain egress_blocked; got {}",
            outcome.event_canonical_json
        );
        assert!(
            outcome
                .event_canonical_json
                .contains("\"audit_wal_append_failed\""),
            "fail-closed audit body must contain audit_wal_append_failed provenance; got {}",
            outcome.event_canonical_json
        );
        assert!(
            !outcome.event_canonical_json.contains("\"egress_approved\""),
            "fail-closed audit body must NOT contain egress_approved; got {}",
            outcome.event_canonical_json
        );

        // 4) The in-memory ring buffer absorbed the fail-closed event.
        let ring_after = handle.audit_buffer.lock().unwrap();
        assert_eq!(
            ring_after.len(),
            baseline_ring_len + 1,
            "ring buffer should have grown by exactly one (the fail-closed mirror)"
        );
        let mirrored = ring_after
            .iter()
            .last()
            .expect("ring has at least one entry")
            .event_canonical_json
            .clone();
        assert!(mirrored.contains("\"egress_blocked\""));
        assert!(mirrored.contains("\"audit_wal_append_failed\""));
        drop(ring_after);

        // 5) WAL state is unchanged: no entry persisted, next_seq did not
        //    advance, chain hash unchanged. The injection short-circuits the
        //    append BEFORE any state mutation, mirroring the real-error
        //    invariant.
        let mut guard = wal_arc.lock().unwrap();
        let after_snapshot = guard.snapshot_after(None, 1024).expect("after snapshot");
        assert_eq!(
            after_snapshot.len(),
            baseline_wal_count,
            "WAL on disk must be unchanged on fail-closed dispatch"
        );
        assert_eq!(
            guard.next_seq(),
            baseline_next_seq,
            "next_seq must NOT advance when append fails"
        );
        assert_eq!(
            guard.last_chain_hash_hex().map(|s| s.to_string()),
            baseline_chain,
            "last_chain_hash_hex must NOT advance when append fails"
        );
        drop(guard);

        // 6) After disarming, evaluate_attempt resumes normal operation.
        let recovered = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate after disarm");
        match &recovered.verdict {
            Verdict::Allow { rule_id } => assert_eq!(rule_id, "rule-allow-anthropic"),
            other => panic!("expected Allow after disarm; got {other:?}"),
        }
        assert!(
            recovered.wal_seq.is_some(),
            "wal_seq should be Some after disarm"
        );

        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_fail_closed_on_wal_failure_overrides_default_deny_too() {
        // Companion to the Allow-override case above: when the unforced
        // verdict was already a deny (DefaultDeny), the dispatch still
        // emits the AuditWalAppendFailed-flavored fail-closed shape, NOT
        // the original DefaultDeny shape. The audit body must reflect the
        // dispatch provenance, not the original deny reason.
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let handle = boot(config).expect("boot");

        let wal_arc = handle.wal_writer().expect("wal wired").clone();
        let injection = wal_arc.lock().unwrap().injection_handle();
        injection.store(true, std::sync::atomic::Ordering::SeqCst);

        let outcome = handle
            .evaluate_attempt(&req_for(Some("pastebin.com"), 443))
            .expect("evaluate_attempt must Ok-with-fail-closed");

        injection.store(false, std::sync::atomic::Ordering::SeqCst);

        match &outcome.verdict {
            Verdict::Deny {
                reason: DeniedReason::AuditWalAppendFailed,
            } => {}
            other => panic!("expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"),
        }
        assert!(outcome.wal_seq.is_none());
        // Provenance must be audit_wal_append_failed, NOT default_deny.
        assert!(outcome
            .event_canonical_json
            .contains("\"audit_wal_append_failed\""));
        assert!(
            !outcome.event_canonical_json.contains("\"default_deny\""),
            "fail-closed dispatch must override the default_deny provenance"
        );
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_fail_closed_on_wal_failure_overrides_explicit_deny() {
        // Third companion: explicit-rule deny path also gets overridden.
        let (handle, _dir) = boot_with_single_rule("rule-deny-pastebin", "pastebin.com", "deny");

        let wal_arc = handle.wal_writer().expect("wal wired").clone();
        let injection = wal_arc.lock().unwrap().injection_handle();
        injection.store(true, std::sync::atomic::Ordering::SeqCst);

        let outcome = handle
            .evaluate_attempt(&req_for(Some("pastebin.com"), 443))
            .expect("evaluate_attempt must Ok-with-fail-closed");

        injection.store(false, std::sync::atomic::Ordering::SeqCst);

        match &outcome.verdict {
            Verdict::Deny {
                reason: DeniedReason::AuditWalAppendFailed,
            } => {}
            other => panic!("expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"),
        }
        // The original deny would have stamped rule_id_matched and
        // decision_provenance="static_rule"; the dispatched shape clears
        // both in favor of the audit_wal_append_failed provenance.
        assert!(outcome
            .event_canonical_json
            .contains("\"audit_wal_append_failed\""));
        assert!(
            !outcome
                .event_canonical_json
                .contains("\"rule-deny-pastebin\""),
            "fail-closed dispatch must drop the original rule_id_matched stamp"
        );
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_fails_closed_within_deadline_when_wal_lock_is_held_across_fsync() {
        // GF3 fault injection: a control-plane operation (drain/reload/ACK) that
        // holds the WAL mutex across a slow fsync must NOT stall the verdict path
        // until the NFQUEUE deadline fail-stops the whole daemon. Model that
        // stall by holding the WAL lock in a background thread past the verdict
        // path's acquisition budget, then prove evaluate_attempt STILL returns
        // (fail-closed) well within the NFQUEUE 2s verdict deadline.
        let (handle, _dir) =
            boot_with_single_rule("rule-allow-anthropic", "api.anthropic.com", "allow");
        let wal_arc = handle.wal_writer().expect("wal wired").clone();

        // Background "control-plane" holder: own the WAL mutex and keep it well
        // past EVALUATE_ATTEMPT_LOCK_BUDGET, exactly as a stuck fsync-under-lock
        // would. It releases only after the verdict has returned.
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let holder_wal = wal_arc.clone();
        let holder_release = release.clone();
        let holder = std::thread::spawn(move || {
            let _guard = holder_wal.lock().unwrap();
            while !holder_release.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        // Ensure the holder actually owns the lock before racing the verdict.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let started = std::time::Instant::now();
        let outcome = handle
            .evaluate_attempt(&req_for(Some("api.anthropic.com"), 443))
            .expect("evaluate_attempt must return fail-closed, never block or Err");
        let elapsed = started.elapsed();

        // 1) Returned within the NFQUEUE fail-closed deadline (2s), not blocked.
        assert!(
            elapsed < std::time::Duration::from_millis(1900),
            "verdict path must return within the queue deadline under a WAL \
             stall; took {elapsed:?}"
        );
        // 2) Fail CLOSED: the audit store was unreachable, so the verdict is Deny
        //    with the audit-failure reason, never a durable Allow.
        match &outcome.verdict {
            Verdict::Deny {
                reason: DeniedReason::AuditWalAppendFailed,
            } => {}
            other => panic!("expected fail-closed Deny(AuditWalAppendFailed); got {other:?}"),
        }
        assert!(
            outcome.wal_seq.is_none(),
            "a stalled WAL cannot have durably sequenced the record"
        );

        release.store(true, std::sync::atomic::Ordering::SeqCst);
        holder.join().expect("holder thread");
        let _ = handle.stop();
    }
}
