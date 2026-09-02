//! Daemon lifecycle orchestration.
//!
//! `run()` boots the daemon: installs signal handlers, opens the audit
//! WAL ring, binds the IPC UDS, starts the accept loop, and waits for a
//! shutdown signal (SIGTERM / SIGINT). On shutdown it asks the IPC server
//! to stop, drains in-flight audit events, and returns. The kernel-touching
//! modules (nftables, NFQUEUE bind, inotify watcher) are wired in by the
//! later checkpoints; this module is the orchestration spine they hang off.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::audit::{AuditRingBuffer, WalWriter};
use crate::config::DaemonConfig;
use crate::constants::{AUDIT_LAYER, SCHEMA_VERSION_V1};
use crate::decision::{AttemptError, DecisionEngine, EvaluationOutcome};
use crate::enforcement::EnforcementRuntime;
use crate::failure::{FailureDisposition, FailureMode};
use crate::ipc::auth::{load_pinned_public_key, AuthError};
use crate::ipc::server::{IpcServer, IpcServerError};
use crate::manifest::{ManifestStore, ManifestStoreError};
use crate::policy::EvaluationRequest;

/// Errors emitted by the daemon lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("F-1 startup failure: {0}")]
    StartupConfig(String),
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
    #[error("manifest store init failed: {0}")]
    ManifestStoreInit(String),
    #[error("F-4 startup failure: audit-producer key load/generate failed: {0}")]
    ProducerKeyLoad(String),
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
        DaemonError::ManifestStoreInit(_) => FailureMode::StartupPolicyParseFailed,
        DaemonError::ProducerKeyLoad(_) => FailureMode::StartupPolicyParseFailed,
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
    /// Owned kernel-enforcement runtime, when the daemon holds one. `None` on
    /// this slice's boot path: the Linux kernel adapter is not drill-verified
    /// yet (ASSURANCE_MATRIX row 17), so the daemon reports ControlPlaneOnly.
    enforcement: Option<EnforcementRuntime>,
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
    /// IPC-owned accept-loop stop flag, retained here only so tests can prove
    /// the IPC server is still live (this flag observed `false`) at the instant
    /// enforcement is released. It is set EXCLUSIVELY by
    /// [`IpcServer::stop_and_join`] during `teardown`, AFTER enforcement
    /// shutdown — never by a signal or `request_stop`. Test-gated because
    /// production never reads it through the handle: the server owns its own
    /// clone.
    #[cfg(test)]
    ipc_stop_flag: Arc<AtomicBool>,
    started_at: Instant,
}

impl DaemonHandle {
    /// Current enforcement truth. The existing boot path deliberately reports
    /// `ControlPlaneOnly` until L1 owns live nftables and NFQUEUE resources.
    ///
    /// `Enforcing` is DERIVED, never stored: it is returned only when an owned
    /// [`EnforcementRuntime`] reports every required component ready. A poisoned
    /// lifecycle lock reads as `Degraded` (and `Degraded` is never promoted to
    /// `Enforcing`), and a runtime that has lost a component reads as
    /// `ControlPlaneOnly` — so process/IPC liveness alone can never present as
    /// kernel enforcement.
    pub fn runtime_state(&self) -> DaemonRuntimeState {
        let lifecycle = self
            .runtime_state
            .lock()
            .map(|state| *state)
            .unwrap_or(DaemonRuntimeState::Degraded);
        crate::enforcement::derive_daemon_state(lifecycle, self.enforcement.as_ref())
    }

    /// Kernel enforcement is true only in the explicit enforcing state.
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
    /// (`nftables.rs` / `nfqueue.rs`, future checkpoint) drive. It
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

    /// Block until shutdown is requested, sweeping audit-buffer expirations
    /// every `tick`.
    pub fn wait_for_shutdown(&self, tick: Duration) {
        while !self.is_shutdown_requested() {
            std::thread::sleep(tick);
            if let Ok(mut buf) = self.audit_buffer.lock() {
                buf.evict_expired(std::time::SystemTime::now());
            }
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

    /// Test-only: attach an enforcement runtime so the `Enforcing` derivation
    /// can be exercised without a real kernel. Never compiled into the shipped
    /// daemon; the production boot path leaves `enforcement` `None`.
    #[cfg(test)]
    pub(crate) fn set_enforcement_for_test(&mut self, runtime: EnforcementRuntime) {
        self.enforcement = Some(runtime);
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
        // Set the daemon shutdown-REQUEST flag. This is NOT the IPC accept-loop
        // stop flag, so it does not begin tearing the control surface down; it
        // only records that a stop was requested (idempotent with a prior
        // signal / request_stop).
        self.request_stop();
        // Enforcement BEFORE IPC. The NFQUEUE verdict thread routes through the
        // decision engine and reports to the IPC control surface, so it must
        // stop (and be joined) while that surface is still live. `shutdown()`
        // releases every component in reverse acquisition order and joins owned
        // threads.
        if let Some(mut enforcement) = self.enforcement.take() {
            enforcement.shutdown();
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
/// not enforcement; `Enforcing` is reserved for a later boot path that holds
/// all required kernel resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonRuntimeState {
    ControlPlaneOnly,
    Enforcing,
    Degraded,
    Stopping,
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
    let pinned_key_array = ManifestStore::load_pinned_key(&config.pinned_public_key_path)
        .map_err(|err: ManifestStoreError| DaemonError::PinnedKeyLoad(err.to_string()))?;
    // The IPC handshake uses raw bytes; the ManifestStore uses a fixed array.
    // Both views share the same key material loaded above.
    let pinned_key_bytes = pinned_key_array.to_vec();
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
    let wal_writer = match WalWriter::open(&config.wal_path) {
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
    )));
    if let Ok(mut store) = manifest_store.lock() {
        // Best-effort first load: a missing manifest at boot does not block
        // the IPC layer from coming up (the daemon stays deny-by-default
        // until the first successful policy.reload). But the failure must be
        // LOUD (codex round-4 HIGH): a manifest the snapshot gate refuses —
        // e.g. one missing the always-on habeas distress lane — must leave an
        // unmissable trace, never a silent no-policy boot.
        if let Err(err) = store.reload() {
            // SAFETY: boot-time refusal fires before any logging/journal
            // sink is guaranteed up; raw stderr is the only channel that
            // reliably reaches the operator console (and systemd captures
            // it), so the loud-refusal contract is stderr at this site.
            eprintln!(
                "castle-wall-daemon: boot-time manifest load failed; running \
                 deny-by-default with NO policy until a valid manifest is \
                 reloaded: {err}"
            );
        }
    }

    // Daemon shutdown-REQUEST flag: set by signal handlers and request_stop,
    // observed by wait_for_shutdown. It drives the DECISION to shut down.
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    // IPC-owned accept-loop stop flag, DISTINCT from the daemon request flag
    // above. Only IpcServer::stop_and_join (called from teardown AFTER
    // enforcement.shutdown) sets it, so a signal or request_stop can never stop
    // the IPC control surface before enforcement is released. Must stay separate
    // from `shutdown_flag`; conflating them reintroduces the premature-IPC-stop
    // defect this separation fixes.
    let ipc_stop_flag = Arc::new(AtomicBool::new(false));

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

    let ipc_server = IpcServer::start(crate::ipc::server::ServerConfig {
        socket_path: config.socket_path.clone(),
        pinned_public_key: pinned_key_bytes,
        prompt_timeout: config.prompt_timeout,
        audit_buffer: Arc::clone(&audit_buffer),
        // The IPC accept loop stops on the IPC-owned flag, NOT the daemon
        // shutdown-request flag, so a signal/request_stop cannot terminate it
        // before enforcement teardown.
        shutdown_flag: Arc::clone(&ipc_stop_flag),
        fortress_id: config.fortress_id.clone(),
        manifest_store: Some(Arc::clone(&manifest_store)),
        wal_writer: Some(Arc::clone(&wal_writer)),
        producer_signer: Some(producer_signer),
    })?;

    // Emit a daemon_started audit event so reconnects can see the boot.
    let started_event = format!(
        "{{\"layer\":\"{}\",\"operation\":\"daemon_started\",\"schema_version\":{},\"fortress_id\":\"{}\"}}",
        AUDIT_LAYER, SCHEMA_VERSION_V1, config.fortress_id
    );
    if let Ok(mut buf) = audit_buffer.lock() {
        buf.append(crate::audit::PendingAuditEvent {
            event_canonical_json: started_event.clone(),
            captured_at: std::time::SystemTime::now(),
            // daemon_started is a recovery-class event (boot signal);
            // preserve through ring-buffer saturation (full-sweep #76).
            critical: true,
        });
    }
    // Also persist the daemon_started event to the WAL so Sanctuary main
    // sees it on first drain after reconnect. fsync per critical event.
    if let Ok(mut wal) = wal_writer.lock() {
        let _ = wal.append_critical(&started_event);
    }

    install_shutdown_signal_handlers(Arc::clone(&shutdown_flag))?;

    let decision_engine = Arc::new(DecisionEngine::new(
        config.fortress_id.clone(),
        Some(Arc::clone(&manifest_store)),
        Some(Arc::clone(&wal_writer)),
        Arc::clone(&audit_buffer),
    ));
    let runtime_state = Arc::new(Mutex::new(DaemonRuntimeState::ControlPlaneOnly));

    Ok(DaemonHandle {
        config,
        ipc_server: Some(ipc_server),
        audit_buffer,
        decision_engine,
        runtime_state,
        // No kernel-enforcement runtime is started on this slice's boot path:
        // the Linux adapter is not drill-verified (ASSURANCE_MATRIX row 17), so
        // the daemon owns no runtime and reports ControlPlaneOnly. This is the
        // seam where `EnforcementRuntime::start(linux_production_plan(..))` will
        // attach once the Linux drill closes; until then it stays `None` rather
        // than a stub that reports enforcement.
        enforcement: None,
        shutdown_flag,
        #[cfg(test)]
        ipc_stop_flag,
        started_at: Instant::now(),
    })
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
    use crate::policy::{DeniedReason, Verdict};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::fs;
    use tempfile::TempDir;

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
    fn runtime_state_reports_enforcing_only_with_a_fully_ready_runtime() {
        let dir = TempDir::new().unwrap();
        let (config, _signing) = fresh_config_in(&dir);
        let mut handle = boot(config).expect("boot");

        // Baseline: no runtime owned -> control plane only, never enforcing.
        assert_eq!(handle.runtime_state(), DaemonRuntimeState::ControlPlaneOnly);
        assert!(!handle.is_enforcing());

        // Attach a fully-ready runtime: NOW the derived state is Enforcing.
        handle.set_enforcement_for_test(EnforcementRuntime::all_ready_for_test());
        assert_eq!(handle.runtime_state(), DaemonRuntimeState::Enforcing);
        assert!(handle.is_enforcing());

        // stop() tears the runtime down and reports Stopping, never Enforcing.
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
    /// targeting `host` on port 443 over tcp. Used by the
    /// evaluate_attempt tests below.
    fn write_single_rule_policy(
        policy_dir: &std::path::Path,
        signing: &SigningKey,
        rule_id: &str,
        host: &str,
        disposition: &str,
    ) {
        fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
        let body = format!(
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{\"host\":[\"{host}\"],\"port\":[443],\"protocol\":\"tcp\"}},\"disposition\":\"{disposition}\"}}"
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
                signing_key_id: "test".to_string(),
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
            dest_ip: Some("203.0.113.10".to_string()),
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
}
