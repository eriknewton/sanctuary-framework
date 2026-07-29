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

use crate::audit::{AuditRingBuffer, WalError, WalWriter};
use crate::config::DaemonConfig;
use crate::constants::{AUDIT_LAYER, SCHEMA_VERSION_V1};
use crate::failure::{default_disposition, FailureDisposition, FailureMode};
use crate::ipc::auth::{load_pinned_public_key, AuthError};
use crate::ipc::server::{IpcServer, IpcServerError};
use crate::manifest::{ManifestStore, ManifestStoreError};
use crate::manifest::canonical_json::CanonicalJsonError;
use crate::policy::{
    build_audit_event_canonical_json, DeniedReason, EvaluationRequest, Verdict,
};

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
        FailureDisposition::RefuseToStart { operator_message_key } => *operator_message_key,
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
    format!("Sanctuary cannot start ({}).\n\n{}\n\nDetail: {}", key, body, detail)
}

/// Live daemon handle. Holding this guarantees the IPC server is bound and
/// the signal handlers are installed; dropping it triggers an orderly stop.
pub struct DaemonHandle {
    config: DaemonConfig,
    ipc_server: Option<IpcServer>,
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    /// Disk-backed WAL. Shared between the daemon-side audit emitters and
    /// the IPC drain dispatch. None when boot was invoked with a transient
    /// in-memory-only configuration (e.g., short-lived smoke runs).
    wal_writer: Option<Arc<Mutex<WalWriter>>>,
    /// Manifest store. Shared with the IPC dispatch's policy.reload handler.
    manifest_store: Option<Arc<Mutex<ManifestStore>>>,
    shutdown_flag: Arc<AtomicBool>,
    started_at: Instant,
}

impl DaemonHandle {
    /// Test/integration helper: hand back the manifest store handle so the
    /// caller can simulate operator-driven flows that the IPC layer carries
    /// in production.
    pub fn manifest_store(&self) -> Option<&Arc<Mutex<ManifestStore>>> {
        self.manifest_store.as_ref()
    }

    /// Test/integration helper: hand back the WAL writer handle so the
    /// caller can append synthetic audit events without going through the
    /// kernel-touching emitter path.
    pub fn wal_writer(&self) -> Option<&Arc<Mutex<WalWriter>>> {
        self.wal_writer.as_ref()
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
        let store = self
            .manifest_store
            .as_ref()
            .ok_or(AttemptError::ManifestStoreUnwired)?;
        let wal = self
            .wal_writer
            .as_ref()
            .ok_or(AttemptError::WalUnwired)?;

        let (verdict, audit_fortress_id, audit_confined_agent_uid) = {
            let guard = store
                .lock()
                .map_err(|_| AttemptError::ManifestStorePoisoned)?;
            // F-1 deny-by-default: when no snapshot has been loaded, the
            // verdict is DefaultDeny. The evaluator on an empty snapshot
            // returns the same shape, so we surface the no-snapshot case
            // through the same code path.
            match guard.current_snapshot() {
                Some(snap) => (
                    snap.evaluate(request),
                    snap.fortress_id.clone(),
                    snap.confined_agent_uid,
                ),
                None => (
                    Verdict::Deny {
                        reason: crate::policy::DeniedReason::DefaultDeny,
                    },
                    self.config.fortress_id.clone(),
                    None,
                ),
            }
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

        let append_result = {
            let mut guard = wal
                .lock()
                .map_err(|_| AttemptError::WalPoisoned)?;
            guard.append_critical(&event_canonical_json)
        };

        match append_result {
            Ok(seq) => {
                // Mirror into the in-memory ring so `wait_for_shutdown` and
                // other observers see the same event count the WAL holds.
                // The ring is capped + TTL-evicted on the wait-loop tick.
                if let Ok(mut buf) = self.audit_buffer.lock() {
                    buf.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: event_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        // Per-attempt allow/deny mirrors are the
                        // high-volume metric stream: drop these first
                        // when the ring saturates so the audit-truncate /
                        // recovery / panic events stay (full-sweep #76).
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
            Err(_wal_err) => {
                // Scope-lock section 7 / section 8: the
                // RuntimeAuditWalAppendFailed dispatch forces fail-closed
                // regardless of the original verdict. Without a durable
                // audit chain the egress decision cannot be reconstructed,
                // so the verdict-loop must drop the packet.
                let disposition =
                    default_disposition(FailureMode::RuntimeAuditWalAppendFailed);
                debug_assert!(
                    matches!(
                        disposition,
                        FailureDisposition::FailClosed {
                            emit_event: "egress_blocked",
                            reason: "audit_wal_append_failed",
                        }
                    ),
                    "RuntimeAuditWalAppendFailed must dispatch to FailClosed \
                     with emit_event=egress_blocked, reason=audit_wal_append_failed",
                );
                let _ = disposition;

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

                // Mirror the synthesized fail-closed event into the
                // in-memory ring so the next ACK can carry a
                // wal_overflow_loss-equivalent record per scope-lock
                // section 8. The original (allow/deny) audit body is
                // intentionally NOT mirrored: the durable record never
                // reached the WAL, and the in-memory ring's contract is
                // "events the verdict-loop acted on," which is the
                // fail-closed shape.
                if let Ok(mut buf) = self.audit_buffer.lock() {
                    buf.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: fail_closed_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        // Fail-closed audit-WAL-failure mirrors are
                        // panic-class events per scope-lock §8 and
                        // must survive ring-buffer saturation
                        // (full-sweep #76).
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

/// Outcome of [`DaemonHandle::evaluate_attempt`]: the policy decision plus
/// the durable WAL receipt (assigned seq, canonical-JSON body, ISO-8601
/// timestamp). `wal_seq` is `None` when the daemon's
/// `RuntimeAuditWalAppendFailed` dispatch fired, in which case `verdict`
/// is the synthesized fail-closed `Verdict::Deny { reason:
/// DeniedReason::AuditWalAppendFailed }` and `event_canonical_json`
/// reflects the fail-closed audit shape rather than the original
/// allow/deny outcome.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub verdict: Verdict,
    pub wal_seq: Option<u64>,
    pub event_canonical_json: String,
    pub timestamp_iso8601: String,
}

/// Errors returned by [`DaemonHandle::evaluate_attempt`].
#[derive(Debug, thiserror::Error)]
pub enum AttemptError {
    #[error("manifest store not wired into this daemon instance")]
    ManifestStoreUnwired,
    #[error("WAL writer not wired into this daemon instance")]
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

/// Render the current wall-clock as an ISO-8601 timestamp suitable for
/// the `AuditEntry.timestamp` field. Uses UTC; format mirrors the existing
/// Sanctuary audit-log convention (`YYYY-MM-DDTHH:MM:SS.sssZ`).
fn current_timestamp_iso8601() -> String {
    let now = std::time::SystemTime::now();
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_ms = dur.as_millis() as i128;
    let secs = (total_ms / 1000) as i64;
    let ms = (total_ms % 1000) as i64;
    let (y, mo, d, h, mi, s) = ymd_hms_from_unix_seconds(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, ms
    )
}

/// Convert a UNIX-epoch second count into UTC (year, month, day, hour,
/// minute, second). Avoids an external chrono dep; civil-from-days
/// algorithm by Howard Hinnant. Valid for any year representable as i32.
fn ymd_hms_from_unix_seconds(unix_seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let secs_per_day: i64 = 86_400;
    let mut days = unix_seconds.div_euclid(secs_per_day);
    let mut secs_of_day = unix_seconds.rem_euclid(secs_per_day);
    if secs_of_day < 0 {
        secs_of_day += secs_per_day;
        days -= 1;
    }
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if m <= 2 { y + 1 } else { y }) as i32;
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    (year, m, d, hour, minute, second)
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

    /// Programmatically request shutdown. Used by tests and by the
    /// signal-handler thread.
    pub fn request_stop(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
    }

    /// Stop the IPC server and wait for it to join.
    pub fn stop(mut self) -> Result<DaemonExitReport, DaemonError> {
        self.request_stop();
        if let Some(server) = self.ipc_server.take() {
            server.stop_and_join();
        }
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
    }
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

    let shutdown_flag = Arc::new(AtomicBool::new(false));

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
        shutdown_flag: Arc::clone(&shutdown_flag),
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

    Ok(DaemonHandle {
        config,
        ipc_server: Some(ipc_server),
        audit_buffer,
        wal_writer: Some(wal_writer),
        manifest_store: Some(manifest_store),
        shutdown_flag,
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
        let file = "rule-0.json";
        fs::write(policy_dir.join(RULES_SUBDIR).join(file), &body_bytes).unwrap();
        // Every composed manifest must carry the genuine habeas local lane
        // (always-on-lane gate); include it so the snapshot builds.
        let habeas_bytes = crate::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes().to_vec();
        let habeas_file = "rule-habeas.json";
        fs::write(
            policy_dir.join(RULES_SUBDIR).join(habeas_file),
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
                    file: file.to_string(),
                    sha256: sha256_hex(&body_bytes),
                },
                ManifestRuleEntry {
                    rule_id: crate::habeas::HABEAS_LOCAL_RULE_ID.to_string(),
                    file: habeas_file.to_string(),
                    sha256: sha256_hex(&habeas_bytes),
                },
            ],
        };
        let canonical =
            canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
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
        assert!(
            outcome
                .event_canonical_json
                .contains("\"rule-allow-anthropic\"")
        );
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
        assert!(outcome.event_canonical_json.contains("\"rule-deny-pastebin\""));
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_writes_durable_wal_seq_visible_through_handle() {
        let (handle, _dir) =
            boot_with_single_rule("rule-allow", "api.anthropic.com", "allow");
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
        let baseline_chain = wal_arc.lock().unwrap().last_chain_hash_hex().map(|s| s.to_string());

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
            other => panic!(
                "expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"
            ),
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
            outcome
                .event_canonical_json
                .contains("\"egress_blocked\""),
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
            !outcome
                .event_canonical_json
                .contains("\"egress_approved\""),
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
            other => panic!(
                "expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"
            ),
        }
        assert!(outcome.wal_seq.is_none());
        // Provenance must be audit_wal_append_failed, NOT default_deny.
        assert!(
            outcome
                .event_canonical_json
                .contains("\"audit_wal_append_failed\"")
        );
        assert!(
            !outcome.event_canonical_json.contains("\"default_deny\""),
            "fail-closed dispatch must override the default_deny provenance"
        );
        let _ = handle.stop();
    }

    #[test]
    fn evaluate_attempt_fail_closed_on_wal_failure_overrides_explicit_deny() {
        // Third companion: explicit-rule deny path also gets overridden.
        let (handle, _dir) =
            boot_with_single_rule("rule-deny-pastebin", "pastebin.com", "deny");

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
            other => panic!(
                "expected Verdict::Deny(AuditWalAppendFailed); got {other:?}"
            ),
        }
        // The original deny would have stamped rule_id_matched and
        // decision_provenance="static_rule"; the dispatched shape clears
        // both in favor of the audit_wal_append_failed provenance.
        assert!(
            outcome
                .event_canonical_json
                .contains("\"audit_wal_append_failed\"")
        );
        assert!(
            !outcome.event_canonical_json.contains("\"rule-deny-pastebin\""),
            "fail-closed dispatch must drop the original rule_id_matched stamp"
        );
        let _ = handle.stop();
    }
}
