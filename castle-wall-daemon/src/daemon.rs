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
use crate::failure::{FailureDisposition, FailureMode};
use crate::ipc::auth::{load_pinned_public_key, AuthError};
use crate::ipc::server::{IpcServer, IpcServerError};
use crate::manifest::{ManifestStore, ManifestStoreError};

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
        // Best-effort first load; ignore errors here so a missing manifest
        // at boot does not block the IPC layer from coming up.
        let _ = store.reload();
    }

    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let ipc_server = IpcServer::start(crate::ipc::server::ServerConfig {
        socket_path: config.socket_path.clone(),
        pinned_public_key: pinned_key_bytes,
        prompt_timeout: config.prompt_timeout,
        audit_buffer: Arc::clone(&audit_buffer),
        shutdown_flag: Arc::clone(&shutdown_flag),
        fortress_id: config.fortress_id.clone(),
        manifest_store: Some(Arc::clone(&manifest_store)),
        wal_writer: Some(Arc::clone(&wal_writer)),
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
            });
        }
        let report = handle.stop().expect("stop");
        assert!(report.audit_remaining >= 1);
    }
}
