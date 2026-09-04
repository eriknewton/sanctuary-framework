//! Unix-domain-socket IPC server: accept loop, per-connection handshake,
//! method dispatch.
//!
//! The server is shutdown-aware: callers pass a shared `AtomicBool` that the
//! accept loop polls between non-blocking accepts. Active connections are
//! bounded, and every handler is tracked with a duplicate stream that can
//! interrupt blocking reads/writes. On shutdown the accept loop rejects new
//! work, shuts down every tracked stream, joins every handler, drops the
//! listener, and unlinks the socket. The 120-second idle timeout is therefore
//! an idle-resource bound, not the shutdown bound.
//!
//! Per scope-lock §5: the socket lives at /run/sanctuary/<fortress-id>/filter.sock,
//! mode 0660, owner root:sanctuary. The accept loop polls every 100ms so
//! shutdown is observed within a tick.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;

use crate::audit::{AuditRingBuffer, PendingAuditEvent, WalWriter};
use crate::constants::{AUDIT_LAYER, IPC_NAMESPACE, SCHEMA_VERSION_V1};
use crate::decision::DecisionEngine;
use crate::ipc::auth::{
    encode_nonce_b64url, generate_challenge_nonce, peer_uid_for_stream, verify_handshake_response,
    AuthError, HandshakeIdentity, CHALLENGE_NONCE_BYTES,
};
use crate::ipc::framing::{frame, parse_frame, ParseStep};
use crate::ipc::messages::{
    AuditDrainEvent, DrainErrorClass, IpcMessage, ManifestState, MessageEnvelope,
    CAP_POLICY_BUNDLE_PUBLISH,
};
use crate::ipc::producer_sig::ProducerSigner;
use crate::live_status::LiveStatus;
use crate::runtime_health::{RuntimeHealthState, RuntimeHealthView};

/// Socket file permissions (mode 0660 per scope-lock §5).
const SOCKET_MODE: u32 = 0o660;
/// Accept-loop poll cadence; bounds shutdown latency.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Per-connection idle deadline. Connections that go idle past this drop
/// without prejudice; the client reconnects.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-connection handshake deadline. Connections that haven't completed
/// the Ed25519 challenge in this window are dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
/// Maximum daemon response body. Sanctuary main's transport accepts 16 MiB;
/// keeping the daemon at the same ceiling prevents a trusted peer from turning
/// an otherwise valid drain request into an unbounded serialization/write.
const MAX_OUTBOUND_BODY_BYTES: usize = 16 * 1024 * 1024;
/// The public consumer's default and maximum useful drain batch. The daemon is
/// authoritative for this bound: an authenticated peer is still untrusted for
/// resource allocation and may put `u32::MAX` on the wire.
const MAX_AUDIT_DRAIN_EVENTS: usize = 256;
/// Hard cap on concurrently live IPC handlers. Authentication does not grant a
/// client unbounded thread/file-descriptor authority.
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const RESERVED_TRUSTED_CONNECTIONS: usize = 8;
const MAX_PREAUTH_PER_UNTRUSTED_UID: usize = 4;
const MAX_PREAUTH_PER_TRUSTED_UID: usize = 16;
const PREAUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_PREAUTH_ATTEMPTS_PER_UNTRUSTED_UID: usize = 16;
const MAX_PREAUTH_ATTEMPTS_PER_TRUSTED_UID: usize = 120;
const MAX_TRACKED_UID_RATE_BUCKETS: usize = 1024;
const CONTROL_OPERATION_BUDGET: Duration = Duration::from_secs(2);

/// Configuration sourced from the daemon at boot.
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub pinned_public_key: Vec<u8>,
    pub prompt_timeout: Duration,
    pub audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    /// Daemon-level stop request. This is distinct from `shutdown_flag`, which
    /// owns only the IPC accept/handler lifecycle: a fatal post-commit control
    /// failure must reach the outer daemon loop so systemd observes process exit.
    pub daemon_shutdown_request: Arc<AtomicBool>,
    /// Distinct fatal-control-path signal. This is set before the ordinary stop
    /// request so the supervisor cannot misclassify a durable publication/audit
    /// failure as a clean operator shutdown.
    pub fatal_control_path: Arc<AtomicBool>,
    pub shutdown_flag: Arc<AtomicBool>,
    pub fortress_id: String,
    /// The exact policy/audit decision surface shared with evaluation and the
    /// manifest watcher. Policy reload reaches the store only through this
    /// object, preventing the three consumers from being wired to divergent
    /// `Arc<Mutex<ManifestStore>>` instances.
    pub decision_engine: Arc<DecisionEngine>,
    /// Optional WAL writer used by the audit.drain + audit.drain_ack
    /// dispatch. When absent, both methods return explicit errors: activation
    /// must never confuse missing evidence storage with a healthy empty WAL.
    pub wal_writer: Option<Arc<Mutex<WalWriter>>>,
    /// Optional producer signer (Slice L1). When present, every drained
    /// enforcement event is signed over `seq ‖ timestamp ‖ canonical-bytes`
    /// with the daemon-held audit-producer key, and the consumer verifies the
    /// signature against the pinned producer public key before accepting the
    /// event as enforcement evidence. When absent (legacy/test boot), events
    /// drain unsigned and the consumer falls back to the documented
    /// channel-authenticity basis.
    pub producer_signer: Option<Arc<ProducerSigner>>,
    /// Truthful daemon lifecycle/runtime source. IPC never synthesizes health.
    pub live_status: Arc<LiveStatus>,
    /// UID owning the pinned service identity. Capacity is reserved for this
    /// principal; group members are still admitted only under per-UID quotas.
    pub trusted_service_uid: u32,
    /// The daemon's published kernel-runtime health observation. Status READS
    /// this; it never locks the runtime and never forks an ownership proof of its
    /// own. That is what stops an authenticated status poller from amplifying
    /// into `nft` subprocess load, and what lets momentary runtime-mutex
    /// contention read as INDETERMINATE rather than as a runtime loss. The
    /// supervision loop in `daemon.rs` is the sole writer; see
    /// [`crate::runtime_health`].
    pub runtime_health: Arc<RuntimeHealthView>,
    /// Number of authenticated bounded WAL drain/ACK operations in flight.
    /// Supervision uses this to distinguish legitimate progress from an
    /// unexplained wedged WAL mutex.
    pub wal_control_progress: Arc<AtomicUsize>,
    /// Physical-cap recovery mode permits only authenticated status and WAL
    /// drain/ACK traffic until startup evidence can be durably appended.
    pub drain_recovery_only: Arc<AtomicBool>,
}

/// Errors emitted by the IPC server lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum IpcServerError {
    #[error("socket bind failed: {0}")]
    Bind(String),
    #[error("socket directory creation failed: {0}")]
    SocketDir(String),
    #[error("socket permissions failed: {0}")]
    Permissions(String),
    #[error("listener configuration failed: {0}")]
    ListenerConfig(String),
}

/// Live IPC server. Owning this struct guarantees the socket is bound and
/// the accept thread is running. Calling `stop_and_join()` triggers a
/// shutdown.
pub struct IpcServer {
    accept_thread: Option<JoinHandle<()>>,
    socket_path: PathBuf,
    shutdown_flag: Arc<AtomicBool>,
    decision_engine: Arc<DecisionEngine>,
    socket_identity: (u64, u64),
}

fn remove_proven_stale_socket(path: &PathBuf) -> Result<(), IpcServerError> {
    let first = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(IpcServerError::Bind(err.to_string())),
    };
    if !first.file_type().is_socket() {
        return Err(IpcServerError::Bind(
            "refusing to replace a non-socket IPC path".to_string(),
        ));
    }
    if first.uid() != unsafe { libc::geteuid() } {
        return Err(IpcServerError::Bind(
            "refusing to replace a foreign-owned IPC socket".to_string(),
        ));
    }
    for _ in 0..2 {
        match UnixStream::connect(path) {
            Ok(stream) => {
                drop(stream);
                return Err(IpcServerError::Bind(
                    "another live daemon owns the IPC socket".to_string(),
                ));
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(err) => {
                return Err(IpcServerError::Bind(format!(
                    "IPC socket liveness probe was inconclusive: {err}"
                )))
            }
        }
        std::thread::yield_now();
    }
    let second = std::fs::symlink_metadata(path)
        .map_err(|err| IpcServerError::Bind(format!("stale socket revalidation failed: {err}")))?;
    if !second.file_type().is_socket()
        || second.uid() != first.uid()
        || second.dev() != first.dev()
        || second.ino() != first.ino()
    {
        return Err(IpcServerError::Bind(
            "IPC socket changed during stale-owner revalidation".to_string(),
        ));
    }
    std::fs::remove_file(path)
        .map_err(|err| IpcServerError::Bind(format!("stale socket removal failed: {err}")))
}

fn remove_owned_socket(path: &PathBuf, identity: (u64, u64)) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_socket() && (meta.dev(), meta.ino()) == identity {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl IpcServer {
    pub fn start(config: ServerConfig) -> Result<Self, IpcServerError> {
        let parent = config
            .socket_path
            .parent()
            .ok_or_else(|| IpcServerError::SocketDir("socket path has no parent".to_string()))?;
        std::fs::create_dir_all(parent)
            .map_err(|err| IpcServerError::SocketDir(err.to_string()))?;

        remove_proven_stale_socket(&config.socket_path)?;

        let listener = UnixListener::bind(&config.socket_path)
            .map_err(|err| IpcServerError::Bind(err.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| IpcServerError::ListenerConfig(err.to_string()))?;
        let mut perms = std::fs::metadata(&config.socket_path)
            .map_err(|err| IpcServerError::Permissions(err.to_string()))?
            .permissions();
        perms.set_mode(SOCKET_MODE);
        std::fs::set_permissions(&config.socket_path, perms)
            .map_err(|err| IpcServerError::Permissions(err.to_string()))?;
        let bound_meta = std::fs::symlink_metadata(&config.socket_path)
            .map_err(|err| IpcServerError::Permissions(err.to_string()))?;
        if !bound_meta.file_type().is_socket() {
            return Err(IpcServerError::Bind(
                "bound IPC path did not revalidate as a socket".to_string(),
            ));
        }
        let socket_identity = (bound_meta.dev(), bound_meta.ino());

        let shutdown_flag = config.shutdown_flag.clone();
        let socket_path = config.socket_path.clone();
        let decision_engine = Arc::clone(&config.decision_engine);
        let mutation_cancel = Arc::clone(config.decision_engine.mutation_cancel_flag());
        let server_state = Arc::new(ServerState {
            audit_buffer: config.audit_buffer,
            daemon_shutdown_request: config.daemon_shutdown_request,
            fatal_control_path: config.fatal_control_path,
            shutdown_flag: config.shutdown_flag.clone(),
            fortress_id: config.fortress_id,
            pinned_public_key: config.pinned_public_key,
            decision_engine: config.decision_engine,
            wal_writer: config.wal_writer,
            producer_signer: config.producer_signer,
            live_status: config.live_status,
            trusted_service_uid: config.trusted_service_uid,
            mutation_cancel,
            runtime_health: config.runtime_health,
            wal_control_progress: config.wal_control_progress,
            drain_recovery_only: config.drain_recovery_only,
            admissions: Arc::new(Mutex::new(AdmissionState::default())),
        });

        let accept_thread = std::thread::Builder::new()
            .name("castle-wall-ipc-accept".to_string())
            .spawn(move || run_accept_loop(listener, server_state))
            .map_err(|err| IpcServerError::ListenerConfig(err.to_string()))?;

        Ok(Self {
            accept_thread: Some(accept_thread),
            socket_path,
            shutdown_flag,
            decision_engine,
            socket_identity,
        })
    }

    /// Composition-root inspection: production boot and tests use this to prove
    /// IPC holds the exact same decision engine as watcher/evaluation.
    pub(crate) fn decision_engine(&self) -> &Arc<DecisionEngine> {
        &self.decision_engine
    }

    pub fn stop_and_join(mut self) {
        self.decision_engine
            .mutation_cancel_flag()
            .store(true, Ordering::SeqCst);
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        remove_owned_socket(&self.socket_path, self.socket_identity);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.decision_engine
            .mutation_cancel_flag()
            .store(true, Ordering::SeqCst);
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        remove_owned_socket(&self.socket_path, self.socket_identity);
    }
}

/// Shared between accept loop and per-connection handlers.
struct ServerState {
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    daemon_shutdown_request: Arc<AtomicBool>,
    fatal_control_path: Arc<AtomicBool>,
    shutdown_flag: Arc<AtomicBool>,
    fortress_id: String,
    pinned_public_key: Vec<u8>,
    decision_engine: Arc<DecisionEngine>,
    wal_writer: Option<Arc<Mutex<WalWriter>>>,
    producer_signer: Option<Arc<ProducerSigner>>,
    live_status: Arc<LiveStatus>,
    trusted_service_uid: u32,
    mutation_cancel: Arc<AtomicBool>,
    runtime_health: Arc<RuntimeHealthView>,
    wal_control_progress: Arc<AtomicUsize>,
    drain_recovery_only: Arc<AtomicBool>,
    admissions: Arc<Mutex<AdmissionState>>,
}

struct WalProgressGuard(Arc<AtomicUsize>);

impl WalProgressGuard {
    fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for WalProgressGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Evidence authority scoped to one authenticated IPC connection. An ACK may
/// only retire WAL entries that this same connection actually received. It is
/// intentionally not shared across connections: possession of the service key
/// does not turn a guessed sequence number into proof of durable delivery.
#[derive(Default)]
struct ConnectionDrainState {
    served_sequences: BTreeSet<u64>,
    last_settled_seq: Option<u64>,
}

impl ConnectionDrainState {
    fn observe_response(&mut self, response: &IpcMessage) {
        if let IpcMessage::AuditDrainResponse {
            events,
            error: None,
            ..
        } = response
        {
            // Keep exact authority, not a high-water mark: a non-zero cursor
            // can legitimately return seq 102 without ever serving 101.
            // Bound per-connection memory. Forgetting old authority is safe;
            // the client can re-drain to obtain it again.
            if self.served_sequences.len().saturating_add(events.len()) > MAX_AUDIT_DRAIN_EVENTS * 2
            {
                self.served_sequences.clear();
            }
            for event in events {
                self.served_sequences.insert(event.seq);
            }
        }
    }

    fn authorizes_ack(&self, seq: u64) -> bool {
        self.served_sequences.contains(&seq)
            && self.last_settled_seq.map_or(true, |settled| seq > settled)
    }

    fn consume_ack(&mut self, seq: u64) {
        self.served_sequences.retain(|served| *served > seq);
        self.last_settled_seq = Some(seq);
    }
}

#[derive(Default)]
struct AdmissionState {
    active_by_uid: HashMap<u32, usize>,
    untrusted_active: usize,
    attempts_by_uid: HashMap<u32, VecDeque<Instant>>,
}

struct AdmissionLease {
    state: Arc<Mutex<AdmissionState>>,
    uid: u32,
    trusted: bool,
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(active) = state.active_by_uid.get_mut(&self.uid) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    state.active_by_uid.remove(&self.uid);
                }
            }
            if !self.trusted {
                state.untrusted_active = state.untrusted_active.saturating_sub(1);
            }
        }
    }
}

impl ServerState {
    fn admit(&self, uid: u32) -> Result<AdmissionLease, &'static str> {
        let trusted = uid == self.trusted_service_uid;
        let now = Instant::now();
        let mut state = self
            .admissions
            .lock()
            .map_err(|_| "admission_state_poisoned")?;
        let active_uids: Vec<u32> = state.active_by_uid.keys().copied().collect();
        state.attempts_by_uid.retain(|tracked_uid, attempts| {
            while attempts
                .front()
                .is_some_and(|time| now.duration_since(*time) >= PREAUTH_RATE_WINDOW)
            {
                attempts.pop_front();
            }
            !attempts.is_empty() || active_uids.contains(tracked_uid)
        });
        if !trusted
            && !state.attempts_by_uid.contains_key(&uid)
            && state.attempts_by_uid.len() >= MAX_TRACKED_UID_RATE_BUCKETS
        {
            return Err("uid_rate_bucket_capacity_exceeded");
        }
        {
            let attempts = state.attempts_by_uid.entry(uid).or_default();
            let rate_limit = if trusted {
                MAX_PREAUTH_ATTEMPTS_PER_TRUSTED_UID
            } else {
                MAX_PREAUTH_ATTEMPTS_PER_UNTRUSTED_UID
            };
            if attempts.len() >= rate_limit {
                return Err("per_uid_preauth_rate_exceeded");
            }
        }
        let active_for_uid = state.active_by_uid.get(&uid).copied().unwrap_or(0);
        let active_limit = if trusted {
            MAX_PREAUTH_PER_TRUSTED_UID
        } else {
            MAX_PREAUTH_PER_UNTRUSTED_UID
        };
        if active_for_uid >= active_limit {
            return Err("per_uid_preauth_active_exceeded");
        }
        if !trusted
            && state.untrusted_active
                >= MAX_ACTIVE_CONNECTIONS.saturating_sub(RESERVED_TRUSTED_CONNECTIONS)
        {
            return Err("trusted_service_capacity_reserved");
        }
        let total: usize = state.active_by_uid.values().sum();
        if total >= MAX_ACTIVE_CONNECTIONS {
            return Err("global_connection_limit_reached");
        }
        state.attempts_by_uid.entry(uid).or_default().push_back(now);
        *state.active_by_uid.entry(uid).or_default() += 1;
        if !trusted {
            state.untrusted_active += 1;
        }
        Ok(AdmissionLease {
            state: Arc::clone(&self.admissions),
            uid,
            trusted,
        })
    }
}

impl ServerState {
    fn append_audit(&self, op: &str, detail: &str) {
        // IPC diagnostics must never make teardown wait behind a ring-buffer
        // holder. Critical mutation receipts use DecisionEngine's required WAL
        // path; this best-effort diagnostic surface is deliberately try-only.
        if let Ok(mut buf) = self.audit_buffer.try_lock() {
            buf.append(PendingAuditEvent {
                event_canonical_json: format!(
                    "{{\"layer\":\"{}\",\"operation\":\"{}\",\"schema_version\":{},\"fortress_id\":\"{}\",\"detail\":{}}}",
                    AUDIT_LAYER,
                    op,
                    SCHEMA_VERSION_V1,
                    self.fortress_id,
                    serde_json::to_string(detail).unwrap_or_else(|_| "\"\"".to_string()),
                ),
                captured_at: SystemTime::now(),
                // Every IPC append_audit emit is a control-plane event
                // (audit-truncate, manifest register/revoke, handshake
                // outcomes, IPC failure cases). All map to one of
                // "audit truncate / key wrap / recovery / panic" per
                // scope-lock §8 and must survive ring-buffer saturation
                // (full-sweep #76).
                critical: true,
            });
        }
    }
}

struct ConnectionHandler {
    /// Duplicate of the handler's stream. `shutdown(Both)` affects the shared
    /// socket and wakes a handler blocked in read or write.
    interrupt: UnixStream,
    thread: JoinHandle<()>,
}

fn reap_finished_handlers(handlers: &mut Vec<ConnectionHandler>) {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].thread.is_finished() {
            let handler = handlers.swap_remove(index);
            let _ = handler.thread.join();
        } else {
            index += 1;
        }
    }
}

fn interrupt_and_join_handlers(handlers: Vec<ConnectionHandler>) {
    for handler in &handlers {
        let _ = handler.interrupt.shutdown(std::net::Shutdown::Both);
    }
    // The IPC component cannot report released while a handler still owns or
    // can reacquire a manifest/WAL resource. The mutation fence and stream
    // shutdown make normal exits prompt; systemd remains the outer bound for
    // an uninterruptible kernel operation, without letting daemon teardown
    // finish while a detached control worker still owns a resource.
    for handler in handlers {
        let _ = handler.thread.join();
    }
}

fn run_accept_loop(listener: UnixListener, state: Arc<ServerState>) {
    let mut handlers = Vec::new();
    loop {
        reap_finished_handlers(&mut handlers);
        if state.shutdown_flag.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Close the accept-after-stop race: a connection accepted in the
                // same scheduler window as shutdown is never handed to a handler.
                if state.shutdown_flag.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    break;
                }
                let peer_uid = match peer_uid_for_stream(&stream) {
                    Ok(uid) => uid,
                    Err(err) => {
                        state.append_audit("ipc_peer_credential_rejected", &err.to_string());
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                };
                let admission = match state.admit(peer_uid) {
                    Ok(lease) => lease,
                    Err(reason) => {
                        state.append_audit(
                            "ipc_preauth_admission_rejected",
                            &format!("uid={peer_uid} reason={reason}"),
                        );
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                };
                // SO_PEERCRED is an authorization factor, not merely quota
                // metadata. Keep the untrusted admission bookkeeping above so
                // repeated same-group probes remain rate bounded, but never let
                // a mismatched kernel UID reach the signing challenge or any
                // control method even if it possesses the pinned private key.
                if !admission.trusted {
                    state.append_audit(
                        "ipc_peer_uid_rejected",
                        &format!(
                            "expected_uid={} got_uid={peer_uid}",
                            state.trusted_service_uid
                        ),
                    );
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                if handlers.len() >= MAX_ACTIVE_CONNECTIONS {
                    state.append_audit("ipc_connection_limit_reached", "tracked handler limit");
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let interrupt = match stream.try_clone() {
                    Ok(clone) => clone,
                    Err(err) => {
                        state.append_audit("ipc_conn_track_failed", &err.to_string());
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                };
                let handler_state = Arc::clone(&state);
                match std::thread::Builder::new()
                    .name("castle-wall-ipc-conn".to_string())
                    .spawn(move || {
                        let _admission = admission;
                        handle_connection(stream, handler_state)
                    }) {
                    Ok(thread) => handlers.push(ConnectionHandler { interrupt, thread }),
                    Err(err) => {
                        state.append_audit("ipc_conn_spawn_failed", &err.to_string());
                        let _ = interrupt.shutdown(std::net::Shutdown::Both);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(err) => {
                state.append_audit("ipc_accept_failed", &err.to_string());
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
        }
    }
    // This is the single connection-lifecycle join point. It runs for explicit
    // stop, Drop, and boot rollback because all paths join the accept thread.
    interrupt_and_join_handlers(handlers);
}

fn handle_connection(mut stream: UnixStream, state: Arc<ServerState>) {
    if state.shutdown_flag.load(Ordering::SeqCst) {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return;
    }
    if let Err(err) = stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT)) {
        state.append_audit("ipc_conn_setup_failed", &err.to_string());
        return;
    }
    if let Err(err) = stream.set_write_timeout(Some(CONNECTION_IDLE_TIMEOUT)) {
        state.append_audit("ipc_conn_setup_failed", &err.to_string());
        return;
    }

    // Run the handshake under a tight deadline. If it doesn't complete in
    // HANDSHAKE_TIMEOUT we drop the connection and audit it.
    //
    // Hoist `buf` to handle_connection scope so any bytes the client sent
    // immediately after the handshake response (i.e., the first request
    // frame batched into the same kernel read) survive into the dispatch
    // loop. perform_handshake consumes one frame and leaves the rest in
    // place.
    let nonce = generate_challenge_nonce();
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let identity = match perform_handshake(&mut stream, &nonce, &state, &mut buf) {
        Ok(id) => id,
        Err(err) => {
            state.append_audit("ipc_handshake_rejected", &format!("{:?}", err));
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };

    if state.shutdown_flag.load(Ordering::SeqCst) {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return;
    }

    state.append_audit(
        "ipc_handshake_accepted",
        &format!(
            "fortress_id={},signing_key_id={},peer_protocol_version={},peer_capabilities={}",
            identity.fortress_id,
            identity.signing_key_id,
            identity
                .peer_protocol_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "absent".to_string()),
            if identity.peer_capabilities.is_empty() {
                "none".to_string()
            } else {
                identity.peer_capabilities.join("|")
            }
        ),
    );

    // Reset the socket-level read timeout from HANDSHAKE_TIMEOUT (used to
    // bound a misbehaving client during auth) back to the post-auth idle
    // budget. Without this the post-handshake loop would inherit the
    // 5-second auth deadline and drop legitimate idle connections.
    if let Err(err) = stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT)) {
        state.append_audit("ipc_post_handshake_timeout_reset_failed", &err.to_string());
        return;
    }
    let mut drain_state = ConnectionDrainState::default();
    loop {
        if state.shutdown_flag.load(Ordering::SeqCst) {
            return;
        }
        match read_one_frame(&mut stream, &mut buf, CONNECTION_IDLE_TIMEOUT) {
            Ok(Some(body)) => {
                // A frame may arrive in the same scheduler window as stop. Do
                // not begin a new control mutation after the server stop flag.
                if state.shutdown_flag.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                let envelope = match parse_envelope(&body) {
                    Ok(env) => env,
                    Err(err) => {
                        state.append_audit("ipc_message_invalid", &err);
                        return;
                    }
                };
                match dispatch(&envelope, &state, &identity, &mut drain_state) {
                    Some(reply_envelope) => {
                        if let Err(err) = write_envelope(&mut stream, &reply_envelope) {
                            state.append_audit("ipc_write_failed", &err);
                            return;
                        }
                    }
                    None => continue,
                }
            }
            Ok(None) => return,
            Err(err) => {
                state.append_audit("ipc_read_failed", &err);
                return;
            }
        }
    }
}

fn perform_handshake(
    stream: &mut UnixStream,
    nonce: &[u8; CHALLENGE_NONCE_BYTES],
    state: &Arc<ServerState>,
    buf: &mut Vec<u8>,
) -> Result<HandshakeIdentity, HandshakeError> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|err| HandshakeError::Io(err.to_string()))?;

    let challenge = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.handshake_challenge", IPC_NAMESPACE),
        params: IpcMessage::HandshakeChallenge {
            nonce_b64url: encode_nonce_b64url(nonce),
            // Advertise what this daemon can do BEFORE the peer commits to a
            // behavior. A consumer that sees no version/capabilities is talking
            // to a pre-v2 daemon and must not assume any of them.
            protocol_version: Some(crate::ipc::messages::IPC_PROTOCOL_VERSION),
            capabilities: crate::ipc::messages::CAPABILITIES
                .iter()
                .map(|c| (*c).to_string())
                .collect(),
        },
    };
    write_envelope(stream, &challenge).map_err(HandshakeError::Io)?;

    let body = match read_one_frame(stream, buf, HANDSHAKE_TIMEOUT) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(HandshakeError::ClientClosed),
        Err(err) => return Err(HandshakeError::Io(err)),
    };
    let envelope = parse_envelope(&body).map_err(HandshakeError::ParseEnvelope)?;
    let response_message = envelope.params;
    verify_handshake_response(
        &response_message,
        nonce,
        &state.fortress_id,
        &state.pinned_public_key,
    )
    .map_err(HandshakeError::Auth)
}

#[derive(Debug)]
#[allow(dead_code)] // fields surfaced via Debug into the audit log on failure
enum HandshakeError {
    Io(String),
    ClientClosed,
    ParseEnvelope(String),
    Auth(AuthError),
}

/// Handle an authenticated `policy_reload_request` as one serialized
/// transaction: verify/stage the exact candidate, durably authorize its exact
/// signature/count through `DecisionEngine::append_control_audit`, then commit
/// the owned staged snapshot. Any verification or audit failure returns
/// `ok:false` with the prior policy still live.
fn handle_policy_reload(request_id: &str, state: &ServerState) -> IpcMessage {
    match state
        .decision_engine
        .reload_manifest_authorized_cancellable(
            "ipc_policy_reload_authorized",
            &format!("request_id={request_id}"),
            &state.mutation_cancel,
            CONTROL_OPERATION_BUDGET,
        ) {
        Ok(summary) => IpcMessage::PolicyReloadResponse {
            request_id: request_id.to_string(),
            ok: true,
            loaded_manifest_signature_b64url: Some(summary.signature_b64url),
            loaded_rule_count: summary.rule_count,
            error: None,
        },
        Err(err) => {
            // F-2 disposition: keep prior policy in force; surface the error
            // to Sanctuary main; emit an audit so the operator dashboard can
            // surface a banner.
            let reason = err.to_string();
            state.append_audit("manifest_verify_failed_kept_prior", &reason);
            let kept_prior = state
                .decision_engine
                .manifest_store()
                .and_then(|store| store.try_lock().ok())
                .and_then(|guard| {
                    guard
                        .current()
                        .map(|c| (c.manifest_signature_b64url.clone(), c.rule_count))
                });
            IpcMessage::PolicyReloadResponse {
                request_id: request_id.to_string(),
                ok: false,
                loaded_manifest_signature_b64url: kept_prior.as_ref().map(|p| p.0.clone()),
                loaded_rule_count: kept_prior.map(|p| p.1).unwrap_or(0),
                error: Some(reason),
            }
        }
    }
}

fn handle_policy_bundle_publish(
    request_id: &str,
    manifest_b64url: &str,
    wire_rules: &[crate::ipc::messages::PolicyBundleRule],
    state: &ServerState,
    peer: &HandshakeIdentity,
) -> IpcMessage {
    const MAX_PUBLISHED_RULES: usize = 1_024;
    const MAX_PUBLISH_ENCODED_BYTES: usize =
        crate::manifest::store::MAX_PUBLISH_BUNDLE_BYTES.div_ceil(3) * 4;
    let response = |ok, signature, count, error| IpcMessage::PolicyBundlePublishResponse {
        request_id: request_id.to_string(),
        ok,
        loaded_manifest_signature_b64url: signature,
        loaded_rule_count: count,
        error,
    };
    let refuse = |reason: String| {
        let _ = state.decision_engine.append_control_audit_bounded(
            "ipc_policy_bundle_publish_refused",
            &reason,
            CONTROL_OPERATION_BUDGET,
        );
        let kept = state
            .decision_engine
            .manifest_store()
            .and_then(|store| store.try_lock().ok())
            .and_then(|guard| {
                guard
                    .current()
                    .map(|value| (value.manifest_signature_b64url.clone(), value.rule_count))
            });
        response(
            false,
            kept.as_ref().map(|value| value.0.clone()),
            kept.map(|value| value.1).unwrap_or(0),
            Some(reason),
        )
    };
    if !peer.accepts(CAP_POLICY_BUNDLE_PUBLISH) {
        return refuse(
            "authenticated peer did not bind policy publication capability into its handshake"
                .to_string(),
        );
    }
    if wire_rules.len() > MAX_PUBLISHED_RULES {
        return refuse(format!(
            "policy bundle has {} rules (cap {MAX_PUBLISHED_RULES})",
            wire_rules.len()
        ));
    }
    let encoded_total = wire_rules
        .iter()
        .fold(manifest_b64url.len(), |total, rule| {
            total
                .saturating_add(rule.file.len())
                .saturating_add(rule.body_b64url.len())
        });
    if encoded_total > MAX_PUBLISH_ENCODED_BYTES {
        return refuse("encoded policy bundle exceeds publication bound".to_string());
    }
    if manifest_b64url.len() > MAX_PUBLISH_ENCODED_BYTES {
        return refuse("encoded manifest exceeds policy publication bound".to_string());
    }
    let manifest =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(manifest_b64url.as_bytes()) {
            Ok(value) => value,
            Err(err) => return refuse(format!("manifest base64url decode failed: {err}")),
        };
    let mut rules = Vec::with_capacity(wire_rules.len());
    for rule in wire_rules {
        if rule.file.is_empty() || rule.file.len() > 255 {
            return refuse("rule filename is outside the bounded component grammar".to_string());
        }
        if rule.body_b64url.len() > MAX_PUBLISH_ENCODED_BYTES {
            return refuse("encoded rule exceeds policy publication bound".to_string());
        }
        let body = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(rule.body_b64url.as_bytes())
        {
            Ok(value) => value,
            Err(err) => return refuse(format!("rule base64url decode failed: {err}")),
        };
        rules.push((rule.file.clone(), body));
    }
    match state
        .decision_engine
        .publish_manifest_bundle_authorized_cancellable(
            &manifest,
            &rules,
            &format!("request_id={request_id} peer_key={}", peer.signing_key_id),
            &state.mutation_cancel,
            CONTROL_OPERATION_BUDGET,
        ) {
        Ok(summary) => {
            if let Err(err) = state.decision_engine.append_control_audit_bounded(
                "ipc_policy_bundle_publish_activated",
                &format!(
                    "request_id={request_id} signature={} rules={}",
                    summary.signature_b64url, summary.rule_count
                ),
                CONTROL_OPERATION_BUDGET,
            ) {
                // The pointer and high-water state are already durable. Do not
                // keep serving a green process that cannot durably record the
                // corresponding activation: withdraw the mutation lane and ask
                // the outer daemon/systemd supervision path to restart. Restart
                // reclaims the fully verified pointed generation.
                withdraw_after_activation_audit_failure(state);
                return response(
                    false,
                    Some(summary.signature_b64url),
                    summary.rule_count,
                    Some(format!(
                        "policy activated but durable success audit failed; runtime must remain non-green: {err}"
                    )),
                );
            }
            response(
                true,
                Some(summary.signature_b64url),
                summary.rule_count,
                None,
            )
        }
        Err(err) => {
            if err.requires_supervised_restart() {
                withdraw_after_activation_audit_failure(state);
            }
            refuse(err.to_string())
        }
    }
}

fn withdraw_after_activation_audit_failure(state: &ServerState) {
    // Fatal classification is published first. The outer supervisor checks it
    // before the ordinary shutdown flag and performs the normal ordered
    // enforcement-before-IPC teardown. Stopping IPC here would invert that
    // order and race away the evidence response.
    state.fatal_control_path.store(true, Ordering::SeqCst);
    state.mutation_cancel.store(true, Ordering::SeqCst);
    state.daemon_shutdown_request.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy)]
enum ControlLockError {
    Cancelled,
    Timeout,
    Poisoned,
}

impl std::fmt::Display for ControlLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "daemon shutdown cancelled the operation",
            Self::Timeout => "WAL lock acquisition exceeded the control-operation budget",
            Self::Poisoned => "WAL lock is poisoned",
        })
    }
}

/// Acquire a control-path mutex without an unbounded teardown wait. Unlike a
/// raw `try_lock`, ordinary append/fsync contention is retried until the bounded
/// deadline, and every terminal outcome is explicit on the wire.
fn lock_control<'a, T>(
    mutex: &'a Mutex<T>,
    cancelled: &AtomicBool,
    budget: Duration,
) -> Result<MutexGuard<'a, T>, ControlLockError> {
    let deadline = Instant::now() + budget;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err(ControlLockError::Cancelled);
        }
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(ControlLockError::Poisoned),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::WouldBlock) => return Err(ControlLockError::Timeout),
        }
    }
}

impl From<&ControlLockError> for DrainErrorClass {
    /// The ONE classification of a control-lock outcome, stated where the error
    /// type lives so a new variant cannot be added without answering this.
    ///
    /// A timeout means another holder had the lock for longer than
    /// `CONTROL_OPERATION_BUDGET` — contention under load, which clears.
    /// `Cancelled` means the daemon is stopping, which clears on the next boot.
    /// `Poisoned` means a holder PANICKED while mutating WAL state, which does
    /// not clear for this process. Collapsing the three is what turned an
    /// ordinary `systemctl stop` or a busy 2-second window into a permanently
    /// not-armed wall with a durable transport-fault record.
    fn from(err: &ControlLockError) -> Self {
        match err {
            ControlLockError::Timeout | ControlLockError::Cancelled => Self::Retryable,
            ControlLockError::Poisoned => Self::Terminal,
        }
    }
}

impl From<&crate::audit::WalError> for DrainErrorClass {
    fn from(err: &crate::audit::WalError) -> Self {
        use crate::audit::WalError;
        match err {
            WalError::Cancelled
            | WalError::OperationBudgetExceeded
            | WalError::OperationInProgress { .. } => Self::Retryable,
            WalError::Io { .. }
            | WalError::Parse { .. }
            | WalError::ChainBroken { .. }
            | WalError::MalformedPriorHash { .. }
            | WalError::RenameFailed { .. }
            | WalError::CapacityExceeded { .. }
            | WalError::Poisoned { .. } => Self::Terminal,
        }
    }
}

fn audit_drain_error(
    request_id: &str,
    after_seq: Option<u64>,
    overflow: Option<u64>,
    error: impl Into<String>,
    class: DrainErrorClass,
) -> IpcMessage {
    IpcMessage::AuditDrainResponse {
        request_id: request_id.to_string(),
        events: Vec::new(),
        next_after_seq: after_seq,
        more_pending: false,
        wal_overflow_count: overflow,
        error: Some(error.into()),
        error_class: Some(class.as_str().to_string()),
    }
}

/// Handle an `audit_drain_request`: snapshot WAL entries strictly after
/// `after_seq`, capped at `max_events`. Returns a typed response carrying
/// the events plus a `more_pending` flag so Sanctuary main knows when to
/// issue another request.
fn handle_audit_drain(
    request_id: &str,
    after_seq: Option<u64>,
    max_events: u32,
    state: &ServerState,
) -> IpcMessage {
    let wal = match state.wal_writer.as_ref() {
        Some(w) => w,
        None => {
            // TERMINAL: a daemon with no WAL will never produce evidence, and no
            // amount of retrying changes that.
            return audit_drain_error(
                request_id,
                after_seq,
                None,
                "WAL is not wired",
                DrainErrorClass::Terminal,
            );
        }
    };
    // Combined ring-buffer overflow + WAL drain cap surface; the in-memory
    // ring buffer's overflow counter feeds Sanctuary main via the response
    // so the operator dashboard can surface "N audit events lost during
    // Sanctuary main downtime" per scope-lock §8.
    if state.mutation_cancel.load(Ordering::SeqCst) {
        // RETRYABLE: shutdown is an ordinary lifecycle event. Nothing was
        // delivered and nothing was lost; the next boot serves the same WAL.
        // Classifying this terminal made every `systemctl stop` with an
        // in-flight drain write a permanent `castle_wall_drain_failed` record.
        return audit_drain_error(
            request_id,
            after_seq,
            None,
            "daemon is stopping",
            DrainErrorClass::Retryable,
        );
    }
    let overflow = state
        .audit_buffer
        .try_lock()
        .ok()
        .map(|b| b.overflow_count());
    let max_for_snapshot = usize::try_from(max_events.max(1))
        .unwrap_or(MAX_AUDIT_DRAIN_EVENTS)
        .min(MAX_AUDIT_DRAIN_EVENTS);
    // Read one look-ahead entry so `more_pending` is evidence-backed even when
    // the caller requested more than the daemon ceiling.
    let snapshot_probe_limit = max_for_snapshot.saturating_add(1);
    let _progress = WalProgressGuard::enter(&state.wal_control_progress);
    let snapshot = match lock_control(wal, &state.mutation_cancel, CONTROL_OPERATION_BUDGET) {
        Ok(mut w) => {
            match w.snapshot_after_bounded(
                after_seq,
                snapshot_probe_limit,
                &state.mutation_cancel,
                CONTROL_OPERATION_BUDGET,
            ) {
                Ok(events) => events,
                Err(err) => {
                    let class = DrainErrorClass::from(&err);
                    state.append_audit("audit_drain_snapshot_failed", &err.to_string());
                    return audit_drain_error(
                        request_id,
                        after_seq,
                        overflow,
                        format!("WAL snapshot failed: {err}"),
                        class,
                    );
                }
            }
        }
        Err(err) => {
            // Class comes from the lock outcome, not from the formatted string:
            // a 2-second contention timeout retries, a poisoned lock does not.
            let class = DrainErrorClass::from(&err);
            state.append_audit(
                "audit_drain_wal_lock_failed",
                &format!("{err} (class={})", class.as_str()),
            );
            return audit_drain_error(
                request_id,
                after_seq,
                overflow,
                format!("WAL lock failed: {err}"),
                class,
            );
        }
    };
    let snapshot_has_more = snapshot.len() > max_for_snapshot;
    let sizing_envelope = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_response", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainResponse {
            request_id: request_id.to_string(),
            events: Vec::new(),
            // Worst-sized scalar spellings make the base an upper bound. Exact
            // event JSON lengths and commas are added below.
            next_after_seq: Some(u64::MAX),
            // `false` is one byte longer than `true`; size against the longer
            // spelling so this envelope remains an upper bound on either arm.
            more_pending: false,
            wal_overflow_count: Some(u64::MAX),
            error: None,
            error_class: None,
        },
    };
    let mut encoded_body_bytes = match serde_json::to_vec(&sizing_envelope) {
        Ok(bytes) => bytes.len(),
        Err(err) => {
            return audit_drain_error(
                request_id,
                after_seq,
                overflow,
                format!("audit drain response sizing failed: {err}"),
                DrainErrorClass::Terminal,
            )
        }
    };
    let mut byte_limited = false;
    let mut events: Vec<AuditDrainEvent> = Vec::new();
    for e in snapshot.into_iter().take(max_for_snapshot) {
        // Slice L1: sign the event over `seq ‖ timestamp ‖ canonical-bytes`
        // with the daemon-held producer key, so the consumer can prove the
        // event came from the enforcing daemon (not an in-process forger)
        // and reject replays of past signed events. When no signer is
        // wired the fields stay None and the consumer falls back to the
        // documented channel-authenticity basis.
        let (producer_signature_b64url, producer_key_id) = match state.producer_signer.as_ref() {
            Some(signer) => (
                Some(signer.sign_event(&e.event_canonical_json, e.captured_at_unix_ms, e.seq)),
                Some(crate::constants::PRODUCER_SIG_KEY_ID_V1.to_string()),
            ),
            None => (None, None),
        };
        let wire_event = AuditDrainEvent {
            seq: e.seq,
            captured_at_unix_ms: e.captured_at_unix_ms,
            prior_sha256_hex: e.prior_sha256_hex,
            event_canonical_json: e.event_canonical_json,
            critical: e.critical,
            producer_signature_b64url,
            producer_key_id,
        };
        let event_bytes = match serde_json::to_vec(&wire_event) {
            Ok(bytes) => bytes.len(),
            Err(err) => {
                return audit_drain_error(
                    request_id,
                    after_seq,
                    overflow,
                    format!("audit drain event serialization failed: {err}"),
                    DrainErrorClass::Terminal,
                )
            }
        };
        let separator_bytes = usize::from(!events.is_empty());
        let projected = encoded_body_bytes
            .checked_add(separator_bytes)
            .and_then(|value| value.checked_add(event_bytes));
        if projected.map_or(true, |value| value > MAX_OUTBOUND_BODY_BYTES) {
            if events.is_empty() {
                return audit_drain_error(
                        request_id,
                        after_seq,
                        overflow,
                        format!(
                            "first pending audit event exceeds response ceiling of {MAX_OUTBOUND_BODY_BYTES} bytes"
                        ),
                        DrainErrorClass::Terminal,
                    );
            }
            byte_limited = true;
            break;
        }
        encoded_body_bytes = projected.expect("checked above");
        events.push(wire_event);
    }
    let more_pending = snapshot_has_more || byte_limited;
    let next_after_seq = events.last().map(|e| e.seq).or(after_seq);
    state.append_audit("audit_drain_served", &format!("count={}", events.len()));
    IpcMessage::AuditDrainResponse {
        request_id: request_id.to_string(),
        events,
        next_after_seq,
        more_pending,
        wal_overflow_count: overflow,
        error: None,
        // No error, so no class. `error_class` without `error` would be a
        // meaningless field the consumer might act on.
        error_class: None,
    }
}

/// Handle an `audit_drain_ack`: truncate the WAL through `last_acked_seq`.
/// On success the ring-buffer overflow counter is reset because Sanctuary
/// main has confirmed durable receipt of every event up to and including
/// the ack point.
fn handle_audit_drain_ack(
    request_id: &str,
    last_acked_seq: u64,
    state: &ServerState,
    connection: &mut ConnectionDrainState,
) -> IpcMessage {
    // `last_acked_seq` is echoed from the REQUEST on every arm, success and
    // failure alike. The consumer refuses any reply whose seq differs from the
    // one it asked about, so this must never be recomputed from daemon-side
    // state; must match the equality check in `IpcClient.sendDrainAck`
    // (`server/src/castle-wall/runtime/ipc-client.ts`).
    let response =
        |ok, truncated_entries, error: Option<String>, class: Option<DrainErrorClass>| {
            IpcMessage::AuditDrainAckResponse {
                request_id: request_id.to_string(),
                ok,
                last_acked_seq,
                truncated_entries,
                error,
                error_class: class.map(|c| c.as_str().to_string()),
            }
        };
    if !connection.authorizes_ack(last_acked_seq) {
        state.append_audit(
            "audit_drain_ack_unserved_seq",
            &format!(
                "request_id={request_id},last_acked_seq={last_acked_seq},served_sequences={:?}",
                connection.served_sequences
            ),
        );
        return response(
            false,
            0,
            Some(
                "ACK sequence was not served on this authenticated connection or was not monotonic"
                    .to_string(),
            ),
            Some(DrainErrorClass::Terminal),
        );
    }
    if state.mutation_cancel.load(Ordering::SeqCst) {
        // RETRYABLE. The consumer already holds these events durably (it
        // advances its own chain state BEFORE acking), so a refused truncation
        // during shutdown costs daemon WAL space and loses nothing. This arm
        // fires on EVERY `systemctl stop` with an ack in flight; treating it as
        // terminal turned a routine restart into a permanent not-armed wall.
        return response(
            false,
            0,
            Some("daemon is stopping".to_string()),
            Some(DrainErrorClass::Retryable),
        );
    }
    let wal = match state.wal_writer.as_ref() {
        Some(w) => w,
        None => {
            state.append_audit("audit_drain_ack_wal_unwired", request_id);
            return response(
                false,
                0,
                Some("WAL is not wired".to_string()),
                Some(DrainErrorClass::Terminal),
            );
        }
    };
    let _progress = WalProgressGuard::enter(&state.wal_control_progress);
    match lock_control(wal, &state.mutation_cancel, CONTROL_OPERATION_BUDGET) {
        Ok(mut w) => match w.truncate_through_seq_bounded(
            last_acked_seq,
            &state.mutation_cancel,
            CONTROL_OPERATION_BUDGET,
        ) {
            Ok(dropped) => {
                connection.consume_ack(last_acked_seq);
                state.append_audit("audit_drain_ack_truncated", &format!("dropped={}", dropped));
                response(true, dropped, None, None)
            }
            Err(err) => {
                let class = DrainErrorClass::from(&err);
                state.append_audit("audit_drain_ack_truncate_failed", &err.to_string());
                response(
                    false,
                    0,
                    Some(format!("WAL truncate failed: {err}")),
                    Some(class),
                )
            }
        },
        Err(err) => {
            let class = DrainErrorClass::from(&err);
            state.append_audit(
                "audit_drain_ack_wal_lock_failed",
                &format!("{err} (class={})", class.as_str()),
            );
            response(
                false,
                0,
                Some(format!("WAL lock failed: {err}")),
                Some(class),
            )
        }
    }
}

fn parse_envelope(body: &str) -> Result<MessageEnvelope, String> {
    serde_json::from_str(body).map_err(|err| err.to_string())
}

fn write_envelope(stream: &mut UnixStream, envelope: &MessageEnvelope) -> Result<(), String> {
    let body = serde_json::to_string(envelope).map_err(|err| err.to_string())?;
    if body.len() > MAX_OUTBOUND_BODY_BYTES {
        return Err(format!(
            "response exceeded maximum body size {MAX_OUTBOUND_BODY_BYTES} bytes"
        ));
    }
    let bytes = frame(&body);
    stream.write_all(&bytes).map_err(|err| err.to_string())
}

fn read_one_frame(
    stream: &mut UnixStream,
    buf: &mut Vec<u8>,
    deadline: Duration,
) -> Result<Option<String>, String> {
    let started = Instant::now();
    let mut chunk = [0u8; 4096];
    loop {
        match parse_frame(buf) {
            ParseStep::Complete {
                body,
                consumed_bytes,
            } => {
                buf.drain(..consumed_bytes);
                return Ok(Some(body));
            }
            ParseStep::NeedMore => {}
            ParseStep::Error { reason } => return Err(reason),
        }
        if started.elapsed() > deadline {
            return Err("read deadline exceeded".to_string());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                return Err("connection idle timeout".to_string())
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

/// Dispatch one request envelope; returns Some(reply) for request/response
/// messages, None for notifications.
fn dispatch(
    envelope: &MessageEnvelope,
    state: &ServerState,
    peer: &HandshakeIdentity,
    drain_state: &mut ConnectionDrainState,
) -> Option<MessageEnvelope> {
    if state.drain_recovery_only.load(Ordering::SeqCst) {
        match &envelope.params {
            IpcMessage::StatusRequest { .. }
            | IpcMessage::AuditDrainRequest { .. }
            | IpcMessage::AuditDrainAck { .. } => {}
            IpcMessage::PolicyReloadRequest { request_id, .. } => {
                return Some(MessageEnvelope {
                    jsonrpc: "2.0".to_string(),
                    method: format!("{}.policy_reload_response", IPC_NAMESPACE),
                    params: IpcMessage::PolicyReloadResponse {
                        request_id: request_id.clone(),
                        ok: false,
                        loaded_manifest_signature_b64url: None,
                        loaded_rule_count: 0,
                        error: Some("daemon is in authenticated WAL drain recovery".to_string()),
                    },
                });
            }
            IpcMessage::PolicyBundlePublishRequest { request_id, .. } => {
                return Some(MessageEnvelope {
                    jsonrpc: "2.0".to_string(),
                    method: format!("{}.policy_bundle_publish_response", IPC_NAMESPACE),
                    params: IpcMessage::PolicyBundlePublishResponse {
                        request_id: request_id.clone(),
                        ok: false,
                        loaded_manifest_signature_b64url: None,
                        loaded_rule_count: 0,
                        error: Some("daemon is in authenticated WAL drain recovery".to_string()),
                    },
                });
            }
            _ => return None,
        }
    }
    match &envelope.params {
        IpcMessage::StatusRequest { request_id } => {
            let status = state.live_status.snapshot();
            // READ the published observation; never probe from the IPC thread.
            // Three outcomes, kept DISTINCT on the wire:
            //   ready             -> a fresh positive proof; readiness may be asserted
            //   lost              -> a PROVEN loss; the runtime state is downgraded
            //   probe_unavailable -> INDETERMINATE (contention, deadline, staleness):
            //                        readiness is WITHHELD but no loss is asserted
            //   no_runtime        -> this daemon holds no kernel runtime at all
            // Collapsing `probe_unavailable` into `degraded` is the defect this
            // replaces: it made a healthy runtime flap under status polling.
            let health = state
                .runtime_health
                .read(crate::runtime_health::STATUS_FRESHNESS_WINDOW);
            let runtime_live = health.proves_ready();
            let proven_lost = matches!(health.state, RuntimeHealthState::Lost(_));
            // THREE-VALUED, for the same reason `runtime_health` is. A boolean
            // here folded contention, poisoning, and an unwired store into one
            // `false`, which the consumer read as a proven-degraded runtime and
            // acted on by tearing down drain + lifecycle. The store lock is
            // genuinely contended in normal operation: `decision.rs` takes it per
            // verdict, and an authorized reload holds it across manifest verify
            // plus a WAL fsync — precisely what the policy write before arming
            // triggers. A momentary reload must not stop a healthy host from
            // arming.
            let (manifest_state, loaded) = match state.decision_engine.manifest_store() {
                Some(store) => match store.try_lock() {
                    Ok(guard) => match guard.current() {
                        Some(manifest) => (
                            ManifestState::Ready,
                            Some((
                                manifest.manifest_signature_b64url.clone(),
                                manifest.rule_count,
                            )),
                        ),
                        // PROVEN empty (deny-by-default boot before the first
                        // successful reload). Distinct from "could not read":
                        // here `loaded_rule_count: 0` is the truth.
                        None => (ManifestState::Empty, None),
                    },
                    // INDETERMINATE. The companion count/signature below are
                    // meaningless in this arm and the consumer is required to
                    // ignore them; they still serialize because both are pre-v2
                    // wire fields that cannot become optional.
                    Err(TryLockError::WouldBlock) => (ManifestState::Unavailable, None),
                    // PROVEN failure: a holder panicked mid-mutation, so policy
                    // state is not trustworthy for this process.
                    Err(TryLockError::Poisoned(_)) => (ManifestState::Degraded, None),
                },
                None => (ManifestState::Unwired, None),
            };
            let reply = IpcMessage::StatusResponse {
                request_id: request_id.clone(),
                uptime_seconds: status.uptime_seconds,
                loaded_manifest_signature_b64url: loaded.as_ref().map(|value| value.0.clone()),
                loaded_rule_count: loaded.map(|value| value.1).unwrap_or(0),
                manifest_state: Some(manifest_state.as_str().to_string()),
                lifecycle_state: status.lifecycle_state.to_string(),
                // `degraded` is asserted ONLY on a PROVEN loss. An indeterminate
                // reading leaves the lifecycle state as-is and withholds the
                // readiness booleans below instead — absence of proof is reported
                // as absence (`runtime_health`), never manufactured into a
                // failure claim and never promoted to health.
                runtime_state: if status.kernel_runtime_ready && proven_lost {
                    "degraded".to_string()
                } else {
                    status.runtime_state.to_string()
                },
                // Both assertions require a FRESH positive proof, so an
                // indeterminate or stale observation reads as not-proven.
                kernel_runtime_ready: status.kernel_runtime_ready && runtime_live,
                enforcing: status.enforcing && runtime_live,
                no_wall_engaged: status.no_wall_engaged,
                // Capability `status_runtime_health`: the exact probe outcome and
                // its age, so a consumer can tell "not proven right now" from
                // "proven lost" instead of inferring one from the booleans.
                runtime_health: Some(health.state.as_str().to_string()),
                runtime_health_age_ms: health
                    .age
                    .map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX)),
            };
            Some(MessageEnvelope {
                jsonrpc: "2.0".to_string(),
                method: format!("{}.status_response", IPC_NAMESPACE),
                params: reply,
            })
        }
        IpcMessage::PolicyReloadRequest { request_id, .. } => {
            let reply = handle_policy_reload(request_id, state);
            Some(MessageEnvelope {
                jsonrpc: "2.0".to_string(),
                method: format!("{}.policy_reload_response", IPC_NAMESPACE),
                params: reply,
            })
        }
        IpcMessage::PolicyBundlePublishRequest {
            request_id,
            manifest_b64url,
            rules,
        } => {
            let reply =
                handle_policy_bundle_publish(request_id, manifest_b64url, rules, state, peer);
            Some(MessageEnvelope {
                jsonrpc: "2.0".to_string(),
                method: format!("{}.policy_bundle_publish_response", IPC_NAMESPACE),
                params: reply,
            })
        }
        IpcMessage::AuditDrainRequest {
            request_id,
            after_seq,
            max_events,
        } => {
            let reply = handle_audit_drain(request_id, *after_seq, *max_events, state);
            drain_state.observe_response(&reply);
            Some(MessageEnvelope {
                jsonrpc: "2.0".to_string(),
                method: format!("{}.audit_drain_response", IPC_NAMESPACE),
                params: reply,
            })
        }
        IpcMessage::AuditDrainAck {
            request_id,
            last_acked_seq,
        } => {
            // The ACK is APPLIED identically for every peer — truncation is a
            // daemon-side durability action, never something a capability
            // negotiation may skip. Only the REPLY is negotiated.
            let reply = handle_audit_drain_ack(request_id, *last_acked_seq, state, drain_state);
            if !peer.accepts(crate::ipc::messages::CAP_AUDIT_DRAIN_ACK_RESPONSE) {
                // Pre-v2 consumer: it sent a one-way notification and registered
                // no pending request for this id, so an unsolicited response
                // frame would at best be discarded and at worst be treated as a
                // protocol fault. Withhold it and record that this peer is
                // running on the legacy unconfirmed-ACK basis, which is weaker:
                // it cannot tell a refused truncation from an applied one.
                state.append_audit(
                    "ipc_audit_drain_ack_response_withheld_legacy_peer",
                    &format!(
                        "request_id={request_id},last_acked_seq={last_acked_seq},\
                         peer_protocol_version={}",
                        peer.peer_protocol_version
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "absent".to_string())
                    ),
                );
                return None;
            }
            Some(MessageEnvelope {
                jsonrpc: "2.0".to_string(),
                method: format!("{}.audit_drain_ack_response", IPC_NAMESPACE),
                params: reply,
            })
        }
        IpcMessage::HandshakeResponse { .. } | IpcMessage::HandshakeChallenge { .. } => {
            state.append_audit("ipc_post_handshake_handshake_message", "ignored");
            None
        }
        IpcMessage::DecisionResponse { request_id, .. } => {
            // Operator-decision arrival; the matching prompt path lands in
            // Checkpoint 3 alongside NFQUEUE bind. For now, acknowledge in
            // the audit log so reconnects can see drift.
            state.append_audit("ipc_decision_response_pending_checkpoint_3", request_id);
            None
        }
        IpcMessage::DecisionRequest { request_id, .. } => {
            // Sanctuary main should never originate a DecisionRequest; the
            // daemon is the originator (per scope-lock §5: prompts go
            // daemon -> main -> operator -> main -> daemon). Surface the
            // misuse but do not disconnect.
            state.append_audit("ipc_unexpected_decision_request", request_id);
            None
        }
        IpcMessage::AuditEmit { .. } | IpcMessage::AuditEmitMetricBatch { .. } => {
            // These are emitted by the daemon, not received. Surface the
            // unexpected direction.
            state.append_audit("ipc_unexpected_audit_emit_direction", "ignored");
            None
        }
        IpcMessage::AuditDrainResponse { .. } | IpcMessage::AuditDrainAckResponse { .. } => {
            state.append_audit("ipc_unexpected_response_direction", "audit_drain_response");
            None
        }
        IpcMessage::UnlockNotification { fortress_id, .. } => {
            state.append_audit("ipc_unlock_received", fortress_id);
            None
        }
        IpcMessage::LockNotification { fortress_id, .. } => {
            state.append_audit("ipc_lock_received", fortress_id);
            None
        }
        IpcMessage::StatusResponse { .. }
        | IpcMessage::PolicyReloadResponse { .. }
        | IpcMessage::PolicyBundlePublishResponse { .. } => {
            state.append_audit("ipc_unexpected_response_direction", "ignored");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    use tempfile::TempDir;

    fn test_decision_engine(
        fortress_id: &str,
        audit_buffer: &Arc<Mutex<AuditRingBuffer>>,
    ) -> Arc<DecisionEngine> {
        Arc::new(DecisionEngine::new(
            fortress_id.to_string(),
            None,
            None,
            Arc::clone(audit_buffer),
        ))
    }

    #[allow(dead_code)]
    fn fresh_state(fortress_id: &str, pk: Vec<u8>) -> Arc<ServerState> {
        let audit_buffer = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        Arc::new(ServerState {
            audit_buffer: Arc::clone(&audit_buffer),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: fortress_id.to_string(),
            pinned_public_key: pk,
            decision_engine: test_decision_engine(fortress_id, &audit_buffer),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            mutation_cancel: Arc::new(AtomicBool::new(false)),
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
            admissions: Arc::new(Mutex::new(AdmissionState::default())),
        })
    }

    #[test]
    fn missing_post_activation_receipt_withdraws_mutations_and_requests_restart() {
        let state = fresh_state("f", vec![0; 32]);
        assert!(!state.mutation_cancel.load(Ordering::SeqCst));
        assert!(!state.daemon_shutdown_request.load(Ordering::SeqCst));
        assert!(!state.fatal_control_path.load(Ordering::SeqCst));
        assert!(!state.shutdown_flag.load(Ordering::SeqCst));

        withdraw_after_activation_audit_failure(&state);

        assert!(state.mutation_cancel.load(Ordering::SeqCst));
        assert!(state.daemon_shutdown_request.load(Ordering::SeqCst));
        assert!(state.fatal_control_path.load(Ordering::SeqCst));
        assert!(
            !state.shutdown_flag.load(Ordering::SeqCst),
            "fatal withdrawal must leave IPC teardown to the ordered outer lifecycle"
        );
    }

    #[test]
    fn post_pointer_publication_failure_is_classified_for_supervised_restart() {
        let err = crate::decision::ManifestReloadAuthorizationError::Verify(
            crate::manifest::store::ManifestStoreError::PublicationCommitIndeterminate {
                source_message: "injected post-pointer durability failure".to_string(),
            },
        );
        assert!(err.requires_supervised_restart());

        let ordinary = crate::decision::ManifestReloadAuthorizationError::Verify(
            crate::manifest::store::ManifestStoreError::ManifestParse {
                path: std::path::PathBuf::from("manifest.json"),
                source_message: "injected pre-commit parse failure".to_string(),
            },
        );
        assert!(!ordinary.requires_supervised_restart());
    }

    fn run_handshake_client_thread(
        path: PathBuf,
        signing: SigningKey,
        fortress_id: String,
    ) -> std::thread::JoinHandle<Result<UnixStream, String>> {
        std::thread::spawn(move || -> Result<UnixStream, String> {
            // Connect with a small retry to give the server time to bind.
            let mut last_err = String::new();
            for _ in 0..50 {
                match UnixStream::connect(&path) {
                    Ok(mut stream) => {
                        let mut buf: Vec<u8> = Vec::with_capacity(4096);
                        let body = read_one_frame(&mut stream, &mut buf, Duration::from_secs(5))
                            .map_err(|e| format!("read challenge: {}", e))?
                            .ok_or_else(|| "server closed before challenge".to_string())?;
                        let envelope: MessageEnvelope =
                            serde_json::from_str(&body).map_err(|e| e.to_string())?;
                        let nonce_b64 = match envelope.params {
                            IpcMessage::HandshakeChallenge { nonce_b64url, .. } => nonce_b64url,
                            _ => return Err("expected HandshakeChallenge".to_string()),
                        };
                        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(nonce_b64.as_bytes())
                            .map_err(|e| e.to_string())?;
                        let nonce: [u8; crate::ipc::auth::CHALLENGE_NONCE_BYTES] = nonce
                            .try_into()
                            .map_err(|_| "challenge nonce has wrong length".to_string())?;
                        let capabilities: Vec<String> = crate::ipc::messages::CAPABILITIES
                            .iter()
                            .map(|c| (*c).to_string())
                            .collect();
                        let signature = signing.sign(&crate::ipc::auth::handshake_signing_bytes(
                            &nonce,
                            &fortress_id,
                            "test",
                            Some(crate::ipc::messages::IPC_PROTOCOL_VERSION),
                            &capabilities,
                        ));
                        let response = MessageEnvelope {
                            jsonrpc: "2.0".to_string(),
                            method: format!("{}.handshake_response", IPC_NAMESPACE),
                            params: IpcMessage::HandshakeResponse {
                                fortress_id: fortress_id.clone(),
                                signing_key_id: "test".to_string(),
                                nonce_signature_b64url:
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .encode(signature.to_bytes()),
                                protocol_version: Some(crate::ipc::messages::IPC_PROTOCOL_VERSION),
                                capabilities,
                            },
                        };
                        let body = serde_json::to_string(&response).map_err(|e| e.to_string())?;
                        let bytes = frame(&body);
                        stream.write_all(&bytes).map_err(|e| e.to_string())?;
                        return Ok(stream);
                    }
                    Err(err) => {
                        last_err = err.to_string();
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            Err(format!("connect failed: {}", last_err))
        })
    }

    #[test]
    fn preauth_quota_is_per_uid_and_reserves_trusted_service_capacity() {
        let state = fresh_state("quota", Vec::new());
        let attacker_uid = state.trusted_service_uid.wrapping_add(1);
        let mut attacker = Vec::new();
        for _ in 0..MAX_PREAUTH_PER_UNTRUSTED_UID {
            attacker.push(state.admit(attacker_uid).expect("within per-UID quota"));
        }
        assert!(matches!(
            state.admit(attacker_uid),
            Err("per_uid_preauth_active_exceeded")
        ));
        drop(attacker);

        let mut untrusted = Vec::new();
        for offset in 1..=MAX_ACTIVE_CONNECTIONS - RESERVED_TRUSTED_CONNECTIONS {
            let uid = state.trusted_service_uid.wrapping_add(10 + offset as u32);
            untrusted.push(state.admit(uid).expect("aggregate untrusted allowance"));
        }
        assert!(matches!(
            state.admit(state.trusted_service_uid.wrapping_add(10_000)),
            Err("trusted_service_capacity_reserved")
        ));
        let trusted = state
            .admit(state.trusted_service_uid)
            .expect("reserved trusted service capacity");
        drop((trusted, untrusted));
    }

    #[test]
    fn trusted_service_bypasses_bucket_capacity_but_not_its_own_rate_limit() {
        let state = fresh_state("trusted-bucket", Vec::new());
        {
            let mut admissions = state.admissions.lock().unwrap();
            for offset in 0..MAX_TRACKED_UID_RATE_BUCKETS {
                admissions.attempts_by_uid.insert(
                    state.trusted_service_uid.wrapping_add(1 + offset as u32),
                    VecDeque::from([Instant::now()]),
                );
            }
        }
        for _ in 0..MAX_PREAUTH_ATTEMPTS_PER_TRUSTED_UID {
            let lease = state
                .admit(state.trusted_service_uid)
                .unwrap_or_else(|other| {
                    panic!("trusted UID was rejected by bucket capacity: {other}")
                });
            // Exercise the attempt-rate limit independently of the concurrent
            // active-connection cap.
            drop(lease);
        }
        assert!(matches!(
            state.admit(state.trusted_service_uid),
            Err("per_uid_preauth_rate_exceeded")
        ));
    }

    /// A peer that declared the full v2 capability set.
    fn v2_peer() -> HandshakeIdentity {
        HandshakeIdentity {
            fortress_id: "f".to_string(),
            signing_key_id: "v1".to_string(),
            peer_protocol_version: Some(crate::ipc::messages::IPC_PROTOCOL_VERSION),
            peer_capabilities: crate::ipc::messages::CAPABILITIES
                .iter()
                .map(|c| (*c).to_string())
                .collect(),
        }
    }

    /// A previously-shipped consumer: no version, no capabilities.
    fn legacy_peer() -> HandshakeIdentity {
        HandshakeIdentity {
            fortress_id: "f".to_string(),
            signing_key_id: "v1".to_string(),
            peer_protocol_version: None,
            peer_capabilities: Vec::new(),
        }
    }

    fn status_request_envelope() -> MessageEnvelope {
        MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.status_request", IPC_NAMESPACE),
            params: IpcMessage::StatusRequest {
                request_id: "s1".to_string(),
            },
        }
    }

    fn dispatch_once(
        envelope: &MessageEnvelope,
        state: &ServerState,
        peer: &HandshakeIdentity,
    ) -> Option<MessageEnvelope> {
        dispatch(envelope, state, peer, &mut ConnectionDrainState::default())
    }

    fn served_through(seq: u64) -> ConnectionDrainState {
        ConnectionDrainState {
            served_sequences: [seq].into_iter().collect(),
            last_settled_seq: None,
        }
    }

    fn running_kernel_ready_state() -> Arc<ServerState> {
        let state = fresh_state("f", vec![0; 32]);
        state.live_status.update(
            crate::live_status::LifecyclePhase::Running,
            crate::daemon::DaemonRuntimeState::KernelRuntimeReady,
        );
        state
    }

    #[test]
    fn status_asserts_readiness_only_from_a_fresh_positive_proof() {
        let state = running_kernel_ready_state();
        state.runtime_health.publish(RuntimeHealthState::Ready);
        let reply = dispatch_once(&status_request_envelope(), &state, &v2_peer()).unwrap();
        match reply.params {
            IpcMessage::StatusResponse {
                kernel_runtime_ready,
                runtime_state,
                runtime_health,
                ..
            } => {
                assert!(kernel_runtime_ready);
                assert_eq!(runtime_state, "kernel_runtime_ready");
                assert_eq!(runtime_health.as_deref(), Some("ready"));
            }
            other => panic!("expected a status response, got {other:?}"),
        }
    }

    /// FAIL-BEFORE for "status collapses lock contention into not-ready": an
    /// INDETERMINATE probe must withhold the readiness assertion WITHOUT claiming
    /// the runtime is degraded. The previous implementation forced
    /// `runtime_state: "degraded"` here, which made a healthy runtime flap under
    /// status polling and gave the consumer no way to tell contention from loss.
    #[test]
    fn an_indeterminate_probe_withholds_readiness_without_claiming_degraded() {
        let state = running_kernel_ready_state();
        state
            .runtime_health
            .publish(RuntimeHealthState::ProbeUnavailable);
        let reply = dispatch_once(&status_request_envelope(), &state, &v2_peer()).unwrap();
        match reply.params {
            IpcMessage::StatusResponse {
                kernel_runtime_ready,
                enforcing,
                runtime_state,
                runtime_health,
                ..
            } => {
                assert!(
                    !kernel_runtime_ready,
                    "an unproven runtime must never assert readiness"
                );
                assert!(!enforcing);
                assert_ne!(
                    runtime_state, "degraded",
                    "contention is not a proven failure; asserting `degraded` from it is the \
                     flap this fixes"
                );
                assert_eq!(
                    runtime_health.as_deref(),
                    Some("probe_unavailable"),
                    "the consumer must be able to tell indeterminate from lost"
                );
            }
            other => panic!("expected a status response, got {other:?}"),
        }
    }

    #[test]
    fn a_proven_loss_is_reported_as_degraded_and_fails_closed() {
        let state = running_kernel_ready_state();
        state.runtime_health.publish(RuntimeHealthState::Lost(
            crate::enforcement::NotReadyReason::ComponentLost(
                crate::enforcement::ComponentKind::NftablesTable,
            ),
        ));
        let reply = dispatch_once(&status_request_envelope(), &state, &v2_peer()).unwrap();
        match reply.params {
            IpcMessage::StatusResponse {
                kernel_runtime_ready,
                enforcing,
                runtime_state,
                runtime_health,
                ..
            } => {
                assert!(!kernel_runtime_ready);
                assert!(!enforcing);
                assert_eq!(runtime_state, "degraded");
                assert_eq!(runtime_health.as_deref(), Some("lost"));
            }
            other => panic!("expected a status response, got {other:?}"),
        }
    }

    /// A status query must not fork an `nft` ownership proof. Proven structurally:
    /// with NOTHING ever published, a thousand status requests still answer
    /// (indeterminate) and touch no runtime, so an authenticated poller cannot
    /// amplify into probe load.
    #[test]
    fn status_never_probes_and_answers_indeterminate_before_any_observation() {
        let state = running_kernel_ready_state();
        for _ in 0..1_000 {
            let reply = dispatch_once(&status_request_envelope(), &state, &v2_peer()).unwrap();
            match reply.params {
                IpcMessage::StatusResponse {
                    kernel_runtime_ready,
                    runtime_health,
                    ..
                } => {
                    assert!(!kernel_runtime_ready);
                    assert_eq!(runtime_health.as_deref(), Some("probe_unavailable"));
                }
                other => panic!("expected a status response, got {other:?}"),
            }
        }
    }

    /// The ACK is applied for EVERY peer; only the reply is negotiated. A pre-v2
    /// consumer sent a one-way notification and registered no pending request, so
    /// an unsolicited response frame would be discarded at best. Withholding it is
    /// what makes new-daemon + old-client work instead of stalling.
    #[test]
    fn the_drain_ack_response_is_withheld_from_a_legacy_peer_and_sent_to_a_v2_peer() {
        let state = fresh_state("f", vec![0; 32]);
        let ack = MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.audit_drain_ack", IPC_NAMESPACE),
            params: IpcMessage::AuditDrainAck {
                request_id: "a1".to_string(),
                last_acked_seq: 1,
            },
        };
        assert!(
            dispatch_once(&ack, &state, &legacy_peer()).is_none(),
            "a pre-v2 peer must receive the exact wire behavior it was built against"
        );
        let reply = dispatch_once(&ack, &state, &v2_peer())
            .expect("a v2 peer that advertised the capability must receive the confirmation");
        assert!(matches!(
            reply.params,
            IpcMessage::AuditDrainAckResponse { .. }
        ));
    }

    /// Advertising a capability the dispatch does not honor (or honoring one that
    /// is never advertised) is the drift AGENTS rule 5 warns about, so the
    /// full-set relationship is asserted rather than a single entry.
    #[test]
    fn every_advertised_capability_is_one_this_daemon_implements() {
        use crate::ipc::messages::{
            CAPABILITIES, CAP_AUDIT_DRAIN_ACK_RESPONSE, CAP_DRAIN_ERROR_CLASS,
            CAP_POLICY_BUNDLE_PUBLISH, CAP_STATUS_RUNTIME_FIELDS, CAP_STATUS_RUNTIME_HEALTH,
        };
        let mut advertised: Vec<&str> = CAPABILITIES.to_vec();
        advertised.sort_unstable();
        let mut implemented = vec![
            CAP_AUDIT_DRAIN_ACK_RESPONSE,
            CAP_STATUS_RUNTIME_FIELDS,
            CAP_STATUS_RUNTIME_HEALTH,
            CAP_DRAIN_ERROR_CLASS,
            CAP_POLICY_BUNDLE_PUBLISH,
        ];
        implemented.sort_unstable();
        assert_eq!(
            advertised, implemented,
            "the advertised capability set and the implemented one must be equal as SETS; \
             a first-entry check cannot detect a missing or extra token"
        );
    }

    /// Every control-lock outcome must have a stated retry class. A `match` on
    /// the enum (rather than a list of the variants the author remembered) is
    /// what makes a new variant a compile error instead of a silent default.
    #[test]
    fn every_control_lock_outcome_is_classified_and_only_poison_is_terminal() {
        use crate::ipc::messages::DrainErrorClass;
        assert_eq!(
            DrainErrorClass::from(&ControlLockError::Timeout),
            DrainErrorClass::Retryable,
            "a 2-second contention timeout is a busy daemon, not a broken one; \
             classifying it terminal is what made load produce a permanent \
             not-armed wall"
        );
        assert_eq!(
            DrainErrorClass::from(&ControlLockError::Cancelled),
            DrainErrorClass::Retryable,
            "shutdown is an ordinary lifecycle event and fires on every \
             `systemctl stop` with an operation in flight"
        );
        assert_eq!(
            DrainErrorClass::from(&ControlLockError::Poisoned),
            DrainErrorClass::Terminal,
            "a poisoned lock means a holder panicked mid-mutation; retrying \
             cannot clear it"
        );
    }

    /// The ACK reply must echo the REQUESTED seq on every arm, including the
    /// failure arms. The consumer rejects any reply whose seq differs, so a
    /// failure arm that dropped or recomputed it would break confirmation
    /// entirely rather than merely losing a diagnostic.
    #[test]
    fn the_ack_reply_echoes_the_requested_seq_on_success_and_on_failure() {
        let state = fresh_state("deadbeef", vec![0u8; 32]);
        let mut first_connection = served_through(4242);
        // Failure arm: no WAL is wired on this state.
        match handle_audit_drain_ack("req-a", 4242, &state, &mut first_connection) {
            IpcMessage::AuditDrainAckResponse {
                ok,
                last_acked_seq,
                error_class,
                ..
            } => {
                assert!(!ok);
                assert_eq!(last_acked_seq, 4242);
                assert_eq!(error_class.as_deref(), Some("terminal"));
            }
            other => panic!("unexpected ack reply: {other:?}"),
        }
        // Shutdown arm: retryable, and still echoing the requested seq.
        state.mutation_cancel.store(true, Ordering::SeqCst);
        let mut second_connection = served_through(7);
        match handle_audit_drain_ack("req-b", 7, &state, &mut second_connection) {
            IpcMessage::AuditDrainAckResponse {
                ok,
                last_acked_seq,
                error_class,
                ..
            } => {
                assert!(!ok);
                assert_eq!(last_acked_seq, 7);
                assert_eq!(
                    error_class.as_deref(),
                    Some("retryable"),
                    "a stopping daemon must not manufacture a permanent drain fault"
                );
            }
            other => panic!("unexpected ack reply: {other:?}"),
        }
    }

    #[test]
    fn ack_authority_is_bound_to_events_served_on_this_connection() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("connection-bound.wal"), 1024 * 1024)
                .unwrap(),
        ));
        {
            let mut writer = wal.lock().unwrap();
            writer.append_critical("{\"event\":0}").unwrap();
            writer.append_critical("{\"event\":1}").unwrap();
        }
        let mut state = fresh_state("connection-bound", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(Arc::clone(&wal));

        let mut served = ConnectionDrainState::default();
        let first = handle_audit_drain("drain", None, 1, &state);
        served.observe_response(&first);
        assert_eq!(served.served_sequences, [0].into_iter().collect());

        // A guessed sequence beyond the returned batch must not delete the
        // unseen second entry.
        assert!(matches!(
            handle_audit_drain_ack("overshoot", 1, &state, &mut served),
            IpcMessage::AuditDrainAckResponse {
                ok: false,
                truncated_entries: 0,
                ..
            }
        ));
        assert_eq!(
            wal.lock().unwrap().snapshot_after(None, 10).unwrap().len(),
            2
        );

        // Served authority is connection-local. A new authenticated connection
        // cannot reuse another connection's drain result.
        let mut other_connection = ConnectionDrainState::default();
        assert!(matches!(
            handle_audit_drain_ack("cross-connection", 0, &state, &mut other_connection),
            IpcMessage::AuditDrainAckResponse {
                ok: false,
                truncated_entries: 0,
                ..
            }
        ));
        assert_eq!(
            wal.lock().unwrap().snapshot_after(None, 10).unwrap().len(),
            2
        );

        assert!(matches!(
            handle_audit_drain_ack("valid", 0, &state, &mut served),
            IpcMessage::AuditDrainAckResponse {
                ok: true,
                truncated_entries: 1,
                ..
            }
        ));
        let remaining = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].seq, 1);
        assert!(served.served_sequences.is_empty());
        assert!(matches!(
            handle_audit_drain_ack("replayed", 0, &state, &mut served),
            IpcMessage::AuditDrainAckResponse { ok: false, .. }
        ));
    }

    #[test]
    fn empty_or_failed_drain_grants_no_ack_authority() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("empty.wal"), 1024 * 1024).unwrap(),
        ));
        let mut state = fresh_state("empty", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(wal);
        let mut connection = ConnectionDrainState::default();

        connection.observe_response(&handle_audit_drain("empty", Some(999), 10, &state));
        assert!(connection.served_sequences.is_empty());
        assert!(matches!(
            handle_audit_drain_ack("empty-ack", 999, &state, &mut connection),
            IpcMessage::AuditDrainAckResponse { ok: false, .. }
        ));

        connection.observe_response(&audit_drain_error(
            "failed",
            Some(999),
            None,
            "injected",
            DrainErrorClass::Terminal,
        ));
        assert!(connection.served_sequences.is_empty());
    }

    #[test]
    fn nonzero_cursor_does_not_authorize_an_unserved_lower_hole() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("cursor-hole.wal"), 1024 * 1024).unwrap(),
        ));
        {
            let mut writer = wal.lock().unwrap();
            writer.append_critical("{\"event\":0}").unwrap();
            writer.append_critical("{\"event\":1}").unwrap();
        }
        let mut state = fresh_state("cursor-hole", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(Arc::clone(&wal));
        let mut connection = ConnectionDrainState::default();
        connection.observe_response(&handle_audit_drain("after-zero", Some(0), 1, &state));
        assert_eq!(connection.served_sequences, [1].into_iter().collect());
        assert!(matches!(
            handle_audit_drain_ack("hole", 0, &state, &mut connection),
            IpcMessage::AuditDrainAckResponse { ok: false, .. }
        ));
        assert_eq!(
            wal.lock().unwrap().snapshot_after(None, 10).unwrap().len(),
            2
        );
    }

    #[test]
    fn unavailable_overflow_counter_is_omitted_not_fabricated_as_zero() {
        let state = fresh_state("overflow-unavailable", Vec::new());
        match handle_audit_drain("unwired", None, 1, &state) {
            IpcMessage::AuditDrainResponse {
                wal_overflow_count, ..
            } => assert_eq!(wal_overflow_count, None),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn one_served_batch_authorizes_cumulative_ascending_acks_until_its_highest_seq() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("ascending-acks.wal"), 1024 * 1024).unwrap(),
        ));
        {
            let mut writer = wal.lock().unwrap();
            for seq in 0..3 {
                writer
                    .append_critical(&format!("{{\"event\":{seq}}}"))
                    .unwrap();
            }
        }
        let mut state = fresh_state("ascending-acks", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(Arc::clone(&wal));
        let mut connection = ConnectionDrainState::default();
        connection.observe_response(&handle_audit_drain("batch", None, 3, &state));
        assert_eq!(connection.served_sequences, [0, 1, 2].into_iter().collect());

        for seq in 0..=2 {
            assert!(matches!(
                handle_audit_drain_ack("ack", seq, &state, &mut connection),
                IpcMessage::AuditDrainAckResponse { ok: true, .. }
            ));
            assert_eq!(
                connection.served_sequences,
                ((seq + 1)..=2).collect::<BTreeSet<_>>()
            );
        }
        assert!(wal
            .lock()
            .unwrap()
            .snapshot_after(None, 10)
            .unwrap()
            .is_empty());
    }

    /// A drain against a stopping daemon is RETRYABLE, and a drain against a
    /// daemon with no WAL is TERMINAL. Both used to be indistinguishable free
    /// text that the consumer converted into the same permanent fault.
    #[test]
    fn drain_errors_carry_a_retry_class_that_separates_stopping_from_broken() {
        // TERMINAL: no WAL is wired, so no retry can ever produce evidence. This
        // check precedes the stopping check in `handle_audit_drain`, which is why
        // the retryable half below needs a genuinely wired WAL.
        let unwired = fresh_state("deadbeef", vec![0u8; 32]);
        match handle_audit_drain("d-1", None, 10, &unwired) {
            IpcMessage::AuditDrainResponse {
                error, error_class, ..
            } => {
                assert!(error.is_some());
                assert_eq!(error_class.as_deref(), Some("terminal"));
            }
            other => panic!("unexpected drain reply: {other:?}"),
        }

        // RETRYABLE: a healthy, WAL-wired daemon that happens to be stopping.
        let dir = TempDir::new().unwrap();
        let mut wired = fresh_state("deadbeef", vec![0u8; 32]);
        {
            let state = Arc::get_mut(&mut wired).expect("sole owner during setup");
            state.wal_writer = Some(Arc::new(Mutex::new(
                WalWriter::open_with_cap(&dir.path().join("filter.wal"), 1024 * 1024)
                    .expect("open wal"),
            )));
        }
        wired.mutation_cancel.store(true, Ordering::SeqCst);
        match handle_audit_drain("d-2", None, 10, &wired) {
            IpcMessage::AuditDrainResponse {
                error, error_class, ..
            } => {
                assert!(error.is_some());
                assert_eq!(
                    error_class.as_deref(),
                    Some("retryable"),
                    "an ordinary `systemctl stop` must not read as a broken \
                     evidence channel"
                );
            }
            other => panic!("unexpected drain reply: {other:?}"),
        }
    }

    /// `ManifestState` exists to keep three different things from collapsing into
    /// one `false`, so the tokens must stay distinct AND the "are the companion
    /// fields real" question must be answered per state in one place.
    #[test]
    fn manifest_state_tokens_are_distinct_and_only_proven_states_carry_fields() {
        use crate::ipc::messages::ManifestState;
        let all = [
            ManifestState::Ready,
            ManifestState::Empty,
            ManifestState::Unavailable,
            ManifestState::Degraded,
            ManifestState::Unwired,
        ];
        let mut tokens: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(
            tokens.len(),
            all.len(),
            "two states sharing a wire token would reintroduce the conflation"
        );
        assert!(ManifestState::Ready.companion_fields_are_authoritative());
        assert!(ManifestState::Empty.companion_fields_are_authoritative());
        for indeterminate_or_failed in [
            ManifestState::Unavailable,
            ManifestState::Degraded,
            ManifestState::Unwired,
        ] {
            assert!(
                !indeterminate_or_failed.companion_fields_are_authoritative(),
                "{} must not license reading `loaded_rule_count: 0` as \
                 'this daemon has no rules'",
                indeterminate_or_failed.as_str()
            );
        }
    }

    #[test]
    fn server_binds_and_unlinks_socket() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "abc".to_string(),
            decision_engine: test_decision_engine("abc", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");
        assert!(socket.exists());
        let meta = std::fs::metadata(&socket).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        server.stop_and_join();
        assert!(!socket.exists());
    }

    #[test]
    fn mismatched_peer_uid_is_rejected_before_the_signing_challenge() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let peer_uid = unsafe { libc::geteuid() };
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: signing.verifying_key().to_bytes().to_vec(),
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "uid-boundary".to_string(),
            decision_engine: test_decision_engine("uid-boundary", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: peer_uid.wrapping_add(1),
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");
        let mut stream = UnixStream::connect(&socket).expect("connect reaches UID boundary");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte);
        assert!(
            matches!(read, Ok(0)) || read.is_err(),
            "a mismatched SO_PEERCRED UID must receive no challenge bytes"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(audit.lock().unwrap().iter().any(|event| {
            event
                .event_canonical_json
                .contains("\"ipc_peer_uid_rejected\"")
                && event
                    .event_canonical_json
                    .contains(&format!("got_uid={peer_uid}"))
        }));
        server.stop_and_join();
    }

    #[test]
    fn audit_drain_without_a_wal_is_an_explicit_failure() {
        let state = fresh_state("wal-unwired", Vec::new());
        let mut connection = served_through(1);
        assert!(matches!(
            handle_audit_drain("drain-unwired", None, 100, &state),
            IpcMessage::AuditDrainResponse {
                events,
                error: Some(error),
                ..
            } if events.is_empty() && error.contains("not wired")
        ));
        assert!(matches!(
            handle_audit_drain_ack("ack-unwired", 1, &state, &mut connection),
            IpcMessage::AuditDrainAckResponse {
                ok: false,
                error: Some(error),
                ..
            } if error.contains("not wired")
        ));
    }

    #[test]
    fn wal_lock_poisoning_is_reported_for_drain_and_ack() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open(&dir.path().join("poisoned.wal")).unwrap(),
        ));
        let poison = Arc::clone(&wal);
        let _ = std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison WAL mutex");
        })
        .join();
        let mut state = fresh_state("wal-poisoned", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(wal);
        let mut connection = served_through(1);

        assert!(matches!(
            handle_audit_drain("drain-poisoned", None, 100, &state),
            IpcMessage::AuditDrainResponse {
                error: Some(error),
                ..
            } if error.contains("poisoned")
        ));
        assert!(matches!(
            handle_audit_drain_ack("ack-poisoned", 1, &state, &mut connection),
            IpcMessage::AuditDrainAckResponse {
                ok: false,
                error: Some(error),
                ..
            } if error.contains("poisoned")
        ));
    }

    #[test]
    fn audit_drain_clamps_untrusted_event_count_and_reports_lookahead() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("bounded.wal"), 8 * 1024 * 1024).unwrap(),
        ));
        {
            let mut writer = wal.lock().unwrap();
            for index in 0..300 {
                writer
                    .append_critical(&format!("{{\"event\":{index}}}"))
                    .unwrap();
            }
        }
        let mut state = fresh_state("wal-bounded", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(wal);

        match handle_audit_drain("drain-bounded", None, u32::MAX, &state) {
            IpcMessage::AuditDrainResponse {
                events,
                next_after_seq,
                more_pending,
                error: None,
                ..
            } => {
                assert_eq!(events.len(), MAX_AUDIT_DRAIN_EVENTS);
                assert_eq!(next_after_seq, Some((MAX_AUDIT_DRAIN_EVENTS - 1) as u64));
                assert!(more_pending);
            }
            other => panic!("expected bounded audit drain response, got {other:?}"),
        }
    }

    #[test]
    fn audit_drain_never_builds_an_oversized_encoded_response() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(Mutex::new(
            WalWriter::open_with_cap(&dir.path().join("byte-bounded.wal"), 32 * 1024 * 1024)
                .unwrap(),
        ));
        let large_value = "x".repeat(300 * 1024);
        {
            let mut writer = wal.lock().unwrap();
            for index in 0..60 {
                writer
                    .append_metric(&format!(
                        "{{\"event\":{index},\"payload\":\"{large_value}\"}}"
                    ))
                    .unwrap();
            }
        }
        let mut state = fresh_state("wal-byte-bounded", Vec::new());
        Arc::get_mut(&mut state).unwrap().wal_writer = Some(wal);

        let response = handle_audit_drain("drain-byte-bounded", None, u32::MAX, &state);
        let event_count = match &response {
            IpcMessage::AuditDrainResponse {
                events,
                more_pending,
                error: None,
                ..
            } => {
                assert!(*more_pending);
                events.len()
            }
            other => panic!("expected byte-bounded audit drain response, got {other:?}"),
        };
        assert!(event_count > 0 && event_count < 60);
        let envelope = MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.audit_drain_response", IPC_NAMESPACE),
            params: response,
        };
        assert!(serde_json::to_vec(&envelope).unwrap().len() <= MAX_OUTBOUND_BODY_BYTES);
    }

    #[test]
    fn wal_lock_contention_retries_then_fails_explicitly_at_its_budget() {
        let mutex = Mutex::new(());
        let _held = mutex.lock().unwrap();
        let cancelled = AtomicBool::new(false);
        let started = Instant::now();
        let result = lock_control(&mutex, &cancelled, Duration::from_millis(20));
        assert!(matches!(result, Err(ControlLockError::Timeout)));
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn server_rejects_stale_socket_then_rebinds() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        // Pre-create a real socket at the path to simulate stale state.
        let _stale = UnixListener::bind(&socket).unwrap();
        drop(_stale);
        assert!(socket.exists());

        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "abc".to_string(),
            decision_engine: test_decision_engine("abc", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start despite stale");
        server.stop_and_join();
    }

    #[test]
    fn second_daemon_cannot_unlink_or_replace_a_live_owner_socket() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("single-owner.sock");
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let make_config = || ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: SigningKey::generate(&mut OsRng)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "single-owner".to_string(),
            decision_engine: test_decision_engine("single-owner", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let first = IpcServer::start(make_config()).expect("first owner");
        assert!(matches!(
            IpcServer::start(make_config()),
            Err(IpcServerError::Bind(_))
        ));
        assert!(
            UnixStream::connect(&socket).is_ok(),
            "first listener must survive"
        );
        first.stop_and_join();
    }

    #[test]
    fn handshake_round_trip_against_real_server() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "fortress-x".to_string(),
            decision_engine: test_decision_engine("fortress-x", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");
        let client_handle =
            run_handshake_client_thread(socket.clone(), signing, "fortress-x".to_string());
        // Wait for the connection thread to finish the handshake.
        let mut stream = client_handle.join().unwrap().expect("handshake");
        // Send a status request and verify a status response comes back.
        let request = MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.status_request", IPC_NAMESPACE),
            params: IpcMessage::StatusRequest {
                request_id: "abc-123".to_string(),
            },
        };
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(&frame(&body)).unwrap();
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let reply_body = read_one_frame(&mut stream, &mut buf, Duration::from_secs(2))
            .unwrap()
            .unwrap();
        let reply_env: MessageEnvelope = serde_json::from_str(&reply_body).unwrap();
        match reply_env.params {
            IpcMessage::StatusResponse { request_id, .. } => assert_eq!(request_id, "abc-123"),
            other => panic!("unexpected reply {:?}", other),
        }
        // Verify ipc_handshake_accepted made it into the audit buffer.
        let saw_handshake_event = audit.lock().unwrap().iter().any(|e| {
            e.event_canonical_json
                .contains("\"ipc_handshake_accepted\"")
        });
        assert!(
            saw_handshake_event,
            "expected ipc_handshake_accepted audit entry"
        );
        server.stop_and_join();
    }

    #[test]
    fn handshake_with_bad_key_is_rejected() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let server_signing = SigningKey::generate(&mut OsRng);
        let attacker_signing = SigningKey::generate(&mut OsRng);
        let pk = server_signing.verifying_key().to_bytes().to_vec();
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "f".to_string(),
            decision_engine: test_decision_engine("f", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");
        let client_handle =
            run_handshake_client_thread(socket.clone(), attacker_signing, "f".to_string());
        // Client returns a stream after sending the response; the server
        // closes the connection upon verifying the bad signature. The
        // client side will not error on send, but subsequent reads will
        // see EOF.
        let stream_result = client_handle.join().unwrap();
        let mut stream = stream_result.expect("connect+send");
        let mut buf = [0u8; 16];
        let read = stream.read(&mut buf);
        assert!(matches!(read, Ok(0)) || read.is_err());
        // The audit log should record ipc_handshake_rejected.
        // Allow a brief moment for the server thread to write the audit.
        std::thread::sleep(Duration::from_millis(50));
        let saw_rejection = audit.lock().unwrap().iter().any(|e| {
            e.event_canonical_json
                .contains("\"ipc_handshake_rejected\"")
        });
        assert!(saw_rejection, "expected handshake rejection audit");
        server.stop_and_join();
    }

    #[test]
    fn trusted_uid_active_limit_rejects_the_next_client_without_spawning_a_handler() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: signing.verifying_key().to_bytes().to_vec(),
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "limit-test".to_string(),
            decision_engine: test_decision_engine("limit-test", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");

        // Complete authentication so every admitted connection sits in the
        // 120-second post-auth idle read, rather than expiring at the 5-second
        // handshake deadline while the cap is filled.
        let mut admitted = Vec::with_capacity(MAX_PREAUTH_PER_TRUSTED_UID);
        for _ in 0..MAX_PREAUTH_PER_TRUSTED_UID {
            admitted.push(
                run_handshake_client_thread(
                    socket.clone(),
                    signing.clone(),
                    "limit-test".to_string(),
                )
                .join()
                .unwrap()
                .expect("admitted authenticated client"),
            );
        }

        let mut rejected = UnixStream::connect(&socket).expect("overflow connect reaches listener");
        rejected
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut one = [0u8; 1];
        let read = rejected.read(&mut one);
        assert!(
            matches!(read, Ok(0)) || read.is_err(),
            "overflow client must be closed without receiving a challenge"
        );
        assert!(audit.lock().unwrap().iter().any(|event| {
            event
                .event_canonical_json
                .contains("\"ipc_preauth_admission_rejected\"")
                && event
                    .event_canonical_json
                    .contains("per_uid_preauth_active_exceeded")
        }));

        server.stop_and_join();
        drop(admitted);
    }

    #[test]
    fn shutdown_interrupts_idle_handler_and_joins_well_before_idle_timeout() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024 * 1024,
            Duration::from_secs(86_400),
        )));
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: signing.verifying_key().to_bytes().to_vec(),
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::clone(&audit),
            daemon_shutdown_request: Arc::new(AtomicBool::new(false)),
            fatal_control_path: Arc::new(AtomicBool::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "shutdown-test".to_string(),
            decision_engine: test_decision_engine("shutdown-test", &audit),
            wal_writer: None,
            producer_signer: None,
            live_status: Arc::new(LiveStatus::activating()),
            trusted_service_uid: unsafe { libc::geteuid() },
            runtime_health: Arc::new(RuntimeHealthView::new()),
            wal_control_progress: Arc::new(AtomicUsize::new(0)),
            drain_recovery_only: Arc::new(AtomicBool::new(false)),
        };
        let server = IpcServer::start(cfg).expect("start");
        let mut client =
            run_handshake_client_thread(socket.clone(), signing, "shutdown-test".to_string())
                .join()
                .unwrap()
                .expect("authenticated idle client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let started = Instant::now();
        server.stop_and_join();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "tracked stream shutdown must wake and join the 120-second idle handler"
        );
        let mut one = [0u8; 1];
        let read = client.read(&mut one);
        assert!(matches!(read, Ok(0)) || read.is_err());
        assert!(!socket.exists());
        assert!(UnixStream::connect(&socket).is_err());
    }
}
