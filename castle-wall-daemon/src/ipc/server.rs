//! Unix-domain-socket IPC server: accept loop, per-connection handshake,
//! method dispatch.
//!
//! The server is shutdown-aware: callers pass a shared `AtomicBool` that the
//! accept loop polls between non-blocking accepts. On shutdown the listener
//! is dropped and the socket file is unlinked. Connection threads are
//! joined; in-flight requests are abandoned but the kernel ruleset (set
//! up in PR 2b Checkpoint 3) is unaffected. The IPC layer only carries
//! control-plane signals.
//!
//! Per scope-lock §5: the socket lives at /run/sanctuary/<fortress-id>/filter.sock,
//! mode 0660, owner root:sanctuary. The accept loop polls every 100ms so
//! shutdown is observed within a tick.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::audit::{AuditRingBuffer, PendingAuditEvent, WalWriter};
use crate::constants::{AUDIT_LAYER, IPC_NAMESPACE, SCHEMA_VERSION_V1};
use crate::ipc::auth::{
    encode_nonce_b64url, generate_challenge_nonce, verify_handshake_response, AuthError,
    HandshakeIdentity, CHALLENGE_NONCE_BYTES,
};
use crate::ipc::framing::{frame, parse_frame, ParseStep};
use crate::ipc::messages::{AuditDrainEvent, IpcMessage, MessageEnvelope};
use crate::manifest::ManifestStore;

/// Socket file permissions (mode 0660 per scope-lock §5).
const SOCKET_MODE: u32 = 0o660;
/// Accept-loop poll cadence; bounds shutdown latency.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Per-connection idle deadline. Connections that go idle past this drop
/// without prejudice; the client reconnects.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-connection handshake deadline. Connections that haven't completed
/// the Ed25519 challenge in this window are dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum frame size accepted from a connecting peer. Bounds memory pressure
/// from a misbehaving client; well above any legitimate IPC message.
const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Configuration sourced from the daemon at boot.
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub pinned_public_key: Vec<u8>,
    pub prompt_timeout: Duration,
    pub audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    pub shutdown_flag: Arc<AtomicBool>,
    pub fortress_id: String,
    /// Optional manifest store used by the policy.reload dispatch.
    ///
    /// When absent (e.g., in PR 2a integration tests that exercise only
    /// handshake plus status), policy.reload returns a typed-error response
    /// so callers can distinguish "not wired" from "verify failed."
    pub manifest_store: Option<Arc<Mutex<ManifestStore>>>,
    /// Optional WAL writer used by the audit.drain + audit.drain_ack
    /// dispatch. When absent, drain returns an empty batch and ack is a
    /// no-op so PR 2a tests remain green.
    pub wal_writer: Option<Arc<Mutex<WalWriter>>>,
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
}

impl IpcServer {
    pub fn start(config: ServerConfig) -> Result<Self, IpcServerError> {
        let parent = config
            .socket_path
            .parent()
            .ok_or_else(|| IpcServerError::SocketDir("socket path has no parent".to_string()))?;
        std::fs::create_dir_all(parent)
            .map_err(|err| IpcServerError::SocketDir(err.to_string()))?;

        // Remove any stale socket file from a previous unclean shutdown so
        // bind() succeeds. If something other than a socket lives at the
        // path we leave it alone and let bind() report the conflict.
        if config.socket_path.exists() {
            if let Ok(meta) = std::fs::metadata(&config.socket_path) {
                if meta.file_type().is_socket() {
                    let _ = std::fs::remove_file(&config.socket_path);
                }
            }
        }

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

        let shutdown_flag = config.shutdown_flag.clone();
        let socket_path = config.socket_path.clone();
        let server_state = Arc::new(ServerState {
            audit_buffer: config.audit_buffer,
            shutdown_flag: config.shutdown_flag.clone(),
            fortress_id: config.fortress_id,
            pinned_public_key: config.pinned_public_key,
            manifest_store: config.manifest_store,
            wal_writer: config.wal_writer,
        });

        let accept_thread = std::thread::Builder::new()
            .name("castle-wall-ipc-accept".to_string())
            .spawn(move || run_accept_loop(listener, server_state))
            .map_err(|err| IpcServerError::ListenerConfig(err.to_string()))?;

        Ok(Self {
            accept_thread: Some(accept_thread),
            socket_path,
            shutdown_flag,
        })
    }

    pub fn stop_and_join(mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Shared between accept loop and per-connection handlers.
struct ServerState {
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    shutdown_flag: Arc<AtomicBool>,
    fortress_id: String,
    pinned_public_key: Vec<u8>,
    manifest_store: Option<Arc<Mutex<ManifestStore>>>,
    wal_writer: Option<Arc<Mutex<WalWriter>>>,
}

impl ServerState {
    fn append_audit(&self, op: &str, detail: &str) {
        if let Ok(mut buf) = self.audit_buffer.lock() {
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
            });
        }
    }
}

fn run_accept_loop(listener: UnixListener, state: Arc<ServerState>) {
    while !state.shutdown_flag.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                let _ = std::thread::Builder::new()
                    .name("castle-wall-ipc-conn".to_string())
                    .spawn(move || handle_connection(stream, state));
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
}

fn handle_connection(mut stream: UnixStream, state: Arc<ServerState>) {
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

    state.append_audit(
        "ipc_handshake_accepted",
        &format!(
            "fortress_id={},signing_key_id={}",
            identity.fortress_id, identity.signing_key_id
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
    loop {
        if state.shutdown_flag.load(Ordering::SeqCst) {
            return;
        }
        match read_one_frame(&mut stream, &mut buf, CONNECTION_IDLE_TIMEOUT) {
            Ok(Some(body)) => {
                let envelope = match parse_envelope(&body) {
                    Ok(env) => env,
                    Err(err) => {
                        state.append_audit("ipc_message_invalid", &err);
                        return;
                    }
                };
                match dispatch(&envelope, &state) {
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
    verify_handshake_response(&response_message, nonce, &state.pinned_public_key)
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

/// Handle a `policy_reload_request` end-to-end: invoke `ManifestStore::reload`
/// and translate the result into a `PolicyReloadResponse`. F-2 disposition:
/// on verify failure the prior good policy is retained and the response
/// carries `ok: false` plus the reason.
fn handle_policy_reload(request_id: &str, state: &ServerState) -> IpcMessage {
    let store = match state.manifest_store.as_ref() {
        Some(s) => s,
        None => {
            state.append_audit(
                "ipc_policy_reload_store_unwired",
                request_id,
            );
            return IpcMessage::PolicyReloadResponse {
                request_id: request_id.to_string(),
                ok: false,
                loaded_manifest_signature_b64url: None,
                loaded_rule_count: 0,
                error: Some(
                    "manifest store not configured on this daemon instance".to_string(),
                ),
            };
        }
    };
    let mut guard = match store.lock() {
        Ok(g) => g,
        Err(_poisoned) => {
            state.append_audit("ipc_policy_reload_store_poisoned", request_id);
            return IpcMessage::PolicyReloadResponse {
                request_id: request_id.to_string(),
                ok: false,
                loaded_manifest_signature_b64url: None,
                loaded_rule_count: 0,
                error: Some("manifest store mutex poisoned".to_string()),
            };
        }
    };
    match guard.reload() {
        Ok(loaded) => {
            let sig = loaded.manifest_signature_b64url.clone();
            let count = loaded.rule_count;
            state.append_audit(
                "ipc_policy_reload_succeeded",
                &format!("rules={}", count),
            );
            IpcMessage::PolicyReloadResponse {
                request_id: request_id.to_string(),
                ok: true,
                loaded_manifest_signature_b64url: Some(sig),
                loaded_rule_count: count,
                error: None,
            }
        }
        Err(err) => {
            // F-2 disposition: keep prior policy in force; surface the error
            // to Sanctuary main; emit an audit so the operator dashboard can
            // surface a banner.
            let reason = err.to_string();
            state.append_audit(
                "manifest_verify_failed_kept_prior",
                &reason,
            );
            let kept_prior = guard
                .current()
                .map(|c| (c.manifest_signature_b64url.clone(), c.rule_count));
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
            return IpcMessage::AuditDrainResponse {
                request_id: request_id.to_string(),
                events: Vec::new(),
                next_after_seq: after_seq,
                more_pending: false,
                wal_overflow_count: 0,
            };
        }
    };
    // Combined ring-buffer overflow + WAL drain cap surface; the in-memory
    // ring buffer's overflow counter feeds Sanctuary main via the response
    // so the operator dashboard can surface "N audit events lost during
    // Sanctuary main downtime" per scope-lock §8.
    let overflow = state
        .audit_buffer
        .lock()
        .map(|b| b.overflow_count())
        .unwrap_or(0);
    let max_for_snapshot = max_events.max(1) as usize;
    let snapshot = match wal.lock() {
        Ok(mut w) => match w.snapshot_after(after_seq, max_for_snapshot) {
            Ok(events) => events,
            Err(err) => {
                state.append_audit("audit_drain_snapshot_failed", &err.to_string());
                return IpcMessage::AuditDrainResponse {
                    request_id: request_id.to_string(),
                    events: Vec::new(),
                    next_after_seq: after_seq,
                    more_pending: false,
                    wal_overflow_count: overflow,
                };
            }
        },
        Err(_) => {
            state.append_audit("audit_drain_wal_poisoned", request_id);
            return IpcMessage::AuditDrainResponse {
                request_id: request_id.to_string(),
                events: Vec::new(),
                next_after_seq: after_seq,
                more_pending: false,
                wal_overflow_count: overflow,
            };
        }
    };
    let more_pending = snapshot.len() == max_for_snapshot;
    let next_after_seq = snapshot.last().map(|e| e.seq).or(after_seq);
    let events: Vec<AuditDrainEvent> = snapshot
        .into_iter()
        .map(|e| AuditDrainEvent {
            seq: e.seq,
            captured_at_unix_ms: e.captured_at_unix_ms,
            prior_sha256_hex: e.prior_sha256_hex,
            event_canonical_json: e.event_canonical_json,
            critical: e.critical,
        })
        .collect();
    state.append_audit(
        "audit_drain_served",
        &format!("count={}", events.len()),
    );
    IpcMessage::AuditDrainResponse {
        request_id: request_id.to_string(),
        events,
        next_after_seq,
        more_pending,
        wal_overflow_count: overflow,
    }
}

/// Handle an `audit_drain_ack`: truncate the WAL through `last_acked_seq`.
/// On success the ring-buffer overflow counter is reset because Sanctuary
/// main has confirmed durable receipt of every event up to and including
/// the ack point.
fn handle_audit_drain_ack(request_id: &str, last_acked_seq: u64, state: &ServerState) {
    let wal = match state.wal_writer.as_ref() {
        Some(w) => w,
        None => {
            state.append_audit("audit_drain_ack_wal_unwired", request_id);
            return;
        }
    };
    match wal.lock() {
        Ok(mut w) => match w.truncate_through_seq(last_acked_seq) {
            Ok(dropped) => {
                state.append_audit(
                    "audit_drain_ack_truncated",
                    &format!("dropped={}", dropped),
                );
            }
            Err(err) => {
                state.append_audit("audit_drain_ack_truncate_failed", &err.to_string());
            }
        },
        Err(_) => {
            state.append_audit("audit_drain_ack_wal_poisoned", request_id);
        }
    }
}

fn parse_envelope(body: &str) -> Result<MessageEnvelope, String> {
    serde_json::from_str(body).map_err(|err| err.to_string())
}

fn write_envelope(stream: &mut UnixStream, envelope: &MessageEnvelope) -> Result<(), String> {
    let body = serde_json::to_string(envelope).map_err(|err| err.to_string())?;
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
        if buf.len() > MAX_FRAME_BYTES {
            return Err(format!(
                "frame exceeded maximum size {} bytes",
                MAX_FRAME_BYTES
            ));
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
fn dispatch(envelope: &MessageEnvelope, state: &ServerState) -> Option<MessageEnvelope> {
    match &envelope.params {
        IpcMessage::StatusRequest { request_id } => {
            let reply = IpcMessage::StatusResponse {
                request_id: request_id.clone(),
                uptime_seconds: 0,
                loaded_manifest_signature_b64url: None,
                loaded_rule_count: 0,
                no_wall_engaged: false,
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
        IpcMessage::AuditDrainRequest {
            request_id,
            after_seq,
            max_events,
        } => {
            let reply = handle_audit_drain(request_id, *after_seq, *max_events, state);
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
            handle_audit_drain_ack(request_id, *last_acked_seq, state);
            // ACKs are notifications; no response.
            None
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
        IpcMessage::AuditDrainResponse { .. } => {
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
        IpcMessage::StatusResponse { .. } | IpcMessage::PolicyReloadResponse { .. } => {
            state.append_audit("ipc_unexpected_response_direction", "ignored");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    use tempfile::TempDir;

    #[allow(dead_code)]
    fn fresh_state(fortress_id: &str, pk: Vec<u8>) -> Arc<ServerState> {
        Arc::new(ServerState {
            audit_buffer: Arc::new(Mutex::new(AuditRingBuffer::new(
                1024 * 1024,
                Duration::from_secs(86_400),
            ))),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: fortress_id.to_string(),
            pinned_public_key: pk,
            manifest_store: None,
            wal_writer: None,
        })
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
                            IpcMessage::HandshakeChallenge { nonce_b64url } => nonce_b64url,
                            _ => return Err("expected HandshakeChallenge".to_string()),
                        };
                        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(nonce_b64.as_bytes())
                            .map_err(|e| e.to_string())?;
                        let signature = signing.sign(&nonce);
                        let response = MessageEnvelope {
                            jsonrpc: "2.0".to_string(),
                            method: format!("{}.handshake_response", IPC_NAMESPACE),
                            params: IpcMessage::HandshakeResponse {
                                fortress_id: fortress_id.clone(),
                                signing_key_id: "test".to_string(),
                                nonce_signature_b64url:
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .encode(signature.to_bytes()),
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
    fn server_binds_and_unlinks_socket() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::new(Mutex::new(AuditRingBuffer::new(
                1024 * 1024,
                Duration::from_secs(86_400),
            ))),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "abc".to_string(),
            manifest_store: None,
            wal_writer: None,
        };
        let server = IpcServer::start(cfg).expect("start");
        assert!(socket.exists());
        let meta = std::fs::metadata(&socket).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        server.stop_and_join();
        assert!(!socket.exists());
    }

    #[test]
    fn server_rejects_stale_socket_then_rebinds() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("filter.sock");
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        // Pre-create a real socket at the path to simulate stale state.
        let _stale = UnixListener::bind(&socket).unwrap();
        drop(_stale);
        assert!(socket.exists());

        let cfg = ServerConfig {
            socket_path: socket.clone(),
            pinned_public_key: pk,
            prompt_timeout: Duration::from_secs(30),
            audit_buffer: Arc::new(Mutex::new(AuditRingBuffer::new(
                1024 * 1024,
                Duration::from_secs(86_400),
            ))),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "abc".to_string(),
            manifest_store: None,
            wal_writer: None,
        };
        let server = IpcServer::start(cfg).expect("start despite stale");
        server.stop_and_join();
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
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "fortress-x".to_string(),
            manifest_store: None,
            wal_writer: None,
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
        let saw_handshake_event = audit
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event_canonical_json.contains("\"ipc_handshake_accepted\""));
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
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            fortress_id: "f".to_string(),
            manifest_store: None,
            wal_writer: None,
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
        let saw_rejection = audit
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event_canonical_json.contains("\"ipc_handshake_rejected\""));
        assert!(saw_rejection, "expected handshake rejection audit");
        server.stop_and_join();
    }
}
