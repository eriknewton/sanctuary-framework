//! End-to-end integration: boot the daemon, exercise the IPC dispatch for
//! policy.reload + audit.drain + audit.drain_ack against a real running
//! UDS server.
//!
//! Coverage:
//! 1. boot_then_policy_reload_succeeds_with_real_manifest_on_disk
//! 2. policy_reload_keeps_prior_on_signature_failure (F-2 disposition)
//! 3. audit_drain_returns_daemon_started_event_after_boot
//! 4. audit_drain_with_after_seq_skips_already_drained_entries
//! 5. audit_drain_ack_truncates_wal_through_seq
//! 6. audit_drain_more_pending_when_capped
//!
//! Tests run on every host (Linux + macOS) because nothing here touches
//! kernel-only primitives. The daemon's lifecycle, IPC server, manifest
//! store, and WAL writer are all platform-portable.

use base64::Engine;
use castle_wall_daemon::audit::WalWriter;
use castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY;
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::boot;
use castle_wall_daemon::ipc::framing::{frame, parse_frame, ParseStep};
use castle_wall_daemon::ipc::messages::{IpcMessage, MessageEnvelope};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const SIGNATURE_SCHEME_V1: &str = "ed25519-v1";
const IPC_NAMESPACE: &str = "castle-wall";

struct BootedDaemon {
    handle: castle_wall_daemon::daemon::DaemonHandle,
    socket_path: PathBuf,
    signing_key: SigningKey,
    fortress_id: String,
    policy_dir: PathBuf,
    _dir_keepalive: TempDir,
}

/// Build a minimally-valid `AllowlistRule` JSON body whose `id` field
/// matches the manifest entry's `rule_id`. PolicySnapshot construction
/// requires the body to round-trip through `AllowlistRule`.
fn rule_body_for(rule_id: &str) -> Vec<u8> {
    format!(
        "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{}},\"disposition\":\"allow\"}}"
    )
    .into_bytes()
}

fn boot_daemon_with_policy(rule_count: usize) -> BootedDaemon {
    let dir = TempDir::new().expect("tempdir");
    let policy_dir = dir.path().join("policy/egress");
    let pinned_path = policy_dir.join("pinned.key");
    let wal_path = dir.path().join("filter-events.wal");
    let socket_path = dir.path().join("filter.sock");

    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();

    let signing = SigningKey::generate(&mut OsRng);
    let pinned = signing.verifying_key().to_bytes();
    fs::write(&pinned_path, pinned).unwrap();

    write_signed_manifest(&policy_dir, &signing, rule_count);

    let cfg = DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: socket_path.clone(),
        policy_dir: policy_dir.clone(),
        wal_path,
        pinned_public_key_path: pinned_path,
        producer_key_path: policy_dir.join("audit-producer.key"),
        producer_pub_key_path: policy_dir.join("audit-producer.pub"),
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_size_cap_bytes: 16 * 1024 * 1024,
        wal_ttl: Duration::from_secs(86_400),
    };
    let handle = boot(cfg).expect("boot daemon");
    BootedDaemon {
        handle,
        socket_path,
        signing_key: signing,
        fortress_id: "deadbeef".to_string(),
        policy_dir,
        _dir_keepalive: dir,
    }
}

fn write_signed_manifest(policy_dir: &Path, signing: &SigningKey, rule_count: usize) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let mut entries = Vec::new();
    for i in 0..rule_count {
        let file = format!("rule-{}.json", i);
        let rule_id = format!("uuid-{}", i);
        let body = rule_body_for(&rule_id);
        fs::write(policy_dir.join(RULES_SUBDIR).join(&file), &body).unwrap();
        entries.push(ManifestRuleEntry {
            rule_id,
            file,
            sha256: sha256_hex(&body),
        });
    }
    // Every composed manifest must carry the genuine habeas local lane
    // (always-on-lane gate); the daemon refuses a lane-less manifest.
    let habeas_body = HABEAS_LOCAL_RULE_BODY.as_bytes().to_vec();
    let habeas_file = "rule-habeas.json".to_string();
    fs::write(policy_dir.join(RULES_SUBDIR).join(&habeas_file), &habeas_body).unwrap();
    entries.push(ManifestRuleEntry {
        rule_id: "reserved_habeas_distress_local".to_string(),
        file: habeas_file,
        sha256: sha256_hex(&habeas_body),
    });
    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-05T00:00:00Z".to_string(),
        agent_origin: None,
        rules: entries,
    };
    let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let sig = signing.sign(&canonical);
    let signature_b64url =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
            signing_key_id: "test".to_string(),
            signature_b64url,
        },
    };
    let serialized = serde_json::to_string_pretty(&signed).unwrap();
    fs::write(policy_dir.join(MANIFEST_FILENAME), serialized).unwrap();
}

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

fn connect_and_handshake(socket_path: &Path, signing: &SigningKey, fortress_id: &str) -> UnixStream {
    let mut last_err = String::new();
    for _ in 0..50 {
        match UnixStream::connect(socket_path) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf: Vec<u8> = Vec::with_capacity(4096);
                let body = read_one_frame(&mut stream, &mut buf, Duration::from_secs(5))
                    .expect("read challenge");
                let envelope: MessageEnvelope = serde_json::from_str(&body).unwrap();
                let nonce_b64 = match envelope.params {
                    IpcMessage::HandshakeChallenge { nonce_b64url } => nonce_b64url,
                    other => panic!("expected HandshakeChallenge, got {:?}", other),
                };
                let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(nonce_b64.as_bytes())
                    .unwrap();
                let signature = signing.sign(&nonce);
                let response = MessageEnvelope {
                    jsonrpc: "2.0".to_string(),
                    method: format!("{}.handshake_response", IPC_NAMESPACE),
                    params: IpcMessage::HandshakeResponse {
                        fortress_id: fortress_id.to_string(),
                        signing_key_id: "test".to_string(),
                        nonce_signature_b64url:
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(signature.to_bytes()),
                    },
                };
                send_envelope(&mut stream, &response);
                return stream;
            }
            Err(err) => {
                last_err = err.to_string();
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("connect_and_handshake gave up: {}", last_err);
}

fn send_envelope(stream: &mut UnixStream, envelope: &MessageEnvelope) {
    let body = serde_json::to_string(envelope).unwrap();
    let bytes = frame(&body);
    stream.write_all(&bytes).unwrap();
}

fn recv_envelope(stream: &mut UnixStream, buf: &mut Vec<u8>) -> MessageEnvelope {
    let body = read_one_frame(stream, buf, Duration::from_secs(5)).expect("read frame");
    serde_json::from_str(&body).unwrap()
}

fn read_one_frame(
    stream: &mut UnixStream,
    buf: &mut Vec<u8>,
    deadline: Duration,
) -> Result<String, String> {
    let started = std::time::Instant::now();
    let mut chunk = [0u8; 4096];
    loop {
        match parse_frame(buf) {
            ParseStep::Complete {
                body,
                consumed_bytes,
            } => {
                buf.drain(..consumed_bytes);
                return Ok(body);
            }
            ParseStep::NeedMore => {}
            ParseStep::Error { reason } => return Err(reason),
        }
        if started.elapsed() > deadline {
            return Err("integration read deadline exceeded".to_string());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err("server closed".to_string()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                return Err("integration connection idle timeout".to_string());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

#[test]
fn boot_then_policy_reload_succeeds_with_real_manifest_on_disk() {
    let booted = boot_daemon_with_policy(2);
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.policy_reload_request", IPC_NAMESPACE),
        params: IpcMessage::PolicyReloadRequest {
            request_id: "policy-1".to_string(),
            manifest_path: "ignored".to_string(),
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::PolicyReloadResponse {
            request_id,
            ok,
            loaded_rule_count,
            error,
            ..
        } => {
            assert_eq!(request_id, "policy-1");
            assert!(ok, "expected ok=true; error={:?}", error);
            // 2 synthetic rules + the habeas local lane.
            assert_eq!(loaded_rule_count, 3);
            assert!(error.is_none(), "expected no error; got {:?}", error);
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn policy_reload_keeps_prior_on_signature_failure() {
    let booted = boot_daemon_with_policy(1);
    // Tamper: rewrite the rule file, breaking the recorded SHA-256 digest.
    fs::write(
        booted.policy_dir.join(RULES_SUBDIR).join("rule-0.json"),
        b"{\"r\":\"tampered\"}",
    )
    .unwrap();
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.policy_reload_request", IPC_NAMESPACE),
        params: IpcMessage::PolicyReloadRequest {
            request_id: "policy-bad".to_string(),
            manifest_path: "ignored".to_string(),
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::PolicyReloadResponse {
            ok,
            loaded_rule_count,
            error,
            loaded_manifest_signature_b64url,
            ..
        } => {
            assert!(!ok, "expected ok=false on tampered rule");
            // Prior policy was loaded at boot (1 rule + habeas lane);
            // tampered reload should keep the prior count + signature.
            assert_eq!(loaded_rule_count, 2);
            assert!(loaded_manifest_signature_b64url.is_some());
            let err = error.expect("error string for tampered reload");
            assert!(
                err.contains("rule") || err.contains("digest") || err.contains("sha256"),
                "expected rule/digest error; got {}",
                err
            );
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn audit_drain_returns_daemon_started_event_after_boot() {
    let booted = boot_daemon_with_policy(1);
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-1".to_string(),
            after_seq: None,
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse {
            request_id,
            events,
            more_pending,
            ..
        } => {
            assert_eq!(request_id, "drain-1");
            assert!(!events.is_empty(), "expected daemon_started event");
            assert!(events
                .iter()
                .any(|e| e.event_canonical_json.contains("daemon_started")));
            assert!(!more_pending);
            // Genesis entry has no prior chain hash; subsequent entries do.
            assert_eq!(events[0].prior_sha256_hex, None);
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

/// Slice L1 acceptance: every drained enforcement event carries a producer
/// signature that verifies against the daemon's published producer public key,
/// and a signature is NOT valid against a different (seq) message — i.e. a
/// replayed past signature cannot pass as a current event.
#[test]
fn audit_drain_events_carry_verifiable_producer_signature() {
    use castle_wall_daemon::constants::PRODUCER_SIG_KEY_ID_V1;
    use castle_wall_daemon::ipc::producer_sig::producer_signing_bytes;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let booted = boot_daemon_with_policy(1);

    // Load the daemon's PUBLISHED producer public key (world-readable). This is
    // the only key material the consumer side has; it can verify but not sign.
    let pub_path = booted.policy_dir.join("audit-producer.pub");
    let pub_bytes = fs::read(&pub_path).expect("producer pub key published at boot");
    assert_eq!(pub_bytes.len(), 32, "producer pub key is 32 raw bytes");
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).expect("valid verifying key");

    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-sig".to_string(),
            after_seq: None,
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            assert!(!events.is_empty(), "expected at least the daemon_started event");
            for e in &events {
                // Every event is signed and key-id-tagged (the signer is wired).
                let sig_b64 = e
                    .producer_signature_b64url
                    .as_ref()
                    .unwrap_or_else(|| panic!("event seq {} missing producer signature", e.seq));
                assert_eq!(
                    e.producer_key_id.as_deref(),
                    Some(PRODUCER_SIG_KEY_ID_V1),
                    "event seq {} has the v1 producer key id",
                    e.seq
                );
                let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(sig_b64.as_bytes())
                    .expect("signature is base64url");
                assert_eq!(sig_bytes.len(), 64, "ed25519 signature is 64 bytes");
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig_bytes);
                let signature = Signature::from_bytes(&sig_arr);

                // Positive: verifies over the canonical seq‖ts‖event binding.
                let message = producer_signing_bytes(
                    &e.event_canonical_json,
                    e.captured_at_unix_ms,
                    e.seq,
                );
                verifying_key
                    .verify(&message, &signature)
                    .unwrap_or_else(|_| panic!("event seq {} signature must verify", e.seq));

                // Negative (replay): the same signature does NOT verify when the
                // seq is changed, so a captured signature can't be replayed onto
                // a different position to fake current liveness.
                let replayed = producer_signing_bytes(
                    &e.event_canonical_json,
                    e.captured_at_unix_ms,
                    e.seq.wrapping_add(1),
                );
                assert!(
                    verifying_key.verify(&replayed, &signature).is_err(),
                    "event seq {} signature must NOT verify against a different seq (replay)",
                    e.seq
                );
            }
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn audit_drain_with_after_seq_skips_already_drained_entries() {
    let booted = boot_daemon_with_policy(1);
    // Push three additional WAL entries directly via the helper.
    {
        let wal: &std::sync::Arc<std::sync::Mutex<WalWriter>> =
            booted.handle.wal_writer().expect("wal handle");
        let mut w = wal.lock().unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"a\"}").unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"b\"}").unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"c\"}").unwrap();
    }
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    // Drain after seq=0 (skip daemon_started which is at seq 0).
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-after-0".to_string(),
            after_seq: Some(0),
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            // Should see exactly the 3 hand-pushed entries (seq 1, 2, 3).
            assert_eq!(events.len(), 3);
            assert_eq!(events[0].seq, 1);
            assert_eq!(events[2].seq, 3);
            assert!(events[0].event_canonical_json.contains("\"a\""));
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn audit_drain_ack_truncates_wal_through_seq() {
    let booted = boot_daemon_with_policy(1);
    {
        let wal = booted.handle.wal_writer().expect("wal");
        let mut w = wal.lock().unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"x\"}").unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"y\"}").unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"z\"}").unwrap();
        // Now next_seq == 4; daemon_started at 0, x/y/z at 1,2,3.
    }
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    // ACK through seq=2 (drops daemon_started + x + y; keeps z).
    let ack = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_ack", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainAck {
            request_id: "ack-1".to_string(),
            last_acked_seq: 2,
        },
    };
    send_envelope(&mut stream, &ack);
    // Give the daemon a moment to process the notification.
    std::thread::sleep(Duration::from_millis(100));
    // Drain again and confirm only seq=3 survives.
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-after-ack".to_string(),
            after_seq: None,
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].seq, 3);
            assert!(events[0].event_canonical_json.contains("\"z\""));
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn evaluate_attempt_audit_drains_through_real_ipc_wire() {
    // End-to-end: boot the daemon with one allow rule, drive a real
    // evaluate_attempt through the DaemonHandle, drain via the IPC server
    // over a real UDS, and assert the audit event arrives on the wire
    // with the canonical egress_approved + static_rule shape.
    use castle_wall_daemon::policy::EvaluationRequest;
    let booted = boot_daemon_with_policy(0);
    // Manifest store currently has no rule; reload from disk via the
    // DaemonHandle to load the snapshot. boot_daemon_with_policy(0) wrote
    // a manifest with zero rules, so we install a real rule manifest now.
    let signing = &booted.signing_key;
    write_signed_manifest(&booted.policy_dir, signing, 1);
    {
        let store = booted.handle.manifest_store().expect("store");
        let mut g = store.lock().unwrap();
        g.reload().expect("reload");
    }
    let request = EvaluationRequest {
        agent_id: "agent-1".to_string(),
        agent_template: "claude-code".to_string(),
        // The minimal rule body has empty match_clause, so any host on
        // any port over any protocol matches and resolves to allow.
        dest_host: Some("api.example.com".to_string()),
        dest_ip: Some("203.0.113.42".to_string()),
        dest_port: 443,
        dest_protocol: "tcp".to_string(),
        opaque: false,
    };
    let outcome = booted
        .handle
        .evaluate_attempt(&request)
        .expect("evaluate");
    // Sanity: the verdict resolved through the rule we installed.
    assert!(matches!(
        outcome.verdict,
        castle_wall_daemon::policy::Verdict::Allow { .. }
    ));

    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let drain = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-eval".to_string(),
            after_seq: None,
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &drain);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            // daemon_started + at least one egress_approved.
            assert!(events.len() >= 2);
            let approved = events
                .iter()
                .find(|e| e.event_canonical_json.contains("\"egress_approved\""))
                .expect("egress_approved on the wire");
            assert!(approved.critical, "evaluate_attempt emits critical events");
            assert!(approved.event_canonical_json.contains("\"l1\""));
            assert!(approved.event_canonical_json.contains("\"static_rule\""));
            assert!(approved.event_canonical_json.contains("\"agent-1\""));
            assert!(approved.event_canonical_json.contains("\"api.example.com\""));
            // Chain integrity: the egress_approved entry's prior_sha256_hex
            // is not None (it has at least the daemon_started predecessor).
            assert!(approved.prior_sha256_hex.is_some());
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn audit_drain_more_pending_when_capped() {
    let booted = boot_daemon_with_policy(1);
    {
        let wal = booted.handle.wal_writer().expect("wal");
        let mut w = wal.lock().unwrap();
        for i in 0..5 {
            w.append_critical(&format!("{{\"layer\":\"l1\",\"operation\":\"e{}\"}}", i))
                .unwrap();
        }
    }
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-cap".to_string(),
            after_seq: None,
            max_events: 2,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse {
            events,
            more_pending,
            next_after_seq,
            ..
        } => {
            assert_eq!(events.len(), 2);
            assert!(more_pending);
            assert_eq!(next_after_seq, Some(events[1].seq));
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}
