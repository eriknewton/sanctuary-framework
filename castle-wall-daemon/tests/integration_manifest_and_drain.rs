//! End-to-end integration: boot the daemon, exercise the IPC dispatch for
//! policy.reload + audit.drain + audit.drain_ack against a real running
//! UDS server.
//!
//! Coverage:
//! 1. authenticated IPC reload durably authorizes the exact staged candidate
//!    before it becomes live
//! 2. injected authorization-WAL failure returns `ok:false` and leaves the prior
//!    manifest/snapshot untouched
//! 3. policy_reload_keeps_prior_on_signature_failure (F-2 disposition)
//! 4. audit drain/ack cursor, truncation, and cap behavior
//!
//! The ASSERTIONS here are platform-portable, but the BOOT is not: `daemon::boot`
//! calls `activate_kernel_runtime`, which on a privileged Linux host installs the
//! `sanctuary-castle` nftables table, takes the host ownership lock, and writes
//! the authenticated ownership journal. This suite therefore carries
//! `required-features = ["test-isolation"]` like every other target that can
//! reach a host-global object, and takes the shared [`isolation`] guard.
//!
//! The guard is taken INSIDE [`boot_daemon_with_policy`] and parked in the
//! returned [`BootedDaemon`], not at the top of each `#[test]`. That is
//! deliberate: a per-test `let _suite = isolation::guard();` line is a convention
//! the next test author has to remember, and forgetting it is invisible on macOS
//! and destructive on Linux. Binding the guard to the boot helper makes the
//! isolation structural — there is no way to boot this suite's daemon without it.

use base64::Engine;
use castle_wall_daemon::audit::WalWriter;
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::boot;
use castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY;
use castle_wall_daemon::ipc::auth::{handshake_signing_bytes, CHALLENGE_NONCE_BYTES};
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
use std::sync::{Arc, MutexGuard};
use std::time::Duration;
use tempfile::TempDir;

mod isolation;

const SIGNATURE_SCHEME_V1: &str = "ed25519-v1";
const IPC_NAMESPACE: &str = "castle-wall";

struct BootedDaemon {
    handle: castle_wall_daemon::daemon::DaemonHandle,
    socket_path: PathBuf,
    signing_key: SigningKey,
    fortress_id: String,
    policy_dir: PathBuf,
    _dir_keepalive: TempDir,
    /// Held for the lifetime of the booted daemon. Dropped with the struct, which
    /// is what serializes this binary's tests against the ONE isolated table,
    /// host lock, and ownership journal they share. Declared last so it is
    /// released only after `handle` (whose `Drop` tears enforcement down) has run.
    _suite: MutexGuard<'static, ()>,
}

/// Build a minimally-valid `AllowlistRule` JSON body whose `id` field
/// matches the manifest entry's `rule_id`. PolicySnapshot construction
/// requires the body to round-trip through `AllowlistRule`.
fn rule_body_for(rule_id: &str) -> Vec<u8> {
    format!(
        "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-05-05T00:00:00Z\",\"match\":{{\"ip\":[\"203.0.113.7\"]}},\"disposition\":\"allow\"}}"
    )
    .into_bytes()
}

/// Clear the ISOLATED host-global objects this binary's tests share, so each boot
/// starts from a clean ownership state.
///
/// Both operations name only isolated objects: the table comes from
/// `isolation::table()` (always `sanctuary-castle-test-<pid>`) and the journal
/// path from `isolation::runtime_paths()` (always under this run's temp root).
/// Best-effort on purpose — on macOS there is no `nft` and no journal to remove.
///
/// Failure mode if this is skipped: a previous test's owned table survives, the
/// next `boot()` sees a foreign pre-existing table and fails activation, and the
/// symptom reads as an unrelated enforcement bug rather than as leftover state.
fn reset_isolated_host_state() {
    let _ = std::process::Command::new("nft")
        .args([
            "delete",
            "table",
            castle_wall_daemon::nftables::CASTLE_FAMILY,
            isolation::table(),
        ])
        .output();
    let _ = fs::remove_file(isolation::runtime_paths().ownership_journal_path);
}

fn boot_daemon_with_policy(rule_count: usize) -> BootedDaemon {
    // Isolation FIRST, before anything can resolve a host-global name. `guard()`
    // installs the per-process isolated nftables table on first call and
    // re-asserts on every entry that the production table has never been
    // resolved, so the `boot()` below cannot install into `sanctuary-castle`.
    let suite = isolation::guard();
    reset_isolated_host_state();
    let dir = TempDir::new().expect("tempdir");
    let policy_dir = dir.path().join("policy/egress");
    let pinned_path = policy_dir.join("pinned.key");
    let wal_path = dir.path().join("filter-events.wal");
    let socket_path = dir.path().join("filter.sock");

    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();

    let signing = SigningKey::generate(&mut OsRng);
    let pinned = signing.verifying_key().to_bytes();
    fs::write(&pinned_path, pinned).unwrap();

    write_signed_manifest(&policy_dir, &signing, rule_count, 1);

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
        trusted_service_uid: Some(unsafe { libc::geteuid() }),
        wal_ttl: Duration::from_secs(86_400),
        // ISOLATION (AGENTS.md, "the operator's machine is not a fixture"): this
        // harness drives the REAL `boot()`, whose Linux activation path takes the
        // host lock and writes the ownership journal + its MAC key. These come
        // from the SHARED isolation module rather than this test's own temp dir:
        // the suite lock held above serializes access to them, and one source for
        // the isolated paths is what keeps them from drifting per suite
        // (AGENTS rule 5).
        linux_runtime_paths: isolation::runtime_paths(),
    };
    let handle = boot(cfg).expect("boot daemon");
    BootedDaemon {
        handle,
        socket_path,
        signing_key: signing,
        fortress_id: "deadbeef".to_string(),
        policy_dir,
        _dir_keepalive: dir,
        _suite: suite,
    }
}

fn write_signed_manifest(
    policy_dir: &Path,
    signing: &SigningKey,
    rule_count: usize,
    generation: u64,
) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let mut entries = Vec::new();
    for i in 0..rule_count {
        let rule_id = format!("uuid-{}", i);
        let file = format!("{}.json", rule_id);
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
    let habeas_file = "reserved_habeas_distress_local.json".to_string();
    fs::write(
        policy_dir.join(RULES_SUBDIR).join(&habeas_file),
        &habeas_body,
    )
    .unwrap();
    entries.push(ManifestRuleEntry {
        rule_id: "reserved_habeas_distress_local".to_string(),
        file: habeas_file,
        sha256: sha256_hex(&habeas_body),
    });
    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-05T00:00:00Z".to_string(),
        generation,
        agent_origin: None,
        operator_baseline: None,
        rules: entries,
    };
    let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let sig = signing.sign(&canonical);
    let signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
            signing_key_id: castle_wall_daemon::crypto::castle_wall_signing_key_id(
                &signing.verifying_key().to_bytes(),
            )
            .unwrap(),
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

fn connect_and_handshake(
    socket_path: &Path,
    signing: &SigningKey,
    fortress_id: &str,
) -> UnixStream {
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
                    IpcMessage::HandshakeChallenge { nonce_b64url, .. } => nonce_b64url,
                    other => panic!("expected HandshakeChallenge, got {:?}", other),
                };
                let nonce: [u8; CHALLENGE_NONCE_BYTES] =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(nonce_b64.as_bytes())
                        .unwrap()
                        .try_into()
                        .expect("challenge nonce has the protocol length");
                let protocol_version =
                    Some(castle_wall_daemon::ipc::messages::IPC_PROTOCOL_VERSION);
                let capabilities: Vec<String> = castle_wall_daemon::ipc::messages::CAPABILITIES
                    .iter()
                    .map(|c| (*c).to_string())
                    .collect();
                let signature = signing.sign(&handshake_signing_bytes(
                    &nonce,
                    fortress_id,
                    "test",
                    protocol_version,
                    &capabilities,
                ));
                let response = MessageEnvelope {
                    jsonrpc: "2.0".to_string(),
                    method: format!("{}.handshake_response", IPC_NAMESPACE),
                    params: IpcMessage::HandshakeResponse {
                        fortress_id: fortress_id.to_string(),
                        signing_key_id: "test".to_string(),
                        nonce_signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(signature.to_bytes()),
                        protocol_version,
                        capabilities,
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
fn authenticated_reload_durably_authorizes_exact_candidate_before_commit() {
    let booted = boot_daemon_with_policy(2);
    let prior_signature = booted
        .handle
        .manifest_store()
        .unwrap()
        .lock()
        .unwrap()
        .current()
        .unwrap()
        .manifest_signature_b64url
        .clone();
    write_signed_manifest(&booted.policy_dir, &booted.signing_key, 3, 2);
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
    let committed_signature = match reply.params {
        IpcMessage::PolicyReloadResponse {
            request_id,
            ok,
            loaded_rule_count,
            loaded_manifest_signature_b64url,
            error,
        } => {
            assert_eq!(request_id, "policy-1");
            assert!(ok, "expected ok=true; error={:?}", error);
            // 3 synthetic rules + the habeas local lane.
            assert_eq!(loaded_rule_count, 4);
            assert!(error.is_none(), "expected no error; got {:?}", error);
            loaded_manifest_signature_b64url.expect("committed signature")
        }
        other => panic!("unexpected reply {:?}", other),
    };
    assert_ne!(committed_signature, prior_signature);
    let store = booted.handle.manifest_store().unwrap().lock().unwrap();
    assert_eq!(
        store.current().unwrap().manifest_signature_b64url,
        committed_signature
    );
    assert_eq!(store.current().unwrap().rule_count, 4);
    drop(store);
    let entries = booted
        .handle
        .wal_writer()
        .unwrap()
        .lock()
        .unwrap()
        .snapshot_after(None, 100)
        .unwrap();
    let authorization = entries
        .iter()
        .find(|entry| {
            entry
                .event_canonical_json
                .contains("\"operation\":\"ipc_policy_reload_authorized\"")
        })
        .expect("durable authorization precedes successful response");
    assert!(authorization.critical);
    assert!(authorization
        .event_canonical_json
        .contains(&committed_signature));
    assert!(authorization.event_canonical_json.contains("rules=4"));
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn boot_manifest_is_durably_authorized_before_daemon_started() {
    let booted = boot_daemon_with_policy(1);
    let wal = booted.handle.wal_writer().expect("wal");
    let events = wal.lock().unwrap().snapshot_after(None, 100).unwrap();
    let authorization = events
        .iter()
        .position(|event| {
            event
                .event_canonical_json
                .contains("\"operation\":\"boot_manifest_load_authorized\"")
        })
        .expect("boot authorization receipt");
    let started = events
        .iter()
        .position(|event| {
            event
                .event_canonical_json
                .contains("\"operation\":\"daemon_started\"")
        })
        .expect("daemon started receipt");
    assert!(authorization < started);
    assert!(booted
        .handle
        .manifest_store()
        .unwrap()
        .lock()
        .unwrap()
        .current()
        .is_some());
    booted.handle.stop().unwrap();
}

/// FAIL-BEFORE for the contention-read-as-failure defect (P1).
///
/// The manifest store lock is genuinely contended in normal operation: verdict
/// evaluation takes it per packet, and an authorized reload holds it across
/// manifest verify plus a WAL fsync — exactly what a policy write before arming
/// triggers. A status query landing in that window used to report
/// `manifest_state_available: false` with `loaded_rule_count: 0` and a null
/// signature, which the consumer read as a PROVEN-degraded runtime and acted on
/// by tearing down drain and lifecycle. A momentary reload therefore stopped a
/// healthy privileged host from arming.
///
/// The daemon must report the state as INDETERMINATE, and must not fabricate the
/// companion fields into a "this daemon has no rules" reading.
#[test]
fn a_contended_manifest_store_reads_indeterminate_never_degraded() {
    let booted = boot_daemon_with_policy(1);
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let store = booted.handle.manifest_store().expect("store").clone();
    // Hold the store lock across the status round-trip, which is what a
    // concurrent reload or verdict evaluation does.
    let held = store.lock().unwrap();
    send_envelope(
        &mut stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.status_request", IPC_NAMESPACE),
            params: IpcMessage::StatusRequest {
                request_id: "contended".to_string(),
            },
        },
    );
    let mut buf = Vec::new();
    match recv_envelope(&mut stream, &mut buf).params {
        IpcMessage::StatusResponse {
            manifest_state,
            lifecycle_state,
            runtime_state,
            ..
        } => {
            assert_eq!(
                manifest_state.as_deref(),
                Some("unavailable"),
                "a held store lock is contention, not a proven policy failure"
            );
            assert_ne!(
                manifest_state.as_deref(),
                Some("degraded"),
                "reporting contention as degraded is what tore down a healthy wall"
            );
            // The rest of the status is untouched: the runtime did not become
            // unhealthy because a lock was briefly busy.
            assert_eq!(lifecycle_state, "running");
            assert_ne!(runtime_state, "degraded");
        }
        other => panic!("unexpected status reply: {other:?}"),
    }
    drop(held);
    booted.handle.stop().unwrap();
}

#[test]
fn status_reports_live_manifest_and_control_plane_truth() {
    let booted = boot_daemon_with_policy(1);
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    send_envelope(
        &mut stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.status_request", IPC_NAMESPACE),
            params: IpcMessage::StatusRequest {
                request_id: "live-status".to_string(),
            },
        },
    );
    let mut buf = Vec::new();
    match recv_envelope(&mut stream, &mut buf).params {
        IpcMessage::StatusResponse {
            request_id,
            loaded_manifest_signature_b64url,
            loaded_rule_count,
            manifest_state,
            lifecycle_state,
            runtime_state,
            kernel_runtime_ready,
            enforcing,
            no_wall_engaged,
            ..
        } => {
            assert_eq!(request_id, "live-status");
            assert!(loaded_manifest_signature_b64url.is_some());
            assert_eq!(loaded_rule_count, 2); // operator rule + habeas lane
                                              // `ready` is the ONLY token under which the count above is
                                              // authoritative. Asserting the token (not a boolean) is what keeps a
                                              // contended or poisoned store from reading as this state.
            assert_eq!(manifest_state.as_deref(), Some("ready"));
            assert_eq!(lifecycle_state, "running");
            assert!(matches!(
                runtime_state.as_str(),
                "control_plane_only" | "kernel_runtime_ready"
            ));
            assert_eq!(
                kernel_runtime_ready,
                runtime_state == "kernel_runtime_ready"
            );
            assert!(!enforcing);
            assert!(!no_wall_engaged);
        }
        other => panic!("unexpected status reply: {other:?}"),
    }
    booted.handle.stop().unwrap();
}

#[test]
fn authenticated_reload_wal_failure_returns_false_and_keeps_prior_snapshot() {
    let booted = boot_daemon_with_policy(1);
    let prior_signature = booted
        .handle
        .manifest_store()
        .unwrap()
        .lock()
        .unwrap()
        .current()
        .unwrap()
        .manifest_signature_b64url
        .clone();
    write_signed_manifest(&booted.policy_dir, &booted.signing_key, 2, 2);
    let wal = std::sync::Arc::clone(booted.handle.wal_writer().unwrap());
    let poisoned = std::thread::spawn(move || {
        let _held = wal.lock().unwrap();
        panic!("test-injected WAL mutex poison");
    });
    assert!(poisoned.join().is_err());

    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.policy_reload_request", IPC_NAMESPACE),
        params: IpcMessage::PolicyReloadRequest {
            request_id: "policy-wal-fail".to_string(),
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
            loaded_manifest_signature_b64url,
            error,
            ..
        } => {
            assert!(!ok);
            assert_eq!(loaded_rule_count, 2);
            assert_eq!(
                loaded_manifest_signature_b64url.as_deref(),
                Some(prior_signature.as_str())
            );
            assert!(error
                .unwrap()
                .contains("durable reload authorization failed"));
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let store = booted.handle.manifest_store().unwrap().lock().unwrap();
    assert_eq!(
        store.current().unwrap().manifest_signature_b64url,
        prior_signature
    );
    assert!(store
        .current_snapshot()
        .unwrap()
        .rules
        .iter()
        .any(|rule| rule.id == "uuid-0"));
    assert!(!store
        .current_snapshot()
        .unwrap()
        .rules
        .iter()
        .any(|rule| rule.id == "uuid-1"));
    drop(store);
    let _ = stream;
    let _ = booted.handle.stop();
}

#[test]
fn policy_reload_keeps_prior_on_signature_failure() {
    let booted = boot_daemon_with_policy(1);
    // Tamper: rewrite the rule file, breaking the recorded SHA-256 digest.
    fs::write(
        booted.policy_dir.join(RULES_SUBDIR).join("uuid-0.json"),
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
            assert!(
                !events.is_empty(),
                "expected at least the daemon_started event"
            );
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
                let message =
                    producer_signing_bytes(&e.event_canonical_json, e.captured_at_unix_ms, e.seq);
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
    let baseline_seq;
    // Push three additional WAL entries directly via the helper.
    {
        let wal: &std::sync::Arc<std::sync::Mutex<WalWriter>> =
            booted.handle.wal_writer().expect("wal handle");
        let mut w = wal.lock().unwrap();
        baseline_seq = w
            .snapshot_after(None, 100)
            .unwrap()
            .last()
            .expect("boot audit baseline")
            .seq;
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"a\"}")
            .unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"b\"}")
            .unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"c\"}")
            .unwrap();
    }
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    // Drain after the complete boot audit baseline (authorization plus
    // daemon_started); only the three hand-pushed entries should remain.
    let req = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-after-0".to_string(),
            after_seq: Some(baseline_seq),
            max_events: 100,
        },
    };
    send_envelope(&mut stream, &req);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            // Should see exactly the 3 hand-pushed entries.
            assert_eq!(events.len(), 3);
            assert_eq!(events[0].seq, baseline_seq + 1);
            assert_eq!(events[2].seq, baseline_seq + 3);
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
    let (y_seq, z_seq);
    {
        let wal = booted.handle.wal_writer().expect("wal");
        let mut w = wal.lock().unwrap();
        w.append_critical("{\"layer\":\"l1\",\"operation\":\"x\"}")
            .unwrap();
        y_seq = w
            .append_critical("{\"layer\":\"l1\",\"operation\":\"y\"}")
            .unwrap();
        z_seq = w
            .append_critical("{\"layer\":\"l1\",\"operation\":\"z\"}")
            .unwrap();
    }
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    // Serve y on this authenticated connection first. ACK authority is granted
    // only for the latest non-empty drain response served on this connection.
    let drain = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_request", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainRequest {
            request_id: "drain-through-y".to_string(),
            after_seq: Some(y_seq - 1),
            max_events: 1,
        },
    };
    send_envelope(&mut stream, &drain);
    let mut buf = Vec::new();
    match recv_envelope(&mut stream, &mut buf).params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].seq, y_seq);
        }
        other => panic!("unexpected drain reply {other:?}"),
    }

    // ACK through y, irrespective of how many boot control records precede it.
    let ack = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{}.audit_drain_ack", IPC_NAMESPACE),
        params: IpcMessage::AuditDrainAck {
            request_id: "ack-1".to_string(),
            last_acked_seq: y_seq,
        },
    };
    send_envelope(&mut stream, &ack);
    let ack_reply = recv_envelope(&mut stream, &mut buf);
    match ack_reply.params {
        IpcMessage::AuditDrainAckResponse {
            request_id,
            ok,
            last_acked_seq,
            truncated_entries,
            error,
            error_class,
        } => {
            assert_eq!(request_id, "ack-1");
            assert!(ok, "ACK truncation must be confirmed: {error:?}");
            assert_eq!(
                last_acked_seq, y_seq,
                "the reply must echo the REQUESTED seq; the consumer refuses any \
                 other value, so a daemon that recomputed it would break every ack"
            );
            assert!(truncated_entries >= 2);
            assert!(error.is_none());
            assert!(
                error_class.is_none(),
                "a class without an error would be a field the consumer could act on"
            );
        }
        other => panic!("unexpected ACK reply {:?}", other),
    }
    // Drain again and confirm only z survives.
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
    let reply = recv_envelope(&mut stream, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].seq, z_seq);
            assert!(events[0].event_canonical_json.contains("\"z\""));
        }
        other => panic!("unexpected reply {:?}", other),
    }
    let _ = stream;
    let _ = booted.handle.stop();
}

/// TEARDOWN RACE (P2): a packet the fence DROPS must not leave the audit trail
/// ending on a canonical `allow` receipt.
///
/// The race is real and not hypothetical: `evaluate_attempt` makes its decision
/// durable BEFORE returning (deliberately - evidence must never trail the
/// packet), and the NFQUEUE callback re-checks the teardown fence AFTER it. A
/// shutdown that begins inside that window drops the packet on the wire while
/// the WAL keeps an `egress_approved` receipt for a packet that never left.
/// Fail-closed on the wire, but the audit log is the product's evidence claim.
///
/// Driven deterministically rather than by timing luck: this test HOLDS the
/// manifest-store lock so the verdict thread parks inside `evaluate_attempt`,
/// sets the fence while it is parked, then releases. That lands the flag in the
/// exact window a real `systemctl stop` would.
#[test]
fn a_packet_dropped_at_the_teardown_fence_leaves_a_superseding_record() {
    use castle_wall_daemon::nfqueue::{build_verdict_callback, NfVerdict, PendingPacket};
    use std::sync::atomic::Ordering;

    let booted = boot_daemon_with_policy(0);
    // Install a real allow rule for the fixture's exact IP destination.
    write_signed_manifest(&booted.policy_dir, &booted.signing_key, 1, 2);
    let mut reload_stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    send_envelope(
        &mut reload_stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.policy_reload_request", IPC_NAMESPACE),
            params: IpcMessage::PolicyReloadRequest {
                request_id: "fence-reload".to_string(),
                manifest_path: "ignored".to_string(),
            },
        },
    );
    let mut reload_buf = Vec::new();
    match recv_envelope(&mut reload_stream, &mut reload_buf).params {
        IpcMessage::PolicyReloadResponse { ok: true, .. } => {}
        other => panic!("authorized reload failed: {other:?}"),
    }

    let engine = booted.handle.decision_engine();
    let store = booted.handle.manifest_store().expect("store").clone();
    let callback = build_verdict_callback(Arc::clone(&engine));
    let packet = PendingPacket {
        packet_id: 7,
        nfmark: 1,
        source_agent_id: Some("agent-fence-race".to_string()),
        source_cgroup_id: 1,
        dest_ip: Some("203.0.113.7".to_string()),
        dest_port: 443,
        protocol: 6,
        packet_len: 64,
    };

    // Park the verdict thread INSIDE evaluate_attempt by holding the store lock
    // it must acquire.
    let held = store.lock().unwrap();
    let worker = std::thread::spawn(move || callback(&packet));
    // Give the worker time to pass the pre-evaluation fence and block on the
    // store. Generous on purpose: an early release would test nothing, and the
    // assertions below would fail loudly rather than pass vacuously.
    std::thread::sleep(Duration::from_millis(200));
    engine.mutation_cancel_flag().store(true, Ordering::SeqCst);
    drop(held);

    assert_eq!(
        worker.join().expect("verdict thread"),
        NfVerdict::Drop,
        "the teardown fence must still drop the packet; the superseding record \
         corrects the EVIDENCE, it never softens the verdict"
    );

    let wal = booted.handle.wal_writer().expect("wal");
    let events = wal.lock().unwrap().snapshot_after(None, 500).unwrap();
    let approved = events
        .iter()
        .find(|e| {
            e.event_canonical_json
                .contains("\"operation\":\"egress_approved\"")
        })
        .expect("the allow receipt this race is about");
    let superseding = events
        .iter()
        .find(|e| {
            e.event_canonical_json
                .contains("\"operation\":\"egress_verdict_superseded\"")
        })
        .expect(
            "a dropped packet must not leave a canonical allow receipt as the \
             final word; a superseding record naming it is required",
        );
    assert!(
        superseding.seq > approved.seq,
        "strict sequence semantics: the superseding record must land AFTER the \
         verdict it overrides, so a reader resolves the final verdict by \
         scanning forward"
    );
    assert!(
        superseding
            .event_canonical_json
            .contains(&format!("\"superseded_wal_seq\":{}", approved.seq)),
        "the superseding record must name the EXACT sequence it overrides, not \
         merely exist: {}",
        superseding.event_canonical_json
    );
    assert!(
        superseding
            .event_canonical_json
            .contains("\"final_verdict\":\"drop\""),
        "the superseding record must state what actually happened to the packet"
    );

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
    write_signed_manifest(&booted.policy_dir, signing, 1, 2);
    let mut reload_stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    send_envelope(
        &mut reload_stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.policy_reload_request", IPC_NAMESPACE),
            params: IpcMessage::PolicyReloadRequest {
                request_id: "evaluate-reload".to_string(),
                manifest_path: "ignored".to_string(),
            },
        },
    );
    let mut reload_buf = Vec::new();
    match recv_envelope(&mut reload_stream, &mut reload_buf).params {
        IpcMessage::PolicyReloadResponse { ok: true, .. } => {}
        other => panic!("authorized reload failed: {other:?}"),
    }
    let request = EvaluationRequest {
        agent_id: "agent-1".to_string(),
        agent_template: "claude-code".to_string(),
        // The fixture rule names this exact IP. Host/port/protocol are otherwise
        // unconstrained, so this request resolves through the intended rule.
        dest_host: Some("api.example.com".to_string()),
        dest_ip: Some("203.0.113.7".to_string()),
        dest_port: 443,
        dest_protocol: "tcp".to_string(),
        opaque: false,
    };
    let outcome = booted.handle.evaluate_attempt(&request).expect("evaluate");
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
            assert!(approved
                .event_canonical_json
                .contains("\"api.example.com\""));
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
fn shutdown_cancels_policy_reload_waiting_on_manifest_mutex() {
    let booted = boot_daemon_with_policy(1);
    let store = Arc::clone(booted.handle.manifest_store().expect("store"));
    let _held = store.lock().unwrap();
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    send_envelope(
        &mut stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.policy_reload_request", IPC_NAMESPACE),
            params: IpcMessage::PolicyReloadRequest {
                request_id: "blocked-reload".to_string(),
                manifest_path: "ignored".to_string(),
            },
        },
    );
    std::thread::sleep(Duration::from_millis(50));
    let started = std::time::Instant::now();
    booted.handle.stop().expect("bounded stop");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "shutdown must cancel a handler waiting on the shared manifest mutex"
    );
}

#[test]
fn shutdown_cancels_policy_reload_waiting_on_wal_mutex() {
    let booted = boot_daemon_with_policy(1);
    let wal = Arc::clone(booted.handle.wal_writer().expect("wal"));
    let _held = wal.lock().unwrap();
    let mut stream = connect_and_handshake(
        &booted.socket_path,
        &booted.signing_key,
        &booted.fortress_id,
    );
    send_envelope(
        &mut stream,
        &MessageEnvelope {
            jsonrpc: "2.0".to_string(),
            method: format!("{}.policy_reload_request", IPC_NAMESPACE),
            params: IpcMessage::PolicyReloadRequest {
                request_id: "wal-blocked-reload".to_string(),
                manifest_path: "ignored".to_string(),
            },
        },
    );
    std::thread::sleep(Duration::from_millis(50));
    let started = std::time::Instant::now();
    booted.handle.stop().expect("bounded stop");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "shutdown must cancel a handler waiting on the shared WAL mutex"
    );
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
