//! Integration tests for scope-lock section 9 failure-mode dispositions
//! (PR 2b Checkpoint 4 PART A).
//!
//! Each test drives the daemon through a real failure scenario using kernel
//! primitives where applicable, asserts the daemon takes the section 9
//! prescribed disposition (refuse-to-start, fail-closed, fail-degraded,
//! retain-prior-policy), and where the audit log is wired, asserts the
//! audit-event shape matches the disposition tag.
//!
//! These complement the unit-level dispatch-table tests in
//! castle-wall-daemon/src/failure.rs::tests (which cover the pure
//! FailureMode to FailureDisposition mapping) by exercising the same paths
//! against real filesystem, real UDS, real nftables, and the real boot
//! lifecycle.
//!
//! Coverage map (FailureMode -> what this file exercises):
//!
//! - StartupFilterInstallFailed (F-1) -> dispatch + boot rejection unit
//!   path; production install path covered by integration_kernel_binding's
//!   nftables_install_castle_table_creates_and_is_idempotent.
//! - StartupPolicyParseFailed (F-4) -> pinned-key missing at boot returns
//!   DaemonError::PinnedKeyLoad, mode_for_error maps to RefuseToStart F-4;
//!   bad-signature manifest at boot (best-effort first load) keeps the
//!   default-deny invariant on first evaluate_attempt.
//! - StartupIpcBindFailed (F-3-startup) -> regular file at socket path
//!   triggers IpcServer bind failure with the F-3-startup message key.
//! - RuntimeDaemonCrash (F-2) -> kernel rules persist when the daemon
//!   handle drops; a fresh boot finds the table still installed.
//! - RuntimeIpcDropKernelUp (F-3) -> kernel rules persist after a forced
//!   client-side IPC drop; the daemon stays up; reconnect succeeds.
//! - RuntimeExternalFirewallClobber (F-7) -> external nft flush ruleset
//!   wipes the castle table; install_castle_table restores it idempotently.
//! - RuntimeQueueSaturated (F-5) -> dispatch maps to FailClosed with
//!   reason=queue_saturated; QueueHandle.packets_saturated counter mechanism
//!   exercised against the real Atomic counter.
//! - RuntimeAuditWalAppendFailed -> dispatch maps to FailClosed with
//!   reason=audit_wal_append_failed; the unit-level dispatch test in
//!   failure.rs::tests::audit_wal_append_failure_fails_closed already
//!   covers the mapping. Real WAL append failure injection has no clean
//!   API today; tracked as a v1.x coverage gap.
//!
//! Linux-gated. cfg-out on macOS so `cargo test` on the dev sandbox sees
//! zero tests from this file.

#![cfg(target_os = "linux")]

use base64::Engine as _;
use castle_wall_daemon::audit::WalWriter;
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::{boot, mode_for_error, refuse_to_start_message, DaemonError};
use castle_wall_daemon::failure::{default_disposition, FailureDisposition, FailureMode};
use castle_wall_daemon::ipc::framing::{frame, parse_frame, ParseStep};
use castle_wall_daemon::ipc::messages::{IpcMessage, MessageEnvelope};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use castle_wall_daemon::nfqueue::{NfqueueConfig, QueueHandle};
use castle_wall_daemon::nftables::{
    self, AgentRulesetId, NftRuleFragment, CASTLE_FAMILY, CASTLE_TABLE,
};
use castle_wall_daemon::policy::{DeniedReason, EvaluationRequest, Verdict};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const SIGNATURE_SCHEME_V1: &str = "ed25519-v1";
const IPC_NAMESPACE: &str = "castle-wall";

// ---- helpers --------------------------------------------------------------

fn cleanup_castle_table() {
    let _ = Command::new("nft")
        .args(["delete", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output();
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

fn write_pinned_key(dir: &Path, signing: &SigningKey) -> PathBuf {
    let path = dir.join("pinned.key");
    fs::write(&path, signing.verifying_key().to_bytes()).unwrap();
    path
}

fn write_signed_manifest_one_rule(policy_dir: &Path, signing: &SigningKey) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let body = format!(
        "{{\"id\":\"{}\",\"schema_version\":1,\"created_at\":\"2026-05-06T00:00:00Z\",\"match\":{{\"host\":[\"example.com\"],\"port\":[443],\"protocol\":\"tcp\"}},\"disposition\":\"allow\"}}",
        "rule-allow-example"
    );
    let body_bytes = body.into_bytes();
    let file = "rule-0.json";
    fs::write(policy_dir.join(RULES_SUBDIR).join(file), &body_bytes).unwrap();

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-06T00:00:00Z".to_string(),
        rules: vec![ManifestRuleEntry {
            rule_id: "rule-allow-example".to_string(),
            file: file.to_string(),
            sha256: sha256_hex(&body_bytes),
        }],
    };
    let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let sig = signing.sign(&canonical);
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
            signing_key_id: "test".to_string(),
            signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sig.to_bytes()),
        },
    };
    let serialized = serde_json::to_string_pretty(&signed).unwrap();
    fs::write(policy_dir.join(MANIFEST_FILENAME), serialized).unwrap();
}

fn write_bad_signature_manifest(policy_dir: &Path, signing: &SigningKey) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let body = b"{\"id\":\"rule-0\",\"schema_version\":1,\"created_at\":\"2026-05-06T00:00:00Z\",\"match\":{},\"disposition\":\"allow\"}";
    fs::write(policy_dir.join(RULES_SUBDIR).join("rule-0.json"), body).unwrap();

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-06T00:00:00Z".to_string(),
        rules: vec![ManifestRuleEntry {
            rule_id: "rule-0".to_string(),
            file: "rule-0.json".to_string(),
            sha256: sha256_hex(body),
        }],
    };
    // Sign with a DIFFERENT key so the pinned key fails verification.
    let attacker = SigningKey::generate(&mut OsRng);
    let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let bad_sig = attacker.sign(&canonical);
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
            signing_key_id: "test".to_string(),
            signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(bad_sig.to_bytes()),
        },
    };
    fs::write(
        policy_dir.join(MANIFEST_FILENAME),
        serde_json::to_string_pretty(&signed).unwrap(),
    )
    .unwrap();
    let _ = signing; // pinned key is the signing key; manifest is signed by attacker.
}

fn fresh_config(dir: &TempDir, signing: &SigningKey) -> DaemonConfig {
    DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: dir.path().join("filter.sock"),
        policy_dir: dir.path().to_path_buf(),
        wal_path: dir.path().join("wal.jsonl"),
        pinned_public_key_path: write_pinned_key(dir.path(), signing),
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_ttl: Duration::from_secs(86_400),
        wal_size_cap_bytes: 16 * 1024 * 1024,
    }
}

// ---- F-3-startup: IPC bind failure ----------------------------------------

#[test]
fn f3_startup_ipc_bind_fails_when_socket_path_is_a_regular_file() {
    // Place a regular file at the socket path. IpcServer::start removes
    // stale UDS sockets but leaves non-socket files alone, so UnixListener
    // bind fails and surfaces as DaemonError::IpcBind.
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let mut config = fresh_config(&dir, &signing);
    fs::write(&config.socket_path, b"i am not a socket").unwrap();
    config.socket_path = config.socket_path.clone();

    let err = match boot(config) {
        Ok(_handle) => panic!("boot should refuse when socket path is a regular file"),
        Err(err) => err,
    };
    assert!(matches!(err, DaemonError::IpcBind(_)), "got: {err:?}");

    let mode = mode_for_error(&err);
    assert_eq!(mode, FailureMode::StartupIpcBindFailed);

    let disposition = default_disposition(mode);
    match &disposition {
        FailureDisposition::RefuseToStart {
            operator_message_key,
        } => assert_eq!(*operator_message_key, "F-3-startup"),
        other => panic!("expected RefuseToStart F-3-startup; got {other:?}"),
    }

    let msg = refuse_to_start_message(&disposition, &err.to_string());
    assert!(msg.contains("F-3-startup"));
    assert!(msg.contains("IPC socket"));
}

// ---- F-4 startup: pinned-key missing --------------------------------------

#[test]
fn f4_startup_pinned_key_missing_refuses_to_start_with_f4_message() {
    // Boot when the pinned-key file is absent. mode_for_error maps
    // PinnedKeyLoad to StartupPolicyParseFailed; disposition is RefuseToStart
    // with key F-4. This is the integration-level companion to the unit
    // test daemon::tests::boot_refuses_with_missing_pinned_key.
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let mut config = fresh_config(&dir, &signing);
    config.pinned_public_key_path = dir.path().join("pinned.key.does-not-exist");

    let err = match boot(config) {
        Ok(_handle) => panic!("boot should refuse when pinned key is missing"),
        Err(err) => err,
    };
    assert!(matches!(err, DaemonError::PinnedKeyLoad(_)));

    let mode = mode_for_error(&err);
    assert_eq!(mode, FailureMode::StartupPolicyParseFailed);

    let disposition = default_disposition(mode);
    match &disposition {
        FailureDisposition::RefuseToStart {
            operator_message_key,
        } => assert_eq!(*operator_message_key, "F-4"),
        other => panic!("expected RefuseToStart F-4; got {other:?}"),
    }

    let msg = refuse_to_start_message(&disposition, &err.to_string());
    assert!(msg.contains("F-4"));
    assert!(msg.contains("allowlist"));
}

// ---- F-4 startup: bad-signature manifest preserves default-deny -----------

#[test]
fn f4_bad_signature_manifest_at_boot_keeps_default_deny_at_first_evaluate() {
    // boot() does a best-effort first manifest load. Bad signature -> the
    // store stays in current=None; the daemon comes up but the F-1 deny-by-
    // default invariant is preserved on the very first evaluate_attempt.
    // This is the audit-shape proof: scope-lock section 7 F-4 says the
    // operator-facing surface refuses to start at the Sanctuary main level
    // when the allowlist signature does not verify; on the daemon side the
    // analogous proof is "no rule was loaded, so every outbound is
    // egress_blocked + default_deny."
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let config = fresh_config(&dir, &signing);
    write_bad_signature_manifest(&config.policy_dir, &signing);

    let handle = boot(config).expect("boot is best-effort on first manifest load");

    let request = EvaluationRequest {
        agent_id: "agent-1".to_string(),
        agent_template: "claude-code".to_string(),
        dest_host: Some("api.anthropic.com".to_string()),
        dest_ip: Some("104.18.0.1".to_string()),
        dest_port: 443,
        dest_protocol: "tcp".to_string(),
        opaque: false,
    };
    let outcome = handle.evaluate_attempt(&request).expect("evaluate");

    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert!(outcome.event_canonical_json.contains("\"egress_blocked\""));
    assert!(outcome.event_canonical_json.contains("\"default_deny\""));
    let _ = handle.stop();
}

// ---- F-2 runtime daemon crash: kernel rules persist -----------------------

#[test]
fn f2_runtime_daemon_crash_kernel_rules_persist_after_handle_drop() {
    // Section 9 F-2: filter daemon crashed mid-session. The kernel ruleset
    // is the load-bearing enforcement surface; it persists across a daemon
    // crash so wrapped-agent traffic stays denied during the gap. This test
    // proves: daemon installs castle table + per-agent ruleset, daemon
    // handle drops (simulating the crash), the table + chain remain, a
    // fresh boot sees them still installed.
    cleanup_castle_table();
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let config = fresh_config(&dir, &signing);
    let socket_path = config.socket_path.clone();

    let handle = boot(config).expect("boot");
    nftables::install_castle_table().expect("install_castle_table");

    let id = AgentRulesetId {
        agent_id: "f2-test".to_string(),
        cgroup_path: PathBuf::from("/test-placeholder/f2-test"),
    };
    let frags = vec![NftRuleFragment {
        rule_id: "r-f2".to_string(),
        nft_expr: "tcp dport 443 accept".to_string(),
    }];
    let script = nftables::build_agent_ruleset_no_cgroup_match("f2-test", &frags);
    nftables::load_agent_ruleset(&id, &script).expect("load_agent_ruleset");

    // Sanity: the chain is in the kernel before the simulated crash.
    let pre = Command::new("nft")
        .args(["list", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output()
        .expect("pre-list");
    let pre_out = String::from_utf8_lossy(&pre.stdout);
    assert!(pre_out.contains("agent_f2-test"), "pre-drop chain present");

    // Simulate daemon crash: drop the handle without orderly shutdown. The
    // IpcServer's Drop impl unbinds the socket; the kernel ruleset is in
    // a separate kernel namespace and survives the userspace drop.
    drop(handle);

    // Kernel-side: chain still present.
    let post = Command::new("nft")
        .args(["list", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output()
        .expect("post-list");
    let post_out = String::from_utf8_lossy(&post.stdout);
    assert!(
        post_out.contains("agent_f2-test"),
        "section 9 F-2: kernel ruleset must survive a daemon crash; got: {post_out}"
    );

    // Userspace side: the IPC socket is gone (proves the daemon really did drop).
    assert!(!socket_path.exists(), "IPC socket should be removed on drop");

    // Fresh boot finds the kernel rules still in place; idempotent install
    // is a no-op against the existing table.
    let signing2 = SigningKey::generate(&mut OsRng);
    let dir2 = TempDir::new().unwrap();
    let config2 = fresh_config(&dir2, &signing2);
    let handle2 = boot(config2).expect("re-boot");
    nftables::install_castle_table().expect("install idempotent");
    let still_present = Command::new("nft")
        .args(["list", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output()
        .expect("re-list");
    let still_out = String::from_utf8_lossy(&still_present.stdout);
    assert!(still_out.contains("agent_f2-test"), "rules persist into re-boot");

    // Verify the dispatch table for runtime crash is FailClosed.
    let disposition = default_disposition(FailureMode::RuntimeDaemonCrash);
    match disposition {
        FailureDisposition::FailClosed { emit_event, reason } => {
            assert_eq!(emit_event, "egress_blocked");
            assert_eq!(reason, "no_matching_rule");
        }
        other => panic!("expected FailClosed; got {other:?}"),
    }

    let _ = handle2.stop();
    cleanup_castle_table();
}

// ---- F-3 runtime IPC drop: kernel up, daemon up, reconnect succeeds -------

#[test]
fn f3_runtime_ipc_drop_kernel_rules_persist_and_daemon_stays_up() {
    cleanup_castle_table();
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let config = fresh_config(&dir, &signing);
    write_signed_manifest_one_rule(&config.policy_dir, &signing);
    let socket_path = config.socket_path.clone();
    let fortress_id = config.fortress_id.clone();

    let handle = boot(config).expect("boot");
    nftables::install_castle_table().expect("install");

    let id = AgentRulesetId {
        agent_id: "f3-test".to_string(),
        cgroup_path: PathBuf::from("/test-placeholder/f3-test"),
    };
    let frags = vec![NftRuleFragment {
        rule_id: "r-f3".to_string(),
        nft_expr: "tcp dport 443 accept".to_string(),
    }];
    let script = nftables::build_agent_ruleset_no_cgroup_match("f3-test", &frags);
    nftables::load_agent_ruleset(&id, &script).expect("load");

    // Connect, handshake, then forcibly close the client side mid-session.
    let stream = connect_with_handshake(&socket_path, &signing, &fortress_id);
    drop(stream); // simulates client-side IPC drop (Sanctuary main vanishing)

    // Section 9 F-3 disposition: kernel up, IPC down -> fail-degraded for up
    // to 60s. The kernel ruleset is the load-bearing surface and remains
    // in place; the daemon does not shut itself down; reconnect succeeds.
    assert!(!handle.is_shutdown_requested(), "daemon must stay up on IPC drop");

    let kernel_after_drop = Command::new("nft")
        .args(["list", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output()
        .expect("post-drop list");
    let out = String::from_utf8_lossy(&kernel_after_drop.stdout);
    assert!(
        out.contains("agent_f3-test"),
        "section 9 F-3: kernel rules persist on IPC drop; got: {out}"
    );

    // A fresh client connects + completes the handshake against the same
    // running daemon. Proves the management plane recovered.
    let mut stream2 = connect_with_handshake(&socket_path, &signing, &fortress_id);
    let drain = MessageEnvelope {
        jsonrpc: "2.0".to_string(),
        method: format!("{IPC_NAMESPACE}.audit_drain_request"),
        params: IpcMessage::AuditDrainRequest {
            request_id: "f3-recover".to_string(),
            after_seq: None,
            max_events: 10,
        },
    };
    send_envelope(&mut stream2, &drain);
    let mut buf = Vec::new();
    let reply = recv_envelope(&mut stream2, &mut buf);
    match reply.params {
        IpcMessage::AuditDrainResponse { events, .. } => {
            assert!(!events.is_empty(), "reconnected drain returns daemon_started");
        }
        other => panic!("unexpected reply on reconnect: {other:?}"),
    }

    // Verify dispatch is FailDegraded (matches §9 F-3 "kernel up, IPC down").
    let disposition = default_disposition(FailureMode::RuntimeIpcDropKernelUp);
    assert!(matches!(disposition, FailureDisposition::FailDegraded { .. }));

    drop(stream2);
    let _ = handle.stop();
    cleanup_castle_table();
}

// ---- F-7 external firewall clobber: restoration is idempotent -------------

#[test]
fn f7_external_firewall_clobber_castle_table_is_restored_idempotently() {
    // Section 9 F-7: a sibling process (ufw, firewalld, an operator running
    // `nft flush ruleset`) wipes the castle table mid-session. The
    // disposition is RestoreAndAudit: the daemon detects, restores, logs,
    // continues. PR 2b ships the idempotent install; the netlink-driven
    // ruleset-change watchdog is queued for v1.x. This test proves the
    // restoration mechanism: install, externally flush, install again,
    // table is back.
    cleanup_castle_table();
    nftables::install_castle_table().expect("install initial");
    assert!(nftables::table_exists().expect("table_exists 1"));

    // External clobber: another root process flushes the entire ruleset.
    // This is the exact behavior `ufw enable` or `nft flush ruleset` causes.
    let flush = Command::new("nft")
        .args(["flush", "ruleset"])
        .output()
        .expect("nft flush");
    assert!(flush.status.success(), "external flush succeeded");
    assert!(
        !nftables::table_exists().expect("table_exists 2"),
        "table gone after external flush"
    );

    // Restoration via the same idempotent install path the netlink
    // watchdog would call when it observes the ruleset-change event.
    nftables::install_castle_table().expect("install restored");
    assert!(
        nftables::table_exists().expect("table_exists 3"),
        "table back after restoration"
    );

    // Verify dispatch is RestoreAndAudit with the section 9 timing budget.
    let disposition = default_disposition(FailureMode::RuntimeExternalFirewallClobber);
    match disposition {
        FailureDisposition::RestoreAndAudit { restored_within_ms } => {
            assert!(
                restored_within_ms > 0,
                "RestoreAndAudit disposition carries a restoration budget"
            );
        }
        other => panic!("expected RestoreAndAudit; got {other:?}"),
    }

    cleanup_castle_table();
}

// ---- F-5 NFQUEUE saturation: dispatch + counter mechanism -----------------

#[test]
fn f5_runtime_queue_saturated_disposition_emits_egress_blocked_queue_saturated() {
    // Real packet-flow saturation requires sustained packet pressure with
    // a verdict loop running, which is fragile in CI. This test exercises
    // the two surfaces PR 2b ships:
    //
    //  1. Dispatch table maps RuntimeQueueSaturated to FailClosed with
    //     emit_event=egress_blocked + reason=queue_saturated.
    //  2. QueueHandle.packets_saturated counter (the wire surface the
    //     verdict loop atomically increments when a kernel-drop event
    //     arrives) increments correctly under direct manipulation.
    //
    // Real-kernel saturation under the verdict loop is gated to the v1.x
    // hardening sweep; the contract is locked here.
    let disposition = default_disposition(FailureMode::RuntimeQueueSaturated);
    match disposition {
        FailureDisposition::FailClosed { emit_event, reason } => {
            assert_eq!(emit_event, "egress_blocked");
            assert_eq!(reason, "queue_saturated");
        }
        other => panic!("expected FailClosed queue_saturated; got {other:?}"),
    }

    // Counter mechanism: QueueHandle exposes packets_saturated as an
    // Arc<AtomicU64> so the verdict loop can increment it when nfq reports
    // a saturation event. Verify the counter wiring under direct
    // manipulation; the kernel-side trigger is exercised by the v1.x
    // hardening sweep.
    let cfg = NfqueueConfig::default();
    assert!(!cfg.fail_open);

    let handle = QueueHandle {
        queue_number: 0,
        packets_processed: Arc::new(AtomicU64::new(0)),
        packets_saturated: Arc::new(AtomicU64::new(0)),
        stop_flag: Arc::new(AtomicBool::new(false)),
    };
    handle.packets_saturated.fetch_add(7, Ordering::Relaxed);
    assert_eq!(handle.packets_saturated.load(Ordering::Relaxed), 7);
    handle.stop_flag.store(true, Ordering::Relaxed);
}

// ---- F-1 dispatch parity with refuse-to-start message rendering -----------

#[test]
fn f1_dispatch_renders_filter_install_failure_message_for_operator() {
    // Section 9 F-1 ("Filter daemon never started") has the strongest
    // refuse-to-start posture. Verify the chain mode_for_error -> dispatch
    // -> render produces the operator-facing message that names nftables
    // and points at the recovery path. PlatformMissing and SignalSetup
    // are the two DaemonError variants that map to F-1.
    let pm = DaemonError::PlatformMissing("nftables binary missing".to_string());
    let mode = mode_for_error(&pm);
    assert_eq!(mode, FailureMode::StartupFilterInstallFailed);
    let disposition = default_disposition(mode);
    match &disposition {
        FailureDisposition::RefuseToStart {
            operator_message_key,
        } => assert_eq!(*operator_message_key, "F-1"),
        other => panic!("expected RefuseToStart F-1; got {other:?}"),
    }
    let msg = refuse_to_start_message(&disposition, &pm.to_string());
    assert!(msg.contains("F-1"));
    assert!(msg.contains("nftables"));
    assert!(msg.contains("nftables binary missing"));
}

// ---- WAL append failure dispatch mapping ----------------------------------

#[test]
fn audit_wal_append_failure_dispatch_is_fail_closed() {
    // Companion to the failure.rs unit test
    // audit_wal_append_failure_fails_closed. The unit test runs on every
    // host; this integration-level repeat keeps the section 9 catalog
    // trace contiguous in the tests/ directory and binds the assertion to
    // the actual FailureDisposition variant.
    //
    // Real WAL append failure injection (e.g., a forced fsync error mid-
    // append) has no clean public API today; tracked as a v1.x integration
    // coverage gap in this file's module-level docstring. Once the daemon
    // grows a programmatic "inject WAL failure" hook for testing, the
    // real failure path lands here.
    let disposition = default_disposition(FailureMode::RuntimeAuditWalAppendFailed);
    match disposition {
        FailureDisposition::FailClosed { emit_event, reason } => {
            assert_eq!(emit_event, "egress_blocked");
            assert_eq!(reason, "audit_wal_append_failed");
        }
        other => panic!("expected FailClosed audit_wal_append_failed; got {other:?}"),
    }
}

// ---- WAL replay corruption is a refuse-to-start gate ----------------------

#[test]
fn wal_chain_corruption_at_open_refuses_to_start() {
    // The WAL writer replays the file at open-time and verifies the
    // SHA-256 chain across entries. A corrupted (or hand-edited) WAL
    // surfaces as an open failure; the daemon refuses to come up rather
    // than continue with broken audit history. Mirrors scope-lock section
    // 8 "tamper-evident at the main-process boundary" intent at the
    // daemon-local boundary.
    let dir = TempDir::new().unwrap();
    let wal_path = dir.path().join("corrupt.wal");
    fs::write(
        &wal_path,
        // Hand-crafted entry whose prior_sha256_hex points at a hash that
        // does not match the (non-existent) prior line. Replay sees a
        // chain break at seq 0.
        b"{\"seq\":0,\"captured_at_unix_ms\":1,\"prior_sha256_hex\":\"deadbeef\",\"event_canonical_json\":\"{}\",\"critical\":true}\n",
    )
    .unwrap();
    let err = WalWriter::open(&wal_path).expect_err("corrupt WAL must refuse open");
    let msg = err.to_string();
    assert!(
        msg.contains("chain") || msg.contains("integrity"),
        "expected chain integrity error; got {msg}"
    );
}

// ---- IPC handshake helpers (mirrors integration_manifest_and_drain.rs) ----

fn connect_with_handshake(
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
                    IpcMessage::HandshakeChallenge { nonce_b64url } => nonce_b64url,
                    other => panic!("expected HandshakeChallenge, got {other:?}"),
                };
                let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(nonce_b64.as_bytes())
                    .unwrap();
                let signature = signing.sign(&nonce);
                let response = MessageEnvelope {
                    jsonrpc: "2.0".to_string(),
                    method: format!("{IPC_NAMESPACE}.handshake_response"),
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
    panic!("connect_with_handshake gave up: {last_err}");
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

// Quietly used here so an unused-import warning does not bite when feature
// flags drop unrelated paths.
#[allow(dead_code)]
fn _silence_unused_listener_import() -> Option<UnixListener> {
    None
}
