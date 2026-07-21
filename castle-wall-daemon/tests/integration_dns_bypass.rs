//! Integration tests for DNS / DoH / DoT bypass attempts (PR 2b
//! Checkpoint 4 PART B).
//!
//! Scope-lock section 9 (test-tier table at lines 2056 of the scope-lock
//! doc) promotes these scenarios to required Tier 0 + Tier 2 + Tier 3
//! coverage:
//!
//! - **Plain DNS bypass** (UDP/53 to a non-allowed resolver). Lowest-effort
//!   exfil path; agents that retain the OS resolver list can leak the
//!   target host name as an A query. The catchall rule must drop.
//! - **DoH bypass** (TCP/443 to a known DoH provider, e.g. dns.google or
//!   cloudflare-dns.com). The most common LLM-agent exfil shape: blends
//!   into ordinary HTTPS, no separate port to filter on. The host-name
//!   match must reject any 443 destination not in the curated allowlist.
//! - **DoT bypass** (TCP/853 to a non-allowed DoT resolver). Less common
//!   but trivial to attempt; same shape as DoH minus the port disguise.
//!
//! This file ships two coverage tiers:
//!
//! 1. **Active CI tests.** Drive the daemon's policy evaluator with
//!    synthesized DNS / DoH / DoT EvaluationRequest shapes. They prove
//!    that when the kernel hands the daemon a DNS-class request matching
//!    a bypass scenario, the verdict resolves to Deny with DefaultDeny
//!    provenance and the audit entry carries the scope-lock-prescribed
//!    egress_blocked + default_deny shape. They do not require real
//!    cgroup attachment or real packet flow; they lock the contract on
//!    every Linux CI cycle.
//!
//! 2. **Real-cgroup, real-packet tests.** Active in Linux CI as of the
//!    chain-wiring fix (this PR). They exercise the full kernel drop
//!    path: cgroup attach + subprocess + nftables cgroupv2 match +
//!    base-output-chain jump + NFQUEUE drop verdict + audit assertion.
//!    Require root or `CAP_NET_ADMIN` (same as the kernel-binding tests
//!    in `integration_kernel_binding.rs`).
//!
//! Linux-gated. cfg-out on macOS so `cargo test` on the dev sandbox sees
//! zero tests from this file.

#![cfg(target_os = "linux")]

use base64::Engine as _;
use castle_wall_daemon::cgroup;
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::{boot, DaemonHandle};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use castle_wall_daemon::nfqueue::{self, NfVerdict, NfqueueConfig, PendingPacket, QueueHandle};
use castle_wall_daemon::nftables::{self, AgentRulesetId, NftRuleFragment};
use castle_wall_daemon::policy::{DeniedReason, EvaluationRequest, Verdict};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const SIGNATURE_SCHEME_V1: &str = "ed25519-v1";

// ---- helpers --------------------------------------------------------------

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

/// Boot a daemon with a single allow rule for `example.com:443/tcp`. Every
/// other destination falls through to default-deny, which is the exact
/// shape the bypass tests need.
fn boot_with_only_example_com_443_allowed() -> (DaemonHandle, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let signing = SigningKey::generate(&mut OsRng);
    let pinned_path = dir.path().join("pinned.key");
    fs::write(&pinned_path, signing.verifying_key().to_bytes()).unwrap();

    write_signed_allow_only_example_443(dir.path(), &signing);

    let config = DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: dir.path().join("filter.sock"),
        policy_dir: dir.path().to_path_buf(),
        wal_path: dir.path().join("wal.jsonl"),
        pinned_public_key_path: pinned_path,
        producer_key_path: dir.path().join("audit-producer.key"),
        producer_pub_key_path: dir.path().join("audit-producer.pub"),
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_ttl: Duration::from_secs(86_400),
        wal_size_cap_bytes: 16 * 1024 * 1024,
    };
    let handle = boot(config).expect("boot");
    (handle, dir)
}

fn write_signed_allow_only_example_443(policy_dir: &Path, signing: &SigningKey) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let body = b"{\"id\":\"rule-allow-example\",\"schema_version\":1,\"created_at\":\"2026-05-06T00:00:00Z\",\"match\":{\"host\":[\"example.com\"],\"port\":[443],\"protocol\":\"tcp\"},\"disposition\":\"allow\"}";
    fs::write(policy_dir.join(RULES_SUBDIR).join("rule-0.json"), body).unwrap();
    // Every composed manifest must carry the genuine habeas local lane
    // (always-on-lane gate). Scoped to the reserved emitter id, so it cannot
    // satisfy any agent-classified flow in these bypass tests.
    let habeas_body = castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
    fs::write(policy_dir.join(RULES_SUBDIR).join("rule-habeas.json"), habeas_body).unwrap();

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-06T00:00:00Z".to_string(),
        agent_origin: None,
        operator_baseline: None,
        rules: vec![
            ManifestRuleEntry {
                rule_id: "rule-allow-example".to_string(),
                file: "rule-0.json".to_string(),
                sha256: sha256_hex(body),
            },
            ManifestRuleEntry {
                rule_id: "reserved_habeas_distress_local".to_string(),
                file: "rule-habeas.json".to_string(),
                sha256: sha256_hex(habeas_body),
            },
        ],
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
    fs::write(
        policy_dir.join(MANIFEST_FILENAME),
        serde_json::to_string_pretty(&signed).unwrap(),
    )
    .unwrap();
}

fn dns_request(host: Option<&str>, ip: &str, port: u16, protocol: &str) -> EvaluationRequest {
    EvaluationRequest {
        agent_id: "agent-bypass-test".to_string(),
        agent_template: "claude-code".to_string(),
        dest_host: host.map(|h| h.to_string()),
        dest_ip: Some(ip.to_string()),
        dest_port: port,
        dest_protocol: protocol.to_string(),
        opaque: host.is_none(),
    }
}

fn assert_default_deny_audit(outcome_json: &str) {
    assert!(
        outcome_json.contains("\"egress_blocked\""),
        "audit must record egress_blocked; got: {outcome_json}"
    );
    assert!(
        outcome_json.contains("\"default_deny\""),
        "audit must record default_deny provenance; got: {outcome_json}"
    );
    assert!(
        outcome_json.contains("\"l1\""),
        "audit must record layer l1; got: {outcome_json}"
    );
}

// ---- Tier A: policy-evaluator-driven bypass tests (active in CI) ----------

#[test]
fn policy_blocks_plain_dns_to_unallowed_resolver_emits_egress_blocked_default_deny() {
    // Scope-lock section 9 plain DNS bypass: agent attempts UDP/53 to
    // 8.8.8.8 (Google's public resolver). Policy allows only
    // example.com:443/tcp. The catchall rule -> NFQUEUE -> evaluate_attempt
    // path resolves to Verdict::Deny { DefaultDeny } and emits the
    // scope-lock-prescribed audit shape.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(None, "8.8.8.8", 53, "udp"))
        .expect("evaluate plain DNS");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    assert!(outcome.event_canonical_json.contains("\"udp\""));
    assert!(outcome.event_canonical_json.contains("53"));
    let _ = handle.stop();
}

#[test]
fn policy_blocks_plain_dns_tcp_to_unallowed_resolver() {
    // Scope-lock section 9 plain DNS-over-TCP bypass: same shape as UDP/53
    // but on TCP/53 (RFC 7766). Less common path but trivial for an agent
    // to attempt; must drop.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(None, "1.1.1.1", 53, "tcp"))
        .expect("evaluate DNS-over-TCP");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    let _ = handle.stop();
}

#[test]
fn policy_blocks_doh_to_unallowed_provider_emits_egress_blocked_default_deny() {
    // Scope-lock section 9 DoH bypass: this is the most common LLM-agent
    // exfil path. Agent sends an HTTPS request to dns.google (a published
    // DoH endpoint) on TCP/443. Policy allows only example.com:443. The
    // host-name match misses the curated allow entry; default-deny fires.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(Some("dns.google"), "8.8.8.8", 443, "tcp"))
        .expect("evaluate DoH dns.google");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    assert!(outcome.event_canonical_json.contains("\"dns.google\""));
    let _ = handle.stop();
}

#[test]
fn policy_blocks_doh_to_cloudflare_provider() {
    // Same shape as the dns.google test, with the second canonical DoH
    // provider. Section 9 explicitly names both.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(
            Some("cloudflare-dns.com"),
            "1.1.1.1",
            443,
            "tcp",
        ))
        .expect("evaluate DoH cloudflare");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    let _ = handle.stop();
}

#[test]
fn policy_blocks_dot_to_unallowed_resolver_emits_egress_blocked_default_deny() {
    // Scope-lock section 9 DoT bypass: TCP/853 to cloudflare-dns.com.
    // Same evaluator path as the DoH case; the destination port is 853
    // and the catchall fires.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(
            Some("cloudflare-dns.com"),
            "1.1.1.1",
            853,
            "tcp",
        ))
        .expect("evaluate DoT");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    assert!(outcome.event_canonical_json.contains("853"));
    let _ = handle.stop();
}

#[test]
fn policy_blocks_dot_to_quad9_resolver() {
    // Quad9 (9.9.9.9) is a third commonly-used DoT resolver. Same shape
    // as the cloudflare DoT test; locks coverage of the third canonical
    // provider mentioned in operator briefings.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(Some("dns.quad9.net"), "9.9.9.9", 853, "tcp"))
        .expect("evaluate DoT quad9");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    let _ = handle.stop();
}

#[test]
fn policy_blocks_raw_ip_https_with_no_dns_resolution() {
    // Scope-lock section 9 raw-IP HTTPS exfil: agent skips DNS entirely
    // and connects to a known IP on 443 with no host name. The opaque
    // flag is set; section 6 confidence labels would render this as
    // low_raw_ip in the operator prompt (PR 5 surface). On the daemon
    // side, the policy evaluator default-denies because no rule matches
    // the opaque destination.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();
    let outcome = handle
        .evaluate_attempt(&dns_request(None, "203.0.113.42", 443, "tcp"))
        .expect("evaluate raw-IP HTTPS");
    assert!(matches!(
        outcome.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    assert_default_deny_audit(&outcome.event_canonical_json);
    let _ = handle.stop();
}

#[test]
fn policy_allows_explicitly_listed_destination_alongside_bypass_denials() {
    // Sanity that the bypass tests are not just default-deny against an
    // empty policy: the same daemon allows the one explicitly-listed
    // destination AND denies every bypass shape exercised above. This
    // proves the tests exercise the catchall, not a rule-load bug.
    let (handle, _dir) = boot_with_only_example_com_443_allowed();

    // Explicit-allow path.
    let allowed = handle
        .evaluate_attempt(&EvaluationRequest {
            agent_id: "agent-bypass-test".to_string(),
            agent_template: "claude-code".to_string(),
            dest_host: Some("example.com".to_string()),
            dest_ip: Some("93.184.216.34".to_string()),
            dest_port: 443,
            dest_protocol: "tcp".to_string(),
            opaque: false,
        })
        .expect("evaluate allowed");
    match allowed.verdict {
        Verdict::Allow { rule_id } => assert_eq!(rule_id, "rule-allow-example"),
        other => panic!("expected Allow for example.com:443; got {other:?}"),
    }
    assert!(allowed.event_canonical_json.contains("\"egress_approved\""));

    // Bypass path (DoH).
    let denied = handle
        .evaluate_attempt(&dns_request(Some("dns.google"), "8.8.8.8", 443, "tcp"))
        .expect("evaluate DoH bypass");
    assert!(matches!(
        denied.verdict,
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny
        }
    ));
    let _ = handle.stop();
}

// ---- Tier B: real-cgroup, real-packet bypass tests ------------------------
//
// These tests exercise the full production drop path: real systemd
// transient unit + cgroup via `cgroup::create_agent_scope`, production
// `nftables::build_agent_ruleset` with the cgroup-v2 path-string emission
// fixed in PR #130, the base-output-chain jump rule wired by
// `nftables::load_agent_ruleset` (this PR), real subprocess attach via
// `cgroup::classify_pid`, real NFQUEUE verdict loop, and a real audit
// drain assertion against the daemon's policy evaluator. Closing the
// chain-wiring gap was the last load-bearing fix needed for Phase 1
// production enforcement; activation requires no test rewrite, just
// removing `#[ignore]`.
//
// **Activation status.** All three Tier B tests are active. Plain-DNS
// (UDP/53), DoH (TCP/443), and DoT (TCP/853) all exercise the full
// production drop path end-to-end (cgroup attach -> cgroupv2 match ->
// base-output-chain jump -> NFQUEUE drop -> audit assertion). The DoH
// and DoT tests were `#[ignore]`-d in PR #131 because both got 0 packets
// in NFQUEUE; v1.x housekeeping (18) traced the cause to a shell
// line-continuation interaction in the subprocess wrapper rather than
// any kernel-binding gap. The fix is a single-line `connect_ex` Python
// shape that emits one TCP SYN cleanly.

/// Test fixture: kernel-binding pieces for one bypass scenario.
struct KernelBypassFixture {
    /// Optional so [`Drop`] can take ownership of the [`DaemonHandle`]
    /// (which `daemon.stop()` consumes by value) without moving out of
    /// `&mut self`.
    daemon: Option<DaemonHandle>,
    _tempdir: TempDir,
    agent_id: String,
    scope: cgroup::ScopeHandle,
    ruleset_id: AgentRulesetId,
    nfq_thread: Option<std::thread::JoinHandle<()>>,
    nfq_stop: Arc<std::sync::atomic::AtomicBool>,
    captured: Arc<Mutex<Vec<PendingPacket>>>,
}

impl KernelBypassFixture {
    /// Stand up a daemon with example.com:443 allowed, create an agent
    /// cgroup scope, install the production ruleset (with the real
    /// `socket cgroupv2 level 2 <id>` match), and start an NFQUEUE
    /// verdict-loop thread that captures packets and drops them.
    fn setup(agent_id: &str, queue_number: u16) -> Self {
        let (daemon, tempdir) = boot_with_only_example_com_443_allowed();

        cleanup_castle_table_silent();
        nftables::install_castle_table().expect("install_castle_table");

        let scope = cgroup::create_agent_scope(agent_id).expect("create_agent_scope");
        let cgroup_relative = cgroup::cgroup_relative_path(&scope).expect("cgroup_relative_path");

        // Production ruleset: real `socket cgroupv2 level <N> "<path>"` match.
        // The allow rule covers example.com (93.184.216.34) at 443/tcp;
        // anything else hits the catchall and is queued to NFQUEUE.
        let frags = vec![NftRuleFragment {
            rule_id: "allow-example".to_string(),
            nft_expr: "ip daddr 93.184.216.34 tcp dport 443 accept".to_string(),
        }];
        let script =
            nftables::build_agent_ruleset(agent_id, &cgroup_relative, scope.cgroup_level, &frags);
        let ruleset_id = AgentRulesetId {
            agent_id: agent_id.to_string(),
            cgroup_path: scope.cgroup_path.clone(),
        };
        nftables::load_agent_ruleset(&ruleset_id, &script, scope.cgroup_level, &cgroup_relative)
            .expect("load_agent_ruleset");

        let captured: Arc<Mutex<Vec<PendingPacket>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();

        let nfq_cfg = NfqueueConfig {
            queue_number,
            ..NfqueueConfig::default()
        };
        let nfq_handle = nfqueue::bind_queue(&nfq_cfg).expect("bind_queue");
        let nfq_stop = nfq_handle.stop_flag.clone();

        let thread_handle = QueueHandle {
            queue_number: nfq_handle.queue_number,
            packets_processed: nfq_handle.packets_processed.clone(),
            packets_saturated: nfq_handle.packets_saturated.clone(),
            stop_flag: nfq_stop.clone(),
        };

        let nfq_thread = std::thread::spawn(move || {
            let cfg = NfqueueConfig {
                queue_number,
                ..NfqueueConfig::default()
            };
            let _ = nfqueue::run_verdict_loop(
                &thread_handle,
                &cfg,
                Box::new(move |pkt| {
                    captured_clone.lock().unwrap().push(pkt.clone());
                    NfVerdict::Drop
                }),
            );
        });

        Self {
            daemon: Some(daemon),
            _tempdir: tempdir,
            agent_id: agent_id.to_string(),
            scope,
            ruleset_id,
            nfq_thread: Some(nfq_thread),
            nfq_stop,
            captured,
        }
    }

    /// Spawn the bypass attempt subprocess in the agent cgroup. The shell
    /// wrapper writes the subprocess PID to `cgroup.procs` BEFORE exec'ing
    /// the real command, so the network attempt happens from inside the
    /// cgroup (no race window).
    fn spawn_bypass(&self, bypass_shell_cmd: &str) {
        let cgroup_procs = self.scope.cgroup_path.join("cgroup.procs");
        let wrapped = format!(
            "echo $$ > {} && exec {}",
            cgroup_procs.display(),
            bypass_shell_cmd
        );
        let mut child = Command::new("sh")
            .args(["-c", &wrapped])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bypass subprocess");
        // Give the kernel ~2s to route the attempt's packets through
        // nftables and into NFQUEUE for the verdict-loop thread to capture.
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Drain captured kernel packets, synthesize an `EvaluationRequest`
    /// for one of them, run it through the daemon's policy evaluator
    /// (which writes the audit entry), and return the audit canonical-JSON.
    /// Falls back to a synthetic request shape if no packets were captured
    /// so a clear assertion failure surfaces with diagnostic context.
    fn drive_audit_for_first_capture(
        &self,
        fallback_protocol: &str,
        fallback_port: u16,
        fallback_dest_ip: &str,
        fallback_dest_host: Option<&str>,
    ) -> (usize, String) {
        let snapshot = self.captured.lock().unwrap().clone();
        let captured_count = snapshot.len();

        // Use the first captured packet that looks like the expected
        // bypass shape (right protocol + port). If none match, fall back
        // to the synthetic request so the audit assertion still fires
        // and the failure mode is debuggable.
        let proto_byte: u8 = match fallback_protocol {
            "tcp" => 6,
            "udp" => 17,
            _ => 0,
        };
        let chosen = snapshot
            .iter()
            .find(|pkt| pkt.protocol == proto_byte && pkt.dest_port == fallback_port);

        let (agent_id, dest_ip, dest_port, protocol_str) = match chosen {
            Some(pkt) => (
                pkt.source_agent_id
                    .clone()
                    .unwrap_or_else(|| "missing-agent-attribution".to_string()),
                pkt.dest_ip
                    .clone()
                    .unwrap_or_else(|| fallback_dest_ip.to_string()),
                pkt.dest_port,
                fallback_protocol.to_string(),
            ),
            None => (
                self.agent_id.clone(),
                fallback_dest_ip.to_string(),
                fallback_port,
                fallback_protocol.to_string(),
            ),
        };

        let req = EvaluationRequest {
            agent_id,
            agent_template: "claude-code".to_string(),
            dest_host: fallback_dest_host.map(|h| h.to_string()),
            dest_ip: Some(dest_ip),
            dest_port,
            dest_protocol: protocol_str,
            opaque: fallback_dest_host.is_none(),
        };
        let outcome = self
            .daemon
            .as_ref()
            .expect("daemon must be present during test body")
            .evaluate_attempt(&req)
            .expect("evaluate_attempt");
        (captured_count, outcome.event_canonical_json)
    }

    /// Explicit shutdown for tests that want to control teardown ordering.
    /// Idempotent with the Drop impl: setting nfq_stop a second time and
    /// taking nfq_thread when it's already None are both no-ops.
    fn shutdown(mut self) {
        self.shutdown_in_place();
    }

    fn shutdown_in_place(&mut self) {
        // Stop the NFQUEUE listener thread FIRST so it releases its
        // netlink binding on queue 0 before any later test re-binds.
        // Without this, a panic in the test body leaves the thread alive
        // and competing for packets the next test emits.
        self.nfq_stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.nfq_thread.take() {
            // Bounded join: the verdict loop polls stop_flag every ~10ms
            // (non-blocking recv + brief sleep), so this returns promptly.
            let _ = thread.join();
        }
        let _ = nftables::remove_agent_ruleset(&self.ruleset_id);
        cleanup_castle_table_silent();
        let _ = cgroup::destroy_agent_scope(&self.scope);
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.stop();
        }
    }
}

impl Drop for KernelBypassFixture {
    /// Belt-and-suspenders cleanup. Without this, an `assert!` panic in
    /// the test body skips the explicit `shutdown()` call and leaks the
    /// NFQUEUE listener thread bound to queue 0. A leaked listener
    /// captures packets emitted by the NEXT test's bypass subprocess
    /// into an orphaned `captured` Vec, so the next test sees zero
    /// packets and panics in the same place. Drop fires during stack
    /// unwinding on panic, so this guarantees teardown regardless of
    /// whether the test asserted cleanly or aborted mid-body.
    fn drop(&mut self) {
        self.shutdown_in_place();
    }
}

fn cleanup_castle_table_silent() {
    let _ = std::process::Command::new("nft")
        .args(["delete", "table", "inet", "sanctuary-castle"])
        .output();
}

/// Real-cgroup-driven plain DNS bypass test. Creates an agent cgroup,
/// installs the production castle-wall ruleset (real `socket cgroupv2`
/// match) that only allows example.com:443, attaches a subprocess to the
/// cgroup that attempts UDP/53 to 8.8.8.8, captures packets via the
/// NFQUEUE verdict loop, and asserts the daemon's audit emits an
/// `egress_blocked` + `default_deny` shape for the bypass.
#[test]
fn kernel_drops_plain_dns_to_unallowed_resolver() {
    // queue_number 0 matches `build_agent_ruleset`'s hardcoded
    // `queue num 0` catchall verdict. CI runs castle-wall integration
    // tests with --test-threads=1, so there is no parallel-bind conflict
    // across the three Tier B tests; each test binds and releases queue 0
    // in sequence.
    let fixture = KernelBypassFixture::setup("dns-bypass-test", 0);

    // `nslookup` is in `bsdmainutils` on Ubuntu and may not always be
    // present on a stripped runner. Fall back to a Rust-equivalent that
    // any Linux ships: a UDP send to 8.8.8.8:53. The shell wrapper
    // ensures the sender is in the agent cgroup before sending.
    fixture.spawn_bypass(
        "python3 -c \"import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1.0);s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01',('8.8.8.8',53));\\\nimport time;time.sleep(0.3)\" || true",
    );

    let (captured_count, audit_json) =
        fixture.drive_audit_for_first_capture("udp", 53, "8.8.8.8", None);

    assert!(
        captured_count >= 1,
        "expected at least one packet in NFQUEUE for plain-DNS bypass; got 0. \
         This suggests either the cgroupv2 match did not fire (production ruleset bug) \
         or the subprocess did not enter the cgroup."
    );
    assert!(
        audit_json.contains("\"agent_id\":\"dns-bypass-test\""),
        "audit must attribute NFQUEUE packet to wrapped agent; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"egress_blocked\""),
        "audit must record egress_blocked; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"default_deny\""),
        "audit must record default_deny provenance; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"udp\""),
        "audit must record udp protocol; got: {audit_json}"
    );

    fixture.shutdown();
}

/// Real-cgroup-driven DoH bypass test. Same shape as the plain DNS
/// activation, but the subprocess opens a TCP/443 connection to
/// `dns.google` (8.8.8.8). Asserts the production ruleset's catchall
/// queues the SYN to NFQUEUE and the audit records `egress_blocked` for
/// tcp/443 with `default_deny` provenance.
#[test]
fn kernel_drops_doh_to_unallowed_provider() {
    // queue_number 0 matches the hardcoded `queue num 0` catchall in
    // `build_agent_ruleset`. CI's --test-threads=1 prevents parallel-bind
    // conflict; the prior plain-DNS test releases queue 0 before this
    // one binds. Without the queue-number alignment the bind would
    // succeed but no packets would arrive (the kernel routes the
    // catchall verdict to queue 0, not whatever this test bound).
    let fixture = KernelBypassFixture::setup("doh-bypass-test", 0);

    // TCP SYN to 8.8.8.8:443 from inside the agent cgroup. The kernel's
    // `socket cgroupv2` match fires on the SYN packet's owning socket,
    // queueing it to NFQUEUE before any TLS handshake completes. Python's
    // socket library connect() with a short timeout is a deterministic
    // way to emit one SYN and surface the captured packet.
    // Single-line valid Python: `connect_ex` returns errno on failure
    // instead of raising, so no `try:`/`except:` block is needed. The
    // earlier shape used `try:`/`except:` with `\<newline>` separators
    // inside the shell double-quoted command, but sh strips
    // backslash-newline as a line continuation inside double quotes,
    // collapsing the script onto one logical line where Python rejects
    // `try: ... except: ...` as a SyntaxError. The subprocess died
    // before any SYN was emitted, so NFQUEUE never saw a packet.
    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);s.connect_ex(('8.8.8.8',443))\" || true",
    );

    let (captured_count, audit_json) =
        fixture.drive_audit_for_first_capture("tcp", 443, "8.8.8.8", Some("dns.google"));

    assert!(
        captured_count >= 1,
        "expected at least one packet in NFQUEUE for DoH bypass; got 0. \
         This suggests the production cgroupv2 match did not fire."
    );
    assert!(
        audit_json.contains("\"agent_id\":\"doh-bypass-test\""),
        "audit must attribute NFQUEUE packet to wrapped agent; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"egress_blocked\""),
        "audit must record egress_blocked; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"default_deny\""),
        "audit must record default_deny provenance; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"tcp\""),
        "audit must record tcp protocol; got: {audit_json}"
    );

    fixture.shutdown();
}

/// Real-cgroup-driven DoT bypass test. Same shape as the DoH activation,
/// but the subprocess opens a TCP/853 connection to a DoT provider
/// (cloudflare-dns.com / 1.1.1.1). Asserts the kernel drop fires before
/// the TLS handshake completes; audit records `egress_blocked` for
/// tcp/853 with `default_deny` provenance.
#[test]
fn kernel_drops_dot_to_unallowed_resolver() {
    // queue_number 0 matches the hardcoded `queue num 0` catchall.
    // See the queue-alignment note on kernel_drops_doh_to_unallowed_provider.
    let fixture = KernelBypassFixture::setup("dot-bypass-test", 0);

    // Single-line valid Python via `connect_ex`. See the matching note
    // on `kernel_drops_doh_to_unallowed_provider` for why the earlier
    // `try:`/`except:` shape failed (sh line-continuation collapses the
    // script onto one logical line, Python rejects `try:`/`except:` on
    // the same line as a SyntaxError, subprocess dies before SYN).
    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);s.connect_ex(('1.1.1.1',853))\" || true",
    );

    let (captured_count, audit_json) =
        fixture.drive_audit_for_first_capture("tcp", 853, "1.1.1.1", Some("cloudflare-dns.com"));

    assert!(
        captured_count >= 1,
        "expected at least one packet in NFQUEUE for DoT bypass; got 0. \
         This suggests the production cgroupv2 match did not fire."
    );
    assert!(
        audit_json.contains("\"agent_id\":\"dot-bypass-test\""),
        "audit must attribute NFQUEUE packet to wrapped agent; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"egress_blocked\""),
        "audit must record egress_blocked; got: {audit_json}"
    );
    assert!(
        audit_json.contains("\"default_deny\""),
        "audit must record default_deny provenance; got: {audit_json}"
    );
    // `dest_port` is a JSON integer in the audit canonical-JSON, so the
    // substring is `853` without surrounding double quotes (matches the
    // shape used by the working plain-DNS test's `contains("53")`).
    assert!(
        audit_json.contains("853"),
        "audit must record port 853; got: {audit_json}"
    );

    fixture.shutdown();
}
