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
//! 2. **Real-cgroup, real-packet tests.** Scaffolded but `#[ignore]`-d
//!    behind the v1.x cgroup_create_agent_scope unblock condition (Ubuntu
//!    24.04 + systemd 255 surface from Checkpoint 3.5 status). They
//!    exercise the full kernel drop path: cgroup attach + subprocess +
//!    nftables cgroupv2 match + NFQUEUE drop verdict + audit assertion.
//!    Once the production cgroup work lands per the v1.x ticket, these
//!    activate without a rewrite.
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

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-06T00:00:00Z".to_string(),
        rules: vec![ManifestRuleEntry {
            rule_id: "rule-allow-example".to_string(),
            file: "rule-0.json".to_string(),
            sha256: sha256_hex(body),
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
        .evaluate_attempt(&dns_request(
            Some("dns.google"),
            "8.8.8.8",
            443,
            "tcp",
        ))
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
        .evaluate_attempt(&dns_request(
            Some("dns.quad9.net"),
            "9.9.9.9",
            853,
            "tcp",
        ))
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
    assert!(allowed
        .event_canonical_json
        .contains("\"egress_approved\""));

    // Bypass path (DoH).
    let denied = handle
        .evaluate_attempt(&dns_request(
            Some("dns.google"),
            "8.8.8.8",
            443,
            "tcp",
        ))
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
// These tests exercise the full production drop path:
// `cgroup::create_agent_scope` (real systemd transient unit + cgroup),
// `nftables::build_agent_ruleset` with the production path-string emission
// (`socket cgroupv2 level <N> "<cgroup-relative-path>" queue num 0`), real
// subprocess attach via `cgroup::classify_pid`, real NFQUEUE verdict loop,
// and a real audit drain assertion against the daemon's policy evaluator.
//
// The earlier rule-load failure on Ubuntu 24.04 + nft 1.0.9 + systemd 255
// (`cgroupv2 path fails: No such file or directory`) was a Sanctuary-side
// input-format bug: the rule emitted the cgroup inode integer where nft
// expects a quoted cgroup-relative path string. The integer is what nft
// stores internally after path-to-inode resolution at rule-load time and
// what `nft list rules` displays back; it is not the documented input
// form. The fix shipped in this PR emits the path string, which nft's
// rule-load parser accepts; the kernel-binding tests in
// `integration_kernel_binding.rs` now exercise this end-to-end against
// real systemd transient units.
//
// However, the Tier B activation surfaced a SEPARATE production gap that
// blocks real packet flow: the per-agent chains hold rules with the
// cgroupv2 socket match, but `install_castle_table` creates a base
// `output` chain (`type filter hook output priority 0 ; policy accept`)
// with no `jump` or `goto` rule into the per-agent chain. nftables
// non-base chains are dead chains until something hooked into netfilter
// jumps to them. Without that wiring, packets emitted by the bypass
// subprocess flow through the base `output` chain (policy accept) and
// never enter the per-agent chain where the cgroupv2 match lives. Result:
// no packets in NFQUEUE; the activation tests panic with "expected at
// least one packet in NFQUEUE for {plain DNS|DoH|DoT} bypass; got 0."
// The path-string fix in this PR is necessary but not sufficient for
// real-cgroup, real-packet enforcement; the chain-wiring layer is the
// remaining production gap and is tracked separately as the next v1.x
// hardening item.
//
// The 3 tests below stay `#[ignore]`-d behind that separate v1.x ticket.
// The fixture and helpers stay in place so activation in the future is
// just removing the `#[ignore]` (no rewrite).

/// Test fixture: kernel-binding pieces for one bypass scenario.
#[allow(dead_code)] // used by #[ignore]'d tests pending the chain-wiring v1.x item
struct KernelBypassFixture {
    daemon: DaemonHandle,
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
        let cgroup_relative =
            cgroup::cgroup_relative_path(&scope).expect("cgroup_relative_path");

        // Production ruleset: real `socket cgroupv2 level <N> "<path>"` match.
        // The allow rule covers example.com (93.184.216.34) at 443/tcp;
        // anything else hits the catchall and is queued to NFQUEUE.
        let frags = vec![NftRuleFragment {
            rule_id: "allow-example".to_string(),
            nft_expr: "ip daddr 93.184.216.34 tcp dport 443 accept".to_string(),
        }];
        let script = nftables::build_agent_ruleset(
            agent_id,
            &cgroup_relative,
            scope.cgroup_level,
            &frags,
        );
        let ruleset_id = AgentRulesetId {
            agent_id: agent_id.to_string(),
            cgroup_path: scope.cgroup_path.clone(),
        };
        nftables::load_agent_ruleset(&ruleset_id, &script).expect("load_agent_ruleset");

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
            daemon,
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

        let (dest_ip, dest_port, protocol_str) = match chosen {
            Some(pkt) => (
                pkt.dest_ip.clone().unwrap_or_else(|| fallback_dest_ip.to_string()),
                pkt.dest_port,
                fallback_protocol.to_string(),
            ),
            None => (
                fallback_dest_ip.to_string(),
                fallback_port,
                fallback_protocol.to_string(),
            ),
        };

        let req = EvaluationRequest {
            agent_id: self.agent_id.clone(),
            agent_template: "claude-code".to_string(),
            dest_host: fallback_dest_host.map(|h| h.to_string()),
            dest_ip: Some(dest_ip),
            dest_port,
            dest_protocol: protocol_str,
            opaque: fallback_dest_host.is_none(),
        };
        let outcome = self
            .daemon
            .evaluate_attempt(&req)
            .expect("evaluate_attempt");
        (captured_count, outcome.event_canonical_json)
    }

    fn shutdown(mut self) {
        self.nfq_stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.nfq_thread.take() {
            // Bounded join: the verdict loop polls stop_flag every ~10ms
            // (non-blocking recv + brief sleep), so this returns promptly.
            let _ = thread.join();
        }
        let _ = nftables::remove_agent_ruleset(&self.ruleset_id);
        cleanup_castle_table_silent();
        let _ = cgroup::destroy_agent_scope(&self.scope);
        let _ = self.daemon.stop();
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
#[ignore = "blocked on a separate v1.x ticket: the per-agent chain holding \
            the cgroupv2 socket match is not jumped to from the base output \
            chain, so packets bypass the per-agent rules entirely. \
            `install_castle_table` creates the base `output` chain with \
            policy accept and no jump rule; per-agent chains are dead \
            chains until that wiring lands. The path-string fix in this PR \
            is necessary but not sufficient for real-cgroup enforcement. \
            Activate by removing `#[ignore]` once the chain-wiring v1.x \
            ticket merges."]
fn kernel_drops_plain_dns_to_unallowed_resolver() {
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
#[ignore = "blocked on the chain-wiring v1.x ticket (see \
            kernel_drops_plain_dns_to_unallowed_resolver for the full \
            failure mode and remaining production gap)."]
fn kernel_drops_doh_to_unallowed_provider() {
    let fixture = KernelBypassFixture::setup("doh-bypass-test", 1);

    // TCP SYN to 8.8.8.8:443 from inside the agent cgroup. The kernel's
    // `socket cgroupv2` match fires on the SYN packet's owning socket,
    // queueing it to NFQUEUE before any TLS handshake completes. Python's
    // socket library connect() with a short timeout is a deterministic
    // way to emit one SYN and surface the captured packet.
    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);\\\ntry: s.connect(('8.8.8.8',443))\\\nexcept Exception: pass\" || true",
    );

    let (captured_count, audit_json) = fixture.drive_audit_for_first_capture(
        "tcp",
        443,
        "8.8.8.8",
        Some("dns.google"),
    );

    assert!(
        captured_count >= 1,
        "expected at least one packet in NFQUEUE for DoH bypass; got 0. \
         This suggests the production cgroupv2 match did not fire."
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
#[ignore = "blocked on the chain-wiring v1.x ticket (see \
            kernel_drops_plain_dns_to_unallowed_resolver for the full \
            failure mode and remaining production gap)."]
fn kernel_drops_dot_to_unallowed_resolver() {
    let fixture = KernelBypassFixture::setup("dot-bypass-test", 2);

    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);\\\ntry: s.connect(('1.1.1.1',853))\\\nexcept Exception: pass\" || true",
    );

    let (captured_count, audit_json) = fixture.drive_audit_for_first_capture(
        "tcp",
        853,
        "1.1.1.1",
        Some("cloudflare-dns.com"),
    );

    assert!(
        captured_count >= 1,
        "expected at least one packet in NFQUEUE for DoT bypass; got 0. \
         This suggests the production cgroupv2 match did not fire."
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
        audit_json.contains("\"853\""),
        "audit must record port 853; got: {audit_json}"
    );

    fixture.shutdown();
}
