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

mod isolation;

use base64::Engine as _;
use castle_wall_daemon::cgroup;
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::{boot, DaemonHandle};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use castle_wall_daemon::nftables::{self, AgentRulesetId};
use castle_wall_daemon::policy::{DeniedReason, EvaluationRequest, Verdict};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
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

/// Boot a daemon with a single IP-pinned allow rule. Every
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
        trusted_service_uid: Some(unsafe { libc::geteuid() }),
        // ISOLATION (AGENTS.md, "the operator's machine is not a fixture"): the
        // host lock, ownership journal, and journal MAC key land in this run's
        // temp root, never in /var/lib/sanctuary.
        linux_runtime_paths: isolation::runtime_paths(),
    };
    let handle = boot(config).expect("boot");
    (handle, dir)
}

fn write_signed_allow_only_example_443(policy_dir: &Path, signing: &SigningKey) {
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let body = b"{\"id\":\"rule-allow-example\",\"schema_version\":1,\"created_at\":\"2026-05-06T00:00:00Z\",\"match\":{\"ip\":[\"203.0.113.44\"],\"port\":[443],\"protocol\":\"tcp\"},\"disposition\":\"allow\"}";
    fs::write(
        policy_dir
            .join(RULES_SUBDIR)
            .join("rule-allow-example.json"),
        body,
    )
    .unwrap();
    // Every composed manifest must carry the genuine habeas local lane
    // (always-on-lane gate). Scoped to the reserved emitter id, so it cannot
    // satisfy any agent-classified flow in these bypass tests.
    let habeas_body = castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
    fs::write(
        policy_dir
            .join(RULES_SUBDIR)
            .join("reserved_habeas_distress_local.json"),
        habeas_body,
    )
    .unwrap();

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-06T00:00:00Z".to_string(),
        generation: 1,
        agent_origin: None,
        operator_baseline: None,
        rules: vec![
            ManifestRuleEntry {
                rule_id: "rule-allow-example".to_string(),
                file: "rule-allow-example.json".to_string(),
                sha256: sha256_hex(body),
            },
            ManifestRuleEntry {
                rule_id: "reserved_habeas_distress_local".to_string(),
                file: "reserved_habeas_distress_local.json".to_string(),
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
            signing_key_id: castle_wall_daemon::crypto::castle_wall_signing_key_id(
                &signing.verifying_key().to_bytes(),
            )
            .unwrap(),
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
    let _suite = isolation::guard();
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
            // Must match the IP the single allow rule pins
            // (`write_signed_allow_only_example_443` writes ip 203.0.113.44,
            // the RFC 5737 documentation address). The rule matches on IP, so
            // the allowed request has to carry that exact IP to resolve to Allow.
            dest_ip: Some("203.0.113.44".to_string()),
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
// These tests exercise the PRODUCTION drop path end to end, with the DAEMON as
// the sole NFQUEUE consumer. `daemon::boot` on a privileged Linux host
// activates the kernel enforcement runtime (`activate_kernel_runtime` ->
// `EnforcementRuntime::start` -> `NfqueueProvider`): it installs the isolated
// castle table under the host ownership lock, binds NFQUEUE queue 0 with
// fail-open OFF, and runs the verdict loop wired to the shared DecisionEngine
// via `build_verdict_callback`. NFQUEUE queue 0 is a host-global singleton, so
// a test MUST NOT bind a second listener on it or install a competing castle
// table: the daemon already owns both, and a second `bind(0)` returns EPERM.
// (An earlier version of these tests stood up their own queue-0 listener; that
// bind failed EPERM under the now-active daemon enforcement, the error was
// swallowed, and every capture came back empty. See the fixture below.)
//
// The test's job is therefore: (1) wrap a real agent cgroup and install its
// per-agent chain + base-output jump INTO THE DAEMON'S owned table so the
// cgroup's packets carry the agent mark and route to queue 0; (2) emit a real
// non-allowlisted packet from inside that cgroup; (3) prove the daemon's own
// verdict loop dequeued it, defaulted closed (kernel DROP with fail-open off),
// and wrote the scope-lock audit shape (egress_blocked + default_deny,
// attributed to the wrapped agent) to the durable WAL. Asserting on the
// daemon's WAL is the production-faithful proof: the WAL receipt exists only
// because the daemon's verdict loop received the real packet off NFQUEUE.

/// Test fixture: one wrapped agent whose non-allowlisted egress the booted
/// daemon must drop and audit through its own verdict loop.
struct KernelBypassFixture {
    /// Optional so [`Drop`] can take ownership of the [`DaemonHandle`]
    /// (`daemon.stop()` consumes by value) without moving out of `&mut self`.
    daemon: Option<DaemonHandle>,
    _tempdir: TempDir,
    agent_id: String,
    scope: cgroup::ScopeHandle,
    ruleset_id: AgentRulesetId,
}

impl KernelBypassFixture {
    /// Boot the enforcing daemon, then wrap one agent cgroup and route its
    /// egress to the daemon-owned NFQUEUE 0.
    fn setup(agent_id: &str) -> Self {
        // Boot activates enforcement: installs the isolated castle table under
        // the host lock, binds queue 0 fail-open-off, and starts the verdict
        // loop. The daemon is now the NFQUEUE consumer for this process.
        let (daemon, tempdir) = boot_with_only_example_com_443_allowed();

        // Wrap a real agent cgroup and install its per-agent chain + base-output
        // jump INTO THE DAEMON'S owned table. `build_agent_ruleset` registers
        // the agent's nfmark (so the daemon's verdict loop can attribute the
        // dequeued packet back to this agent) and emits the
        // `socket cgroupv2 ... meta mark set <mark> queue to 0` catchall;
        // `load_agent_ruleset` wires the base-output-chain jump. The load
        // authorizes because the daemon already holds this process's single nft
        // runtime ownership identity.
        let scope = cgroup::create_agent_scope(agent_id).expect("create_agent_scope");
        let cgroup_relative = cgroup::cgroup_relative_path(&scope).expect("cgroup_relative_path");
        let ruleset_id = AgentRulesetId {
            agent_id: agent_id.to_string(),
            cgroup_path: scope.cgroup_path.clone(),
        };
        // Static fragments are intentionally empty: the NFQUEUE-only model
        // routes every unmatched packet to the daemon's userspace evaluator,
        // which is exactly what these bypass tests exercise.
        let script =
            nftables::build_agent_ruleset(agent_id, &cgroup_relative, scope.cgroup_level, &[]);
        nftables::load_agent_ruleset(&ruleset_id, &script, scope.cgroup_level, &cgroup_relative)
            .expect("load_agent_ruleset into daemon-owned table");

        Self {
            daemon: Some(daemon),
            _tempdir: tempdir,
            agent_id: agent_id.to_string(),
            scope,
            ruleset_id,
        }
    }

    /// Spawn the bypass attempt subprocess in the agent cgroup. The shell
    /// wrapper writes the subprocess PID to `cgroup.procs` BEFORE exec'ing the
    /// real command, so the socket the packet leaves on is owned inside the
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
        // Give the kernel + daemon verdict loop time to route the attempt's
        // packets through nftables into NFQUEUE and have the daemon dequeue,
        // evaluate, drop, and durably audit them.
        std::thread::sleep(Duration::from_secs(2));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Poll the daemon's durable WAL for the drop receipt its verdict loop
    /// writes when it dequeues the agent's non-allowlisted packet from NFQUEUE,
    /// evaluates it against the shared DecisionEngine (default-deny), and drops
    /// it. Returns the first matching audit canonical-JSON. The receipt exists
    /// ONLY because the daemon's verdict loop received the real kernel packet;
    /// a synthesized request would never carry this agent's attribution here.
    fn await_agent_drop_audit(&self) -> Option<String> {
        let wal = self
            .daemon
            .as_ref()
            .expect("daemon present during test body")
            .wal_writer()
            .expect("wal writer");
        let agent_needle = format!("\"agent_id\":\"{}\"", self.agent_id);
        // Up to ~4s: the verdict loop polls the queue every ~10ms and the WAL
        // append is synchronous inside evaluate_attempt.
        for _ in 0..80 {
            let snapshot = {
                let mut guard = wal.lock().unwrap();
                guard.snapshot_after(None, 512).unwrap_or_default()
            };
            if let Some(entry) = snapshot.iter().find(|e| {
                e.event_canonical_json.contains(&agent_needle)
                    && e.event_canonical_json.contains("\"egress_blocked\"")
                    && e.event_canonical_json.contains("\"default_deny\"")
            }) {
                return Some(entry.event_canonical_json.clone());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Explicit shutdown for tests that want to control teardown ordering.
    /// Idempotent with the Drop impl.
    fn shutdown(mut self) {
        self.shutdown_in_place();
    }

    fn shutdown_in_place(&mut self) {
        // Remove the per-agent chain/jump while the daemon still holds nft
        // runtime ownership (remove_agent_ruleset verifies it), then tear down
        // the cgroup, then stop the daemon (which releases the owned table and
        // unbinds queue 0). Reversing this order would try to mutate a table
        // the stopped daemon no longer owns.
        let _ = nftables::remove_agent_ruleset(&self.ruleset_id);
        let _ = cgroup::destroy_agent_scope(&self.scope);
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.stop();
        }
    }
}

impl Drop for KernelBypassFixture {
    /// Belt-and-suspenders cleanup so an `assert!` panic in the test body still
    /// removes the agent ruleset, destroys the cgroup, and stops the daemon
    /// (releasing the owned nft table and unbinding queue 0) during unwinding.
    fn drop(&mut self) {
        self.shutdown_in_place();
    }
}

/// Real-cgroup-driven plain DNS bypass test. Wraps an agent cgroup whose only
/// allowed destination is example.com:443, emits UDP/53 to 8.8.8.8 from inside
/// that cgroup, and asserts the DAEMON's own verdict loop dropped and audited
/// the packet (egress_blocked + default_deny, attributed to the agent).
#[test]
fn kernel_drops_plain_dns_to_unallowed_resolver() {
    let _suite = isolation::guard();
    let fixture = KernelBypassFixture::setup("dns-bypass-test");

    // UDP send to 8.8.8.8:53 from inside the agent cgroup. The shell wrapper
    // ensures the sender is in the cgroup before sending, so the packet's
    // owning socket matches the daemon's `socket cgroupv2` catchall and is
    // queued to NFQUEUE 0.
    fixture.spawn_bypass(
        "python3 -c \"import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1.0);s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01',('8.8.8.8',53));\\\nimport time;time.sleep(0.3)\" || true",
    );

    let audit = fixture.await_agent_drop_audit().expect(
        "daemon verdict loop must dequeue, drop, and durably audit the \
         non-allowlisted plain-DNS packet; got no egress_blocked WAL receipt \
         for the agent. Either the cgroupv2 match/jump did not route the packet \
         to queue 0, the subprocess did not enter the cgroup, or the daemon's \
         NFQUEUE consumer is not live.",
    );
    assert!(
        audit.contains("\"udp\""),
        "audit must record udp protocol; got: {audit}"
    );
    assert!(
        audit.contains("53"),
        "audit must record port 53; got: {audit}"
    );

    fixture.shutdown();
}

/// Real-cgroup-driven DoH bypass test. Opens a TCP/443 connection to
/// `dns.google` (8.8.8.8) from inside the agent cgroup and asserts the daemon's
/// verdict loop dropped + audited the SYN (egress_blocked, tcp/443,
/// default_deny) before any TLS handshake.
#[test]
fn kernel_drops_doh_to_unallowed_provider() {
    let _suite = isolation::guard();
    let fixture = KernelBypassFixture::setup("doh-bypass-test");

    // TCP SYN to 8.8.8.8:443 from inside the agent cgroup. `connect_ex` returns
    // errno instead of raising, so a single-line Python emits exactly one SYN
    // whose owning socket the daemon's cgroupv2 catchall queues to NFQUEUE 0
    // before the handshake completes.
    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);s.connect_ex(('8.8.8.8',443))\" || true",
    );

    let audit = fixture.await_agent_drop_audit().expect(
        "daemon verdict loop must dequeue, drop, and durably audit the \
         non-allowlisted DoH SYN; got no egress_blocked WAL receipt for the agent.",
    );
    assert!(
        audit.contains("\"tcp\""),
        "audit must record tcp protocol; got: {audit}"
    );
    assert!(
        audit.contains("443"),
        "audit must record port 443; got: {audit}"
    );

    fixture.shutdown();
}

/// Real-cgroup-driven DoT bypass test. Opens a TCP/853 connection to a DoT
/// provider (1.1.1.1) from inside the agent cgroup and asserts the daemon's
/// verdict loop dropped + audited the SYN (egress_blocked, tcp/853,
/// default_deny) before the TLS handshake.
#[test]
fn kernel_drops_dot_to_unallowed_resolver() {
    let _suite = isolation::guard();
    let fixture = KernelBypassFixture::setup("dot-bypass-test");

    // Single-line valid Python via `connect_ex`; one TCP SYN to 1.1.1.1:853
    // from inside the agent cgroup.
    fixture.spawn_bypass(
        "python3 -c \"import socket;s=socket.socket();s.settimeout(1.5);s.connect_ex(('1.1.1.1',853))\" || true",
    );

    let audit = fixture.await_agent_drop_audit().expect(
        "daemon verdict loop must dequeue, drop, and durably audit the \
         non-allowlisted DoT SYN; got no egress_blocked WAL receipt for the agent.",
    );
    assert!(
        audit.contains("\"tcp\""),
        "audit must record tcp protocol; got: {audit}"
    );
    // `dest_port` is a JSON integer in the audit canonical-JSON, so the
    // substring is `853` without surrounding double quotes.
    assert!(
        audit.contains("853"),
        "audit must record port 853; got: {audit}"
    );

    fixture.shutdown();
}
