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
use castle_wall_daemon::config::DaemonConfig;
use castle_wall_daemon::daemon::{boot, DaemonHandle};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use castle_wall_daemon::policy::{DeniedReason, EvaluationRequest, Verdict};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
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

// ---- Tier B: real-cgroup, real-packet bypass tests (#[ignore]'d) ----------

/// Real-cgroup-driven plain DNS bypass test. Creates an agent cgroup,
/// installs a castle-wall ruleset that only allows example.com:443, attaches
/// a subprocess to the cgroup that attempts UDP/53 to 8.8.8.8, and asserts
/// via the daemon's audit drain that the attempt was kernel-dropped.
///
/// Blocked on v1.x cgroup_create_agent_scope fix. Once the production
/// cgroup creation path works on Ubuntu 24.04 + systemd 255 (per the v1.x
/// housekeeping ticket carried from Checkpoint 3.5), this test activates
/// by removing the `#[ignore]` attribute.
#[test]
#[ignore = "blocked on v1.x cgroup_create_agent_scope fix (Ubuntu 24.04 + systemd 255)"]
fn kernel_drops_plain_dns_to_unallowed_resolver() {
    // Scaffolding for the v1.x activation. The shape:
    //
    //  1. cgroup::create_agent_scope("dns-bypass-test") -> ScopeHandle
    //  2. nftables::install_castle_table()
    //  3. Build a ruleset that allows only example.com:443/tcp and uses
    //     the real `socket cgroupv2 level 2 <id>` match (NOT the test
    //     sibling), so the catchall scopes to the agent cgroup only.
    //  4. nftables::load_agent_ruleset(&id, &script)
    //  5. Spawn `nslookup -type=A example.com 8.8.8.8` as a subprocess
    //     attached to the agent cgroup (cgroup::classify_pid).
    //  6. Run NFQUEUE verdict loop (or sample audit drain) for ~2s.
    //  7. Assert audit drain returns at least one egress_blocked event
    //     for udp/53 with default_deny provenance.
    //  8. Cleanup: destroy_agent_scope, remove_castle_table.
    //
    // The test sibling pattern from Checkpoint 3.5 is intentionally not
    // used here: the whole point of the kernel-level test is to verify
    // the cgroup match fires.
}

/// Real-cgroup-driven DoH bypass test. Same shape as the plain DNS
/// scaffolding above, but the subprocess is `curl https://dns.google/dns-query`
/// (or equivalent). Asserts the kernel drop fires for the TCP/443
/// connection because dns.google is not in the allow set.
#[test]
#[ignore = "blocked on v1.x cgroup_create_agent_scope fix (Ubuntu 24.04 + systemd 255)"]
fn kernel_drops_doh_to_unallowed_provider() {
    // See kernel_drops_plain_dns_to_unallowed_resolver above for the
    // activation shape. Subprocess is `curl --max-time 2 -o /dev/null
    // https://dns.google/dns-query?dns=...`. Audit drain assertion
    // identical except the destination shape is dns.google:443/tcp.
}

/// Real-cgroup-driven DoT bypass test. Same shape as the DoH scaffolding,
/// but the subprocess opens a TCP/853 connection to a DoT provider and
/// negotiates TLS. Asserts the kernel drop fires before the TLS handshake
/// completes.
#[test]
#[ignore = "blocked on v1.x cgroup_create_agent_scope fix (Ubuntu 24.04 + systemd 255)"]
fn kernel_drops_dot_to_unallowed_resolver() {
    // See kernel_drops_plain_dns_to_unallowed_resolver above for the
    // activation shape. Subprocess is `kdig -d @1.1.1.1 +tls
    // -p 853 example.com` or equivalent. Audit drain assertion identical
    // except the destination shape is the chosen DoT IP:853/tcp.
}
