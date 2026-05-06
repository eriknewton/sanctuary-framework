//! Integration tests for the kernel-binding modules: nftables, cgroup v2, and
//! NFQUEUE. These tests exercise real kernel primitives and require Linux with
//! CAP_NET_ADMIN (root). They run in the CI `castle-wall-linux-integration`
//! job on Ubuntu 24.04.
//!
//! On macOS (the dev sandbox), the entire file is cfg-gated out. `cargo test`
//! on macOS sees zero tests from this file.
//!
//! Per scope-lock section 9 Tier 0: these are required coverage.

#![cfg(target_os = "linux")]

use castle_wall_daemon::nftables::{
    self, AgentRulesetId, NftRuleFragment, CASTLE_FAMILY, CASTLE_TABLE,
};
use castle_wall_daemon::cgroup;
use castle_wall_daemon::nfqueue::{self, NfqueueConfig};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;

// ---- helpers ---------------------------------------------------------------

fn nft_cmd(args: &[&str]) -> String {
    let output = Command::new("nft")
        .args(args)
        .output()
        .expect("nft binary must be available");
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn cleanup_castle_table() {
    let _ = Command::new("nft")
        .args(["delete", "table", CASTLE_FAMILY, CASTLE_TABLE])
        .output();
}

/// Create a transient systemd scope for testing and return its path + cgroup id.
/// nftables `socket cgroupv2 level 2 <id>` validates the cgroup id at rule-load
/// time by walking /sys/fs/cgroup. Plain mkdir cgroups under /sys/fs/cgroup
/// are not always resolvable by nft (observed on Ubuntu 24.04 CI runner with
/// nft 1.x), so tests use systemd-run --scope to create cgroups under
/// /sys/fs/cgroup/system.slice/<name>.scope/ that mirror the production path.
fn create_test_cgroup(name: &str) -> (PathBuf, u64) {
    use std::os::unix::fs::MetadataExt;
    let unit = format!("sanctuary-castle-test-{name}.scope");
    let cgroup_path = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));

    // Best-effort cleanup of any prior run.
    let _ = Command::new("systemctl").args(["stop", &unit]).output();

    let output = Command::new("systemd-run")
        .args([
            "--scope",
            "--unit",
            &unit,
            "--property=Delegate=yes",
            "--remain-after-exit",
            "/bin/true",
        ])
        .output()
        .expect("systemd-run available on Linux CI");
    if !output.status.success() {
        panic!(
            "systemd-run --scope failed for {}: {}",
            unit,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let meta = std::fs::metadata(&cgroup_path)
        .unwrap_or_else(|e| panic!("metadata {}: {}", cgroup_path.display(), e));
    (cgroup_path, meta.ino())
}

/// Tear down the transient scope created by `create_test_cgroup`.
fn destroy_test_cgroup(cgroup_path: &std::path::Path) {
    if let Some(unit_name) = cgroup_path.file_name().and_then(|n| n.to_str()) {
        let _ = Command::new("systemctl").args(["stop", unit_name]).output();
    }
}

// ---- nftables tests -------------------------------------------------------

#[test]
fn nftables_install_castle_table_creates_and_is_idempotent() {
    cleanup_castle_table();

    nftables::install_castle_table().expect("install_castle_table");
    assert!(
        nftables::table_exists().expect("table_exists"),
        "sanctuary-castle table should exist after install"
    );

    // Idempotent.
    nftables::install_castle_table().expect("install_castle_table (idempotent)");
    assert!(nftables::table_exists().expect("table_exists"));

    cleanup_castle_table();
}

#[test]
fn nftables_load_and_remove_agent_ruleset() {
    cleanup_castle_table();
    nftables::install_castle_table().expect("install");

    let (cgroup_path, cgroup_id) = create_test_cgroup("agent-1");
    let id = AgentRulesetId {
        agent_id: "test-agent-1".to_string(),
        cgroup_path: cgroup_path.clone(),
    };

    let frags = vec![NftRuleFragment {
        rule_id: "r-test-1".to_string(),
        nft_expr: "tcp dport 443 accept".to_string(),
    }];
    let script = nftables::build_agent_ruleset("test-agent-1", cgroup_id, &frags);
    nftables::load_agent_ruleset(&id, &script).expect("load_agent_ruleset");

    let output = nft_cmd(&["list", "table", CASTLE_FAMILY, CASTLE_TABLE]);
    assert!(
        output.contains("agent_test-agent-1"),
        "agent chain should appear: {}",
        output
    );

    let listed = nftables::list_agent_rulesets().expect("list");
    assert!(listed.iter().any(|r| r.agent_id == "test-agent-1"));

    nftables::remove_agent_ruleset(&id).expect("remove_agent_ruleset");
    let listed = nftables::list_agent_rulesets().expect("list after remove");
    assert!(!listed.iter().any(|r| r.agent_id == "test-agent-1"));

    cleanup_castle_table();
    destroy_test_cgroup(&cgroup_path);
}

#[test]
fn nftables_atomic_replace_updates_rules() {
    cleanup_castle_table();
    nftables::install_castle_table().expect("install");

    let (cgroup_path, cgroup_id) = create_test_cgroup("replace");
    let id = AgentRulesetId {
        agent_id: "test-replace".to_string(),
        cgroup_path: cgroup_path.clone(),
    };

    let frags1 = vec![NftRuleFragment {
        rule_id: "r1".to_string(),
        nft_expr: "tcp dport 443 accept".to_string(),
    }];
    let script1 = nftables::build_agent_ruleset("test-replace", cgroup_id, &frags1);
    nftables::load_agent_ruleset(&id, &script1).expect("load v1");

    let frags2 = vec![NftRuleFragment {
        rule_id: "r2".to_string(),
        nft_expr: "tcp dport 8443 accept".to_string(),
    }];
    let script2 = nftables::build_agent_ruleset("test-replace", cgroup_id, &frags2);
    nftables::load_agent_ruleset(&id, &script2).expect("load v2");

    let out = nft_cmd(&["list", "chain", CASTLE_FAMILY, CASTLE_TABLE, "agent_test-replace"]);
    assert!(out.contains("8443"), "v2 should contain 8443: {}", out);

    cleanup_castle_table();
    destroy_test_cgroup(&cgroup_path);
}

#[test]
fn nftables_namespace_isolation_from_default_filter() {
    cleanup_castle_table();
    nftables::install_castle_table().expect("install");

    let tables = nft_cmd(&["list", "tables"]);
    assert!(tables.contains(CASTLE_TABLE));

    if tables.contains("table inet filter") {
        let filter_output = nft_cmd(&["list", "table", "inet", "filter"]);
        assert!(!filter_output.contains(CASTLE_TABLE));
    }

    cleanup_castle_table();
}

#[test]
fn nftables_ruleset_includes_nfqueue_catchall() {
    cleanup_castle_table();
    nftables::install_castle_table().expect("install");

    let (cgroup_path, cgroup_id) = create_test_cgroup("queue");
    let id = AgentRulesetId {
        agent_id: "test-queue".to_string(),
        cgroup_path: cgroup_path.clone(),
    };

    let frags = vec![NftRuleFragment {
        rule_id: "r1".to_string(),
        nft_expr: "tcp dport 443 accept".to_string(),
    }];
    let script = nftables::build_agent_ruleset("test-queue", cgroup_id, &frags);
    nftables::load_agent_ruleset(&id, &script).expect("load");

    let out = nft_cmd(&["list", "chain", CASTLE_FAMILY, CASTLE_TABLE, "agent_test-queue"]);
    assert!(
        out.contains("queue"),
        "ruleset should include NFQUEUE catch-all: {}",
        out
    );

    cleanup_castle_table();
    destroy_test_cgroup(&cgroup_path);
}

// ---- cgroup tests ---------------------------------------------------------

#[test]
fn cgroup_resolve_id_on_root_cgroup() {
    let path = PathBuf::from("/sys/fs/cgroup");
    if path.exists() {
        let id = cgroup::resolve_cgroup_id(&path).expect("resolve");
        assert!(id > 0, "root cgroup inode > 0");
    }
}

#[test]
fn cgroup_scope_unit_name_format() {
    let name = cgroup::scope_unit_name("my-agent");
    assert_eq!(name, "sanctuary-agent-my-agent.scope");
}

#[test]
fn cgroup_path_for_scope_shape() {
    let path = cgroup::cgroup_path_for_scope("sanctuary-agent-test.scope");
    assert_eq!(
        path,
        PathBuf::from("/sys/fs/cgroup/system.slice/sanctuary-agent-test.scope")
    );
}

// ---- nfqueue tests --------------------------------------------------------

#[test]
fn nfqueue_config_default_fail_open_off() {
    let cfg = NfqueueConfig::default();
    assert!(!cfg.fail_open);
}

#[test]
fn nfqueue_bind_rejects_fail_open_true() {
    let config = NfqueueConfig {
        fail_open: true,
        ..Default::default()
    };
    let result = nfqueue::bind_queue(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("FAIL_OPEN"));
}

#[test]
fn nfqueue_bind_succeeds_with_fail_open_off() {
    let config = NfqueueConfig::default();
    let handle = nfqueue::bind_queue(&config).expect("bind_queue");
    assert_eq!(handle.queue_number, 0);
    assert_eq!(handle.packets_processed.load(Ordering::Relaxed), 0);
    handle.stop_flag.store(true, Ordering::Relaxed);
}

#[test]
fn nfqueue_parse_ip_header_tcp() {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = 6; // TCP
    pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 1;
    pkt[22] = 0x01; pkt[23] = 0xBB; // port 443
    let (ip, port, proto) = nfqueue::parse_ip_header(&pkt);
    assert_eq!(ip, Some("10.0.0.1".to_string()));
    assert_eq!(port, 443);
    assert_eq!(proto, 6);
}

#[test]
fn nfqueue_parse_ip_header_udp_dns() {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8;
    pkt[22] = 0x00; pkt[23] = 0x35; // port 53
    let (ip, port, proto) = nfqueue::parse_ip_header(&pkt);
    assert_eq!(ip, Some("8.8.8.8".to_string()));
    assert_eq!(port, 53);
    assert_eq!(proto, 17);
}

// ---- end-to-end: nftables + daemon evaluate_attempt + WAL -----------------

#[test]
fn end_to_end_nftables_then_evaluate_then_audit() {
    use castle_wall_daemon::nftables::rule_to_nft_expr;
    use castle_wall_daemon::policy::{
        AllowlistRule, EvaluationRequest, RuleDisposition, RuleMatch, RuleScope, Verdict,
    };
    use castle_wall_daemon::{boot, DaemonConfig};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;
    use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
    use castle_wall_daemon::manifest::verify::{
        AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
    };
    use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
    use base64::Engine as _;

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned_path = dir.path().join("pinned.key");
    fs::write(&pinned_path, signing.verifying_key().to_bytes()).unwrap();

    let policy_dir = dir.path().to_path_buf();
    fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();

    let rule_body = serde_json::json!({
        "id": "rule-allow-test",
        "schema_version": 1,
        "created_at": "2026-05-05T00:00:00Z",
        "match": { "host": ["api.anthropic.com"], "port": [443], "protocol": "tcp" },
        "disposition": "allow"
    });
    let rule_bytes = serde_json::to_vec(&rule_body).unwrap();
    fs::write(policy_dir.join(RULES_SUBDIR).join("rule-0.json"), &rule_bytes).unwrap();

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(&rule_bytes);
    let sha_hex = format!("{:x}", sha_hasher.finalize());

    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "deadbeef".to_string(),
        issued_at: "2026-05-05T00:00:00Z".to_string(),
        rules: vec![ManifestRuleEntry {
            rule_id: "rule-allow-test".to_string(),
            file: "rule-0.json".to_string(),
            sha256: sha_hex,
        }],
    };
    let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let sig = signing.sign(&canonical);
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: "ed25519-v1".to_string(),
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

    let config = DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: dir.path().join("filter.sock"),
        policy_dir,
        wal_path: dir.path().join("wal.jsonl"),
        pinned_public_key_path: pinned_path,
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_ttl: Duration::from_secs(86_400),
        wal_size_cap_bytes: 16 * 1024 * 1024,
    };

    let handle = boot(config).expect("daemon boot");

    // Install nftables table + agent ruleset.
    cleanup_castle_table();
    nftables::install_castle_table().expect("install castle table");

    let test_rule = AllowlistRule {
        id: "rule-allow-test".to_string(),
        schema_version: 1,
        created_at: "2026-05-05T00:00:00Z".to_string(),
        description: None,
        match_clause: RuleMatch {
            host: Some(vec!["api.anthropic.com".to_string()]),
            host_pattern: None,
            port: Some(vec![443]),
            protocol: Some("tcp".to_string()),
        },
        scope: RuleScope::default(),
        disposition: RuleDisposition::Allow,
    };
    let frags = rule_to_nft_expr(&test_rule);
    assert!(!frags.is_empty());

    let (e2e_cgroup_path, e2e_cgroup_id) = create_test_cgroup("e2e");
    let ruleset_script = nftables::build_agent_ruleset("test-e2e", e2e_cgroup_id, &frags);
    let agent_id = AgentRulesetId {
        agent_id: "test-e2e".to_string(),
        cgroup_path: e2e_cgroup_path.clone(),
    };
    nftables::load_agent_ruleset(&agent_id, &ruleset_script).expect("load");

    // Verify rules installed.
    let output = nft_cmd(&["list", "chain", CASTLE_FAMILY, CASTLE_TABLE, "agent_test-e2e"]);
    assert!(output.contains("443"));
    assert!(output.contains("queue"));

    // Evaluate: allowed destination.
    let req_allowed = EvaluationRequest {
        agent_id: "test-e2e".to_string(),
        agent_template: "claude-code".to_string(),
        dest_host: Some("api.anthropic.com".to_string()),
        dest_ip: Some("104.18.0.1".to_string()),
        dest_port: 443,
        dest_protocol: "tcp".to_string(),
        opaque: false,
    };
    let outcome = handle.evaluate_attempt(&req_allowed).expect("evaluate");
    assert!(matches!(outcome.verdict, Verdict::Allow { .. }));
    assert!(outcome.event_canonical_json.contains("\"egress_approved\""));
    assert!(outcome.event_canonical_json.contains("\"l1\""));

    // Evaluate: denied destination.
    let req_denied = EvaluationRequest {
        agent_id: "test-e2e".to_string(),
        agent_template: "claude-code".to_string(),
        dest_host: Some("evil.example.com".to_string()),
        dest_ip: Some("198.51.100.1".to_string()),
        dest_port: 443,
        dest_protocol: "tcp".to_string(),
        opaque: false,
    };
    let outcome_denied = handle.evaluate_attempt(&req_denied).expect("evaluate denied");
    assert!(matches!(
        outcome_denied.verdict,
        Verdict::Deny { reason: castle_wall_daemon::DeniedReason::DefaultDeny }
    ));
    assert!(outcome_denied.event_canonical_json.contains("\"egress_blocked\""));

    // Verify WAL has both events.
    let wal = handle.wal_writer().expect("wal");
    let mut wal_guard = wal.lock().unwrap();
    let snapshot = wal_guard.snapshot_after(None, 100).expect("snapshot");
    let approved = snapshot.iter().filter(|e| e.event_canonical_json.contains("\"egress_approved\"")).count();
    let blocked = snapshot.iter().filter(|e| e.event_canonical_json.contains("\"egress_blocked\"")).count();
    assert!(approved >= 1);
    assert!(blocked >= 1);
    drop(wal_guard);

    let _ = handle.stop();
    cleanup_castle_table();
    destroy_test_cgroup(&e2e_cgroup_path);
}
