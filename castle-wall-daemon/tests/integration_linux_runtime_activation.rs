//! Integration test for the shipped Linux kernel-runtime ACTIVATION path.
//!
//! These tests drive `daemon::boot` — the real production boot path — on Linux
//! and assert the servers-first fail-before contract end to end:
//!
//! * a wired boot reaches `KernelRuntimeReady` when the host is privileged
//!   (nft present + CAP_NET_ADMIN), and NEVER reads as `Enforcing` (no agent is
//!   wrapped in this slice), and `is_enforcing()` stays false throughout;
//! * on a SUPPORTED Linux host, boot NEVER falls through to `ControlPlaneOnly`
//!   when the kernel runtime cannot be acquired — it FAILS-BEFORE, returning a
//!   typed `DaemonError::KernelRuntimeActivation` and leaving no handle, so
//!   systemd (`Restart=on-failure`) restarts it. If nftables acquisition had
//!   completed before a later component failed, the exact owned table and its
//!   authenticated journal remain for fail-closed restart adoption;
//! * a second daemon cannot own the host nftables runtime while a first holds
//!   it (the host ownership lock), so the second FAILS-BEFORE, not
//!   `ControlPlaneOnly`;
//! * a foreign pre-existing `sanctuary-castle` table makes boot fail-before and
//!   is left intact (unwind removes only owned state).
//!
//! Why no `ControlPlaneOnly` outcome on Linux: `ControlPlaneOnly` is now
//! reachable only via `UnsupportedPlatform` (the `cfg(not(target_os = "linux"))`
//! provider branches), which cannot occur on this Linux build. So on Linux a
//! boot either returns `Ok(KernelRuntimeReady)` or `Err`.
//!
//! HARDWARE / UBUNTU-CI PENDING. The `KernelRuntimeReady` assertions require a
//! real kernel with `nft` and CAP_NET_ADMIN; they are meaningful only in the
//! Ubuntu 24.04 `castle-wall-linux-integration` CI job (or on the reference
//! server drill host), NOT on the macOS dev host, where the whole file is
//! cfg-gated out. On an UNPRIVILEGED Linux runner the daemon cannot acquire the
//! runtime, so boot fails-before with the typed error — which the tests below
//! assert directly. Activation SUCCESS remains pending until this privileged
//! suite and the captured hardware drill close ASSURANCE_MATRIX row 17.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use castle_wall_daemon::config::LinuxRuntimePaths;
use castle_wall_daemon::daemon::{self, DaemonError, DaemonRuntimeState};
use castle_wall_daemon::manifest::canonical_json::canonicalize_to_bytes;
use castle_wall_daemon::manifest::verify::{
    AgentOrigin, AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
};
use castle_wall_daemon::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};
use castle_wall_daemon::nftables::{
    self, SafetyNetScope, CASTLE_FAMILY, CASTLE_TABLE, ISOLATED_TABLE_PREFIX,
};
use castle_wall_daemon::ownership_journal::{
    self, DEFAULT_JOURNAL_AUTH_KEY_PATH, DEFAULT_OWNERSHIP_JOURNAL_PATH,
};
use castle_wall_daemon::runtime_lock::DEFAULT_HOST_LOCK_PATH;
use castle_wall_daemon::runtime_providers::{
    self, force_next_agent_binding_readback_mismatch_for_test,
    force_next_agent_binding_write_ahead_error_for_test,
};
use castle_wall_daemon::safety_net_uid::{
    validate_safety_net_uid, ConfinedUidSet, HostOverflowUid,
};
use castle_wall_daemon::DaemonConfig;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// The uid these two A7 tests confine, and the manifest ceiling it clears.
/// `bind_admitted_uid_before_ready`'s install and readback steps (A3, A4) only
/// run under a `Confined` identity, so both the fail-before and the ordering
/// test need a manifest that actually confines someone.
const TEST_AGENT_UID: u32 = 60123;
const TEST_UID_CEILING: u32 = 1000;

/// The host-global runtime dir the boot path's lock lives under in PRODUCTION.
/// Named here only so the isolation assertions can prove this suite stays out
/// of it; nothing in this file creates or writes it.
const PRODUCTION_RUNTIME_DIR: &str = "/run/sanctuary";
const EXPECT_PRIVILEGED_ENV: &str = "SANCTUARY_EXPECT_PRIVILEGED_LINUX";

mod isolation;

/// Suite-entry guard: serializes this binary's tests and re-asserts, on every
/// entry, that no production runtime object has been resolved. See
/// [`isolation`] for why both halves are needed.
fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    isolation::guard()
}

fn isolated_paths() -> LinuxRuntimePaths {
    isolation::runtime_paths()
}

fn isolation_root() -> &'static Path {
    isolation::root()
}

fn ownership_journal_path() -> PathBuf {
    isolation::runtime_paths().ownership_journal_path
}

fn journal_auth_key_path() -> PathBuf {
    isolation::runtime_paths().journal_auth_key_path
}

/// argv every spawned daemon in this suite carries so the SUBPROCESS lands on the
/// same isolated table and paths as the in-process boots.
fn isolation_args() -> Vec<String> {
    isolation::subprocess_args()
}

/// Run the shipped binary's explicit `--disarm` recovery action AGAINST THE
/// ISOLATED runtime. Returns whether it exited 0 (deleted/cleared) so a test can
/// assert success or refusal.
///
/// The isolation flags exist only in a `--features test-isolation` build, which
/// is also the only build this test target compiles under (`required-features`),
/// so the shipped binary keeps exactly the argv surface it ships with.
fn run_disarm() -> bool {
    Command::new(env!("CARGO_BIN_EXE_castle-wall-daemon"))
        .arg("--disarm")
        .args(isolation_args())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cleanup_castle_table() {
    // Deletes the ISOLATED table only: `nftables::castle_table()` resolves to the
    // per-process test name installed by `isolated()`, never `sanctuary-castle`.
    let _ = Command::new("nft")
        .args(["delete", "table", CASTLE_FAMILY, nftables::castle_table()])
        .output();
}

/// Remove any ownership journal left by a prior run so each test starts from a
/// clean ownership state (no stale reclaim proof). Best-effort. The auth KEY is
/// intentionally left in place across runs (it is reused; a fresh journal is
/// re-signed with it), matching production where the key is durable.
fn cleanup_journal() {
    let _ = std::fs::remove_file(ownership_journal_path());
}

/// Read the exact live table identity through nft's real JSON output. `-a` is
/// required because handle output is opt-in; successful parsing proves the live
/// output contained the table handle, base-chain handle, marker, and exact shape.
fn live_owned_identity() -> Result<nftables::CastleTableOwnership, String> {
    let output = Command::new("nft")
        .args([
            "-a",
            "-j",
            "list",
            "table",
            CASTLE_FAMILY,
            nftables::castle_table(),
        ])
        .output()
        .map_err(|err| format!("could not execute nft handle listing: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "nft handle listing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let json = std::str::from_utf8(&output.stdout)
        .map_err(|err| format!("nft JSON was not UTF-8: {err}"))?;
    // NoneConfined: this suite installs no per-agent binding, so one appearing in
    // the live table is state the helper cannot vouch for and must refuse.
    nftables::parse_owned_table_identity(
        json,
        &castle_wall_daemon::nftables::ExpectedAgentBinding::NoneConfined,
    )
    .map_err(|err| format!("nft JSON lacked the required owned handles/shape: {err}"))
}

/// The isolated equivalent of the production `RuntimeDirectory=` /
/// `StateDirectory=` provisioning. The temp root already exists, so this is a
/// no-op kept as a named step: the production directories are deliberately NOT
/// created or touched here.
fn ensure_runtime_dir() {
    debug_assert!(isolation_root().is_dir());
}

fn write_pinned_key(dir: &TempDir, signing: &SigningKey) -> std::path::PathBuf {
    let path = dir.path().join("pinned.key");
    std::fs::write(&path, signing.verifying_key().to_bytes()).unwrap();
    path
}

fn fresh_config(dir: &TempDir) -> DaemonConfig {
    let signing = SigningKey::generate(&mut OsRng);
    DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: dir.path().join("filter.sock"),
        policy_dir: dir.path().to_path_buf(),
        wal_path: dir.path().join("wal.jsonl"),
        pinned_public_key_path: write_pinned_key(dir, &signing),
        producer_key_path: dir.path().join("audit-producer.key"),
        producer_pub_key_path: dir.path().join("audit-producer.pub"),
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_ttl: Duration::from_secs(86_400),
        wal_size_cap_bytes: 16 * 1024 * 1024,
        trusted_service_uid: Some(unsafe { libc::geteuid() }),
        // The host-global lock / ownership journal / journal MAC key all land in
        // the suite's temp root, never in /var/lib/sanctuary.
        linux_runtime_paths: isolated_paths(),
        test_boot_time_shutdown_requested: false,
    }
}

/// Like [`fresh_config`], but keyed to a CALLER-SUPPLIED signing key, so the
/// caller can also sign a manifest under that same key before boot. The pinned
/// key and the manifest signature must trace to one key pair, or the daemon
/// rejects the manifest at signature verification for a reason that has
/// nothing to do with the confined uid these two A7 tests mean to exercise.
fn fresh_confining_config(dir: &TempDir, signing: &SigningKey) -> DaemonConfig {
    DaemonConfig {
        fortress_id: "deadbeef".to_string(),
        socket_path: dir.path().join("filter.sock"),
        policy_dir: dir.path().to_path_buf(),
        wal_path: dir.path().join("wal.jsonl"),
        pinned_public_key_path: write_pinned_key(dir, signing),
        producer_key_path: dir.path().join("audit-producer.key"),
        producer_pub_key_path: dir.path().join("audit-producer.pub"),
        prompt_timeout: Duration::from_secs(30),
        no_wall_max_duration: Duration::from_secs(3600),
        wal_ttl: Duration::from_secs(86_400),
        wal_size_cap_bytes: 16 * 1024 * 1024,
        trusted_service_uid: Some(unsafe { libc::geteuid() }),
        linux_runtime_paths: isolated_paths(),
        test_boot_time_shutdown_requested: false,
    }
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

/// Write a manifest the daemon admits, confining [`TEST_AGENT_UID`]. Mirrors
/// `write_signed_manifest_one_rule_with_uid_origin` in
/// `integration_failure_modes.rs`: a per-agent kernel binding is only
/// legitimate because a manifest in force confines that uid, and both A7 tests
/// below need `bind_admitted_uid_before_ready` to actually reach the install
/// and readback steps (A3, A4), which run only under a `Confined` identity.
fn write_confining_manifest(policy_dir: &Path, signing: &SigningKey) {
    std::fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
    let body = b"{\"id\":\"rule-allow-ip\",\"schema_version\":1,\"created_at\":\"2026-05-06T00:00:00Z\",\"match\":{\"ip\":[\"203.0.113.10\"],\"port\":[443],\"protocol\":\"tcp\"},\"disposition\":\"allow\"}";
    std::fs::write(
        policy_dir.join(RULES_SUBDIR).join("rule-allow-ip.json"),
        body,
    )
    .unwrap();
    // Every composed manifest must carry the genuine habeas local lane
    // (always-on-lane gate), or the daemon rejects it at parse.
    let habeas_body = castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
    std::fs::write(
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
        // Must match TEST_AGENT_UID / TEST_UID_CEILING above.
        agent_origin: Some(AgentOrigin {
            mode: "uid".to_string(),
            egress_helper_signing_id: None,
            egress_helper_team_id: None,
            agent_runtime_port_range: None,
            agent_uid: Some(TEST_AGENT_UID),
            gate_uid: None,
            system_uid_allow_ceiling: TEST_UID_CEILING,
        }),
        operator_baseline: None,
        rules: vec![
            ManifestRuleEntry {
                rule_id: "rule-allow-ip".to_string(),
                file: "rule-allow-ip.json".to_string(),
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
            signature_scheme: "ed25519-v1".to_string(),
            signing_key_id: castle_wall_daemon::crypto::castle_wall_signing_key_id(
                &signing.verifying_key().to_bytes(),
            )
            .unwrap(),
            signature_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sig.to_bytes()),
        },
    };
    std::fs::write(
        policy_dir.join(MANIFEST_FILENAME),
        serde_json::to_string_pretty(&signed).unwrap(),
    )
    .unwrap();
}

/// Assert a boot error is the typed kernel-runtime activation fail-before, not
/// some other startup error.
fn assert_activation_failure(err: &DaemonError) {
    assert!(
        matches!(err, DaemonError::KernelRuntimeActivation(_)),
        "a Linux kernel-runtime acquisition failure must surface as the typed \
         KernelRuntimeActivation fail-before error, got {err:?}"
    );
}

/// Emit an unmistakable skip record on ad-hoc unprivileged Linux hosts, but
/// fail the test when the privileged CI/drill contract was explicitly enabled.
fn skip_or_fail_unprivileged(reason: &str) {
    if std::env::var_os(EXPECT_PRIVILEGED_ENV).is_some() {
        panic!(
            "privileged Linux runtime was required by {EXPECT_PRIVILEGED_ENV}, but unavailable: \
             {reason}"
        );
    }
    eprintln!("SKIP (privileged Linux runtime unavailable): {reason}");
}

#[test]
fn boot_reaches_kernel_runtime_ready_or_fails_before_never_control_plane_only() {
    let _suite = suite_guard();
    cleanup_castle_table();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    // On Linux boot is TWO-valued: Ok(KernelRuntimeReady) on a privileged clean
    // host, or Err(KernelRuntimeActivation) on any host that cannot acquire the
    // runtime (unprivileged runner, unprovisioned /run/sanctuary, ...). It NEVER
    // returns a ControlPlaneOnly handle on Linux (see the module docs).
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            // Privileged clean host: the runtime activated. Never enforcing (no
            // agent is wrapped), and a returned handle on Linux is always
            // KernelRuntimeReady, never ControlPlaneOnly.
            assert!(
                !handle.is_enforcing(),
                "this slice wraps no agent; is_enforcing() must be false"
            );
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady,
                "a Linux boot that returns a handle must be KernelRuntimeReady, \
                 never ControlPlaneOnly or Enforcing"
            );
            assert!(
                nftables::table_exists().expect("table_exists query"),
                "a ready kernel runtime must have installed the sanctuary-castle table"
            );
            nftables::verify_castle_table_shape().expect("installed table must have our shape");

            // FAIL-CLOSED PRESERVATION (blocker 1): ordinary stop releases only the
            // process-local lock. The owned table AND its authenticated ownership
            // journal SURVIVE — a mere process exit never tears down an acquired
            // enforcement object. Deletion is the separate, explicit `--disarm`
            // (proven end-to-end by the SIGKILL/shipped-binary test below; here the
            // daemon runs IN-PROCESS, so its recorded source identity would not
            // match the out-of-process `--disarm` binary — a test artifact, not a
            // production one, since production runs one installed binary).
            handle.stop().expect("clean stop");
            assert!(
                nftables::table_exists().unwrap_or(false),
                "ordinary stop() must PRESERVE the owned table (fail-closed), never delete it"
            );
            assert!(
                ownership_journal_path().exists(),
                "ordinary stop() must preserve the ownership journal, never clear it"
            );
            // Clean up this in-process daemon's owned state directly (nft + rm),
            // which does not depend on the source-identity match `--disarm` uses.
            cleanup_castle_table();
            cleanup_journal();
        }
        Err(err) => {
            // Any Linux host that could not cleanly acquire the runtime
            // FAILS-BEFORE with the typed error — never a control-plane-only
            // handle. No `READY=1` was sent. If a later component failed after
            // table acquisition, fail-closed release intentionally preserves
            // that exact table with its authenticated journal for adoption.
            assert_activation_failure(&err);
            if nftables::table_exists().unwrap_or(false) {
                assert!(
                    ownership_journal_path().exists(),
                    "a preserved table after partial startup must retain its ownership journal"
                );
                nftables::verify_castle_table_shape().expect(
                    "a preserved table after partial startup must keep the fail-closed shape",
                );
            }
            let reason = format!("clean privileged boot did not activate: {err}");
            cleanup_castle_table();
            skip_or_fail_unprivileged(&reason);
        }
    }
    cleanup_castle_table();
}

#[test]
fn fatal_control_path_is_loud_and_nonzero_in_the_real_subprocess() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();
    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);
    let output = Command::new(env!("CARGO_BIN_EXE_castle-wall-daemon"))
        .args([
            "--fortress-id",
            "deadbeef",
            "--socket-path",
            dir.path().join("fatal.sock").to_str().unwrap(),
            "--policy-dir",
            dir.path().to_str().unwrap(),
            "--wal-path",
            dir.path().join("fatal.wal").to_str().unwrap(),
            "--pinned-public-key",
            pinned.to_str().unwrap(),
            "--producer-key",
            dir.path().join("audit-producer.key").to_str().unwrap(),
            "--producer-pub-key",
            dir.path().join("audit-producer.pub").to_str().unwrap(),
            "--test-trigger-fatal-control-path",
        ])
        .args(isolation_args())
        .output()
        .expect("run fatal-control subprocess");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("kernel runtime activation failed") {
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&stderr);
        return;
    }
    assert!(
        !output.status.success(),
        "fatal control path must exit nonzero"
    );
    assert!(
        stderr.contains("fatal control-path durability failure"),
        "fatal control path must be loud on stderr: {stderr}"
    );
    cleanup_castle_table();
    cleanup_journal();
}

#[test]
fn a_second_daemon_fails_before_while_a_first_owns_the_host_runtime() {
    let _suite = suite_guard();
    cleanup_castle_table();
    ensure_runtime_dir();

    let dir_a = TempDir::new().unwrap();
    let first = match daemon::boot(fresh_config(&dir_a)) {
        Ok(handle) => handle,
        Err(err) => {
            // Unprivileged runner: the first daemon cannot activate, so there is
            // no held runtime to contend for. The fail-before is still typed.
            assert_activation_failure(&err);
            cleanup_castle_table();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the host-runtime contention precondition: {err}"
            ));
            return;
        }
    };

    // The first daemon activated -> it holds the host ownership lock. A second
    // daemon — even with a DIFFERENT fortress id and a different IPC socket — must
    // FAIL-BEFORE on the host-lock conflict, never boot control-plane-only.
    assert_eq!(
        first.runtime_state(),
        DaemonRuntimeState::KernelRuntimeReady,
        "the first daemon must be ready before its host lock can prove contention"
    );
    let dir_b = TempDir::new().unwrap();
    let mut config_b = fresh_config(&dir_b);
    config_b.fortress_id = "cafef00d".to_string();
    let err = daemon::boot(config_b)
        .err()
        .expect("second daemon must fail-before while the first owns the host runtime");
    assert_activation_failure(&err);

    first.stop().expect("first stop");
    cleanup_castle_table();
}

#[test]
fn a_preexisting_sanctuary_castle_table_makes_boot_fail_before_and_is_left_intact() {
    let _suite = suite_guard();
    // blocker 1 + servers-first fail-before: the acquisition path must NEVER
    // mutate pre-existing sanctuary-castle state, and a foreign table is now a
    // FATAL fail-before (not a control-plane-only downgrade). This is the
    // deterministic "acquisition failure returns error / no handle / leaves no
    // partial state" test: given the foreign-table precondition, boot MUST return
    // Err and MUST leave the pre-existing table intact.
    cleanup_castle_table();
    ensure_runtime_dir();

    // Pre-create a foreign table. On an unprivileged runner this fails; if it did
    // not create, the test cannot make its point, so require it or skip.
    let created = Command::new("nft")
        .args(["add", "table", CASTLE_FAMILY, nftables::castle_table()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created || !nftables::table_exists().unwrap_or(false) {
        // No privilege to create the precondition; nothing to prove here.
        cleanup_castle_table();
        skip_or_fail_unprivileged(
            "could not create the foreign table required by the fail-before test",
        );
        return;
    }

    let dir = TempDir::new().unwrap();
    // Refused AND fatal: the daemon does not adopt the foreign table and does not
    // fall through to control-plane-only — it fails-before with the typed error.
    let err = daemon::boot(fresh_config(&dir))
        .err()
        .expect("a pre-existing sanctuary-castle table must make boot fail-before");
    assert_activation_failure(&err);

    // Untouched: the unwind removes ONLY owned state (this acquisition created
    // nothing), so the pre-existing table still exists.
    assert!(
        nftables::table_exists().unwrap_or(false),
        "the pre-existing table must be left intact, never deleted"
    );
    cleanup_castle_table();
}

/// Boot-and-exit smoke path cannot report success after a failed acquisition.
///
/// Runs the SHIPPED binary with `--boot-and-exit` under a forced activation
/// failure and asserts a NONZERO exit and the absence of the "clean exit" line.
/// The precondition guarantees activation cannot succeed on either kind of
/// runner: on a privileged host the pre-created foreign table forces a
/// fail-before; on an unprivileged host the daemon cannot acquire the runtime at
/// all. Either way `daemon::boot` returns Err, so `main` exits before the
/// boot-and-exit success branch is ever reached.
#[test]
fn boot_and_exit_cannot_report_success_after_a_failed_acquisition() {
    let _suite = suite_guard();
    cleanup_castle_table();
    ensure_runtime_dir();

    // Force a failure precondition where we can (privileged); where we cannot,
    // the daemon fails to acquire anyway, so activation cannot succeed either way.
    let created = Command::new("nft")
        .args(["add", "table", CASTLE_FAMILY, nftables::castle_table()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
        && nftables::table_exists().unwrap_or(false);
    if !created {
        skip_or_fail_unprivileged(
            "could not create the foreign-table precondition for boot-and-exit",
        );
    }

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);

    let output = Command::new(env!("CARGO_BIN_EXE_castle-wall-daemon"))
        .args([
            "--fortress-id",
            "deadbeef",
            "--socket-path",
            dir.path().join("filter.sock").to_str().unwrap(),
            "--policy-dir",
            dir.path().to_str().unwrap(),
            "--wal-path",
            dir.path().join("wal.jsonl").to_str().unwrap(),
            "--pinned-public-key",
            pinned.to_str().unwrap(),
            // Point producer keys at the temp dir so every pre-activation gate
            // (WAL, manifest store, producer signer, IPC bind) passes and the
            // binary reaches the kernel-runtime acquisition — the step under test.
            "--producer-key",
            dir.path().join("audit-producer.key").to_str().unwrap(),
            "--producer-pub-key",
            dir.path().join("audit-producer.pub").to_str().unwrap(),
            "--boot-and-exit",
        ])
        .args(isolation_args())
        .output()
        .expect("run the shipped daemon binary with --boot-and-exit");

    assert!(
        !output.status.success(),
        "boot-and-exit must NOT exit 0 after a failed kernel-runtime acquisition"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("clean exit"),
        "boot-and-exit must NOT print the clean-exit success line after a failed \
         acquisition; stdout was:\n{stdout}"
    );
    cleanup_castle_table();
}

/// blocker 1, raced foreign-table semantics: `create_castle_table_exclusive`
/// must be FAIL-ON-EXISTS (nft `create`), not idempotent (`add`). A table that
/// races in between the acquisition's preflight check and the create must abort
/// the transaction, not be silently adopted. Proven directly: a second create of
/// the same table must error.
#[test]
fn create_castle_table_exclusive_is_fail_on_exists_not_idempotent() {
    let _suite = suite_guard();
    cleanup_castle_table();
    let marker = "sanctuary-castle-owner:v1:00000000000000000000000000000000";
    match nftables::create_castle_table_exclusive(marker) {
        Ok(()) => {
            // Privileged: the first create succeeded. A SECOND create of the same
            // table MUST fail — that is the fail-on-exists property that rejects a
            // raced/foreign table instead of adopting it the way `add` would.
            let second = nftables::create_castle_table_exclusive(marker);
            assert!(
                second.is_err(),
                "a second create of an existing table must fail: create is fail-on-exists \
                 (not idempotent add), which is what refuses a raced foreign table"
            );
            cleanup_castle_table();
        }
        // Unprivileged runner: cannot create the table at all; nothing to prove.
        Err(err) => {
            cleanup_castle_table();
            skip_or_fail_unprivileged(&format!(
                "could not create a table for fail-on-exists proof: {err}"
            ));
        }
    }
}

/// Privileged proof that the production `-a -j list table` path emits the
/// handles required by the ownership parser and that the same identity verifies.
#[test]
fn structured_owned_table_listing_contains_required_live_handles() {
    let _suite = suite_guard();
    cleanup_castle_table();
    let marker = "sanctuary-castle-owner:v1:11111111111111111111111111111111";
    if let Err(err) = nftables::create_castle_table_exclusive(marker) {
        cleanup_castle_table();
        skip_or_fail_unprivileged(&format!(
            "could not create a table for structured handle-output proof: {err}"
        ));
        return;
    }

    let production_identity = nftables::capture_owned_castle_table(marker)
        .expect("production capture must parse table and chain handles from nft -a -j output");
    let independent_identity =
        live_owned_identity().expect("independent nft -a -j listing must contain both handles");
    assert_eq!(production_identity, independent_identity);
    nftables::verify_owned_castle_table(
        &production_identity,
        &castle_wall_daemon::nftables::ExpectedAgentBinding::NoneConfined,
    )
    .expect("the captured live handle identity must verify unchanged");
    cleanup_castle_table();
}

/// Wait for the daemon's real systemd readiness beacon while also proving the
/// child remains alive. Table existence is intentionally NOT a readiness signal:
/// it survives crashes by design and would make a failed restart false-positive.
fn wait_for_ready(
    child: &mut Child,
    listener: &UnixDatagram,
    timeout: Duration,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("could not make notify listener nonblocking: {err}"))?;
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let mut buf = [0u8; 128];
        match listener.recv(&mut buf) {
            Ok(n) if &buf[..n] == b"READY=1\n" => return Ok(()),
            Ok(n) => {
                return Err(format!(
                    "daemon sent an unexpected readiness datagram: {:?}",
                    &buf[..n]
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(format!("readiness receive failed: {err}")),
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("could not inspect daemon child: {err}"))?
        {
            return Err(format!(
                "daemon exited with {status} before sending READY=1"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for READY=1 from a still-running daemon".to_string())
}

/// Spawn the shipped daemon as a LONG-RUNNING child (no `--boot-and-exit`) with a
/// temp config, so it activates the kernel runtime and then supervises until a
/// signal. The caller drives its lifecycle (kill / SIGTERM).
fn spawn_long_running_daemon(
    dir: &TempDir,
    pinned: &std::path::Path,
    notify_socket: &std::path::Path,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_castle-wall-daemon"))
        .args([
            "--fortress-id",
            "deadbeef",
            "--socket-path",
            dir.path().join("filter.sock").to_str().unwrap(),
            "--policy-dir",
            dir.path().to_str().unwrap(),
            "--wal-path",
            dir.path().join("wal.jsonl").to_str().unwrap(),
            "--pinned-public-key",
            pinned.to_str().unwrap(),
            "--producer-key",
            dir.path().join("audit-producer.key").to_str().unwrap(),
            "--producer-pub-key",
            dir.path().join("audit-producer.pub").to_str().unwrap(),
        ])
        // Subprocess isolation: the spawned daemon must land on the SAME isolated
        // table and host-global paths as the in-process boots, or it would create
        // and delete the operator's real `sanctuary-castle` table.
        .args(isolation_args())
        .env("NOTIFY_SOCKET", notify_socket)
        // Piped so a caller that needs to observe the daemon's own stderr (the
        // A7 readback-ordering test below) can read it incrementally while the
        // daemon is still running, without waiting for it to exit. A caller
        // that never takes `child.stderr` is unaffected: the daemon's own
        // startup/shutdown stderr output stays well under a pipe buffer, so an
        // undrained pipe cannot make it block on a full buffer during this
        // suite's short-lived runs.
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the shipped daemon binary (long-running)")
}

/// Crash recovery, real bounded subprocess harness: a SIGKILL between activation
/// and clean shutdown must NOT wedge the next start, and must never delete
/// foreign state. (blocker 3)
///
/// Spawn the shipped daemon, wait until it OWNS the table, then SIGKILL it — no
/// clean release runs, so the table AND the durable ownership journal survive
/// the crash exactly as they would after a real crash or a systemd
/// `TimeoutStartSec` kill. Spawn it AGAIN: the restart must RECLAIM its own table
/// (reach ready again via the journal + marker + handle proof) rather than
/// refusing it forever as "foreign" (the permanent restart wedge this fixes). A
/// final SIGTERM stops cleanly while preserving the exact owned table and journal.
///
/// Privilege-gated: on an unprivileged runner the first daemon never owns the
/// table (nft/CAP_NET_ADMIN absent), so there is nothing to reclaim. Ad-hoc runs
/// emit explicit skip evidence; the privileged CI job sets
/// `SANCTUARY_EXPECT_PRIVILEGED_LINUX=1`, making absence a hard failure.
#[test]
fn a_sigkill_between_activation_and_shutdown_reclaims_on_restart_without_wedging() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);

    // 1) First instance: require the real READY=1 handshake (or explicitly skip
    //    only when this is an ad-hoc unprivileged run).
    let first_notify_path = dir.path().join("notify-first.sock");
    let first_listener = UnixDatagram::bind(&first_notify_path).expect("bind first notify socket");
    let mut first = spawn_long_running_daemon(&dir, &pinned, &first_notify_path);
    if let Err(reason) = wait_for_ready(&mut first, &first_listener, Duration::from_secs(10)) {
        let _ = first.kill();
        let _ = first.wait();
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&reason);
        return;
    }
    assert!(
        first.try_wait().unwrap().is_none(),
        "ready daemon must be alive"
    );
    assert!(nftables::table_exists().unwrap_or(false));
    assert!(
        ownership_journal_path().exists(),
        "an owned runtime must have written the durable ownership journal"
    );
    let identity_before_sigkill =
        live_owned_identity().expect("ready first daemon must expose its exact live identity");

    // 2) SIGKILL: no clean release runs, so the owned table and journal survive
    //    the crash — the exact precondition the old code wedged on.
    first.kill().expect("SIGKILL the first daemon"); // std kill == SIGKILL on unix
    let _ = first.wait();
    assert!(
        nftables::table_exists().unwrap_or(false),
        "the owned table must survive a SIGKILL (no clean release ran)"
    );
    assert!(
        ownership_journal_path().exists(),
        "the ownership journal must survive the crash so the restart can reclaim"
    );

    // 3) Restart: must RECLAIM its own table and reach ready again, NOT wedge
    //    refusing it as foreign, and NOT delete/duplicate it.
    let second_notify_path = dir.path().join("notify-second.sock");
    let second_listener =
        UnixDatagram::bind(&second_notify_path).expect("bind second notify socket");
    let mut second = spawn_long_running_daemon(&dir, &pinned, &second_notify_path);
    wait_for_ready(&mut second, &second_listener, Duration::from_secs(10)).expect(
        "the restarted daemon must stay alive, adopt the preserved table, and send READY=1",
    );
    assert!(
        second.try_wait().unwrap().is_none(),
        "the restarted daemon must still be alive after its readiness handshake"
    );
    nftables::verify_castle_table_shape().expect("the reclaimed table still has our shape");
    let identity_after_adoption =
        live_owned_identity().expect("ready restarted daemon must expose its exact live identity");
    assert_eq!(
        identity_after_adoption, identity_before_sigkill,
        "restart must adopt the identical table handle, chain handle, and marker; delete/recreate is forbidden"
    );

    // 4) Clean SIGTERM: FAIL-CLOSED PRESERVATION (blocker 1). Ordinary shutdown
    //    releases only the process-local lock; the owned table AND its
    //    authenticated journal SURVIVE, so the non-bypass posture and durable proof
    //    are never torn down by a mere process exit.
    let pid = second.id().to_string();
    let signal_status = Command::new("kill")
        .args(["-TERM", pid.as_str()])
        .status()
        .expect("send SIGTERM to adopted daemon");
    assert!(signal_status.success(), "SIGTERM delivery must succeed");
    let second_status = second.wait().expect("wait for adopted daemon shutdown");
    assert!(second_status.success(), "adopted daemon must stop cleanly");
    assert!(
        nftables::table_exists().unwrap_or(false),
        "a clean SIGTERM must PRESERVE the owned table (fail-closed), never delete it"
    );
    assert!(
        ownership_journal_path().exists(),
        "a clean SIGTERM must preserve the ownership journal, never clear it"
    );

    // 5) Explicit disarm is the ONLY path that removes the enforcement object: it
    //    deletes the owned table (handle-qualified), verifies absence, and clears
    //    the journal only after both are confirmed.
    assert!(
        run_disarm(),
        "--disarm must delete the owned table and clear the journal"
    );
    assert!(
        !nftables::table_exists().unwrap_or(false),
        "--disarm must remove the owned table"
    );
    assert!(
        !ownership_journal_path().exists(),
        "--disarm clears the journal AFTER confirming deletion + absence"
    );

    cleanup_castle_table();
    cleanup_journal();
}

/// Ordinary stop PRESERVES the acquired object and a fresh boot ADOPTS it.
/// (blockers 1, 2, finding 8: ordinary stop + preserved-table adoption)
///
/// Boot to ready, stop cleanly (ordinary teardown), and assert the table +
/// authenticated journal survive. Boot AGAIN and assert the second daemon ADOPTS
/// the preserved object (reaches ready over the same live table) rather than
/// refusing it as foreign or re-creating it. Finally disarm to clean up.
#[test]
fn ordinary_stop_preserves_the_object_and_a_fresh_boot_adopts_it() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let first = match daemon::boot(fresh_config(&dir)) {
        Ok(h) => h,
        Err(err) => {
            // Unprivileged runner: cannot acquire; nothing to preserve/adopt.
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish ordinary-stop preservation: {err}"
            ));
            return;
        }
    };
    assert_eq!(
        first.runtime_state(),
        DaemonRuntimeState::KernelRuntimeReady
    );
    first.stop().expect("clean stop");
    // Preserved across ordinary shutdown.
    assert!(
        nftables::table_exists().unwrap_or(false),
        "ordinary stop must preserve the owned table"
    );
    assert!(ownership_journal_path().exists());

    // A fresh boot ADOPTS the preserved table (reclaim), reaching ready over it.
    // On an ad-hoc shared host another process may contend for the host lock
    // between the two boots; that typed failure is emitted as an explicit skip.
    // Privileged CI requires the adoption to succeed and fails rather than skip.
    // When the second boot comes up it must be KernelRuntimeReady over the SAME
    // preserved table (adopt, not re-create or refuse).
    match daemon::boot(fresh_config(&dir)) {
        Ok(second) => {
            assert_eq!(
                second.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady,
                "the adopting daemon must be KernelRuntimeReady over the preserved table"
            );
            assert!(nftables::table_exists().unwrap_or(false));
            second.stop().expect("clean stop");
            // Still preserved after the second ordinary stop.
            assert!(nftables::table_exists().unwrap_or(false));
        }
        Err(err) => {
            assert_activation_failure(&err);
            skip_or_fail_unprivileged(&format!(
                "fresh boot did not adopt the preserved owned table: {err}"
            ));
        }
    }

    // Clean up this in-process daemon's owned state directly (nft + rm). The
    // out-of-process `--disarm` end-to-end delete is proven by the SIGKILL/shipped
    // -binary test, where the daemon and disarm share one binary identity.
    cleanup_castle_table();
    cleanup_journal();
}

/// A tampered/unauthenticated ownership journal makes the next boot FAIL-BEFORE
/// (blocker 3), never silently fresh-create over the live owned table.
///
/// Boot to ready, stop (preserving table + journal), corrupt the journal file's
/// bytes, then boot again: the corrupt/unauthenticated proof is a HARD ERROR, so
/// activation fails-before with the typed error and the pre-existing table is
/// left intact (never clobbered on an unprovable record). Clean up via nft + rm
/// so the corrupt journal cannot poison a later test.
#[test]
fn a_tampered_authenticated_journal_makes_boot_fail_before_and_leaves_the_table() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            // Unprivileged runner: cannot acquire; nothing to tamper.
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish authenticated-journal tamper precondition: {err}"
            ));
            return;
        }
    }
    // The journal survived the ordinary stop; corrupt its bytes in place.
    assert!(ownership_journal_path().exists());
    std::fs::write(ownership_journal_path(), b"{\"tampered\":true}").unwrap();

    // Boot again: a corrupt/unauthenticated journal is a hard error -> fail-before.
    let err = daemon::boot(fresh_config(&dir))
        .err()
        .expect("a corrupt ownership journal must make boot fail-before, never fresh-create");
    assert_activation_failure(&err);
    // The pre-existing owned table is left intact (never clobbered on an
    // unprovable record).
    assert!(
        nftables::table_exists().unwrap_or(false),
        "a fail-before on a corrupt journal must leave the pre-existing table intact"
    );

    // Clean up the corrupt journal (nft table + rm) so it cannot poison later
    // tests, whose boots load the journal before deciding.
    cleanup_castle_table();
    let _ = std::fs::remove_file(ownership_journal_path());
    let _ = std::fs::remove_file(journal_auth_key_path());
}

/// List the isolated owned table's ruleset text (helper for the GF1 post-checks).
fn nft_list_isolated_table() -> String {
    let out = Command::new("nft")
        .args(["list", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .expect("nft list table");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// GF1 wiring (drift-then-restart): an externally DRIFTED owned table must not
/// leave a `policy accept` base chain in force across the refusing restart. Boot
/// to ready (owns a `policy accept` base), stop (preserving table + journal),
/// inject a foreign `accept` rule into the base output chain so the captured
/// identity no longer verifies, then boot again. The reclaim path must install
/// the deny-all safety net BEFORE it fails-before, leaving the table at
/// `policy drop` (a non-allowlisted packet is dropped), never `policy accept`.
#[test]
fn gf1_drift_then_restart_installs_deny_all_before_refusing_never_leaves_accept() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            // Unprivileged runner: cannot acquire; nothing to drift.
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the drift precondition: {err}"
            ));
            return;
        }
    }
    // Precondition: the preserved base chain is `policy accept`.
    let before = nft_list_isolated_table();
    assert!(
        before.contains("policy accept"),
        "precondition: preserved base chain is policy accept: {before}"
    );

    // DRIFT: inject a foreign accept rule (no owned marker comment) into the base
    // output chain, so `verify_owned_castle_table` no longer matches.
    let drift = Command::new("nft")
        .args([
            "add",
            "rule",
            CASTLE_FAMILY,
            isolation::table(),
            "output",
            "ip",
            "daddr",
            "9.9.9.9",
            "accept",
        ])
        .status()
        .expect("inject drift rule");
    assert!(drift.success(), "drift injection must succeed");

    // Boot again: reclaim sees the drift, installs deny-all, THEN fails-before.
    let err = daemon::boot(fresh_config(&dir))
        .err()
        .expect("a drifted owned table must make boot fail-before, never adopt or leave accept");
    assert_activation_failure(&err);

    // POST-CONDITION: deny-all installed before the refuse. Base chain policy
    // drop; no accept base; the drifted 9.9.9.9 accept rule is gone.
    let after = nft_list_isolated_table();
    assert!(
        after.contains("policy drop"),
        "post: deny-all base must be policy drop: {after}"
    );
    assert!(
        !after.contains("policy accept"),
        "post: no accept base may survive the drift refusal: {after}"
    );
    assert!(
        !after.contains("9.9.9.9"),
        "post: the drifted accept rule must be flushed: {after}"
    );

    cleanup_castle_table();
    cleanup_journal();
}

/// GF1 wiring (delete-table-then-restart): when the owned table VANISHES while
/// the journal still asserts ownership for this boot, the restart must re-arm
/// deny-all, never fresh-create a `policy accept` base. Boot to ready, stop
/// (preserving the journal), delete the table (external `nft delete table`),
/// then boot again: the reclaim path routes to ReArmLostOwned, installs deny-all
/// and fails-before, leaving the recreated table at `policy drop`, never accept.
#[test]
fn gf1_lost_owned_table_then_restart_re_arms_deny_all_never_fresh_accept() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the lost-owned-table precondition: {err}"
            ));
            return;
        }
    }
    // The journal survived the ordinary stop; now DELETE the table out from
    // under it (an external `nft delete table` while ownership is asserted).
    assert!(ownership_journal_path().exists());
    cleanup_castle_table();
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "precondition: the owned table was deleted while the journal asserts ownership"
    );

    // Boot again: decide -> ReArmLostOwned -> install deny-all -> fail-before.
    let err = daemon::boot(fresh_config(&dir))
        .err()
        .expect("a vanished owned table must make boot fail-before, never fresh-create accept");
    assert_activation_failure(&err);

    // POST-CONDITION: the table is re-created as deny-all (policy drop), NEVER an
    // empty `policy accept` base that would let a live agent egress unfiltered.
    assert!(
        nftables::table_exists().unwrap_or(false),
        "post: the deny-all safety net re-created the owned table"
    );
    let after = nft_list_isolated_table();
    assert!(
        after.contains("policy drop"),
        "post: re-armed base must be policy drop: {after}"
    );
    assert!(
        !after.contains("policy accept"),
        "post: a lost owned table must never be re-armed as policy accept: {after}"
    );

    cleanup_castle_table();
    cleanup_journal();
}

// --- A162 (register LINUX-BOOT-STOP-HOSTWIDE-NET-01): a stop requested during
// the BOOT phase never installs a host-wide net, extending A155's post-READY
// rule to every pre-READY safety-net install site. Both tests below drive the
// SAME ReArmLostOwned site the two GF1 tests above exercise (boot to ready,
// stop, delete the table out from under the surviving journal, boot again),
// but the second boot pre-arms `test_boot_time_shutdown_requested` (the
// boot-phase counterpart of `--test-shutdown-at pre-recovery`, applied to
// `DaemonConfig` directly here since these are in-process `daemon::boot()`
// wired-consumer tests, the same production composition root the GF1 tests
// above exercise). AGENTS.md rule 4: this proves the production acquisition
// path reaches the A162 skip, not merely that `stop_time_hostwide_skip` (a
// unit test in `runtime_providers.rs`) returns the right bool in isolation.

/// A162, unknown-identity leg: the first boot admits no agent (no confining
/// manifest), so its journal record's `confined` key is absent. On restart the
/// vanished table resolves ReArmLostOwned with UNKNOWN history -> HostWide
/// scope. With a stop already requested, the host-wide install must be
/// SKIPPED entirely (the table stays absent), never installed and then
/// refused -- unlike the ordinary (no-stop) GF1 re-arm above, which DOES
/// install it.
#[test]
fn a162_boot_stop_skips_hostwide_net_with_unknown_confined_history() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the lost-owned-table precondition: {err}"
            ));
            return;
        }
    }
    // The journal survived the ordinary stop; delete the table out from under
    // it, exactly like the GF1 restart test above.
    assert!(ownership_journal_path().exists());
    cleanup_castle_table();
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "precondition: the owned table was deleted while the journal asserts ownership"
    );

    // Boot again with a stop ALREADY requested before kernel activation (the
    // A162 seam). decide -> ReArmLostOwned; this boot's history is unknown
    // (no confining manifest was ever admitted), so the resolution is HostWide.
    let mut config = fresh_config(&dir);
    config.test_boot_time_shutdown_requested = true;
    let err = daemon::boot(config).err().expect(
        "a boot-phase stop over an unknown identity must still fail-before (never reach READY)",
    );
    assert_activation_failure(&err);

    // POST-CONDITION, the A162 assertion: unlike the ordinary GF1 re-arm, NO
    // net was installed. The table stays absent.
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "a stop already requested with no confined identity known must skip the host-wide \
         install entirely, never install-then-refuse"
    );
    // SPECIFICITY (Claude Lens B round 1): the table's absence alone would also
    // pass if boot failed earlier for an unrelated reason. Pin the failure to
    // THIS skip: the error names the register id and the skip verb, never the
    // install arm's text, AND the residual audit row this skip is required to
    // attempt is actually present in the WAL.
    assert!(
        error_names_the_hostwide_skip(&err.to_string()),
        "the boot error must specifically name the LINUX-BOOT-STOP-HOSTWIDE-NET-01 skip, \
         not just fail for some other reason that happens to leave the table absent: {err}"
    );
    assert!(
        wal_contains_hostwide_skip_residual_row(&dir),
        "the residual audit row `stop_time_net_skipped_no_known_identity` must be present"
    );

    cleanup_castle_table();
    cleanup_journal();
}

/// A162, known-identity sibling: the first boot DOES admit a confined agent
/// (a confining manifest), so the journal record's `confined` key names
/// [`TEST_AGENT_UID`]. On restart the vanished table resolves ReArmLostOwned
/// with a KNOWN identity -> `SafetyNetScope::Identity`. A stop already
/// requested must NOT skip this install (memo `Linux_C2a_FailClosed_Architecture_v2`
/// §1 invariant: a proven loss with a known confined identity always gets its
/// one net attempt) -- the table must be re-armed exactly as the ordinary
/// (no-stop) GF1 test above re-arms it.
#[test]
fn a162_boot_stop_still_installs_identity_scope_net_with_known_confined_history() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    write_confining_manifest(dir.path(), &signing);
    match daemon::boot(fresh_confining_config(&dir, &signing)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the confined lost-owned-table precondition: \
                 {err}"
            ));
            return;
        }
    }
    assert!(ownership_journal_path().exists());
    cleanup_castle_table();
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "precondition: the owned table was deleted while the journal asserts ownership"
    );

    let mut config = fresh_confining_config(&dir, &signing);
    config.test_boot_time_shutdown_requested = true;
    let err = daemon::boot(config)
        .err()
        .expect("a vanished owned table must still fail-before even with a stop already requested");
    assert_activation_failure(&err);

    // POST-CONDITION: a KNOWN confined identity still gets its one net attempt
    // under a requested boot-phase stop; the table is re-armed as an
    // Identity-scoped deny-all net, never skipped.
    assert!(
        nftables::table_exists().unwrap_or(false),
        "a known confined identity must still install its net even under a boot-phase stop"
    );
    assert!(
        matches!(
            nftables::live_net_covers_attempt(&identity_scope(&[TEST_AGENT_UID])),
            Ok(true)
        ),
        "the installed table must be the recognised Identity-scoped deny-all net, never HostWide"
    );

    cleanup_castle_table();
    cleanup_journal();
}

/// Explicit disarm REFUSES a foreign table (no ownership proof) and leaves it
/// intact. (blockers 1, 2, 6: disarm never deletes by name)
#[test]
fn disarm_refuses_a_foreign_table_and_leaves_it_intact() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    // Pre-create a FOREIGN table (no ownership journal). Skip if unprivileged.
    let created = Command::new("nft")
        .args(["add", "table", CASTLE_FAMILY, nftables::castle_table()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created || !nftables::table_exists().unwrap_or(false) {
        cleanup_castle_table();
        skip_or_fail_unprivileged(
            "could not create the foreign table required by the disarm-refusal test",
        );
        return;
    }

    // Disarm must REFUSE (nonzero) — there is no ownership proof, so the table is
    // foreign and must never be deleted by name — and leave the table intact.
    assert!(
        !run_disarm(),
        "--disarm must refuse a foreign table (no ownership proof), never delete it by name"
    );
    assert!(
        nftables::table_exists().unwrap_or(false),
        "a refused disarm must leave the foreign table intact"
    );
    cleanup_castle_table();
}

/// THE ISOLATION PROOF (AGENTS.md: "the operator's machine is not a fixture").
///
/// A convention that says "point the tests somewhere else" is exactly what
/// failed here, so this asserts the property mechanically instead:
///
/// * the process resolved an isolated nftables table and NEVER the production
///   one (`production_castle_table_in_use()` latches the first resolution, so a
///   single stray call anywhere in this binary would flip it);
/// * every host-global path this suite hands `boot()` is off the production set;
/// * none of the production objects exists BECAUSE OF this run: each is either
///   absent, or (on a host that genuinely runs the daemon) untouched -- which the
///   isolated-table assertion above already guarantees, since no code path in
///   this process ever named them.
///
/// Runs like any other test, so it is subject to the same suite lock and cannot
/// observe a half-set-up run.
#[test]
fn this_suite_never_resolves_a_production_runtime_object() {
    let _suite = suite_guard();
    let paths = isolated_paths();

    assert!(
        !nftables::production_castle_table_in_use(),
        "a production table resolution anywhere in this test binary means some code path \
         could have created or DELETED the operator's live `{CASTLE_TABLE}` table"
    );
    assert_ne!(nftables::castle_table(), CASTLE_TABLE);
    assert!(nftables::castle_table().starts_with(ISOLATED_TABLE_PREFIX));

    for path in [
        &paths.host_lock_path,
        &paths.ownership_journal_path,
        &paths.journal_auth_key_path,
    ] {
        assert!(
            path.starts_with(isolation_root()),
            "{} must live under this run's temp root",
            path.display()
        );
    }
    assert_ne!(paths.host_lock_path, PathBuf::from(DEFAULT_HOST_LOCK_PATH));
    assert_ne!(
        paths.ownership_journal_path,
        PathBuf::from(DEFAULT_OWNERSHIP_JOURNAL_PATH)
    );
    assert_ne!(
        paths.journal_auth_key_path,
        PathBuf::from(DEFAULT_JOURNAL_AUTH_KEY_PATH)
    );

    // The config the tests actually boot with is the isolated one, not a
    // production default that merely happens to be overridden somewhere later.
    let dir = TempDir::new().unwrap();
    let config = fresh_config(&dir);
    assert_eq!(config.linux_runtime_paths, isolated_paths());
    assert!(config.linux_runtime_paths.is_isolated_from_production());

    // And the spawned-subprocess path carries the same isolation, so the shipped
    // binary this suite executes cannot reach production objects either.
    let args = isolation_args();
    assert!(args.contains(&"--isolated-runtime-root".to_string()));
    assert!(args.contains(&"--isolated-castle-table-tag".to_string()));

    // Nothing in this file references the production runtime directory.
    assert!(!isolation_root().starts_with(PRODUCTION_RUNTIME_DIR));
}

/// FAIL-BEFORE for the isolation seam itself: the seam must be unable to point a
/// daemon at the production table (or at an arbitrary operator table), and must
/// refuse to switch tables once state has been acquired under the first one.
#[test]
fn the_isolation_seam_cannot_be_aimed_at_a_production_or_foreign_table() {
    let _suite = suite_guard();
    let active = isolation::table();

    let err = nftables::use_isolated_castle_table(CASTLE_TABLE)
        .expect_err("the seam must refuse the production table name");
    assert!(err.contains(ISOLATED_TABLE_PREFIX), "{err}");

    let err = nftables::use_isolated_castle_table("operator-firewall")
        .expect_err("the seam must refuse an arbitrary operator table name");
    assert!(err.contains(ISOLATED_TABLE_PREFIX), "{err}");

    // Re-installing the SAME name is idempotent; a different one is refused,
    // because state acquired under the first name would be leaked.
    assert_eq!(
        nftables::use_isolated_castle_table(active).expect("idempotent re-install"),
        active
    );
    let err = nftables::use_isolated_castle_table(&format!("{ISOLATED_TABLE_PREFIX}other"))
        .expect_err("switching tables mid-process must be refused");
    assert!(err.contains("already resolved"), "{err}");
}

// ---- A7: readback fail-before, and readback-before-readiness ordering -----
//
// Slice A design packet section 2 (A4) and section 5 (leg L-A): `READY=1`
// implies the admitted uid's jump was READ BACK from the kernel, not merely
// that the load call returned `Ok`. The two tests below are the builder's
// deviation item 6 ("the clearest gap against A7"), closed here.

/// A7 fail-before: a forced kernel readback mismatch must withhold readiness.
///
/// `bind_admitted_uid_before_ready`'s readback step (A4) is the ONLY thing
/// standing between "the kernel accepted the load call" and "the kernel
/// actually holds the admitted uid's jump"; an `Ok` from the load proves
/// nothing about what a concurrent actor did a moment later. This test cannot
/// wait for a genuine race to lose that way on demand, so it drives the exact
/// branch through the test-isolation seam
/// (`force_next_agent_binding_readback_mismatch_for_test`,
/// `runtime_providers.rs`) and asserts the daemon takes the IDENTICAL
/// production refusal a real kernel divergence would, never a parallel
/// test-only path: the forced detail is folded into the same
/// `readback_failure` variable a genuine `UidMismatch` would produce, before
/// the branch that returns `refuse_after_owned_table`.
///
/// In-process (not `spawn_long_running_daemon`): the seam is a static in this
/// same address space, and a subprocess would boot with its own fresh, unarmed
/// copy of it, so nothing here would need to reach across a process boundary.
///
/// BOUND on what it observes: the ABSENCE of the readback-success line is NOT
/// asserted here. Rust's default test harness captures `eprintln!` inside the
/// harness before it reaches file descriptor 2, so an fd-2 swap in this process
/// reads empty whether or not the line was emitted, and an assertion over that
/// buffer would stay green if the emission moved above the readback guard. That
/// absence is NOT covered out of process either:
/// `readback_line_is_emitted_on_a_boot_that_reaches_readiness` boots
/// successfully and asserts the line's PRESENCE on that different, non-failing
/// boot, never its absence on this one. What this test asserts instead is the
/// readiness datagram's absence, which crosses a socket the harness does not
/// touch; moving the emission above the readback guard would still leave both
/// tests green, which is a named residual, not a covered case.
#[test]
fn a_forced_readback_mismatch_withholds_readiness() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    write_confining_manifest(dir.path(), &signing);
    let config = fresh_confining_config(&dir, &signing);

    // Bound, not discarded: the guard's `Drop` clears the latch, so it must
    // outlive the one `daemon::boot` call below it exists to cover, exactly as
    // `force_next_reclaim_owned_probe_error_for_test`'s callers already do in
    // `integration_gf1_recovery.rs`.
    let _forced_mismatch = force_next_agent_binding_readback_mismatch_for_test();

    // The NEGATIVE observation this test owes: no readiness datagram may reach a
    // configured NOTIFY_SOCKET. Armed BEFORE the boot call, because the beacon
    // reads the variable once.
    let readiness = ReadinessProbe::armed();
    let boot_result = daemon::boot(config);

    match boot_result {
        Ok(_handle) => panic!(
            "a forced readback mismatch must withhold READY=1 (return Err), not hand back a \
             ready handle"
        ),
        Err(err) => {
            assert_activation_failure(&err);
            let message = err.to_string();
            if !message.contains("forced to mismatch") {
                // The daemon failed-before for some OTHER reason (most likely an
                // unprivileged runner that cannot acquire nft/CAP_NET_ADMIN at
                // all) before ever reaching the A4 readback step this test means
                // to exercise. Skip like every other privileged-path test in this
                // file, rather than asserting text this run could never produce;
                // `SANCTUARY_EXPECT_PRIVILEGED_LINUX=1` turns this into a hard
                // failure on the privileged CI job, same as the rest of the file.
                cleanup_castle_table();
                cleanup_journal();
                skip_or_fail_unprivileged(&format!(
                    "boot did not reach the forced readback seam: {message}"
                ));
                return;
            }
            assert!(
                message.contains("did not read back from the kernel"),
                "the refusal must go through the A4 readback guard, not some unrelated \
                 acquisition failure; got: {message}"
            );
            readiness.assert_silent();
        }
    }

    cleanup_castle_table();
    cleanup_journal();
}

/// CAPABILITY: after a fresh acquisition, the ownership journal names THIS
/// boot's identity, owner marker and kernel handles, and a refusal that
/// withholds readiness leaves that record exactly as the acquisition wrote it.
///
/// Why it needs a wired test rather than a unit test: the property is about what
/// the whole acquisition leaves on disk, not about one function's return value.
/// The schedule drives it end to end: a valid previous-boot `Owned` record is
/// planted (authenticated with the real key, so the acquisition treats it as
/// genuine) with no live table, which routes the acquisition to `FreshCreate`;
/// the readback is then forced to fail, which drives the refusal path. The
/// journal is READ BACK and must hold the FRESH record, its confined history
/// exactly the one uid the write-ahead put there.
///
/// BOUND on what it proves: the refusal path no longer writes the journal at
/// all, so this is a regression guard on the record's contents, not a
/// discriminator between a correct write and a stale one. The property that
/// there is no write to get wrong is pinned at the source by
/// `the_slice_a_refusal_path_never_reads_or_writes_the_journal`.
/// Register: defect.linux-pr3b-refusal-record.
#[test]
fn a_refusal_after_a_fresh_acquisition_never_restores_the_previous_boots_record() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    write_confining_manifest(dir.path(), &signing);
    let config = fresh_confining_config(&dir, &signing);

    // PLANT the previous boot's record. The values are deliberately distinctive
    // so a restored record is unmistakable in the assertion below.
    const PLANTED_TABLE_HANDLE: u64 = 999_001;
    const PLANTED_BASE_CHAIN_HANDLE: u64 = 999_002;
    // CROSS-FILE PIN: the prefix must match `OWNER_MARKER_PREFIX` in
    // `src/nftables.rs`; the 32 hex digits are the 128-bit nonce `new_owner_marker`
    // emits, spelled out here so this planted value can never collide with a real
    // one drawn from /dev/urandom.
    let planted_marker = format!(
        "{}deadbeefdeadbeefdeadbeefdeadbeef",
        nftables::OWNER_MARKER_PREFIX
    );
    // CROSS-FILE PIN: the journal's boot-id grammar is hexadecimal digits and
    // hyphens only (`ownership_journal::store_atomic` validates it before
    // writing), so a mnemonic suffix makes the plant unstorable and the test
    // panics before the schedule it means to drive. These 32 hex digits are
    // distinct from any real `/proc/sys/kernel/random/boot_id` by construction:
    // the host's value is random and this one is a fixed pattern.
    let planted_boot_id = "00000000-0000-4000-8000-00000000d1fe".to_string();
    let key = ownership_journal::load_or_generate_auth_key(&journal_auth_key_path())
        .expect("the isolated key path must be writable");
    let planted = ownership_journal::OwnershipJournal::owned_with_known_history(
        ownership_journal::JournalIdentity {
            schema_version: ownership_journal::JOURNAL_SCHEMA_VERSION,
            marker: planted_marker.clone(),
            boot_id: planted_boot_id.clone(),
            source: ownership_journal::current_source(),
        },
        PLANTED_TABLE_HANDLE,
        PLANTED_BASE_CHAIN_HANDLE,
        Vec::new(),
    )
    .expect("the planted record must be constructible");
    ownership_journal::store_atomic(&ownership_journal_path(), &planted, &key)
        .expect("the planted record must store");

    let _forced_mismatch = force_next_agent_binding_readback_mismatch_for_test();
    let boot_result = daemon::boot(config);
    let message = match boot_result {
        Ok(_handle) => panic!("a forced readback mismatch must withhold READY=1"),
        Err(err) => err.to_string(),
    };
    if !message.contains("forced to mismatch") {
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&format!(
            "boot did not reach the forced readback seam: {message}"
        ));
        return;
    }

    // READ THE JOURNAL BACK: the record this acquisition created, unchanged by
    // the refusal that followed it.
    let after = ownership_journal::load(&ownership_journal_path(), Some(&key))
        .expect("the journal must still authenticate after the refusal")
        .expect("the refusal must not clear the ownership record");
    match after {
        ownership_journal::OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
            confined,
        } => {
            assert_ne!(
                identity.boot_id, planted_boot_id,
                "a refusal must not restore a previous boot's identity"
            );
            assert_eq!(
                identity.boot_id,
                ownership_journal::current_boot_id().expect("a readable boot id"),
                "the record must name THIS boot"
            );
            assert_ne!(
                identity.marker, planted_marker,
                "a refusal must not restore a previous boot's owner marker"
            );
            assert_ne!(
                table_handle, PLANTED_TABLE_HANDLE,
                "a refusal must not restore a previous boot's table handle"
            );
            assert_ne!(
                base_chain_handle, PLANTED_BASE_CHAIN_HANDLE,
                "a refusal must not restore a previous boot's base chain handle"
            );
            // The history is EXACTLY what the acquisition's own write-ahead put
            // there: one entry, the admitted uid. A refusal that appended to it
            // would show up here as a second member or a changed role.
            let history = confined.expect("the fresh record's history is known, not absent");
            let uids: Vec<u32> = history.iter().map(|entry| entry.uid).collect();
            assert_eq!(
                uids,
                vec![TEST_AGENT_UID],
                "the refusal must leave the write-ahead's history untouched"
            );
        }
        other => panic!("the refusal must leave an Owned record, got {other:?}"),
    }

    cleanup_castle_table();
    cleanup_journal();
}

/// CAPABILITY: when the confined-uid write-ahead fails, the daemon refuses
/// readiness AND the kernel is left holding a safety net whose rule 1 denies the
/// uid it was about to bind.
///
/// Why it needs a fault-injected wired test rather than a unit test: neither the
/// pure planner's tests nor a source-region pin can show what the kernel ends up
/// holding on this arm, and the arm needs a journal failure to reach. The seam
/// forces the SAME `Result` the real persist returns, so the branch taken here
/// is the production one. Register: defect.linux-pr3b-refusal-record.
///
/// THE PLANTED SCHEDULE, and why a fresh first start is the wrong one: the
/// net-on-refusal predicate reads this boot's confined history and the live
/// binding set, and on a first start both are empty, so the production answer is
/// correctly NO NET and an assertion that a net was installed fails on a correct
/// daemon. The schedule that requires one is the deleted-jump shape: the wall
/// owns a table, this boot's authenticated record already names the uid, and the
/// per-agent jump is not in the table. That is planted here by booting once over
/// a manifest that confines nobody (which leaves an owned, jump-free table),
/// rewriting the record it wrote to carry this boot's history `[TEST_AGENT_UID]`
/// under the real MAC key, and only then arming the fault.
///
/// FAILURE MODE worth stating: on an unprivileged runner the boot fails before
/// it ever reaches the write-ahead, which looks identical to a pass unless the
/// refusal text is checked; that is what the skip branches below are for, and
/// `SANCTUARY_EXPECT_PRIVILEGED_LINUX=1` turns a skip into a hard failure.
///
/// BOUND on what it observes: as in `a_forced_readback_mismatch_withholds_readiness`,
/// the absence of the two pinned stderr lines is not asserted in this process,
/// because the default test harness captures `eprintln!` before file descriptor
/// 2 and such an assertion would be vacuous. The readiness datagram and the
/// INSTALLED kernel scope are what this test observes, and neither goes through
/// the harness.
#[test]
fn a_failed_write_ahead_refuses_readiness_and_installs_a_net_naming_the_uid() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    // FIRST BOOT, over a manifest that confines nobody: it creates and owns the
    // table and writes this boot's record, and it installs no per-agent jump, so
    // what it leaves behind is exactly the owned, EMPTY table the schedule needs.
    match daemon::boot(fresh_config(&dir)) {
        Ok(handle) => {
            assert_eq!(
                handle.runtime_state(),
                DaemonRuntimeState::KernelRuntimeReady
            );
            handle.stop().expect("clean stop");
        }
        Err(err) => {
            assert_activation_failure(&err);
            cleanup_castle_table();
            cleanup_journal();
            skip_or_fail_unprivileged(&format!(
                "first daemon could not establish the owned-empty-table precondition: {err}"
            ));
            return;
        }
    }

    // REWRITE THE RECORD so this boot's confined history names the uid, keeping
    // the identity and both kernel handles the first boot captured: those are
    // what the reclaim matches the live table against, and a synthesised marker
    // or handle would route the next boot to a refusal before the bind.
    let key = ownership_journal::load_or_generate_auth_key(&journal_auth_key_path())
        .expect("the isolated key path must be writable");
    let planted = match ownership_journal::load(&ownership_journal_path(), Some(&key))
        .expect("the first boot's record must authenticate")
        .expect("the first boot must leave an ownership record")
    {
        ownership_journal::OwnershipJournal::Owned {
            identity,
            table_handle,
            base_chain_handle,
            ..
        } => ownership_journal::OwnershipJournal::owned_with_known_history(
            identity,
            table_handle,
            base_chain_handle,
            vec![ownership_journal::ConfinedIdentity {
                uid: TEST_AGENT_UID,
                role: ownership_journal::ConfinedRole::Agent,
            }],
        )
        .expect("the planted record must be constructible"),
        other => panic!("the first boot must leave an Owned record, got {other:?}"),
    };
    ownership_journal::store_atomic(&ownership_journal_path(), &planted, &key)
        .expect("the planted record must store");

    // SECOND BOOT: the manifest now admits the uid, the table is owned and holds
    // no jump for it, and the write-ahead is forced to fail.
    let signing = SigningKey::generate(&mut OsRng);
    write_confining_manifest(dir.path(), &signing);
    let config = fresh_confining_config(&dir, &signing);

    // Bound, not discarded: the guard's `Drop` clears the latch, so it must
    // outlive the one `daemon::boot` call it exists to cover.
    let _forced_error = force_next_agent_binding_write_ahead_error_for_test();
    let readiness = ReadinessProbe::armed();
    let boot_result = daemon::boot(config);

    let message = match boot_result {
        Ok(_handle) => panic!("a failed write-ahead must withhold READY=1"),
        Err(err) => {
            assert_activation_failure(&err);
            err.to_string()
        }
    };
    if !message.contains("write-ahead forced to fail") {
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&format!(
            "boot did not reach the forced write-ahead seam: {message}"
        ));
        return;
    }
    assert!(
        message.contains("could not be written into this boot's confined history"),
        "the refusal must go through the write-ahead guard: {message}"
    );
    assert!(
        message.contains("Installed the safety net"),
        "a failed write-ahead over a history that names a uid must not leave the refusal \
         netless: {message}"
    );
    // THE KERNEL, not the sentence. The refusal's introductory text names the
    // admitted uid whatever scope was installed, so searching the message for it
    // would pass on a net that protects somebody else. This reads rule 1 back out
    // of the table the daemon left behind.
    let denied = installed_net_rule_one_uids();
    assert!(
        denied.contains(&TEST_AGENT_UID),
        "rule 1 of the installed net must deny the uid the bind was about to make live; \
         denied={denied:?}, refusal={message}"
    );
    readiness.assert_silent();

    cleanup_castle_table();
    cleanup_journal();
}

/// Rule 1's uid set, read back out of the live isolated table.
///
/// CROSS-FILE PIN: the rule is recognised by its comment, which must match
/// `NET_RULE_COMMENT_IDENTITY` in `src/nftables.rs`; the emitter and this reader
/// share that one constant rather than two copies of a string. The uid set is
/// taken from the PARSED ruleset for the same reason `integration_kernel_binding.rs`
/// parses rather than greps: a text search for the number finds it in a comment,
/// in a handle, or in another rule, none of which is rule 1's scope.
///
/// FAILURE MODE worth stating: an empty return reads the same whether the net is
/// host-wide (the v1 shape carries no rules) or absent, so a caller asserting
/// membership must also have asserted that a net was installed at all.
///
/// DELIBERATELY LAXER than the product's shared `skuid_right_members`
/// (`src/nftables.rs`), and not a hand-mirrored copy of it in the sense that
/// rule warns against: neither `skuid_right_members` nor `one_skuid_scalar`
/// is `pub`, so this integration-test crate cannot call either one at all,
/// only the crate's public surface. This helper's `filter_map` on a mixed
/// `{"set":[60123,"root"]}` member list silently drops the non-numeric entry
/// rather than refusing the whole match; the product function refuses. That
/// divergence is safe here because this is a read-only diagnostic reader over
/// a table THIS test just installed (never adversarial input), and no real
/// nft output mixes a numeric and a non-numeric member in one skuid set, so
/// the laxer read never fires on anything but a hand-crafted test fixture the
/// product-level unit tests already cover separately.
fn installed_net_rule_one_uids() -> Vec<u32> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .expect("nft -j list table");
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&listing) else {
        return Vec::new();
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule.get("comment").and_then(|v| v.as_str()) != Some(nftables::NET_RULE_COMMENT_IDENTITY)
        {
            continue;
        }
        // nft renders a one-member anonymous set as a bare scalar (`meta skuid
        // 60123`) and a larger one as `{"set": [..]}`; both are rule 1's scope.
        // Reading only the set form returned an empty scope for a live one-uid
        // net on the first privileged run of this suite.
        let Some(right) = rule
            .get("expr")
            .and_then(|v| v.as_array())
            .and_then(|exprs| exprs.first())
            .and_then(|e| e.get("match"))
            .and_then(|m| m.get("right"))
        else {
            return Vec::new();
        };
        let members: Vec<u64> = match right.get("set").and_then(|v| v.as_array()) {
            Some(set) => set.iter().filter_map(|m| m.as_u64()).collect(),
            None => right.as_u64().into_iter().collect(),
        };
        let mut uids: Vec<u32> = members
            .into_iter()
            .filter_map(|v| u32::try_from(v).ok())
            .collect();
        uids.sort_unstable();
        uids.dedup();
        return uids;
    }
    Vec::new()
}

/// Room for any datagram the beacon can send, with margin to spare.
///
/// DERIVATION: `READY_DATAGRAM` in `src/systemd_notify.rs` is `READY=1\n`, which
/// is 8 bytes, and it is the ONLY datagram `signal_ready` writes. 64 is 8 times
/// that, so a datagram this probe receives is reported whole in the panic message
/// rather than truncated into bytes that read like a different message. The
/// margin exists because a truncated read here would be indistinguishable from a
/// correct one, and the failure would be a misleading panic string rather than a
/// missed refusal.
const READINESS_DATAGRAM_BUFFER_BYTES: usize = 64;

/// A bound `NOTIFY_SOCKET` that can answer "was `READY=1` ever sent".
///
/// FAILURE MODE worth stating: the beacon reads the environment variable ONCE
/// per boot, so the variable has to be set before `daemon::boot` is called, not
/// after; set it late and the test proves nothing because no socket was ever
/// configured.
struct ReadinessProbe {
    socket: UnixDatagram,
    _dir: TempDir,
}

impl ReadinessProbe {
    fn armed() -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("notify.sock");
        let socket = UnixDatagram::bind(&path).expect("a bindable notify socket");
        socket
            .set_nonblocking(true)
            .expect("the probe must never block the test");
        std::env::set_var("NOTIFY_SOCKET", &path);
        Self { socket, _dir: dir }
    }

    /// Assert nothing was delivered. A readiness datagram that arrives after a
    /// refusal is the failure this exists to catch.
    fn assert_silent(&self) {
        let mut buf = [0u8; READINESS_DATAGRAM_BUFFER_BYTES];
        match self.socket.recv(&mut buf) {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(n) => panic!(
                "a refused boot must send no readiness datagram; got {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(err) => panic!("unexpected notify-socket error: {err}"),
        }
    }
}

impl Drop for ReadinessProbe {
    fn drop(&mut self) {
        std::env::remove_var("NOTIFY_SOCKET");
    }
}

/// The pinned readback line is emitted on a boot that reaches readiness.
///
/// BOUND: this asserts PRESENCE, not order. Timestamping a stderr line on one
/// consumer thread and a `NOTIFY_SOCKET` datagram on another measures when THIS
/// process was scheduled to observe each, so a correctly emitted line can sit in
/// a pipe buffer until after readiness is seen (a red on a correct daemon) and a
/// slow reader can hide a reversed emission (a green on a wrong one). A test that
/// can fail on correct code and pass on wrong code is not evidence either way, so
/// the ordering claim is carried elsewhere.
///
/// The ORDERING claim is carried by two things that do not depend on reader
/// scheduling: the line is emitted from the readback parse result and from
/// nowhere else (`AGENT_BINDING_READBACK_LINE_PREFIX` has exactly one emission
/// site), and `agent_binding_readback_mismatch_withholds_readiness` proves a
/// failed readback withholds `READY=1` entirely. The L-A drill leg orders the two
/// on the real unit using journald `__MONOTONIC_TIMESTAMP` and the unit's
/// `ActiveEnterTimestampMonotonic`, which is one clock rather than two threads.
#[test]
fn readback_line_is_emitted_on_a_boot_that_reaches_readiness() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);
    write_confining_manifest(dir.path(), &signing);

    let notify_path = dir.path().join("notify.sock");
    let listener = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    let mut child = spawn_long_running_daemon(&dir, &pinned, &notify_path);

    // Drain stderr on a background thread so a full pipe can never make the
    // daemon block on a write while this thread waits on the notify socket.
    let stderr = child.stderr.take().expect("stderr must be piped");
    let seen: Arc<Mutex<(bool, bool)>> = Arc::new(Mutex::new((false, false)));
    let seen_writer = Arc::clone(&seen);
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF: the child closed its stderr end.
                Ok(_) => {
                    let mut flags = seen_writer.lock().unwrap();
                    if line.contains(runtime_providers::AGENT_BINDING_READBACK_LINE_PREFIX) {
                        flags.0 = true;
                    }
                    // CROSS-FILE PIN: the write-ahead needle L-A3 run 1 greps.
                    // Must match `AGENT_BINDING_WRITE_AHEAD_LINE_PREFIX` in
                    // `src/runtime_providers.rs`.
                    if line.contains(runtime_providers::AGENT_BINDING_WRITE_AHEAD_LINE_PREFIX) {
                        flags.1 = true;
                    }
                }
                Err(_) => break,
            }
        }
    });

    if let Err(reason) = wait_for_ready(&mut child, &listener, Duration::from_secs(10)) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&reason);
        return;
    }

    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", pid.as_str()]).status();
    let _ = child.wait();
    // Joining the reader after the child has exited drains stderr to EOF, so the
    // flags below are read after every line the daemon wrote, not after whatever
    // this thread happened to be scheduled to see.
    let _ = reader.join();

    let (readback_seen, write_ahead_seen) = *seen.lock().unwrap();
    assert!(
        readback_seen,
        "the pinned readback line must appear on stderr for a boot that reaches READY=1"
    );
    assert!(
        write_ahead_seen,
        "the pinned write-ahead line must appear for a boot that installed the binding"
    );

    cleanup_castle_table();
    cleanup_journal();
}

// --- W1a/W1b: wired-consumer tests for C2a1(a), register id
// LINUX-STOP-LOSS-RACE-01 (design memo `Linux_C2a_FailClosed_Architecture_v2`
// §4 test table). AGENTS.md rule 4: a capability that claims a live effect
// needs a test that constructs the real production object graph and proves
// the consumer is reached; U1-U4 (this crate's unit tests) prove the decision
// function and the runtime-provider skip removal in isolation, not that the
// real `main` binary reaches them. These two tests close that gap.

/// Spawn the shipped daemon exactly like [`spawn_long_running_daemon`], with
/// additional argv appended after the isolation args. Kept as a separate
/// function (rather than widening the existing signature) so W1a/W1b's
/// test-isolation-only seam arguments cannot leak onto the three call sites
/// above that must keep exercising the daemon's ordinary long-running argv.
fn spawn_long_running_daemon_with_extra_args(
    dir: &TempDir,
    pinned: &std::path::Path,
    notify_socket: &std::path::Path,
    extra_args: &[&str],
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_castle-wall-daemon"))
        .args([
            "--fortress-id",
            "deadbeef",
            "--socket-path",
            dir.path().join("filter.sock").to_str().unwrap(),
            "--policy-dir",
            dir.path().to_str().unwrap(),
            "--wal-path",
            dir.path().join("wal.jsonl").to_str().unwrap(),
            "--pinned-public-key",
            pinned.to_str().unwrap(),
            "--producer-key",
            dir.path().join("audit-producer.key").to_str().unwrap(),
            "--producer-pub-key",
            dir.path().join("audit-producer.pub").to_str().unwrap(),
        ])
        .args(isolation_args())
        .args(extra_args)
        .env("NOTIFY_SOCKET", notify_socket)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the shipped daemon binary (long-running, with test seam args)")
}

/// Wait up to `timeout` for `child` to exit on its own, polling like
/// [`wait_for_ready`] rather than blocking indefinitely. On timeout the child
/// is SIGKILLed and reaped so a wedged daemon cannot hang the suite; the
/// caller sees that as a failed bound, not a hang.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus, String> {
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("could not inspect daemon child: {err}"))?
        {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "daemon did not exit within {timeout:?} of the loss/shutdown seam"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Build an `Identity` scope through the ONLY admitted constructor path,
/// mirroring `identity_scope` in `integration_gf1_recovery.rs` (AGENTS.md rule
/// 5: one source rather than a second hand-mirrored copy would be preferable,
/// but the two suites are separate compilation units with no shared non-`isolation`
/// module today, so this is the smallest faithful duplication).
fn identity_scope(uids: &[u32]) -> SafetyNetScope {
    let overflow = HostOverflowUid::from_host().expect("a Linux host exposes kernel.overflowuid");
    let validated: Vec<_> = uids
        .iter()
        .map(|&uid| validate_safety_net_uid(uid, overflow).expect("an attestable uid"))
        .collect();
    SafetyNetScope::Identity(ConfinedUidSet::from_validated(validated).expect("a non-empty set"))
}

/// Whether the WAL this run wrote holds a `kernel_runtime_lost` control row
/// carrying a recovery attempt. Deliberately a raw substring scan rather than
/// parsing the nested canonical-JSON-inside-JSON `WalEntry` shape
/// (`audit.rs`'s `append_control_audit_bounded_with_safety_net` embeds the
/// operation event as an escaped string field): the row's `operation` and
/// `detail` text survive that escaping unbroken, and this test only needs to
/// prove the row is present, not parse its full structure.
fn wal_contains_recovery_row(dir: &TempDir) -> bool {
    let Ok(contents) = std::fs::read_to_string(dir.path().join("wal.jsonl")) else {
        return false;
    };
    contents.contains("kernel_runtime_lost") && contents.contains("recovery=")
}

/// Whether the WAL this run wrote holds the LINUX-BOOT-STOP-HOSTWIDE-NET-01 /
/// A155 residual row `stop_time_hostwide_skip` appends on every host-wide skip
/// under a requested stop. Same raw-substring-scan rationale as
/// `wal_contains_recovery_row` above: the operation name is the one literal
/// every caller's audit trail and any operator grep for this residual class
/// relies on (`runtime_providers.rs`'s `RESIDUAL_REASON` constant), and this
/// test only needs to prove the row is present, not parse its full structure.
fn wal_contains_hostwide_skip_residual_row(dir: &TempDir) -> bool {
    let Ok(contents) = std::fs::read_to_string(dir.path().join("wal.jsonl")) else {
        return false;
    };
    contents.contains("stop_time_net_skipped_no_known_identity")
}

/// Whether a boot error's text is SPECIFICALLY the LINUX-BOOT-STOP-HOSTWIDE-NET-01
/// host-wide skip (never a generic install or an unrelated failure that would
/// also leave the table absent). Checked by the register id every A162 skip
/// message carries plus the "skipped" verb, and the ABSENCE of the install
/// arm's "Installed the safety net" text, so a test asserting on this cannot
/// pass because the daemon failed for some other reason before ever reaching
/// the skip decision.
fn error_names_the_hostwide_skip(message: &str) -> bool {
    message.contains("LINUX-BOOT-STOP-HOSTWIDE-NET-01")
        && message.contains("safety net install was skipped")
        && !message.contains("Installed the safety net")
}

/// W1a (memo §4 test table): the real `main` binary, `--test-health-interval-ms`
/// set large so no periodic tick follows the initial one, then a proven loss
/// (the isolated table deleted out from under a READY daemon) racing a manager
/// stop (SIGTERM). Exercises sites 2/3 (`stop_final_health_outcome` /
/// `S_STOP_FINAL_HEALTH`): on `174475fe` this exits 0 with the table absent
/// (mutants M2/M3 restore that bare shutdown-wins-over-loss ordering); after
/// C2a1(a) it must exit 78 with a freshly installed, recognised net.
#[test]
fn stop_racing_a_proven_loss_installs_the_net_w1a() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);
    // A known confined identity, so the stop-time install is Identity-scoped
    // (A155): with no confined identity a HostWide install is skipped under
    // shutdown and only a residual audit row is recorded instead.
    write_confining_manifest(dir.path(), &signing);

    let notify_path = dir.path().join("notify-w1a.sock");
    let listener = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    // 600000ms (10 minutes): far longer than this test's bounded wait below, so
    // the periodic health tick cannot fire a second time and race the SIGTERM;
    // the daemon's OWN stop-time final health pass must be what proves the loss.
    const NO_SECOND_TICK_MS: &str = "600000";
    let mut child = spawn_long_running_daemon_with_extra_args(
        &dir,
        &pinned,
        &notify_path,
        &["--test-health-interval-ms", NO_SECOND_TICK_MS],
    );

    if let Err(reason) = wait_for_ready(&mut child, &listener, Duration::from_secs(10)) {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&reason);
        return;
    }

    // Inject the loss: delete the isolated owned table out from under the
    // ready daemon, the same real-kernel loss an external delete or `nft
    // flush` would produce.
    cleanup_castle_table();
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "the loss injection must actually remove the isolated table before SIGTERM races it"
    );

    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", pid.as_str()]).status();
    let status = match wait_for_exit(&mut child, Duration::from_secs(15)) {
        Ok(status) => status,
        Err(reason) => {
            cleanup_castle_table();
            cleanup_journal();
            panic!("{reason}");
        }
    };

    assert_eq!(
        status.code(),
        Some(78),
        "a proven loss racing a manager stop must exit 78 (RepairRequired), never 0; got {status:?}"
    );
    assert!(
        nftables::table_exists().unwrap_or(false),
        "the stop-time recovery must have installed a fresh table before exit"
    );
    assert!(
        matches!(
            nftables::live_net_covers_attempt(&identity_scope(&[TEST_AGENT_UID])),
            Ok(true)
        ),
        "the installed table must be the recognised Identity-scoped deny-all net for the \
         confined uid (A155: a known confined identity gets Identity scope, never HostWide)"
    );
    assert!(
        wal_contains_recovery_row(&dir),
        "the audit WAL must hold a kernel_runtime_lost row carrying the recovery attempt result"
    );

    cleanup_castle_table();
    cleanup_journal();
}

/// W1b (memo §4 test table, site 5): the real `main` binary with the
/// `--test-shutdown-at pre-recovery` seam armed, which flips the real
/// shutdown flag on the first live shutdown read inside the recovery
/// controller, after the component's probe has already seen the loss, so it
/// proves the site-5 precedence fix (a first-entry proven loss still gets its
/// one net-install attempt when a stop lands between the probe and the
/// decision) without racing an OS signal.
/// No SIGTERM is sent in this test; the daemon stops itself. On `174475fe`
/// this exits 0 with `NoInstall` (mutant M1's skip, and M3); after C2a1(a) it
/// must exit 78 with the net live.
#[test]
fn shutdown_observed_at_pre_recovery_still_installs_the_net_w1b() {
    let _suite = suite_guard();
    cleanup_castle_table();
    cleanup_journal();
    ensure_runtime_dir();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pinned = write_pinned_key(&dir, &signing);
    write_confining_manifest(dir.path(), &signing);

    let notify_path = dir.path().join("notify-w1b.sock");
    let listener = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    // A short interval: the seam must fire on the NEXT periodic health call
    // after the loss is injected below, well inside this test's bounded wait.
    const HEALTH_TICK_MS: &str = "200";
    let mut child = spawn_long_running_daemon_with_extra_args(
        &dir,
        &pinned,
        &notify_path,
        &[
            "--test-health-interval-ms",
            HEALTH_TICK_MS,
            "--test-shutdown-at",
            "pre-recovery",
        ],
    );

    if let Err(reason) = wait_for_ready(&mut child, &listener, Duration::from_secs(10)) {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_castle_table();
        cleanup_journal();
        skip_or_fail_unprivileged(&reason);
        return;
    }

    cleanup_castle_table();
    assert!(
        !nftables::table_exists().unwrap_or(true),
        "the loss injection must actually remove the isolated table before the next health tick"
    );

    // No external signal: the armed seam sets the shutdown flag itself on the
    // next health call, immediately before the recovery attempt it protects.
    let status = match wait_for_exit(&mut child, Duration::from_secs(15)) {
        Ok(status) => status,
        Err(reason) => {
            cleanup_castle_table();
            cleanup_journal();
            panic!("{reason}");
        }
    };

    assert_eq!(
        status.code(),
        Some(78),
        "shutdown observed at the pre-recovery call boundary must still exit 78 \
         (RepairRequired), never 0; got {status:?}"
    );
    assert!(
        nftables::table_exists().unwrap_or(false),
        "the recovery attempt this seam races must have installed a fresh table"
    );
    assert!(
        matches!(
            nftables::live_net_covers_attempt(&identity_scope(&[TEST_AGENT_UID])),
            Ok(true)
        ),
        "the installed table must be the recognised Identity-scoped deny-all net"
    );

    cleanup_castle_table();
    cleanup_journal();
}
