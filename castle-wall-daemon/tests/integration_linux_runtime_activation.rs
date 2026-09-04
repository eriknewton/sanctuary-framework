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

use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use castle_wall_daemon::config::LinuxRuntimePaths;
use castle_wall_daemon::daemon::{self, DaemonError, DaemonRuntimeState};
use castle_wall_daemon::nftables::{self, CASTLE_FAMILY, CASTLE_TABLE, ISOLATED_TABLE_PREFIX};
use castle_wall_daemon::ownership_journal::{
    DEFAULT_JOURNAL_AUTH_KEY_PATH, DEFAULT_OWNERSHIP_JOURNAL_PATH,
};
use castle_wall_daemon::runtime_lock::DEFAULT_HOST_LOCK_PATH;
use castle_wall_daemon::DaemonConfig;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;

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
    nftables::parse_owned_table_identity(json)
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
    }
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
    nftables::verify_owned_castle_table(&production_identity)
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
