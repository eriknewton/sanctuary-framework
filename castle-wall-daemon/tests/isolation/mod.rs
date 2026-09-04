//! Shared host-state isolation for the privileged Linux integration suites.
//!
//! AGENTS.md, "Test isolation: the operator's machine is not a fixture": every
//! test binary in this directory that drives `daemon::boot` or calls into
//! `nftables` touches HOST-GLOBAL objects -- one `sanctuary-castle` nftables
//! table, one host ownership lock, one authenticated ownership journal, and its
//! root-owned MAC key. Before this module existed each suite used the production
//! objects directly, and their setup helpers ran
//! `nft delete table inet sanctuary-castle`, deleting a LIVE enforcement table on
//! any Linux host where `cargo test` ran.
//!
//! ONE module rather than a copy per suite: a per-suite copy is precisely the
//! hand-mirrored shape that drifts (AGENTS rule 5). Each suite calls
//! [`guard`] at the top of every test and builds its `DaemonConfig` with
//! [`runtime_paths`].
//!
//! This file is only reachable from a `--features test-isolation` build, which
//! the suites that include it declare through `required-features`. A release
//! build of the daemon contains none of these seams.

#![allow(dead_code)] // each suite uses a different subset of these helpers

use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use castle_wall_daemon::config::LinuxRuntimePaths;
use castle_wall_daemon::nftables::{self, ISOLATED_TABLE_PREFIX};
use tempfile::TempDir;

struct Isolated {
    root: TempDir,
    paths: LinuxRuntimePaths,
    table: &'static str,
}

static ISOLATED: OnceLock<Isolated> = OnceLock::new();

/// Serializes every test inside one binary.
///
/// Isolation from PRODUCTION does not make the suite safe against ITSELF: the
/// isolated table, lock, and journal are still one set of objects shared by the
/// whole binary. This used to depend entirely on CI passing `--test-threads=1`,
/// which nothing in the source asserted. Failure mode without it: a test observes
/// another test's table or journal and reports a fail-before that never happened,
/// which reads as a flaky enforcement bug rather than as interference.
static SUITE_LOCK: Mutex<()> = Mutex::new(());

fn isolated() -> &'static Isolated {
    ISOLATED.get_or_init(|| {
        let root = TempDir::new().expect("isolation root");
        // Per-PROCESS tag: two concurrent `cargo test` invocations on one host run
        // separate test binaries and must not collide on a shared test table.
        let tag = format!("{:x}", std::process::id());
        let table = nftables::use_isolated_castle_table(&format!("{ISOLATED_TABLE_PREFIX}{tag}"))
            .expect("install the isolated castle table before any nftables call");
        let paths = LinuxRuntimePaths::isolated_under(root.path());
        assert!(
            paths.is_isolated_from_production(),
            "every host-global path this suite uses must be off the production set"
        );
        Isolated { root, paths, table }
    })
}

/// Take the suite lock and re-assert isolation on EVERY test entry. A poisoned
/// lock is recovered rather than cascading: one failing test must not convert the
/// rest into false failures.
pub fn guard() -> MutexGuard<'static, ()> {
    let lock = SUITE_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let iso = isolated();
    assert!(
        !nftables::production_castle_table_in_use(),
        "this suite must never resolve the production `sanctuary-castle` table"
    );
    assert!(iso.table.starts_with(ISOLATED_TABLE_PREFIX));
    assert!(iso.paths.is_isolated_from_production());
    // Each test must begin from the clean ownership state a freshly-exec'd daemon
    // would have. A production daemon holds ONE authenticated nft runtime identity
    // for its whole life; a test binary re-acquires one per test, so without this
    // the second boot fails with "a different nft runtime identity is already
    // active in this process", or reclaims a journal whose live table no longer
    // matches. Clear the process-global latch and drop any ownership journal a
    // prior test left in the isolated root; the seam is compiled only under
    // `--features test-isolation`, which this suite always builds with.
    nftables::reset_runtime_ownership_for_tests();
    let _ = std::fs::remove_file(&iso.paths.ownership_journal_path);
    // Drop any leftover ISOLATED table too, so each test's boot starts from a
    // clean host-global state: with no table AND no journal the acquisition path
    // takes FreshCreate, never a RefuseForeign against a prior test's table
    // whose journal we just cleared, and never a reclaim-verify against a stale
    // agent jump. Isolated name only (iso.table starts with ISOLATED_TABLE_PREFIX,
    // asserted above); the production `sanctuary-castle` table is never named.
    let _ = std::process::Command::new("nft")
        .args(["delete", "table", nftables::CASTLE_FAMILY, iso.table])
        .output();
    lock
}

/// The isolated host-global paths a `DaemonConfig` in this suite must carry.
pub fn runtime_paths() -> LinuxRuntimePaths {
    isolated().paths.clone()
}

/// The isolated nftables table name. Equal to `nftables::castle_table()`; exposed
/// so a suite's own `nft` shell-outs name the same table the library does.
pub fn table() -> &'static str {
    isolated().table
}

/// This run's temp root, for a suite that needs to place its own files beside the
/// isolated lock/journal.
pub fn root() -> &'static Path {
    isolated().root.path()
}

/// argv every spawned daemon subprocess must carry so the SUBPROCESS lands on the
/// same isolated table and paths as the in-process boots.
pub fn subprocess_args() -> Vec<String> {
    vec![
        "--isolated-castle-table-tag".to_string(),
        format!("{:x}", std::process::id()),
        "--isolated-runtime-root".to_string(),
        root().display().to_string(),
        // Every spawned daemon must carry the authenticated broker UID the boot
        // path now REQUIRES: daemon::boot fails-before with TrustedServiceUidMissing
        // when it is absent, so without this a spawned daemon never reaches the
        // behavior under test (fatal control path, SIGKILL reclaim, disarm) and the
        // privilege-gated tests silently SKIP. Use this process's own euid, which
        // under the privileged CI / drill sudo-runner is the same root the
        // in-process boots pass via `fresh_config`'s `Some(geteuid())`.
        "--trusted-service-uid".to_string(),
        // SAFETY: geteuid() is always-successful and has no preconditions.
        (unsafe { libc::geteuid() }).to_string(),
    ]
}
