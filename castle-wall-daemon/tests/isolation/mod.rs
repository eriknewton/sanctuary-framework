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
        // The daemon-side stop hook resolves a host-global tree of its own: the
        // owner socket, the receipt pins, the daemon release log and the keys
        // beside them. Bind it to this run's root before any test can reach the
        // startup path that calls it. Linux-only, because the owner module is.
        //
        // Failure mode without this: a `test-isolation` binary is not
        // `cfg(test)`, so the hook resolves the INSTALLED tree and a `cargo
        // test` run reads the operator's own owner socket and pins on any host
        // with Sanctuary installed, with no error attributable to the suite
        // that did it.
        #[cfg(target_os = "linux")]
        castle_wall_daemon::protected_agent::owner::use_isolated_owner_paths(root.path())
            .expect("bind the daemon-side stop hook to this run's isolated tree");
        Isolated { root, paths, table }
    })
}

/// Take the suite lock and re-assert isolation on EVERY test entry. A poisoned
/// lock is recovered rather than cascading: one failing test must not convert the
/// rest into false failures.
/// The write-ahead proof the per-agent kernel bind requires, minted WITHOUT a journal
/// write for a suite that is exercising the kernel path rather than the journal one.
///
/// Available only here, in a `test-isolation` build. The production bind can obtain a
/// proof ONLY from a successful journal write, which is what makes the persist
/// unskippable outside these suites; the journal-order property itself is asserted by
/// the crate's own write-ahead tests rather than by these kernel suites.
pub fn write_ahead_receipt_for(
    binding: castle_wall_daemon::nftables::AgentUidBinding,
) -> castle_wall_daemon::ownership_journal::WriteAheadReceipt {
    castle_wall_daemon::ownership_journal::WriteAheadReceipt::for_isolated_test(binding.agent_uid)
}

pub fn guard() -> SuiteGuard {
    let lock = SUITE_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let iso = isolated();
    assert!(
        !nftables::production_castle_table_in_use(),
        "this suite must never resolve the production `sanctuary-castle` table"
    );
    assert!(iso.table.starts_with(ISOLATED_TABLE_PREFIX));
    assert!(iso.paths.is_isolated_from_production());
    // Re-read what the daemon-side stop hook itself resolves, not what this
    // module asked it to resolve: the assertion is about the tree the hook
    // reaches, so it calls the resolver rather than restating the binding.
    #[cfg(target_os = "linux")]
    {
        let hook_tree = castle_wall_daemon::protected_agent::owner::resolved_hook_paths()
            .expect("the daemon-side stop hook must resolve this run's isolated tree");
        assert!(
            hook_tree.is_isolated_from_production(),
            "the stop hook must carry no installed name in an isolated suite"
        );
        assert!(
            hook_tree
                .every_path()
                .iter()
                .all(|name| name.starts_with(iso.root.path())),
            "every name the stop hook reads must be inside this run's isolated root"
        );
    }
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
    SuiteGuard { _lock: lock }
}

/// The suite lock plus the end-of-test teardown of this run's kernel state.
///
/// Holding it serializes the binary (see [`SUITE_LOCK`]); dropping it, on a
/// passing return AND on a panic unwind, removes the isolated table and then
/// refuses any leftover kernel object named for this run.
///
/// Why the teardown exists: the entry sweep in [`guard`] cleaned up after a test
/// only when ANOTHER test in the same binary started. The LAST test of a binary
/// therefore left its table in the kernel until the workflow's final cleanup
/// step, and a test that drives a refusal arm leaves the deny-all safety net
/// there (`policy drop` on the inet output hook). Failure mode: every later
/// step on the same runner loses DNS, and the next network step fails with
/// `getaddrinfo EAI_AGAIN`, which reads as GitHub weather rather than as a test
/// that did not clean up.
pub struct SuiteGuard {
    /// Fields drop only after `Drop::drop` returns, so the lock is still held
    /// while the teardown sweeps: the next test cannot start against a table this
    /// one still owns.
    _lock: MutexGuard<'static, ()>,
}

impl Drop for SuiteGuard {
    fn drop(&mut self) {
        let iso = isolated();
        // The net goes in `castle_table()` (src/nftables.rs
        // `install_deny_all_safety_net`), which this run pinned to `iso.table`
        // through `use_isolated_castle_table`, so deleting that one name removes
        // an owned wall and a safety net alike. Must match the name
        // `castle_table()` resolves in src/nftables.rs; `guard` asserts the
        // production name is never resolved, so this never names the operator's
        // table.
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", nftables::CASTLE_FAMILY, iso.table])
            .output();
        // A leftover after the sweep is a TEST FAILURE, never a second silent
        // sweep: a table the sweep could not remove, or one named for this run
        // that the sweep does not own, is exactly the state that took the
        // runner's DNS down, and it must name itself where it happened.
        if let Err(report) = leftover_kernel_state() {
            if std::thread::panicking() {
                // A second panic during an unwind aborts the process and loses the
                // original failure; report beside it instead.
                eprintln!("{report}");
            } else {
                panic!("{report}");
            }
        }
    }
}

/// Must match `EXPECT_PRIVILEGED_ENV` in the privileged suites and the
/// `SANCTUARY_EXPECT_PRIVILEGED_LINUX` env in `.github/workflows/castle-wall-linux.yml`.
const EXPECT_PRIVILEGED_ENV: &str = "SANCTUARY_EXPECT_PRIVILEGED_LINUX";

/// Every kernel table this run could have created: this run's isolated table and
/// any `<isolated table>-<suffix>` beside it. The trailing `-` keeps a different
/// process's tag that merely starts with this one's hex (pid `2b3` vs `2b30`)
/// out of the match. The production `sanctuary-castle` table is deliberately NOT
/// matched: [`guard`] asserts no test in this binary resolves it, and on an
/// operator's host it is live enforcement this suite must never touch.
/// The workflow step `Refuse leftover kernel state before the upload` in
/// `.github/workflows/castle-wall-linux.yml` refuses the wider `sanctuary-castle*`
/// family across the whole run; must match that step's patterns.
fn names_this_run(name: &str, table: &str) -> bool {
    name == table
        || name
            .strip_prefix(table)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Refuse kernel state this run left behind: `Err` names each leftover table and
/// carries the whole ruleset, after deleting the leftovers so a failed test does
/// not ALSO take the runner's DNS down for every later step.
///
/// A ruleset that cannot be read is indeterminate. Under the privileged contract
/// ([`EXPECT_PRIVILEGED_ENV`]) that is a failure, never a pass; on an ad-hoc
/// unprivileged host (or one with no `nft`) the suite could not have created a
/// table either, so there is nothing to refuse.
pub fn leftover_kernel_state() -> Result<(), String> {
    let table = isolated().table;
    let listed = std::process::Command::new("nft")
        .args(["list", "tables"])
        .output();
    let listing = match listed {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        other => {
            if std::env::var_os(EXPECT_PRIVILEGED_ENV).is_some() {
                return Err(format!(
                    "leftover kernel state check: `nft list tables` could not be read under \
                     {EXPECT_PRIVILEGED_ENV}; an unreadable ruleset is not a clean one: {other:?}"
                ));
            }
            return Ok(());
        }
    };
    // `nft list tables` prints one `table <family> <name>` line per table.
    let leftovers: Vec<(String, String)> = listing
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("table"), Some(family), Some(name)) if names_this_run(name, table) => {
                    Some((family.to_string(), name.to_string()))
                }
                _ => None,
            }
        })
        .collect();
    if leftovers.is_empty() {
        return Ok(());
    }
    let ruleset = std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_else(|err| format!("<`nft list ruleset` failed: {err}>"));
    for (family, name) in &leftovers {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", family, name])
            .output();
    }
    Err(format!(
        "leftover kernel state after the isolation teardown: {leftovers:?} survived the \
         sweep of `{table}` (deleted now so later steps keep their network). A test left \
         kernel state behind; the ruleset at teardown was:\n{ruleset}"
    ))
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

/// Post-installation readiness assertion, shared by the privileged fixtures that
/// install a per-agent uid binding into the daemon's acquired table.
///
/// Linux-only because the cache it waits out is the Linux `nft` ownership proof;
/// the non-Linux suites that also include this module have no such probe.
#[cfg(target_os = "linux")]
mod health_freshness {
    use std::time::Duration;

    use castle_wall_daemon::daemon::DaemonHandle;
    use castle_wall_daemon::runtime_health::RuntimeHealthState;
    use castle_wall_daemon::runtime_providers::NFT_HEALTH_MIN_INTERVAL;

    /// Slack added to `NFT_HEALTH_MIN_INTERVAL` before a post-install readiness
    /// poll. Absorbs sleep granularity only; it is not a retry budget and must
    /// never be raised to make a flaky fixture pass.
    const HEALTH_FRESHNESS_MARGIN: Duration = Duration::from_millis(100);

    /// Consecutive indeterminate readings tolerated, `HEALTH_PROBE_RETRY_SPACING`
    /// apart. 40 x 50ms = 2s, comfortably past the daemon's 1s bounded `nft`
    /// proof (`NFT_HEALTH_QUERY_TIMEOUT`), so a proof still in flight resolves
    /// rather than failing the fixture.
    const HEALTH_PROBE_MAX_INDETERMINATE: usize = 40;
    const HEALTH_PROBE_RETRY_SPACING: Duration = Duration::from_millis(50);

    /// Assert the daemon's OWN supervision reads the live table as owned, from a
    /// health observation that COMPLETED AFTER the caller installed its binding.
    ///
    /// One shared helper rather than an inline loop per suite: three fixtures
    /// need the identical predicate, and a per-suite copy is the hand-mirrored
    /// shape that drifts (AGENTS rule 5).
    ///
    /// Why the sleep is load-bearing: `BoundedHealthProbe::poll_result`
    /// (`src/health_probe.rs`) serves any reading taken within
    /// `NFT_HEALTH_MIN_INTERVAL` of the last completed proof straight from cache.
    /// A poll issued immediately after an install can therefore return a reading
    /// of the PRE-INSTALL table and certify an inventory that was never examined.
    /// Sleeping one whole min-interval past the install bounds the age of any
    /// cached reading below the elapsed time since that install, so whatever comes
    /// back was observed after it; a cache that has aged out forks a fresh `nft`
    /// proof instead. Either way the observation post-dates the installation.
    ///
    /// Failure mode if this is skipped: the fixture passes through the cache while
    /// the binding is unverifiable, then fails intermittently once the cache
    /// expires, which reads as a flake rather than as the missing supervision it
    /// is.
    ///
    /// `ProbeUnavailable` is INDETERMINATE (a bounded `nft` proof may still be in
    /// flight), so it is retried and NEVER read as ready; a proven `Lost` fails
    /// now.
    pub fn assert_ownership_health_after_install(handle: &DaemonHandle, context: &str) {
        std::thread::sleep(NFT_HEALTH_MIN_INTERVAL + HEALTH_FRESHNESS_MARGIN);
        for _ in 0..HEALTH_PROBE_MAX_INDETERMINATE {
            match handle.kernel_runtime_health() {
                RuntimeHealthState::Ready => return,
                RuntimeHealthState::ProbeUnavailable => {
                    std::thread::sleep(HEALTH_PROBE_RETRY_SPACING);
                }
                other => panic!(
                    "{context}: kernel runtime health must be Ready in an observation taken \
                     AFTER the manifest-matched uid binding was installed; got {other:?}"
                ),
            }
        }
        panic!(
            "{context}: kernel runtime health never resolved past ProbeUnavailable, so no \
             post-installation observation was ever completed"
        );
    }
}

// Same reason as the file-level `dead_code` allow: only three of the suites that
// include this module install a uid binding, so for the others the re-export is
// legitimately unused.
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use health_freshness::assert_ownership_health_after_install;
