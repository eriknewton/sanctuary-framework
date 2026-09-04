//! Real-nft integration tests for the round-2 Castle Wall hardening residuals
//! GF1.1 (create-failure recovery, acquire AND disarm), GF1.2 (drift fail-closed
//! escalation post-condition), and GF1.3 (runtime-loss deny-all via `health()`).
//!
//! These drive the SHIPPED public API against a real kernel `nft` on an ISOLATED
//! `sanctuary-castle-test-*` table (never the operator's production table; see
//! [`isolation`]). They require CAP_NET_ADMIN, so they run under the privileged
//! Ubuntu-CI / drill sudo-runner and emit an explicit SKIP on an unprivileged
//! host. The whole file is `cfg(target_os = "linux")`-gated out on the dev host.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use castle_wall_daemon::config::LinuxRuntimePaths;
use castle_wall_daemon::nfqueue::NfqueueConfig;
use castle_wall_daemon::nftables::{self, CASTLE_FAMILY, OWNER_MARKER_PREFIX};
use castle_wall_daemon::ownership_journal::{
    self as journal, JournalIdentity, OwnershipJournal, JOURNAL_SCHEMA_VERSION,
};
use castle_wall_daemon::runtime_providers::{
    acquire_castle_table_component_for_test, disarm_castle_runtime, DisarmOutcome,
    LinuxRuntimeConfig,
};

mod isolation;

const EXPECT_PRIVILEGED_ENV: &str = "SANCTUARY_EXPECT_PRIVILEGED_LINUX";

/// Emit an unmistakable SKIP on ad-hoc unprivileged Linux hosts, but FAIL when the
/// privileged CI/drill contract was explicitly enabled. Mirrors the sibling suite.
fn skip_or_fail_unprivileged(reason: &str) {
    if std::env::var_os(EXPECT_PRIVILEGED_ENV).is_some() {
        panic!(
            "privileged Linux runtime required by {EXPECT_PRIVILEGED_ENV}, unavailable: {reason}"
        );
    }
    eprintln!("SKIP (privileged Linux runtime unavailable): {reason}");
}

/// Can this host actually mutate nftables? Probes with a real add+delete of the
/// ISOLATED table. Returns false (and the caller SKIPs) on any nft/permission
/// failure so the suite never silently passes on an unprivileged runner.
fn nft_available() -> bool {
    let add = Command::new("nft")
        .args(["add", "table", CASTLE_FAMILY, isolation::table()])
        .output();
    match add {
        Ok(o) if o.status.success() => {
            let _ = Command::new("nft")
                .args(["delete", "table", CASTLE_FAMILY, isolation::table()])
                .output();
            true
        }
        _ => false,
    }
}

fn config(paths: &LinuxRuntimePaths, policy_dir: &Path) -> LinuxRuntimeConfig {
    LinuxRuntimeConfig {
        lock_path: paths.host_lock_path.clone(),
        journal_path: paths.ownership_journal_path.clone(),
        journal_key_path: paths.journal_auth_key_path.clone(),
        policy_dir: policy_dir.to_path_buf(),
        poll_interval: Duration::from_millis(200),
        nfqueue: NfqueueConfig::default(),
    }
}

/// Write a `Preparing` ownership journal for THIS boot with a fresh marker, the
/// exact durable state a create failure (or a crash after `store_atomic(Preparing)`
/// before `create`) leaves behind.
fn write_preparing_journal(cfg: &LinuxRuntimeConfig) {
    let key = journal::load_or_generate_auth_key(&cfg.journal_key_path)
        .expect("load/generate the journal MAC key");
    let identity = JournalIdentity {
        schema_version: JOURNAL_SCHEMA_VERSION,
        marker: format!("{OWNER_MARKER_PREFIX}{}", "a".repeat(32)),
        boot_id: journal::current_boot_id().expect("boot id"),
        source: journal::current_source(),
    };
    journal::store_atomic(
        &cfg.journal_path,
        &OwnershipJournal::Preparing { identity },
        &key,
    )
    .expect("durably record the Preparing journal");
}

/// The live isolated table's base output chain policy (`accept`/`drop`), or None
/// if the table is absent. Read straight from `nft` so the packet disposition is
/// asserted against the kernel, not a library re-derivation.
fn live_base_policy() -> Option<String> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    for item in doc.get("nftables")?.as_array()? {
        if let Some(chain) = item.get("chain") {
            if chain.get("name").and_then(|v| v.as_str()) == Some("output") {
                return chain
                    .get("policy")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
        }
    }
    None
}

// GF1.1: crash-after-Preparing-before-create, then a SUBSEQUENT acquire recovers
// (no wedge) with deny-all held throughout. Before the fix the second pass saw
// the deny-all net + Preparing -> FinalizeInterrupted -> capture fails -> wedge.
#[test]
fn gf1_1_acquire_recovers_from_create_failure_wedge_holding_deny_all() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // 1) The create-failure durable state: Preparing journal, no live table.
    write_preparing_journal(&cfg);
    assert!(
        !nftables::table_exists().unwrap(),
        "precondition: no live table"
    );

    // 2) First pass: no table + Preparing -> ReArmLostOwned -> installs the
    //    deny-all net and REFUSES. Deny-all is now held.
    let first = acquire_castle_table_component_for_test(&cfg);
    assert!(
        first.is_err(),
        "the first pass must refuse after arming the deny-all net"
    );
    assert!(
        nftables::live_table_is_deny_all_safety_net().unwrap(),
        "ReArmLostOwned must leave this daemon's deny-all net live"
    );
    assert_eq!(
        live_base_policy().as_deref(),
        Some("drop"),
        "deny-all held: the base chain drops every packet"
    );

    // 3) Second pass: deny-all net + Preparing -> FinalizeInterrupted -> capture
    //    fails -> RECOGNIZE our net -> atomic reset to a fresh owned table ->
    //    finalize. No wedge. The atomic reset means deny-all is held until the
    //    owned wall is up (never an intermediate absent/`accept`-without-owner).
    let recovered = acquire_castle_table_component_for_test(&cfg)
        .expect("the second pass must RECOVER, not wedge");
    // The live table is now a fully-formed owned table (policy accept), and the
    // recovered component reports ready against it.
    assert!(
        recovered.is_ready(),
        "the recovered component must be ready against the fresh owned table"
    );
    let live = live_owned_identity().expect("recovered table parses as owned");
    assert!(live.marker.starts_with(OWNER_MARKER_PREFIX));
    assert_eq!(
        live_base_policy().as_deref(),
        Some("accept"),
        "recovery lands a fresh owned table"
    );
    // Releasing drops ONLY the host lock (fail-closed preservation); the owned
    // table + Owned journal survive for the suite guard to clean up next.
    drop(recovered);
}

// GF1.1: the SAME wedge state is recoverable by `--disarm`. Before the fix disarm
// also wedged (capture fails, refuse+retain forever).
#[test]
fn gf1_1_disarm_recovers_from_create_failure_wedge() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // Reconstruct the armed wedge: Preparing journal + this daemon's deny-all net.
    write_preparing_journal(&cfg);
    nftables::install_deny_all_safety_net().expect("arm the deny-all net");
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    // --disarm must recognize its own net for an interrupted acquisition, delete
    // it, confirm absence, and clear the record: StaleRecordCleared, not a wedge.
    let outcome = disarm_castle_runtime(&cfg).expect("disarm must RECOVER, not wedge");
    assert_eq!(outcome, DisarmOutcome::StaleRecordCleared);
    assert!(
        !nftables::table_exists().unwrap(),
        "disarm must leave no live table"
    );
    assert!(
        !cfg.journal_path.exists(),
        "disarm must clear the interrupted ownership record"
    );
}

// GF1.2 post-condition: the drift escalation's by-name delete leaves NO live
// `policy accept` castle table. (The escalation SEQUENCE -- install-fail ->
// delete -- is proven deterministically in the runtime_providers unit tests; this
// asserts the delete achieves the fail-closed post-condition on real nft.)
#[test]
fn gf1_2_by_name_delete_leaves_no_live_accept() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    // A live owned `policy accept` table (the drifted-table stand-in).
    let marker = format!("{OWNER_MARKER_PREFIX}{}", "b".repeat(32));
    nftables::create_castle_table_exclusive(&marker).expect("create an accept table");
    assert_eq!(live_base_policy().as_deref(), Some("accept"));

    // The escalation's last-resort action.
    nftables::force_delete_castle_table_by_name().expect("force-delete by name");
    assert!(
        !nftables::table_exists().unwrap(),
        "no live castle table (hence no `policy accept` path) may remain"
    );
    assert_eq!(live_base_policy(), None);
}

// GF1.3: an owned table deleted at runtime -> `health()` detects Lost -> installs
// the deny-all net IMMEDIATELY (base chain drops), without waiting for a restart.
#[test]
fn gf1_3_runtime_loss_installs_deny_all_net_via_health() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // 1) Fresh-acquire a real owned table (no prior table/journal -> FreshCreate).
    let component =
        acquire_castle_table_component_for_test(&cfg).expect("fresh acquire an owned table");
    assert!(
        component.is_ready(),
        "the freshly owned table must read ready"
    );
    assert_eq!(live_base_policy().as_deref(), Some("accept"));

    // 2) External runtime loss: delete the owned table out from under the daemon.
    let deleted = Command::new("nft")
        .args(["delete", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .expect("delete the owned table");
    assert!(deleted.status.success(), "external delete must succeed");
    assert!(!nftables::table_exists().unwrap());

    // 3) health() must detect the completed loss and install the deny-all net
    //    immediately (not merely report Lost and wait for the systemd restart).
    let mut became_lost = false;
    for _ in 0..8 {
        if matches!(
            component.health(),
            castle_wall_daemon::enforcement::ComponentHealth::Lost
        ) {
            became_lost = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(600));
    }
    assert!(
        became_lost,
        "health() must report the completed loss as Lost"
    );
    assert!(
        nftables::live_table_is_deny_all_safety_net().unwrap(),
        "runtime loss must install the deny-all net without waiting for a restart"
    );
    assert_eq!(
        live_base_policy().as_deref(),
        Some("drop"),
        "a non-allowlisted packet is dropped, never accepted, after the loss"
    );
    drop(component);
}

/// Read the exact live isolated-table identity through nft's real JSON output.
fn live_owned_identity() -> Result<nftables::CastleTableOwnership, String> {
    let output = Command::new("nft")
        .args([
            "-a",
            "-j",
            "list",
            "table",
            CASTLE_FAMILY,
            isolation::table(),
        ])
        .output()
        .map_err(|err| format!("nft listing failed to run: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "nft listing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let json =
        std::str::from_utf8(&output.stdout).map_err(|err| format!("non-utf8 nft json: {err}"))?;
    nftables::parse_owned_table_identity(json).map_err(|err| format!("not an owned table: {err}"))
}
