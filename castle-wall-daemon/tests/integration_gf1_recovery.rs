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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use castle_wall_daemon::config::LinuxRuntimePaths;
use castle_wall_daemon::enforcement::{
    AcquiredComponent, ComponentHealth, ComponentKind, ComponentProvider, EnforcementError,
    EnforcementRuntime, EnforcementStartError, EnforcementStatus, NotReadyReason, StartupReadiness,
};
use castle_wall_daemon::nfqueue::NfqueueConfig;
use castle_wall_daemon::nftables::{self, SafetyNetAuditState, CASTLE_FAMILY, OWNER_MARKER_PREFIX};
use castle_wall_daemon::ownership_journal::{
    self as journal, JournalIdentity, OwnershipJournal, JOURNAL_SCHEMA_VERSION,
};
use castle_wall_daemon::protected_agent::owner;
use castle_wall_daemon::runtime_lock::HostRuntimeLock;
use castle_wall_daemon::runtime_providers::{
    acquire_castle_table_component_for_test, disarm_castle_runtime,
    force_next_reclaim_owned_probe_error_for_test, DisarmOutcome, LinuxRuntimeConfig,
    NFT_HEALTH_MIN_INTERVAL, RECOVERY_RETRY_INTERVAL,
};
use castle_wall_daemon::safety_net_uid::{
    validate_safety_net_uid, ConfinedUidSet, HostOverflowUid,
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
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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

/// Write an `Owned` ownership journal for THIS boot, the durable state a
/// successful acquisition leaves behind. `marker`/`table_handle`/
/// `base_chain_handle` may be arbitrary: D3's `ReclaimOwned` arm probes the LIVE
/// table's shape (is it this daemon's safety net?) before it ever trusts this
/// record's own handles against a real inventory, so a case that only needs the
/// safety-net branch (cases (a), (f)) never reaches the point where these values
/// would have to be real; a case that needs the ordinary-reclaim branch (case
/// (b)) supplies a live table whose actual handles will not match these anyway,
/// which is the point of that case.
fn write_owned_journal(
    cfg: &LinuxRuntimeConfig,
    marker: &str,
    table_handle: u64,
    base_chain_handle: u64,
) {
    write_owned_journal_with_history(cfg, marker, table_handle, base_chain_handle, Some(vec![]));
}

fn write_owned_journal_with_history(
    cfg: &LinuxRuntimeConfig,
    marker: &str,
    table_handle: u64,
    base_chain_handle: u64,
    confined: Option<Vec<journal::ConfinedIdentity>>,
) {
    let key = journal::load_or_generate_auth_key(&cfg.journal_key_path)
        .expect("load/generate the journal MAC key");
    let identity = JournalIdentity {
        schema_version: JOURNAL_SCHEMA_VERSION,
        marker: marker.to_string(),
        boot_id: journal::current_boot_id().expect("boot id"),
        source: journal::current_source(),
    };
    let record = match confined {
        Some(entries) => OwnershipJournal::owned_with_known_history(
            identity,
            table_handle,
            base_chain_handle,
            entries,
        )
        .expect("valid known history"),
        None => {
            OwnershipJournal::owned_with_unknown_history(identity, table_handle, base_chain_handle)
        }
    };
    journal::store_atomic(&cfg.journal_path, &record, &key)
        .expect("durably record the Owned journal");
}

/// Run a multi-statement nft script via `-f -` (stdin), mirroring the
/// production `run_nft_stdin` transaction style so the near-net-drift fixtures
/// below (D2, PR-2 packet case (h)) are built the same way the daemon itself
/// builds tables, rather than through a sequence of separately-argv'd `nft`
/// invocations that cannot express a `{ comment "..." ; }` table block cleanly.
fn nft_script(script: &str) -> bool {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = match Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let wrote = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(script.as_bytes()).is_ok())
        .unwrap_or(false);
    wrote && child.wait().map(|s| s.success()).unwrap_or(false)
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
    // PR-1: the scope is a typed argument now; this leg drives the v1 host-wide shape, which is what the base installed.
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("arm the deny-all net");
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    // --disarm must recognize its own net for an interrupted acquisition, delete
    // it, confirm absence, and clear the record: SafetyNetCleared (D3; renamed
    // from StaleRecordCleared now that `disarm_recover_deny_all_net` is also
    // reachable from `ReclaimOwned`, where "a stale record" would be the wrong
    // description), not a wedge. Packet test case (c).
    let outcome = disarm_castle_runtime(&cfg).expect("disarm must RECOVER, not wedge");
    assert_eq!(outcome, DisarmOutcome::SafetyNetCleared);
    assert!(
        !nftables::table_exists().unwrap(),
        "disarm must leave no live table"
    );
    assert!(
        !cfg.journal_path.exists(),
        "disarm must clear the interrupted ownership record"
    );
}

// D3 fix round: the same shared requirement proven at the `FinalizeInterrupted`
// (Preparing) recovery site as `gf1_h1_zero_rule_non_owner_table_comment_refused`
// proves at the `ReclaimOwned` site: a live table's comment key must be absent,
// read from the same inventory the recognizer parses, before disarm treats it as
// this daemon's own safety net. A zero-rule `policy drop` table carrying a table
// comment routes to the existing marker-mismatch refusal instead.
#[test]
fn gf1_finalize_interrupted_zero_rule_non_owner_table_comment_refused() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());
    let table = isolation::table();

    write_preparing_journal(&cfg);
    let script = format!(
        "add table {CASTLE_FAMILY} {table} {{ comment \"not-ours\" ; }}\n\
         add chain {CASTLE_FAMILY} {table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n"
    );
    assert!(nft_script(&script), "fixture setup must succeed");

    let err = disarm_castle_runtime(&cfg).expect_err("a commented table must refuse");
    assert!(nftables::table_exists().unwrap(), "must be retained: {err}");
    assert!(cfg.journal_path.exists(), "journal must be retained: {err}");
}

// D3 case (a): a same-boot `Owned` journal record whose live table is this
// daemon's own safety net: disarm recognises the net, deletes it by name,
// verifies absence and clears the record, returning `SafetyNetCleared`.
// Fail-before: on the base this case returned a refusal and retained both the
// table and the record (register id
// `defect.linux-disarm-cannot-clear-own-safety-net-01`).
#[test]
fn gf1_owned_journal_plus_this_daemons_net_clears_as_safety_net() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // Any marker/handles: the safety-net branch is reached from the LIVE
    // table's shape, never from these journal-recorded values.
    write_owned_journal(&cfg, "any-marker-disarm-must-not-trust-yet", 1, 2);
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("arm the safety net");
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    let outcome = disarm_castle_runtime(&cfg).expect("disarm must recover the safety net");
    assert_eq!(outcome, DisarmOutcome::SafetyNetCleared);
    assert!(
        !nftables::table_exists().unwrap(),
        "disarm must leave no live table"
    );
    assert!(
        !cfg.journal_path.exists(),
        "disarm must clear the Owned record"
    );
}

// D3 case (b): an `Owned` journal record whose live table is a genuinely
// DIFFERENT owned wall (`policy accept`, a foreign marker and foreign handles),
// never this daemon's safety net. The new probe this PR-2 adds must say "not the
// net" and fall through to the UNCHANGED exact-inventory re-validation, which
// then refuses on the handle/marker mismatch exactly as it did before this
// change -- the existing drift behavior, not a new one.
#[test]
fn gf1_owned_journal_plus_drifted_accept_table_still_refuses() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // The journal names a marker/handles this live table will not carry.
    write_owned_journal(
        &cfg,
        &format!("{OWNER_MARKER_PREFIX}{}", "c".repeat(32)),
        999_001,
        999_002,
    );
    let live_marker = format!("{OWNER_MARKER_PREFIX}{}", "d".repeat(32));
    nftables::create_castle_table_exclusive(&live_marker).expect("create a drifted accept table");
    assert!(
        !nftables::live_table_is_deny_all_safety_net().unwrap(),
        "a policy-accept owned table is never mistaken for the safety net"
    );

    let err = disarm_castle_runtime(&cfg).expect_err("a drifted table must still refuse");
    assert!(
        err.to_string()
            .contains("no longer matches the owned identity"),
        "the existing drift refusal text must be unchanged: {err}"
    );
    assert!(
        nftables::table_exists().unwrap(),
        "the drifted table must be retained, never deleted by name"
    );
    assert!(
        cfg.journal_path.exists(),
        "the journal must be retained on a refusal"
    );
}

// D3 case (f): a same-boot legacy `Owned` record whose `confined` key is absent
// plus the v1 host-wide safety net: still cleared. PR-1's never-adopt rule for
// a legacy record (D1b step 6) lives in the
// ACQUISITION path (`journal::decide`'s callers there), not in the shared
// `decide` function disarm also calls, so a legacy record must keep reaching
// THIS arm and being cleared. MUST MATCH the acquisition-specific gate PR-1
// keeps around `ReclaimDecision::ReclaimOwned` in `ownership_journal.rs` /
// `runtime_providers.rs`'s acquisition path (memo D3): if a future change makes
// `decide` itself divert a legacy record away from `ReclaimOwned` for every
// caller, this test starts failing and is the tripwire for that regression.
#[test]
fn gf1_legacy_owned_record_plus_v1_net_still_clears() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    write_owned_journal_with_history(&cfg, "legacy-record-no-confined-field", 1, 2, None);
    let key = journal::load_or_generate_auth_key(&cfg.journal_key_path).expect("journal key");
    let record = journal::load(&cfg.journal_path, Some(&key))
        .expect("read legacy record")
        .expect("legacy record exists");
    assert_eq!(record.confined(), None, "the key must remain absent");
    assert!(
        !String::from_utf8(std::fs::read(&cfg.journal_path).unwrap())
            .unwrap()
            .contains("\"confined\""),
        "legacy fixture must omit the confined key"
    );
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("arm the v1 host-wide safety net");
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    let outcome = disarm_castle_runtime(&cfg).expect("a legacy record must still clear");
    assert_eq!(outcome, DisarmOutcome::SafetyNetCleared);
    assert!(!nftables::table_exists().unwrap());
    assert!(!cfg.journal_path.exists());
}

// D3 case (g): the probe-error branch, driven through the PRODUCTION
// `disarm_castle_runtime` path via the `test-isolation`-only force-error
// override (a live-nft integration test cannot make a real probe fail on
// demand without a broken `nft` binary on the runner, so this seam exists
// solely to drive that one branch of the real code, not a substitute for it).
// The classifier's own branch logic is additionally unit-tested in isolation
// by `runtime_providers::tests::reclaim_owned_arm_probe_error_refuses_
// without_guessing`.
#[test]
fn gf1_reclaim_owned_probe_error_refuses_and_retains() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    write_owned_journal(&cfg, "reclaim-owned-probe-error-fixture", 1, 2);
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("arm the safety net");
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    // Bound, not discarded: the returned guard must outlive the disarm call it
    // covers, and its `Drop` clears the latch afterward so a later, unrelated
    // test's `ReclaimOwned` probe never inherits a forced failure this test
    // armed.
    let _forced_probe_error = force_next_reclaim_owned_probe_error_for_test();
    let err = disarm_castle_runtime(&cfg).expect_err("a forced probe error must refuse");
    assert!(
        nftables::table_exists().unwrap(),
        "the table must be retained: {err}"
    );
    assert!(
        cfg.journal_path.exists(),
        "the journal must be retained: {err}"
    );
}

// D3 case (h), fixtures 2-4 (near-net drift THAT CARRIES A RULE): the
// recognizer's shape acceptance is exact (rule count, order, and every rule's
// comment), so a complete v2 three-rule table with one comment altered, the
// same three rules plus a fourth, or only the first of the three, are ALL
// "not the net", and disarm must fall through to the unchanged exact-inventory
// refusal exactly as case (b) does.
#[test]
fn gf1_near_net_drift_with_a_rule_still_refuses() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let table = isolation::table();

    // h2: the COMPLETE v2 three-rule shape (D1's exact transaction text, the
    // same shape the (d)/(e) fixture installs), with ONLY rule 1's comment
    // altered; rules 2 and 3 keep their correct text.
    let wrong_rule_comment = format!(
        "add table {CASTLE_FAMILY} {table}\n\
         add chain {CASTLE_FAMILY} {table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n\
         add rule {CASTLE_FAMILY} {table} output meta skuid {{ 60123, 60124 }} drop \
         comment \"not-the-real-comment\"\n\
         add rule {CASTLE_FAMILY} {table} output icmpv6 type \
         {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept \
         comment \"sanctuary-castle-net:v2:kernel-nd\"\n\
         add rule {CASTLE_FAMILY} {table} output meta skuid != {{ 60123, 60124 }} accept \
         comment \"sanctuary-castle-net:v2:other-principals\"\n"
    );
    // h3: the correct v2 three rules plus a FOURTH, spurious rule.
    let extra_rule = format!(
        "add table {CASTLE_FAMILY} {table}\n\
         add chain {CASTLE_FAMILY} {table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n\
         add rule {CASTLE_FAMILY} {table} output meta skuid {{ 60123, 60124 }} drop \
         comment \"sanctuary-castle-net:v2:confined-identity\"\n\
         add rule {CASTLE_FAMILY} {table} output icmpv6 type \
         {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept \
         comment \"sanctuary-castle-net:v2:kernel-nd\"\n\
         add rule {CASTLE_FAMILY} {table} output meta skuid != {{ 60123, 60124 }} accept \
         comment \"sanctuary-castle-net:v2:other-principals\"\n\
         add rule {CASTLE_FAMILY} {table} output tcp dport 22 accept comment \"extra\"\n"
    );
    // h4: the one-rule shape (D1 never installs this: only zero rules or all
    // three at once).
    let one_rule = format!(
        "add table {CASTLE_FAMILY} {table}\n\
         add chain {CASTLE_FAMILY} {table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n\
         add rule {CASTLE_FAMILY} {table} output meta skuid {{ 60123, 60124 }} drop \
         comment \"sanctuary-castle-net:v2:confined-identity\"\n"
    );

    for (label, script) in [
        ("h2 wrong rule comment", wrong_rule_comment),
        ("h3 extra rule", extra_rule),
        ("h4 one-rule shape", one_rule),
    ] {
        let policy_dir = tempfile::tempdir().unwrap();
        let paths = isolation::runtime_paths();
        let cfg = config(&paths, policy_dir.path());
        write_owned_journal(&cfg, "near-net-drift-fixture", 1, 2);
        assert!(nft_script(&script), "{label}: fixture setup must succeed");
        assert!(
            !nftables::live_table_is_deny_all_safety_net().unwrap(),
            "{label}: a drifted rule shape is not this daemon's safety net"
        );

        let err = disarm_castle_runtime(&cfg).expect_err(&format!("{label}: must refuse"));
        assert!(
            nftables::table_exists().unwrap(),
            "{label}: the drifted table must be retained: {err}"
        );
        assert!(
            cfg.journal_path.exists(),
            "{label}: the journal must be retained: {err}"
        );

        // Clean up so the next fixture in this loop starts from an absent table
        // (guard() only resets state on the NEXT test's entry, and this test
        // drives three fixtures through one guard).
        let _ = Command::new("nft")
            .args(["delete", "table", CASTLE_FAMILY, table])
            .output();
        let _ = std::fs::remove_file(&cfg.journal_path);
    }
}

// D3 case (h), fixture 1: a zero-rule `policy drop` table that carries a table
// comment. The disarm `ReclaimOwned` arm requires the live table's comment key
// to be absent, read from the same inventory the recognizer parses, before it
// treats the table as this daemon's own safety net (D1 installs the net with
// no table comment at all); a present comment routes to the ordinary reclaim
// path instead, which refuses and retains on this table's mismatched identity.
#[test]
fn gf1_h1_zero_rule_non_owner_table_comment_refused() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());
    let table = isolation::table();

    write_owned_journal(&cfg, "near-net-drift-h1", 1, 2);
    let script = format!(
        "add table {CASTLE_FAMILY} {table} {{ comment \"not-ours\" ; }}\n\
         add chain {CASTLE_FAMILY} {table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n"
    );
    assert!(nft_script(&script), "fixture setup must succeed");

    let err = disarm_castle_runtime(&cfg).expect_err("a non-owner-commented table must refuse");
    assert!(nftables::table_exists().unwrap(), "must be retained: {err}");
    assert!(cfg.journal_path.exists(), "journal must be retained: {err}");
}

// D3(d/e): a known Owned journal and PR-1's installed three-rule identity net
// are classified by the live shape. The authenticated history is checked as a
// fixture precondition, then disarm's clearing outcome is checked separately.
fn assert_owned_journal_v2_net_clears(confined_uids: &[u32], expect_journal_mismatch: bool) {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());
    let confined: Vec<_> = confined_uids
        .iter()
        .map(|&uid| journal::ConfinedIdentity {
            uid,
            role: journal::ConfinedRole::Agent,
        })
        .collect();
    write_owned_journal_with_history(&cfg, "v2-net-known-history", 1, 2, Some(confined.clone()));
    let key = journal::load_or_generate_auth_key(&cfg.journal_key_path).expect("journal key");
    let record = journal::load(&cfg.journal_path, Some(&key))
        .expect("read known history")
        .expect("record exists");
    assert_eq!(record.confined(), Some(confined.as_slice()));
    let scope = identity_scope(&[60123, 60124]);
    let recorded_uids: Vec<_> = record
        .confined()
        .unwrap()
        .iter()
        .map(|entry| entry.uid)
        .collect();
    if expect_journal_mismatch {
        assert_ne!(
            recorded_uids,
            scope.denied_uids(),
            "D3(e) requires distinct known sets"
        );
    } else {
        assert_eq!(recorded_uids, scope.denied_uids());
    }
    nftables::install_deny_all_safety_net(&scope).expect("arm the three-rule identity net");
    assert_eq!(live_rule_comments_in_order().len(), 3);
    assert!(nftables::live_table_is_deny_all_safety_net().unwrap());

    let outcome = disarm_castle_runtime(&cfg).expect("disarm must recover the v2 safety net");
    assert_eq!(outcome, DisarmOutcome::SafetyNetCleared);
    assert!(!nftables::table_exists().unwrap());
    assert!(!cfg.journal_path.exists());
}

#[test]
fn gf1_owned_journal_plus_v2_net_clears_as_safety_net() {
    assert_owned_journal_v2_net_clears(&[60123, 60124], false);
}

// D3(e): a present, known authenticated array differs from the live net's
// {60123, 60124} deny set. Shape recognition, not journal-set equality, decides
// whether this explicit disarm removes the net.
#[test]
fn gf1_v2_net_with_different_known_journal_array_still_clears() {
    assert_owned_journal_v2_net_clears(&[60125], true);
}

/// The live isolated table as `nft -j` JSON, or None when absent.
fn live_table_json() -> Option<String> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// The ordered `comment` of every rule in the live base output chain.
fn live_rule_comments_in_order() -> Vec<String> {
    let Some(json) = live_table_json() else {
        return Vec::new();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&json) else {
        return Vec::new();
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.get("rule"))
        .filter_map(|rule| rule.get("comment").and_then(|c| c.as_str()))
        .map(str::to_string)
        .collect()
}

/// Build an `Identity` scope through the ONLY admitted constructor path: validate
/// each uid against this host's configured overflow value, then collect.
fn identity_scope(uids: &[u32]) -> nftables::SafetyNetScope {
    let overflow = HostOverflowUid::from_host().expect("a Linux host exposes kernel.overflowuid");
    let validated: Vec<_> = uids
        .iter()
        .map(|&uid| validate_safety_net_uid(uid, overflow).expect("an attestable uid"))
        .collect();
    nftables::SafetyNetScope::Identity(
        ConfinedUidSet::from_validated(validated).expect("a non-empty set"),
    )
}

// D1/D2 on real nft: an `Identity` scope installs exactly the three rules, IN
// ORDER, under a `drop` base policy, and the recogniser reads its own output back.
#[test]
fn identity_scope_installs_three_ordered_rules_and_is_recognised() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    nftables::install_deny_all_safety_net(&identity_scope(&[60123, 60124]))
        .expect("install the identity net");

    // The base policy still DROPS, so anything the three rules do not match falls
    // closed. This is what makes rule 2's carve-out necessary rather than cosmetic.
    assert_eq!(live_base_policy().as_deref(), Some("drop"));

    // ORDER is the invariant: the confined identity is dropped FIRST, so no later
    // accept is reachable by a packet the kernel can attribute to it.
    assert_eq!(
        live_rule_comments_in_order(),
        vec![
            nftables::NET_RULE_COMMENT_IDENTITY.to_string(),
            nftables::NET_RULE_COMMENT_KERNEL_ND.to_string(),
            nftables::NET_RULE_COMMENT_OTHERS.to_string(),
        ]
    );

    // The recogniser reads back the exact shape the installer emitted. Producer and
    // consumer are proven against ONE kernel listing here, which a fixture written
    // on a host without nft cannot do.
    assert!(
        nftables::live_table_is_deny_all_safety_net().expect("probe the live table"),
        "the installer's own output must be recognised as this daemon's net"
    );
}

// The host-wide shape on real nft: zero rules under the same drop policy, and it is
// recognised as the net's other permanent shape.
#[test]
fn host_wide_scope_installs_no_rules_and_is_recognised() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("install the host-wide net");
    assert_eq!(live_base_policy().as_deref(), Some("drop"));
    assert!(live_rule_comments_in_order().is_empty());
    assert!(nftables::live_table_is_deny_all_safety_net().expect("probe the live table"));
}

/// Resolve a scope the way the daemon does, from the three sources, so a leg exercises
/// the RESOLVER rather than a scope composed by the test.
fn resolved_scope(
    history: &[(u32, journal::ConfinedRole)],
    admitted: Option<(u32, Option<u32>)>,
    live: &[u32],
) -> castle_wall_daemon::runtime_providers::SafetyNetResolution {
    let overflow = HostOverflowUid::from_host().expect("a Linux host exposes kernel.overflowuid");
    let entries: Vec<journal::ConfinedIdentity> = history
        .iter()
        .map(|&(uid, role)| journal::ConfinedIdentity { uid, role })
        .collect();
    castle_wall_daemon::runtime_providers::resolve_safety_net_scope(
        &castle_wall_daemon::runtime_providers::ConfinedHistory::Known(entries),
        admitted,
        &nftables::LiveTableBindings::Bindings(live.to_vec()),
        overflow,
    )
}

// FAIL-BEFORE: with an identity KNOWN, history known and the deny set within the cap,
// the installed table names that identity and is never the zero-rule shape. The scope
// comes from `resolve_safety_net_scope`, so this leg fails on a build whose resolver
// cannot produce an identity scope, rather than passing because the test handed the
// installer one.
#[test]
fn a_within_cap_identity_resolves_and_never_installs_the_zero_rule_shape() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    // Sources: (a) the journal names 60123, (b) the manifest names 60124 with a gate,
    // (c) the live table contributes 60126.
    let resolution = resolved_scope(
        &[(60123, journal::ConfinedRole::Agent)],
        Some((60124, Some(60125))),
        &[60126],
    );
    assert_eq!(
        resolution.reason,
        nftables::SafetyNetReason::Identity,
        "a known identity within the cap must resolve to the identity reason"
    );
    assert_eq!(
        resolution.scope.denied_uids(),
        vec![60123, 60124, 60125, 60126],
        "the deny set is the union of all three sources"
    );
    // The KILL set excludes the live-table uid.
    assert_eq!(resolution.kill_set, vec![60123, 60124, 60125]);

    nftables::install_deny_all_safety_net(&resolution.scope).expect("install the resolved net");
    let comments = live_rule_comments_in_order();
    assert_eq!(
        comments.len(),
        3,
        "a known identity within the cap installs the three-rule shape, never the \
         zero-rule shape: {comments:?}"
    );
    assert_eq!(live_base_policy().as_deref(), Some("drop"));
    assert!(nftables::live_table_is_deny_all_safety_net().expect("probe"));
}

// A known-empty journal is a present history key. The resolver carries both
// the admitted and the live-table identities into the installed predicate.
#[test]
fn known_empty_history_installs_the_resolved_identity_scope() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let resolution = resolved_scope(&[], Some((60124, None)), &[60123]);
    assert_eq!(resolution.scope.denied_uids(), vec![60123, 60124]);
    nftables::install_deny_all_safety_net(&resolution.scope).expect("install resolved scope");
    assert_eq!(live_rule_comments_in_order().len(), 3);
    assert!(nftables::live_table_is_deny_all_safety_net().expect("probe installed scope"));
}

// An absent history key selects the host-wide shape. Installation must not
// rewrite the authenticated journal or turn that absence into a known history.
#[test]
fn absent_history_key_installs_the_resolved_host_wide_scope_without_a_store() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let dir = tempfile::tempdir().expect("isolated journal directory");
    let path = dir.path().join("ownership.json");
    let key_path = dir.path().join("ownership.key");
    let key = journal::load_or_generate_auth_key(&key_path).expect("journal key");
    let record = OwnershipJournal::owned_with_unknown_history(
        JournalIdentity {
            schema_version: JOURNAL_SCHEMA_VERSION,
            marker: format!("{OWNER_MARKER_PREFIX}{}", "a".repeat(32)),
            boot_id: journal::current_boot_id().expect("boot id"),
            source: journal::current_source(),
        },
        2,
        1,
    );
    journal::store_atomic(&path, &record, &key).expect("store unknown history");
    let before = std::fs::read(&path).expect("read journal before install");
    let reloaded = journal::load(&path, Some(&key)).unwrap().unwrap();
    assert_eq!(reloaded.confined(), None);
    let resolution = castle_wall_daemon::runtime_providers::resolve_safety_net_scope(
        &castle_wall_daemon::runtime_providers::ConfinedHistory::Unknown,
        Some((60124, None)),
        &nftables::LiveTableBindings::Bindings(vec![60123]),
        HostOverflowUid::from_host().expect("host overflow uid"),
    );
    assert_eq!(resolution.scope, nftables::SafetyNetScope::HostWide);
    nftables::install_deny_all_safety_net(&resolution.scope).expect("install resolved scope");
    assert!(live_rule_comments_in_order().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        journal::load(&path, Some(&key))
            .unwrap()
            .unwrap()
            .confined(),
        None
    );
}

// OVER CAPACITY: a 257-entry union resolves to the zero-rule host-wide shape with the
// over-capacity reason, and the INSTALLED table is that shape. Nothing is truncated:
// a truncated set would stop denying whichever uid fell off the end.
#[test]
fn an_over_capacity_union_installs_the_zero_rule_shape_with_the_over_capacity_reason() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let over: Vec<u32> = (0..=nftables::DENY_SET_MAX as u32)
        .map(|i| 60_000 + i)
        .collect();
    assert_eq!(over.len(), nftables::DENY_SET_MAX + 1);
    let resolution = resolved_scope(&[], None, &over);
    match resolution.reason {
        nftables::SafetyNetReason::DenySetOverCapacity { count, cap } => {
            assert_eq!(count, nftables::DENY_SET_MAX + 1);
            assert_eq!(cap, nftables::DENY_SET_MAX);
        }
        other => panic!("expected the over-capacity reason, got {other:?}"),
    }
    assert_eq!(resolution.scope, nftables::SafetyNetScope::HostWide);
    // The full union is still CARRIED, so a later recompute in the same process cannot
    // narrow below what this one knew.
    assert_eq!(resolution.deny_union.len(), nftables::DENY_SET_MAX + 1);

    nftables::install_deny_all_safety_net(&resolution.scope).expect("install the host-wide net");
    assert_eq!(live_base_policy().as_deref(), Some("drop"));
    assert!(
        live_rule_comments_in_order().is_empty(),
        "the over-capacity resolution installs the zero-rule shape"
    );
    assert!(nftables::live_table_is_deny_all_safety_net().expect("probe"));
    // And the refusal an operator reads names the count, the cap and that operator
    // access is not preserved on this path.
    let sentence = nftables::safety_net_scope_sentence(&resolution.scope, &resolution.reason);
    assert!(
        sentence.contains("deny set over capacity (257 of 256)"),
        "{sentence}"
    );
    assert!(sentence.contains("operator access is not preserved on this path"));
}

// The cap's upper boundary on the target nft: DENY_SET_MAX distinct skuid values
// install and are recognised, so the constant is proven on the platform rather than
// assumed. One over the cap is resolved to the host-wide shape by the resolver,
// which is unit-tested; this leg proves the kernel accepts the set AT the cap.
#[test]
fn a_full_cap_identity_set_installs_and_is_recognised_on_the_target_nft() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let uids: Vec<u32> = (0..nftables::DENY_SET_MAX as u32)
        .map(|i| 60_000 + i)
        .collect();
    nftables::install_deny_all_safety_net(&identity_scope(&uids))
        .expect("nft must accept a full-cap anonymous set in both rules");
    assert_eq!(live_base_policy().as_deref(), Some("drop"));
    assert_eq!(live_rule_comments_in_order().len(), 3);
    assert!(
        nftables::live_table_is_deny_all_safety_net().expect("probe the live table"),
        "a full-cap set must still be recognised, in both the == and the != rule"
    );
}

// The PROBE the parser rests on: record the JSON forms `nft -j` actually renders for
// the set-valued `==` skuid match, the set-valued `!=` skuid match and the
// `icmpv6 type` set, on the target nft.
//
// This test is the evidence for the parser's shape assumptions. It is written to
// FAIL LOUDLY with the observed JSON if any form differs from what the parser reads,
// so the recorded forms come from a kernel rather than from a fixture composed on a
// host that has no nft.
#[test]
fn nft_set_json_forms_are_the_shapes_the_parser_reads() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let uids: Vec<u32> = (0..nftables::DENY_SET_MAX as u32)
        .map(|i| 60_000 + i)
        .collect();
    nftables::install_deny_all_safety_net(&identity_scope(&uids)).expect("install");
    let json = live_table_json().expect("list the live table");
    // SAFETY: stderr is this test's evidence channel. The recorded forms are the
    // artifact the parser's shape assumptions rest on, so they are emitted whether
    // the assertions pass or fail.
    eprintln!("RECORDED nft -j listing for the identity net:\n{json}");

    let doc: serde_json::Value = serde_json::from_str(&json).expect("nft -j parses");
    let items = doc["nftables"].as_array().expect("an nftables array");
    let rules: Vec<&serde_json::Value> = items.iter().filter_map(|item| item.get("rule")).collect();
    assert_eq!(rules.len(), 3, "three rules: {json}");

    // Rule 1: a set-valued `==` on `meta skuid`, with INTEGER members (nft renders
    // uids as integers without `-u`), and a bare `drop` verdict object.
    let m1 = &rules[0]["expr"][0]["match"];
    assert_eq!(m1["op"], "==", "rule 1 op: {json}");
    assert_eq!(m1["left"]["meta"]["key"], "skuid", "rule 1 left: {json}");
    let set1 = m1["right"]["set"]
        .as_array()
        .expect("rule 1 right is a set");
    assert_eq!(
        set1.len(),
        nftables::DENY_SET_MAX,
        "rule 1 set size: {json}"
    );
    assert!(
        set1.iter().all(|m| m.is_u64()),
        "rule 1 set members must render as integers: {json}"
    );
    assert!(
        rules[0]["expr"][1].get("drop").is_some(),
        "rule 1 verdict: {json}"
    );

    // Rule 2: the `icmpv6 type` SET form. The parser tolerates a leading protocol
    // dependency match that nft may add for an inet-family ICMPv6 match, so the
    // recorded expression list is emitted above for exactly this reason.
    let nd_exprs = rules[1]["expr"].as_array().expect("rule 2 expr");
    let nd_match = nd_exprs
        .iter()
        .filter_map(|e| e.get("match"))
        .find(|m| m["left"].get("payload").is_some())
        .expect("rule 2 carries an icmpv6 payload match");
    assert_eq!(nd_match["left"]["payload"]["protocol"], "icmpv6");
    assert_eq!(nd_match["left"]["payload"]["field"], "type");
    let nd_set = nd_match["right"]["set"]
        .as_array()
        .expect("rule 2 right is a set");
    assert_eq!(nd_set.len(), 3, "exactly the three ND types: {json}");
    assert!(
        nd_set.iter().all(|m| m.is_string()),
        "icmpv6 type set members render as symbolic names: {json}"
    );

    // Rule 3: the set-valued `!=` form, over the SAME set as rule 1.
    let m3 = &rules[2]["expr"][0]["match"];
    assert_eq!(m3["op"], "!=", "rule 3 op: {json}");
    assert_eq!(m3["left"]["meta"]["key"], "skuid", "rule 3 left: {json}");
    let set3 = m3["right"]["set"]
        .as_array()
        .expect("rule 3 right is a set");
    assert_eq!(set1, set3, "the two sets must be equal: {json}");

    // And the recogniser accepts the listing it just produced, which is the whole
    // point of pinning the forms.
    assert!(nftables::live_table_is_deny_all_safety_net().expect("probe"));
}

// The sibling case the probe above never exercised: a ONE-uid identity net. The
// full-cap probe above only ever recorded the multi-member `{"set":[..]}` form,
// so nothing in CI installed a single-uid net and read it back on a real kernel
// before this case existed. This is the real-kernel witness for the collapse
// `skuid_right_members` (`castle-wall-daemon/src/nftables.rs`) reads: rule 1's
// `right` for exactly one denied uid renders as a BARE SCALAR, not
// `{"set":[N]}`, and the recogniser must still accept it as this daemon's own
// deny-all safety net.
#[test]
fn nft_set_json_forms_are_the_shapes_the_parser_reads_for_one_uid() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    nftables::install_deny_all_safety_net(&identity_scope(&[60123])).expect("install");
    let json = live_table_json().expect("list the live table");
    // SAFETY: stderr is this test's evidence channel, exactly as the sibling
    // full-cap probe above: the recorded form is the artifact the parser's
    // single-member shape assumption rests on.
    eprintln!("RECORDED nft -j listing for the one-uid identity net:\n{json}");

    let doc: serde_json::Value = serde_json::from_str(&json).expect("nft -j parses");
    let items = doc["nftables"].as_array().expect("an nftables array");
    let rules: Vec<&serde_json::Value> = items.iter().filter_map(|item| item.get("rule")).collect();
    assert_eq!(rules.len(), 3, "three rules: {json}");

    // Rule 1: the ONE-member collapse. `right` is the bare uid, with NO "set"
    // wrapper at all -- this is the exact shape `skuid_right_members` exists to
    // read, and the exact shape the module's array-only history never covered.
    let m1 = &rules[0]["expr"][0]["match"];
    assert_eq!(m1["op"], "==", "rule 1 op: {json}");
    assert_eq!(m1["left"]["meta"]["key"], "skuid", "rule 1 left: {json}");
    assert!(
        m1["right"].get("set").is_none(),
        "a one-member skuid set must NOT keep the \"set\" wrapper: {json}"
    );
    assert_eq!(
        m1["right"].as_u64(),
        Some(60123),
        "rule 1 right must be the bare scalar uid: {json}"
    );

    // Rule 3: the same collapse on the `!=` form, over the SAME uid as rule 1.
    let m3 = &rules[2]["expr"][0]["match"];
    assert_eq!(m3["op"], "!=", "rule 3 op: {json}");
    assert!(
        m3["right"].get("set").is_none(),
        "rule 3's one-member skuid set must NOT keep the \"set\" wrapper: {json}"
    );
    assert_eq!(
        m3["right"].as_u64(),
        m1["right"].as_u64(),
        "the two rules must name the same uid: {json}"
    );

    // And the recogniser accepts this real one-uid listing as its own deny-all
    // safety net -- the whole point of pinning this sibling form.
    assert!(
        nftables::live_table_is_deny_all_safety_net().expect("probe"),
        "a real one-uid net must be recognised as the safety net: {json}"
    );

    // The DIRECT witness for the confirmed defect, which is on the READER side:
    // `installed_net_rule_one_uids` (`integration_linux_runtime_activation.rs`)
    // records that reading only the `{"set":[..]}` array form "returned an
    // empty scope for a live one-uid net on the first privileged run of this
    // suite." `expectation` here is `NoneConfined`, which the safety-net
    // recognition branch of `live_table_uid_bindings` never reads, so this
    // exercises exactly source (c) of `resolve_safety_net_scope`, on the SAME
    // real kernel listing the recogniser assertion above just accepted.
    assert_eq!(
        nftables::live_table_uid_bindings(
            &json,
            &nftables::ExpectedAgentBinding::NoneConfined,
            HostOverflowUid::from_host().expect("a Linux host exposes kernel.overflowuid"),
        ),
        nftables::LiveTableBindings::Bindings(vec![60123]),
        "source (c) must read the live one-uid net's own uid, not an empty scope: {json}"
    );
}

// The by-name delete primitive on real nft: after it runs, no live castle table and
// therefore no live `policy accept` castle path remains.
//
// Its OWNER under Part A is the disarm verb's interrupted-acquisition recovery, which
// is explicit operator teardown where deleting the table is the intended outcome. The
// runtime-loss and reclaim-drift paths do NOT delete: they install the net and leave
// the table standing, which their own tests assert. This test covers the primitive,
// not those paths.
#[test]
fn by_name_delete_leaves_no_live_accept_table() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    // A live owned `policy accept` table (the drifted-table stand-in).
    let marker = format!("{OWNER_MARKER_PREFIX}{}", "b".repeat(32));
    nftables::create_castle_table_exclusive(&marker).expect("create an accept table");
    assert_eq!(live_base_policy().as_deref(), Some("accept"));

    // The primitive the disarm verb's recovery arm uses.
    nftables::force_delete_castle_table_by_name().expect("force-delete by name");
    assert!(
        !nftables::table_exists().unwrap(),
        "no live castle table (hence no `policy accept` path) may remain"
    );
    assert_eq!(live_base_policy(), None);
}

// GF1.3: an owned table deleted at runtime is detected as a completed loss, and the
// net goes into the kernel WITHOUT waiting for a restart.
//
// Part A splits that into two responsibilities, and this test pins both halves:
// `health()` is a REPORT, so it answers `Lost` and touches no kernel state; the
// POST-READY LOSS row's install belongs to the recovery controller, which the
// supervisor drives on a completed `Lost` proof before any exit arm. The operator-
// facing claim is unchanged and is what the final assertions state: runtime loss
// installs the net without waiting for a restart.
//
// FAIL-BEFORE NOTE: an earlier revision of this suite asked `health()` for the
// install. Under the current contract a health poll is a question, so the same
// outcome is now reached through the controller entry the supervisor actually calls.
#[test]
fn gf1_3_runtime_loss_installs_the_net_through_the_recovery_controller() {
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

    // 3) `health()` REPORTS the completed loss and installs NOTHING. Asserting the
    //    table is still absent immediately after the report is what proves the poll
    //    is a question rather than an action.
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
        !nftables::table_exists().unwrap(),
        "a health poll must install nothing: the table is still absent after the report"
    );

    // 4) Drive the production entry the supervisor uses on a completed Lost proof.
    //    No restart happens anywhere in this test.
    let in_force = component.attempt_post_ready_recovery(&|| false);
    assert!(
        in_force.holds_gate(),
        "the recovery controller must report the net in force after a completed loss"
    );

    // 5) The net is in the kernel, dropping by policy. This fixture is store-less, so
    //    no manifest names a confined identity and the journal's history is
    //    known-empty: the deny set is empty and the host-wide shape is the correct
    //    resolution, which the refusal texts and the audit row both name as its own
    //    reason.
    assert!(
        nftables::live_table_is_deny_all_safety_net().unwrap(),
        "runtime loss installs the net without waiting for a restart"
    );
    assert_eq!(
        live_base_policy().as_deref(),
        Some("drop"),
        "a non-allowlisted packet is dropped, never accepted, after the loss"
    );
    assert!(
        live_rule_comments_in_order().is_empty(),
        "with no confined identity recoverable the net is the zero-rule host-wide shape"
    );

    // 6) A second external loss WHILE Recovering must cause a second real
    //    transaction. The first successful install is not evidence that this
    //    externally deleted net remains in force. This was the reachable P1
    //    success-latch bug: it reported Installed but skipped this reinstall.
    let deleted_net = Command::new("nft")
        .args(["delete", "table", CASTLE_FAMILY, isolation::table()])
        .output()
        .expect("delete the first installed net");
    assert!(
        deleted_net.status.success(),
        "second external delete must succeed"
    );
    assert!(!nftables::table_exists().unwrap());
    assert_eq!(
        component.health(),
        ComponentHealth::Recovering,
        "the host lock owner stays in Recovering after its net is removed"
    );
    std::thread::sleep(RECOVERY_RETRY_INTERVAL + Duration::from_millis(100));
    let mut reinstalled = false;
    for _ in 0..8 {
        if component
            .attempt_post_ready_recovery(&|| false)
            .holds_gate()
        {
            reinstalled = true;
            break;
        }
        assert!(
            !nftables::table_exists().unwrap(),
            "an unavailable retry may not claim a net that is still absent"
        );
        std::thread::sleep(Duration::from_millis(600));
    }
    assert!(
        reinstalled,
        "the next eligible completed loss must execute a second install"
    );
    assert!(
        nftables::live_table_is_deny_all_safety_net().unwrap(),
        "the second install must restore the real isolated nft net"
    );
    assert_eq!(
        component.safety_net_audit_state().unwrap().tag(),
        "installed",
        "the audit claim follows the second actual successful transaction"
    );

    // 7) The controller observes the shutdown flag, so `systemctl stop` is a clean
    //    exit rather than a box that keeps re-arming while it is taken down.
    assert!(
        !component.attempt_post_ready_recovery(&|| true).holds_gate(),
        "a shutting-down daemon must not re-arm"
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
    // NoneConfined: these lifecycle tests wrap no agent, so a per-agent binding
    // in the table would be state this helper cannot vouch for and must refuse.
    nftables::parse_owned_table_identity(
        json,
        &castle_wall_daemon::nftables::ExpectedAgentBinding::NoneConfined,
    )
    .map_err(|err| format!("not an owned table: {err}"))
}

// ---------------------------------------------------------------------------
// The two STARTUP readiness rows of memo D1b step 7, and the EXCLUDED non-nftables
// loss, driven through the real `EnforcementRuntime::start` against real nft.
//
// Why a composed plan instead of the production one: `start`'s plan gate requires the
// advertised kinds to equal `ComponentKind::REQUIRED_IN_ORDER` exactly, and the property
// under test is what the two startup readiness checks do to the KERNEL when the nftables
// component's reading is not `Ready`. The FIRST provider is the real acquisition path
// through the `test-isolation` seam, so the component whose reading is read, whose
// responder runs, whose deny set is resolved and whose host lock is released is the
// production one. The later two providers stand in for NFQUEUE and the manifest watcher:
// they own no kernel object, and one of them is where the loss lands, which is exactly
// the window the whole-set re-check exists for (a later acquisition invalidating an
// earlier component).
// ---------------------------------------------------------------------------

/// Slack added to `NFT_HEALTH_MIN_INTERVAL` before a reading is expected to reflect a
/// kernel change. Absorbs sleep granularity only; it is not a retry budget and must
/// never be raised to make a fixture pass.
const READING_FRESHNESS_MARGIN: Duration = Duration::from_millis(100);

/// What the live table looked like at one moment, read straight from `nft`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveTableObservation {
    net_recognised: bool,
    base_policy: Option<String>,
}

fn observe_live_table() -> LiveTableObservation {
    LiveTableObservation {
        net_recognised: nftables::live_table_is_deny_all_safety_net().unwrap_or(false),
        base_policy: live_base_policy(),
    }
}

/// The real nftables table component, acquired through the production acquisition path.
///
/// `indeterminate_at_the_whole_set_check` wraps the acquired component in the scripted
/// decorator below; `None` leaves the production component exactly as it is.
struct RealNftTableProvider {
    cfg: LinuxRuntimeConfig,
    indeterminate_at_the_whole_set_check: Option<Arc<AtomicUsize>>,
}

impl ComponentProvider for RealNftTableProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::NftablesTable
    }

    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
        let component = acquire_castle_table_component_for_test(&self.cfg)?;
        match self.indeterminate_at_the_whole_set_check {
            None => Ok(component),
            Some(responder_calls) => Ok(Box::new(IndeterminateAtTheWholeSetCheck {
                inner: component,
                health_polls: AtomicUsize::new(0),
                responder_calls,
            })),
        }
    }
}

/// A stand-in for a component that owns no kernel egress object, with a readiness the
/// test scripts.
///
/// INVARIANT this stub must keep, and the reason it proves anything: it does NOT
/// override `on_startup_lost`, `on_startup_indeterminate` or
/// `attempt_post_ready_recovery`. The trait defaults are no-ops, which IS the contract
/// for every component but the nftables table, whose loss is the only one that can mean
/// adopted agents are live with no gate in the kernel. A stub that overrode them would
/// be asserting its own behaviour rather than the routing under test.
struct NonNftStubComponent {
    kind: ComponentKind,
    health: Arc<Mutex<ComponentHealth>>,
    /// Filled on this stub's `release`. Teardown runs in REVERSE acquisition order, so
    /// the last-acquired stub is released FIRST: an observation recorded here is taken
    /// before the nftables component's own release, which is how the leg proves the net
    /// reached the kernel ahead of the unwind rather than during it.
    observation: Option<Arc<Mutex<Vec<LiveTableObservation>>>>,
    released: bool,
}

impl AcquiredComponent for NonNftStubComponent {
    fn kind(&self) -> ComponentKind {
        self.kind
    }

    fn is_ready(&self) -> bool {
        matches!(self.health(), ComponentHealth::Ready)
    }

    fn health(&self) -> ComponentHealth {
        // A poisoned lock is recovered rather than unwrapped: `health` is reachable from
        // a teardown path that must not panic.
        *self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn release(&mut self) {
        if self.released {
            return; // idempotent, per the trait contract
        }
        if let Some(sink) = &self.observation {
            let mut sink = sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            sink.push(observe_live_table());
        }
        self.released = true;
    }
}

struct NonNftStubProvider {
    kind: ComponentKind,
    health: Arc<Mutex<ComponentHealth>>,
    observation: Option<Arc<Mutex<Vec<LiveTableObservation>>>>,
    /// Runs INSIDE `acquire`, which is the only place a test can act during the window
    /// between the nftables per-component check and the whole-set check.
    during_acquire: Option<Box<dyn FnOnce() + Send>>,
}

impl ComponentProvider for NonNftStubProvider {
    fn kind(&self) -> ComponentKind {
        self.kind
    }

    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
        let this = *self;
        if let Some(act) = this.during_acquire {
            act();
        }
        Ok(Box::new(NonNftStubComponent {
            kind: this.kind,
            health: this.health,
            observation: this.observation,
            released: false,
        }))
    }
}

/// The REAL nftables component with one scripted reading: the second health poll of a
/// start answers indeterminate.
///
/// Why scripted here and real in the loss leg: a COMPLETED negative proof is producible
/// from a test by deleting the table, so that row is driven end to end against the
/// kernel. An indeterminate reading is by definition the ABSENCE of an answer from the
/// bounded `nft` ownership proof, and a healthy kernel cannot be asked to withhold one on
/// demand. Everything else on this path is the production component: the responder that
/// runs, the kill set it resolves, the host lock it releases, and the table every
/// assertion reads back from the kernel.
///
/// The poll count is the script: poll one is the per-component check after acquisition
/// and delegates to the real proof, poll two is the whole-set check before `READY=1`.
/// `is_ready` delegates instead of routing through `health`, so a readiness query cannot
/// consume a scripted reading.
struct IndeterminateAtTheWholeSetCheck {
    inner: Box<dyn AcquiredComponent>,
    health_polls: AtomicUsize,
    responder_calls: Arc<AtomicUsize>,
}

impl AcquiredComponent for IndeterminateAtTheWholeSetCheck {
    fn kind(&self) -> ComponentKind {
        self.inner.kind()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    fn health(&self) -> ComponentHealth {
        if self.health_polls.fetch_add(1, Ordering::SeqCst) == 0 {
            return self.inner.health();
        }
        ComponentHealth::ProbeUnavailable
    }

    fn on_startup_lost(&self) {
        // Delegated rather than swallowed: if the routing ever sent an indeterminate
        // reading here, the production responder would run and the leg's kernel
        // assertions below would fail loudly instead of passing on a stub.
        self.inner.on_startup_lost();
    }

    fn on_startup_indeterminate(&self) {
        self.responder_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.on_startup_indeterminate();
    }

    fn attempt_post_ready_recovery(
        &self,
        shutting_down: &dyn Fn() -> bool,
    ) -> castle_wall_daemon::enforcement::PostReadyRecoveryResult {
        self.inner.attempt_post_ready_recovery(shutting_down)
    }

    fn safety_net_audit_state(&self) -> Option<SafetyNetAuditState> {
        self.inner.safety_net_audit_state()
    }

    fn release(&mut self) {
        self.inner.release();
    }
}

/// Leave an owned table and an `Owned` ownership record behind, the exact durable state
/// a previous daemon lifetime leaves: ordinary release drops the host lock ONLY, so both
/// survive for the next start to adopt.
fn leave_an_adopted_table(cfg: &LinuxRuntimeConfig) -> nftables::CastleTableOwnership {
    let first = acquire_castle_table_component_for_test(cfg).expect("fresh acquire an owned table");
    assert!(first.is_ready(), "the freshly owned table must read ready");
    drop(first);
    let adopted = live_owned_identity().expect("the released table is still owned");
    assert_eq!(
        live_base_policy().as_deref(),
        Some("accept"),
        "the preserved table is the wall, not the net"
    );
    adopted
}

// STARTUP LOST (memo D1b step 7): a COMPLETED negative ownership proof at the whole-set
// readiness check installs the net from the in-memory deny set BEFORE the unwind, returns
// the typed evidence, and leaves the host lock free for the disarm verb.
#[test]
fn a_startup_ownership_loss_installs_the_net_before_the_unwind_and_frees_the_host_lock() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    // The posture the row is about: an adopted table with the agents of a previous
    // lifetime potentially still live, which is why a proven loss here cannot simply
    // unwind and wait for a restart.
    let adopted = leave_an_adopted_table(&cfg);
    assert!(adopted.marker.starts_with(OWNER_MARKER_PREFIX));

    let observations = Arc::new(Mutex::new(Vec::new()));
    let providers: Vec<Box<dyn ComponentProvider>> = vec![
        Box::new(RealNftTableProvider {
            cfg: cfg.clone(),
            indeterminate_at_the_whole_set_check: None,
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::Nfqueue,
            health: Arc::new(Mutex::new(ComponentHealth::Ready)),
            observation: None,
            during_acquire: Some(Box::new(|| {
                // The loss: the adopted table goes away while a LATER component is being
                // acquired. The per-component check already passed, so this is the window
                // the whole-set re-check exists for.
                let deleted = Command::new("nft")
                    .args(["delete", "table", CASTLE_FAMILY, isolation::table()])
                    .output()
                    .expect("delete the adopted table");
                assert!(deleted.status.success(), "the external delete must succeed");
                // The ownership proof is rate-limited: a reading younger than
                // NFT_HEALTH_MIN_INTERVAL is served from the last completed check.
                // Waiting one whole interval past the delete bounds the age of any cached
                // reading below the time since the delete, so the whole-set check either
                // forks a fresh proof or serves one taken after it. Failure mode if this
                // is skipped: the check reads the PRE-DELETE table, `start` hands back a
                // ready runtime, and the row under test is never reached at all.
                std::thread::sleep(NFT_HEALTH_MIN_INTERVAL + READING_FRESHNESS_MARGIN);
            })),
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::ManifestWatcher,
            health: Arc::new(Mutex::new(ComponentHealth::Ready)),
            observation: Some(Arc::clone(&observations)),
            during_acquire: None,
        }),
    ];

    let err = EnforcementRuntime::start(providers)
        .expect_err("a proven startup ownership loss must refuse the start");
    match err {
        EnforcementStartError::Component {
            failed, evidence, ..
        } => {
            assert_eq!(
                failed,
                ComponentKind::NftablesTable,
                "the earliest casualty is the nftables table"
            );
            // The TYPED evidence is what lets a caller tell a completed negative proof
            // from a no-answer without re-deriving it from message text.
            assert_eq!(
                evidence,
                Some(StartupReadiness::Lost {
                    kind: ComponentKind::NftablesTable
                }),
                "the acquisition error must carry the typed loss reading"
            );
        }
        other => panic!("expected a component start failure, got {other:?}"),
    }

    // BEFORE `release`: the first component released during the reverse unwind already
    // saw the net in the kernel, dropping by policy.
    let observed = observations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(
        observed.len(),
        1,
        "exactly one release observation is recorded: {observed:?}"
    );
    assert!(
        observed[0].net_recognised,
        "the net must be in the kernel before the reverse-order unwind begins: {:?}",
        observed[0]
    );
    assert_eq!(
        observed[0].base_policy.as_deref(),
        Some("drop"),
        "a non-allowlisted packet is dropped, never accepted, from the moment the net is \
         installed: {:?}",
        observed[0]
    );
    drop(observed);

    // And it is still in force after the unwind: release drops the host lock only.
    assert!(
        nftables::live_table_is_deny_all_safety_net().expect("probe the live table"),
        "the net survives the teardown that returns the acquisition error"
    );
    assert_eq!(live_base_policy().as_deref(), Some("drop"));
    // This fixture is store-less, so no manifest names a confined identity and the
    // journal's history is known-empty: the empty deny set resolves to the host-wide
    // shape, which the refusal text and the audit row both name as their own reason.
    assert!(
        live_rule_comments_in_order().is_empty(),
        "with no confined identity recoverable the net is the zero-rule shape"
    );

    // The host lock is free, which is the disarm verb's precondition. `flock` is held per
    // open file description, so this acquisition genuinely fails if the refused start had
    // kept the lock.
    let mut lock = HostRuntimeLock::acquire(&cfg.lock_path)
        .expect("the host lock must be re-acquirable after a refused start");
    lock.release();
}

// STARTUP INDETERMINATE (memo D1b step 7), the sibling of the row above: an indeterminate
// reading at the same check installs NOTHING and leaves the adopted table exactly as it
// was. Absence of evidence is not evidence, and installing on it would replace a table
// that may be perfectly healthy.
#[test]
fn a_startup_indeterminate_reading_installs_nothing_and_leaves_the_adopted_table_as_it_was() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    let adopted = leave_an_adopted_table(&cfg);
    let responder_calls = Arc::new(AtomicUsize::new(0));
    let providers: Vec<Box<dyn ComponentProvider>> = vec![
        Box::new(RealNftTableProvider {
            cfg: cfg.clone(),
            indeterminate_at_the_whole_set_check: Some(Arc::clone(&responder_calls)),
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::Nfqueue,
            health: Arc::new(Mutex::new(ComponentHealth::Ready)),
            observation: None,
            during_acquire: None,
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::ManifestWatcher,
            health: Arc::new(Mutex::new(ComponentHealth::Ready)),
            observation: None,
            during_acquire: None,
        }),
    ];

    let err = EnforcementRuntime::start(providers)
        .expect_err("an indeterminate startup reading withholds readiness");
    match err {
        EnforcementStartError::Component {
            failed, evidence, ..
        } => {
            assert_eq!(failed, ComponentKind::NftablesTable);
            assert_eq!(
                evidence,
                Some(StartupReadiness::Indeterminate {
                    kind: ComponentKind::NftablesTable
                }),
                "an indeterminate reading must never be reported as a completed loss"
            );
        }
        other => panic!("expected a component start failure, got {other:?}"),
    }
    assert_eq!(
        responder_calls.load(Ordering::SeqCst),
        1,
        "the indeterminate responder runs exactly once, before the unwind"
    );

    // The table is exactly what it was: the same owned object, handles and marker
    // included, still the wall and never the net.
    assert_eq!(
        live_owned_identity().expect("the adopted table is still owned"),
        adopted,
        "an indeterminate reading installs nothing and replaces nothing"
    );
    assert_eq!(live_base_policy().as_deref(), Some("accept"));
    assert!(
        !nftables::live_table_is_deny_all_safety_net().expect("probe the live table"),
        "no net may be installed on absent evidence"
    );
    let mut lock = HostRuntimeLock::acquire(&cfg.lock_path)
        .expect("the host lock must be re-acquirable after a refused start");
    lock.release();
}

// The startup rows above also reach the DAEMON-SIDE STOP HOOK, which resolves a
// host-global tree of its own: the owner socket, the receipt pins, the daemon
// release log and the keys beside them. In a `test-isolation` binary that tree is
// this run's isolated root and nothing else, and the shipped hook entry point
// answers from it. Asserted beside the suites that drive the hook rather than in
// the crate's own unit tests, because `cfg(test)` and `--features test-isolation`
// are different build configurations and only this one links the library the way
// an integration binary does. No kernel privilege is involved, so this row runs
// wherever the suite runs.
#[test]
fn the_stop_hook_reads_only_this_runs_isolated_tree_in_a_test_isolation_binary() {
    let _suite = isolation::guard();
    let hook_tree =
        owner::resolved_hook_paths().expect("a test-isolation binary resolves the bound tree");
    for name in hook_tree.every_path() {
        assert!(
            name.starts_with(isolation::root()),
            "the stop hook must read nothing outside the bound tree: {name:?}"
        );
    }
    assert!(
        hook_tree.is_isolated_from_production(),
        "no name the hook resolves may be an installed one"
    );
    // The SHIPPED entry point is what the startup path calls. The bound socket
    // does not exist, so an answer at all is evidence that the name it looked
    // for was the bound one: an installed owner on this host would answer
    // differently, and the bound names stay absent afterwards.
    assert_eq!(
        owner::stop_failure_for_hook(&[1001], "post-ready ownership reading indeterminate", None),
        owner::OwnerOutcome::OwnerUnavailable
    );
    assert!(!hook_tree.socket.exists());
    assert!(!hook_tree.pins.exists());
    assert!(!hook_tree.release_log.exists());
}

// EXCLUDED from every install row (memo D1b step 7): a non-nftables component's
// post-READY loss. The kernel egress gate is intact, so nothing is installed and nothing
// is deleted; the daemon keeps today's exit-and-adopt path and the next start adopts the
// preserved table.
#[test]
fn a_post_ready_non_nftables_loss_keeps_the_table_and_the_next_start_adopts_it() {
    let _suite = isolation::guard();
    if !nft_available() {
        skip_or_fail_unprivileged("nft add/delete on the isolated table failed");
        return;
    }
    let policy_dir = tempfile::tempdir().unwrap();
    let paths = isolation::runtime_paths();
    let cfg = config(&paths, policy_dir.path());

    let nfqueue_health = Arc::new(Mutex::new(ComponentHealth::Ready));
    let providers: Vec<Box<dyn ComponentProvider>> = vec![
        Box::new(RealNftTableProvider {
            cfg: cfg.clone(),
            indeterminate_at_the_whole_set_check: None,
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::Nfqueue,
            health: Arc::clone(&nfqueue_health),
            observation: None,
            during_acquire: None,
        }),
        Box::new(NonNftStubProvider {
            kind: ComponentKind::ManifestWatcher,
            health: Arc::new(Mutex::new(ComponentHealth::Ready)),
            observation: None,
            during_acquire: None,
        }),
    ];

    let mut runtime =
        EnforcementRuntime::start(providers).expect("a fully ready plan reaches readiness");
    assert!(runtime.is_kernel_runtime_ready());
    let owned = live_owned_identity().expect("the started runtime owns a table");
    assert_eq!(live_base_policy().as_deref(), Some("accept"));

    // POST-READY: the non-nftables component proves ITS resource lost.
    *nfqueue_health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = ComponentHealth::Lost;

    // The supervisor's order, and both halves matter: every component reporting a
    // completed negative proof is offered one recovery attempt BEFORE any exit arm, then
    // the status is re-read. A component with no kernel gate of its own declines, so no
    // net is installed for it.
    assert!(
        !runtime
            .attempt_post_ready_recovery(&|| false, false)
            .holds_gate(),
        "a non-nftables loss must not put any gate in the kernel"
    );
    assert_eq!(
        runtime.status(),
        EnforcementStatus::NotReady {
            reason: NotReadyReason::ComponentLost(ComponentKind::Nfqueue)
        },
        "the loss withdraws readiness and names the component"
    );
    assert!(
        matches!(
            runtime.safety_net_audit_state(),
            SafetyNetAuditState::NotAttempted
        ),
        "no install was attempted, and the audit state must say so rather than claim a \
         protection"
    );
    assert!(
        !nftables::live_table_is_deny_all_safety_net().expect("probe the live table"),
        "the table is untouched by another component's loss"
    );
    assert_eq!(live_base_policy().as_deref(), Some("accept"));
    assert_eq!(
        live_owned_identity().expect("still owned"),
        owned,
        "no install and no delete: the same owned object stands"
    );

    // The exit path: reverse-order teardown, which drops the host lock and nothing else.
    runtime.shutdown();
    assert!(
        nftables::table_exists().unwrap(),
        "the table survives the exit"
    );
    assert_eq!(
        live_owned_identity().expect("owned after the exit"),
        owned,
        "fail-closed preservation: process exit deletes neither the table nor the record"
    );

    // And the next start ADOPTS it: the same handles and marker, never a fresh create.
    let readopted = acquire_castle_table_component_for_test(&cfg)
        .expect("a fresh start must adopt the preserved table");
    assert!(readopted.is_ready(), "the adopted table reads ready");
    assert_eq!(
        live_owned_identity().expect("owned after adoption"),
        owned,
        "adoption re-uses the preserved object rather than replacing it"
    );
    drop(readopted);
}
