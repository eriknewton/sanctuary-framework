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
    // PR-1: the scope is a typed argument now; this leg drives the v1 host-wide shape, which is what the base installed.
    nftables::install_deny_all_safety_net(&nftables::SafetyNetScope::HostWide)
        .expect("arm the deny-all net");
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
    let in_force = component.attempt_post_ready_recovery(false);
    assert!(
        in_force,
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

    // 6) The controller observes the shutdown flag, so `systemctl stop` is a clean
    //    exit rather than a box that keeps re-arming while it is taken down.
    assert!(
        !component.attempt_post_ready_recovery(true),
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
