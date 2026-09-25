//! Production Linux enforcement-runtime providers.
//!
//! These are the concrete [`ComponentProvider`]s the shipped daemon boots
//! through [`EnforcementRuntime::start`]. They acquire, in order:
//!
//! 1. nftables table ([`ComponentKind::NftablesTable`]) — takes the host-global
//!    ownership lock BEFORE any nftables call, then reads the durable, AUTHENTICATED
//!    ownership journal and live-table presence UNDER the lock and drives the
//!    crash-recovery state machine ([`crate::ownership_journal`]). With no live
//!    table it fresh-acquires (prepare → atomic fail-on-exists `create` → capture
//!    → finalize `Owned`); with a live table the journal proves is ours for this
//!    boot it RECLAIMS after re-verifying the exact identity; with a live table
//!    and no ownership proof it REFUSES, never adopting, mutating, or clobbering
//!    it. Its live readiness re-verifies the exact owned identity (handles +
//!    marker + pristine shape), so a same-shape delete/recreate or a mutation
//!    withdraws readiness.
//! 2. NFQUEUE ([`ComponentKind::Nfqueue`]) — opens and binds the kernel queue
//!    with FAIL_OPEN disabled on a worker thread, signals ready only after the
//!    bind succeeds, and turns health non-green the instant the verdict thread
//!    exits or panics ([`crate::thread_component`]).
//! 3. manifest watcher ([`ComponentKind::ManifestWatcher`]) — starts the
//!    inotify/poll watcher on a worker thread and drives `ManifestStore::reload`
//!    on each change, preserving the prior verified generation on an invalid
//!    reload (the store's F-2 behavior). A verified candidate is staged, durably
//!    authorized in the authenticated audit WAL, and only then committed live.
//!    The 2-second poll fallback validates the policy directory synchronously and
//!    is durably audited before bind succeeds. Any later watcher loss is fatal to
//!    component health so the systemd restart policy restores the capability.
//!
//! ## Fail-closed preservation of kernel state (blocker 1)
//!
//! Once the nftables table is acquired, ordinary userspace loss NEVER deletes it
//! or clears its ownership proof. The component's `release()` — which runs on
//! every ordinary shutdown, SIGTERM/systemd stop, readiness-notify failure,
//! partial-startup rollback, and Drop — releases ONLY the process-local host lock;
//! the owned table and its authenticated journal SURVIVE, so a restart adopts the
//! preserved object rather than re-creating it, and the durable proof persists.
//! Deletion happens ONLY through the separate, explicitly-named
//! [`disarm_castle_runtime`] recovery path (the `--disarm` CLI action), which
//! revalidates the exact complete inventory immediately before a handle-qualified
//! delete, verifies absence immediately after, and clears the journal only once
//! deletion AND post-delete absence are positively confirmed — retaining the
//! journal and failing on any ambiguity. Systemd stop is therefore NOT disarm.
//!
//! ## Honesty bound
//!
//! Wiring this plan into `boot()` ACTIVATES the kernel runtime on a privileged
//! Linux host, but does NOT make the daemon claim to be enforcing: no protected
//! agent is launched and no per-agent cgroup jump rule is installed, so the base
//! output chain stays `policy accept` and a fully-acquired runtime reads as
//! `KernelRuntimeReady`, never `Enforcing` (see [`crate::enforcement`]). Linux
//! egress enforcement stays `not_implemented` in `ASSURANCE_MATRIX.md` row 17
//! until a captured hardware drill on the reference platform proves a wrapped
//! agent is actually blocked; the kernel-touching acquisition bodies here are
//! `cfg(target_os = "linux")` and exercised only by the hardware/Ubuntu-CI
//! integration test, never by the macOS dev gates.
//!
//! On a non-Linux host every provider's `acquire()` returns
//! [`EnforcementError::NotAvailableOnPlatform`], so `EnforcementRuntime::start`
//! fails-before at the first component and the daemon reports `ControlPlaneOnly`
//! — the honest state for a host with no kernel adapter.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use crate::decision::ControlAuditError;
use crate::decision::DecisionEngine;
use crate::enforcement::{AcquiredComponent, ComponentKind, ComponentProvider, EnforcementError};
use crate::nfqueue::NfqueueConfig;

/// Configuration for the production Linux enforcement plan. Assembled by
/// `boot()` from [`crate::config::DaemonConfig`]; the lock path is host-global
/// (fortress-independent) by design (see [`crate::runtime_lock`]).
#[derive(Debug, Clone)]
pub struct LinuxRuntimeConfig {
    /// Host-global nftables ownership lock path (NOT per-fortress).
    pub lock_path: PathBuf,
    /// Root-owned ownership-journal path under the systemd `StateDirectory`
    /// (`/var/lib/sanctuary`). Persists across service restarts and reboots so a
    /// crash between atomic-create and finalize can be reclaimed, not wedged
    /// (see [`crate::ownership_journal`]).
    pub journal_path: PathBuf,
    /// Root-owned journal-authentication key path under the same
    /// `StateDirectory`. The MAC key that authenticates the journal; generated on
    /// first acquisition, 0600 root-owned, never leaves the StateDirectory
    /// (blocker 3).
    pub journal_key_path: PathBuf,
    /// Directory holding the signed manifest the watcher observes.
    pub policy_dir: PathBuf,
    /// Poll cadence for the watcher's degraded (non-inotify) fallback.
    pub poll_interval: Duration,
    /// NFQUEUE bind configuration (queue number, FAIL_OPEN off, deadlines).
    pub nfqueue: NfqueueConfig,
    /// LINUX-BOOT-STOP-HOSTWIDE-NET-01: the daemon's shutdown-REQUEST flag,
    /// threaded from `boot()` all the way into the nftables provider/component
    /// so every pre-READY (boot-phase) safety-net install site can see a stop
    /// that was requested before kernel activation completes, the same way the
    /// post-READY supervisor sees it. `install_shutdown_signal_handlers` sets
    /// this BEFORE kernel activation runs; without this field the boot-phase
    /// install sites read no shutdown state at all. Every site downstream that
    /// consults this field (drift, `ReArmLostOwned`, startup loss, and the
    /// slice-A refusal path) loads it FRESH at its own decision point rather
    /// than caching a copy earlier, so a stop that arrives mid-acquisition is
    /// still observed; see `bind_admitted_uid_before_ready`'s doc comment for
    /// why the slice-A site takes this `Arc` rather than a sampled `bool`. Must
    /// be the SAME `Arc` `boot()` hands `DaemonHandle::shutdown_flag`, never a
    /// copy.
    pub shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Build the production Linux enforcement plan in acquisition order. The order
/// exactly equals [`ComponentKind::REQUIRED_IN_ORDER`], so
/// [`EnforcementRuntime::start`]'s plan-shape gate accepts it; any drift here is
/// caught there before a single provider is acquired.
///
/// [`EnforcementRuntime::start`]: crate::enforcement::EnforcementRuntime::start
pub fn linux_production_plan(
    decision_engine: Arc<DecisionEngine>,
    config: &LinuxRuntimeConfig,
) -> Vec<Box<dyn ComponentProvider>> {
    vec![
        Box::new(NftablesTableProvider {
            lock_path: config.lock_path.clone(),
            journal_path: config.journal_path.clone(),
            journal_key_path: config.journal_key_path.clone(),
            decision_engine: Arc::clone(&decision_engine),
            shutdown_requested: Arc::clone(&config.shutdown_requested),
        }),
        Box::new(NfqueueProvider {
            decision_engine: Arc::clone(&decision_engine),
            nfqueue_config: config.nfqueue.clone(),
        }),
        Box::new(ManifestWatcherProvider {
            decision_engine,
            policy_dir: config.policy_dir.clone(),
            poll_interval: config.poll_interval,
        }),
    ]
}

// ---------------------------------------------------------------------------
// nftables table component.
// ---------------------------------------------------------------------------

struct NftablesTableProvider {
    lock_path: PathBuf,
    journal_path: PathBuf,
    journal_key_path: PathBuf,
    /// The frozen armed identity the reclaim, acquisition and health comparisons
    /// read the confined agent uid from. Held as the same `Arc` the decision
    /// engine holds, never a copy of a value, because the identity cell lives on
    /// the engine: the uid is written ONCE at the boot manifest load and a reload
    /// that would change it is refused, so every comparison site reads the same
    /// frozen value rather than re-deriving one that could differ between two
    /// reads of the same boot.
    decision_engine: Arc<DecisionEngine>,
    /// A162: live read of the daemon's shutdown-request flag. Must match
    /// [`LinuxRuntimeConfig::shutdown_requested`]; carried onto the acquired
    /// [`NftablesTableComponent`] so a startup-lost install after `acquire()`
    /// returns can see it too.
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Generate a fresh ownership marker: the [`crate::nftables::OWNER_MARKER_PREFIX`]
/// followed by a random 128-bit hex nonce. Read from `/dev/urandom` (always
/// present on the Linux hosts this path runs on) so no `rand`-feature dependency
/// is needed. The nonce is what makes a foreign same-named table unforgeable and
/// a delete/recreate distinguishable.
#[cfg(target_os = "linux")]
fn new_owner_marker() -> Result<String, EnforcementError> {
    use std::io::Read;
    let mut nonce = [0u8; 16];
    let mut urandom =
        std::fs::File::open("/dev/urandom").map_err(|err| EnforcementError::AcquireFailed {
            kind: ComponentKind::NftablesTable.as_str(),
            detail: format!("could not open /dev/urandom for the ownership nonce: {err}"),
        })?;
    urandom
        .read_exact(&mut nonce)
        .map_err(|err| EnforcementError::AcquireFailed {
            kind: ComponentKind::NftablesTable.as_str(),
            detail: format!("could not read the ownership nonce: {err}"),
        })?;
    Ok(format!(
        "{}{}",
        crate::nftables::OWNER_MARKER_PREFIX,
        hex::encode(nonce)
    ))
}

/// Read the trusted agent-binding expectation out of the identity this process
/// FROZE at boot.
///
/// INVARIANT, and it is the opposite of what this function used to say: the
/// expectation is frozen at boot and a reload that would change it is REFUSED
/// (`DecisionEngine::reload_manifest_authorized_at_boot` writes the cell; every
/// other reload compares against it), so re-reading the live snapshot here would
/// be re-reading a value that cannot have changed. Reading the cell instead is
/// what removes the `try_lock` whose failure had to be read as "not confined": a
/// health probe no longer has an indeterminate answer to fall back from.
///
/// BOUND, stated narrowly because the mechanism is narrow: what survives a plain
/// restart unchanged is the UID, which is the only field the live binding set B
/// carries and therefore the only one an adoption compares. A restart whose
/// manifest names a DIFFERENT uid refuses through the acquisition drift path; a
/// restart whose manifest keeps the uid and changes the ceiling or the gate uid
/// is adopted under the set rule, because B cannot witness either. The operator
/// procedure for any identity change is stop, `--disarm`, start.
///
/// Failure mode when the cell is UNSET: `NoneConfined`, which refuses any live
/// per-agent binding. An unset cell means the boot load has not run, and absent
/// evidence is not passing evidence.
#[cfg(target_os = "linux")]
fn current_expected_agent_binding(
    decision_engine: &DecisionEngine,
) -> crate::nftables::ExpectedAgentBinding {
    use crate::decision::AdmittedSubject;
    use crate::nftables::ExpectedAgentBinding;
    match decision_engine.armed_identity() {
        Some(identity) => match identity.subject {
            AdmittedSubject::Confined { agent_uid, .. } => ExpectedAgentBinding::Confined {
                // The fortress id travels in the cell precisely so this line does
                // not have to reach back into the store for it.
                fortress_id: identity.fortress_id.clone(),
                agent_uid,
            },
            AdmittedSubject::Unconfined => ExpectedAgentBinding::NoneConfined,
        },
        None => ExpectedAgentBinding::NoneConfined,
    }
}

#[cfg(target_os = "linux")]
fn acquire_failed(detail: impl Into<String>) -> EnforcementError {
    EnforcementError::AcquireFailed {
        kind: ComponentKind::NftablesTable.as_str(),
        detail: detail.into(),
    }
}

// ---- The safety net's scope: the deny set, the kill set, and the seven rows ----

/// How often the post-READY recovery controller retries a persist and an install.
///
/// DERIVATION: short enough that an operator repairing the wall sees the net
/// re-arm within one breath, long enough that a persistently failing nft is not
/// forked in a tight loop. One attempt is in flight at a time, so this is the
/// floor on the interval between attempts, not a deadline on any one of them.
/// Must match the `RECOVERY_RETRY_INTERVAL = 5 s` named in memo D1b step 7.
pub const RECOVERY_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// This boot's confined history, as the authenticated journal records it.
///
/// The two variants are NOT interchangeable and the distinction decides the net's
/// scope: `Unknown` resolves host-wide whatever the manifest and the live table
/// say, because a previous binary's record cannot prove which uids were bound.
/// `Known(vec![])` is this binary's own record before any identity was bound, and
/// resolves from the other two sources.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfinedHistory {
    /// The journal's `confined` key is present. These are its uids.
    Known(Vec<crate::ownership_journal::ConfinedIdentity>),
    /// The journal's `confined` key is ABSENT on a same-boot record.
    Unknown,
}

/// The resolved scope plus everything a refusal, an audit row and the PR-3 sweep
/// each need from the same computation.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNetResolution {
    /// What the net will deny.
    pub scope: crate::nftables::SafetyNetScope,
    /// Why it has that scope.
    pub reason: crate::nftables::SafetyNetReason,
    /// The KILL set: sources (a) and (b) ONLY, ascending.
    ///
    /// INVARIANT: source (c) never enters this. A live kernel table is safe
    /// authority for DENYING a uid, because denying a uid that turns out to be
    /// nobody's costs nothing. It is NOT authority for TERMINATING that uid's
    /// processes, because a `CAP_NET_ADMIN` actor can write a jump naming any uid
    /// and would then be choosing whose processes this daemon kills. Only
    /// identities a signed manifest admitted, as the MAC-covered journal records
    /// them, may be killed. PR-3 consumes this; Part A only carries it.
    pub kill_set: Vec<u32>,
    /// Which sources contributed, for the audit row.
    pub sources: crate::nftables::SafetyNetSources,
    /// The FULL deny union this resolution computed, before the cap and the
    /// host-wide fallbacks were applied.
    ///
    /// Carried separately from `scope` because `scope.denied_uids()` is EMPTY for the
    /// host-wide shape, and the retained in-memory set is seeded from a resolution.
    /// Seeding from the scope would discard a known over-capacity union entirely, and a
    /// later recompute could then produce a NARROWER net than the process already knew
    /// about. The monotonic retained set is defined over this field.
    pub deny_union: Vec<u32>,
}

#[cfg(any(target_os = "linux", test))]
impl SafetyNetResolution {
    /// The in-process retention floor is the complete union, including when
    /// the installed scope is host-wide and names no individual uid.
    fn retained_deny_uids(&self) -> &[u32] {
        &self.deny_union
    }
}

/// Resolve the safety net's scope from the three sources of memo D1b.
///
/// SOURCES:
///   * (a) the `Owned` journal record's `confined` array (admitted identities
///     only, MAC-covered, written ahead of every binding);
///   * (b) the currently admitted identity: the agent uid and, when the manifest
///     names one, the distinct gate uid;
///   * (c) the `meta skuid` bindings the LIVE owned table declares, taken from the
///     typed two-phase parse so a table that is ours but has drifted off the
///     current manifest still contributes.
///
/// DENY SET = (a) union (b) union (c). KILL SET = (a) union (b) only.
///
/// UNKNOWN HISTORY overrides everything: an absent `confined` key on a same-boot
/// `Owned` record resolves the net to `HostWide` whatever (b) and (c) say, because
/// the pre-upgrade reload path removed stale jumps while never terminating a
/// rotated-away uid's processes, so neither remaining source can prove the
/// history. The kill set is still (b), which is safe to sweep and may be empty.
///
/// Pure over its inputs, so every row of the resolution matrix is unit-testable on
/// a host with no kernel. `overflow` is the host's configured `kernel.overflowuid`,
/// read once by the caller.
#[cfg(any(target_os = "linux", test))]
pub fn resolve_safety_net_scope(
    history: &ConfinedHistory,
    admitted: Option<(u32, Option<u32>)>,
    live_bindings: &crate::nftables::LiveTableBindings,
    overflow: crate::safety_net_uid::HostOverflowUid,
) -> SafetyNetResolution {
    use crate::nftables::{
        LiveTableBindings, SafetyNetReason, SafetyNetScope, SafetyNetSources, DENY_SET_MAX,
    };
    use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet};

    // Source (a).
    let journal_uids: Vec<u32> = match history {
        ConfinedHistory::Known(entries) => entries.iter().map(|e| e.uid).collect(),
        ConfinedHistory::Unknown => Vec::new(),
    };
    // Source (b): the agent uid and the gate uid travel TOGETHER. The gate is a
    // confined principal the manifest names, and with the wall gone its own allow
    // rules are gone too, so denying the agent while sparing the gate would leave
    // a confined principal with egress.
    let mut manifest_uids: Vec<u32> = Vec::new();
    if let Some((agent_uid, gate_uid)) = admitted {
        manifest_uids.push(agent_uid);
        if let Some(gate) = gate_uid {
            manifest_uids.push(gate);
        }
    }
    // Source (c).
    let live_uids: Vec<u32> = match live_bindings {
        LiveTableBindings::Bindings(uids) => uids.clone(),
        // An unreadable or foreign table yields NOTHING. It is never read as
        // "empty", because those two resolve the net to different scopes.
        LiveTableBindings::NotOurTable { .. } | LiveTableBindings::Unreadable { .. } => Vec::new(),
    };

    let sources = SafetyNetSources {
        journal: !journal_uids.is_empty(),
        manifest: !manifest_uids.is_empty(),
        live_table: !live_uids.is_empty(),
    };

    // KILL SET = (a) union (b). Computed before any host-wide short circuit,
    // because unknown history still yields a kill set from (b).
    let mut kill_set: Vec<u32> = journal_uids
        .iter()
        .chain(manifest_uids.iter())
        .copied()
        .collect();
    kill_set.sort_unstable();
    kill_set.dedup();

    // The full union, computed before any cap or fallback, so every resolution carries
    // what this process knows even when the SCOPE it installs names nobody.
    let mut deny_union: Vec<u32> = journal_uids
        .iter()
        .chain(manifest_uids.iter())
        .chain(live_uids.iter())
        .copied()
        .collect();
    deny_union.sort_unstable();
    deny_union.dedup();

    let host_wide = |reason: SafetyNetReason| SafetyNetResolution {
        scope: SafetyNetScope::HostWide,
        reason,
        kill_set: kill_set.clone(),
        sources: sources.clone(),
        deny_union: deny_union.clone(),
    };

    // UNKNOWN HISTORY short-circuits, and it is checked FIRST so no later branch
    // can narrow the net over a previous binary's record.
    if matches!(history, ConfinedHistory::Unknown) {
        return host_wide(SafetyNetReason::UnknownHistory);
    }

    // DENY SET = (a) union (b) union (c), which is the union computed above.
    let deny = deny_union.clone();
    if deny.len() > DENY_SET_MAX {
        // Over capacity: the identities are known EXACTLY but are too many to name
        // in one rule. Nothing is truncated, because a dropped uid stops being
        // denied, and the journal is untouched.
        return host_wide(SafetyNetReason::DenySetOverCapacity {
            count: deny.len(),
            cap: DENY_SET_MAX,
        });
    }
    // The three refusals apply to every member, whatever source it came from: a
    // uid the kernel cannot attest to one principal must not be named in rule 1.
    // A refused member is DROPPED from the deny set rather than failing the whole
    // resolution, because the remaining members are still real identities that
    // must be denied. Must match `validate_safety_net_uid`.
    let validated: Vec<_> = deny
        .iter()
        .filter_map(|&uid| validate_safety_net_uid(uid, overflow).ok())
        .collect();
    match ConfinedUidSet::from_validated(validated) {
        Ok(set) => SafetyNetResolution {
            scope: SafetyNetScope::Identity(set),
            reason: SafetyNetReason::Identity,
            kill_set,
            sources,
            deny_union,
        },
        // An empty deny set: no confined identity was recoverable from any source.
        Err(_) => host_wide(SafetyNetReason::EmptyDenySet),
    }
}

/// Gather the three sources at a live Linux site and resolve the net's scope.
///
/// The journal record supplies source (a) and, critically, whether this boot's
/// history is KNOWN at all. `Preparing` answers `Known(vec![])` for a different
/// reason than a legacy `Owned` record answers `Unknown`: no binding preceded a
/// `Preparing` record, so there is no history to be missing.
///
/// FAILURE MODE worth stating: if the host's `kernel.overflowuid` cannot be read
/// this returns the HOST-WIDE scope with the empty-deny-set reason rather than
/// guessing. That is the conservative direction (the net still denies the agent),
/// and the refusal text says operator access is not preserved, so the outcome is
/// visible rather than silent.
#[cfg(target_os = "linux")]
fn resolve_net_scope_at_site(
    journal_record: Option<&crate::ownership_journal::OwnershipJournal>,
    decision_engine: &DecisionEngine,
) -> SafetyNetResolution {
    use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope, SafetyNetSources};
    use crate::ownership_journal::OwnershipJournal;

    let history = match journal_record {
        Some(OwnershipJournal::Owned { confined, .. }) => match confined {
            Some(entries) => ConfinedHistory::Known(entries.clone()),
            // The key is ABSENT: a record from a binary that predates the field.
            None => ConfinedHistory::Unknown,
        },
        // No binding preceded a `Preparing` record, and an absent record is a fresh
        // start; both are a known-empty history, resolved from the other sources.
        Some(OwnershipJournal::Preparing { .. }) | None => ConfinedHistory::Known(Vec::new()),
    };

    // Source (b): the agent uid and the gate uid together, from the identity this
    // process FROZE at boot. It is the same read as `admitted_identity` and calls
    // it, rather than repeating a snapshot read here: two spellings of source (b)
    // is how one of them ends up narrowing the net that the other would not.
    let admitted = admitted_identity(decision_engine);

    let overflow = match crate::safety_net_uid::HostOverflowUid::from_host() {
        Ok(value) => value,
        Err(_) => {
            // No host value means no member can be validated, so no identity scope can
            // be named and the host-wide shape is the conservative answer for the NET.
            // The KILL SET is unaffected: it is (a) union (b), identities the signed
            // manifest admitted as the MAC-covered journal records them, and none of
            // that evidence depends on the sysctl. Dropping the journal half here would
            // silently narrow whose processes PR-3 may terminate.
            let mut kill_set: Vec<u32> = match &history {
                ConfinedHistory::Known(entries) => entries.iter().map(|e| e.uid).collect(),
                ConfinedHistory::Unknown => Vec::new(),
            };
            if let Some((agent, gate)) = admitted {
                kill_set.push(agent);
                if let Some(g) = gate {
                    kill_set.push(g);
                }
            }
            kill_set.sort_unstable();
            kill_set.dedup();
            return SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::EmptyDenySet,
                kill_set: kill_set.clone(),
                sources: SafetyNetSources {
                    journal: matches!(history, ConfinedHistory::Known(ref e) if !e.is_empty()),
                    manifest: admitted.is_some(),
                    live_table: false,
                },
                // The union this process knows, even though the scope it installs names
                // nobody: the retained set is seeded from here.
                deny_union: kill_set.clone(),
            };
        }
    };

    // Source (c): the live table's own skuid bindings. Read AFTER the overflow value,
    // because recognising this daemon's own net needs it: when the live table IS the
    // net, (c) is rule 1's set, which is the set currently denying traffic in the
    // kernel. Through the typed two-phase parse otherwise, so an owned table that has
    // drifted off the current manifest still contributes its uids.
    let expectation = current_expected_agent_binding(decision_engine);
    let live = match crate::nftables::list_castle_table_json() {
        Ok(Some(json)) => crate::nftables::live_table_uid_bindings(&json, &expectation, overflow),
        // No table at all is not a parse failure and not a foreign table.
        Ok(None) => LiveTableBindings::Bindings(Vec::new()),
        Err(err) => LiveTableBindings::Unreadable {
            detail: err.to_string(),
        },
    };
    resolve_safety_net_scope(&history, admitted, &live, overflow)
}

/// Write the kill set ((a) union (b)) to the journal AHEAD of a kernel step, and
/// keep UNKNOWN HISTORY unknown.
///
/// INVARIANT, state-indexed (memo D1b step 6): while the `confined` key is ABSENT
/// on a same-boot `Owned` record, NO store may materialise it. Writing the current
/// identity over an absent key would turn unknown history into KNOWN history on the
/// next start and let a rotated-away uid out of the net. So this function writes
/// only when the history is already known, and otherwise re-stores the record with
/// the key still omitted.
///
/// Returns the error for a caller to RECORD. Whether a failed persist aborts the
/// caller's kernel step is the caller's decision and differs per row: the BIND row
/// refuses, every net-install row proceeds, because installing the net makes no uid
/// live and so cannot outrun the journal.
#[cfg(target_os = "linux")]
fn persist_kill_set_write_ahead(
    journal_path: &std::path::Path,
    key: Option<&crate::ownership_journal::JournalAuthKey>,
    record: &crate::ownership_journal::OwnershipJournal,
    kill_set: &[u32],
    admitted: Option<(u32, Option<u32>)>,
) -> Result<(), String> {
    use crate::ownership_journal::{ConfinedIdentity, ConfinedRole, OwnershipJournal};
    let key = key.ok_or_else(|| {
        "no journal authentication key is available, so the confined history cannot be \
         written ahead of the kernel step"
            .to_string()
    })?;
    let OwnershipJournal::Owned {
        identity,
        table_handle,
        base_chain_handle,
        confined,
    } = record
    else {
        // A `Preparing` record carries no history to extend; the write-ahead for a
        // fresh create happens when the record becomes `Owned`.
        return Ok(());
    };
    let next = match confined {
        // UNKNOWN HISTORY stays unknown: re-store with the key omitted.
        None => OwnershipJournal::owned_with_unknown_history(
            identity.clone(),
            *table_handle,
            *base_chain_handle,
        ),
        Some(existing) => {
            // Union the recorded history with the currently admitted identity,
            // tagging each uid with the role the manifest gave it. The union only
            // grows within a boot; a uid leaves it on disarm or reboot.
            let mut merged = existing.clone();
            let mut add = |uid: u32, role: ConfinedRole| {
                if !merged.iter().any(|e| e.uid == uid) {
                    merged.push(ConfinedIdentity { uid, role });
                }
            };
            if let Some((agent, gate)) = admitted {
                add(agent, ConfinedRole::Agent);
                if let Some(g) = gate {
                    add(g, ConfinedRole::Gate);
                }
            }
            // Anything in the kill set that the manifest no longer names is an
            // earlier admitted identity; it keeps its recorded role, and a uid that
            // reached the kill set from source (a) is already present.
            let _ = kill_set;
            OwnershipJournal::owned_with_known_history(
                identity.clone(),
                *table_handle,
                *base_chain_handle,
                merged,
            )
            .map_err(|err| err.to_string())?
        }
    };
    crate::ownership_journal::store_atomic(journal_path, &next, key).map_err(|err| err.to_string())
}

/// Build the `Owned` record to store, PRESERVING this boot's history state.
///
/// INVARIANT (memo D1b step 6, state-indexed): if the record already on disk has
/// the `confined` key ABSENT, the new record must keep it absent. Writing the
/// currently admitted identity over an absent key would turn UNKNOWN history into
/// KNOWN history on the next start, and a uid this daemon rotated away from (whose
/// processes it never terminated) would then be omitted from the net.
///
/// Otherwise the history is known and the currently admitted identity is UNIONED
/// into it, tagged with the role the manifest gave each uid. This is the write-ahead
/// itself: it runs under the host lock BEFORE the kernel step that makes the uid
/// live, so a crash between the two leaves the journal naming MORE than the kernel
/// does, never less.
#[cfg(target_os = "linux")]
fn owned_record_preserving_history(
    journal_path: &std::path::Path,
    key: &crate::ownership_journal::JournalAuthKey,
    identity: crate::ownership_journal::JournalIdentity,
    table_handle: u64,
    base_chain_handle: u64,
    admitted: Option<(u32, Option<u32>)>,
) -> Result<crate::ownership_journal::OwnershipJournal, EnforcementError> {
    use crate::ownership_journal::{
        self as journal, ConfinedIdentity, ConfinedRole, OwnershipJournal,
    };
    // A read failure here must not be turned into "history is known": that is the
    // direction that loses a rotated-away uid. Treat it as unknown.
    let existing = journal::load(journal_path, Some(key)).ok().flatten();
    let prior = match existing.as_ref() {
        Some(OwnershipJournal::Owned { confined, .. }) => confined.clone(),
        // A `Preparing` record or no record means no history has been recorded yet,
        // which is known-empty, not unknown.
        _ => Some(Vec::new()),
    };
    let Some(mut history) = prior else {
        return Ok(OwnershipJournal::owned_with_unknown_history(
            identity,
            table_handle,
            base_chain_handle,
        ));
    };
    if let Some((agent, gate)) = admitted {
        if !history.iter().any(|e| e.uid == agent) {
            history.push(ConfinedIdentity {
                uid: agent,
                role: ConfinedRole::Agent,
            });
        }
        if let Some(g) = gate {
            if !history.iter().any(|e| e.uid == g) {
                history.push(ConfinedIdentity {
                    uid: g,
                    role: ConfinedRole::Gate,
                });
            }
        }
    }
    OwnershipJournal::owned_with_known_history(identity, table_handle, base_chain_handle, history)
        .map_err(|err| {
            acquire_failed(format!(
                "this boot's confined identity history cannot take another binding: {err}"
            ))
        })
}

/// Source (b) alone: the identity this process armed at boot, agent uid and gate
/// uid together.
///
/// It reads the FROZEN cell, not the live snapshot. The snapshot read it
/// replaced could fail (`try_lock` contention) and yield `None`, which narrowed
/// the net for a reason that had nothing to do with what was admitted; the cell
/// cannot fail. `None` here now means exactly one thing: this manifest confines
/// nobody, or the boot load has not run yet.
#[cfg(target_os = "linux")]
fn admitted_identity(decision_engine: &DecisionEngine) -> Option<(u32, Option<u32>)> {
    use crate::decision::AdmittedSubject;
    match decision_engine.armed_identity()?.subject {
        AdmittedSubject::Confined {
            agent_uid,
            gate_uid,
            ..
        } => Some((agent_uid, gate_uid)),
        AdmittedSubject::Unconfined => None,
    }
}

/// The PR-3 stop hook is called here,
/// at the exact sites memo D1b step 7 names, so PR-3 changes one function body
/// instead of finding five call sites: after a FAILED install on the four install
/// rows, and before the exit on both nft-indeterminate rows. It is NEVER called on
/// the BIND row (no kernel step happens there) nor on a non-nft loss (the table is
/// intact), and never after a SUCCESSFUL install.
///
/// `kill_set` is sources (a) and (b) only, never the live table's bindings.
#[cfg(any(target_os = "linux", test))]
fn safety_net_sweep_hook_pr3(
    kill_set: &[u32],
    attempted_scope: Option<&crate::nftables::SafetyNetScope>,
    why: &str,
) {
    // Only a fresh strict live-net shape covering the *attempted* install can
    // suppress an owner stop. A read error, different scope or foreign table
    // has no such meaning. Indeterminate hooks install/probe nothing.
    if let Some(scope) = attempted_scope {
        if matches!(crate::nftables::live_net_covers_attempt(scope), Ok(true)) {
            // SAFETY: stderr is the operator channel for the stop hook's single
            // outcome line. This branch records that a fresh strict live net
            // already covers the attempted install, which is the only shape that
            // suppresses an owner stop, so the suppression must be visible.
            eprintln!("castle-wall-daemon: stop_hook={why} owner_outcome=covered_net");
            return;
        }
    }
    #[cfg(target_os = "linux")]
    let outcome =
        crate::protected_agent::owner::stop_failure_for_hook(kill_set, why, attempted_scope);
    #[cfg(not(target_os = "linux"))]
    let outcome = {
        let _ = kill_set;
        crate::protected_agent::owner_outcome_unavailable()
    };
    let class = match outcome {
        crate::protected_agent::StopClass::IntentAccepted => "intent_accepted",
        crate::protected_agent::StopClass::NoOwnedRelease => "no_owned_release",
        crate::protected_agent::StopClass::OwnerUnavailable => "owner_unavailable",
        crate::protected_agent::StopClass::Inhibit => "inhibit",
    };
    // SAFETY: stderr is the operator channel for the stop hook's single outcome
    // line. The class is the whole local record of what the owner answered, and
    // no result transport carries it anywhere else.
    eprintln!("castle-wall-daemon: stop_hook={why} owner_outcome={class}");
}

/// reclaim drift. See [`drift_enforce_fail_closed`].
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
enum DriftFailClosedOutcome {
    /// The safety net installed; the drifted table now carries the net's scope.
    NetInstalled,
    /// A162 (Erik, 2026-09-24): a stop was already requested and the resolved
    /// scope was HostWide (no known confined identity); no kernel mutation was
    /// attempted. See [`stop_time_hostwide_skip`]. This is not a failure: the
    /// residual audit row and stderr line were already written by that call.
    HostWideSkippedForRequestedStop,
    /// The net install FAILED. The PR-3 sweep hook ran, and the table is LEFT
    /// STANDING.
    ///
    /// INVARIANT: Part A performs NO table deletion outside the disarm verb. A
    /// castle table that is present is one the disarm verb can still reason about,
    /// and removing the table would remove the only egress gate this daemon
    /// controls without putting anything in its place. The action that constrains
    /// the confined identity on this branch is the sweep, which is PR-3's; until it
    /// lands this branch carries the bound the register rows record.
    ///
    /// Tracked in the private register as
    /// `defect.linux-gf1-2-deny-all-and-escalating-delete-both-fail-leaves-kernel-state-indeterminate`.
    /// A residual described only in prose is not owned risk (AGENTS rule 9); the
    /// register row is the record and this line is its pointer.
    InstallFailedSweepHooked { net_err: String },
}

/// A162 (Erik, 2026-09-24), the boot-phase extension of A155: a routine stop
/// never installs a HOST-WIDE net, whether it lands before `READY=1` (a boot
/// acquisition install: the reclaim-drift site, the `ReArmLostOwned` site, the
/// slice-A refusal path routed through [`refuse_after_owned_table`], and the
/// STARTUP LOST path in [`NftablesTableComponent::install_net_on_startup_loss`])
/// or after it (the post-READY controller,
/// [`NftablesTableComponent::recover_post_ready_loss`]). `HostWide` here means
/// no confined uid is known for this boot (or the retained/deny set
/// overflowed), so an install at stop time would have nothing legitimate to
/// scope the drop to and would instead silence every principal on the host on
/// an ordinary `systemctl stop` that merely raced acquisition or a runtime
/// loss. With a known confined identity (`SafetyNetScope::Identity`) this
/// returns `false` and the caller installs as normal, in or out of shutdown: a
/// proven loss with a known identity still gets its one net attempt (memo
/// `Linux_C2a_FailClosed_Architecture_v2` §1 invariant; register
/// LINUX-BOOT-STOP-HOSTWIDE-NET-01 for the boot-phase legs, A155 for the
/// post-READY leg).
///
/// THE ONE site that decides "skip or install" for a requested stop. Every
/// caller above passes through here before mutating the kernel; do not
/// re-implement this check at a new call site. When it returns `true` it has
/// ALREADY recorded the residual audit row and the stderr line naming the
/// skip, so the caller performs no further recording for the skip itself (a
/// caller may still record its own install-history tag, or leave it
/// untouched, per its own contract).
#[cfg(any(target_os = "linux", test))]
fn stop_time_hostwide_skip(
    decision_engine: &DecisionEngine,
    shutdown_requested: bool,
    scope: &crate::nftables::SafetyNetScope,
) -> bool {
    if !shutdown_requested || !matches!(scope, crate::nftables::SafetyNetScope::HostWide) {
        return false;
    }
    // Must match the one literal every caller's audit trail and any operator
    // grep for this residual class relies on; keep this the SOLE definition.
    const RESIDUAL_REASON: &str = "stop_time_net_skipped_no_known_identity";
    if let Err(audit_err) = decision_engine.append_control_audit_bounded(
        RESIDUAL_REASON,
        "a stop was already requested when a proven table loss (or boot-time \
         acquisition failure) resolved to a host-wide net with no known confined \
         identity; the install was skipped so an ordinary stop cannot silence \
         every principal on the host",
        crate::decision::FAILURE_AUDIT_BUDGET,
    ) {
        // SAFETY: stderr is the operator channel of last resort when even the
        // bounded residual audit row cannot be written.
        eprintln!("castle-wall-daemon: {RESIDUAL_REASON} (audit row failed: {audit_err:?})");
    } else {
        // SAFETY: stderr is the operator channel naming the A155/A162 residual;
        // the durable record is the audit row appended just above.
        eprintln!("castle-wall-daemon: {RESIDUAL_REASON}");
    }
    true
}

/// GF1.2: on a reclaim DRIFT, install the safety net for the resolved scope.
///
/// The install is REQUIRED, not best-effort. On FAILURE the PR-3 sweep hook runs
/// and the table is left standing; see
/// [`DriftFailClosedOutcome::InstallFailedSweepHooked`] for why Part A no longer
/// escalates to a by-name delete. Injectable installer so the sequence is
/// unit-testable without a broken nft.
#[cfg(any(target_os = "linux", test))]
fn drift_enforce_fail_closed(
    decision_engine: &DecisionEngine,
    shutdown_requested: bool,
    install_deny_all: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
    kill_set: &[u32],
    attempted_scope: &crate::nftables::SafetyNetScope,
) -> DriftFailClosedOutcome {
    // A162: THE ONE gate every pre-READY installer that routes through this
    // function passes through before touching the kernel. Do not re-implement
    // this check at a new call site; add a new caller to `drift_enforce_fail_closed`
    // instead.
    if stop_time_hostwide_skip(decision_engine, shutdown_requested, attempted_scope) {
        return DriftFailClosedOutcome::HostWideSkippedForRequestedStop;
    }
    match install_deny_all() {
        Ok(()) => DriftFailClosedOutcome::NetInstalled,
        Err(net_err) => {
            // The hook fires ONLY after a failed install, never after a successful
            // one: a net that is in the kernel already denies the identity, and
            // terminating its processes on top of that would be an action with no
            // protection left to add.
            safety_net_sweep_hook_pr3(
                kill_set,
                Some(attempted_scope),
                "reclaim drift: the safety net install failed before readiness was refused",
            );
            DriftFailClosedOutcome::InstallFailedSweepHooked {
                net_err: net_err.to_string(),
            }
        }
    }
}

/// One post-READY safety-net install transaction, injectable so retries and the
/// failed-install-only hook are unit-testable without a live nft. A prior success
/// does not prove that an external actor left the net in place: each eligible
/// completed loss must execute this transaction again. Part A never deletes the
/// table on failure.
#[cfg(any(target_os = "linux", test))]
fn install_deny_all_net_for_recovery(
    install: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
    kill_set: &[u32],
    attempted_scope: &crate::nftables::SafetyNetScope,
) -> bool {
    match install() {
        Ok(()) => true,
        Err(net_err) => {
            safety_net_sweep_hook_pr3(
                kill_set,
                Some(attempted_scope),
                "runtime loss: the safety net install failed; protection could not be proved",
            );
            // SAFETY: stderr is the operator channel for a kernel-egress escalation.
            // systemd's journal is where an operator reconstructs this sequence.
            eprintln!(
                "castle-wall-daemon: owned nft table lost at runtime and installing the \
                 safety net FAILED; the castle table is left standing and protection \
                 could not be proved: {net_err}"
            );
            false
        }
    }
}

/// The caller's completed Lost reading is the first recovery proof. Only later
/// Recovering polls need a fresh ownership query; an unavailable second query
/// must not veto the first protective install.
#[cfg(any(target_os = "linux", test))]
fn post_ready_recovery_proof(
    retrying: bool,
    reprobe: impl FnOnce() -> crate::health_probe::ProbeOutcome,
) -> crate::health_probe::ProbeOutcome {
    if retrying {
        reprobe()
    } else {
        crate::health_probe::ProbeOutcome::Lost
    }
}

/// Consume the probe's completed positive proof even when it arrives after an
/// earlier caller timed out. This changes only recovery bookkeeping: `health()`
/// remains a read and performs no kernel install or delete.
#[cfg(any(target_os = "linux", test))]
fn post_ready_component_health(
    outcome: crate::health_probe::ProbeOutcome,
    recovering: &std::sync::atomic::AtomicBool,
    last_attempt: &std::sync::Mutex<Option<std::time::Instant>>,
) -> crate::enforcement::ComponentHealth {
    use crate::enforcement::ComponentHealth;
    use crate::health_probe::ProbeOutcome;
    use std::sync::atomic::Ordering;

    match outcome {
        ProbeOutcome::Ready => {
            if recovering.swap(false, Ordering::SeqCst) {
                let mut last = match last_attempt.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *last = None;
            }
            ComponentHealth::Ready
        }
        ProbeOutcome::Lost => {
            if recovering.load(Ordering::SeqCst) {
                ComponentHealth::Recovering
            } else {
                ComponentHealth::Lost
            }
        }
        ProbeOutcome::Unavailable => {
            if recovering.load(Ordering::SeqCst) {
                ComponentHealth::Recovering
            } else {
                ComponentHealth::ProbeUnavailable
            }
        }
        ProbeOutcome::Indeterminate => {
            recovering.store(false, Ordering::SeqCst);
            ComponentHealth::Indeterminate
        }
    }
}

/// Test-only: acquire ONLY the nftables table component (no NFQUEUE/manifest) so
/// an integration test can drive the REAL crash-recovery acquisition path --
/// including GF1.1 create-failure recovery -- and the live `health()` transition,
/// without constructing a full `DecisionEngine`/`boot`. Gated to `test-isolation`
/// (the integration binaries' `required-features`); absent from the shipped
/// binary, exactly like the other test-only seams in this crate.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn acquire_castle_table_component_for_test(
    config: &LinuxRuntimeConfig,
) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
    // A STORE-LESS decision engine, so `current_expected_agent_binding` resolves
    // to `NoneConfined`: this seam drives the table-lifecycle paths (fresh
    // create, interrupted-acquisition reclaim, runtime loss) with NO agent
    // wrapped, which is the posture those paths run in. `NoneConfined` is the
    // strict reading there — a per-agent binding appearing in a table this seam
    // owns would be refused — so the seam is never weaker than production.
    let decision_engine = Arc::new(DecisionEngine::new_with_mutation_cancel(
        "test-isolation-fortress".to_string(),
        None,
        None,
        Arc::new(std::sync::Mutex::new(crate::audit::AuditRingBuffer::new(
            1024,
            Duration::from_secs(1),
        ))),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ));
    // The seam freezes the identity EXPLICITLY rather than leaving the cell
    // unset. An unset cell is the "the boot load never ran" state, which
    // acquisition refuses outright, so a seam that left it unset would exercise
    // the refusal instead of the table-lifecycle paths it exists for.
    // `Unconfined` is the strict reading: no agent is bound on these paths, and a
    // per-agent binding appearing in a table this seam owns is refused.
    decision_engine.freeze_armed_identity_for_test(crate::decision::AdmittedIdentity {
        fortress_id: "test-isolation-fortress".to_string(),
        subject: crate::decision::AdmittedSubject::Unconfined,
    });
    Box::new(NftablesTableProvider {
        lock_path: config.lock_path.clone(),
        journal_path: config.journal_path.clone(),
        journal_key_path: config.journal_key_path.clone(),
        decision_engine,
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
    .acquire()
}

/// The line the daemon emits once the kernel has handed the agent's jump back.
///
/// It is a PINNED string, not a log message: the L-A drill orders this line's
/// journald `__MONOTONIC_TIMESTAMP` against the unit's
/// `ActiveEnterTimestampMonotonic` to prove the binding preceded readiness. Must
/// match the needle in the L-A leg of
/// `Review/Sanctuary/Linux_PR3b_Design_Packet_2026-09-19.md` and in the drill
/// harness that greps it. It is emitted ONLY from the readback parse result, so
/// a line in the journal is evidence the kernel answered, never evidence that
/// the daemon intended to install something.
#[cfg(any(target_os = "linux", test))]
pub const AGENT_BINDING_READBACK_LINE_PREFIX: &str =
    "castle-wall-daemon: agent_binding=readback_ok";

/// The line the daemon emits once the journal names the uid, BEFORE the kernel
/// step that can make it live.
///
/// Also a PINNED string, and the companion of the readback needle above: L-A3
/// run 1 greps this one to show the write-ahead happened, and orders it before
/// the readback line to show the journal named MORE than the kernel at every
/// instant. Must match the mirror in
/// `castle-wall-daemon/tests/integration_linux_runtime_activation.rs` and the
/// L-A3 leg of `Review/Sanctuary/Linux_PR3b_Design_Packet_2026-09-19.md`. It is
/// emitted ONLY from a receipt the persist returned, never from an intent to
/// persist.
#[cfg(any(target_os = "linux", test))]
pub const AGENT_BINDING_WRITE_AHEAD_LINE_PREFIX: &str =
    "castle-wall-daemon: agent_binding=write_ahead_ok";

/// This boot's confined history, read from the PRE-MATCH journal record.
///
/// SCOPED TO THIS BOOT, and the boot-id comparison is the whole reason this is a
/// separate function from the mapping inside `resolve_net_scope_at_site`: that
/// one takes the record's history at face value because it normally runs only
/// on paths `journal::decide` already matched to this boot. The one exception
/// is the retained-deny seed taken right after a `FreshCreate` acquisition,
/// which calls it with the PRE-MATCH record (still possibly a previous boot's)
/// because this boot's own record does not exist yet to compare against;
/// reading a stale boot's uids into that seed can only WIDEN the deny set
/// (more uids named, never fewer), so the exception stays conservative rather
/// than defeating what this function's boot-id guard protects. This one also
/// runs on a FRESH acquisition, where the record on disk may be a previous
/// boot's. A previous
/// boot's uids cannot have live processes after a reboot, so reading them as
/// this boot's history would refuse every first start after a reboot that
/// changed the manifest. `Unknown` is preserved rather than flattened: a
/// same-boot record that cannot say which uids were bound is not a record that
/// says none were.
#[cfg(any(target_os = "linux", test))]
fn this_boot_confined_history(
    existing: Option<&crate::ownership_journal::OwnershipJournal>,
    boot_id: &str,
) -> ConfinedHistory {
    use crate::ownership_journal::OwnershipJournal;
    match existing {
        Some(OwnershipJournal::Owned {
            identity, confined, ..
        }) if identity.boot_id == boot_id => match confined {
            Some(entries) => ConfinedHistory::Known(entries.clone()),
            None => ConfinedHistory::Unknown,
        },
        // A `Preparing` record, an absent record, or any record from another boot:
        // no uid was bound under THIS boot's wall before now.
        _ => ConfinedHistory::Known(Vec::new()),
    }
}

/// The uids this boot's history names, or `None` when the history cannot say.
#[cfg(any(target_os = "linux", test))]
fn history_uids(history: &ConfinedHistory) -> Option<Vec<u32>> {
    match history {
        ConfinedHistory::Known(entries) => Some(entries.iter().map(|entry| entry.uid).collect()),
        ConfinedHistory::Unknown => None,
    }
}

/// The live per-agent binding set B, reduced to what a decision needs from it.
///
/// The three variants are NOT interchangeable and the difference is the whole
/// content of the net decision: an UNREADABLE table is not an EMPTY table. A
/// parse that failed cannot prove the kernel routes nobody, so it must read as
/// "a uid may be live", exactly as an unknown history does.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveBindingSet {
    /// B is exactly what the armed identity requires: the `uid-<U>` singleton
    /// under `Confined { U }`, or the empty set under `Unconfined`.
    Verified { binding_count: usize },
    /// B was read and is not the required set. `binding_count` is |B|, which is
    /// what the net decision consults; `detail` is the parser's own account.
    Mismatch {
        binding_count: usize,
        detail: String,
    },
    /// B could not be read at all.
    Unreadable { detail: String },
}

#[cfg(any(target_os = "linux", test))]
impl LiveBindingSet {
    /// Whether the kernel may be routing some uid through a per-agent binding.
    ///
    /// INVARIANT at this line: an unreadable set answers YES. The alternative
    /// reading, "no bindings were seen, so none exist", is the fail-open one.
    fn may_hold_a_binding(&self) -> bool {
        match self {
            Self::Verified { binding_count } | Self::Mismatch { binding_count, .. } => {
                *binding_count > 0
            }
            Self::Unreadable { .. } => true,
        }
    }
}

/// THE NET-ON-REFUSAL PREDICATE, computed in exactly one place.
///
/// INVARIANT at this line: whether a refusal installs the safety net is a
/// function of (this boot's confined history, the live binding set) and of
/// NOTHING else — never of which check refused. A set rule that came back wrong
/// and a readback that came back wrong ask the kernel the same question (is a
/// confined uid possibly live right now), so a per-reason answer would install a
/// net for one and leave a live uid unguarded for the other. Unknown history
/// answers YES: a record that cannot say which uids were bound is not a record
/// that says none were.
#[cfg(any(target_os = "linux", test))]
fn net_required_on_refusal(history: &ConfinedHistory, live: &LiveBindingSet) -> bool {
    let history_names_a_uid = match history_uids(history) {
        None => true,
        Some(uids) => !uids.is_empty(),
    };
    history_names_a_uid || live.may_hold_a_binding()
}

/// What the acquisition must do with the admitted uid, as a value.
///
/// The kernel-touching code executes this plan and decides nothing; every
/// decision the slice makes (the set rule, this boot's history reconciliation,
/// and the net-on-refusal rule that governs both) is taken by
/// [`plan_admitted_binding`], which is pure. That is what lets a macOS run prove
/// the set rule and the reconciliation exhaustively with no kernel: delete
/// either from the pure function and its tests fail.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindPlan {
    /// B is already the exact singleton: adopt it, never reinstall it.
    /// Reinstalling would mint a second write-ahead and change the rule handle a
    /// same-boot restart is supposed to preserve.
    Adopt { agent_uid: u32 },
    /// The table carries no binding and the manifest admits one: write ahead,
    /// then install.
    Install { agent_uid: u32, ceiling: u32 },
    /// The manifest confines nobody and the table carries no binding.
    NothingToBind,
    /// Refuse, and install the net first. `uncovered_uids` is the history's
    /// contribution: the uids this boot bound that the protection about to be
    /// established would NOT cover. Empty for a refusal the history did not
    /// cause; the net's own scope is still resolved from the pre-match record.
    RefuseWithNet {
        reason: String,
        uncovered_uids: Vec<u32>,
    },
    /// Refuse and install nothing: neither source names a uid, so no agent can
    /// have been started under this boot's wall.
    RefuseWithoutNet { reason: String },
}

/// Build the refusal arm the net-on-refusal predicate selects.
#[cfg(any(target_os = "linux", test))]
fn refuse_by_predicate(
    history: &ConfinedHistory,
    live: &LiveBindingSet,
    reason: String,
    uncovered_uids: Vec<u32>,
) -> BindPlan {
    if net_required_on_refusal(history, live) {
        BindPlan::RefuseWithNet {
            reason,
            uncovered_uids,
        }
    } else {
        BindPlan::RefuseWithoutNet { reason }
    }
}

/// THE WHOLE SLICE-A DECISION, as a pure function of its three inputs.
///
/// SCOPE BOUND at this line: this function itself is a pure decision over the
/// SIGNED manifest identity, the kernel-read live bindings B, and this boot's
/// history H (H is journal-derived; the caller reads it from disk before this
/// call, and the executor that later acts on the returned plan reads the
/// authentication key and persists the journal, so the boot path AROUND this
/// decision is not filesystem-free). What this line's bound is about is
/// narrower: this function reads no operator-declared account list and
/// resolves no system account. The account join belongs with the slice that
/// provisions and starts the agent account, which is the first point at which
/// such a join protects anything; adding one here would be new capability, not
/// a preserved one.
///
/// Order, and each step depends on the one before it: the armed identity, the set
/// rule over B, then this boot's history reconciliation.
#[cfg(any(target_os = "linux", test))]
fn plan_admitted_binding(
    identity: Option<&crate::decision::AdmittedIdentity>,
    live: &LiveBindingSet,
    history: &ConfinedHistory,
) -> BindPlan {
    use crate::decision::AdmittedSubject;

    // (0) THE ARMED IDENTITY. Nothing can be bound under an identity this process
    // never froze, and an unset cell is absent evidence, not passing evidence.
    let Some(identity) = identity else {
        return refuse_by_predicate(
            history,
            live,
            "the admitted identity was never frozen at boot, so the wall cannot prove which \
             uid it is supposed to bind; refusing readiness."
                .to_string(),
            Vec::new(),
        );
    };

    // (1) THE SET RULE, over the whole set B rather than over any one binding.
    let staged = match (&identity.subject, live) {
        // `Verified` under `Confined` IS the exact singleton: the set rule is
        // computed in one place (`owned_table_binding_set_from_json`) and both
        // acquisition and health apply that one answer.
        (AdmittedSubject::Confined { agent_uid, .. }, LiveBindingSet::Verified { .. }) => {
            BindPlan::Adopt {
                agent_uid: *agent_uid,
            }
        }
        (
            AdmittedSubject::Confined {
                agent_uid, ceiling, ..
            },
            LiveBindingSet::Mismatch {
                binding_count: 0, ..
            },
        ) => BindPlan::Install {
            agent_uid: *agent_uid,
            ceiling: *ceiling,
        },
        (AdmittedSubject::Unconfined, LiveBindingSet::Verified { .. }) => BindPlan::NothingToBind,
        // Any other readable B: a chain under another agent id, two chains for
        // U, a different uid, any mixture, or any live binding at all under
        // `Unconfined`.
        (_, LiveBindingSet::Mismatch { detail, .. }) => {
            return refuse_by_predicate(
                history,
                live,
                format!(
                    "{detail}; refusing readiness. Repair order: stop the wall, --disarm, start."
                ),
                Vec::new(),
            )
        }
        (_, LiveBindingSet::Unreadable { detail }) => {
            return refuse_by_predicate(
                history,
                live,
                format!(
                    "the owned table's per-agent binding set could not be read ({detail}), so \
                     the wall cannot prove which uid the kernel routes; refusing readiness."
                ),
                Vec::new(),
            )
        }
    };

    // (2) HISTORY RECONCILIATION, on every continuing path including the one that
    // binds nobody.
    //
    // INVARIANT at this line: a uid this boot bound is still potentially live, and
    // the protection about to be established covers exactly one uid. An empty live
    // table therefore proves nothing on its own — the chain and jump can be deleted
    // while the process they confined keeps running — so a historical uid the new
    // protection does not cover must take the net, not a green boot.
    let uncovered: Vec<u32> = match history_uids(history) {
        // Unknown history cannot prove which uids were bound, so it cannot prove
        // the new protection covers them.
        None => Vec::new(),
        Some(uids) => uids
            .into_iter()
            .filter(|uid| match identity.subject {
                AdmittedSubject::Confined { agent_uid, .. } => *uid != agent_uid,
                AdmittedSubject::Unconfined => true,
            })
            .collect(),
    };
    if history_uids(history).is_none() || !uncovered.is_empty() {
        let detail = if uncovered.is_empty() {
            "this boot's confined history cannot say which uids were bound, so the binding \
             about to be established cannot be proven to cover them"
                .to_string()
        } else {
            format!(
                "this boot's confined history names uid(s) {uncovered:?} that the binding about \
                 to be established does not cover, so a previously confined process may still \
                 be live with no wall in front of it"
            )
        };
        return refuse_by_predicate(
            history,
            live,
            format!(
                "{detail}; refusing readiness with reason=HistoricalUidUncovered. Repair order: \
                 stop the wall, --disarm, start."
            ),
            uncovered,
        );
    }

    // DEBT(LINUX-PR3B-TYPED-ACQUIRE-REASONS): acquisition refusal reasons travel
    // as text inside AcquireFailed; typing them touches every acquire_failed
    // consumer and is a follow-up PR.
    staged
}

/// THE REFUSAL NET's SCOPE, as a pure function of three already-read inputs.
///
/// INVARIANT at this line, and why the UNION is the floor: each of the three
/// inputs is evidence, independently obtained, that a particular uid may have a
/// live process behind the wall this refusal is about to leave standing. The
/// resolver's kill set and union carry sources (a) the pre-match journal record's
/// confined history, (b) the identity this process froze at boot and (c) the live
/// table as the resolver could read it; `uncovered_uids` carries the uids the
/// PLANNER proved the new binding would not cover; `live_binding_uids` carries
/// the binding set B the EXECUTOR already parsed. Dropping any one of them
/// narrows the net below what this process knows, which is the fail-open
/// direction: the narrowed net's other-principals rule then ACCEPTS a uid whose
/// jump was deleted while its process kept running. So the answer is never
/// narrower than the resolution the read-only resolver produced, and widening is
/// always allowed.
///
/// INVARIANT at this line, and why NO journal read or write happens here or
/// anywhere on the slice-A refusal path: a re-read can fail, and a failed read of
/// an authenticated record is indistinguishable from an absent one, which reads
/// as an EMPTY history and narrows the net. The inputs above were all read before
/// the refusal, so there is nothing left here that can fail and nothing that can
/// write a record. The journal keeps whatever the acquisition's own match arm
/// already wrote or confirmed. Register: defect.linux-pr3b-refusal-record.
///
/// A raw `u32` cannot be minted into rule 1 outside `crate::safety_net_uid` (that
/// is the point of [`crate::safety_net_uid::ConfinedUidSet`]'s privacy), so when
/// a member of the union is NOT already a validated member of the resolution's
/// identity set the answer is the host-wide shape. That is the widening
/// direction: host-wide denies that member too.
#[cfg(any(target_os = "linux", test))]
fn net_scope_for_refusal(
    resolution: &SafetyNetResolution,
    uncovered_uids: &[u32],
    live_binding_uids: &[u32],
) -> crate::nftables::SafetyNetScope {
    use crate::nftables::SafetyNetScope;
    let named = match &resolution.scope {
        // Already the widest shape: unknown history, an over-capacity union, an
        // unreadable overflow value, or an empty deny set. Nothing below may
        // narrow it, and no union member can widen it further.
        SafetyNetScope::HostWide => return SafetyNetScope::HostWide,
        SafetyNetScope::Identity(set) => set.uids(),
    };
    // The resolution's own two lists are the authenticated floor; the planner's
    // and the executor's lists are the evidence the resolver did not have. A
    // member the resolver DROPPED (an unattestable uid its validator refused) is
    // still covered, because it is not in `named` and therefore widens to
    // host-wide rather than disappearing.
    let union_is_named = resolution
        .kill_set
        .iter()
        .chain(resolution.deny_union.iter())
        .chain(uncovered_uids.iter())
        .chain(live_binding_uids.iter())
        .all(|uid| named.contains(uid));
    if union_is_named {
        resolution.scope.clone()
    } else {
        SafetyNetScope::HostWide
    }
}

/// The operator sentence for the scope a refusal ACTUALLY installs.
///
/// Delegates to the shared producer [`crate::nftables::safety_net_scope_sentence`]
/// for every pairing that producer models. The one pairing it cannot model is the
/// widening above (an identity resolution installed host-wide), which it prints as
/// a defect; that pairing is not a defect here, it is the union covering a uid the
/// resolution's validated set could not name, so it gets its own sentence.
/// Must match the repair order in `crate::nftables::SAFETY_NET_REPAIR_ORDER`.
#[cfg(any(target_os = "linux", test))]
fn refusal_scope_sentence(
    installed: &crate::nftables::SafetyNetScope,
    resolution: &SafetyNetResolution,
) -> String {
    use crate::nftables::{SafetyNetScope, SAFETY_NET_REPAIR_ORDER};
    match (installed, &resolution.scope) {
        (SafetyNetScope::HostWide, SafetyNetScope::Identity(_)) => format!(
            "the refusal must cover a uid the deny set could not name, so the net denies \
             every uid on this host; operator access is not preserved on this path. \
             {SAFETY_NET_REPAIR_ORDER}"
        ),
        _ => crate::nftables::safety_net_scope_sentence(installed, &resolution.reason),
    }
}

/// Everything a slice-A refusal needs to install the safety net.
///
/// Deliberately carries NO journal path, key path or record: the slice-A refusal
/// path neither reads nor writes the journal, and a struct with no handle to it
/// cannot. See the second invariant on [`net_scope_for_refusal`].
#[cfg(target_os = "linux")]
struct RefusalNet {
    /// The scope actually installed, from [`net_scope_for_refusal`].
    scope: crate::nftables::SafetyNetScope,
    /// The PR-3 sweep's kill set, sources (a) and (b) only, carried through from
    /// the read-only resolution.
    kill_set: Vec<u32>,
    /// The operator sentence already rendered for `scope`.
    sentence: String,
}

/// Refuse an acquisition that has already proven the table is ours, installing
/// the safety net exactly when the evidence says a uid may be live.
///
/// THE NET-ON-REFUSAL RULE's single execution site. Neither the DECISION nor the
/// SCOPE is taken here: `net` is `Some` exactly when [`net_required_on_refusal`]
/// (by way of [`plan_admitted_binding`]) said a uid may be live, and its scope
/// came from [`net_scope_for_refusal`]. This function executes.
///
/// FAILURE MODE worth stating: the install is REQUIRED, not best-effort, and a
/// failed install hooks the PR-3 sweep and still refuses readiness. There is no
/// journal write on this path at all, so there is no best-effort persist whose
/// failure could be mistaken for a failed protection.
#[cfg(target_os = "linux")]
fn refuse_after_owned_table(
    decision_engine: &DecisionEngine,
    shutdown_requested: bool,
    net: Option<RefusalNet>,
    reason: String,
) -> EnforcementError {
    let Some(net) = net else {
        return acquire_failed(format!(
            "{reason} No safety net was installed: this boot's confined history names no uid \
             and the live table carries no per-agent binding, so no agent can have been \
             started under this wall."
        ));
    };
    let RefusalNet {
        scope,
        kill_set,
        sentence,
    } = net;
    let refuse_detail = match drift_enforce_fail_closed(
        decision_engine,
        shutdown_requested,
        || crate::nftables::install_deny_all_safety_net(&scope),
        &kill_set,
        &scope,
    ) {
        DriftFailClosedOutcome::NetInstalled => {
            format!("{reason} Installed the safety net and refusing readiness. {sentence}")
        }
        // A162: a stop was already requested with no confined identity known; the
        // host-wide install was skipped rather than silencing every principal on
        // the host. `stop_time_hostwide_skip` has already ATTEMPTED the residual
        // audit row and always emitted the stderr line naming the skip (which
        // names the append failure too, if the bounded append could not
        // complete); the row itself is best-effort, not guaranteed.
        DriftFailClosedOutcome::HostWideSkippedForRequestedStop => format!(
            "{reason} A stop was already requested and no confined identity is known for \
             this boot; skipped the host-wide safety net install (register \
             LINUX-BOOT-STOP-HOSTWIDE-NET-01) rather than silencing every \
             principal on the host. Refusing readiness."
        ),
        DriftFailClosedOutcome::InstallFailedSweepHooked { net_err } => format!(
            "{reason} Safety net installation did not complete ({net_err}); refusing \
             readiness. {}",
            crate::nftables::SAFETY_NET_REPAIR_ORDER
        ),
    };
    acquire_failed(refuse_detail)
}

/// Fault-injection seam: forces the NEXT confined-uid write-ahead inside
/// [`bind_admitted_uid_before_ready`] to fail, so the Linux integration suite can
/// drive the PRODUCTION persist-failure branch (the one that refuses readiness
/// and installs the net over the pre-match evidence) without corrupting a real
/// journal or removing its key mid-boot. Mirrors `RECLAIM_OWNED_PROBE_FORCE_ERROR`
/// and the readback latch below: absent from a normal build (compiled only under
/// `test-isolation`), and cleared unconditionally by the RAII guard so a test that
/// arms it and exits early cannot leave it armed for a later test's persist.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
static AGENT_BINDING_WRITE_AHEAD_FORCE_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// RAII handle for the override above; see
/// [`force_next_agent_binding_write_ahead_error_for_test`].
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub struct ForcedAgentBindingWriteAheadError {
    _private: (),
}

#[cfg(all(target_os = "linux", feature = "test-isolation"))]
impl Drop for ForcedAgentBindingWriteAheadError {
    fn drop(&mut self) {
        AGENT_BINDING_WRITE_AHEAD_FORCE_ERROR.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Arm the override above for exactly the next write-ahead. Returns a guard that
/// clears the latch on drop; a test must bind it (not `let _ = ...`, which would
/// drop it immediately and clear the latch before the boot call it covers).
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn force_next_agent_binding_write_ahead_error_for_test() -> ForcedAgentBindingWriteAheadError {
    AGENT_BINDING_WRITE_AHEAD_FORCE_ERROR.store(true, std::sync::atomic::Ordering::SeqCst);
    ForcedAgentBindingWriteAheadError { _private: () }
}

/// A7 fail-before test seam: forces the NEXT readback inside
/// [`bind_admitted_uid_before_ready`] to read as a mismatch, regardless of what
/// the kernel actually holds, so the Linux integration suite can drive the
/// PRODUCTION readback-failure branch (the guard withholding `READY=1` when the
/// kernel does not answer back with the exact singleton) without needing a real
/// kernel divergence. Mirrors `RECLAIM_OWNED_PROBE_FORCE_ERROR`'s test-only
/// latch convention: absent from a normal build (compiled only under
/// `test-isolation`), and cleared unconditionally by the RAII guard so a test
/// that arms it and exits early cannot leave it armed for a later, unrelated
/// test's readback.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
static AGENT_BINDING_READBACK_FORCE_MISMATCH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// RAII handle for the override above. Construct with
/// [`force_next_agent_binding_readback_mismatch_for_test`] and bind it to a
/// variable that lives for the rest of the test; the latch clears when that
/// variable drops, whether the test returns normally, returns early, or
/// panics.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub struct ForcedAgentBindingReadbackMismatch {
    _private: (),
}

#[cfg(all(target_os = "linux", feature = "test-isolation"))]
impl Drop for ForcedAgentBindingReadbackMismatch {
    fn drop(&mut self) {
        AGENT_BINDING_READBACK_FORCE_MISMATCH.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Arm the override above for exactly the next agent-binding readback. Returns
/// a guard that clears the latch on drop; a test must bind it (not `let _ =
/// ...`, which would drop it immediately and clear the latch before the boot
/// call it is meant to cover).
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn force_next_agent_binding_readback_mismatch_for_test() -> ForcedAgentBindingReadbackMismatch {
    AGENT_BINDING_READBACK_FORCE_MISMATCH.store(true, std::sync::atomic::Ordering::SeqCst);
    ForcedAgentBindingReadbackMismatch { _private: () }
}

/// LINUX-BOOT-STOP-HOSTWIDE-NET-01 fail-before seam: simulates a SIGTERM landing
/// the instant [`bind_admitted_uid_before_ready`] begins its kernel and journal
/// work, the exact window the round-1 defect (a `bool` sampled by the CALLER
/// before this function was even entered) could not observe. Arming this sets
/// the SAME shared `Arc<AtomicBool>` a real signal handler sets -- it is not a
/// parallel flag -- so its effect on the refusal decision is indistinguishable
/// from a genuine signal. Absent from a normal build (compiled only under
/// `test-isolation`), and cleared unconditionally by the RAII guard so a test
/// that arms it and exits early cannot leave it armed for a later test's boot.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
static ARM_SHUTDOWN_AT_SLICE_A_REFUSE_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// RAII handle for the override above; see
/// [`arm_shutdown_at_slice_a_refuse_for_test`].
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub struct ArmedShutdownAtSliceARefuseForTest {
    _private: (),
}

#[cfg(all(target_os = "linux", feature = "test-isolation"))]
impl Drop for ArmedShutdownAtSliceARefuseForTest {
    fn drop(&mut self) {
        ARM_SHUTDOWN_AT_SLICE_A_REFUSE_FOR_TEST.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Arm the override above for exactly the next call to
/// [`bind_admitted_uid_before_ready`]. Returns a guard that clears the latch on
/// drop; a test must bind it (not `let _ = ...`, which would drop it
/// immediately and clear the latch before the boot call it covers).
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn arm_shutdown_at_slice_a_refuse_for_test() -> ArmedShutdownAtSliceARefuseForTest {
    ARM_SHUTDOWN_AT_SLICE_A_REFUSE_FOR_TEST.store(true, std::sync::atomic::Ordering::SeqCst);
    ArmedShutdownAtSliceARefuseForTest { _private: () }
}

/// Bind the admitted uid into the kernel, and prove it from the kernel, before
/// anything can report readiness.
///
/// INVARIANT this function exists to make true: `READY=1` implies the admitted
/// uid's jump is live and was READ BACK from the kernel, so a supervisor that
/// starts the agent on readiness starts it confined. Every arm either returns an
/// acquisition error (which fails the component before the readiness beacon) or
/// leaves the required binding live.
///
/// Order, and each step depends on the one before it: the table is already proven
/// ours by the caller; parse the live binding set; classify it against the armed
/// identity; reconcile this boot's confined history; set the rule; then adopt or
/// install; then read back.
///
/// This function is the EXECUTOR. Every decision in that order is taken by
/// [`plan_admitted_binding`], which is pure and is where the set rule, the
/// reconciliation and the net-on-refusal rule are tested exhaustively without a
/// kernel; what remains here is the kernel work and the failures it can suffer.
#[cfg(target_os = "linux")]
fn bind_admitted_uid_before_ready(
    ownership: &crate::nftables::CastleTableOwnership,
    decision_engine: &DecisionEngine,
    // LINUX-BOOT-STOP-HOSTWIDE-NET-01: the LIVE flag, not a sampled copy. This
    // function does real kernel and journal work (the binding-set read, the
    // journal key load, `load_agent_ruleset`) between being called and the
    // `refuse` closure's decision below; a `bool` taken here would go stale
    // across that work and could let a stop that lands mid-function install a
    // host-wide net anyway. The closure loads it fresh at the decision instead.
    shutdown_requested: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    journal_path: &std::path::Path,
    key_path: &std::path::Path,
    existing: Option<&crate::ownership_journal::OwnershipJournal>,
    boot_id: &str,
) -> Result<(), EnforcementError> {
    use crate::nftables::{AgentRulesetId, AgentUidBinding, OwnedBindingSet};
    use crate::ownership_journal::{self as journal, ConfinedRole};

    // TEST-ISOLATION ONLY, fail-before seam: simulates a SIGTERM landing the
    // instant this function begins, before any of the kernel/journal work below
    // runs. See `arm_shutdown_at_slice_a_refuse_for_test`.
    #[cfg(all(target_os = "linux", feature = "test-isolation"))]
    if ARM_SHUTDOWN_AT_SLICE_A_REFUSE_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst) {
        shutdown_requested.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // H, computed ONCE from the PRE-MATCH record and scoped to this boot id, and
    // the whole reason it is named here rather than inlined: it decides WHETHER a
    // refusal installs a net, and nothing else. A re-read after a fresh create
    // would already name the admitted uid (the create's own write-ahead put it
    // there), so a refusal on a table that never bound anyone would install a net
    // on every fresh refusal.
    //
    // NO refusal below writes the journal, and none re-reads it: the record this
    // acquisition's own match arm wrote or confirmed stands, and the net's scope
    // comes from `net_scope_for_refusal` over evidence already in hand. See the
    // second invariant on that function for why a re-read here was the fail-open
    // shape.
    let history_for_net_decision = this_boot_confined_history(existing, boot_id);

    let identity = decision_engine.armed_identity();
    let expectation = current_expected_agent_binding(decision_engine);

    // B, the live set of `(agent_id, uid)` bindings, reduced to what the decision
    // consults. The table has already been read once to prove it is ours; this is
    // the read that says what it ROUTES.
    let mut live_set_inventory: Option<Vec<(String, u32)>> = None;
    let live = match crate::nftables::owned_table_binding_set(ownership, &expectation) {
        Ok(set) => {
            // |B| is read through the ONE accessor that answers it for both
            // outcomes, so the count the net decision consults cannot diverge
            // between the verified and the mismatching arm.
            let binding_count = set.inventory().bindings.len();
            live_set_inventory = Some(set.inventory().bindings.clone());
            match set {
                OwnedBindingSet::Verified(_) => LiveBindingSet::Verified { binding_count },
                OwnedBindingSet::UidMismatch { detail, .. } => LiveBindingSet::Mismatch {
                    binding_count,
                    detail,
                },
            }
        }
        Err(err) => LiveBindingSet::Unreadable {
            detail: err.to_string(),
        },
    };

    // B's UIDS, kept from the parse above rather than re-read at the refusal.
    // The resolver's source (c) reads the live table a SECOND time and yields
    // nothing when that read fails, so a uid the executor has already seen
    // routed would drop out of the net on exactly the schedule where the table
    // is misbehaving. Must match the inventory the set rule consults.
    let live_binding_uids: Vec<u32> = match &live_set_inventory {
        Some(bindings) => bindings.iter().map(|(_agent, uid)| *uid).collect(),
        None => Vec::new(),
    };

    // THE ONE PLACE a slice-A refusal's net scope is computed, shared by every
    // arm below. The resolution is read-only (it takes the PRE-MATCH record this
    // function was handed and never opens the journal), and the union with the
    // planner's uncovered uids and B is what keeps the installed scope at or
    // above the authenticated floor. See `net_scope_for_refusal`.
    let refuse = |install_net: bool, uncovered_uids: &[u32], reason: String| -> EnforcementError {
        // Loaded HERE, at the decision, not captured from the caller: this is
        // after scope resolution and immediately before `refuse_after_owned_table`
        // may issue an nft transaction, so a stop that arrives anywhere earlier
        // in this function's kernel/journal work is still observed.
        let shutdown_requested_now = shutdown_requested.load(std::sync::atomic::Ordering::SeqCst);
        if !install_net {
            return refuse_after_owned_table(decision_engine, shutdown_requested_now, None, reason);
        }
        let resolution = resolve_net_scope_at_site(existing, decision_engine);
        let scope = net_scope_for_refusal(&resolution, uncovered_uids, &live_binding_uids);
        let sentence = refusal_scope_sentence(&scope, &resolution);
        refuse_after_owned_table(
            decision_engine,
            shutdown_requested_now,
            Some(RefusalNet {
                scope,
                kill_set: resolution.kill_set,
                sentence,
            }),
            reason,
        )
    };

    // EVERY decision this slice makes is taken here, by a pure function whose
    // tests run on any platform. Below this line the code only executes a plan.
    let plan = plan_admitted_binding(identity, &live, &history_for_net_decision);

    let (agent_uid, ceiling, install_required) = match plan {
        BindPlan::RefuseWithNet {
            reason,
            uncovered_uids,
        } => return Err(refuse(true, &uncovered_uids, reason)),
        BindPlan::RefuseWithoutNet { reason } => return Err(refuse(false, &[], reason)),
        BindPlan::NothingToBind => return Ok(()),
        BindPlan::Adopt { agent_uid } => (agent_uid, 0, false),
        BindPlan::Install { agent_uid, ceiling } => (agent_uid, ceiling, true),
    };
    // The identity is `Some` on every continuing plan: the pure function refuses
    // an unset cell before it can stage one.
    let Some(identity) = identity else {
        return Err(acquire_failed(
            "internal: a continuing binding plan was produced with no armed identity".to_string(),
        ));
    };

    // THE NET DECISION FOR A FAILURE THAT HAPPENS WHILE EXECUTING THE PLAN.
    // Computed from the same predicate and the same two inputs the plan's own
    // refusals used, so a failure at the kernel step cannot answer the question
    // differently from a refusal the plan itself took. A literal here would be
    // the fail-open answer: H can name a uid whose jump was deleted, and that uid
    // is left over `policy accept` if the net is skipped.
    let net_required_mid_plan = net_required_on_refusal(&history_for_net_decision, &live);

    if install_required {
        let key = match journal::load_or_generate_auth_key(key_path) {
            Ok(key) => key,
            Err(err) => {
                // NOTHING has been written and nothing bound, so the same two
                // sources the plan consulted still decide the net.
                return Err(refuse(
                    net_required_mid_plan,
                    &[],
                    format!(
                        "the journal authentication key is unusable ({err}) so the admitted \
                         uid cannot be written ahead of the kernel bind; refusing readiness."
                    ),
                ));
            }
        };
        // WRITE AHEAD, then bind. The receipt is the kernel loader's required
        // proof that the journal already names this uid: a crash between the
        // two must leave the journal naming MORE than the kernel, never less.
        // TEST-ISOLATION SEAM: a forced error is folded into the SAME `Result` the
        // real persist returns, BEFORE the branch below, so a test that arms it
        // exercises the identical production refusal a genuine journal failure
        // takes, never a parallel test-only path. See
        // `force_next_agent_binding_write_ahead_error_for_test`.
        #[cfg(all(target_os = "linux", feature = "test-isolation"))]
        let forced_write_ahead_error =
            AGENT_BINDING_WRITE_AHEAD_FORCE_ERROR.swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(all(target_os = "linux", feature = "test-isolation")))]
        let forced_write_ahead_error = false;
        let persisted = if forced_write_ahead_error {
            Err(journal::OwnershipJournalError::UnsafeJournal {
                path: journal_path.to_path_buf(),
                reason: "test-isolation: confined-uid write-ahead forced to fail".to_string(),
            })
        } else {
            journal::persist_confined_uid_write_ahead(
                journal_path,
                &key,
                agent_uid,
                ConfinedRole::Agent,
            )
        };
        let receipt = match persisted {
            Ok(receipt) => receipt,
            Err(err) => {
                // The persist FAILED, so no uid was made live by this process and
                // the pre-match history decides the net. It is the PREDICATE that
                // decides, not this arm: H can already name a uid whose jump was
                // deleted before this start, and that uid is still live.
                return Err(refuse(
                    net_required_mid_plan,
                    &[],
                    format!(
                        "the admitted uid {agent_uid} could not be written into this boot's \
                         confined history ({err}), so it must not be bound; refusing \
                         readiness."
                    ),
                ));
            }
        };
        // SAFETY: stderr is the journald channel the drill's L-A3 leg greps for
        // the write-ahead step. Emitted ONLY from a receipt the persist returned,
        // so the line is evidence the journal named the uid before the kernel did.
        eprintln!(
            "{AGENT_BINDING_WRITE_AHEAD_LINE_PREFIX} uid={agent_uid} agent={}",
            crate::nftables::confined_agent_id(agent_uid)
        );
        let agent_id = crate::nftables::confined_agent_id(agent_uid);
        let ruleset = crate::nftables::build_agent_ruleset(&agent_id, agent_uid, &[]);
        if let Err(err) = crate::nftables::load_agent_ruleset(
            &AgentRulesetId {
                agent_id: agent_id.clone(),
                // From the CELL, not from a fresh store read: the fortress id is a
                // seal input, and a seal computed under a value that could differ
                // from the one the boot froze would not verify on the next reclaim.
                fortress_id: identity.fortress_id.clone(),
            },
            &ruleset,
            AgentUidBinding {
                agent_uid,
                system_uid_allow_ceiling: ceiling,
            },
            receipt,
        ) {
            // The write-ahead SUCCEEDED, so the journal now names this uid even
            // though the kernel step did not complete. The net is unconditional
            // here BY CONSTRUCTION, not by a skipped predicate: a uid that has
            // been written ahead may be bound, so the answer over CURRENT evidence
            // is yes whatever the pre-match predicate said. The SCOPE still covers
            // it: `agent_uid` is source (b) of the resolution, which reads the
            // frozen identity cell.
            return Err(refuse(
                true,
                &[],
                format!(
                    "the admitted uid {agent_uid} was written into this boot's confined \
                     history but the kernel binding did not load ({err}); refusing readiness."
                ),
            ));
        }
    }

    // READBACK. The claim is about what the KERNEL holds, so it is proven by
    // re-reading the kernel, never by the fact that the load returned Ok.
    //
    // TEST-ISOLATION SEAM: a forced mismatch is folded into `readback_failure`
    // BEFORE the branch below, so a test that arms it exercises the identical
    // production refusal a genuine kernel divergence takes, never a parallel
    // test-only path. See `force_next_agent_binding_readback_mismatch_for_test`.
    #[cfg(all(target_os = "linux", feature = "test-isolation"))]
    let forced_readback_mismatch =
        AGENT_BINDING_READBACK_FORCE_MISMATCH.swap(false, std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(all(target_os = "linux", feature = "test-isolation")))]
    let forced_readback_mismatch = false;
    let readback_failure: Option<String> = if forced_readback_mismatch {
        Some("test-isolation: agent-binding readback forced to mismatch".to_string())
    } else {
        match crate::nftables::owned_table_binding_set(ownership, &expectation) {
            Ok(OwnedBindingSet::Verified(_)) => None,
            Ok(OwnedBindingSet::UidMismatch { detail, .. }) => Some(detail),
            Err(err) => Some(err.to_string()),
        }
    };
    if let Some(detail) = readback_failure {
        // The net is unconditional here BY CONSTRUCTION: either the write-ahead
        // above just named this uid in the journal, or the plan adopted a live
        // singleton that names it in the kernel. Both make the answer over CURRENT
        // evidence yes whatever the pre-match predicate said. The SCOPE covers the
        // uid either way: it is source (b) on the first and source (c) plus B on
        // the second.
        return Err(refuse(
            true,
            &[],
            format!(
                "the admitted uid's binding did not read back from the kernel ({detail}); \
                 refusing readiness."
            ),
        ));
    }
    // SAFETY: stderr is the journald channel this daemon's readiness evidence is
    // ordered on. The line is emitted ONLY from the readback result above, so its
    // timestamp is evidence the kernel answered before the readiness beacon; a
    // line emitted anywhere else would make that ordering meaningless.
    eprintln!(
        "{AGENT_BINDING_READBACK_LINE_PREFIX} uid={agent_uid} agent={}",
        crate::nftables::confined_agent_id(agent_uid)
    );
    Ok(())
}

impl ComponentProvider for NftablesTableProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::NftablesTable
    }

    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
        #[cfg(target_os = "linux")]
        {
            use crate::nftables::CastleTableOwnership;
            use crate::ownership_journal::{self as journal, ReclaimDecision};

            // 1) Take the HOST-GLOBAL ownership lock BEFORE any nftables call or
            //    journal read. A second daemon (even with a different fortress id)
            //    contends on the same path and gets AlreadyHeld, so it refuses
            //    here — before it touches the shared table.
            let lock = crate::runtime_lock::HostRuntimeLock::acquire(&self.lock_path)
                .map_err(|err| acquire_failed(err.to_string()))?;

            // 2) Read the durable, AUTHENTICATED ownership journal and the
            //    live-table presence UNDER the lock. The journal is what lets a
            //    restart tell THIS daemon's own interrupted/owned table apart from
            //    foreign state, so a crash between create and finalize does not
            //    wedge restart forever, and a foreign table is never adopted or
            //    clobbered. A strict, non-empty boot id is required first: an
            //    unreadable/empty boot id is a hard activation error (blocker 4),
            //    never an empty string a prior-boot record could match.
            let boot_id = match journal::current_boot_id() {
                Ok(b) => b,
                Err(err) => {
                    drop(lock);
                    return Err(acquire_failed(format!(
                        "could not read a valid Linux boot id: {err}"
                    )));
                }
            };
            let source = journal::current_source();
            let journal_path = self.journal_path.as_path();
            let key_path = self.journal_key_path.as_path();
            // The authentication key: present -> use it; absent (first boot) ->
            // load() returns None-safe and we generate one before the first store.
            // A present-but-unsafe key is a hard error (fail-closed).
            let key_opt = match journal::read_auth_key(key_path) {
                Ok(k) => k,
                Err(err) => {
                    drop(lock);
                    return Err(acquire_failed(format!(
                        "journal authentication key unusable: {err}"
                    )));
                }
            };
            // Load + AUTHENTICATE the journal. A present journal with a missing
            // key, a MAC mismatch, or a corrupt record is a HARD ERROR here
            // (blocker 3): it fails the acquisition closed rather than falling
            // through to a fresh create that could clobber live owned state.
            let existing = match journal::load(journal_path, key_opt.as_ref()) {
                Ok(j) => j,
                Err(err) => {
                    drop(lock);
                    return Err(acquire_failed(format!(
                        "could not read/authenticate the ownership journal: {err}"
                    )));
                }
            };
            let table_present = match crate::nftables::table_exists() {
                Ok(p) => p,
                Err(err) => {
                    drop(lock);
                    return Err(acquire_failed(format!(
                        "could not determine sanctuary-castle table existence: {err}"
                    )));
                }
            };

            // THE NEVER-ADOPT RULE, applied HERE and only here (memo D1b step 6).
            //
            // A same-boot `Owned` record whose `confined` key is ABSENT cannot prove
            // which uids were bound during this boot, so this acquisition must not adopt
            // its table however well the live identity matches: adopting would write a
            // history naming only the CURRENT identity, marking this boot known, and a
            // uid this daemon rotated away from would then be omitted from the net on
            // the next start.
            //
            // It is ACQUISITION-SPECIFIC on purpose. The disarm verb consumes the same
            // shared `journal::decide` routing, and a legacy record whose live table is
            // the recognised net must still reach disarm's `ReclaimOwned` arm to be
            // cleared. Putting the rule in `decide` would take that arm away. Must match
            // the `ReclaimOwned` arm in `disarm_castle_runtime`, which PR-2 extends.
            let decision = journal::decide(existing.as_ref(), table_present, &boot_id, &source);
            let history_unknown_this_boot = matches!(
                existing.as_ref(),
                Some(crate::ownership_journal::OwnershipJournal::Owned { confined: None, .. })
            );
            let decision = match (&decision, history_unknown_this_boot) {
                (ReclaimDecision::ReclaimOwned { .. }, true) => {
                    // Route to the boot owner instead: it installs the host-wide net for
                    // the unknown-history reason and skips the persist entirely.
                    ReclaimDecision::ReArmLostOwned
                }
                _ => decision,
            };
            let ownership = match decision {
                // A live table our Owned journal describes for THIS boot:
                // re-verify the EXACT identity (handles + marker + pristine
                // shape) still holds, then reclaim it. A drift (replaced,
                // mutated) refuses WITHOUT deleting — never clobber by name.
                ReclaimDecision::ReclaimOwned {
                    table_handle,
                    base_chain_handle,
                    marker,
                } => {
                    let owned = CastleTableOwnership {
                        table_handle,
                        base_chain_handle,
                        marker,
                    };
                    // Reclaim/adoption is one of the three sites the design
                    // names for the trusted manifest comparison: a table
                    // preserved across a restart may carry a per-agent binding
                    // this process did not install, so it is adopted only if its
                    // uid still equals the one the CURRENT signed manifest
                    // confines.
                    let expectation = current_expected_agent_binding(&self.decision_engine);
                    if let Err(err) = crate::nftables::verify_and_register_owned_table_for_reclaim(
                        &owned,
                        &expectation,
                    ) {
                        // GF1: the journal proves we own this table for THIS
                        // boot, but the LIVE table DRIFTED off the captured
                        // identity (external nft edit). Do NOT exit leaving a
                        // possibly `policy accept` base chain in force -- that is
                        // the fail-OPEN window this fix closes. Force deny-all
                        // FIRST, then refuse; systemd restarts into the same
                        // fail-CLOSED state until an operator repairs the wall.
                        // We reach this only WITH an authenticated ownership
                        // proof for this boot and `install_deny_all` only ever
                        // rewrites OUR named table, so this never clobbers a
                        // table we cannot prove is ours (RefuseForeign, which has
                        // no such proof, still never installs deny-all).
                        //
                        // A net-install failure refuses readiness and retains the
                        // table for the disarm verb. This acquisition path never
                        // deletes a table by name; D5 owns the separate escalation.
                        // MEMO D1b STEP 7, the two BOOT rows, which differ only in
                        // whether this boot's history is known:
                        //
                        //  * KNOWN HISTORY: persist the kill set BEST-EFFORT, then
                        //    install the net REGARDLESS of the persist result, then the
                        //    sweep hook on a failed install, then return the acquisition
                        //    error naming any persist failure. Installing makes no uid
                        //    live, so a failed persist must never stop the install; the
                        //    live table's bindings recover the set on the next start.
                        //  * ABSENT KEY: NEVER persist (a write would turn unknown
                        //    history into known history and let a rotated-away uid out),
                        //    install host-wide, the hook on a failed install, return.
                        //
                        // The resolver returns the host-wide scope with the
                        // `unknown-history` reason for the absent-key case, so the
                        // persist is skipped by checking that reason, not by a second
                        // read of the journal.
                        let resolution =
                            resolve_net_scope_at_site(existing.as_ref(), &self.decision_engine);
                        let mut persist_failure: Option<String> = None;
                        if resolution.reason != crate::nftables::SafetyNetReason::UnknownHistory {
                            if let Some(record) = existing.as_ref() {
                                let admitted = admitted_identity(&self.decision_engine);
                                if let Err(err) = persist_kill_set_write_ahead(
                                    journal_path,
                                    key_opt.as_ref(),
                                    record,
                                    &resolution.kill_set,
                                    admitted,
                                ) {
                                    persist_failure = Some(err);
                                }
                            }
                        }
                        let scope_sentence = crate::nftables::safety_net_scope_sentence(
                            &resolution.scope,
                            &resolution.reason,
                        );
                        let (refuse_detail, net_installed) = match drift_enforce_fail_closed(
                            &self.decision_engine,
                            self.shutdown_requested
                                .load(std::sync::atomic::Ordering::SeqCst),
                            || crate::nftables::install_deny_all_safety_net(&resolution.scope),
                            &resolution.kill_set,
                            &resolution.scope,
                        ) {
                            DriftFailClosedOutcome::NetInstalled => (
                                format!(
                                    "journal marks an owned table but the live table no longer \
                                 matches the captured identity; installed the safety net and \
                                 refusing to adopt or clobber the drifted table: {err}. \
                                 {scope_sentence}"
                                ),
                                true,
                            ),
                            // A162: a stop was already requested with no confined identity
                            // known for this boot; the host-wide install was skipped rather
                            // than silencing every principal on the host. Not a failure:
                            // `stop_time_hostwide_skip` has already ATTEMPTED the residual
                            // audit row and always emitted the stderr line naming the skip
                            // (which names the append failure too, if the bounded append
                            // could not complete); the row itself is best-effort.
                            DriftFailClosedOutcome::HostWideSkippedForRequestedStop => (
                                format!(
                                    "journal marks an owned table but the live table no longer \
                                 matches the captured identity; a stop was already requested \
                                 and no confined identity is known for this boot, so the \
                                 host-wide safety net install was skipped (register \
                                 LINUX-BOOT-STOP-HOSTWIDE-NET-01) rather than silencing every \
                                 principal on the host: {err}."
                                ),
                                false,
                            ),
                            DriftFailClosedOutcome::InstallFailedSweepHooked { net_err } => (
                                format!(
                                    "owned kernel runtime could not be verified; safety net \
                                     installation did not complete ({net_err}); refusing \
                                     readiness: {err}. {}",
                                    crate::nftables::SAFETY_NET_REPAIR_ORDER
                                ),
                                false,
                            ),
                        };
                        let refuse_detail = match persist_failure {
                            None => refuse_detail,
                            Some(persist_err) if net_installed => format!(
                                "{refuse_detail} The confined history could not be written to \
                                 the journal ({persist_err}); the next start retries the write."
                            ),
                            Some(persist_err) => format!(
                                "{refuse_detail} The confined history could not be written to \
                                 the journal ({persist_err})."
                            ),
                        };
                        drop(lock);
                        return Err(acquire_failed(refuse_detail));
                    }
                    owned
                }
                // An interrupted (Preparing) acquisition for THIS boot with a
                // live table: it is ours only if the marker matches. Capture the
                // handles (which proves the marker), then finalize the journal.
                ReclaimDecision::FinalizeInterrupted { marker } => {
                    let owned = match crate::nftables::capture_owned_castle_table(&marker) {
                        Ok(o) => o,
                        Err(capture_err) => {
                            // GF1.1 create-failure recovery. The journal is
                            // Preparing for THIS boot but the live table is not a
                            // capturable owned table. If it is exactly this
                            // daemon's OWN deny-all safety net (unmarked
                            // `policy drop`, no rules/agents), we are in the
                            // create-failed-then-ReArmLostOwned state: the first
                            // pass wrote Preparing, `create` failed (or crashed
                            // before it), the next pass saw no table + Preparing
                            // -> ReArmLostOwned -> armed the deny-all net, and
                            // this pass now sees that net + Preparing. Before this
                            // fix that wedged (capture fails, neither acquire nor
                            // --disarm could recover). The authenticated
                            // Preparing-this-boot journal + the exact net shape is
                            // the "this boot + source" proof the daemon created
                            // it, so RECOVER: mint a fresh marker, record a fresh
                            // Preparing, then ATOMICALLY reset the net to a fresh
                            // owned table (deny-all held until the owned wall is up
                            // in one nft transaction), then capture + finalize. No
                            // agents exist in this state, so no per-agent jump is
                            // lost. A foreign same-shape swap in the window is the
                            // inherent CAP_NET_ADMIN bound (GF1.4), fail-closed
                            // either way.
                            match crate::nftables::live_table_is_deny_all_safety_net() {
                                Ok(true) => {
                                    match recover_from_deny_all_net(
                                        journal_path,
                                        key_path,
                                        &boot_id,
                                        &source,
                                        admitted_identity(&self.decision_engine),
                                    ) {
                                        Ok(recovered) => recovered,
                                        Err(recover_err) => {
                                            drop(lock);
                                            return Err(recover_err);
                                        }
                                    }
                                }
                                // Not our net (a genuine marker mismatch / foreign
                                // table, or the shape probe could not prove it):
                                // REFUSE without deleting and LEAVE the Preparing
                                // journal, so a later restart can retry rather than
                                // strand our own table as unprovable.
                                Ok(false) => {
                                    drop(lock);
                                    return Err(acquire_failed(format!(
                                            "an interrupted acquisition's marker does not match the \
                                             live sanctuary-castle table and it is not this daemon's \
                                             deny-all net; refusing to adopt or clobber it: \
                                             {capture_err}"
                                        )));
                                }
                                Err(probe_err) => {
                                    drop(lock);
                                    return Err(acquire_failed(format!(
                                        "an interrupted acquisition could not be captured \
                                             ({capture_err}) and the deny-all-net recovery probe \
                                             failed ({probe_err}); refusing without clobbering"
                                    )));
                                }
                            }
                        }
                    };
                    // If we recovered above, the journal is already the fresh
                    // Owned record; finalize_owned is idempotent (rewrites Owned
                    // with the captured handles) so re-running it is safe.
                    finalize_owned(
                        journal_path,
                        key_path,
                        &owned,
                        &boot_id,
                        &source,
                        admitted_identity(&self.decision_engine),
                    )?;
                    owned
                }
                // A live table with no ownership proof: refuse, never delete.
                ReclaimDecision::RefuseForeign => {
                    drop(lock);
                    return Err(acquire_failed(
                        "a sanctuary-castle nftables table exists with no matching ownership \
                         journal; refusing to adopt, mutate, or clobber it (no ownership proof)",
                    ));
                }
                // GF1 (the load-bearing fail-closed fix): the journal proves
                // this daemon owned (or was mid-prepare of) a table THIS boot,
                // but the live table has VANISHED (external `nft delete table`
                // with agents live). `FreshCreate` would reinstall an empty
                // `policy accept` base chain with no agent jumps, so every live
                // cgroup member would egress with NO verdict (fail-OPEN). There
                // is no durable agent registry to reconstruct per-agent jumps,
                // so apply the contract's fallback: DROP ALL egress for the
                // owned scopes. Install deny-all, then refuse readiness rather
                // than present an unowned `policy drop` table as a verified
                // wall; systemd restarts into the same deny-all state until the
                // wall is repaired.
                ReclaimDecision::ReArmLostOwned => {
                    // MEMO D1b STEP 7, the same two BOOT rows as the drift site: the
                    // owned table vanished while the journal still asserts ownership, so
                    // agents adopted earlier in this boot may still be live. Persist the
                    // kill set best-effort unless the history is unknown, then install
                    // REGARDLESS of the persist result.
                    let resolution =
                        resolve_net_scope_at_site(existing.as_ref(), &self.decision_engine);
                    let mut persist_failure: Option<String> = None;
                    if resolution.reason != crate::nftables::SafetyNetReason::UnknownHistory {
                        if let Some(record) = existing.as_ref() {
                            let admitted = admitted_identity(&self.decision_engine);
                            if let Err(err) = persist_kill_set_write_ahead(
                                journal_path,
                                key_opt.as_ref(),
                                record,
                                &resolution.kill_set,
                                admitted,
                            ) {
                                persist_failure = Some(err);
                            }
                        }
                    }
                    let scope_sentence = crate::nftables::safety_net_scope_sentence(
                        &resolution.scope,
                        &resolution.reason,
                    );
                    // Named once, reused by every one of this arm's exit branches, so the
                    // persist-failure note is worded identically whether the net installed,
                    // failed to install, or was skipped under A162.
                    let persisted = match &persist_failure {
                        None => String::new(),
                        Some(err) => format!(
                            " The confined history could not be written to the journal \
                             ({err}); the next start retries the write."
                        ),
                    };
                    // A162: a stop was already requested and this boot's history names no
                    // confined identity (HostWide scope); skip the host-wide install rather
                    // than silencing every principal on the host on an ordinary stop that
                    // merely raced boot. `stop_time_hostwide_skip` has already ATTEMPTED the
                    // residual audit row (best-effort: its own stderr line names the append
                    // failure if the write could not complete) and always emitted its
                    // stderr line naming the skip.
                    if stop_time_hostwide_skip(
                        &self.decision_engine,
                        self.shutdown_requested
                            .load(std::sync::atomic::Ordering::SeqCst),
                        &resolution.scope,
                    ) {
                        drop(lock);
                        return Err(acquire_failed(format!(
                            "owned sanctuary-castle table vanished (external delete) while the \
                             ownership journal still asserts ownership; a stop was already \
                             requested and no confined identity is known for this boot, so the \
                             host-wide safety net install was skipped (register \
                             LINUX-BOOT-STOP-HOSTWIDE-NET-01) rather than silencing every \
                             principal on the host; refusing readiness until the wall is \
                             repaired. {scope_sentence}{persisted}"
                        )));
                    }
                    if let Err(err) =
                        crate::nftables::install_deny_all_safety_net(&resolution.scope)
                    {
                        // The sweep hook fires ONLY after a failed install.
                        safety_net_sweep_hook_pr3(
                            &resolution.kill_set,
                            Some(&resolution.scope),
                            "boot-time owned-table loss: the safety net install failed",
                        );
                        drop(lock);
                        return Err(acquire_failed(format!(
                            "owned kernel runtime could not be verified; safety net installation \
                             did not complete ({err}); refusing readiness. {}",
                            crate::nftables::SAFETY_NET_REPAIR_ORDER
                        )));
                    }
                    drop(lock);
                    // The net is in the kernel. Refuse readiness and name the scope, so
                    // an operator reading the journal knows immediately whether their own
                    // session is affected, and name any persist failure, which the next
                    // start retries.
                    return Err(acquire_failed(format!(
                        "owned sanctuary-castle table vanished (external delete) while the \
                         ownership journal still asserts ownership; installed the safety net \
                         and refusing readiness until the wall is repaired, never re-arming \
                         policy accept. {scope_sentence}{persisted}"
                    )));
                }
                // No live table: fresh acquisition via prepare -> atomic create
                // -> capture/verify -> finalize.
                ReclaimDecision::FreshCreate => fresh_acquire(
                    journal_path,
                    key_path,
                    &boot_id,
                    &source,
                    admitted_identity(&self.decision_engine),
                )?,
            };

            // Runtime ownership is activated BEFORE the binding is loaded, not
            // after: `load_agent_ruleset` refuses a production mutation that has
            // no authenticated active ownership identity, so the order here is a
            // precondition of the bind rather than bookkeeping. An isolated table
            // skips that check, which is why a macOS or isolated run cannot show
            // the miss. The order is pinned at the SOURCE by
            // `runtime_ownership_is_activated_before_the_agent_ruleset_is_loaded`;
            // no test in this repo observes it at runtime today.
            crate::nftables::activate_runtime_ownership(&ownership).map_err(|err| {
                acquire_failed(format!(
                    "could not activate authenticated nft ownership: {err}"
                ))
            })?;

            // SLICE A: bind the admitted uid and read it back from the kernel.
            // Everything after this point runs only if the wall is holding the
            // identity it was armed with, so the readiness beacon below can mean
            // "an agent started now starts confined".
            if let Err(err) = bind_admitted_uid_before_ready(
                &ownership,
                &self.decision_engine,
                &self.shutdown_requested,
                journal_path,
                key_path,
                existing.as_ref(),
                &boot_id,
            ) {
                drop(lock);
                return Err(err);
            }

            // Seed the retained deny set from the resolution this acquisition just
            // computed, so a later loss installs the net from an IN-MEMORY set rather
            // than depending on a journal read that may itself be failing.
            // A host-wide scope has no rules, but its full union must survive
            // for every later retry in this process.
            let seeded = resolve_net_scope_at_site(existing.as_ref(), &self.decision_engine)
                .retained_deny_uids()
                .to_vec();
            Ok(Box::new(NftablesTableComponent {
                lock: Some(lock),
                ownership,
                decision_engine: Arc::clone(&self.decision_engine),
                probe: crate::health_probe::BoundedHealthProbe::new(nft_health_budget()),
                released: false,
                journal_path: journal_path.to_path_buf(),
                journal_key_path: key_path.to_path_buf(),
                retained_deny_uids: std::sync::Mutex::new(seeded),
                recovering: std::sync::atomic::AtomicBool::new(false),
                last_recovery_attempt: std::sync::Mutex::new(None),
                last_safety_net_state: std::sync::Mutex::new(
                    crate::nftables::SafetyNetAuditState::NotAttempted,
                ),
                shutdown_requested: Arc::clone(&self.shutdown_requested),
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No nftables on this host: fail-before so the plan lands
            // ControlPlaneOnly rather than reporting a table it cannot install.
            let _ = (
                &self.lock_path,
                &self.journal_path,
                &self.journal_key_path,
                &self.decision_engine,
                &self.shutdown_requested,
            );
            Err(EnforcementError::NotAvailableOnPlatform(
                ComponentKind::NftablesTable.as_str(),
            ))
        }
    }
}

/// Fresh acquisition: `Preparing` journal -> atomic `create` -> capture+verify
/// handles -> `Owned` journal (finalize). Each kernel mutation is bracketed by a
/// durable, authenticated journal write so every crash boundary is recoverable.
/// (blockers 1, 3)
///
/// Fail-closed preservation: NO failure path here deletes the created table or
/// clears the ownership record. A finalize failure leaves the created table plus
/// the `Preparing` record (whose marker matches the live table), so a restart
/// RECLAIMS via `FinalizeInterrupted` rather than seeing a rolled-back orphan; a
/// create failure created nothing atomically and leaves the `Preparing` record,
/// which a later `FreshCreate` overwrites once the raced foreign state clears.
/// Deletion is reserved for the explicit disarm path (blocker 1/2).
#[cfg(target_os = "linux")]
fn fresh_acquire(
    journal_path: &std::path::Path,
    key_path: &std::path::Path,
    boot_id: &str,
    source: &str,
    // The identity the current signed manifest admits, threaded in so the journal
    // records it BEFORE the kernel step that can make the uid live.
    admitted: Option<(u32, Option<u32>)>,
) -> Result<crate::nftables::CastleTableOwnership, EnforcementError> {
    use crate::ownership_journal::{self as journal, JournalIdentity, OwnershipJournal};

    // Resolve (or first-boot generate) the MAC key under the StateDirectory. A
    // present-but-unsafe key is a hard error (fail-closed).
    let key = journal::load_or_generate_auth_key(key_path)
        .map_err(|err| acquire_failed(format!("journal authentication key unusable: {err}")))?;

    let marker = new_owner_marker()?;
    let identity = JournalIdentity {
        schema_version: journal::JOURNAL_SCHEMA_VERSION,
        marker: marker.clone(),
        boot_id: boot_id.to_string(),
        source: source.to_string(),
    };
    // Prepare BEFORE the kernel mutation: if we crash after create but before
    // finalize, this record (with our marker) is what lets the restart prove the
    // orphaned table is ours and reclaim it instead of refusing it forever.
    let preparing = OwnershipJournal::Preparing {
        identity: identity.clone(),
    };
    if let Err(err) = journal::store_atomic(journal_path, &preparing, &key) {
        return Err(acquire_failed(format!(
            "could not durably record the Preparing ownership journal before create: {err}"
        )));
    }

    // Atomic create with fail-on-exists `create` verbs. A raced foreign table
    // makes this fail; the transaction was atomic so we created NOTHING. We do
    // NOT clear the Preparing record: clearing an ownership record is reserved for
    // the disarm path (blocker 2). The record is harmless — a later `FreshCreate`
    // (no table present) overwrites it, and while a foreign table stands the
    // restart refuses fail-closed rather than clobbering it.
    if let Err(err) = crate::nftables::create_castle_table_exclusive(&marker) {
        return Err(acquire_failed(format!(
            "atomic create of the sanctuary-castle table failed (a raced foreign table would \
             make `create` fail here); created nothing, refusing: {err}"
        )));
    }

    // Capture + verify the exact owned identity. On failure we DID create a
    // table but cannot prove its identity: leave the Preparing record and the
    // table (refuse rather than clobber) so a restart can retry the capture.
    let owned = match crate::nftables::capture_owned_castle_table(&marker) {
        Ok(o) => o,
        Err(err) => {
            return Err(acquire_failed(format!(
                "created the table but could not capture/verify its owned identity; leaving it \
                 for a restart to reclaim rather than deleting unprovable state: {err}"
            )));
        }
    };

    // Finalize: record Owned durably. If this fails we do NOT roll back
    // (blocker 1): the created table + the Preparing record survive, so a restart
    // reclaims via FinalizeInterrupted (marker match) and re-finalizes. Deleting
    // here would violate fail-closed preservation of an acquired enforcement
    // object.
    // WRITE-AHEAD at a fresh create: the record carries the admitted identity
    // before any per-agent binding can make that uid live.
    let record = owned_record_preserving_history(
        journal_path,
        &key,
        identity,
        owned.table_handle,
        owned.base_chain_handle,
        admitted,
    )?;
    if let Err(err) = journal::store_atomic(journal_path, &record, &key) {
        return Err(acquire_failed(format!(
            "could not durably finalize the Owned ownership journal; preserving the created \
             table + Preparing record for a restart to reclaim (no rollback): {err}"
        )));
    }
    Ok(owned)
}

/// GF1.1 create-failure recovery. Called ONLY when the authenticated journal is
/// `Preparing` for this boot AND the live table has been positively recognized as
/// this daemon's own deny-all safety net (unmarked `policy drop`, no rules). That
/// is the wedge state a create failure (or a crash after Preparing before create)
/// leaves once ReArmLostOwned arms the net: `capture` fails forever and neither
/// acquire nor `--disarm` could previously recover.
///
/// Recovery mints a fresh marker, records a fresh `Preparing`, then ATOMICALLY
/// resets the net to a fresh owned table (base output chain `policy accept`,
/// stamped the new marker) in ONE nft transaction, so the kernel is never without
/// a castle table between the `policy drop` net and the owned wall (deny-all held
/// throughout). It then captures the exact handles and finalizes `Owned`. No
/// agents exist in this state (the original `create` never completed), so no
/// per-agent jump is lost.
#[cfg(target_os = "linux")]
fn recover_from_deny_all_net(
    journal_path: &std::path::Path,
    key_path: &std::path::Path,
    boot_id: &str,
    source: &str,
    admitted: Option<(u32, Option<u32>)>,
) -> Result<crate::nftables::CastleTableOwnership, EnforcementError> {
    use crate::ownership_journal::{self as journal, JournalIdentity, OwnershipJournal};

    let key = journal::load_or_generate_auth_key(key_path)
        .map_err(|err| acquire_failed(format!("journal authentication key unusable: {err}")))?;
    let marker = new_owner_marker()?;
    let identity = JournalIdentity {
        schema_version: journal::JOURNAL_SCHEMA_VERSION,
        marker: marker.clone(),
        boot_id: boot_id.to_string(),
        source: source.to_string(),
    };
    // Record the fresh Preparing BEFORE the kernel mutation, exactly like
    // fresh_acquire: if we crash mid-reset, the next restart proves the resulting
    // table is ours by this marker and finalizes it, never wedging again.
    if let Err(err) = journal::store_atomic(
        journal_path,
        &OwnershipJournal::Preparing { identity },
        &key,
    ) {
        return Err(acquire_failed(format!(
            "GF1.1 recovery: could not record the fresh Preparing journal before resetting the \
             deny-all net: {err}"
        )));
    }
    // Atomic drop-net -> owned-accept transition (deny-all held until the owned
    // wall is up). Only reached after the caller proved the live table is our net.
    if let Err(err) = crate::nftables::atomic_reset_deny_all_net_to_fresh_owned(&marker) {
        return Err(acquire_failed(format!(
            "GF1.1 recovery: could not atomically reset the deny-all net to a fresh owned table \
             (the net is preserved fail-closed; leaving the Preparing record for a retry): {err}"
        )));
    }
    let owned = crate::nftables::capture_owned_castle_table(&marker).map_err(|err| {
        acquire_failed(format!(
            "GF1.1 recovery: reset the net to a fresh owned table but could not capture its owned \
             identity; leaving it for a restart to reclaim rather than clobbering: {err}"
        ))
    })?;
    finalize_owned(journal_path, key_path, &owned, boot_id, source, admitted)?;
    Ok(owned)
}

/// Write the `Owned` journal record for an already-captured table (the finalize
/// step of the interrupted-acquisition reclaim). On failure leaves the existing
/// journal in place and fails-before; the table is proven-ours and a later
/// restart re-finalizes.
#[cfg(target_os = "linux")]
fn finalize_owned(
    journal_path: &std::path::Path,
    key_path: &std::path::Path,
    owned: &crate::nftables::CastleTableOwnership,
    boot_id: &str,
    source: &str,
    admitted: Option<(u32, Option<u32>)>,
) -> Result<(), EnforcementError> {
    use crate::ownership_journal::{self as journal, JournalIdentity};
    // A Preparing record (and therefore its authentication key) already exists on
    // this path; load_or_generate reads it (never generates a spurious second).
    let key = journal::load_or_generate_auth_key(key_path)
        .map_err(|err| acquire_failed(format!("journal authentication key unusable: {err}")))?;
    // WRITE-AHEAD, and it PRESERVES unknown history: this function is idempotent
    // and is re-run on a reclaim, so a legacy record whose `confined` key is absent
    // must come back out with the key still absent.
    let record = owned_record_preserving_history(
        journal_path,
        &key,
        JournalIdentity {
            schema_version: journal::JOURNAL_SCHEMA_VERSION,
            marker: owned.marker.clone(),
            boot_id: boot_id.to_string(),
            source: source.to_string(),
        },
        owned.table_handle,
        owned.base_chain_handle,
        admitted,
    )?;
    journal::store_atomic(journal_path, &record, &key).map_err(|err| {
        acquire_failed(format!(
            "could not finalize the reclaimed Owned ownership journal: {err}"
        ))
    })
}

/// The acquired nftables table component. Owns the host ownership lock AND the
/// exact table identity for its lifetime. On release it drops ONLY the
/// process-local host lock — it does NOT delete the table or clear the journal
/// (blocker 1): the acquired enforcement object and its durable proof are
/// preserved across every userspace loss, so a restart adopts the preserved
/// object. Deletion is the separate, explicit [`disarm_castle_runtime`] path.
///
/// Only constructed on Linux (the sole platform whose provider `acquire`
/// succeeds), so the type and its impls are `cfg(target_os = "linux")` to avoid
/// a dead-code diagnostic on the macOS dev host where it can never be built.
#[cfg(target_os = "linux")]
struct NftablesTableComponent {
    /// The host ownership lock, held for the component's life. `Option` so
    /// `release` can move it out and drop it. The lock is process-local: dropping
    /// it frees the runtime for the next daemon WITHOUT touching the table.
    lock: Option<crate::runtime_lock::HostRuntimeLock>,
    /// The EXACT captured/verified owned identity (handles + marker). Readiness
    /// re-verifies against this tuple; it is never used to delete on ordinary
    /// release. A same-name replacement never reads ready. (blocker 2)
    ownership: crate::nftables::CastleTableOwnership,
    /// The live policy state each health poll re-reads its trusted agent-uid
    /// expectation from. See [`current_expected_agent_binding`].
    decision_engine: Arc<DecisionEngine>,
    /// Bounded, single-flight, rate-limited ownership proof. Owns the latching
    /// policy: a COMPLETED negative proof withdraws readiness permanently, while
    /// a deadline overrun is indeterminate and only latches once the consecutive
    /// budget is exhausted. Single-flight is what stops an authenticated status
    /// poller from stacking `nft` forks. See [`crate::health_probe`].
    probe: crate::health_probe::BoundedHealthProbe,
    released: bool,
    /// Where this component's own journal record lives, so a startup-loss or
    /// post-READY recovery can run the boot rows' persist without re-deriving the
    /// path. Must match the paths `acquire` resolved.
    journal_path: PathBuf,
    journal_key_path: PathBuf,
    /// The net's scope as this process last resolved it, retained for the life of the
    /// component.
    ///
    /// INVARIANT: MONOTONIC within one process. A later recompute, from a journal that
    /// never took a write or from a live table whose jumps a reload pruned, may only
    /// WIDEN this set. A narrowing recompute would stop denying a uid whose processes
    /// may still be live, so the retained set is unioned into every later resolution
    /// rather than replaced by it.
    retained_deny_uids: std::sync::Mutex<Vec<u32>>,
    /// Whether this component is currently in the post-READY `Recovering` state.
    ///
    /// Published through health so nothing downstream reaches an exit arm while a
    /// recovery attempt is still in flight. Interior mutability because `health()`
    /// takes `&self`.
    recovering: std::sync::atomic::AtomicBool,
    /// When the recovery controller last attempted an install, so retries are spaced
    /// by `RECOVERY_RETRY_INTERVAL` with ONE attempt in flight.
    last_recovery_attempt: std::sync::Mutex<Option<std::time::Instant>>,
    /// The tagged `safety_net` state this component last produced, recorded at EVERY
    /// install transition so the audit row and the signed report describe the predicate
    /// actually in the kernel rather than one derived from the fact of a loss.
    last_safety_net_state: std::sync::Mutex<crate::nftables::SafetyNetAuditState>,
    /// A162: live read of the daemon's shutdown-request flag, carried over from
    /// [`NftablesTableProvider`] so [`Self::install_net_on_startup_loss`] (which
    /// runs AFTER `acquire()` returns, from the STARTUP LOST hook) can see a stop
    /// requested during boot the same way the post-READY controller does.
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Maximum time a synchronous `nft -j list table` ownership proof may delay a
/// readiness poll. The proof runs on an isolated worker, so SIGTERM/supervision
/// remains bounded even if fork/exec/netlink never returns. The service restart
/// kills any still-wedged process in its systemd cgroup.
#[cfg(target_os = "linux")]
const NFT_HEALTH_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// Minimum spacing between REAL `nft` ownership proofs. Chosen well under
/// `main.rs`'s 2-second supervisor `HEALTH_INTERVAL` so every supervisor tick
/// still runs a fresh proof (a genuine loss is detected within one tick), while
/// any additional caller inside the same window is served from the cached
/// reading instead of forking a second `nft`.
///
/// Public because a reading served from that cache can predate whatever the
/// caller just installed: the privileged integration suites derive their
/// post-install freshness wait from THIS value (see
/// `tests/isolation/mod.rs::assert_ownership_health_after_install`) rather than
/// mirroring the number, so a change here moves the fixtures with it instead of
/// silently letting them certify a pre-installation table.
#[cfg(target_os = "linux")]
pub const NFT_HEALTH_MIN_INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive indeterminate proofs tolerated before readiness is withdrawn
/// fail-closed, while a single transient timeout under momentary load no longer
/// restarts a healthy daemon.
///
/// Derivation against a permanently wedged `nft`, with the supervisor polling
/// every 2s (`main.rs` `HEALTH_INTERVAL`): reading 1 spawns the check and gives
/// up on it after `NFT_HEALTH_QUERY_TIMEOUT` (1s); readings 2 and 3 do NOT fork
/// again — the worker still owns the in-flight slot, and observing it past its
/// deadline is itself the indeterminate reading (see [`crate::health_probe`]).
/// So the three readings land at t=0, t=2s, t=4s and the third returns a PROVEN
/// `Lost`, which the supervisor acts on with no further grace: worst-case ~4s
/// from the first reading, ~6s from onset, and exactly ONE `nft` child for the
/// whole sequence.
#[cfg(target_os = "linux")]
const NFT_HEALTH_MAX_CONSECUTIVE_UNAVAILABLE: u32 = 3;

#[cfg(target_os = "linux")]
fn nft_health_budget() -> crate::health_probe::ProbeBudget {
    crate::health_probe::ProbeBudget {
        timeout: NFT_HEALTH_QUERY_TIMEOUT,
        min_interval: NFT_HEALTH_MIN_INTERVAL,
        max_consecutive_unavailable: NFT_HEALTH_MAX_CONSECUTIVE_UNAVAILABLE,
    }
}

#[cfg(any(target_os = "linux", test))]
fn classify_nft_ownership_probe(
    result: Result<(), crate::nftables::NftablesError>,
) -> Result<bool, ()> {
    use crate::nftables::NftablesError;
    match result {
        Ok(()) => Ok(true),
        Err(NftablesError::ForeignState(_)) => Ok(false),
        Err(NftablesError::InvocationFailed(message))
            if message.contains("No such file or directory")
                || message.contains("does not exist") =>
        {
            Ok(false)
        }
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
impl NftablesTableComponent {
    /// The post-ready controller attempts the safety net after a completed
    /// ownership loss and retries the real transaction on later eligible losses,
    /// including after a prior success. `health()` only reports evidence.
    /// The net's scope for THIS process, from the retained in-memory deny set unioned
    /// with a fresh resolution.
    ///
    /// INVARIANT: the retained set is MONOTONIC. A fresh resolution is unioned into it,
    /// never substituted for it, so a journal that never took a write or a live table
    /// whose jumps a reload pruned cannot narrow what the net denies while this process
    /// lives. The union is then re-evaluated against `DENY_SET_MAX` on every install,
    /// so an over-capacity process stays host-wide on every retry until it restarts.
    fn net_scope_from_retained_set(&self) -> SafetyNetResolution {
        use crate::nftables::{SafetyNetReason, SafetyNetScope, DENY_SET_MAX};
        use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet, HostOverflowUid};

        let journal_record =
            crate::ownership_journal::load_or_generate_auth_key(&self.journal_key_path)
                .ok()
                .and_then(|key| {
                    crate::ownership_journal::load(&self.journal_path, Some(&key))
                        .ok()
                        .flatten()
                });
        let fresh = resolve_net_scope_at_site(journal_record.as_ref(), &self.decision_engine);

        let mut retained = match self.retained_deny_uids.lock() {
            Ok(guard) => guard,
            // A poisoned lock must not silently produce an EMPTY set, which would
            // install the host-wide shape and deny the operator. Fall back to the fresh
            // resolution, which is at least as wide as this process's last kernel state.
            Err(poisoned) => poisoned.into_inner(),
        };
        // HostWide has no rule set; its full union is still the retained floor.
        for &uid in fresh.retained_deny_uids() {
            if !retained.contains(&uid) {
                retained.push(uid);
            }
        }
        retained.sort_unstable();
        retained.dedup();
        let union = retained.clone();
        drop(retained);

        if union.is_empty() {
            return SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::EmptyDenySet,
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            };
        }
        // Unknown history stays sticky for the life of this process: it is a property
        // of the record on disk, not of the retained set.
        if fresh.reason == SafetyNetReason::UnknownHistory {
            return SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::UnknownHistory,
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            };
        }
        if union.len() > DENY_SET_MAX {
            return SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::DenySetOverCapacity {
                    count: union.len(),
                    cap: DENY_SET_MAX,
                },
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            };
        }
        let Ok(overflow) = HostOverflowUid::from_host() else {
            return SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::EmptyDenySet,
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            };
        };
        let validated: Vec<_> = union
            .iter()
            .filter_map(|&uid| validate_safety_net_uid(uid, overflow).ok())
            .collect();
        match ConfinedUidSet::from_validated(validated) {
            Ok(set) => SafetyNetResolution {
                scope: SafetyNetScope::Identity(set),
                reason: SafetyNetReason::Identity,
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            },
            Err(_) => SafetyNetResolution {
                scope: SafetyNetScope::HostWide,
                reason: SafetyNetReason::EmptyDenySet,
                kill_set: fresh.kill_set,
                sources: fresh.sources,
                deny_union: union.clone(),
            },
        }
    }

    /// Persist this boot's kill set BEST-EFFORT, per the two boot rows.
    ///
    /// Returns the error for the caller to RECORD. The caller never aborts a net
    /// install on it: installing the net makes no uid live, so the install can never
    /// outrun the journal, and the next start retries the write.
    ///
    /// INVARIANT: a record whose `confined` key is ABSENT is NOT written here at all.
    /// `persist_kill_set_write_ahead` keeps such a record's key absent, and the caller
    /// skips this entirely on the unknown-history reason.
    fn persist_boot_row_best_effort(&self, resolution: &SafetyNetResolution) -> Option<String> {
        if resolution.reason == crate::nftables::SafetyNetReason::UnknownHistory {
            return None;
        }
        // A read or authentication failure here is REPORTED, never swallowed: the caller
        // names it so an operator knows the write did not happen.
        let key = match crate::ownership_journal::load_or_generate_auth_key(&self.journal_key_path)
        {
            Ok(key) => key,
            Err(err) => return Some(err.to_string()),
        };
        let record = match crate::ownership_journal::load(&self.journal_path, Some(&key)) {
            Ok(Some(record)) => record,
            // No record at all is not a failure: there is nothing to extend.
            Ok(None) => return None,
            Err(err) => return Some(err.to_string()),
        };
        persist_kill_set_write_ahead(
            &self.journal_path,
            Some(&key),
            &record,
            &resolution.kill_set,
            admitted_identity(&self.decision_engine),
        )
        .err()
    }

    /// STARTUP LOST (memo D1b step 7): a COMPLETED negative ownership proof at either
    /// startup readiness check.
    ///
    /// Order, and each step's reason: persist per the two boot rows (best-effort with a
    /// known history, never with the key absent), then install the net from the
    /// IN-MEMORY deny set REGARDLESS of the persist result, because installing makes no
    /// uid live and so cannot outrun the journal, then the sweep hook ONLY on a failed
    /// install. The caller then runs the reverse-order unwind, which releases the host
    /// lock the disarm verb needs, and returns the acquisition error with the typed
    /// evidence.
    fn install_net_on_startup_loss(&self) {
        let resolution = self.net_scope_from_retained_set();
        let persist_failure = self.persist_boot_row_best_effort(&resolution);
        let scope_sentence =
            crate::nftables::safety_net_scope_sentence(&resolution.scope, &resolution.reason);
        // A162: a stop was already requested with no confined identity known for
        // this boot (HostWide scope); skip the host-wide install rather than
        // silencing every principal on the host. `stop_time_hostwide_skip` has
        // already ATTEMPTED the residual audit row (best-effort: its own stderr
        // line names the append failure if the write could not complete) and
        // always emitted its stderr line naming the skip. Leave
        // `last_safety_net_state` untouched, matching the post-READY A155 skip:
        // the tag records install history, not this reason.
        if stop_time_hostwide_skip(
            &self.decision_engine,
            self.shutdown_requested
                .load(std::sync::atomic::Ordering::SeqCst),
            &resolution.scope,
        ) {
            // SAFETY: stderr is the operator channel; the durable record is the
            // residual audit row `stop_time_hostwide_skip` already appended.
            eprintln!(
                "castle-wall-daemon: a startup ownership check proved the owned nft table no \
                 longer holds, but a stop was already requested and no confined identity is \
                 known for this boot; skipped the host-wide safety net install (register \
                 LINUX-BOOT-STOP-HOSTWIDE-NET-01) rather than silencing every principal on \
                 the host. {scope_sentence}{}",
                match &persist_failure {
                    None => String::new(),
                    Some(err) => format!(
                        " The confined history could not be written to the journal ({err})."
                    ),
                }
            );
            return;
        }
        match crate::nftables::install_deny_all_safety_net(&resolution.scope) {
            Ok(()) => {
                self.record_safety_net_state(crate::nftables::SafetyNetAuditState::installed(
                    &resolution.scope,
                    &resolution.reason,
                    resolution.sources.clone(),
                ));
                // SAFETY: stderr is the operator channel. An operator reading the
                // journal after a refused start needs to know the net is in force and
                // whether their own session is affected.
                eprintln!(
                    "castle-wall-daemon: a startup ownership check proved the owned nft table \
                     no longer holds; installed the safety net before unwinding. \
                     {scope_sentence}{}",
                    match &persist_failure {
                        None => String::new(),
                        Some(err) => format!(
                            " The confined history could not be written to the journal ({err}); \
                             the net is installed regardless, and the next start retries the write."
                        ),
                    }
                );
            }
            Err(err) => {
                self.record_safety_net_state(crate::nftables::SafetyNetAuditState::InstallFailed {
                    attempted_scope: resolution.scope.shape_tag().to_string(),
                    error: err.to_string(),
                });
                safety_net_sweep_hook_pr3(
                    &resolution.kill_set,
                    Some(&resolution.scope),
                    "startup ownership loss: the safety net install failed before the unwind",
                );
                // SAFETY: same operator channel; this is the branch where no protection
                // is in place and the refusal must say so.
                eprintln!(
                    "castle-wall-daemon: a startup ownership check proved the owned nft table \
                     no longer holds AND installing the safety net FAILED ({err}); \
                     {scope_sentence}"
                );
            }
        }
    }

    /// STARTUP INDETERMINATE (memo D1b step 7): an nft-specific indeterminate reading at
    /// either startup check.
    ///
    /// Installs NOTHING. An indeterminate reading is the ABSENCE of evidence, and
    /// installing the net on it would replace a table that may be perfectly healthy.
    /// The sweep hook runs before the terminal exit, which is the one action that is
    /// safe without evidence about the table, and the existing exit-and-adopt path then
    /// proceeds unchanged.
    fn hook_on_startup_indeterminate(&self) {
        let kill_set = self.net_scope_from_retained_set().kill_set;
        safety_net_sweep_hook_pr3(
            &kill_set,
            None,
            "startup ownership reading indeterminate: no install is attempted on absent evidence",
        );
    }

    /// POST-READY LOSS (memo D1b step 7): the runtime-level recovery controller, entered
    /// ONLY from a COMPLETED negative ownership proof from this component.
    ///
    /// Order, and why it differs from the boot rows: the net is installed FIRST from the
    /// in-memory deny set, because the kill set is already durable from the bind row and
    /// a net-install persist makes no uid live, so there is nothing to write ahead of.
    /// The persist follows best-effort. The first completed `Lost` proof is consumed
    /// without a second probe that could be unavailable; later `Recovering` polls
    /// re-probe before the INSTALL interval. `Recovering` is published before the
    /// transaction, so no consumer reaches an exit arm while it is in flight.
    /// The sweep hook fires only after a FAILED install, never on entry.
    ///
    /// Return this call's exact result so the supervisor can audit real attempts.
    ///
    /// R2 (LINUX-STOP-LOSS-RACE-01, Grok 2 / Claude F2): `shutting_down` is a
    /// closure, called fresh at EACH decision point below rather than once into
    /// a stored `bool`. The caller's own health probe (which is what gated
    /// whether this function is reached at all) can take up to
    /// `NFT_HEALTH_QUERY_TIMEOUT`; a stop landing during that probe must be
    /// visible to every gate in this function, not just the one a value copied
    /// before the probe would have seen.
    fn recover_post_ready_loss(
        &self,
        shutting_down: &dyn Fn() -> bool,
    ) -> crate::enforcement::PostReadyRecoveryResult {
        use crate::enforcement::PostReadyRecoveryResult;
        use std::sync::atomic::Ordering;
        // C2a1(a) site 5 (LINUX-STOP-LOSS-RACE-01): a stop never leaves a proven loss
        // without its one net attempt. Shutdown no longer skips this call outright;
        // it gates only the RETRYING re-probe path below (no `OwnedWallReady`
        // readiness restoration during a stop) and the throttled-retry interval. A
        // first entry for a proven loss still consumes the Lost proof and attempts
        // the install exactly once, even while shutting down.
        let retrying = self.is_recovering();
        if shutting_down() && retrying {
            // A stop must not restore readiness or keep re-probing; only the FIRST
            // entry for a fresh proven loss gets the one-shot install below.
            return PostReadyRecoveryResult::NoInstall;
        }
        self.mark_prior_install_unverified();
        // The first entry already consumed a completed negative proof supplied by
        // the runtime. Only LATER polls ask whether the original owned wall has
        // returned. Doing this before the install clock recognizes a repair
        // promptly; doing it on first entry could turn a proven loss into a
        // transient no-answer and skip the first protective install.
        let proof = post_ready_recovery_proof(retrying, || {
            let ownership = self.ownership.clone();
            let expectation = current_expected_agent_binding(&self.decision_engine);
            self.probe.reprobe_after_latch(move || {
                // The binding-set form, not the bare ownership check: a repaired
                // table that came back WITHOUT the agent's jump is not the owned
                // wall this process was ready with, and reading it as recovered
                // would restore readiness over an unconfined agent.
                classify_nft_ownership_probe(crate::nftables::verify_owned_castle_table_binding(
                    &ownership,
                    &expectation,
                ))
            })
        });
        match proof {
            crate::health_probe::ProbeOutcome::Ready => {
                self.recovering.store(false, Ordering::SeqCst);
                let mut last = match self.last_recovery_attempt.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *last = None;
                return PostReadyRecoveryResult::OwnedWallReady;
            }
            crate::health_probe::ProbeOutcome::Lost => {}
            crate::health_probe::ProbeOutcome::Unavailable => {
                return PostReadyRecoveryResult::NoInstall
            }
            crate::health_probe::ProbeOutcome::Indeterminate => {
                // No completed proof licenses a kernel mutation. The status read
                // after this call observes the terminal probe latch and reaches
                // the supervisor's existing hook-before-exit arm.
                self.recovering.store(false, Ordering::SeqCst);
                return PostReadyRecoveryResult::NoInstall;
            }
        }

        // The FIRST call consumes the caller's completed Lost proof immediately.
        // Every later call reaches here only after another completed Lost proof.
        // Publish Recovering BEFORE the install attempt and retain it through retries.
        self.recovering.store(true, Ordering::SeqCst);
        // ONE install at a time, spaced by the retry interval. A distinct first
        // loss is never throttled by the clock from a previously repaired wall.
        {
            let mut last = match self.last_recovery_attempt.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if retrying {
                if let Some(at) = *last {
                    if at.elapsed() < RECOVERY_RETRY_INTERVAL {
                        return PostReadyRecoveryResult::NoInstall;
                    }
                }
            }
            *last = Some(std::time::Instant::now());
        }
        let resolution = self.net_scope_from_retained_set();
        // A155 (Erik, 2026-09-24): a routine stop never installs a host-wide net.
        // `SafetyNetScope::HostWide` here means no confined uid is known (or the
        // retained set overflowed), so a stop-time install would have nothing
        // legitimate to scope the drop to and would instead silence the operator's
        // own live sessions on every ordinary `systemctl stop`. With a known
        // confined identity (`SafetyNetScope::Identity`) this branch is not taken
        // and the install proceeds as normal, in or out of shutdown.
        //
        // R2 (LINUX-STOP-LOSS-RACE-01, Grok 2): `shutting_down()` is read AGAIN
        // here, live, rather than reusing the value the `retrying` gate above
        // read. A stop that lands between that gate and this one (inside the
        // scope resolution above, which can shell out to `nft`) must still be
        // seen here, or a host-wide net could be installed after a stop was
        // already requested.
        if stop_time_hostwide_skip(&self.decision_engine, shutting_down(), &resolution.scope) {
            // F8 (LINUX-STOP-LOSS-RACE-01, Claude F8): do NOT overwrite attempt
            // history here. `mark_prior_install_unverified()` above already
            // demoted a prior `Installed` to `Unverified`; any other prior tag
            // (`Unverified`, `InstallFailed`, or the untouched `NotAttempted`
            // default) is left exactly as it was. Stamping `NotAttempted`
            // unconditionally would erase the fact that THIS process attempted
            // and installed earlier in its own lifetime (reachable whenever
            // `recovering == false` because an earlier loss already recovered
            // to `OwnedWallReady` before this new one). The skip itself is
            // recorded durably by the residual audit row `stop_time_hostwide_skip`
            // already wrote; the safety-net tag records install history, not this
            // reason.
            //
            // Return the same result the no-install paths above return (Unavailable/
            // Indeterminate), so the caller reads this the same way: not a proven
            // install, and NOT mapped to a clean exit-0. `recovering` was set true
            // above (before this branch), so the `Recovering` observation this
            // process now publishes keeps every supervisor exit arm nonzero
            // (R1, LINUX-STOP-LOSS-RACE-01: `recovery_call_decision` only reads
            // ShutdownRequested off a Ready/NoRuntime observation, at every call
            // site, not only the ones that already ran a full health match).
            return PostReadyRecoveryResult::NoInstall;
        }
        // INSTALL FIRST. The persist follows.
        let installed = install_deny_all_net_for_recovery(
            || crate::nftables::install_deny_all_safety_net(&resolution.scope),
            &resolution.kill_set,
            &resolution.scope,
        );
        // Record THIS transaction's result before the best-effort persist. A prior
        // success is never used to turn a later failed transaction into Installed.
        self.record_safety_net_state(if installed {
            crate::nftables::SafetyNetAuditState::installed(
                &resolution.scope,
                &resolution.reason,
                resolution.sources.clone(),
            )
        } else {
            crate::nftables::SafetyNetAuditState::InstallFailed {
                attempted_scope: resolution.scope.shape_tag().to_string(),
                error: "the safety net install failed; protection could not be proved".to_string(),
            }
        });
        if installed {
            // Best-effort persist AFTER the install, and a failure here never undoes it.
            if let Some(persist_err) = self.persist_boot_row_best_effort(&resolution) {
                // SAFETY: stderr is the operator channel. The net is in force; the
                // journal write is what did not happen; no retry or restart is promised here.
                eprintln!(
                    "castle-wall-daemon: the safety net is in force after a runtime loss, but \
                     the confined history could not be written to the journal: {persist_err}"
                );
            }
        }
        // INVARIANT: `recovering` STAYS SET whether or not the install succeeded.
        // The supervisor's initial post-READY poll consumes this returned result
        // in the same turn and exits repair-required; a successful net install
        // does not establish journal durability. Later interval polls retain
        // their existing behavior.
        if installed {
            PostReadyRecoveryResult::InstallSucceeded
        } else {
            PostReadyRecoveryResult::InstallFailed
        }
    }

    fn mark_prior_install_unverified(&self) {
        let mut slot = match self.last_safety_net_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        demote_prior_install(&mut slot);
    }

    /// Record the tagged state produced by an install transition.
    ///
    /// Called on EVERY transition, success or failure, so the state a consumer reads is
    /// never a stale success left over from an earlier attempt.
    fn record_safety_net_state(&self, state: crate::nftables::SafetyNetAuditState) {
        let mut slot = match self.last_safety_net_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = state;
    }

    /// Whether this component is publishing the post-READY `Recovering` state.
    fn is_recovering(&self) -> bool {
        self.recovering.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Shared body for [`AcquiredComponent::health`] and
    /// [`AcquiredComponent::health_fresh`] (R3, LINUX-STOP-LOSS-RACE-01, Claude
    /// F3). `fresh=false` uses `BoundedHealthProbe::poll_result`, which may
    /// return a reading cached for up to `NFT_HEALTH_MIN_INTERVAL`;
    /// `fresh=true` uses `reprobe_after_latch`, which clears that cache before
    /// running the same check, so the result is a live proof. Must match the
    /// latch-handling invariant documented on `reprobe_after_latch` itself:
    /// this is bypassing a cache, not weakening the readiness claim.
    fn health_impl(&self, fresh: bool) -> crate::enforcement::ComponentHealth {
        use crate::enforcement::ComponentHealth;
        if self.released || self.lock.is_none() {
            return ComponentHealth::Lost;
        }
        // Live re-poll of the EXACT owned identity AND the expected agent
        // binding (handles + marker + pristine shape via structured nft -j,
        // compared against the frozen uid expectation captured below), not
        // mere table-name existence and not a name-only shape check. (blocker
        // 2) A table deleted, flushed, mutated, or DELETED-AND-RECREATED with
        // the same shape (new handles, or our marker absent), OR one whose
        // per-agent binding no longer matches that expectation, fails this
        // check, dropping the runtime out of KernelRuntimeReady on the next
        // status query.
        //
        // The proof is COMPLETION-latched, not attempt-latched: a completed
        // negative proof means ownership provably no longer holds and withdraws
        // readiness permanently for this process (systemd restart re-adopts the
        // preserved exact table). A deadline overrun proves nothing, so it is
        // reported indeterminate and only latches after
        // NFT_HEALTH_MAX_CONSECUTIVE_UNAVAILABLE consecutive no-answers — the
        // fail-closed backstop for a wedged `nft` without the false restart a
        // single transient timeout used to cause.
        let ownership = self.ownership.clone();
        // Live health is the third comparison site. The expectation is read from
        // the FROZEN identity cell here, before the probe is scheduled, and moved
        // into the closure that may run on a worker thread. Capturing it is sound
        // precisely because the cell is write-once: the value a later poll would
        // read is the same value, so there is nothing to go stale against. Before
        // the freeze this had to be a fresh read at each comparison, and that is
        // the sentence this comment replaces.
        let expectation = current_expected_agent_binding(&self.decision_engine);
        let check = move || {
            // Health requires the BINDING, not just the table: the agent's chain
            // and jump are the only rules that confine the uid, and a table that
            // still verifies after they were deleted would hold readiness over an
            // agent with no wall in front of it.
            classify_nft_ownership_probe(crate::nftables::verify_owned_castle_table_binding(
                &ownership,
                &expectation,
            ))
        };
        let outcome = if fresh {
            self.probe.reprobe_after_latch(check)
        } else {
            self.probe.poll_result(check)
        };
        if outcome == crate::health_probe::ProbeOutcome::Indeterminate {
            // The terminal no-answer bypasses the recovery controller, so it
            // must withdraw any prior installed claim before the exit WAL row.
            self.mark_prior_install_unverified();
        }
        // REPORT ONLY: startup owns its install through `EnforcementRuntime::start`,
        // and the supervisor owns the post-READY controller. A late completed Ready
        // proof may clear our internal recovery flag/clock here without touching the
        // kernel. Transient no-answer stays Recovering while this owner is active;
        // exhausted Indeterminate still reaches the supervisor's hook-before-exit arm.
        post_ready_component_health(outcome, &self.recovering, &self.last_recovery_attempt)
    }
}

#[cfg(any(target_os = "linux", test))]
fn demote_prior_install(state: &mut crate::nftables::SafetyNetAuditState) {
    if matches!(
        *state,
        crate::nftables::SafetyNetAuditState::Installed { .. }
    ) {
        *state = crate::nftables::SafetyNetAuditState::Unverified;
    }
}

#[cfg(target_os = "linux")]
impl AcquiredComponent for NftablesTableComponent {
    fn kind(&self) -> ComponentKind {
        ComponentKind::NftablesTable
    }

    fn is_ready(&self) -> bool {
        // Two-valued gate: indeterminate fails closed here. The startup checks read
        // the THREE-valued `health()` through `StartupReadiness` instead, because a
        // completed negative proof and a no-answer drive different actions there.
        matches!(self.health(), crate::enforcement::ComponentHealth::Ready)
    }

    /// STARTUP LOST. Must match the row in memo D1b step 7: persist per the boot rows,
    /// install from the in-memory deny set, hook only on a failed install. The caller
    /// then unwinds through `release_reverse`, which is what releases the host lock.
    fn on_startup_lost(&self) {
        self.install_net_on_startup_loss();
    }

    /// STARTUP INDETERMINATE. Installs nothing; the hook runs before the terminal exit.
    fn on_startup_indeterminate(&self) {
        self.hook_on_startup_indeterminate();
    }

    fn on_post_ready_indeterminate(&self) {
        let kill_set = self.net_scope_from_retained_set().kill_set;
        safety_net_sweep_hook_pr3(
            &kill_set,
            None,
            "post-ready ownership reading indeterminate",
        );
    }

    fn safety_net_audit_state(&self) -> Option<crate::nftables::SafetyNetAuditState> {
        let slot = match self.last_safety_net_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(slot.clone())
    }

    /// POST-READY LOSS. The supervisor calls this before any exit arm; the controller
    /// installs the net first, then persists best-effort, and publishes `Recovering`
    /// while an attempt is outstanding.
    fn attempt_post_ready_recovery(
        &self,
        shutting_down: &dyn Fn() -> bool,
    ) -> crate::enforcement::PostReadyRecoveryResult {
        self.recover_post_ready_loss(shutting_down)
    }

    fn health(&self) -> crate::enforcement::ComponentHealth {
        self.health_impl(false)
    }

    /// R3 (LINUX-STOP-LOSS-RACE-01, Claude F3): the fresh variant `health_impl(true)`
    /// selects, using `reprobe_after_latch` instead of `poll_result` so the read
    /// bypasses `NFT_HEALTH_MIN_INTERVAL`. See `health_impl` for the shared body.
    fn health_fresh(&self) -> crate::enforcement::ComponentHealth {
        self.health_impl(true)
    }

    fn release(&mut self) {
        if self.released {
            return; // idempotent
        }
        // FAIL-CLOSED PRESERVATION (blocker 1): ordinary release drops ONLY the
        // process-local host lock. It MUST NOT delete the owned table or clear the
        // ownership journal — an acquired enforcement object and its durable proof
        // survive every userspace loss (SIGTERM/systemd stop, readiness-notify
        // failure, partial-startup rollback, watcher/runtime loss, crash, Drop), so
        // a restart adopts the preserved object rather than re-creating it, and the
        // non-bypass posture is never torn down by a mere process exit. Deletion is
        // the separate, explicit `disarm_castle_runtime` recovery path. Panic-free
        // (runs from Drop).
        if let Some(mut lock) = self.lock.take() {
            lock.release();
        }
        self.released = true;
    }
}

#[cfg(target_os = "linux")]
impl Drop for NftablesTableComponent {
    fn drop(&mut self) {
        self.release();
    }
}

// ---------------------------------------------------------------------------
// Explicit disarm / recovery path (blockers 1, 2, 6).
// ---------------------------------------------------------------------------

/// Outcome of an explicit disarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisarmOutcome {
    /// A live owned table was deleted (handle-qualified), its absence verified,
    /// and the authenticated journal cleared afterward.
    TableDeleted,
    /// D3 (memo v2.21): the live table was recognized as this daemon's OWN
    /// deny-all safety net (the v1 host-wide zero-rule shape, or the v2
    /// identity-scoped three-rule shape D2 recognises once PR-1 lands), deleted
    /// by name, its absence verified, and the journal cleared. Named apart from
    /// `TableDeleted` (an ordinary owned WALL, `policy accept`, deleted by
    /// handle) and from `StaleRecordCleared` (no live table at all) so an
    /// operator or the drill harness can tell which of the three was cleared
    /// (open sub-decision 5). Never described as "deny-all" alone in operator
    /// text: the v2 shape denies exactly the confined identity, not the host.
    SafetyNetCleared,
    /// No live owned table existed (already gone / prior boot); a stale ownership
    /// record was cleared after its absence was confirmed.
    StaleRecordCleared,
    /// Nothing to disarm: no owned table and no ownership journal.
    NothingToDisarm,
}

impl std::fmt::Display for DisarmOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DisarmOutcome::TableDeleted => "owned table deleted and journal cleared",
            DisarmOutcome::SafetyNetCleared => {
                "this daemon's safety net deleted and journal cleared"
            }
            DisarmOutcome::StaleRecordCleared => "no live table; stale ownership record cleared",
            DisarmOutcome::NothingToDisarm => "nothing to disarm (no owned table, no journal)",
        })
    }
}

/// Explicitly DISARM the host castle runtime: delete this daemon's owned
/// `sanctuary-castle` table and clear its ownership journal. This is the ONLY
/// path that deletes an acquired enforcement object; ordinary shutdown never
/// does (blocker 1). It is invoked by the unmistakable `--disarm` CLI action, NOT
/// by SIGTERM/systemd stop.
///
/// Safety contract (blockers 2, 6) splits by which live object the
/// authenticated journal's proof resolves to (D3: a same-boot `Owned` record
/// can resolve to either):
///
/// ORDINARY-OWNED ARM (the journal's own owned wall):
/// * Re-validates the EXACT complete inventory (handles + marker + pristine
///   shape) IMMEDIATELY before deletion, deletes by the narrowest
///   handle-qualified operation nft supports, and verifies ABSENCE
///   immediately after.
///
/// SAFETY-NET ARM (D3: the live table is this daemon's own safety net, not the
/// journal's owned wall): the net carries no per-agent handles to
/// re-validate, so this arm instead requires a positive recogniser answer
/// AND an independent check that the live table's comment key is absent, both
/// read from one inventory fetch, before it deletes by name and verifies
/// ABSENCE immediately after exactly as the ordinary arm does. See the
/// `ReclaimOwned` arm's invariant comment and [`disarm_recover_deny_all_net`]
/// for this arm's own TOCTOU bound.
///
/// BOTH ARMS:
/// * Run UNDER the host ownership lock: a still-running daemon holds the lock,
///   so disarm refuses (`AlreadyHeld`) rather than racing a live owner.
/// * Require an AUTHENTICATED journal record for THIS boot/source before any
///   delete. The ordinary-owned arm then deletes only the exact object the
///   record proves (handle-qualified); the safety-net arm deletes by NAME after
///   the shape probe and the absent-comment check, under the replace-between-
///   probe-and-delete bound stated at its site. A foreign table (no record,
///   drifted identity, wrong boot) is REFUSED and left intact on both arms.
/// * The journal is cleared ONLY after deletion AND post-delete absence are both
///   positively confirmed. On ANY ambiguity (corrupt/unauthenticated proof,
///   identity drift, a delete error, or an absence-verification failure), the
///   journal is RETAINED and the call fails.
///
/// Threat-boundary honesty (ORDINARY-OWNED ARM): nftables offers no atomic
/// compare-and-delete, so the verify→delete→verify sequence is a best-effort
/// TOCTOU narrowing, not an atomic guarantee. A concurrent privileged host writer
/// that swaps the table between the pre-delete revalidation and the handle
/// delete could still be raced; deleting by the captured HANDLE (not by name)
/// bounds the damage: a stale handle either no longer resolves (nft errors, we
/// retain and fail) or resolves to a different object we already refused. This
/// is the honest limit of what nft permits and is documented, not claimed away.
/// The SAFETY-NET ARM's own TOCTOU bound is different (a by-name delete, since
/// the net carries no handles to qualify against) and is stated where that arm
/// is implemented, not here.
///
/// D3 fix round: what a disarm recovery probe reads off ONE live inventory
/// fetch. Two independent facts, BOTH required before EITHER of disarm's two
/// recovery sites (the `ReclaimOwned` arm and the `FinalizeInterrupted` arm's
/// capture-failure branch) treats the live table as this daemon's own safety
/// net: the recogniser's own shape verdict
/// ([`crate::nftables::is_deny_all_safety_net_json`], unchanged here) and an
/// independent check that the same inventory's table object carries no
/// comment key at all ([`crate::nftables::castle_table_comment_is_absent`]).
/// Named fields, not a bare tuple, so a future caller cannot transpose the two
/// booleans by accident. This is the ONE shared requirement named at both
/// call sites below; it must read identically at each (pin comment on both
/// arms).
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SafetyNetRecoveryProbeReading {
    recognised_as_safety_net: bool,
    table_comment_absent: bool,
}

/// Both disarm recovery arms classify one inventory with the same host-specific
/// uid boundary. An unreadable overflow uid or vanished table is a probe error,
/// never evidence that a live table belongs to this daemon.
#[cfg(target_os = "linux")]
fn read_safety_net_recovery_probe(
) -> Result<SafetyNetRecoveryProbeReading, crate::nftables::NftablesError> {
    let overflow = crate::safety_net_uid::HostOverflowUid::from_host().map_err(|err| {
        crate::nftables::NftablesError::InvocationFailed(format!(
            "cannot classify the live table without this host's configured kernel.overflowuid: {err}"
        ))
    })?;
    let json = crate::nftables::live_castle_table_json()?;
    Ok(SafetyNetRecoveryProbeReading {
        recognised_as_safety_net: crate::nftables::is_deny_all_safety_net_json(&json, overflow),
        table_comment_absent: crate::nftables::castle_table_comment_is_absent(&json),
    })
}

/// D3 (memo v2.21, fix round): outcome of probing whether a disarm recovery
/// site's live table is actually this daemon's own safety net rather than the
/// object the journal state otherwise implies. Named states (not a bare
/// bool/Result) because the probe-failure branch is a THIRD outcome, not a
/// degenerate case of the other two: it refuses and retains rather than
/// guessing either way. Shared by both the `ReclaimOwned` arm and the
/// `FinalizeInterrupted` arm's capture-failure branch.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
enum SafetyNetRecoveryDecision {
    /// The live table is this daemon's own safety net: recover it (delete,
    /// confirm absence, clear the journal). Requires BOTH fields of
    /// [`SafetyNetRecoveryProbeReading`] to hold; either alone is
    /// `NotSafetyNet`.
    RecoverSafetyNet,
    /// Not the safety net: the caller's own existing refusal (`ReclaimOwned`'s
    /// ordinary exact-inventory reclaim, or `FinalizeInterrupted`'s
    /// marker-mismatch refusal) applies instead.
    NotSafetyNet,
    /// The probe itself failed: refuse and retain (never guess which branch
    /// applies).
    ProbeFailed(String),
}

/// D3: the ONE piece of disarm's recovery-site decisions that is pure and
/// unit-testable without a real kernel, since everything else in
/// `disarm_castle_runtime` needs an authenticated on-disk journal, the host
/// lock, and a live nft table, so the rest of the proof is integration
/// (packet: "the decision logic is not mockable without nft except through
/// one narrow injected-closure seam for the recogniser probe"). `probe` reads
/// the live inventory once and reports both fields of
/// [`SafetyNetRecoveryProbeReading`]; production builds it from one
/// `crate::nftables::live_castle_table_json` fetch at each call site (the
/// `ReclaimOwned` arm and the `FinalizeInterrupted` arm below), and a unit
/// test injects a closure returning `Err(..)`, or an arbitrary reading, to
/// prove every branch without touching nft.
#[cfg(any(target_os = "linux", test))]
fn classify_safety_net_recovery_probe(
    probe: impl FnOnce() -> Result<SafetyNetRecoveryProbeReading, crate::nftables::NftablesError>,
) -> SafetyNetRecoveryDecision {
    match probe() {
        Ok(reading) if reading.recognised_as_safety_net && reading.table_comment_absent => {
            SafetyNetRecoveryDecision::RecoverSafetyNet
        }
        Ok(_) => SafetyNetRecoveryDecision::NotSafetyNet,
        Err(probe_err) => SafetyNetRecoveryDecision::ProbeFailed(probe_err.to_string()),
    }
}

/// D3 fix round (packet item 3): test-only override for the `ReclaimOwned`
/// arm's probe, so the Linux integration suite can drive the PRODUCTION
/// `disarm_castle_runtime` path through the probe-error branch. Absent from a
/// normal build (compiled only under `test-isolation`); the production call
/// site is unchanged when this feature is off. The call site consumes it
/// (resets to `false`) ONLY when that exact probe call is reached; a test that
/// arms it and then exits early (an earlier assertion fails, a fixture setup
/// step errors, or the disarm call takes a different arm than expected) would
/// otherwise leave it set for whatever LATER, unrelated test's `ReclaimOwned`
/// probe runs next. [`ForcedReclaimOwnedProbeError`] closes that gap: it is
/// the only way to arm the latch, and its `Drop` clears it unconditionally, so
/// the guarantee is scoped to one test's lifetime, never to "the call site
/// happened to be reached." Mirrors
/// `crate::nftables::reset_runtime_ownership_for_tests`'s test-only latch
/// convention, with an RAII clear in place of a manual one.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
static RECLAIM_OWNED_PROBE_FORCE_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// RAII handle for the override above. Construct with
/// [`force_next_reclaim_owned_probe_error_for_test`] and bind it to a variable
/// that lives for the rest of the test; the latch clears when that variable
/// drops, whether the test returns normally, returns early, or panics.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub struct ForcedReclaimOwnedProbeError {
    _private: (),
}

#[cfg(all(target_os = "linux", feature = "test-isolation"))]
impl Drop for ForcedReclaimOwnedProbeError {
    fn drop(&mut self) {
        RECLAIM_OWNED_PROBE_FORCE_ERROR.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Arm the override above for exactly the next `ReclaimOwned`-arm probe call.
/// Returns a guard that clears the latch on drop; a test must bind it (not
/// `let _ = ...`, which would drop it immediately and clear the latch before
/// the disarm call it is meant to cover).
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn force_next_reclaim_owned_probe_error_for_test() -> ForcedReclaimOwnedProbeError {
    RECLAIM_OWNED_PROBE_FORCE_ERROR.store(true, std::sync::atomic::Ordering::SeqCst);
    ForcedReclaimOwnedProbeError { _private: () }
}

/// GF1.1 / D3 disarm-path recovery: the live table has been positively
/// recognized as this daemon's own safety net (v1 host-wide or v2
/// identity-scoped shape; never "deny-all" alone, since the v2 shape denies
/// exactly the confined identity, not the host). Delete it by name, confirm
/// absence, and clear the journal record. This is explicit teardown, so
/// safety-net -> nothing is the intended outcome; on any ambiguity the record
/// is RETAINED. Does NOT touch the host lock: the caller owns its lifetime and
/// drops it after.
///
/// Two callers, two different calling states: `FinalizeInterrupted` (a
/// `Preparing` record, the create-failure wedge, GF1.1) and `ReclaimOwned` (a
/// same-boot `Owned` record whose live table turned out to be the safety net
/// rather than the ordinary owned wall the record names, D3). `calling_state` is
/// a short label for the journal state disarm found, so every message this
/// helper produces says what it recovered FROM rather than assuming the
/// Preparing case (the doc comment and error texts here used to say
/// "an interrupted acquisition" unconditionally, which was false when this
/// helper started being reachable from `Owned` too).
#[cfg(target_os = "linux")]
fn disarm_recover_deny_all_net(
    journal_path: &std::path::Path,
    calling_state: &str,
) -> Result<DisarmOutcome, EnforcementError> {
    let disarm_failed = |detail: String| EnforcementError::AcquireFailed {
        kind: ComponentKind::NftablesTable.as_str(),
        detail,
    };
    crate::nftables::force_delete_castle_table_by_name().map_err(|del_err| {
        disarm_failed(format!(
            "recognized this daemon's safety net for {calling_state} but deleting it \
             failed; retaining the record: {del_err}"
        ))
    })?;
    match crate::nftables::table_exists() {
        Ok(false) => {}
        Ok(true) => {
            return Err(disarm_failed(format!(
                "safety net still present after a by-name delete for {calling_state}; \
                 retaining the record"
            )))
        }
        Err(exists_err) => {
            return Err(disarm_failed(format!(
                "could not verify safety net absence after delete for {calling_state}; \
                 retaining the record: {exists_err}"
            )))
        }
    }
    crate::ownership_journal::clear(journal_path).map_err(|clear_err| {
        disarm_failed(format!(
            "deleted the safety net for {calling_state} but clearing the ownership \
             record failed: {clear_err}"
        ))
    })?;
    Ok(DisarmOutcome::SafetyNetCleared)
}

pub fn disarm_castle_runtime(
    config: &LinuxRuntimeConfig,
) -> Result<DisarmOutcome, EnforcementError> {
    #[cfg(target_os = "linux")]
    {
        use crate::nftables::CastleTableOwnership;
        use crate::ownership_journal::{self as journal, ReclaimDecision};

        let disarm_failed = |detail: String| EnforcementError::AcquireFailed {
            kind: ComponentKind::NftablesTable.as_str(),
            detail,
        };

        // 1) Take the host lock. A live daemon holds it -> refuse (do not race).
        // Repair-order text (memo D2's refusal convention, packet item 4): a bare
        // "stop it" leaves an operator guessing at systemd's restart behavior; a
        // still-running unit re-takes this same lock on its next restart, so a
        // disarm retry without stopping the unit first just refuses again.
        let lock =
            crate::runtime_lock::HostRuntimeLock::acquire(&config.lock_path).map_err(|err| {
                disarm_failed(format!(
                    "cannot take the host ownership lock to disarm; stop the castle-wall unit \
                     first (systemd would otherwise restart it and re-take this same lock), \
                     then run disarm: {err}"
                ))
            })?;

        let journal_path = config.journal_path.as_path();
        let key_path = config.journal_key_path.as_path();
        let boot_id = journal::current_boot_id()
            .map_err(|err| disarm_failed(format!("could not read a valid Linux boot id: {err}")))?;
        let source = journal::current_source();

        // 2) Load + AUTHENTICATE the journal. A corrupt/unauthenticated/missing-key
        //    record is a hard error; RETAIN it and fail (never delete on an
        //    unprovable record).
        let key_opt = journal::read_auth_key(key_path)
            .map_err(|err| disarm_failed(format!("journal authentication key unusable: {err}")))?;
        let record = journal::load(journal_path, key_opt.as_ref()).map_err(|err| {
            disarm_failed(format!(
                "could not read/authenticate the ownership journal; retaining it and refusing to \
                 disarm on an unprovable record: {err}"
            ))
        })?;
        let table_present = crate::nftables::table_exists()
            .map_err(|err| disarm_failed(format!("could not determine table existence: {err}")))?;

        // 3) Classify with the SAME audited decision function the acquisition path
        //    uses (`decide`), so disarm and acquire share one ownership model.
        //    Resolve the exact object this proof authorizes deleting, or refuse.
        let owned: CastleTableOwnership =
            match journal::decide(record.as_ref(), table_present, &boot_id, &source) {
                // No live table. A stale record (prior boot, or an owned record
                // whose table is already gone) is a CONFIRMED-ABSENT proof: clear
                // it. No record and no table: nothing to do. GF1: an owned/prepare
                // record whose table vanished THIS boot now classifies as
                // `ReArmLostOwned`; on the DISARM path that still means "the table
                // is already gone", so it clears the stale record too -- disarm is
                // an explicit teardown and never installs a deny-all net.
                ReclaimDecision::FreshCreate | ReclaimDecision::ReArmLostOwned => {
                    let cleared = record.is_some();
                    if cleared {
                        journal::clear(journal_path).map_err(|err| {
                            disarm_failed(format!(
                                "could not clear the stale ownership record: {err}"
                            ))
                        })?;
                    }
                    drop(lock);
                    return Ok(if cleared {
                        DisarmOutcome::StaleRecordCleared
                    } else {
                        DisarmOutcome::NothingToDisarm
                    });
                }
                // A live table with no proof for THIS boot/source (foreign, wrong
                // boot, or no record): REFUSE and RETAIN — never delete by name.
                ReclaimDecision::RefuseForeign => {
                    drop(lock);
                    return Err(disarm_failed(
                        "a live sanctuary-castle table has no ownership proof for this \
                         boot/binary; refusing to delete foreign state (retaining any record)"
                            .to_string(),
                    ));
                }
                // Our Owned table for this boot: normally the exact identity to
                // delete, UNLESS the live table is actually this daemon's own
                // safety net (D3): a runtime-loss or boot-drift recovery (memo
                // D1b step 7) can install the safety net over what the journal
                // still calls an `Owned` (steady-state) record, and the safety
                // net's shape (drop policy, no per-agent jump) is NOT the
                // owned-wall shape `verify_owned_castle_table` below expects, so
                // without this check step 5 would refuse it as "drifted" and
                // disarm would wedge exactly on the case it exists to recover.
                // D1b's never-adopt rule for a same-boot LEGACY `Owned` record
                // (the `confined` key absent, PR-1) is ACQUISITION-specific and
                // must not reroute disarm away from this arm: a legacy record
                // with a live recognised net still reaches here and is cleared
                // (must match the acquisition-specific gate PR-1 adds around
                // `ReclaimDecision::ReclaimOwned` in `ownership_journal.rs`,
                // memo D3, PR-2 packet item 3 test case (f)).
                //
                // PIN (shared requirement, both arms; must match the identical
                // requirement at the `FinalizeInterrupted` arm below): the
                // recovery branch requires THREE things at once, all read
                // fresh at this call site: a positive recogniser answer over
                // the live inventory, that SAME inventory's table object
                // carrying no comment key at all (D1 installs the net with no
                // table comment; a comment of any content means `NotSafetyNet`
                // instead, which here falls through to the ordinary reclaim,
                // re-validating the exact inventory on its own terms and
                // refusing on any mismatch it finds), and the authenticated
                // this-boot `Owned` journal already established above. A
                // by-name delete (inside `disarm_recover_deny_all_net`) is not
                // atomic with the read that authorized it: another
                // `CAP_NET_ADMIN` holder could replace the table in between,
                // and the delete then removes whatever holds the name at that
                // moment. That is the accepted TOCTOU bound nft's tooling
                // permits (memo D3); this path never claims it deletes only
                // what this daemon armed.
                ReclaimDecision::ReclaimOwned {
                    table_handle,
                    base_chain_handle,
                    marker,
                } => {
                    let probe =
                    || -> Result<SafetyNetRecoveryProbeReading, crate::nftables::NftablesError> {
                        #[cfg(all(target_os = "linux", feature = "test-isolation"))]
                        if RECLAIM_OWNED_PROBE_FORCE_ERROR
                            .swap(false, std::sync::atomic::Ordering::SeqCst)
                        {
                            return Err(crate::nftables::NftablesError::InvocationFailed(
                                "test-isolation: reclaim-owned probe forced to fail".to_string(),
                            ));
                        }
                        read_safety_net_recovery_probe()
                    };
                    match classify_safety_net_recovery_probe(probe) {
                        SafetyNetRecoveryDecision::RecoverSafetyNet => {
                            let outcome = disarm_recover_deny_all_net(
                                journal_path,
                                "a same-boot Owned journal record whose live table is this \
                                 daemon's safety net",
                            );
                            drop(lock);
                            return outcome;
                        }
                        SafetyNetRecoveryDecision::NotSafetyNet => CastleTableOwnership {
                            table_handle,
                            base_chain_handle,
                            marker,
                        },
                        SafetyNetRecoveryDecision::ProbeFailed(probe_err) => {
                            drop(lock);
                            return Err(disarm_failed(format!(
                                "could not determine whether the live table is this daemon's \
                                 safety net; refusing to delete (retaining the journal): \
                                 {probe_err}"
                            )));
                        }
                    }
                }
                // An interrupted (Preparing) acquisition with a live table: capture
                // the live handles by marker. A marker mismatch (foreign) or nft
                // error -> refuse + RETAIN.
                ReclaimDecision::FinalizeInterrupted { marker } => {
                    match crate::nftables::capture_owned_castle_table(&marker) {
                        Ok(o) => o,
                        // GF1.1 create-failure recovery on the DISARM path. The journal
                        // is Preparing for this boot but the live table is not a
                        // capturable owned table. If it is this daemon's OWN safety
                        // net (the create-failed-then-ReArmLostOwned wedge state),
                        // disarm can clean it up (delete by name, confirm absence,
                        // clear the record) since this is explicit teardown;
                        // otherwise refuse + RETAIN. Without this, --disarm was
                        // wedged exactly like acquire.
                        //
                        // PIN (shared requirement, both arms; must match the
                        // identical requirement at the `ReclaimOwned` arm above):
                        // the recovery branch requires the SAME two facts from ONE
                        // inventory fetch, a positive recogniser answer AND that
                        // inventory's table object carrying no comment key at all;
                        // either alone is `NotSafetyNet`, which here takes the
                        // existing marker-mismatch refusal below rather than a
                        // further reclaim step (there is none once capture has
                        // already failed).
                        Err(err) => {
                            let probe = || -> Result<
                                SafetyNetRecoveryProbeReading,
                                crate::nftables::NftablesError,
                            > {
                                read_safety_net_recovery_probe()
                            };
                            match classify_safety_net_recovery_probe(probe) {
                                SafetyNetRecoveryDecision::RecoverSafetyNet => {
                                    let outcome = disarm_recover_deny_all_net(
                                        journal_path,
                                        "an interrupted acquisition (Preparing)",
                                    );
                                    drop(lock);
                                    return outcome;
                                }
                                SafetyNetRecoveryDecision::NotSafetyNet => {
                                    drop(lock);
                                    return Err(disarm_failed(format!(
                                        "an interrupted acquisition's marker does not match \
                                         the live table and it is not this daemon's safety \
                                         net; refusing to delete (retaining the record): {err}"
                                    )));
                                }
                                SafetyNetRecoveryDecision::ProbeFailed(probe_err) => {
                                    drop(lock);
                                    return Err(disarm_failed(format!(
                                        "an interrupted acquisition could not be captured \
                                         ({err}) and the safety-net recovery probe failed \
                                         ({probe_err}); refusing without clobbering \
                                         (retaining the record)"
                                    )));
                                }
                            }
                        }
                    }
                }
            };

        // 5) Re-validate the EXACT complete inventory immediately before deletion.
        //    A drift (replaced, mutated, foreign) -> refuse + RETAIN the journal.
        // Structure-only: disarm holds no fortress id and no manifest, and its
        // question is "has this drifted off the identity we captured, so that
        // deleting it would clobber someone else's state?" A seal or uid mismatch
        // here would wedge the operator's only recovery path while protecting
        // nothing, since the table is deleted on the very next step.
        if let Err(err) = crate::nftables::verify_owned_castle_table(
            &owned,
            &crate::nftables::ExpectedAgentBinding::StructureOnly,
        ) {
            drop(lock);
            return Err(disarm_failed(format!(
                "the live table no longer matches the owned identity; refusing to delete \
                 (retaining the journal): {err}"
            )));
        }

        // 6) Handle-qualified delete (re-verifies + deletes by handle internally).
        //    On error RETAIN the journal and fail.
        if let Err(err) = crate::nftables::remove_owned_castle_table(
            &owned,
            &crate::nftables::ExpectedAgentBinding::StructureOnly,
        ) {
            drop(lock);
            return Err(disarm_failed(format!(
                "handle-qualified delete failed; retaining the journal: {err}"
            )));
        }

        // 7) Verify ABSENCE immediately after. If the table is still present or the
        //    query errors, the delete is AMBIGUOUS: RETAIN the journal and fail.
        match crate::nftables::table_exists() {
            Ok(false) => {}
            Ok(true) => {
                drop(lock);
                return Err(disarm_failed(
                    "table still present after a handle-qualified delete; retaining the journal"
                        .to_string(),
                ));
            }
            Err(err) => {
                drop(lock);
                return Err(disarm_failed(format!(
                    "could not verify table absence after delete; retaining the journal: {err}"
                )));
            }
        }

        // 8) Deletion AND absence are positively confirmed: clear the journal now.
        //    A clear failure is surfaced (the table is gone, but the operator must
        //    know the record persisted).
        journal::clear(journal_path).map_err(|err| {
            disarm_failed(format!(
                "table deleted and absent, but clearing the ownership journal failed: {err}"
            ))
        })?;
        drop(lock);
        Ok(DisarmOutcome::TableDeleted)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(EnforcementError::NotAvailableOnPlatform(
            ComponentKind::NftablesTable.as_str(),
        ))
    }
}

// ---------------------------------------------------------------------------
// NFQUEUE component (thread-backed).
// ---------------------------------------------------------------------------

struct NfqueueProvider {
    decision_engine: Arc<DecisionEngine>,
    nfqueue_config: NfqueueConfig,
}

#[cfg(any(target_os = "linux", test))]
fn record_nfqueue_serve_failure(
    decision_engine: &DecisionEngine,
    result: Result<(), crate::nfqueue::NfqueueError>,
) {
    if let Err(err) = result {
        let operation = match err {
            crate::nfqueue::NfqueueError::VerdictDeadlineExceeded(_)
            | crate::nfqueue::NfqueueError::QueueSaturated(_) => "wall_saturated",
            _ => "nfqueue_serve_failed",
        };
        if let Err(audit_err) = decision_engine.append_control_audit_bounded(
            operation,
            &err.to_string(),
            crate::decision::FAILURE_AUDIT_BUDGET,
        ) {
            // SAFETY: stderr is the last-resort channel when the durable failure audit
            // ITSELF failed, so the structured channel is the thing unavailable here.
            eprintln!(
                "castle-wall-daemon: NFQUEUE serve failed ({err}) and durable failure audit failed: {audit_err}"
            );
            return;
        }
        // SAFETY: stderr is the operator-visible NFQUEUE failure line that accompanies
        // the durable audit written just above; the audit is the record, this is the
        // journal diagnostic an operator sees without opening the WAL.
        eprintln!("castle-wall-daemon: NFQUEUE serve failed: {err}");
    }
}

impl ComponentProvider for NfqueueProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::Nfqueue
    }

    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
        #[cfg(target_os = "linux")]
        {
            use std::sync::atomic::AtomicU64;
            // The verdict callback routes each packet through the shared decision
            // engine (verified policy + durable audit + fail-closed).
            let verdict_fn =
                crate::nfqueue::build_verdict_callback(Arc::clone(&self.decision_engine));
            let serve_decision_engine = Arc::clone(&self.decision_engine);
            let bind_config = self.nfqueue_config.clone();
            // Processed-packet counter owned by the serve loop for its lifetime.
            let processed = Arc::new(AtomicU64::new(0));
            let saturated = Arc::new(AtomicU64::new(0));
            let serve_config = self.nfqueue_config.clone();
            let component = crate::thread_component::ThreadBackedComponent::spawn(
                ComponentKind::Nfqueue,
                // BIND (synchronous, on the calling thread): open+bind the queue
                // with FAIL_OPEN off. The component is ready only after this
                // returns Ok, so it is never ready before the kernel queue is
                // really intercepting; a wedged bind is bounded by systemd
                // TimeoutStartSec, not a false in-process deadline (blocker 8).
                move || {
                    crate::nfqueue::open_bind_fail_closed(&bind_config).map_err(|err| {
                        EnforcementError::AcquireFailed {
                            kind: ComponentKind::Nfqueue.as_str(),
                            detail: err.to_string(),
                        }
                    })
                },
                // SERVE: run the verdict loop until stopped. Returning (cleanly or
                // via Err) ends the thread, which the component turns into loss of
                // health.
                move |mut bound, stop| {
                    let result = crate::nfqueue::serve_bound_queue(
                        &mut bound,
                        verdict_fn,
                        serve_config.verdict_deadline,
                        &processed,
                        &saturated,
                        stop,
                    );
                    record_nfqueue_serve_failure(&serve_decision_engine, result);
                },
            )?;
            Ok(Box::new(component))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&self.decision_engine, &self.nfqueue_config);
            Err(EnforcementError::NotAvailableOnPlatform(
                ComponentKind::Nfqueue.as_str(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest watcher component (thread-backed).
// ---------------------------------------------------------------------------

struct ManifestWatcherProvider {
    decision_engine: Arc<DecisionEngine>,
    policy_dir: PathBuf,
    poll_interval: Duration,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, thiserror::Error)]
enum ManifestWatcherControlError {
    #[error("manifest reload authorization failed: {0}")]
    ReloadAuthorization(String),
    #[error(transparent)]
    Audit(#[from] ControlAuditError),
}

#[cfg(any(target_os = "linux", test))]
fn record_manifest_watcher_degradation(
    decision_engine: &DecisionEngine,
    reason: &str,
    poll_interval: Duration,
) -> Result<(), ControlAuditError> {
    decision_engine
        .append_control_audit(
            "manifest_watcher_degraded_to_poll",
            &format!(
                "poll_interval_ms={} reason={reason}",
                poll_interval.as_millis()
            ),
        )
        .map(|_| ())
}

/// Drive `ManifestStore::reload` off watcher events until stopped, treating
/// EVERY hard poll error as terminal. (blocker 5)
///
/// `WouldBlock`/idle already surfaces as `Ok(None)` from `poll_event` (see
/// `manifest::watcher`), so any `Err` here is a genuine hard failure (e.g. a
/// broken inotify fd). Returning on it ends the serve thread, which the
/// `ThreadBackedComponent` turns into loss-of-health — surfacing a dead watcher
/// rather than silently spinning on a persistent error and reporting ready. On
/// `ManifestChanged` first stages a fully verified candidate, then requires a
/// durable `manifest_watcher_reload_authorized` WAL record before committing
/// that exact staged value. A verification `Err` keeps the prior verified
/// generation in force (F-2) and durably emits
/// `manifest_verify_failed_kept_prior`. Any required-audit failure is terminal
/// to watcher health, preserving the prior generation and causing systemd to
/// restart the daemon.
///
/// Pure over an injected `poll` fn (not tied to the concrete watcher or to
/// Linux) so the terminate-on-hard-error contract is unit-testable on the dev
/// host without a real inotify fd.
///
/// Compiled on Linux (where the watcher provider calls it) and under `test`
/// (where the dev host exercises it); on a non-Linux non-test build there is no
/// caller, so it is cfg'd out to avoid a dead-code diagnostic under
/// `clippy -D warnings`.
/// Longest the serve loop may sleep inside one `poll_event` call.
///
/// `ManifestWatcher::poll_event` naps `wait_for.min(poll_interval)` before it
/// stats, so THIS value is what bounds how long a stop request waits, and (when
/// it is smaller than the configured interval) it is also the real stat cadence.
/// It is deliberately smaller than `MANIFEST_WATCHER_POLL_INTERVAL_MS` so
/// SIGTERM stays responsive; the configured interval is enforced by the elapsed
/// check in `drive_manifest_watcher_at`, not by the nap, so the audited cadence and
/// the observed one are the same number. Failure mode if these are conflated
/// again: the degradation audit records `poll_interval_ms=2000` while the
/// watcher actually stats ten times a second, and every doc citing "a 2-second
/// poller" is false.
#[cfg(any(target_os = "linux", test))]
const MANIFEST_WATCHER_SERVE_WAIT: Duration = Duration::from_millis(200);

#[cfg(any(target_os = "linux", test))]
fn manifest_watcher_stat_cadence(degraded_to_poll: bool, poll_interval: Duration) -> Duration {
    if degraded_to_poll {
        poll_interval
    } else {
        // inotify blocks inside poll_event until an event or the short serve
        // wait; imposing the fallback stat cadence here would add up to two
        // seconds of avoidable policy-activation latency.
        Duration::ZERO
    }
}

/// Drive the watcher with an explicit cadence. Production selects zero for the
/// event-driven inotify mode and the configured interval for degraded polling;
/// tests can use short intervals without waiting real seconds.
#[cfg(any(target_os = "linux", test))]
fn drive_manifest_watcher_at<P>(
    mut poll: P,
    decision_engine: Option<Arc<DecisionEngine>>,
    stop: &std::sync::atomic::AtomicBool,
    poll_interval: Duration,
) where
    P: FnMut(
        Duration,
    ) -> Result<
        Option<crate::manifest::watcher::WatcherEvent>,
        crate::manifest::watcher::WatcherError,
    >,
{
    use std::sync::atomic::Ordering;
    let mut last_stat: Option<std::time::Instant> = None;
    while !stop.load(Ordering::SeqCst) {
        // Two DIFFERENT bounds, kept apart on purpose: the nap bounds shutdown
        // responsiveness, the elapsed check bounds the stat cadence. Collapsing
        // them (passing the nap as the cadence) is what made the effective
        // fallback 200ms while every doc and the degradation audit said 2000ms.
        if let Some(at) = last_stat {
            if at.elapsed() < poll_interval {
                std::thread::sleep(MANIFEST_WATCHER_SERVE_WAIT.min(poll_interval - at.elapsed()));
                continue;
            }
        }
        last_stat = Some(std::time::Instant::now());
        match poll(MANIFEST_WATCHER_SERVE_WAIT) {
            // DegradedToPoll only ever arrives at start (handled at bind time);
            // other events / idle polls (Ok(None)) are no-ops.
            Ok(event) => {
                if let Err(err) = handle_manifest_watcher_event(event, decision_engine.as_deref()) {
                    // SAFETY: stderr is the operator channel for a TERMINAL control-path failure
                    // in the manifest watcher thread; the thread returns immediately after, so
                    // nothing downstream would carry the reason.
                    eprintln!(
                        "castle-wall-daemon: fatal manifest watcher control-path failure: {err}"
                    );
                    return;
                }
            }
            // A hard poll error is TERMINAL: return so the thread exits and the
            // component turns health non-green. WouldBlock never reaches here.
            Err(err) => {
                if let Some(decision_engine) = decision_engine.as_deref() {
                    if let Err(audit_err) = decision_engine.append_control_audit_bounded(
                        "manifest_watcher_lost",
                        &err.to_string(),
                        crate::decision::FAILURE_AUDIT_BUDGET,
                    ) {
                        // SAFETY: stderr is the last-resort channel when the durable loss audit for
                        // the watcher itself could not be written.
                        eprintln!(
                            "castle-wall-daemon: manifest watcher lost and durable loss audit failed: {audit_err}"
                        );
                    }
                }
                return;
            }
        }
    }
}

impl ComponentProvider for ManifestWatcherProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::ManifestWatcher
    }

    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
        #[cfg(target_os = "linux")]
        {
            use crate::manifest::watcher::{ManifestWatcher, WatcherEvent};
            let policy_dir = self.policy_dir.clone();
            let poll_interval = self.poll_interval;
            // The verified store the watcher drives reloads against. On an
            // invalid reload the store keeps the prior verified generation
            // (F-2), so a bad manifest never drops the good policy in force.
            let decision_engine = Arc::clone(&self.decision_engine);
            let bind_decision_engine = Arc::clone(&decision_engine);
            let startup_decision_engine = Arc::clone(&decision_engine);
            let component = crate::thread_component::ThreadBackedComponent::spawn_with_worker_init_and_heartbeat(
                ComponentKind::ManifestWatcher,
                // BIND (synchronous): start the watcher (inotify preferred, poll
                // fallback). Bounded by systemd TimeoutStartSec, not an in-process
                // deadline (blocker 8).
                move || {
                    let (watcher, degraded) =
                        ManifestWatcher::start(policy_dir, poll_interval, true).map_err(|err| {
                            EnforcementError::AcquireFailed {
                                kind: ComponentKind::ManifestWatcher.as_str(),
                                detail: err.to_string(),
                            }
                        })?;
                    // Expose the degraded (poll) fallback honestly rather than
                    // silently: an operator reading the journal must see that
                    // manifest reloads now have higher latency than inotify.
                    if let Some(WatcherEvent::DegradedToPoll { reason }) = &degraded {
                        record_manifest_watcher_degradation(
                            &bind_decision_engine,
                            reason,
                            poll_interval,
                        )
                        .map_err(|err| {
                            EnforcementError::AcquireFailed {
                                kind: ComponentKind::ManifestWatcher.as_str(),
                                detail: format!(
                                "poll fallback could not be durably audited before readiness: {err}"
                            ),
                            }
                        })?;
                        // Also keep a loud boot diagnostic in systemd's journal;
                        // the authenticated WAL record above is the required audit.
                        // SAFETY: stderr is the boot diagnostic beside the authenticated WAL record
                        // written just above; the WAL entry is the required audit, this line is the
                        // loud journal copy so a degraded watcher is visible without a drain.
                        eprintln!(
                            "castle-wall-daemon: manifest watcher degraded to polling: {reason}"
                        );
                    }
                    Ok(watcher)
                },
                // WORKER STARTUP CHECK: perform the first REAL watcher read on the
                // worker thread, then reconcile the authoritative manifest after
                // watch registration. A replacement before registration is read
                // by reconciliation; one after registration is either read by
                // reconciliation or remains queued for the serve loop. Readiness
                // therefore cannot straddle an unobserved boot/watch gap.
                move |watcher| {
                    let _startup_event = watcher.poll_event(Duration::ZERO).map_err(|err| {
                        EnforcementError::AcquireFailed {
                            kind: ComponentKind::ManifestWatcher.as_str(),
                            detail: format!("first watcher read failed before readiness: {err}"),
                        }
                    })?;
                    reconcile_manifest_after_watch_registration(&startup_decision_engine).map_err(
                        |err| EnforcementError::AcquireFailed {
                            kind: ComponentKind::ManifestWatcher.as_str(),
                            detail: format!(
                                "manifest reconciliation failed after watch registration: {err}"
                            ),
                        },
                    )?;
                    Ok(())
                },
                poll_interval + Duration::from_secs(3),
                // SERVE: drive reloads off watcher events, terminating on any
                // hard poll error (blocker 5). Factored into `drive_manifest_watcher_at`
                // so the terminate-on-error contract is unit-tested directly.
                move |mut watcher, stop, heartbeat| {
                    let cadence = manifest_watcher_stat_cadence(
                        watcher.is_degraded(),
                        poll_interval,
                    );
                    drive_manifest_watcher_at(
                        |wait| {
                            if let Ok(mut at) = heartbeat.lock() {
                                *at = std::time::Instant::now();
                            }
                            let result = watcher.poll_event(wait);
                            if let Ok(mut at) = heartbeat.lock() {
                                *at = std::time::Instant::now();
                            }
                            result
                        },
                        Some(decision_engine),
                        stop,
                        cadence,
                    );
                },
            )?;
            Ok(Box::new(component))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&self.decision_engine, &self.policy_dir, self.poll_interval);
            Err(EnforcementError::NotAvailableOnPlatform(
                ComponentKind::ManifestWatcher.as_str(),
            ))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn handle_manifest_watcher_event(
    event: Option<crate::manifest::watcher::WatcherEvent>,
    decision_engine: Option<&DecisionEngine>,
) -> Result<(), ManifestWatcherControlError> {
    if matches!(
        event,
        Some(crate::manifest::watcher::WatcherEvent::ManifestChanged)
    ) {
        if let Some(decision_engine) = decision_engine {
            reload_manifest_from_watcher(
                decision_engine,
                "manifest_watcher_reload_authorized",
                "watcher",
            )?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn reconcile_manifest_after_watch_registration(
    decision_engine: &DecisionEngine,
) -> Result<(), ManifestWatcherControlError> {
    reload_manifest_from_watcher(
        decision_engine,
        "manifest_watcher_startup_reconciled",
        "watcher_startup",
    )
}

#[cfg(any(target_os = "linux", test))]
fn reload_manifest_from_watcher(
    decision_engine: &DecisionEngine,
    operation: &str,
    context: &str,
) -> Result<(), ManifestWatcherControlError> {
    match decision_engine.reload_manifest_authorized(operation, context) {
        Ok(_) => Ok(()),
        Err(crate::decision::ManifestReloadAuthorizationError::Verify(err)) => {
            decision_engine.append_control_audit_bounded(
                "manifest_verify_failed_kept_prior",
                &err.to_string(),
                crate::decision::FAILURE_AUDIT_BUDGET,
            )?;
            Ok(())
        }
        // A refused IDENTITY change is NON-FATAL to the watcher, exactly like a
        // verification failure above and for the same reason: the prior policy is
        // still live and the file on disk is the operator's problem, not a
        // control-path failure. Making it fatal would take the watcher component
        // down for a manifest the daemon correctly refused, and the bound matters
        // because the refused file STAYS on disk: every later watcher event
        // re-reads it, so the cost per event has to be one bounded row and no
        // more. An audit failure here is still fatal (the `?`), because a refusal
        // nobody can prove happened is not a refusal.
        Err(crate::decision::ManifestReloadAuthorizationError::IdentityChangeWhileArmed(
            detail,
        )) => {
            decision_engine.append_control_audit_bounded(
                "manifest_identity_change_refused_kept_prior",
                &detail,
                crate::decision::FAILURE_AUDIT_BUDGET,
            )?;
            Ok(())
        }
        Err(err) => Err(ManifestWatcherControlError::ReloadAuthorization(
            err.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditRingBuffer, WalWriter};
    use crate::crypto::castle_wall_signing_key_id;
    use crate::manifest::canonical_json::canonicalize_to_bytes;
    use crate::manifest::verify::{
        AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
    };
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn nft_health_only_calls_verified_absence_or_foreign_identity_lost() {
        use crate::nftables::NftablesError;
        assert_eq!(classify_nft_ownership_probe(Ok(())), Ok(true));
        assert_eq!(
            classify_nft_ownership_probe(Err(NftablesError::ForeignState("drift".into()))),
            Ok(false)
        );
        assert_eq!(
            classify_nft_ownership_probe(Err(NftablesError::InvocationFailed(
                "No such file or directory".into()
            ))),
            Ok(false)
        );
        for indeterminate in [
            NftablesError::BinaryMissing("nft".into()),
            NftablesError::InvocationFailed("permission denied".into()),
            NftablesError::ParseFailed("short read".into()),
        ] {
            assert_eq!(classify_nft_ownership_probe(Err(indeterminate)), Err(()));
        }
    }

    #[test]
    fn the_acquisition_path_never_adopts_an_unknown_history_record() {
        // The rule lives on the acquisition path, not in the shared routing. This asserts
        // it at the source: the acquisition arm recomputes the decision and diverts a
        // same-boot record whose `confined` key is absent to the boot owner, which
        // installs the host-wide net and skips the persist. The companion test in
        // `ownership_journal` proves the SHARED routing still reaches `ReclaimOwned`, so
        // disarm keeps its recovery path.
        let whole = include_str!("runtime_providers.rs");
        let start = whole
            .find("// THE NEVER-ADOPT RULE, applied HERE and only here")
            .expect("the rule is stated at the acquisition site");
        let end = whole[start..]
            .find("let ownership = match decision {")
            .map(|o| start + o)
            .expect("the rule precedes the routing match");
        let region = &whole[start..end];
        assert!(
            region.contains("OwnershipJournal::Owned { confined: None, .. }"),
            "the rule must key on the ABSENT confined key, not on the uid comparison"
        );
        assert!(
            region.contains("ReclaimDecision::ReclaimOwned { .. }, true")
                && region.contains("ReclaimDecision::ReArmLostOwned"),
            "an unknown-history record must be diverted from adoption to the boot owner"
        );
        // And the rule is NOT in the shared decision function.
        let journal_source = include_str!("ownership_journal.rs");
        let decide_at = journal_source
            .find("pub fn decide(")
            .expect("the shared routing is in that file");
        let decide_end = journal_source[decide_at..]
            .find("\n#[cfg(test)]")
            .map(|o| decide_at + o)
            .unwrap_or(journal_source.len());
        assert!(
            !journal_source[decide_at..decide_end].contains("confined: None"),
            "the shared routing must not carry the acquisition-specific rule, or disarm \
             loses its recovery arm"
        );
    }

    // ---- The safety net's scope resolver (memo D1b) ----

    fn overflow_fixture() -> crate::safety_net_uid::HostOverflowUid {
        crate::safety_net_uid::HostOverflowUid::from_value(65534)
    }

    fn known(uids: &[(u32, crate::ownership_journal::ConfinedRole)]) -> ConfinedHistory {
        ConfinedHistory::Known(
            uids.iter()
                .map(|&(uid, role)| crate::ownership_journal::ConfinedIdentity { uid, role })
                .collect(),
        )
    }

    #[test]
    fn deny_set_is_the_union_of_all_three_sources_and_the_kill_set_excludes_the_live_table() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope};
        use crate::ownership_journal::ConfinedRole;

        let resolution = resolve_safety_net_scope(
            // (a) the journal's recorded history
            &known(&[(60001, ConfinedRole::Agent), (60002, ConfinedRole::Gate)]),
            // (b) the currently admitted identity
            Some((60003, Some(60004))),
            // (c) the live table's own bindings
            &LiveTableBindings::Bindings(vec![60005]),
            overflow_fixture(),
        );
        let SafetyNetScope::Identity(set) = &resolution.scope else {
            panic!("an identity is recoverable, so the scope is the identity net");
        };
        assert_eq!(set.uids(), vec![60001, 60002, 60003, 60004, 60005]);
        assert_eq!(resolution.reason, SafetyNetReason::Identity);
        // KILL SET = (a) union (b) ONLY. 60005 came from the live kernel table,
        // which a CAP_NET_ADMIN actor can write, so it may be DENIED but never
        // KILLED.
        assert_eq!(resolution.kill_set, vec![60001, 60002, 60003, 60004]);
        assert!(resolution.sources.journal);
        assert!(resolution.sources.manifest);
        assert!(resolution.sources.live_table);
    }

    #[test]
    fn fresh_instance_rebuilds_kill_set_from_authenticated_journal_and_manifest_only() {
        use crate::nftables::{LiveTableBindings, SafetyNetScope};
        use crate::ownership_journal::{
            self as journal, ConfinedIdentity, ConfinedRole, JournalIdentity, OwnershipJournal,
        };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nft-ownership.json");
        let key_path = dir.path().join("nft-journal-auth.key");
        let first_key = journal::load_or_generate_auth_key(&key_path).unwrap();
        let record = OwnershipJournal::owned_with_known_history(
            JournalIdentity {
                schema_version: journal::JOURNAL_SCHEMA_VERSION,
                marker: "m".into(),
                boot_id: "3f2b91c0-7d4e-4a18-b6c2-0e15a9d83b77".into(),
                source: "/usr/local/bin/castle-wall-daemon".into(),
            },
            2,
            1,
            vec![ConfinedIdentity {
                uid: 60001,
                role: ConfinedRole::Agent,
            }],
        )
        .unwrap();
        journal::store_atomic(&path, &record, &first_key).unwrap();
        drop(first_key);

        // A new instance reads only the persisted authenticated record; it has
        // no retained in-memory deny set from the process that wrote it.
        let next_key = journal::load_or_generate_auth_key(&key_path).unwrap();
        let reloaded = journal::load(&path, Some(&next_key)).unwrap().unwrap();
        let history = ConfinedHistory::Known(reloaded.confined().unwrap().to_vec());
        let resolution = resolve_safety_net_scope(
            &history,
            Some((60002, Some(60003))),
            &LiveTableBindings::Bindings(vec![60004]),
            overflow_fixture(),
        );
        let SafetyNetScope::Identity(set) = resolution.scope else {
            panic!("known history confines the net");
        };
        assert_eq!(set.uids(), vec![60001, 60002, 60003, 60004]);
        assert_eq!(resolution.kill_set, vec![60001, 60002, 60003]);
        assert!(
            resolution.sources.journal
                && resolution.sources.manifest
                && resolution.sources.live_table
        );
    }

    #[test]
    fn unknown_history_resolves_host_wide_whatever_the_other_sources_say() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope};
        // The ABSENT-KEY row: a record from a previous binary cannot prove which
        // uids were bound this boot, because the pre-upgrade reload path removed
        // stale jumps while never terminating a rotated-away uid's processes.
        let resolution = resolve_safety_net_scope(
            &ConfinedHistory::Unknown,
            Some((60003, Some(60004))),
            &LiveTableBindings::Bindings(vec![60005]),
            overflow_fixture(),
        );
        assert_eq!(resolution.scope, SafetyNetScope::HostWide);
        assert_eq!(resolution.reason, SafetyNetReason::UnknownHistory);
        // The kill set is still (b): an admitted identity is safe to sweep.
        assert_eq!(resolution.kill_set, vec![60003, 60004]);
    }

    #[test]
    fn a_known_empty_history_still_resolves_from_the_manifest_and_the_live_table() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope};
        // FAIL-BEFORE / the distinction that matters: this is `Some(vec![])`, this
        // binary's own record before any identity was bound, NOT an absent key. It
        // must narrow to the identity net, while the absent-key case above must not.
        let resolution = resolve_safety_net_scope(
            &known(&[]),
            Some((60003, None)),
            &LiveTableBindings::Bindings(vec![60005]),
            overflow_fixture(),
        );
        let SafetyNetScope::Identity(set) = &resolution.scope else {
            panic!("a known-empty history resolves from the other two sources");
        };
        assert_eq!(set.uids(), vec![60003, 60005]);
        assert_eq!(resolution.reason, SafetyNetReason::Identity);
    }

    #[test]
    fn an_empty_union_resolves_host_wide_with_its_own_reason() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope};
        let resolution = resolve_safety_net_scope(
            &known(&[]),
            None,
            &LiveTableBindings::Bindings(Vec::new()),
            overflow_fixture(),
        );
        assert_eq!(resolution.scope, SafetyNetScope::HostWide);
        // A DISTINCT reason from unknown history: the operator action differs, and
        // folding the two made an over-capacity set read as unknown history.
        assert_eq!(resolution.reason, SafetyNetReason::EmptyDenySet);
        assert!(resolution.kill_set.is_empty());
    }

    #[test]
    fn a_foreign_or_unreadable_live_table_contributes_nothing_and_is_not_read_as_empty() {
        use crate::nftables::{LiveTableBindings, SafetyNetScope};
        // Source (c) yields NOTHING for a table that is not ours, and an
        // identity-parser error is never read as "the table has no bindings".
        for live in [
            LiveTableBindings::NotOurTable {
                detail: "foreign rule".into(),
            },
            LiveTableBindings::Unreadable {
                detail: "nft timed out".into(),
            },
        ] {
            let resolution = resolve_safety_net_scope(
                &known(&[]),
                Some((60003, None)),
                &live,
                overflow_fixture(),
            );
            let SafetyNetScope::Identity(set) = &resolution.scope else {
                panic!("the manifest still names an identity");
            };
            assert_eq!(set.uids(), vec![60003]);
            assert!(
                !resolution.sources.live_table,
                "the audit row must not claim the live table contributed"
            );
        }
    }

    #[test]
    fn a_deny_set_over_capacity_resolves_host_wide_with_the_count_and_the_cap() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope, DENY_SET_MAX};
        use crate::ownership_journal::ConfinedRole;
        // FAIL-BEFORE (the packet's deny-set bound test): at the cap the identity net
        // installs; one over it the host-wide shape installs with the
        // `deny-set-over-capacity` reason, and NOTHING is truncated, because a
        // dropped uid stops being denied.
        let at_cap: Vec<u32> = (0..DENY_SET_MAX as u32).map(|i| 60_000 + i).collect();
        let bindings = LiveTableBindings::Bindings(at_cap.clone());
        let resolution = resolve_safety_net_scope(&known(&[]), None, &bindings, overflow_fixture());
        let SafetyNetScope::Identity(set) = &resolution.scope else {
            panic!("exactly at the cap is an operating shape");
        };
        assert_eq!(set.len(), DENY_SET_MAX);

        let over: Vec<u32> = (0..=DENY_SET_MAX as u32).map(|i| 60_000 + i).collect();
        let resolution = resolve_safety_net_scope(
            &known(&[(59_999, ConfinedRole::Agent)]),
            None,
            &LiveTableBindings::Bindings(over),
            overflow_fixture(),
        );
        assert_eq!(resolution.scope, SafetyNetScope::HostWide);
        assert_eq!(resolution.retained_deny_uids().len(), DENY_SET_MAX + 2);
        assert!(resolution.retained_deny_uids().contains(&59_999));
        match resolution.reason {
            SafetyNetReason::DenySetOverCapacity { count, cap } => {
                assert_eq!(count, DENY_SET_MAX + 2);
                assert_eq!(cap, DENY_SET_MAX);
            }
            other => panic!("expected the over-capacity reason, got {other:?}"),
        }
        // The kill set is unaffected by the cap: it is sources (a) and (b) only.
        assert_eq!(resolution.kill_set, vec![59_999]);
    }

    #[test]
    fn an_unattestable_uid_from_any_source_never_reaches_rule_one() {
        use crate::nftables::{LiveTableBindings, SafetyNetScope};
        use crate::ownership_journal::ConfinedRole;
        // A live kernel table a CAP_NET_ADMIN actor wrote could name 0 or the host's
        // overflow uid. Those are dropped from the deny set while the real
        // identities are kept, so one hostile member cannot collapse the net to
        // host-wide (which would deny the operator).
        let resolution = resolve_safety_net_scope(
            &known(&[(60001, ConfinedRole::Agent)]),
            None,
            &LiveTableBindings::Bindings(vec![0, 65534, u32::MAX, 60005]),
            overflow_fixture(),
        );
        let SafetyNetScope::Identity(set) = &resolution.scope else {
            panic!("the attestable members still form an identity net");
        };
        assert_eq!(set.uids(), vec![60001, 60005]);
    }

    #[test]
    fn refusal_texts_name_the_scope_and_the_repair_order() {
        use crate::nftables::{
            safety_net_scope_sentence, SafetyNetReason, SafetyNetScope, DENY_SET_MAX,
        };
        use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet};
        let set = ConfinedUidSet::from_validated(vec![
            validate_safety_net_uid(60123, overflow_fixture()).unwrap(),
            validate_safety_net_uid(60124, overflow_fixture()).unwrap(),
        ])
        .unwrap();
        let identity =
            safety_net_scope_sentence(&SafetyNetScope::Identity(set), &SafetyNetReason::Identity);
        assert!(identity.contains("60123"));
        assert!(
            identity.contains("including root and ssh, is unaffected"),
            "an operator's first question is whether their own session dies: {identity}"
        );
        assert!(identity.contains("stop the castle-wall unit"));

        // ONE TEXT PER REASON, each naming that reason and then stating plainly that
        // operator access is NOT preserved.
        for (reason, expected) in [
            (
                SafetyNetReason::EmptyDenySet,
                "no confined identity was recoverable",
            ),
            (
                SafetyNetReason::UnknownHistory,
                "history unknown for this boot",
            ),
            (
                SafetyNetReason::DenySetOverCapacity {
                    count: DENY_SET_MAX + 1,
                    cap: DENY_SET_MAX,
                },
                "deny set over capacity (257 of 256)",
            ),
        ] {
            let text = safety_net_scope_sentence(&SafetyNetScope::HostWide, &reason);
            assert!(
                text.contains(expected),
                "reason text missing {expected}: {text}"
            );
            assert!(text.contains("operator access is not preserved on this path"));
            // The repair order, in the order that WORKS: stopping the unit first is
            // what stops systemd restarting the daemon into the same refusal and
            // re-taking the host lock disarm needs.
            assert!(text
                .contains("stop the castle-wall unit, repair the wall, then run the disarm verb"));
        }
    }

    #[test]
    fn the_audit_state_describes_only_the_predicate_actually_installed() {
        use crate::nftables::{
            SafetyNetAuditState, SafetyNetReason, SafetyNetScope, SafetyNetSources,
        };
        use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet};
        let set = ConfinedUidSet::from_validated(vec![validate_safety_net_uid(
            60123,
            overflow_fixture(),
        )
        .unwrap()])
        .unwrap();
        let sources = SafetyNetSources {
            journal: true,
            manifest: true,
            live_table: false,
        };
        let installed = SafetyNetAuditState::installed(
            &SafetyNetScope::Identity(set),
            &SafetyNetReason::Identity,
            sources.clone(),
        );
        let json = installed.to_json();
        assert_eq!(json["state"], "installed");
        assert_eq!(json["shape"], "v2-confined-identity");
        assert_eq!(json["reason"], "identity");
        assert_eq!(json["denied_uids"], serde_json::json!([60123]));
        assert_eq!(json["rules"].as_array().expect("rules").len(), 3);
        assert_eq!(json["unattestable_packets"], "drop-except-kernel-nd");
        assert_eq!(json["kernel_nd_accepted"].as_array().unwrap().len(), 3);
        assert!(json["coverage"]
            .as_str()
            .unwrap()
            .contains("packet sockets"));

        // The host-wide shape accepts NO neighbour discovery, because it carries no
        // rules at all. Saying so is the honest row.
        let host_wide = SafetyNetAuditState::installed(
            &SafetyNetScope::HostWide,
            &SafetyNetReason::UnknownHistory,
            sources,
        );
        let json = host_wide.to_json();
        assert_eq!(json["shape"], "v1-host-wide");
        assert_eq!(json["kernel_nd_accepted"], serde_json::json!([]));
        assert_eq!(json["rules"], serde_json::json!([]));

        // A FAILED install never attests to a protection that is not in place, and a
        // path that attempted nothing says so distinctly.
        let failed = SafetyNetAuditState::InstallFailed {
            attempted_scope: "v2-confined-identity".into(),
            error: "nft timed out".into(),
        };
        assert_eq!(failed.to_json()["state"], "install_failed");
        assert_eq!(failed.tag(), "install_failed");
        assert_eq!(
            SafetyNetAuditState::Unverified.to_json(),
            serde_json::json!({ "state": "unverified" })
        );
        assert_eq!(SafetyNetAuditState::Unverified.tag(), "unverified");
        assert_eq!(
            SafetyNetAuditState::NotAttempted.to_json()["state"],
            "not_attempted"
        );
    }

    // Part A performs no table deletion outside the disarm verb. These two tests pin
    // that: a failed net install leaves the castle table standing and fires the PR-3
    // sweep hook, and a successful install fires no hook at all.
    #[test]
    fn drift_never_deletes_the_table_and_hooks_the_sweep_only_on_a_failed_install() {
        use crate::nftables::NftablesError;
        use std::cell::Cell;

        let engine = test_decision_engine();
        let kill_set = [60123u32, 60124];

        // Install fails -> the table is LEFT STANDING and the hook fires.
        let outcome = drift_enforce_fail_closed(
            &engine,
            false,
            || {
                Err(NftablesError::InvocationFailed(
                    "injected net failure".into(),
                ))
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        match outcome {
            DriftFailClosedOutcome::InstallFailedSweepHooked { net_err } => {
                assert!(net_err.contains("injected net failure"));
            }
            other => panic!("expected the hooked failure arm, got {other:?}"),
        }

        // Install succeeds -> the net is in force and nothing further happens. The
        // hook must NOT fire after a successful install: the net already denies the
        // identity, so terminating its processes adds no protection.
        let installed = Cell::new(false);
        let outcome2 = drift_enforce_fail_closed(
            &engine,
            false,
            || {
                installed.set(true);
                Ok(())
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        assert_eq!(outcome2, DriftFailClosedOutcome::NetInstalled);
        assert!(installed.get());
    }

    // A162: a stop already requested with no confined identity known (HostWide)
    // skips the install entirely -- the installer closure is never called -- and
    // reports the dedicated outcome rather than either install arm.
    #[test]
    fn drift_enforce_fail_closed_skips_hostwide_install_on_a_requested_stop() {
        use std::cell::Cell;

        let engine = test_decision_engine();
        let kill_set = [60123u32, 60124];
        let called = Cell::new(false);
        let outcome = drift_enforce_fail_closed(
            &engine,
            true,
            || {
                called.set(true);
                Ok(())
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        assert_eq!(
            outcome,
            DriftFailClosedOutcome::HostWideSkippedForRequestedStop
        );
        assert!(!called.get(), "the installer must not run on an A162 skip");
    }

    // The identity-scoped counterpart: a known confined identity still installs
    // even while a stop is requested (the memo's invariant that a proven loss
    // with a known identity always gets its one net attempt).
    #[test]
    fn drift_enforce_fail_closed_still_installs_identity_scope_on_a_requested_stop() {
        use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet};
        use std::cell::Cell;

        let engine = test_decision_engine();
        let kill_set = [60123u32];
        let set = ConfinedUidSet::from_validated(vec![validate_safety_net_uid(
            60123,
            overflow_fixture(),
        )
        .unwrap()])
        .unwrap();
        let called = Cell::new(false);
        let outcome = drift_enforce_fail_closed(
            &engine,
            true,
            || {
                called.set(true);
                Ok(())
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::Identity(set),
        );
        assert_eq!(outcome, DriftFailClosedOutcome::NetInstalled);
        assert!(
            called.get(),
            "a known confined identity must still install under shutdown"
        );
    }

    // U1 (A162): the decision matrix `stop_time_hostwide_skip` itself, over every
    // reachable (scope, shutdown_requested) pair, independent of any call site.
    #[test]
    fn stop_time_hostwide_skip_decision_matrix() {
        use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet};

        let engine = test_decision_engine();
        let identity_set = ConfinedUidSet::from_validated(vec![validate_safety_net_uid(
            60123,
            overflow_fixture(),
        )
        .unwrap()])
        .unwrap();

        // HostWide + shutdown requested: skip.
        assert!(stop_time_hostwide_skip(
            &engine,
            true,
            &crate::nftables::SafetyNetScope::HostWide
        ));
        // HostWide + no shutdown: never skip (an ordinary boot/runtime loss still
        // installs).
        assert!(!stop_time_hostwide_skip(
            &engine,
            false,
            &crate::nftables::SafetyNetScope::HostWide
        ));
        // Identity + shutdown requested: never skip (memo §1 invariant -- a known
        // confined identity always gets its one net attempt).
        assert!(!stop_time_hostwide_skip(
            &engine,
            true,
            &crate::nftables::SafetyNetScope::Identity(identity_set.clone())
        ));
        // Identity + no shutdown: never skip.
        assert!(!stop_time_hostwide_skip(
            &engine,
            false,
            &crate::nftables::SafetyNetScope::Identity(identity_set)
        ));
    }

    // A completed first loss is already an install-authorising proof. A second
    // unavailable reading would not erase it; only later Recovering polls re-probe.
    #[test]
    fn first_runtime_loss_consumes_proof_without_a_second_query() {
        use crate::health_probe::ProbeOutcome;
        let mut queries = 0;
        let first = post_ready_recovery_proof(false, || {
            queries += 1;
            ProbeOutcome::Unavailable
        });
        assert_eq!(first, ProbeOutcome::Lost);
        assert_eq!(
            queries, 0,
            "first loss must not be vetoed by a new no-answer"
        );
        let later = post_ready_recovery_proof(true, || {
            queries += 1;
            ProbeOutcome::Ready
        });
        assert_eq!(later, ProbeOutcome::Ready);
        assert_eq!(queries, 1, "a later recovering poll must re-probe");
    }

    #[test]
    fn no_answer_withdraws_only_a_prior_success_claim() {
        use crate::nftables::{
            SafetyNetAuditState, SafetyNetReason, SafetyNetScope, SafetyNetSources,
        };
        let mut success = SafetyNetAuditState::installed(
            &SafetyNetScope::HostWide,
            &SafetyNetReason::UnknownHistory,
            SafetyNetSources {
                journal: false,
                manifest: false,
                live_table: false,
            },
        );
        demote_prior_install(&mut success);
        assert_eq!(success, SafetyNetAuditState::Unverified);
        let mut failure = SafetyNetAuditState::InstallFailed {
            attempted_scope: "v1-host-wide".into(),
            error: "injected".into(),
        };
        demote_prior_install(&mut failure);
        assert_eq!(failure.tag(), "install_failed");
        let mut never = SafetyNetAuditState::NotAttempted;
        demote_prior_install(&mut never);
        assert_eq!(never.tag(), "not_attempted");
    }

    #[test]
    fn late_ready_clears_recovery_clock_so_a_distinct_loss_is_first_again() {
        use crate::enforcement::ComponentHealth;
        use crate::health_probe::ProbeOutcome;
        use std::sync::atomic::{AtomicBool, Ordering};

        let recovering = AtomicBool::new(true);
        let last = std::sync::Mutex::new(Some(std::time::Instant::now()));
        assert_eq!(
            post_ready_component_health(ProbeOutcome::Unavailable, &recovering, &last),
            ComponentHealth::Recovering,
            "a timed-out recovery proof must not enter the generic no-answer exit path"
        );
        assert!(recovering.load(Ordering::SeqCst));
        assert!(last.lock().unwrap().is_some());

        // The same worker may complete after its caller's deadline. A later
        // health poll consumes that positive proof without another probe.
        assert_eq!(
            post_ready_component_health(ProbeOutcome::Ready, &recovering, &last),
            ComponentHealth::Ready
        );
        assert!(!recovering.load(Ordering::SeqCst));
        assert!(last.lock().unwrap().is_none());

        assert_eq!(
            post_ready_component_health(ProbeOutcome::Lost, &recovering, &last),
            ComponentHealth::Lost,
            "a distinct completed loss must be a fresh immediate-install entry"
        );
        let mut redundant_queries = 0;
        assert_eq!(
            post_ready_recovery_proof(recovering.load(Ordering::SeqCst), || {
                redundant_queries += 1;
                ProbeOutcome::Unavailable
            }),
            ProbeOutcome::Lost
        );
        assert_eq!(redundant_queries, 0);
    }

    #[test]
    fn terminal_indeterminate_overrides_recovering_no_answer() {
        use crate::enforcement::ComponentHealth;
        use crate::health_probe::ProbeOutcome;
        use std::sync::atomic::{AtomicBool, Ordering};

        let recovering = AtomicBool::new(true);
        let last = std::sync::Mutex::new(Some(std::time::Instant::now()));
        assert_eq!(
            post_ready_component_health(ProbeOutcome::Unavailable, &recovering, &last),
            ComponentHealth::Recovering
        );
        assert_eq!(
            post_ready_component_health(ProbeOutcome::Indeterminate, &recovering, &last),
            ComponentHealth::Indeterminate,
            "exhausted no-answer must reach the hook-before-exit consumer"
        );
        assert!(!recovering.load(Ordering::SeqCst));
    }

    // GF1.3: every eligible post-READY loss executes a real install, including a
    // second loss after a prior success. A later failure cannot inherit success.
    #[test]
    fn runtime_loss_net_reinstalls_after_success_and_reports_later_failure() {
        use crate::nftables::NftablesError;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let kill_set = [60123u32];

        let first = install_deny_all_net_for_recovery(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        assert!(first);
        let second = install_deny_all_net_for_recovery(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        assert!(second);
        let third = install_deny_all_net_for_recovery(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(NftablesError::InvocationFailed("later failure".into()))
            },
            &kill_set,
            &crate::nftables::SafetyNetScope::HostWide,
        );
        assert!(
            !third,
            "a previous success cannot report a failed retry installed"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "every eligible loss must execute the actual transaction"
        );
    }

    // Persistent failure remains retryable; the PR-3 hook is entered only by the
    // failed-install arm and Part A performs no by-name delete.
    #[test]
    fn runtime_loss_persistent_install_failure_keeps_retrying() {
        use crate::nftables::NftablesError;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let kill_set = [60123u32];

        for poll in 1..=3 {
            let installed = install_deny_all_net_for_recovery(
                || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err(NftablesError::InvocationFailed(
                        "persistent net failure".into(),
                    ))
                },
                &kill_set,
                &crate::nftables::SafetyNetScope::HostWide,
            );
            assert!(!installed, "poll {poll} must not report an install");
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "every eligible poll must re-attempt the net"
        );
    }

    fn write_watcher_policy(policy_dir: &Path, signing: &SigningKey, rule_id: &str) -> String {
        write_watcher_policy_with_origin(policy_dir, signing, rule_id, None)
    }

    /// The same writer, with the manifest's ADMITTED IDENTITY under the caller's
    /// control, so a test can plant a candidate whose identity differs from the
    /// one a boot load froze. Must match `AgentOrigin` in `src/manifest/verify.rs`.
    fn write_watcher_policy_with_origin(
        policy_dir: &Path,
        signing: &SigningKey,
        rule_id: &str,
        agent_origin: Option<crate::manifest::verify::AgentOrigin>,
    ) -> String {
        use crate::manifest::{MANIFEST_FILENAME, RULES_SUBDIR};

        fs::create_dir_all(policy_dir.join(RULES_SUBDIR)).unwrap();
        let rule_file = format!("{rule_id}.json");
        let rule_body = format!(
            "{{\"id\":\"{rule_id}\",\"schema_version\":1,\"created_at\":\"2026-09-02T00:00:00Z\",\"match\":{{\"ip\":[\"203.0.113.7\"]}},\"disposition\":\"allow\"}}"
        )
        .into_bytes();
        fs::write(policy_dir.join(RULES_SUBDIR).join(&rule_file), &rule_body).unwrap();
        let habeas_file = format!("{}.json", crate::habeas::HABEAS_LOCAL_RULE_ID);
        let habeas_body = crate::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
        fs::write(
            policy_dir.join(RULES_SUBDIR).join(&habeas_file),
            habeas_body,
        )
        .unwrap();

        let manifest = AllowlistManifest {
            schema_version: crate::constants::SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: format!("2026-09-02T00:00:0{}Z", rule_id.len() % 10),
            generation: if rule_id.contains("old") || rule_id == "rule-boot" {
                1
            } else {
                2
            },
            agent_origin,
            operator_baseline: None,
            rules: vec![
                ManifestRuleEntry {
                    rule_id: rule_id.to_string(),
                    file: rule_file,
                    sha256: sha256_hex(&rule_body),
                },
                ManifestRuleEntry {
                    rule_id: crate::habeas::HABEAS_LOCAL_RULE_ID.to_string(),
                    file: habeas_file,
                    sha256: sha256_hex(habeas_body),
                },
            ],
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let signature = signing.sign(&canonical);
        let signature_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: crate::constants::SIGNATURE_SCHEME_V1.to_string(),
                signing_key_id: castle_wall_signing_key_id(&signing.verifying_key().to_bytes())
                    .unwrap(),
                signature_b64url: signature_b64url.clone(),
            },
        };
        fs::write(
            policy_dir.join(MANIFEST_FILENAME),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
        signature_b64url
    }

    type AuditEngineFixture = (
        Arc<DecisionEngine>,
        Arc<Mutex<WalWriter>>,
        Arc<Mutex<AuditRingBuffer>>,
        Arc<std::sync::atomic::AtomicBool>,
    );

    fn audit_backed_engine(
        dir: &TempDir,
        store: Option<Arc<Mutex<crate::manifest::ManifestStore>>>,
    ) -> AuditEngineFixture {
        let wal = WalWriter::open(&dir.path().join("watcher.wal")).unwrap();
        let injection = wal.injection_handle();
        let wal = Arc::new(Mutex::new(wal));
        let audit_buffer = Arc::new(Mutex::new(AuditRingBuffer::new(
            16 * 1024,
            Duration::from_secs(60),
        )));
        let engine = Arc::new(DecisionEngine::new(
            "deadbeef".to_string(),
            store,
            Some(Arc::clone(&wal)),
            Arc::clone(&audit_buffer),
        ));
        (engine, wal, audit_buffer, injection)
    }

    fn test_decision_engine() -> Arc<DecisionEngine> {
        let audit_buffer = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024,
            Duration::from_secs(60),
        )));
        Arc::new(DecisionEngine::new(
            "deadbeef".to_string(),
            None,
            None,
            audit_buffer,
        ))
    }

    fn test_config() -> LinuxRuntimeConfig {
        LinuxRuntimeConfig {
            lock_path: PathBuf::from("/nonexistent/castle-wall.nft.lock"),
            journal_path: PathBuf::from("/nonexistent/nft-ownership.json"),
            journal_key_path: PathBuf::from("/nonexistent/nft-journal-auth.key"),
            policy_dir: PathBuf::from("/nonexistent/policy"),
            poll_interval: Duration::from_millis(200),
            nfqueue: NfqueueConfig::default(),
            shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A hand-built [`NftablesTableComponent`] bypassing `acquire` (no real host
    /// lock or kernel table), for U2/U2b below. `net_scope_from_retained_set`
    /// still shells out to `nft` to read live table bindings, so these tests
    /// need real `nft` privileges (the same caveat as W1a/W1b). They are
    /// ordinary `#[test]` functions with no skip guard (F7, Claude F7):
    /// unlike the integration suite's privileged tests (which call
    /// `skip_or_fail_unprivileged`), these run in the unprivileged unit lane
    /// too, on every `cargo test`, and fail (not skip) without `nft`
    /// privileges -- the same lane every other test in this module runs in.
    #[cfg(target_os = "linux")]
    fn fixture_component(
        decision_engine: Arc<DecisionEngine>,
        journal_dir: &Path,
        retained_deny_uids: Vec<u32>,
    ) -> NftablesTableComponent {
        NftablesTableComponent {
            lock: None,
            ownership: crate::nftables::CastleTableOwnership {
                table_handle: 1,
                base_chain_handle: 2,
                marker: "test-marker".to_string(),
            },
            decision_engine,
            probe: crate::health_probe::BoundedHealthProbe::new(nft_health_budget()),
            released: false,
            journal_path: journal_dir.join("nonexistent-ownership.json"),
            journal_key_path: journal_dir.join("nonexistent-ownership.key"),
            retained_deny_uids: std::sync::Mutex::new(retained_deny_uids),
            recovering: std::sync::atomic::AtomicBool::new(false),
            last_recovery_attempt: std::sync::Mutex::new(None),
            last_safety_net_state: std::sync::Mutex::new(
                crate::nftables::SafetyNetAuditState::NotAttempted,
            ),
            shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// U2 (LINUX-STOP-LOSS-RACE-01): `recover_post_ready_loss(&|| true)` on a
    /// proven Lost with a known confined identity (Identity scope): installs
    /// once. A
    /// SECOND call under shutdown is the retrying re-probe path, which shutdown
    /// still gates: no re-probe, no install, no readiness restore. Fails on
    /// dd2e5b06, which returns `NoInstall` unconditionally under shutdown (the
    /// first call never attempts anything).
    #[cfg(target_os = "linux")]
    #[test]
    fn u2_first_entry_under_shutdown_installs_once_identity_scope() {
        use crate::enforcement::PostReadyRecoveryResult as R;

        let dir = TempDir::new().unwrap();
        // F7 (LINUX-STOP-LOSS-RACE-01, Claude F7): 65_000 is a fixture uid, not
        // a derived one; its only requirement is that it not collide with
        // THIS host's `kernel.overflowuid` (validate_safety_net_uid refuses
        // exactly that collision, which would resolve HostWide instead of the
        // Identity scope this test needs). Assert the precondition rather than
        // silently depending on it, so a host configured with overflowuid=65000
        // fails loudly here instead of failing confusingly inside the install.
        let overflow = crate::safety_net_uid::HostOverflowUid::from_host()
            .expect("this host's kernel.overflowuid must be readable in CI");
        assert_ne!(
            65_000,
            overflow.value(),
            "fixture uid 65_000 must not equal this host's kernel.overflowuid, or it \
             would be refused and resolve HostWide instead of the Identity scope this test needs"
        );
        let component = fixture_component(test_decision_engine(), dir.path(), vec![65_000]);

        let first = component.recover_post_ready_loss(&|| true);
        assert_ne!(
            first,
            R::NoInstall,
            "a stop must not leave a first-entry proven loss without its one net attempt"
        );
        assert!(
            component.is_recovering(),
            "recovering must be set after the attempt, success or failure"
        );

        let second = component.recover_post_ready_loss(&|| true);
        assert_eq!(
            second,
            R::NoInstall,
            "a later poll under shutdown is the gated retrying re-probe path"
        );
    }

    /// U2b (A155): HostWide scope (no known confined identity, or overflow)
    /// under shutdown installs nothing and records the residual, instead of
    /// installing a host-wide net that would silence the operator's own live
    /// sessions on an ordinary `systemctl stop`.
    #[cfg(target_os = "linux")]
    #[test]
    fn u2b_hostwide_scope_under_shutdown_skips_install_and_records_residual() {
        use crate::enforcement::PostReadyRecoveryResult as R;

        let dir = TempDir::new().unwrap();
        let (decision_engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        // Empty retained set, no journal/manifest history: net_scope_from_retained_set
        // resolves HostWide (EmptyDenySet), i.e. no known confined identity.
        let component = fixture_component(decision_engine, dir.path(), Vec::new());

        let result = component.recover_post_ready_loss(&|| true);
        assert_eq!(
            result,
            R::NoInstall,
            "A155: a routine stop must never install a host-wide net"
        );

        let rows = wal
            .lock()
            .unwrap()
            .snapshot_after(None, 32)
            .unwrap()
            .into_iter()
            .filter(|entry| {
                entry
                    .event_canonical_json
                    .contains("stop_time_net_skipped_no_known_identity")
            })
            .count();
        assert_eq!(rows, 1, "the A155 residual must be recorded");
    }

    /// R2 (LINUX-STOP-LOSS-RACE-01, Grok 2): the exact race window Grok finding
    /// 2 named -- a stop landing AFTER the health probe that gated this call but
    /// BEFORE `recover_post_ready_loss` reaches its HostWide decision. Before
    /// R2, the caller copied `is_shutdown_requested()` into a `bool` before the
    /// probe ran, so a stop in that window was invisible to this function and a
    /// HostWide install would proceed uninterrupted. Modelled here with a
    /// closure that returns false on its first call (the `retrying` gate, which
    /// this first entry must pass to reach the HostWide decision at all) and
    /// true on every call after (simulating the stop arriving in the window),
    /// so the LATER read -- the one the HostWide branch itself takes -- is what
    /// must see it live. Fails if `recover_post_ready_loss` reads the closure
    /// only once and discards the value, or reads it before the retrying gate
    /// and reuses that stale reading for the HostWide branch.
    #[cfg(target_os = "linux")]
    #[test]
    fn u2c_shutdown_set_between_probe_and_hostwide_decision_installs_nothing() {
        use crate::enforcement::PostReadyRecoveryResult as R;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = TempDir::new().unwrap();
        let (decision_engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        // Empty retained set: HostWide scope, same precondition as u2b.
        let component = fixture_component(decision_engine, dir.path(), Vec::new());

        let calls = AtomicUsize::new(0);
        let shutting_down = || calls.fetch_add(1, Ordering::SeqCst) > 0;

        let result = component.recover_post_ready_loss(&shutting_down);
        assert_eq!(
            result,
            R::NoInstall,
            "a stop observed only between the probe and the HostWide decision must \
             still skip the host-wide install, exactly as a stop observed before the \
             call would -- the live read must reach the HostWide branch, not just the \
             earlier retrying gate"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the function must read the closure more than once: once for the \
             retrying gate (which this first entry must pass as false) and again, \
             live, for the HostWide decision"
        );

        let rows = wal
            .lock()
            .unwrap()
            .snapshot_after(None, 32)
            .unwrap()
            .into_iter()
            .filter(|entry| {
                entry
                    .event_canonical_json
                    .contains("stop_time_net_skipped_no_known_identity")
            })
            .count();
        assert_eq!(
            rows, 1,
            "the A155 residual must still be recorded when the stop is observed late"
        );
    }

    /// F8 (LINUX-STOP-LOSS-RACE-01, Claude F8): the A155 host-wide skip must not
    /// overwrite attempt history with `NotAttempted`. A component that
    /// installed earlier in this SAME process (recovering==false again because
    /// that earlier loss recovered to `OwnedWallReady`) and now hits a fresh
    /// loss with a HostWide scope must retain `Unverified` (the demotion
    /// `mark_prior_install_unverified` already applied to the prior
    /// `Installed` tag), not have it erased back to `NotAttempted` -- that
    /// would under-claim: it would say no install was EVER attempted this
    /// process, when one was.
    #[cfg(target_os = "linux")]
    #[test]
    fn u2d_hostwide_skip_preserves_prior_attempt_history_as_unverified() {
        use crate::enforcement::PostReadyRecoveryResult as R;
        use crate::nftables::SafetyNetAuditState as Tag;

        let dir = TempDir::new().unwrap();
        let (decision_engine, _wal, _audit, _injection) = audit_backed_engine(&dir, None);
        let component = fixture_component(decision_engine, dir.path(), Vec::new());
        // Simulate an earlier successful install THIS process already made and
        // that has since gone unverified again (the state `record_safety_net_state`
        // would carry into a later loss).
        *component.last_safety_net_state.lock().unwrap() = Tag::Installed {
            shape: "v1-host-wide",
            reason: "unknown-history",
            deny_set_size: 0,
            deny_set_max: 1,
            rules: vec![],
            denied_uids: vec![],
            sources: crate::nftables::SafetyNetSources {
                journal: false,
                manifest: false,
                live_table: false,
            },
            kernel_nd_accepted: vec![],
            unattestable_packets: "drop-except-kernel-nd",
            coverage: "inet output hook",
        };

        let result = component.recover_post_ready_loss(&|| true);
        assert_eq!(
            result,
            R::NoInstall,
            "A155 still skips the host-wide install"
        );

        let tag = component.safety_net_audit_state().unwrap();
        assert_eq!(
            tag.tag(),
            "unverified",
            "a prior Installed claim demoted to Unverified must not be further \
             overwritten to NotAttempted by the A155 skip; got {tag:?}"
        );
    }

    // ---- drive_manifest_watcher_at: hard poll error terminates (blocker 5) ----

    use crate::manifest::watcher::{WatcherError, WatcherEvent};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn nft_health_check_timeout_is_bounded_and_never_reads_ready() {
        use crate::health_probe::{BoundedHealthProbe, ProbeBudget, ProbeOutcome};
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(20),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 3,
        });
        let started = std::time::Instant::now();
        let outcome = probe.poll(|| {
            std::thread::sleep(Duration::from_millis(250));
            true
        });
        assert_ne!(
            outcome,
            ProbeOutcome::Ready,
            "a timed-out ownership proof must never assert readiness"
        );
        assert_eq!(
            outcome,
            ProbeOutcome::Unavailable,
            "a single timeout is indeterminate, not a proven loss; collapsing it into \
             loss is what restarted a healthy daemon on momentary contention"
        );
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "the caller must not wait for the wedged proof worker"
        );
    }

    /// The nft probe budget must keep a genuine loss detectable within ONE
    /// supervisor tick: if `min_interval` ever grew past the supervisor's health
    /// interval, every other tick would be served from cache and real loss
    /// detection would silently halve. Pinned here because the two constants live
    /// in different files (`main.rs` owns `HEALTH_INTERVAL`).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_nft_probe_budget_cannot_outlive_a_supervisor_health_tick() {
        let budget = nft_health_budget();
        assert!(
            budget.min_interval < crate::daemon::SUPERVISOR_HEALTH_INTERVAL,
            "a real ownership proof must run on every supervisor tick"
        );
        assert!(
            budget.timeout <= crate::daemon::SUPERVISOR_HEALTH_INTERVAL,
            "a probe must not outlive the tick that started it"
        );
    }

    #[test]
    fn init_poll_fallback_is_durably_audited_at_the_two_second_cadence() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        record_manifest_watcher_degradation(
            &engine,
            "test inotify init failure",
            Duration::from_secs(2),
        )
        .expect("degradation audit must be durable");

        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .event_canonical_json
            .contains("\"operation\":\"manifest_watcher_degraded_to_poll\""));
        assert!(entries[0]
            .event_canonical_json
            .contains("poll_interval_ms=2000"));
        assert!(entries[0].critical);
    }

    #[test]
    fn init_poll_fallback_refuses_readiness_when_durable_audit_fails() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, audit, injection) = audit_backed_engine(&dir, None);
        injection.store(true, Ordering::SeqCst);
        let err = record_manifest_watcher_degradation(
            &engine,
            "test inotify init failure",
            Duration::from_secs(2),
        )
        .expect_err("fallback without durable audit must fail before readiness");
        assert!(err.to_string().contains("WAL append failed"));
        assert!(wal
            .lock()
            .unwrap()
            .snapshot_after(None, 10)
            .unwrap()
            .is_empty());
        assert_eq!(audit.lock().unwrap().len(), 0);
    }

    #[test]
    fn nfqueue_serve_error_is_not_swallowed_and_is_durably_audited() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        record_nfqueue_serve_failure(
            &engine,
            Err(crate::nfqueue::NfqueueError::VerdictLoopError(
                "test netlink failure".to_string(),
            )),
        );
        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .event_canonical_json
            .contains("\"operation\":\"nfqueue_serve_failed\""));
        assert!(entries[0]
            .event_canonical_json
            .contains("test netlink failure"));
        assert!(entries[0].critical);
    }

    #[test]
    fn nfqueue_fatal_loss_reporting_is_bounded_when_wal_owner_never_returns() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        let never_returning_owner = wal.lock().unwrap();
        let started = std::time::Instant::now();

        record_nfqueue_serve_failure(
            &engine,
            Err(crate::nfqueue::NfqueueError::VerdictDeadlineExceeded(
                Duration::from_millis(25),
            )),
        );

        assert!(
            started.elapsed() < Duration::from_millis(250),
            "NFQUEUE loss reporting must not inherit a stuck WAL owner"
        );
        drop(never_returning_owner);
    }

    #[test]
    fn watcher_loop_terminates_on_the_first_hard_poll_error() {
        // A hard poll error must END the serve loop (return), even though `stop`
        // is never set — a persistent inotify failure surfaces as a dead thread,
        // not an infinite spin. The poll fn errors on its 2nd call.
        let calls = AtomicUsize::new(0);
        let stop = AtomicBool::new(false); // never set: only the error can end it
        let poll = |_wait: Duration| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(Some(WatcherEvent::ManifestChanged))
            } else {
                Err(WatcherError::Poll("inotify fd broke".to_string()))
            }
        };
        // Returns (does not hang) despite stop never being set. Zero cadence so
        // the test measures the TERMINATION contract, not the sleep schedule.
        drive_manifest_watcher_at(poll, None, &stop, Duration::ZERO);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "loop must stop right after the first hard error"
        );
    }

    #[test]
    fn watcher_loop_durably_audits_capability_loss_before_exit() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        let stop = AtomicBool::new(false);
        drive_manifest_watcher_at(
            |_wait| Err(WatcherError::Poll("test watcher fd loss".to_string())),
            Some(engine),
            &stop,
            Duration::ZERO,
        );
        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .event_canonical_json
            .contains("\"operation\":\"manifest_watcher_lost\""));
        assert!(entries[0]
            .event_canonical_json
            .contains("test watcher fd loss"));
        assert!(entries[0].critical);
    }

    #[test]
    fn watcher_loss_exits_bounded_when_wal_owner_never_returns() {
        let dir = TempDir::new().unwrap();
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, None);
        let stop = AtomicBool::new(false);
        let never_returning_owner = wal.lock().unwrap();
        let started = std::time::Instant::now();

        drive_manifest_watcher_at(
            |_wait| Err(WatcherError::Poll("test watcher fd loss".to_string())),
            Some(engine),
            &stop,
            Duration::ZERO,
        );

        assert!(
            started.elapsed() < Duration::from_millis(250),
            "watcher loss must exit even when its failure WAL resource is stuck"
        );
        drop(never_returning_owner);
    }

    #[test]
    fn manifest_watcher_start_fails_synchronously_on_an_initial_hard_error() {
        // blocker 5: the REAL production adapter must fail STARTUP synchronously on
        // an initial hard filesystem error, so the manifest-watcher component's
        // BIND fails-before and the component is never advertised ready over a
        // blind watcher. A "policy dir" that is actually a file makes the
        // synchronous metadata read fail hard (NotADirectory), distinct from a
        // legitimately-absent manifest (NotFound). The complementary "a LATER hard
        // error terminates the serve loop" contract is covered by
        // `watcher_loop_terminates_on_the_first_hard_poll_error`.
        use crate::manifest::watcher::ManifestWatcher;
        let dir = tempfile::TempDir::new().unwrap();
        let policy_is_a_file = dir.path().join("policy_is_a_file");
        std::fs::write(&policy_is_a_file, b"not a directory").unwrap();
        let started = ManifestWatcher::start(policy_is_a_file, Duration::from_millis(0), false);
        assert!(
            started.is_err(),
            "an initial hard filesystem error must fail the watcher bind synchronously"
        );
    }

    #[test]
    fn watcher_loop_continues_on_ok_events_until_stopped() {
        // Ok(None) idle polls and Ok(Some(ManifestChanged)) must NOT terminate
        // the loop; only `stop` (or a hard error) does. The poll fn sets stop
        // after a few successful polls and the loop then exits cleanly.
        let calls = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let poll = |_wait: Duration| -> Result<Option<WatcherEvent>, WatcherError> {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n >= 3 {
                stop.store(true, Ordering::SeqCst);
            }
            if n % 2 == 0 {
                Ok(None)
            } else {
                Ok(Some(WatcherEvent::ManifestChanged))
            }
        };
        drive_manifest_watcher_at(poll, None, &stop, Duration::ZERO);
        assert!(
            calls.load(Ordering::SeqCst) >= 4,
            "loop must survive Ok events and end only on stop"
        );
    }

    /// The AUDITED cadence and the OBSERVED one must be the same number.
    ///
    /// The degradation record says `poll_interval_ms=2000` and both
    /// `ASSURANCE_MATRIX.md` row 17 and `castle-wall-daemon/README.md` describe a
    /// "2-second poller". The serve loop previously passed its 200ms shutdown nap
    /// straight into `poll_event`, whose own `wait_for.min(poll_interval)` then
    /// made the real stat cadence 200ms: ten times what every claim about it said.
    /// This pins the two apart so the claim stays true.
    #[test]
    fn the_watcher_stats_at_the_audited_cadence_not_at_the_shutdown_nap() {
        assert!(
            MANIFEST_WATCHER_SERVE_WAIT
                < Duration::from_millis(crate::failure::MANIFEST_WATCHER_POLL_INTERVAL_MS as u64),
            "the shutdown nap must be shorter than the poll cadence, or SIGTERM waits a full cycle"
        );

        let calls = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let cadence = Duration::from_millis(120);
        let poll = |wait: Duration| -> Result<Option<WatcherEvent>, WatcherError> {
            // The value handed to `poll_event` is the SHUTDOWN nap, never the
            // cadence: that is what keeps a stop request bounded.
            assert!(wait <= MANIFEST_WATCHER_SERVE_WAIT);
            if calls.fetch_add(1, Ordering::SeqCst) >= 2 {
                stop.store(true, Ordering::SeqCst);
            }
            Ok(None)
        };
        drive_manifest_watcher_at(poll, None, &stop, cadence);
        let elapsed = started.elapsed();
        let stats = calls.load(Ordering::SeqCst);
        assert!(stats >= 3, "expected at least three stats, saw {stats}");
        assert!(
            elapsed >= cadence.saturating_mul((stats as u32).saturating_sub(1)),
            "{stats} stats in {elapsed:?} is faster than the {cadence:?} cadence allows"
        );

        assert_eq!(
            manifest_watcher_stat_cadence(true, cadence),
            cadence,
            "degraded stat polling must honor the audited configured interval"
        );
        assert_eq!(
            manifest_watcher_stat_cadence(false, cadence),
            Duration::ZERO,
            "inotify events must not be throttled by the fallback stat interval"
        );
    }

    #[test]
    fn watcher_reload_failure_keeps_prior_and_emits_critical_audit() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(std::sync::Mutex::new(crate::manifest::ManifestStore::new(
            dir.path().to_path_buf(),
            dir.path().join("pinned.pub"),
            [7u8; 32],
            "deadbeef".to_string(),
        )));
        let (engine, _wal, audit_buffer, _injection) = audit_backed_engine(&dir, Some(store));

        handle_manifest_watcher_event(Some(WatcherEvent::ManifestChanged), Some(&engine))
            .expect("verification failure audit must succeed");

        let audit = audit_buffer.lock().unwrap();
        let event = audit.iter().next().expect("reload failure audit event");
        assert!(event.critical);
        assert!(event
            .event_canonical_json
            .contains("\"operation\":\"manifest_verify_failed_kept_prior\""));
        assert!(event.event_canonical_json.contains("manifest file missing"));
    }

    #[test]
    fn watcher_reload_commits_only_after_durable_precommit_authorization() {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        let signing = SigningKey::generate(&mut OsRng);
        write_watcher_policy(&policy_dir, &signing, "rule-old");
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        )));
        store.lock().unwrap().reload().expect("load prior policy");
        let prior_signature = store
            .lock()
            .unwrap()
            .current()
            .unwrap()
            .manifest_signature_b64url
            .clone();
        let next_signature = write_watcher_policy(&policy_dir, &signing, "rule-new");
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, Some(Arc::clone(&store)));
        // The production shape: the boot load freezes the identity before the
        // watcher can ever be acquired, so a watcher reload always runs with the
        // cell set. `write_watcher_policy` admits no agent uid, so the frozen
        // identity is `Unconfined` and the reload preserves it.
        assert!(
            engine.freeze_armed_identity_for_test(crate::decision::AdmittedIdentity {
                fortress_id: "deadbeef".to_string(),
                subject: crate::decision::AdmittedSubject::Unconfined,
            })
        );

        handle_manifest_watcher_event(Some(WatcherEvent::ManifestChanged), Some(&engine))
            .expect("authorized watcher reload");

        let live_signature = store
            .lock()
            .unwrap()
            .current()
            .unwrap()
            .manifest_signature_b64url
            .clone();
        assert_ne!(live_signature, prior_signature);
        assert_eq!(live_signature, next_signature);
        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .event_canonical_json
            .contains("\"operation\":\"manifest_watcher_reload_authorized\""));
        assert!(entries[0].event_canonical_json.contains(&next_signature));
        assert!(entries[0].critical);
    }

    #[test]
    fn startup_reconciliation_loads_a_replacement_from_before_watch_registration() {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        let signing = SigningKey::generate(&mut OsRng);
        write_watcher_policy(&policy_dir, &signing, "rule-boot");
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        )));
        store.lock().unwrap().reload().expect("load boot snapshot");

        // Model a replacement in the formerly invisible interval between the
        // daemon's boot load and successful watch registration.
        let replacement_signature = write_watcher_policy(&policy_dir, &signing, "rule-after-boot");
        let (engine, wal, _audit, _injection) = audit_backed_engine(&dir, Some(Arc::clone(&store)));
        // The production shape: the boot load freezes the identity before the
        // watcher can ever be acquired, so a watcher reload always runs with the
        // cell set. `write_watcher_policy` admits no agent uid, so the frozen
        // identity is `Unconfined` and the reload preserves it.
        assert!(
            engine.freeze_armed_identity_for_test(crate::decision::AdmittedIdentity {
                fortress_id: "deadbeef".to_string(),
                subject: crate::decision::AdmittedSubject::Unconfined,
            })
        );

        reconcile_manifest_after_watch_registration(&engine)
            .expect("post-registration reconciliation must authorize latest manifest");

        let guard = store.lock().unwrap();
        assert_eq!(
            guard.current().unwrap().manifest_signature_b64url,
            replacement_signature
        );
        assert!(guard
            .current_snapshot()
            .unwrap()
            .rules
            .iter()
            .any(|rule| rule.id == "rule-after-boot"));
        assert!(!guard
            .current_snapshot()
            .unwrap()
            .rules
            .iter()
            .any(|rule| rule.id == "rule-boot"));
        drop(guard);

        let entries = wal.lock().unwrap().snapshot_after(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .event_canonical_json
            .contains("\"operation\":\"manifest_watcher_startup_reconciled\""));
        assert!(entries[0]
            .event_canonical_json
            .contains(&replacement_signature));
        assert!(entries[0].critical);
    }

    #[test]
    fn watcher_reload_wal_failure_keeps_the_prior_manifest_unchanged() {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        let signing = SigningKey::generate(&mut OsRng);
        write_watcher_policy(&policy_dir, &signing, "rule-old");
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        )));
        store.lock().unwrap().reload().expect("load prior policy");
        let prior_signature = store
            .lock()
            .unwrap()
            .current()
            .unwrap()
            .manifest_signature_b64url
            .clone();
        let next_signature = write_watcher_policy(&policy_dir, &signing, "rule-new");
        assert_ne!(prior_signature, next_signature);
        let (engine, wal, audit, injection) = audit_backed_engine(&dir, Some(Arc::clone(&store)));
        injection.store(true, Ordering::SeqCst);

        let err = handle_manifest_watcher_event(Some(WatcherEvent::ManifestChanged), Some(&engine))
            .expect_err("a failed durable authorization must reject the reload");
        assert!(err.to_string().contains("WAL append failed"));
        let guard = store.lock().unwrap();
        assert_eq!(
            guard.current().unwrap().manifest_signature_b64url,
            prior_signature,
            "the staged candidate must never become live"
        );
        assert!(guard
            .current_snapshot()
            .unwrap()
            .rules
            .iter()
            .any(|rule| rule.id == "rule-old"));
        assert!(!guard
            .current_snapshot()
            .unwrap()
            .rules
            .iter()
            .any(|rule| rule.id == "rule-new"));
        drop(guard);
        assert!(wal
            .lock()
            .unwrap()
            .snapshot_after(None, 10)
            .unwrap()
            .is_empty());
        assert_eq!(audit.lock().unwrap().len(), 0);
    }

    #[test]
    fn plan_advertises_exactly_the_required_kinds_in_order() {
        // The plan-shape gate in EnforcementRuntime::start requires this to equal
        // REQUIRED_IN_ORDER; assert it here too so a reordering is caught at the
        // provider source, not only at start().
        let plan = linux_production_plan(test_decision_engine(), &test_config());
        let kinds: Vec<ComponentKind> = plan.iter().map(|p| p.kind()).collect();
        assert_eq!(kinds, ComponentKind::REQUIRED_IN_ORDER.to_vec());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn disarm_is_not_available_off_linux() {
        // Off Linux there is no nft runtime to disarm; the explicit recovery path
        // returns NotAvailableOnPlatform rather than pretending to have deleted
        // anything.
        let err = disarm_castle_runtime(&test_config())
            .expect_err("disarm has no kernel adapter off Linux");
        assert!(matches!(err, EnforcementError::NotAvailableOnPlatform(_)));
    }

    // D3: the shared classifier both disarm recovery sites (`ReclaimOwned` and
    // `FinalizeInterrupted`) call. `RecoverSafetyNet` requires BOTH fields of
    // the reading; either alone, or a probe error, is exercised here at the
    // pure-function level. The production wiring (one live inventory fetch
    // feeding both the recogniser and the comment-absence check) is exercised
    // end-to-end by the real-nft integration suite
    // (tests/integration_gf1_recovery.rs, cases (a)-(f), (h)); the
    // `ReclaimOwned` arm's probe-error branch is ALSO driven through the
    // production path there (case (g), via the test-isolation-only
    // force-error override), since a live-nft integration test cannot make a
    // real probe fail on demand without a broken `nft` binary on the runner.
    #[test]
    fn safety_net_recovery_probe_error_refuses_without_guessing() {
        use crate::nftables::NftablesError;

        assert_eq!(
            classify_safety_net_recovery_probe(|| Ok(SafetyNetRecoveryProbeReading {
                recognised_as_safety_net: true,
                table_comment_absent: true,
            })),
            SafetyNetRecoveryDecision::RecoverSafetyNet
        );
        assert_eq!(
            classify_safety_net_recovery_probe(|| Ok(SafetyNetRecoveryProbeReading {
                recognised_as_safety_net: true,
                table_comment_absent: false,
            })),
            SafetyNetRecoveryDecision::NotSafetyNet,
            "a positive recognizer answer alone must not be enough without an \
             absent table comment"
        );
        assert_eq!(
            classify_safety_net_recovery_probe(|| Ok(SafetyNetRecoveryProbeReading {
                recognised_as_safety_net: false,
                table_comment_absent: true,
            })),
            SafetyNetRecoveryDecision::NotSafetyNet,
            "an absent table comment alone must not be enough without a \
             positive recognizer answer"
        );
        match classify_safety_net_recovery_probe(|| {
            Err(NftablesError::InvocationFailed(
                "injected probe failure".to_string(),
            ))
        }) {
            SafetyNetRecoveryDecision::ProbeFailed(detail) => {
                assert!(
                    detail.contains("injected probe failure"),
                    "the probe error must reach the refusal text: {detail}"
                );
            }
            other => panic!("expected ProbeFailed, got {other:?}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_plan_fails_before_at_nftables_and_never_reads_ready() {
        // On a host with no kernel adapter the first provider fails-before with
        // NotAvailableOnPlatform, so no runtime is constructed and nothing reads
        // as ready. This is the honest ControlPlaneOnly path the dev/macOS gates
        // exercise.
        let plan = linux_production_plan(test_decision_engine(), &test_config());
        let err = crate::enforcement::EnforcementRuntime::start(plan)
            .expect_err("no kernel adapter on this platform -> fail-before");
        match err {
            crate::enforcement::EnforcementStartError::Component { failed, reason, .. } => {
                assert_eq!(failed, ComponentKind::NftablesTable);
                assert!(matches!(
                    reason,
                    EnforcementError::NotAvailableOnPlatform(_)
                ));
            }
            other => panic!("expected a component fail-before, got {other:?}"),
        }
    }

    // ---- slice A: the wall binds the admitted uid before it reports ready ----
    //
    // Register: defect.linux-readiness-precedes-confinement,
    // defect.linux-driver-binding-vs-engine-expectation-01.

    use crate::decision::{AdmittedIdentity, AdmittedSubject};
    use crate::ownership_journal::{
        ConfinedIdentity, ConfinedRole, JournalIdentity, OwnershipJournal,
    };

    fn journal_identity(boot_id: &str) -> JournalIdentity {
        JournalIdentity {
            schema_version: crate::ownership_journal::JOURNAL_SCHEMA_VERSION,
            marker: "sanctuary-castle-owner:ffff".to_string(),
            boot_id: boot_id.to_string(),
            source: "test".to_string(),
        }
    }

    fn owned_with_history(boot_id: &str, uids: &[u32]) -> OwnershipJournal {
        OwnershipJournal::owned_with_known_history(
            journal_identity(boot_id),
            2,
            1,
            uids.iter()
                .map(|uid| ConfinedIdentity {
                    uid: *uid,
                    role: ConfinedRole::Agent,
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn this_boots_history_ignores_a_previous_boots_record() {
        let record = owned_with_history("boot-a", &[60123]);
        assert_eq!(
            this_boot_confined_history(Some(&record), "boot-a"),
            ConfinedHistory::Known(vec![ConfinedIdentity {
                uid: 60123,
                role: ConfinedRole::Agent
            }])
        );
        // A previous boot's uids cannot have live processes after a reboot, so
        // reading them as THIS boot's history would refuse every first start
        // after a reboot that changed the manifest.
        assert_eq!(
            this_boot_confined_history(Some(&record), "boot-b"),
            ConfinedHistory::Known(Vec::new())
        );
        assert_eq!(
            this_boot_confined_history(None, "boot-a"),
            ConfinedHistory::Known(Vec::new())
        );
    }

    #[test]
    fn an_absent_confined_key_on_a_same_boot_record_stays_unknown() {
        let record = OwnershipJournal::owned_with_unknown_history(journal_identity("boot-a"), 2, 1);
        assert_eq!(
            this_boot_confined_history(Some(&record), "boot-a"),
            ConfinedHistory::Unknown
        );
        assert_eq!(history_uids(&ConfinedHistory::Unknown), None);
    }

    #[test]
    fn a_refused_identity_change_is_non_fatal_to_the_watcher_and_costs_one_bounded_row() {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        fs::create_dir_all(&policy_dir).unwrap();
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        // A valid, correctly signed manifest that confines NOBODY, LOADED through
        // the real boot entry so there is a committed prior snapshot to preserve
        // and the frozen identity is the one that boot actually committed.
        let boot_signature = write_watcher_policy(&policy_dir, &signing, "rule-boot");
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        )));
        let (engine, wal, _ring, _injection) = audit_backed_engine(&dir, Some(Arc::clone(&store)));
        engine
            .reload_manifest_authorized_at_boot()
            .expect("the boot load must commit and freeze");
        assert_eq!(
            engine.armed_identity().map(|id| id.subject),
            Some(AdmittedSubject::Unconfined),
            "the cell holds the identity the COMMITTED snapshot carries"
        );

        // Now the manifest on disk changes the admitted identity. Same signing
        // key, same fortress, a higher generation: everything except the identity
        // would make this a legitimate reload.
        write_watcher_policy_with_origin(
            &policy_dir,
            &signing,
            "rule-changed",
            Some(crate::manifest::verify::AgentOrigin {
                mode: "uid".to_string(),
                egress_helper_signing_id: None,
                egress_helper_team_id: None,
                agent_runtime_port_range: None,
                agent_uid: Some(60123),
                gate_uid: None,
                system_uid_allow_ceiling: 500,
            }),
        );

        // The refused file STAYS on disk, so the cost has to be bounded PER EVENT.
        for _ in 0..3 {
            reload_manifest_from_watcher(&engine, "manifest_watcher_reload_authorized", "watcher")
                .expect("a refused identity change must not take the watcher down");
        }

        // THE PRIOR POLICY IS STILL LIVE, asserted as an observable effect rather
        // than inferred from the absence of a success row: the committed snapshot
        // is still the boot manifest's, by its signature and by its identity.
        {
            let guard = store.lock().unwrap();
            let snapshot = guard
                .current_snapshot()
                .expect("the prior snapshot must still be committed");
            assert_eq!(
                snapshot.manifest_signature_b64url.as_deref(),
                Some(boot_signature.as_str()),
                "a refused reload commits nothing, so the boot manifest stays live"
            );
            assert_eq!(
                snapshot.confined_agent_uid, None,
                "the refused candidate's identity must not have reached the live snapshot"
            );
        }
        // BOUND on what this test observes: it calls the reload helper directly
        // and constructs NO watcher component, so it cannot say a component is
        // still acquired. What it does show is the two facts the component's
        // supervision loop depends on: every event above returned `Ok(())` (a
        // refused identity change is non-fatal), and the cell is still the one
        // boot froze.
        assert_eq!(
            engine.armed_identity().map(|id| id.subject),
            Some(AdmittedSubject::Unconfined)
        );

        let operations: Vec<String> = wal
            .lock()
            .unwrap()
            .snapshot_after(None, 100)
            .unwrap()
            .iter()
            .map(|entry| {
                let row: serde_json::Value =
                    serde_json::from_str(&entry.event_canonical_json).unwrap();
                row["operation"].as_str().unwrap_or_default().to_string()
            })
            .collect();
        assert_eq!(
            operations
                .iter()
                .filter(|op| op.as_str() == "manifest_identity_change_refused_kept_prior")
                .count(),
            3,
            "one bounded row per watcher event, and no success row: {operations:?}"
        );
        assert!(
            !operations
                .iter()
                .any(|op| op == "manifest_watcher_reload_authorized"),
            "a refused reload must leave no success row: {operations:?}"
        );
    }

    // ---- The pure slice-A decision (A2/A3/A7): exhaustive, no kernel ----

    fn armed_confined(agent_uid: u32, ceiling: u32) -> AdmittedIdentity {
        AdmittedIdentity {
            fortress_id: "deadbeef".to_string(),
            subject: AdmittedSubject::Confined {
                agent_uid,
                ceiling,
                gate_uid: None,
            },
        }
    }

    fn armed_unconfined() -> AdmittedIdentity {
        AdmittedIdentity {
            fortress_id: "deadbeef".to_string(),
            subject: AdmittedSubject::Unconfined,
        }
    }

    fn known_history(uids: &[u32]) -> ConfinedHistory {
        ConfinedHistory::Known(
            uids.iter()
                .map(|uid| ConfinedIdentity {
                    uid: *uid,
                    role: ConfinedRole::Agent,
                })
                .collect(),
        )
    }

    /// B is empty: the table is ours and routes nobody. Under `Confined` the set
    /// rule reads that as a mismatch with |B| = 0, which is the install arm.
    fn empty_binding_set() -> LiveBindingSet {
        LiveBindingSet::Mismatch {
            binding_count: 0,
            detail: "the owned table carries no per-agent binding".to_string(),
        }
    }

    /// B is exactly the singleton the armed identity requires.
    fn required_singleton() -> LiveBindingSet {
        LiveBindingSet::Verified { binding_count: 1 }
    }

    /// B is empty AND that is what `Unconfined` requires.
    fn verified_empty() -> LiveBindingSet {
        LiveBindingSet::Verified { binding_count: 0 }
    }

    /// A live binding that is not the required one (a foreign agent id over the
    /// admitted uid, a second chain, a different uid).
    fn foreign_binding_set() -> LiveBindingSet {
        LiveBindingSet::Mismatch {
            binding_count: 1,
            detail: "a per-agent chain under another agent id routes the admitted uid".to_string(),
        }
    }

    #[test]
    fn an_unconfining_manifest_over_a_uid_this_boot_bound_refuses_with_the_net() {
        // A3/A7: the table can be empty while the process it confined is still
        // live, so an empty B proves nothing on its own.
        let plan = plan_admitted_binding(
            Some(&armed_unconfined()),
            &verified_empty(),
            &known_history(&[60123]),
        );
        match &plan {
            BindPlan::RefuseWithNet { uncovered_uids, .. } => {
                assert_eq!(uncovered_uids, &vec![60123]);
            }
            other => panic!("expected a net refusal naming 60123, got {other:?}"),
        }
    }

    #[test]
    fn a_different_admitted_uid_over_a_uid_this_boot_bound_refuses_with_the_net_naming_it() {
        let plan = plan_admitted_binding(
            Some(&armed_confined(60125, 500)),
            &empty_binding_set(),
            &known_history(&[60123]),
        );
        match plan {
            BindPlan::RefuseWithNet {
                uncovered_uids,
                reason,
            } => {
                assert_eq!(uncovered_uids, vec![60123]);
                assert!(
                    reason.contains("reason=HistoricalUidUncovered"),
                    "typed reason: {reason}"
                );
            }
            other => panic!("expected a net refusal naming 60123, got {other:?}"),
        }
    }

    #[test]
    fn the_admitted_uid_over_its_own_history_installs_and_the_gate_runs() {
        assert_eq!(
            plan_admitted_binding(
                Some(&armed_confined(60123, 500)),
                &empty_binding_set(),
                &known_history(&[60123]),
            ),
            BindPlan::Install {
                agent_uid: 60123,
                ceiling: 500
            }
        );
    }

    #[test]
    fn a_fresh_table_with_no_history_installs() {
        assert_eq!(
            plan_admitted_binding(
                Some(&armed_confined(60123, 700)),
                &empty_binding_set(),
                &known_history(&[]),
            ),
            BindPlan::Install {
                agent_uid: 60123,
                ceiling: 700
            }
        );
    }

    #[test]
    fn the_exact_singleton_is_adopted_and_never_reinstalled() {
        assert_eq!(
            plan_admitted_binding(
                Some(&armed_confined(60123, 500)),
                &required_singleton(),
                &known_history(&[60123]),
            ),
            BindPlan::Adopt { agent_uid: 60123 }
        );
    }

    #[test]
    fn a_foreign_binding_refuses_with_the_net_in_the_set_rule() {
        // Design round 5, P2-2: a wrong-uid jump dies in the SET RULE, before the
        // history reconciliation can be reached, and the refusal detail is the
        // set rule's own. The net comes from the live binding, not the history:
        // this planted history is empty.
        let plan = plan_admitted_binding(
            Some(&armed_confined(60123, 500)),
            &foreign_binding_set(),
            &known_history(&[]),
        );
        match plan {
            BindPlan::RefuseWithNet { reason, .. } => assert!(
                reason.contains("another agent id"),
                "the set rule's own detail must reach the refusal: {reason}"
            ),
            other => panic!("expected a net refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unset_armed_identity_is_a_typed_refusal_the_predicate_still_answers() {
        // L-A-neg's no-net half: neither source names a uid, so no agent can have
        // been started under this boot's wall and the table is left exactly as it
        // was found. The same unset cell over a history that DOES name one takes
        // the net.
        assert!(matches!(
            plan_admitted_binding(None, &empty_binding_set(), &known_history(&[])),
            BindPlan::RefuseWithoutNet { .. }
        ));
        assert!(matches!(
            plan_admitted_binding(None, &empty_binding_set(), &known_history(&[60123])),
            BindPlan::RefuseWithNet { .. }
        ));
    }

    #[test]
    fn an_unreadable_binding_set_is_never_read_as_an_empty_one() {
        let plan = plan_admitted_binding(
            Some(&armed_confined(60123, 500)),
            &LiveBindingSet::Unreadable {
                detail: "nft returned malformed JSON".to_string(),
            },
            &known_history(&[]),
        );
        assert!(
            matches!(plan, BindPlan::RefuseWithNet { .. }),
            "an unreadable table cannot prove the kernel routes nobody: {plan:?}"
        );
    }

    #[test]
    fn unknown_history_refuses_with_the_net_on_a_continuing_path() {
        let plan = plan_admitted_binding(
            Some(&armed_confined(60123, 500)),
            &empty_binding_set(),
            &ConfinedHistory::Unknown,
        );
        assert!(
            matches!(plan, BindPlan::RefuseWithNet { .. }),
            "a record that cannot say which uids were bound is not a record that says none \
             were: {plan:?}"
        );
    }

    #[test]
    fn the_net_predicate_reads_both_sources_and_defaults_to_installing() {
        // This is the exact value the executor passes at the key-load and
        // write-ahead failure arms. H names a uid whose jump was deleted, so a
        // literal `false` there would leave that uid over `policy accept`.
        assert!(net_required_on_refusal(
            &known_history(&[60123]),
            &empty_binding_set()
        ));
        assert!(net_required_on_refusal(
            &known_history(&[]),
            &foreign_binding_set()
        ));
        assert!(net_required_on_refusal(
            &ConfinedHistory::Unknown,
            &empty_binding_set()
        ));
        assert!(net_required_on_refusal(
            &known_history(&[]),
            &LiveBindingSet::Unreadable {
                detail: "unreadable".to_string()
            }
        ));
        assert!(!net_required_on_refusal(
            &known_history(&[]),
            &empty_binding_set()
        ));
    }

    // ---- The refusal net's scope (S1: no journal read, no journal write) ----

    /// The resolution a read-only resolver would produce at a site, built from
    /// the same pure function production calls. `history` is source (a), `admitted`
    /// is (b), `live` is (c).
    fn resolution_at_site(
        history: &[u32],
        admitted: Option<(u32, Option<u32>)>,
        live: &[u32],
    ) -> SafetyNetResolution {
        use crate::nftables::LiveTableBindings;
        let entries: Vec<(u32, ConfinedRole)> = history
            .iter()
            .map(|&uid| (uid, ConfinedRole::Agent))
            .collect();
        resolve_safety_net_scope(
            &known(&entries),
            admitted,
            &LiveTableBindings::Bindings(live.to_vec()),
            overflow_fixture(),
        )
    }

    #[test]
    fn the_codex_1_schedule_names_both_the_historical_and_the_admitted_uid() {
        // THE SCHEDULE: uid 60123 was bound under this boot's wall, its jump was
        // deleted, and the daemon restarts admitting 60124. The refusal's net must
        // deny BOTH: 60124 because the manifest confines it, and 60123 because a
        // process of its may still be live behind a wall that no longer routes it.
        // The scope is resolved from evidence already in hand, never from a read
        // taken at the moment of refusal, so no single failing read can shrink
        // it. Register: defect.linux-pr3b-refusal-record.
        let resolution = resolution_at_site(&[60123], Some((60124, None)), &[]);
        let scope = net_scope_for_refusal(&resolution, &[60123], &[]);
        let crate::nftables::SafetyNetScope::Identity(set) = &scope else {
            panic!("both uids are attestable, so the identity scope is installed: {scope:?}");
        };
        assert_eq!(set.uids(), vec![60123, 60124]);
    }

    #[test]
    fn an_uncovered_uid_is_never_dropped_from_the_refusal_scope() {
        // The planner's uncovered list is independent evidence. Where the
        // resolution already names it the scope names it; where the resolution
        // does NOT (the resolver's own validator refused the member, or its read
        // of the live table came back without it), the answer widens to host-wide
        // rather than losing the uid.
        let named = resolution_at_site(&[60123], Some((60124, None)), &[]);
        assert!(matches!(
            net_scope_for_refusal(&named, &[60123], &[]),
            crate::nftables::SafetyNetScope::Identity(_)
        ));
        let without = resolution_at_site(&[], Some((60124, None)), &[]);
        assert_eq!(
            net_scope_for_refusal(&without, &[60123], &[]),
            crate::nftables::SafetyNetScope::HostWide,
            "a uid the resolution cannot name must widen the net, never vanish from it"
        );
    }

    #[test]
    fn a_live_binding_uid_is_never_dropped_from_the_refusal_scope() {
        // B is the set the EXECUTOR parsed. The resolver reads the live table a
        // second time, and that read can fail; when it does, source (c) is empty
        // and only this input still carries the uid the kernel is routing.
        let resolution = resolution_at_site(&[], Some((60124, None)), &[]);
        assert_eq!(
            net_scope_for_refusal(&resolution, &[], &[60999]),
            crate::nftables::SafetyNetScope::HostWide,
            "a uid B names and the resolution does not must widen the net"
        );
        let both = resolution_at_site(&[], Some((60124, None)), &[60999]);
        let scope = net_scope_for_refusal(&both, &[], &[60999]);
        let crate::nftables::SafetyNetScope::Identity(set) = &scope else {
            panic!("both reads agree, so the identity scope is installed: {scope:?}");
        };
        assert_eq!(set.uids(), vec![60124, 60999]);
    }

    #[test]
    fn an_unknown_history_stays_host_wide_whatever_the_other_inputs_say() {
        use crate::nftables::{LiveTableBindings, SafetyNetReason, SafetyNetScope};
        let resolution = resolve_safety_net_scope(
            &ConfinedHistory::Unknown,
            Some((60124, None)),
            &LiveTableBindings::Bindings(vec![60125]),
            overflow_fixture(),
        );
        assert_eq!(resolution.reason, SafetyNetReason::UnknownHistory);
        assert_eq!(
            net_scope_for_refusal(&resolution, &[60123], &[60125]),
            SafetyNetScope::HostWide,
            "no later input may narrow a host-wide resolution"
        );
    }

    #[test]
    fn the_persist_failure_arms_scope_input_is_the_union_the_subtraction_defines() {
        // Codex 4(a), macOS half. The Linux fault test drives the arm itself; what
        // a kernel-free run can prove is that the arm's INPUTS resolve to a scope
        // naming the admitted uid, which is the uid the failed write-ahead was
        // about to bind. The arm passes no uncovered list (the planner staged an
        // install, so nothing was uncovered) and B, which is empty on that arm.
        let resolution = resolution_at_site(&[60123], Some((60123, None)), &[]);
        let scope = net_scope_for_refusal(&resolution, &[], &[]);
        assert_eq!(scope.denied_uids(), vec![60123]);
    }

    #[test]
    fn the_refusal_sentence_describes_the_scope_that_was_installed() {
        use crate::nftables::SafetyNetScope;
        let resolution = resolution_at_site(&[], Some((60124, None)), &[]);
        let widened = net_scope_for_refusal(&resolution, &[60123], &[]);
        assert_eq!(widened, SafetyNetScope::HostWide);
        let sentence = refusal_scope_sentence(&widened, &resolution);
        assert!(
            sentence.contains("could not name") && sentence.contains("every uid on this host"),
            "the widened pairing gets its own sentence, not the defect one: {sentence}"
        );
        assert!(
            !sentence.contains("this pairing is a defect"),
            "the widening is the design, not a defect: {sentence}"
        );
    }

    /// The source-region pin for the property a macOS run cannot execute: the net
    /// decision at the kernel-step failure arms, which need a kernel to reach.
    /// The region ends at the provider impl, the item that follows the bind
    /// function in this file.
    fn bind_function_source() -> String {
        let source = fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime_providers.rs"),
        )
        .unwrap();
        let start = source
            .find("fn bind_admitted_uid_before_ready(")
            .expect("the bind function must exist");
        let end = source[start..]
            .find("\nimpl ComponentProvider for NftablesTableProvider {")
            .expect("the bind function must be followed by the provider impl")
            + start;
        source[start..end].to_string()
    }

    #[test]
    fn no_failure_arm_inside_the_bind_hard_codes_the_net_decision() {
        // CAPABILITY: the net decision at every kernel-step failure arm comes
        // from the one predicate, never from a constant written at the arm. A
        // macOS run cannot execute those arms (they need a kernel), so the
        // property is pinned at the source instead of asserted at runtime.
        let body = bind_function_source();
        assert_eq!(
            body.matches("net_required_mid_plan,").count(),
            2,
            "the key-load and write-ahead failure arms both pass the predicate"
        );
        // ANCHORED, not distance-measured: find the plan's own no-net arm by its
        // match pattern and require the ONE literal-false refusal in the whole
        // body to be the one that arm makes. A byte-distance threshold silently
        // stops covering the arm the moment the arm grows past it, and it has to
        // be re-tuned every time rustfmt rewraps the line.
        let arm_start = body
            .find("BindPlan::RefuseWithoutNet { reason }")
            .expect("the plan's no-net arm must exist");
        let arm_end = body[arm_start..]
            .find("\n        BindPlan::")
            .expect("another plan arm must follow the no-net one")
            + arm_start;
        let arm = &body[arm_start..arm_end];
        assert!(
            arm.contains("refuse(false,"),
            "the no-net arm is the one that refuses without a net: {arm}"
        );
        assert_eq!(
            body.matches("refuse(false,").count(),
            1,
            "no other arm may hard-code the no-net answer"
        );
    }

    #[test]
    fn the_slice_a_refusal_path_never_reads_or_writes_the_journal() {
        // CAPABILITY: after the ownership proof, a slice-A refusal neither reads
        // nor writes the ownership journal. The record the acquisition's own
        // match arm wrote or confirmed stands, and the net's scope comes from
        // evidence already in hand, so there is no read that can fail and narrow
        // the net and no write that can restore a superseded record.
        //
        // DERIVATION of the needles: `persist_kill_set_write_ahead` is the only
        // function that writes a confined-history record from a caller-supplied
        // record, and `journal::load(` / `ownership_journal::load(` is the only
        // authenticated read. `journal::load_or_generate_auth_key` shares the
        // `journal::load` prefix and is NOT a record read, which is why both
        // needles carry the opening parenthesis.
        let whole = fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime_providers.rs"),
        )
        .unwrap();
        let production = &whole[..whole.find("\n#[cfg(test)]\n").expect("a test module")];
        assert!(
            !production.contains("fn current_journal_record("),
            "the refusal-time record re-read is deleted, not merely unused"
        );

        let helper_start = production
            .find("fn refuse_after_owned_table(")
            .expect("the refusal helper must exist");
        let helper_end = production[helper_start..]
            .find("\n/// Fault-injection seam")
            .expect("the refusal helper must be followed by the write-ahead seam")
            + helper_start;
        let helper = &production[helper_start..helper_end];
        for needle in [
            "persist_kill_set_write_ahead",
            "journal::load(",
            "ownership_journal::load(",
            "journal_path",
            "key_path",
        ] {
            assert!(
                !helper.contains(needle),
                "the refusal helper must not mention {needle}; it has no journal handle at all"
            );
        }

        // The refusal closure inside the bind function is the other half: it is
        // where the scope is computed, and it must reach the journal no more than
        // the helper does. The bind function's INSTALL path legitimately writes
        // ahead (`persist_confined_uid_write_ahead`), so the span checked here is
        // the closure, anchored at its own `let refuse =` binding.
        let body = bind_function_source();
        let closure_start = body
            .find("let refuse = |install_net: bool")
            .expect("the one refusal closure must exist");
        let closure_end = body[closure_start..]
            .find("\n    };\n")
            .expect("the refusal closure must close")
            + closure_start;
        let closure = &body[closure_start..closure_end];
        for needle in [
            "persist_kill_set_write_ahead",
            "journal::load(",
            "ownership_journal::load(",
        ] {
            assert!(
                !closure.contains(needle),
                "the refusal closure must not mention {needle}"
            );
        }
        assert_eq!(
            body.matches("net_scope_for_refusal(").count(),
            1,
            "every refusal arm shares ONE scope computation"
        );
        assert_eq!(
            body.matches("refuse_after_owned_table(").count(),
            2,
            "the helper is reached only through that closure's two arms"
        );
    }

    #[test]
    fn runtime_ownership_is_activated_before_the_agent_ruleset_is_loaded() {
        // Grok P2-2 / design round 5 P2-10: `load_agent_ruleset` refuses a
        // production mutation with no authenticated active ownership, and an
        // isolated-table run skips that check, so a macOS or isolated run cannot
        // show the miss. BOUND: this asserts the production SOURCE order on the
        // ownership path and nothing more. No test in this repo observes the
        // order at runtime today, on any platform, and the production comment at
        // the activation site says the same thing; the runtime observation is
        // owed to the L-A drill leg on the real unit.
        // PRODUCTION source only: the test module below mentions these same
        // call-site strings, and counting those would make the assertion
        // meaningless.
        let whole = fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime_providers.rs"),
        )
        .unwrap();
        let source = whole[..whole.find("\n#[cfg(test)]\n").expect("a test module")].to_string();
        let activate = source
            .find("crate::nftables::activate_runtime_ownership(&ownership)")
            .expect("the acquisition must activate runtime ownership");
        let bind = source
            .find("if let Err(err) = bind_admitted_uid_before_ready(")
            .expect("the acquisition must call the bind");
        assert!(
            activate < bind,
            "activation must precede the bind that loads the agent ruleset"
        );
        let load_sites: Vec<usize> = source
            .match_indices("crate::nftables::load_agent_ruleset(")
            .map(|(idx, _)| idx)
            .collect();
        assert_eq!(
            load_sites.len(),
            1,
            "one loader call site, inside the bind: {load_sites:?}"
        );
        // The loader's only call site is INSIDE the bind function's body (which
        // is DEFINED earlier in the file than the acquisition that calls it), so
        // the ordering claim is: activation precedes the bind CALL, and the bind
        // is the only thing that reaches the loader.
        let bind_body_start = source
            .find("fn bind_admitted_uid_before_ready(")
            .expect("the bind function must exist");
        let bind_body_end = source[bind_body_start..]
            .find("\nimpl ComponentProvider for NftablesTableProvider {")
            .expect("the bind function must be followed by the provider impl")
            + bind_body_start;
        assert!(
            load_sites[0] > bind_body_start && load_sites[0] < bind_body_end,
            "the only loader call sits inside the bind, which runs after activation"
        );
    }

    #[test]
    fn no_try_lock_on_the_manifest_store_remains_in_this_file() {
        let source = fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime_providers.rs"),
        )
        .unwrap();
        let production: Vec<&str> = source
            .lines()
            .take_while(|line| !line.starts_with("#[cfg(test)]"))
            .collect();
        let offenders: Vec<&&str> = production
            .iter()
            .filter(|line| line.contains(".try_lock()"))
            .filter(|line| !line.contains("last_recovery_attempt"))
            .collect();
        assert!(
            offenders.is_empty(),
            "every expectation reader now reads the frozen identity cell; a `try_lock` on the \
             store is an indeterminate answer where a definite one exists: {offenders:?}"
        );
    }
}
