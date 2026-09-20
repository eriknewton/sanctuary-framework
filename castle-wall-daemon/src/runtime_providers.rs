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
    /// The operator's agent registry, read once at activation. See
    /// [`crate::agent_registry`]; the value is
    /// [`crate::config::LinuxRuntimePaths::agent_registry_path`], never a literal,
    /// so a test cannot reach the operator's real file.
    pub agent_registry_path: PathBuf,
    /// Directory holding the signed manifest the watcher observes.
    pub policy_dir: PathBuf,
    /// Poll cadence for the watcher's degraded (non-inotify) fallback.
    pub poll_interval: Duration,
    /// NFQUEUE bind configuration (queue number, FAIL_OPEN off, deadlines).
    pub nfqueue: NfqueueConfig,
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
            agent_registry_path: config.agent_registry_path.clone(),
            decision_engine: Arc::clone(&decision_engine),
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
    /// Where the operator declared which account this wall confines.
    agent_registry_path: PathBuf,
    /// The verified manifest state the reclaim and health comparisons read the
    /// CURRENT confined agent uid from. Held as the same `Arc` the decision
    /// engine holds, never a copy of a value: the expectation must be re-read at
    /// each comparison, so a manifest reload that changes the uid invalidates a
    /// stale kernel binding instead of continuing to bless it.
    decision_engine: Arc<DecisionEngine>,
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
/// health probe no longer has an indeterminate answer to fall back from. A
/// restart that would change the identity refuses through the acquisition drift
/// path rather than silently re-blessing a stale binding.
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

/// GF1.2: on a reclaim DRIFT, install the safety net for the resolved scope.
///
/// The install is REQUIRED, not best-effort. On FAILURE the PR-3 sweep hook runs
/// and the table is left standing; see
/// [`DriftFailClosedOutcome::InstallFailedSweepHooked`] for why Part A no longer
/// escalates to a by-name delete. Injectable installer so the sequence is
/// unit-testable without a broken nft.
#[cfg(any(target_os = "linux", test))]
fn drift_enforce_fail_closed(
    install_deny_all: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
    kill_set: &[u32],
    attempted_scope: &crate::nftables::SafetyNetScope,
) -> DriftFailClosedOutcome {
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
                "runtime loss: the safety net install failed and will be retried",
            );
            // SAFETY: stderr is the operator channel for a kernel-egress escalation.
            // systemd's journal is where an operator reconstructs this sequence.
            eprintln!(
                "castle-wall-daemon: owned nft table lost at runtime and installing the \
                 safety net FAILED; the castle table is left standing and the net is \
                 retried on the next poll: {net_err}"
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
        agent_registry_path: config.agent_registry_path.clone(),
        decision_engine,
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

/// This boot's confined history, read from the PRE-MATCH journal record.
///
/// SCOPED TO THIS BOOT, and the boot-id comparison is the whole reason this is a
/// separate function from the mapping inside `resolve_net_scope_at_site`: that
/// one runs only on paths `journal::decide` already matched to this boot, so it
/// can take the record's history at face value. This one also runs on a FRESH
/// acquisition, where the record on disk may be a previous boot's. A previous
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

/// Refuse an acquisition that has already proven the table is ours, installing
/// the safety net exactly when the evidence says a uid may be live.
///
/// THE NET-ON-REFUSAL RULE, in one place so every failure after the ownership
/// proof takes the same decision: whether a net is installed is decided by this
/// boot's confined history and the live bindings, NEVER by which check refused.
/// A registry that is malformed and a readback that came back wrong are the same
/// question to the kernel — is a confined uid possibly live right now — and a
/// per-reason answer would install a net for one and leave a live uid unguarded
/// for the other. When neither source names a uid (a fresh or disarmed state) the
/// refusal installs nothing and leaves the table exactly as it found it, because
/// no agent can have been started under this boot's wall.
///
/// FAILURE MODE worth stating: the persist is best-effort and the install is not.
/// Installing the net makes no uid live, so a journal that could not be written
/// must never stop it; the reverse order would trade a real protection for a
/// record of one.
#[cfg(target_os = "linux")]
fn refuse_after_owned_table(
    decision_engine: &DecisionEngine,
    journal_path: &std::path::Path,
    key: Option<&crate::ownership_journal::JournalAuthKey>,
    history_record: Option<&crate::ownership_journal::OwnershipJournal>,
    install_net: bool,
    reason: String,
) -> EnforcementError {
    if !install_net {
        return acquire_failed(format!(
            "{reason} No safety net was installed: this boot's confined history names no uid \
             and the live table carries no per-agent binding, so no agent can have been \
             started under this wall."
        ));
    }
    let resolution = resolve_net_scope_at_site(history_record, decision_engine);
    let mut persist_failure: Option<String> = None;
    if resolution.reason != crate::nftables::SafetyNetReason::UnknownHistory {
        if let Some(record) = history_record {
            let admitted = admitted_identity(decision_engine);
            if let Err(err) = persist_kill_set_write_ahead(
                journal_path,
                key,
                record,
                &resolution.kill_set,
                admitted,
            ) {
                persist_failure = Some(err);
            }
        }
    }
    let scope_sentence =
        crate::nftables::safety_net_scope_sentence(&resolution.scope, &resolution.reason);
    let (refuse_detail, net_installed) = match drift_enforce_fail_closed(
        || crate::nftables::install_deny_all_safety_net(&resolution.scope),
        &resolution.kill_set,
        &resolution.scope,
    ) {
        DriftFailClosedOutcome::NetInstalled => (
            format!("{reason} Installed the safety net and refusing readiness. {scope_sentence}"),
            true,
        ),
        DriftFailClosedOutcome::InstallFailedSweepHooked { net_err } => (
            format!(
                "{reason} Safety net installation did not complete ({net_err}); refusing \
                 readiness. {}",
                crate::nftables::SAFETY_NET_REPAIR_ORDER
            ),
            false,
        ),
    };
    let refuse_detail = match persist_failure {
        None => refuse_detail,
        Some(persist_err) if net_installed => format!(
            "{refuse_detail} The confined history could not be written to the journal \
             ({persist_err}); the next start retries the write."
        ),
        Some(persist_err) => format!(
            "{refuse_detail} The confined history could not be written to the journal \
             ({persist_err})."
        ),
    };
    acquire_failed(refuse_detail)
}

/// What the set rule says to do with the live binding set.
#[cfg(target_os = "linux")]
enum AdmittedBindingPlan {
    /// The live set is already exactly the required singleton: adopt it, never
    /// reinstall it. Reinstalling would mint a second write-ahead and change the
    /// rule handle a same-boot restart is supposed to preserve.
    Adopt { agent_uid: u32 },
    /// The table carries no binding and the manifest admits one: install it.
    Install { agent_uid: u32, ceiling: u32 },
    /// The manifest confines nobody and the table carries no binding.
    NothingToBind,
    /// Any other live set. Refused through the drift path.
    Refuse { detail: String },
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
/// identity; reconcile this boot's confined history; run the registry gate; then
/// adopt or install; then read back.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn bind_admitted_uid_before_ready(
    ownership: &crate::nftables::CastleTableOwnership,
    decision_engine: &DecisionEngine,
    registry_path: &std::path::Path,
    journal_path: &std::path::Path,
    key_path: &std::path::Path,
    key_opt: Option<&crate::ownership_journal::JournalAuthKey>,
    existing: Option<&crate::ownership_journal::OwnershipJournal>,
    boot_id: &str,
) -> Result<(), EnforcementError> {
    use crate::decision::AdmittedSubject;
    use crate::nftables::{AgentRulesetId, AgentUidBinding, OwnedBindingSet};
    use crate::ownership_journal::{self as journal, ConfinedRole};

    // H, computed ONCE from the PRE-MATCH record, and every decision below that
    // consults history consults THIS value. A re-read after a fresh create would
    // already name the admitted uid (the create's own write-ahead put it there),
    // so a refusal on a table that never bound anyone would install a net.
    let history = this_boot_confined_history(existing, boot_id);
    let history_uids = history_uids(&history);

    let Some(identity) = decision_engine.armed_identity() else {
        // Refuse BEFORE reading the registry or touching the kernel: nothing can
        // be bound under an identity this process never froze.
        let install_net = history_uids.as_ref().map(|uids| !uids.is_empty()) != Some(false);
        return Err(refuse_after_owned_table(
            decision_engine,
            journal_path,
            key_opt,
            existing,
            install_net,
            "the admitted identity was never frozen at boot, so the wall cannot prove which \
             uid it is supposed to bind; refusing readiness."
                .to_string(),
        ));
    };
    let expectation = current_expected_agent_binding(decision_engine);

    // (1) B, the live set of `(agent_id, uid)` bindings.
    let live = match crate::nftables::owned_table_binding_set(ownership, &expectation) {
        Ok(live) => live,
        Err(err) => {
            // An unreadable or structurally drifted table is not an EMPTY table:
            // B is indeterminate, so the net decision cannot read it as "nothing
            // is bound".
            return Err(refuse_after_owned_table(
                decision_engine,
                journal_path,
                key_opt,
                existing,
                true,
                format!(
                    "the owned table's per-agent binding set could not be read ({err}), so the \
                     wall cannot prove which uid the kernel routes; refusing readiness."
                ),
            ));
        }
    };
    let bindings = live.inventory().bindings.clone();

    // (2) THE SET RULE.
    let plan = match (&identity.subject, &live) {
        (AdmittedSubject::Confined { agent_uid, .. }, OwnedBindingSet::Verified(_)) => {
            // `Verified` under `Confined` IS the exact singleton: the set rule is
            // computed in one place (`owned_table_binding_set_from_json`) and both
            // acquisition and health apply that one answer.
            AdmittedBindingPlan::Adopt {
                agent_uid: *agent_uid,
            }
        }
        (
            AdmittedSubject::Confined {
                agent_uid, ceiling, ..
            },
            OwnedBindingSet::UidMismatch { detail, .. },
        ) => {
            if bindings.is_empty() {
                AdmittedBindingPlan::Install {
                    agent_uid: *agent_uid,
                    ceiling: *ceiling,
                }
            } else {
                AdmittedBindingPlan::Refuse {
                    detail: detail.clone(),
                }
            }
        }
        (AdmittedSubject::Unconfined, OwnedBindingSet::Verified(_)) => {
            AdmittedBindingPlan::NothingToBind
        }
        (AdmittedSubject::Unconfined, OwnedBindingSet::UidMismatch { detail, .. }) => {
            AdmittedBindingPlan::Refuse {
                detail: detail.clone(),
            }
        }
    };
    if let AdmittedBindingPlan::Refuse { detail } = &plan {
        // Always the net here: this arm is only reachable with a non-empty B.
        return Err(refuse_after_owned_table(
            decision_engine,
            journal_path,
            key_opt,
            existing,
            true,
            format!("{detail}; refusing readiness. Repair order: stop the wall, --disarm, start."),
        ));
    }

    // (3) HISTORY RECONCILIATION, on every continuing path.
    //
    // INVARIANT: a uid this boot bound is still potentially live, and the
    // protection about to be established covers exactly one uid. An empty live
    // table therefore proves nothing on its own — the chain and jump can be
    // deleted while the process they confined keeps running — so a historical uid
    // the new protection does not cover must take the net, not a green boot.
    let uncovered: Vec<u32> = match &history_uids {
        // Unknown history cannot prove which uids were bound, so it cannot prove
        // the new protection covers them.
        None => Vec::new(),
        Some(uids) => uids
            .iter()
            .copied()
            .filter(|uid| match identity.subject {
                AdmittedSubject::Confined { agent_uid, .. } => *uid != agent_uid,
                AdmittedSubject::Unconfined => true,
            })
            .collect(),
    };
    if history_uids.is_none() || !uncovered.is_empty() {
        let detail = match &history_uids {
            None => "this boot's confined history cannot say which uids were bound, so the \
                     binding about to be established cannot be proven to cover them"
                .to_string(),
            Some(_) => format!(
                "this boot's confined history names uid(s) {uncovered:?} that the binding about \
                 to be established does not cover, so a previously confined process may still \
                 be live with no wall in front of it"
            ),
        };
        return Err(refuse_after_owned_table(
            decision_engine,
            journal_path,
            key_opt,
            existing,
            true,
            format!(
                "{detail}; refusing readiness with reason=HistoricalUidUncovered. Repair order: \
                 stop the wall, --disarm, start."
            ),
        ));
    }

    // (4) THE REGISTRY GATE, exactly once, after the table is proven ours and
    // after the set rule, never inside or ahead of a refusing arm.
    //
    // INVARIANT: a registered agent that the manifest does not admit, or whose
    // account no longer resolves to the admitted uid, must never see READY,
    // because READY is what starts it; and a refusal never decides the net, the
    // confined history and the live bindings do.
    if let Err(detail) = check_registered_agent_against_identity(
        registry_path,
        &crate::agent_registry::SystemAccountLookup,
        &identity.subject,
    ) {
        let install_net = !bindings.is_empty()
            || history_uids
                .as_ref()
                .map(|uids| !uids.is_empty())
                .unwrap_or(true);
        return Err(refuse_after_owned_table(
            decision_engine,
            journal_path,
            key_opt,
            existing,
            install_net,
            format!("{detail}; refusing readiness."),
        ));
    }

    // (5) Adopt, or write ahead and install.
    let bound_uid = match plan {
        AdmittedBindingPlan::NothingToBind => return Ok(()),
        // Never reinstalled: a same-boot restart adopts the exact rule, which is
        // what keeps the rule handle (and any established connection) stable.
        AdmittedBindingPlan::Adopt { agent_uid } => agent_uid,
        AdmittedBindingPlan::Install { agent_uid, ceiling } => {
            let key = match journal::load_or_generate_auth_key(key_path) {
                Ok(key) => key,
                Err(err) => {
                    return Err(refuse_after_owned_table(
                        decision_engine,
                        journal_path,
                        key_opt,
                        existing,
                        false,
                        format!(
                            "the journal authentication key is unusable ({err}) so the admitted \
                             uid cannot be written ahead of the kernel bind; refusing readiness."
                        ),
                    ))
                }
            };
            // WRITE AHEAD, then bind. The receipt is the kernel loader's required
            // proof that the journal already names this uid: a crash between the
            // two must leave the journal naming MORE than the kernel, never less.
            let receipt = match journal::persist_confined_uid_write_ahead(
                journal_path,
                &key,
                agent_uid,
                ConfinedRole::Agent,
            ) {
                Ok(receipt) => receipt,
                Err(err) => {
                    // The persist FAILED, so no uid was made live by this process
                    // and the pre-match history still decides the net.
                    return Err(refuse_after_owned_table(
                        decision_engine,
                        journal_path,
                        key_opt,
                        existing,
                        false,
                        format!(
                            "the admitted uid {agent_uid} could not be written into this boot's \
                             confined history ({err}), so it must not be bound; refusing \
                             readiness."
                        ),
                    ));
                }
            };
            let agent_id = crate::nftables::confined_agent_id(agent_uid);
            let ruleset = crate::nftables::build_agent_ruleset(&agent_id, agent_uid, &[]);
            if let Err(err) = crate::nftables::load_agent_ruleset(
                &AgentRulesetId {
                    agent_id: agent_id.clone(),
                    // From the CELL, not from a fresh store read: the fortress id
                    // is a seal input, and a seal computed under a value that
                    // could differ from the one the boot froze would not verify on
                    // the next reclaim.
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
                // though the kernel step did not complete. The updated record, not
                // the pre-match one, is what the net must be resolved from here.
                let updated = journal::load(journal_path, Some(&key)).ok().flatten();
                return Err(refuse_after_owned_table(
                    decision_engine,
                    journal_path,
                    Some(&key),
                    updated.as_ref().or(existing),
                    true,
                    format!(
                        "the admitted uid {agent_uid} was written into this boot's confined \
                         history but the kernel binding did not load ({err}); refusing readiness."
                    ),
                ));
            }
            agent_uid
        }
        AdmittedBindingPlan::Refuse { .. } => {
            // Safety: the refusing arm returned above; this match is only reached
            // on a continuing plan.
            unreachable!("a refusing plan returns before the bind")
        }
    };

    // (6) READBACK. The claim is about what the KERNEL holds, so it is proven by
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
        // Always the net: whatever the live set now is, the write-ahead (or the
        // adopted binding) names this uid, so a uid may be live.
        return Err(refuse_after_owned_table(
            decision_engine,
            journal_path,
            key_opt,
            existing,
            true,
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
        "{AGENT_BINDING_READBACK_LINE_PREFIX} uid={bound_uid} agent={}",
        crate::nftables::confined_agent_id(bound_uid)
    );
    Ok(())
}

/// The registry half of the A2 gate: a registered agent must be the admitted one.
///
/// Returns the typed refusal reason as a string. Kept separate from the
/// filesystem read so the policy join (registry entry versus armed identity) is
/// testable without a root-owned file.
#[cfg(any(target_os = "linux", test))]
fn check_registered_agent_against_identity(
    registry_path: &std::path::Path,
    lookup: &dyn crate::agent_registry::AccountLookup,
    subject: &crate::decision::AdmittedSubject,
) -> Result<(), String> {
    use crate::decision::AdmittedSubject;
    let entry = match crate::agent_registry::read_registered_agent(registry_path, lookup) {
        // No agent is registered, so the registry imposes nothing and the binding
        // follows the signed manifest alone.
        Ok(None) => return Ok(()),
        Ok(Some(entry)) => entry,
        Err(err) => return Err(format!("reason=RegisteredAccountMismatch {err}")),
    };
    match subject {
        AdmittedSubject::Confined {
            agent_uid,
            gate_uid,
            ..
        } if *agent_uid == entry.uid && gate_uid.is_none() => Ok(()),
        _ => Err(format!(
            "reason=RegisteredAgentNotAdmitted the operator registered account {} at uid {}, \
             which the signed manifest does not admit as the sole confined identity \
             (armed={subject:?})",
            entry.account_name(),
            entry.uid
        )),
    }
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
                    let persisted = match persist_failure {
                        None => String::new(),
                        Some(err) => format!(
                            " The confined history could not be written to the journal \
                             ({err}); the net is installed anyway, because installing it \
                             makes no uid live, and the next start retries the write."
                        ),
                    };
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
            // skips that check, which is exactly why a macOS or isolated run
            // cannot show the miss and the Linux wired test asserts the order.
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
                &self.agent_registry_path,
                journal_path,
                key_path,
                key_opt.as_ref(),
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
                &self.agent_registry_path,
                &self.decision_engine,
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
    fn recover_post_ready_loss(
        &self,
        shutting_down: bool,
    ) -> crate::enforcement::PostReadyRecoveryResult {
        use crate::enforcement::PostReadyRecoveryResult;
        use std::sync::atomic::Ordering;
        // The shutdown flag is observed so `systemctl stop` is a clean exit rather than
        // a box that keeps re-arming while it is being taken down.
        if shutting_down {
            self.recovering.store(false, Ordering::SeqCst);
            return PostReadyRecoveryResult::NoInstall;
        }
        self.mark_prior_install_unverified();
        let retrying = self.is_recovering();
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
                error: "the safety net install failed and will be retried".to_string(),
            }
        });
        if installed {
            // Best-effort persist AFTER the install, and a failure here never undoes it.
            if let Some(persist_err) = self.persist_boot_row_best_effort(&resolution) {
                // SAFETY: stderr is the operator channel. The net is in force; the
                // journal write is what did not happen, and the next start retries it.
                eprintln!(
                    "castle-wall-daemon: the safety net is in force after a runtime loss, but \
                     the confined history could not be written to the journal: {persist_err}"
                );
            }
        }
        // INVARIANT: `recovering` STAYS SET whether or not the install succeeded.
        // Clearing it on success would let the next tick read the latched loss and
        // exit. A later positive wall proof, terminal indeterminate reading, or
        // operator shutdown ends this controller; otherwise it retries on interval.
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
        shutting_down: bool,
    ) -> crate::enforcement::PostReadyRecoveryResult {
        self.recover_post_ready_loss(shutting_down)
    }

    fn health(&self) -> crate::enforcement::ComponentHealth {
        use crate::enforcement::ComponentHealth;
        if self.released || self.lock.is_none() {
            return ComponentHealth::Lost;
        }
        // Live re-poll of the EXACT owned identity (handles + marker + pristine
        // shape via structured nft -j), not mere table-name existence and not a
        // name-only shape check. (blocker 2) A table deleted, flushed, mutated,
        // or DELETED-AND-RECREATED with the same shape (new handles, or our
        // marker absent) fails this check, dropping the runtime out of
        // KernelRuntimeReady on the next status query.
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
        // Live health is the third comparison site: the expectation is snapshot
        // BEFORE the probe is scheduled (the closure may run on a worker thread)
        // but read from the CURRENT snapshot on every poll, never cached.
        let expectation = current_expected_agent_binding(&self.decision_engine);
        let outcome = self.probe.poll_result(move || {
            // Health requires the BINDING, not just the table: the agent's chain
            // and jump are the only rules that confine the uid, and a table that
            // still verifies after they were deleted would hold readiness over an
            // agent with no wall in front of it.
            classify_nft_ownership_probe(crate::nftables::verify_owned_castle_table_binding(
                &ownership,
                &expectation,
            ))
        });
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

        let kill_set = [60123u32, 60124];

        // Install fails -> the table is LEFT STANDING and the hook fires.
        let outcome = drift_enforce_fail_closed(
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
            agent_origin: None,
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
            agent_registry_path: PathBuf::from("/nonexistent/agent-registry-v1.json"),
            policy_dir: PathBuf::from("/nonexistent/policy"),
            poll_interval: Duration::from_millis(200),
            nfqueue: NfqueueConfig::default(),
        }
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

    use crate::agent_registry::{AccountLookup, AgentRegistryError};
    use crate::decision::{AdmittedIdentity, AdmittedSubject};
    use crate::ownership_journal::{
        ConfinedIdentity, ConfinedRole, JournalIdentity, OwnershipJournal,
    };

    struct FixedLookup(Option<u32>);

    impl AccountLookup for FixedLookup {
        fn uid_for_account(&self, _account: &str) -> Result<Option<u32>, String> {
            Ok(self.0)
        }
    }

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
    fn the_registry_gate_passes_when_no_agent_is_registered() {
        let dir = TempDir::new().unwrap();
        // An absent registry imposes nothing, whatever the manifest admits.
        for subject in [
            AdmittedSubject::Unconfined,
            AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None,
            },
        ] {
            assert!(check_registered_agent_against_identity(
                &dir.path().join("absent.json"),
                &FixedLookup(None),
                &subject,
            )
            .is_ok());
        }
    }

    #[test]
    fn the_registry_gate_refuses_a_registered_agent_the_manifest_does_not_admit() {
        let dir = TempDir::new().unwrap();
        let registry = dir.path().join("registry-v1.json");
        fs::write(
            &registry,
            r#"{"schema_version":1,"entries":[{"name":"drill","uid":60123,"profile":1}]}"#,
        )
        .unwrap();
        // This process is not root, so the custody gate fires first. That IS the
        // refusal being asserted: a registry a non-root principal could rewrite
        // is not a statement by the operator.
        let err = check_registered_agent_against_identity(
            &registry,
            &FixedLookup(Some(60123)),
            &AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("reason=Registered"), "typed reason: {err}");
    }

    #[test]
    fn the_registry_join_refuses_a_gate_uid_and_a_different_admitted_uid() {
        // The join is exercised directly, without the filesystem, because the
        // custody gate above cannot be satisfied by a non-root test process.
        let entry = crate::agent_registry::RegisteredAgent {
            name: "drill".to_string(),
            uid: 60123,
        };
        let admitted_matches = |subject: &AdmittedSubject| match subject {
            AdmittedSubject::Confined {
                agent_uid,
                gate_uid,
                ..
            } => *agent_uid == entry.uid && gate_uid.is_none(),
            AdmittedSubject::Unconfined => false,
        };
        assert!(admitted_matches(&AdmittedSubject::Confined {
            agent_uid: 60123,
            ceiling: 500,
            gate_uid: None
        }));
        for subject in [
            AdmittedSubject::Unconfined,
            AdmittedSubject::Confined {
                agent_uid: 60125,
                ceiling: 500,
                gate_uid: None,
            },
            AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: Some(60124),
            },
        ] {
            assert!(
                !admitted_matches(&subject),
                "{subject:?} must not satisfy a registry naming uid 60123"
            );
        }
    }

    #[test]
    fn a_malformed_registry_is_a_typed_refusal_not_a_pass() {
        let dir = TempDir::new().unwrap();
        let registry = dir.path().join("registry-v1.json");
        fs::write(&registry, b"not json").unwrap();
        assert!(check_registered_agent_against_identity(
            &registry,
            &FixedLookup(Some(60123)),
            &AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None,
            },
        )
        .is_err());
        assert!(matches!(
            crate::agent_registry::read_registered_agent(&registry, &FixedLookup(Some(1))),
            Err(AgentRegistryError::Custody { .. }) | Err(AgentRegistryError::Malformed { .. })
        ));
    }

    #[test]
    fn a_refused_identity_change_is_non_fatal_to_the_watcher_and_costs_one_bounded_row() {
        let dir = TempDir::new().unwrap();
        let policy_dir = dir.path().join("policy");
        fs::create_dir_all(&policy_dir).unwrap();
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        // A valid, correctly signed manifest that confines NOBODY.
        write_watcher_policy(&policy_dir, &signing, "rule-boot");
        let store = Arc::new(Mutex::new(crate::manifest::ManifestStore::new(
            policy_dir.clone(),
            dir.path().join("pinned.key"),
            signing.verifying_key().to_bytes(),
            "deadbeef".to_string(),
        )));
        let (engine, wal, _ring, _injection) = audit_backed_engine(&dir, Some(store));
        // The process is armed with a CONFINED identity, so the manifest on disk
        // is an identity change.
        assert!(engine.freeze_armed_identity_for_test(AdmittedIdentity {
            fortress_id: "deadbeef".to_string(),
            subject: AdmittedSubject::Confined {
                agent_uid: 60123,
                ceiling: 500,
                gate_uid: None,
            },
        }));
        // The refused file STAYS on disk, so the cost has to be bounded PER EVENT.
        for _ in 0..3 {
            reload_manifest_from_watcher(&engine, "manifest_watcher_reload_authorized", "watcher")
                .expect("a refused identity change must not take the watcher down");
        }
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
