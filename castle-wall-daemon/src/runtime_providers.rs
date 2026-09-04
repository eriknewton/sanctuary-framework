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

#[cfg(target_os = "linux")]
fn acquire_failed(detail: impl Into<String>) -> EnforcementError {
    EnforcementError::AcquireFailed {
        kind: ComponentKind::NftablesTable.as_str(),
        detail: detail.into(),
    }
}

/// GF1.2 outcome of enforcing "no live `policy accept` castle table remains" on a
/// reclaim drift. See [`drift_enforce_fail_closed`].
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
enum DriftFailClosedOutcome {
    /// The deny-all net installed; the drifted table is now `policy drop`.
    NetInstalled,
    /// The net install FAILED, so the drifted table was force-deleted by name and
    /// no castle table (hence no `policy accept` path) remains.
    EscalatedDeleteOk,
    /// The net install FAILED and the escalating by-name delete ALSO failed: the
    /// kernel egress state is genuinely indeterminate (loud refusal upstream).
    Indeterminate { net_err: String, delete_err: String },
}

/// GF1.2: on a reclaim DRIFT, guarantee no live `policy accept` castle table can
/// remain. The deny-all net install is REQUIRED, not best-effort; if it FAILS,
/// escalate to a by-name delete so the host has NO castle-accept path. Injectable
/// installer/deleter so the fail-closed escalation SEQUENCE is unit-testable
/// without a broken nft (the production call site passes the real nft fns).
#[cfg(any(target_os = "linux", test))]
fn drift_enforce_fail_closed(
    install_deny_all: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
    force_delete: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
) -> DriftFailClosedOutcome {
    match install_deny_all() {
        Ok(()) => DriftFailClosedOutcome::NetInstalled,
        Err(net_err) => match force_delete() {
            Ok(()) => DriftFailClosedOutcome::EscalatedDeleteOk,
            Err(delete_err) => DriftFailClosedOutcome::Indeterminate {
                net_err: net_err.to_string(),
                delete_err: delete_err.to_string(),
            },
        },
    }
}

/// GF1.3: install the deny-all net at most once (latched), retrying on failure.
/// Returns true iff this call installed it. Injectable installer + force-deleter so
/// the latch + retry + fail-closed escalation are unit-testable without a
/// live/broken nft; the production caller
/// ([`NftablesTableComponent::ensure_runtime_loss_deny_all_net`]) passes the real
/// installer and by-name deleter. A FAILED install does NOT set the latch, so the
/// next health poll retries rather than silently giving up on a table-less host.
///
/// GF1.3 fail-closed escalation (mirrors GF1.2 [`drift_enforce_fail_closed`]): a
/// runtime-loss `Lost` can observe an owned table that DRIFTED to `policy accept`.
/// If the deny-all net install FAILS, leaving that live accept path up until a
/// later retry is a fail-OPEN window, so we ESCALATE to a by-name delete exactly as
/// the reclaim drift path does. INVARIANT: no live `policy accept` castle table may
/// remain after a completed runtime loss is observed -- this holds on the install
/// FAILURE branch (via the escalating delete), not only on the success branch. The
/// latch stays unset either way, so the proper deny-all net (our table at `policy
/// drop`) is still retried on the next health poll.
#[cfg(any(target_os = "linux", test))]
fn ensure_deny_all_net_installed_once(
    latch: &std::sync::atomic::AtomicBool,
    install: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
    force_delete: impl FnOnce() -> Result<(), crate::nftables::NftablesError>,
) -> bool {
    use std::sync::atomic::Ordering;
    if latch.load(Ordering::SeqCst) {
        return false;
    }
    match install() {
        Ok(()) => {
            latch.store(true, Ordering::SeqCst);
            true
        }
        Err(net_err) => {
            // Fail-closed escalation: the deny-all install failed, so an owned table
            // that drifted to `policy accept` would otherwise stay LIVE until a
            // later retry. Force-delete our table by name so no `policy accept`
            // castle path remains (same this-boot authority as the GF1.2 drift path;
            // the delete only ever targets OUR name). The latch stays unset so the
            // proper deny-all net is retried on the next health poll.
            match force_delete() {
                Ok(()) => {
                    eprintln!(
                        "castle-wall-daemon: owned nft table lost at runtime and installing the \
                         deny-all safety net FAILED; ESCALATED to a by-name delete so no live \
                         `policy accept` castle table remains; will retry the deny-all net on the \
                         next health poll: {net_err}"
                    );
                }
                Err(delete_err) => {
                    eprintln!(
                        "castle-wall-daemon: owned nft table lost at runtime; BOTH the deny-all \
                         safety net install AND the escalating by-name delete FAILED (kernel \
                         egress state is genuinely indeterminate; a drifted `policy accept` castle \
                         table may still be live); will retry on the next health poll: \
                         net={net_err} delete={delete_err}"
                    );
                }
            }
            false
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
    Box::new(NftablesTableProvider {
        lock_path: config.lock_path.clone(),
        journal_path: config.journal_path.clone(),
        journal_key_path: config.journal_key_path.clone(),
    })
    .acquire()
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

            let ownership = match journal::decide(
                existing.as_ref(),
                table_present,
                &boot_id,
                &source,
            ) {
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
                    if let Err(err) =
                        crate::nftables::verify_and_register_owned_table_for_reclaim(&owned)
                    {
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
                        // GF1.2 fail-closed post-condition: the deny-all install
                        // is REQUIRED, not best-effort. If it FAILS, the drifted
                        // (possibly `policy accept`) table would otherwise stay
                        // live while we refuse -- a fail-OPEN residual. Escalate
                        // to the strongest available fail-closed action: delete
                        // the drifted table by name so NO live `policy accept`
                        // castle path can remain (the daemon refuses readiness,
                        // so no agent is launched behind the table-less host).
                        // Post-condition after this block, install-ok or not: a
                        // live `policy accept` sanctuary-castle table never
                        // remains. If BOTH the net install and the escalating
                        // delete fail, the kernel state is genuinely
                        // indeterminate and the loud refusal says so.
                        let refuse_detail = match drift_enforce_fail_closed(
                            crate::nftables::install_deny_all_safety_net,
                            crate::nftables::force_delete_castle_table_by_name,
                        ) {
                            DriftFailClosedOutcome::NetInstalled => format!(
                                "journal marks an owned table but the live table no longer \
                                 matches the captured identity; installed a deny-all safety net \
                                 and refusing to adopt or clobber the drifted table: {err}"
                            ),
                            DriftFailClosedOutcome::EscalatedDeleteOk => format!(
                                "journal marks an owned table but the live table drifted; the \
                                 deny-all safety net FAILED to install, so escalated to deleting \
                                 the drifted table by name (no live `policy accept` castle path \
                                 remains); refusing readiness: {err}"
                            ),
                            DriftFailClosedOutcome::Indeterminate {
                                net_err,
                                delete_err,
                            } => format!(
                                "journal marks an owned table but the live table drifted; BOTH the \
                                 deny-all safety net install ({net_err}) and the escalating \
                                 by-name delete ({delete_err}) failed -- kernel egress state is \
                                 indeterminate; refusing readiness: {err}"
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
                    finalize_owned(journal_path, key_path, &owned, &boot_id, &source)?;
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
                    crate::nftables::install_deny_all_safety_net().map_err(|err| {
                        acquire_failed(format!(
                            "owned sanctuary-castle table vanished while the journal still \
                                 asserts ownership, and installing the deny-all safety net FAILED \
                                 (kernel egress state indeterminate): {err}"
                        ))
                    })?;
                    drop(lock);
                    return Err(acquire_failed(
                        "owned sanctuary-castle table vanished (external delete) while the \
                             ownership journal still asserts ownership; installed a deny-all \
                             safety net (all egress for the owned scopes dropped) and refusing \
                             readiness until the wall is repaired -- never re-arming policy accept",
                    ));
                }
                // No live table: fresh acquisition via prepare -> atomic create
                // -> capture/verify -> finalize.
                ReclaimDecision::FreshCreate => {
                    fresh_acquire(journal_path, key_path, &boot_id, &source)?
                }
            };

            crate::nftables::activate_runtime_ownership(&ownership).map_err(|err| {
                acquire_failed(format!(
                    "could not activate authenticated nft ownership: {err}"
                ))
            })?;

            Ok(Box::new(NftablesTableComponent {
                lock: Some(lock),
                ownership,
                probe: crate::health_probe::BoundedHealthProbe::new(nft_health_budget()),
                released: false,
                deny_all_net_installed: std::sync::atomic::AtomicBool::new(false),
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No nftables on this host: fail-before so the plan lands
            // ControlPlaneOnly rather than reporting a table it cannot install.
            let _ = (&self.lock_path, &self.journal_path, &self.journal_key_path);
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
    if let Err(err) = journal::store_atomic(
        journal_path,
        &OwnershipJournal::Owned {
            identity,
            table_handle: owned.table_handle,
            base_chain_handle: owned.base_chain_handle,
        },
        &key,
    ) {
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
    finalize_owned(journal_path, key_path, &owned, boot_id, source)?;
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
) -> Result<(), EnforcementError> {
    use crate::ownership_journal::{self as journal, JournalIdentity, OwnershipJournal};
    // A Preparing record (and therefore its authentication key) already exists on
    // this path; load_or_generate reads it (never generates a spurious second).
    let key = journal::load_or_generate_auth_key(key_path)
        .map_err(|err| acquire_failed(format!("journal authentication key unusable: {err}")))?;
    let record = OwnershipJournal::Owned {
        identity: JournalIdentity {
            schema_version: journal::JOURNAL_SCHEMA_VERSION,
            marker: owned.marker.clone(),
            boot_id: boot_id.to_string(),
            source: source.to_string(),
        },
        table_handle: owned.table_handle,
        base_chain_handle: owned.base_chain_handle,
    };
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
    /// Bounded, single-flight, rate-limited ownership proof. Owns the latching
    /// policy: a COMPLETED negative proof withdraws readiness permanently, while
    /// a deadline overrun is indeterminate and only latches once the consecutive
    /// budget is exhausted. Single-flight is what stops an authenticated status
    /// poller from stacking `nft` forks. See [`crate::health_probe`].
    probe: crate::health_probe::BoundedHealthProbe,
    released: bool,
    /// GF1.3: latches once the runtime-loss deny-all safety net has been installed
    /// by `health()`, so a repeatedly-polled `Lost` health does not re-fork `nft`
    /// to reinstall the (idempotent) net on every supervisor tick. Interior
    /// mutability because `health()` takes `&self`.
    deny_all_net_installed: std::sync::atomic::AtomicBool,
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
#[cfg(target_os = "linux")]
const NFT_HEALTH_MIN_INTERVAL: Duration = Duration::from_millis(500);

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
    /// GF1.3: install the deny-all safety net once when `health()` first observes a
    /// completed loss of the owned table, so the host is fail-CLOSED in the window
    /// between the loss and the systemd restart. Idempotent and latched: the first
    /// `Lost` poll installs it; later `Lost` polls short-circuit so a wedged health
    /// loop does not re-fork `nft` every tick. A failed install is logged loudly
    /// and the latch stays UNSET so the next poll retries (never a silent give-up).
    fn ensure_runtime_loss_deny_all_net(&self) {
        // Delegates to the injectable, unit-tested latch+retry+escalate helper with
        // the real nft installer and by-name deleter. A FAILED install ESCALATES to
        // a by-name delete (no live `policy accept` castle table may remain after a
        // completed loss) and leaves the latch unset so the next health poll retries
        // the deny-all net rather than assuming a table-less host is protected.
        let _ = ensure_deny_all_net_installed_once(
            &self.deny_all_net_installed,
            crate::nftables::install_deny_all_safety_net,
            crate::nftables::force_delete_castle_table_by_name,
        );
    }
}

#[cfg(target_os = "linux")]
impl AcquiredComponent for NftablesTableComponent {
    fn kind(&self) -> ComponentKind {
        ComponentKind::NftablesTable
    }

    fn is_ready(&self) -> bool {
        // Two-valued gate: indeterminate fails closed here. This is what the
        // startup all-or-nothing readiness check uses, where "no answer" must
        // not let a runtime escape as ready.
        matches!(self.health(), crate::enforcement::ComponentHealth::Ready)
    }

    fn health(&self) -> crate::enforcement::ComponentHealth {
        use crate::enforcement::ComponentHealth;
        use crate::health_probe::ProbeOutcome;
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
        match self.probe.poll_result(move || {
            classify_nft_ownership_probe(crate::nftables::verify_owned_castle_table(&ownership))
        }) {
            ProbeOutcome::Ready => ComponentHealth::Ready,
            ProbeOutcome::Lost => {
                // GF1.3 runtime-loss invariant: a COMPLETED negative proof means
                // the owned table was deleted or drifted off its identity WHILE the
                // daemon is live. Reporting `Lost` and waiting for the systemd
                // restart leaves a multi-second window with NO castle table (host
                // default `accept`) for any live agent. Install the deny-all safety
                // net IMMEDIATELY so egress is fail-CLOSED without waiting for the
                // restart. We hold this component's authenticated this-boot
                // ownership identity, so forcing OUR named table to deny-all never
                // clobbers a table we cannot prove is ours (same authority as the
                // reclaim drift/loss paths; the net only ever rewrites our name).
                // Idempotent + latched so a repeatedly-`Lost` poll forks `nft` once.
                self.ensure_runtime_loss_deny_all_net();
                ComponentHealth::Lost
            }
            ProbeOutcome::Unavailable => ComponentHealth::ProbeUnavailable,
        }
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
/// Safety contract (blockers 2, 6):
/// * Runs UNDER the host ownership lock — a still-running daemon holds the lock,
///   so disarm refuses (`AlreadyHeld`) rather than racing a live owner.
/// * Deletes ONLY an object the AUTHENTICATED journal proves is ours for THIS
///   boot/source; a foreign table (no proof, drifted identity, wrong boot) is
///   REFUSED and left intact, never clobbered by name.
/// * Re-validates the EXACT complete inventory (handles + marker + pristine
///   shape) IMMEDIATELY before deletion, deletes by the narrowest handle-qualified
///   operation nft supports, and verifies ABSENCE immediately after.
/// * The journal is cleared ONLY after deletion AND post-delete absence are both
///   positively confirmed. On ANY ambiguity — corrupt/unauthenticated proof,
///   identity drift, a delete error, or an absence-verification failure — the
///   journal is RETAINED and the call fails.
///
/// Threat-boundary honesty: nftables offers no atomic compare-and-delete, so the
/// verify→delete→verify sequence is a best-effort TOCTOU narrowing, not an atomic
/// guarantee. A concurrent privileged host writer that swaps the table between the
/// pre-delete revalidation and the handle delete could still be raced; deleting by
/// the captured HANDLE (not by name) bounds the damage — a stale handle either no
/// longer resolves (nft errors, we retain and fail) or resolves to a different
/// object we already refused. This is the honest limit of what nft permits and is
/// documented, not claimed away.
///
/// GF1.1 disarm-path recovery: the live table has been positively recognized as
/// this daemon's own deny-all safety net for an interrupted (Preparing)
/// acquisition (the create-failure wedge). Delete it by name, confirm absence,
/// and clear the interrupted record. This is explicit teardown, so deny-all ->
/// nothing is the intended outcome; on any ambiguity the record is RETAINED. Does
/// NOT touch the host lock — the caller owns its lifetime and drops it after.
#[cfg(target_os = "linux")]
fn disarm_recover_deny_all_net(
    journal_path: &std::path::Path,
) -> Result<DisarmOutcome, EnforcementError> {
    let disarm_failed = |detail: String| EnforcementError::AcquireFailed {
        kind: ComponentKind::NftablesTable.as_str(),
        detail,
    };
    crate::nftables::force_delete_castle_table_by_name().map_err(|del_err| {
        disarm_failed(format!(
            "recognized this daemon's deny-all net for an interrupted acquisition but deleting it \
             failed; retaining the record: {del_err}"
        ))
    })?;
    match crate::nftables::table_exists() {
        Ok(false) => {}
        Ok(true) => {
            return Err(disarm_failed(
                "deny-all net still present after a by-name delete; retaining the record"
                    .to_string(),
            ))
        }
        Err(exists_err) => {
            return Err(disarm_failed(format!(
                "could not verify deny-all net absence after delete; retaining the record: \
                 {exists_err}"
            )))
        }
    }
    crate::ownership_journal::clear(journal_path).map_err(|clear_err| {
        disarm_failed(format!(
            "deleted the deny-all net but clearing the interrupted ownership record failed: \
             {clear_err}"
        ))
    })?;
    Ok(DisarmOutcome::StaleRecordCleared)
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
        let lock =
            crate::runtime_lock::HostRuntimeLock::acquire(&config.lock_path).map_err(|err| {
                disarm_failed(format!(
                    "cannot take the host ownership lock to disarm (is the daemon still \
                     running? stop it first): {err}"
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
                // Our Owned table for this boot: the exact identity to delete.
                ReclaimDecision::ReclaimOwned {
                    table_handle,
                    base_chain_handle,
                    marker,
                } => CastleTableOwnership {
                    table_handle,
                    base_chain_handle,
                    marker,
                },
                // An interrupted (Preparing) acquisition with a live table: capture
                // the live handles by marker. A marker mismatch (foreign) or nft
                // error -> refuse + RETAIN.
                ReclaimDecision::FinalizeInterrupted { marker } => {
                    match crate::nftables::capture_owned_castle_table(&marker) {
                        Ok(o) => o,
                        // GF1.1 create-failure recovery on the DISARM path. The journal
                        // is Preparing for this boot but the live table is not a
                        // capturable owned table. If it is this daemon's OWN deny-all net
                        // (the create-failed-then-ReArmLostOwned wedge state), disarm can
                        // clean it up (delete by name, confirm absence, clear the record)
                        // since this is explicit teardown; otherwise refuse + RETAIN.
                        // Without this, --disarm was wedged exactly like acquire.
                        Err(err) => match crate::nftables::live_table_is_deny_all_safety_net() {
                            Ok(true) => {
                                let outcome = disarm_recover_deny_all_net(journal_path);
                                drop(lock);
                                return outcome;
                            }
                            Ok(false) => {
                                drop(lock);
                                return Err(disarm_failed(format!(
                                    "an interrupted acquisition's marker does not match the live \
                                 table and it is not this daemon's deny-all net; refusing to \
                                 delete (retaining the record): {err}"
                                )));
                            }
                            Err(probe_err) => {
                                drop(lock);
                                return Err(disarm_failed(format!(
                                "an interrupted acquisition could not be captured ({err}) and the \
                                 deny-all-net recovery probe failed ({probe_err}); refusing \
                                 without clobbering (retaining the record)"
                            )));
                            }
                        },
                    }
                }
            };

        // 5) Re-validate the EXACT complete inventory immediately before deletion.
        //    A drift (replaced, mutated, foreign) -> refuse + RETAIN the journal.
        if let Err(err) = crate::nftables::verify_owned_castle_table(&owned) {
            drop(lock);
            return Err(disarm_failed(format!(
                "the live table no longer matches the owned identity; refusing to delete \
                 (retaining the journal): {err}"
            )));
        }

        // 6) Handle-qualified delete (re-verifies + deletes by handle internally).
        //    On error RETAIN the journal and fail.
        if let Err(err) = crate::nftables::remove_owned_castle_table(&owned) {
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
            eprintln!(
                "castle-wall-daemon: NFQUEUE serve failed ({err}) and durable failure audit failed: {audit_err}"
            );
            return;
        }
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

    // GF1.2: a reclaim drift whose deny-all net install FAILS must ESCALATE to a
    // by-name delete (so no live `policy accept` castle path remains), and a
    // successful install must NOT delete. Injected closures make the escalation
    // sequence deterministic without a live/broken nft; the real-nft post-condition
    // (a by-name delete leaves no live table) is asserted in the integration suite.
    #[test]
    fn drift_escalates_to_delete_only_when_deny_all_net_install_fails() {
        use crate::nftables::NftablesError;
        use std::cell::Cell;

        // Install fails -> escalate to delete.
        let deleted = Cell::new(false);
        let outcome = drift_enforce_fail_closed(
            || {
                Err(NftablesError::InvocationFailed(
                    "injected net failure".into(),
                ))
            },
            || {
                deleted.set(true);
                Ok(())
            },
        );
        assert!(matches!(outcome, DriftFailClosedOutcome::EscalatedDeleteOk));
        assert!(
            deleted.get(),
            "a failed deny-all install must escalate to a by-name delete"
        );

        // Install succeeds -> never delete.
        let deleted2 = Cell::new(false);
        let outcome2 = drift_enforce_fail_closed(
            || Ok(()),
            || {
                deleted2.set(true);
                Ok(())
            },
        );
        assert!(matches!(outcome2, DriftFailClosedOutcome::NetInstalled));
        assert!(
            !deleted2.get(),
            "a successful deny-all install must not delete the table"
        );

        // Both fail -> indeterminate (loud upstream), delete still attempted.
        let outcome3 = drift_enforce_fail_closed(
            || Err(NftablesError::InvocationFailed("net".into())),
            || Err(NftablesError::InvocationFailed("del".into())),
        );
        assert!(matches!(
            outcome3,
            DriftFailClosedOutcome::Indeterminate { .. }
        ));
    }

    // GF1.3: the runtime-loss deny-all net is installed at most once (latched) and
    // retried on failure. Injected installer + deleter make latch/retry/escalation
    // deterministic. On a FAILED install the by-name delete ESCALATION fires (no
    // live `policy accept` may remain) and the latch stays unset so it still retries.
    #[test]
    fn runtime_loss_deny_all_net_latches_once_and_retries_on_failure() {
        use crate::nftables::NftablesError;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let latch = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);
        let deletes = AtomicUsize::new(0);

        // First Lost with a FAILING install: not latched, so it will retry, AND it
        // escalates to a by-name delete so no drifted `policy accept` table lingers.
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(NftablesError::InvocationFailed("injected".into()))
            },
            || {
                deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(!installed);
        assert!(
            !latch.load(Ordering::SeqCst),
            "a failed install must not latch"
        );
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            1,
            "a failed deny-all install must escalate to a by-name delete"
        );

        // Retry, now succeeding: latches, and does NOT delete.
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || {
                deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(installed);
        assert!(latch.load(Ordering::SeqCst));
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            1,
            "a successful install must not escalate to a delete"
        );

        // Subsequent Lost polls must NOT re-fork nft: neither installer nor deleter
        // is called once the net is latched in.
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || {
                deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(!installed);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "installer runs only until it first succeeds (retry once, then latched)"
        );
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            1,
            "no delete after the net is latched"
        );
    }

    // GF1.3 (round-3 re-gate) fault injection: a PERSISTENT deny-all install failure
    // at runtime loss must stay fail-CLOSED. Each failing poll escalates to a
    // by-name delete so no drifted `policy accept` castle table remains live, and
    // when BOTH the install and the escalating delete fail the state is genuinely
    // indeterminate (loud) but never silently latched as "protected". This closes
    // the escalation asymmetry the round-2 re-gate found: the runtime-loss path
    // installed the net but, unlike the GF1.2 drift path, did not escalate on an
    // install failure, so a persistent failure left a drifted `policy accept` table
    // live until a later retry.
    #[test]
    fn runtime_loss_persistent_install_failure_escalates_and_stays_fail_closed() {
        use crate::nftables::NftablesError;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let latch = AtomicBool::new(false);
        let deletes = AtomicUsize::new(0);

        // Poll 1: install fails, escalating delete succeeds -> no live accept path,
        // latch unset (will retry).
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || {
                Err(NftablesError::InvocationFailed(
                    "persistent net failure".into(),
                ))
            },
            || {
                deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(!installed);
        assert!(
            !latch.load(Ordering::SeqCst),
            "a failed install never latches"
        );
        assert_eq!(deletes.load(Ordering::SeqCst), 1);

        // Poll 2: still failing -> escalates AGAIN (fail-closed on every poll, never
        // a one-shot that then gives up).
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || {
                Err(NftablesError::InvocationFailed(
                    "persistent net failure".into(),
                ))
            },
            || {
                deletes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(!installed);
        assert!(!latch.load(Ordering::SeqCst));
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            2,
            "a persistent install failure re-escalates the by-name delete on every poll"
        );

        // Poll 3: BOTH install and the escalating delete fail -> indeterminate, but
        // still NOT latched (never records a table-less host as protected).
        let installed = ensure_deny_all_net_installed_once(
            &latch,
            || Err(NftablesError::InvocationFailed("net".into())),
            || Err(NftablesError::InvocationFailed("del".into())),
        );
        assert!(!installed);
        assert!(
            !latch.load(Ordering::SeqCst),
            "even a both-failed poll must not latch a table-less host as protected"
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
            crate::enforcement::EnforcementStartError::Component { failed, reason } => {
                assert_eq!(failed, ComponentKind::NftablesTable);
                assert!(matches!(
                    reason,
                    EnforcementError::NotAvailableOnPlatform(_)
                ));
            }
            other => panic!("expected a component fail-before, got {other:?}"),
        }
    }
}
