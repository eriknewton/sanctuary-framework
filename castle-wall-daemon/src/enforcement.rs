//! Kernel-runtime enforcement lifecycle seam (Castle Wall Layer 1).
//!
//! The shipped daemon must never equate an authenticated IPC socket or a live
//! process with kernel enforcement. This module owns the ordered acquisition,
//! readiness gating, and reverse-order teardown of the runtime components that
//! together constitute a live *kernel runtime*: the nftables table, the NFQUEUE
//! handle and its verdict thread, and the manifest watcher.
//! `DaemonRuntimeState::KernelRuntimeReady` is DERIVED from an
//! [`EnforcementRuntime`] that owns every required component and where every
//! component still reports ready; it is never stored, so liveness alone can
//! never present as a ready kernel runtime.
//!
//! Kernel-runtime readiness is NOT the same claim as *enforcing*. A ready
//! runtime means the kernel-side machinery (table, bound queue, watcher) is
//! live and would gate a wrapped agent's egress; it does NOT mean any agent's
//! traffic is actually being enforced, because this slice launches no protected
//! agent and installs no per-agent cgroup jump rule (the base output chain is
//! `policy accept`). `DaemonRuntimeState::Enforcing` — and therefore
//! `DaemonHandle::is_enforcing()` — is reserved for the later slice that wraps a
//! real agent and gates its cgroup; it is NEVER derived from kernel-runtime
//! readiness here. Conflating the two is the exact "liveness read as
//! enforcement" defect this module exists to prevent, one level up: an
//! authenticated socket is not enforcement, and neither is a merely-ready
//! kernel runtime with nothing wrapped behind it.
//!
//! The seam is expressed as two traits so startup ordering and cleanup can be
//! driven by deterministic fakes on a host without a kernel (macOS CI):
//!
//! * [`ComponentProvider`] — a factory that acquires exactly one component or
//!   fails. A provider whose `acquire()` returns `Err` has already released any
//!   partial resource it took; the runtime never releases a component that
//!   failed to acquire.
//! * [`AcquiredComponent`] — an owned, releasable resource. `release()` is
//!   idempotent and MUST join any thread the component owns before returning,
//!   so no detached resource-owning thread can outlive the runtime owner.
//!
//! Distro neutrality: the runtime core depends only on mainline-kernel
//! primitives (nftables, NFQUEUE, inotify), never on a distro's init system,
//! package layout, or paths. It is designed to serve BOTH fleet/server Debian
//! or Ubuntu and developer-desktop Omarchy or Arch. Ubuntu 24.04 may be the
//! reference server CI/drill environment, but no Ubuntu-only behavior is baked
//! in; a distro-specific concern belongs in the boot/install layer, not here.
//! Server hardware is the first acceptance platform (Omarchy is not); Linux
//! assurance stays `not_implemented` until captured hardware-drill evidence
//! exists.
//!
//! Scope boundary: this L1 slice owns the kernel-runtime lifecycle only. The
//! long-term fleet target (research-cluster sandbox egress plus credential
//! custody) layers ON this seam — credential custody and any per-agent cgroup
//! sandbox scoping are deliberately NOT modeled here and NOT claimed. The
//! [`ComponentKind`] set is this runtime's kernel components, not a finished
//! fleet-egress design; a later slice extends it (see its docs).
//!
//! The concrete production providers (real nftables install under the host
//! ownership lock, real NFQUEUE bind + verdict thread, real manifest watcher)
//! live in [`crate::runtime_providers`], and `boot()` drives them through
//! [`EnforcementRuntime::start`]. This module keeps only the platform-neutral
//! lifecycle CONTRACT — ordered acquisition, readiness gating, reverse-order
//! teardown — so it stays testable with deterministic fakes on a host without a
//! kernel. Activating the plan makes the daemon reach `KernelRuntimeReady` on a
//! privileged Linux host. That base state alone is not `Enforcing`: a protected
//! agent must also be wrapped. Linux egress enforcement stays
//! `not_implemented` (ASSURANCE_MATRIX row 17) until a captured hardware drill
//! proves a wrapped agent is actually blocked.
//! [`EnforcementError::AdapterNotVerified`] remains the vocabulary for a future
//! provider that is wired but not yet drill-proven.

use crate::daemon::DaemonRuntimeState;

/// The kernel-runtime components THIS L1 enforcement runtime owns, in
/// acquisition order. `Enforcing` requires EVERY one of these acquired and
/// still ready; process liveness and an authenticated IPC socket are
/// deliberately absent because they are not enforcement.
///
/// This is the L1 kernel-lifecycle set, not the complete fleet-egress design:
/// per-agent cgroup sandbox scoping and credential custody are separate,
/// out-of-scope concerns for this slice. A later slice that needs one adds its
/// kind here (and to `REQUIRED_IN_ORDER`), which tightens `Enforcing` by
/// construction — a partial set can never read as enforcing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    /// The `castle-wall` nftables table + base chains (`nftables.rs`). Installed
    /// first so the NFQUEUE dispatch rule it hosts has a table to attach to.
    NftablesTable,
    /// The bound NFQUEUE handle and its verdict-loop thread (`nfqueue.rs`).
    /// Acquired after the table so queued packets have fail-closed rules behind
    /// them; released before the table so the thread stops feeding a table that
    /// is about to be removed.
    Nfqueue,
    /// The manifest inotify/poll watcher (`manifest/watcher.rs`).
    ManifestWatcher,
}

impl ComponentKind {
    /// Required components in acquisition order. Teardown is the reverse of
    /// this slice; both orders are asserted by tests so the contract is
    /// executable, not just documented.
    pub const REQUIRED_IN_ORDER: [ComponentKind; 3] = [
        ComponentKind::NftablesTable,
        ComponentKind::Nfqueue,
        ComponentKind::ManifestWatcher,
    ];

    /// Stable operator/log token for the component.
    pub fn as_str(&self) -> &'static str {
        match self {
            ComponentKind::NftablesTable => "nftables_table",
            ComponentKind::Nfqueue => "nfqueue",
            ComponentKind::ManifestWatcher => "manifest_watcher",
        }
    }
}

impl std::fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors a provider can return from `acquire()`.
#[derive(Debug, thiserror::Error)]
pub enum EnforcementError {
    /// The component's backing primitive does not exist on this platform (e.g.
    /// NFQUEUE on macOS). A required component that is unavailable is a
    /// fail-before condition, not a silent downgrade.
    #[error("component {0} not available on this platform")]
    NotAvailableOnPlatform(&'static str),
    /// The backing kernel/OS call failed while acquiring the component.
    #[error("component {kind} acquisition failed: {detail}")]
    AcquireFailed { kind: &'static str, detail: String },
    /// The component acquired but did not report ready. Treated identically to
    /// an acquire failure by [`EnforcementRuntime::start`]: unwind everything.
    /// Emitted both for a just-acquired component that is unready and for an
    /// EARLIER component the whole-set re-check finds lost after a later
    /// acquisition (see [`EnforcementRuntime::start`]).
    #[error("component {0} acquired but did not report ready")]
    NotReadyAfterAcquire(&'static str),
    /// The provider returned a component whose `kind()` does not match the kind
    /// it advertised via [`ComponentProvider::kind`]. The plan gate validates
    /// the ADVERTISED kinds' order before acquisition; this closes the gap to
    /// the DELIVERED component so a provider cannot clear the ordered-plan gate
    /// and then hand back a component of a different kind, which would silently
    /// diverge the owned set from [`ComponentKind::REQUIRED_IN_ORDER`]. A
    /// matching shape is not a matching kind. Treated as a fail-before: the
    /// mismatched component and all predecessors are released in reverse order.
    #[error("component provider advertised {expected} but delivered a {actual} component")]
    ComponentKindMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    /// The production adapter for this component is not yet wired to a
    /// drill-verified kernel path, so it refuses to report success. This is the
    /// honest not-ready state the shipped path uses until the Linux drill
    /// (ASSURANCE_MATRIX row 17) closes; it is NOT a stub that pretends to
    /// enforce.
    #[error("component {0} adapter is not wired to a drill-verified kernel path in this slice")]
    AdapterNotVerified(&'static str),
}

/// An acquired, owned runtime resource.
///
/// `release()` is the teardown contract: it MUST be idempotent (second and
/// later calls are no-ops) and MUST join any thread the component owns before
/// returning, so the "no detached thread outlives the owner" invariant holds
/// even on a panicking or forgetful caller (the runtime's `Drop` calls it).
///
/// `release()` MUST also be panic-free: it runs from [`EnforcementRuntime`]'s
/// `Drop`, and a panic in a `Drop` that is itself running during an unwind
/// aborts the whole process. An implementation therefore swallows (or logs)
/// join and teardown failures rather than unwrapping them — a failed thread
/// join or a poisoned lock is a degraded teardown, never an abort.
/// One controller call's result, carried to the supervisor for exact attempt
/// evidence. No variant is a persistent assertion about the wall or net.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostReadyRecoveryResult {
    NoInstall,
    OwnedWallReady,
    InstallSucceeded,
    InstallFailed,
}

impl PostReadyRecoveryResult {
    pub fn holds_gate(self) -> bool {
        matches!(self, Self::OwnedWallReady | Self::InstallSucceeded)
    }
}

pub trait AcquiredComponent: Send {
    fn kind(&self) -> ComponentKind;
    /// Live readiness. A component that has lost its resource — a clobbered
    /// table, a verdict thread that exited — reports `false` here, and the
    /// runtime treats that as loss of `Enforcing`. Readiness is re-polled on
    /// every state query, never cached at acquisition.
    ///
    /// This is the TWO-valued gate used where indeterminate must fail closed
    /// (the startup all-or-nothing readiness check). Where the difference
    /// between "proven lost" and "no answer" matters — the supervision loop and
    /// the status projection — use [`health`](Self::health) instead.
    fn is_ready(&self) -> bool;
    /// Three-valued live health. The default derives from
    /// [`is_ready`](Self::is_ready) for components whose check cannot be
    /// indeterminate (an in-process flag, a thread liveness bit). A component
    /// whose check can time out or contend — the nftables ownership proof forks
    /// `nft` — overrides this so a momentary no-answer is reported as
    /// [`ComponentHealth::ProbeUnavailable`] rather than manufacturing a loss.
    ///
    /// Every consumer must treat `ProbeUnavailable` as not-proven: it withholds
    /// a readiness assertion but does not itself assert failure.
    fn health(&self) -> ComponentHealth {
        if self.is_ready() {
            ComponentHealth::Ready
        } else {
            ComponentHealth::Lost
        }
    }
    /// R3 (LINUX-STOP-LOSS-RACE-01, Claude F3): the same three-valued read as
    /// [`health`](Self::health), but MUST bypass any internal rate-limit cache
    /// so the result is a live proof, never a reading up to that cache's
    /// window old. The default delegates to `health`, which is correct for
    /// every component with no such cache (an in-process flag, a thread
    /// liveness bit). The nftables component overrides this to re-probe
    /// instead of reusing its `NFT_HEALTH_MIN_INTERVAL` cached reading.
    /// `stop_final_health_outcome`'s one stop-time pass is the only caller
    /// that needs this; the periodic supervision loop keeps using `health`.
    fn health_fresh(&self) -> ComponentHealth {
        self.health()
    }
    /// Called when a STARTUP readiness check reads this component `Lost`, BEFORE the
    /// reverse-order unwind and before any error is returned.
    ///
    /// The default is a no-op, which is the correct behaviour for every component
    /// whose loss leaves the kernel egress gate intact: the daemon simply unwinds and
    /// the preserved table is adopted on restart. The nftables component overrides it,
    /// because a completed negative proof of ITS resource means adopted agents may be
    /// live with no gate in the kernel, and the safety net has to be installed while
    /// this process still holds the host lock.
    ///
    /// INVARIANT for any implementor: this runs BEFORE `release`, so it may still use
    /// resources the component owns; it must not panic, because the unwind must
    /// proceed either way, and it must not itself release anything.
    fn on_startup_lost(&self) {}

    /// Called when a STARTUP readiness check reads this component `Indeterminate`.
    ///
    /// An indeterminate reading is the ABSENCE of evidence, so an implementor must
    /// install nothing here. The default is a no-op.
    fn on_startup_indeterminate(&self) {}

    /// Post-ready exhausted probe budget: run the hook once before exit.
    /// A transient unavailable reading never reaches this method.
    fn on_post_ready_indeterminate(&self) {}

    /// POST-READY recovery for a COMPLETED negative proof of this component's
    /// resource, invoked by the supervisor BEFORE any exit arm.
    ///
    /// The default is a no-op returning false, which is correct for every component
    /// that has no kernel gate to re-arm. The nftables component overrides it to
    /// install the safety net and then persist best-effort, and publishes `Recovering`
    /// through its health while an attempt is outstanding.
    ///
    /// F4 / C2a1(a) (LINUX-STOP-LOSS-RACE-01): `shutting_down` is a closure so an
    /// implementor reads the CURRENT shutdown state at the moment it actually
    /// decides, not a value copied before this call was reached (R2: a stop can
    /// land during the health probe that gated this call). A stop never leaves a
    /// proven loss without its one net attempt: the first entry for a fresh loss
    /// installs regardless of what the closure returns; shutdown gates only a
    /// later retry (no re-probe, no readiness restoration) and any host-wide
    /// install (A155). The result describes this call only; it is not a
    /// retained claim about kernel state.
    fn attempt_post_ready_recovery(
        &self,
        shutting_down: &dyn Fn() -> bool,
    ) -> PostReadyRecoveryResult {
        let _ = shutting_down;
        PostReadyRecoveryResult::NoInstall
    }

    /// The tagged `safety_net` state this component last produced, for the audit row
    /// and the signed status report.
    ///
    /// `None` from a component that has no safety net of its own, which is every
    /// component but the nftables table. The default is `None` rather than
    /// `NotAttempted`, so a component that cannot install one is distinguishable from
    /// one that could and did not.
    fn safety_net_audit_state(&self) -> Option<crate::nftables::SafetyNetAuditState> {
        None
    }

    /// Idempotent, panic-free teardown; joins owned threads before returning.
    /// Runs from `Drop`, so it must never unwrap a fallible join or lock.
    fn release(&mut self);
}

/// A component's readiness AT STARTUP, typed so the three outcomes drive three
/// different actions instead of collapsing into a boolean.
///
/// INVARIANT, and why a boolean will not do here: `Lost` and `Indeterminate` both
/// withhold readiness, so a boolean gate treats them identically. They are not
/// identical. A COMPLETED negative ownership proof from the nftables component is
/// evidence that the kernel no longer holds this daemon's table while adopted agents
/// may still be live, and the safety net must be installed before the daemon unwinds.
/// An indeterminate reading is the ABSENCE of evidence and must install nothing,
/// because installing on no evidence would replace a healthy table on a momentarily
/// contended probe. The `kind` rides along because only the nftables component's
/// reading carries either action; every other component's loss leaves the table
/// intact and keeps the existing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupReadiness {
    /// Proven ready.
    Ready,
    /// A COMPLETED negative proof: this component's resource provably does not hold.
    Lost { kind: ComponentKind },
    /// No answer. Proves nothing, and is never promoted to `Lost` here.
    Indeterminate { kind: ComponentKind },
}

impl StartupReadiness {
    /// Read a component's startup readiness from its three-valued health.
    ///
    /// Derived from [`AcquiredComponent::health`] rather than from `is_ready`, so a
    /// probe that can time out reports its indeterminate arm instead of having it
    /// folded into a loss. Must match the `ComponentHealth` arms below.
    pub fn of(component: &dyn AcquiredComponent) -> Self {
        let kind = component.kind();
        match component.health() {
            ComponentHealth::Ready => StartupReadiness::Ready,
            ComponentHealth::Lost => StartupReadiness::Lost { kind },
            ComponentHealth::ProbeUnavailable => StartupReadiness::Indeterminate { kind },
            ComponentHealth::Indeterminate => StartupReadiness::Indeterminate { kind },
            // The recovery controller is a POST-READY owner, so a component cannot be
            // recovering during startup. If one ever reports it here, the reading it
            // rests on is a completed negative proof, so treat it as the loss it is
            // rather than as readiness.
            ComponentHealth::Recovering => StartupReadiness::Lost { kind },
        }
    }

    /// Whether this reading is the nftables component's, which is the only one whose
    /// startup loss or indeterminacy carries a safety-net action.
    pub fn nftables_kind(&self) -> Option<ComponentKind> {
        match self {
            StartupReadiness::Ready => None,
            StartupReadiness::Lost { kind } | StartupReadiness::Indeterminate { kind } => {
                (*kind == ComponentKind::NftablesTable).then_some(*kind)
            }
        }
    }
}

/// Route a non-ready STARTUP reading to the component's own responder.
///
/// Kept as one function so the two checks in `start` cannot drift apart on which
/// reading calls which responder, and so the polarity is stated once: `Lost` is a
/// completed negative proof and may act on the kernel; `Indeterminate` proves
/// nothing and must not.
fn respond_to_startup_readiness(component: &dyn AcquiredComponent, readiness: StartupReadiness) {
    match readiness {
        StartupReadiness::Ready => {}
        StartupReadiness::Lost { .. } => component.on_startup_lost(),
        StartupReadiness::Indeterminate { .. } => component.on_startup_indeterminate(),
    }
}

/// Three-valued component health. `ProbeUnavailable` is the indeterminate arm;
/// it exists so contention or a probe deadline is never reported as a proven
/// loss (which would restart a healthy daemon) and never as readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentHealth {
    Ready,
    Lost,
    ProbeUnavailable,
    /// The probe's own consecutive no-answer budget has been exhausted.
    /// This is a terminal no-evidence outcome, distinct from a transient poll.
    Indeterminate,
    /// A COMPLETED negative proof has been observed AND a recovery attempt for it is
    /// in flight: the safety net is being installed or retried while this process
    /// keeps the host lock.
    ///
    /// Distinct from `Lost` so no consumer reaches an exit arm before the net has had
    /// its chance. It is NOT readiness: a consumer must never treat it as enforcing.
    /// Every consumer that has an exit arm for `Lost` must have an explicit
    /// non-exiting arm for this.
    Recovering,
}

/// A factory that yields exactly one acquired component or fails.
///
/// `acquire()` consumes the provider (a provider makes one component). On `Err`
/// the provider is responsible for having released any partial resource it
/// took; the runtime will not call `release()` on a component it never received.
pub trait ComponentProvider: Send {
    /// The component this provider will produce; known before `acquire()` so a
    /// failure can be attributed to the right step.
    fn kind(&self) -> ComponentKind;
    fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError>;
}

/// Whether the daemon holds a live, ready kernel runtime, and if not, precisely
/// why. This is a readiness claim about the kernel-side machinery, NOT an
/// enforcement claim about any agent's traffic (see the module docs): a ready
/// runtime is a precondition for enforcing a wrapped agent, never enforcement
/// on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Every required component is owned and still reports ready. The kernel
    /// runtime is live; this is NOT `Enforcing` (no agent is wrapped in this
    /// slice), so it never satisfies `DaemonHandle::is_enforcing()`.
    KernelRuntimeReady,
    NotReady {
        reason: NotReadyReason,
    },
}

/// The specific reason a runtime is not ready. Every variant is a hard
/// "not ready" — absent, indeterminate, and lost all read as not-proven,
/// never as passing.
///
/// `Copy` because it is carried by value inside the published health
/// observation ([`crate::runtime_health::RuntimeHealthState`]), which a reader
/// copies out from under a briefly-held mutex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyReason {
    /// No `EnforcementRuntime` is owned at all (the shipped path in this slice).
    NoRuntime,
    /// A required component was never acquired into the runtime.
    MissingComponent(ComponentKind),
    /// A required component was acquired but its `is_ready()` now returns false.
    ComponentLost(ComponentKind),
    /// The runtime has been shut down (or is mid-shutdown); teardown released
    /// its components.
    ShuttingDown,
    /// The shared runtime health object could not be locked. Readiness probes
    /// fail closed rather than returning the last cached healthy value.
    HealthProbeUnavailable,
    /// The nft ownership probe exhausted its no-answer budget. No kernel
    /// replacement is justified, but the hook must run before exit.
    HealthProbeIndeterminate,
    /// The audit WAL suffered an ambiguous durable mutation or its lock was
    /// poisoned. Continuing could emit decisions without trustworthy evidence.
    AuditWalPoisoned,
    /// A component proved its resource lost and the safety net is being installed or
    /// retried for it while this process keeps the host lock.
    ///
    /// NOT readiness, and NOT an exit condition: a consumer that exits on
    /// `ComponentLost` must WAIT on this instead, so the net has its chance before the
    /// process goes away and the restart window opens. Must match
    /// `ComponentHealth::Recovering`.
    SafetyNetRecovering(ComponentKind),
}

/// Failure returned by [`EnforcementRuntime::start`] when the daemon could not
/// reach the fully-enforcing state. By the time a [`Component`](Self::Component)
/// failure is returned every component acquired before the failure has been
/// released in reverse order, so the daemon is left non-enforcing with no
/// leaked resource or thread. A [`PlanMismatch`](Self::PlanMismatch) is returned
/// before any provider is acquired, so it leaks nothing by construction.
#[derive(Debug, thiserror::Error)]
pub enum EnforcementStartError {
    /// The plan's ordered component kinds did not EXACTLY equal
    /// [`ComponentKind::REQUIRED_IN_ORDER`] — a missing component, an extra or
    /// duplicate one, or a wrong order. This is validated BEFORE any provider is
    /// acquired, so a misordered or incomplete plan touches no kernel resource
    /// and acquires nothing; the daemon is left non-enforcing. Without this
    /// gate a caller-assembled plan could acquire a partial or reordered set
    /// (e.g. NFQUEUE before its nftables table) that per-step checks alone would
    /// not catch.
    #[error("enforcement plan mismatch: expected {expected:?} in order, got {actual:?}")]
    PlanMismatch {
        expected: Vec<ComponentKind>,
        actual: Vec<ComponentKind>,
    },
    /// A provider failed to acquire, delivered a component of the wrong kind, or
    /// a component was not ready — either just after acquisition or at the
    /// whole-set re-check that runs before a runtime escapes. Every component
    /// acquired before the failure (and the offending one, when it was
    /// acquired) has been released in reverse order.
    #[error("enforcement start failed at component {failed}: {reason}")]
    Component {
        /// The component the failure is attributed to: the provider that failed
        /// to acquire or delivered the wrong kind, or — for the whole-set
        /// re-check — the earliest component found no longer ready.
        failed: ComponentKind,
        /// The TYPED startup readiness that produced this failure, when the failure
        /// came from one of the two readiness checks.
        ///
        /// Carried so a caller can tell a COMPLETED negative proof from an
        /// indeterminate reading without re-deriving it from the message text. `None`
        /// means the failure came from acquisition or a kind mismatch, where no
        /// readiness reading was taken. Must match the arms of `StartupReadiness`.
        evidence: Option<StartupReadiness>,
        #[source]
        reason: EnforcementError,
    },
}

/// Owns the acquired runtime components and enforces the lifecycle contract:
/// all-or-nothing startup, reverse-order teardown, and readiness-gated state.
pub struct EnforcementRuntime {
    /// Acquired components in acquisition order. Teardown pops from the end, so
    /// this vector's tail is always the next thing to release.
    components: Vec<Box<dyn AcquiredComponent>>,
    /// Set once teardown has run so status queries after shutdown report
    /// `ShuttingDown` rather than re-inspecting released components.
    shutdown_done: bool,
}

impl EnforcementRuntime {
    /// Acquire every provider in order. On the FIRST failure — an `acquire()`
    /// error, a component whose delivered `kind()` does not match the kind its
    /// provider advertised, or a component that acquires but is not ready —
    /// every already-acquired component (including the just-acquired offending
    /// one) is released in reverse acquisition order and the error is returned.
    ///
    /// The plan's SHAPE is validated first: the providers' ordered kinds must
    /// exactly equal [`ComponentKind::REQUIRED_IN_ORDER`]. A misordered,
    /// incomplete, or over-complete plan is rejected with
    /// [`EnforcementStartError::PlanMismatch`] BEFORE any provider is acquired,
    /// so a mismatched plan touches no kernel resource and acquires nothing.
    /// This makes "the runtime always owns exactly the required set, in order"
    /// a startup invariant rather than something the per-step loop only
    /// approximates.
    ///
    /// Two post-acquire checks close the gap between the plan gate (which sees
    /// only ADVERTISED kinds) and the components actually delivered:
    ///
    /// * a per-step DELIVERED-kind check rejects a provider that clears the
    ///   ordered-plan gate on one advertised kind but hands back a component of
    ///   another kind ([`EnforcementError::ComponentKindMismatch`]);
    /// * a final WHOLE-SET readiness re-check, run after the last provider is
    ///   acquired and before any runtime escapes, catches an earlier component
    ///   that lost readiness DURING a later provider's `acquire()` (e.g. binding
    ///   NFQUEUE clobbering the nftables table). The per-step check cannot see
    ///   that, so without the re-check a later acquisition could silently
    ///   invalidate an earlier component yet `start` would return an
    ///   "enforcing" runtime.
    ///
    /// Fail-before is structural here: a runtime value only ever escapes this
    /// function when the whole ordered set is acquired, is the exact kind set,
    /// and every member is STILL ready at the end, so a caller cannot hold a
    /// partially-constructed or already-degraded runtime that would read as
    /// enforcing.
    pub fn start(
        providers: Vec<Box<dyn ComponentProvider>>,
    ) -> Result<Self, EnforcementStartError> {
        // Validate the plan against the required set/order BEFORE acquiring any
        // provider: `acquire()` consumes the provider and may touch the kernel,
        // so a shape mismatch must be caught while every provider is still
        // untouched. `Vec<ComponentKind> == [ComponentKind; N]` compares element
        // by element, so this rejects wrong order, wrong count, and duplicates.
        let advertised: Vec<ComponentKind> = providers.iter().map(|p| p.kind()).collect();
        if advertised != ComponentKind::REQUIRED_IN_ORDER {
            return Err(EnforcementStartError::PlanMismatch {
                expected: ComponentKind::REQUIRED_IN_ORDER.to_vec(),
                actual: advertised,
            });
        }
        // Freeze the advertised kinds from the preflight vector and drive
        // acquisition by zipping each provider with its already-observed
        // expected kind. provider.kind() is called EXACTLY ONCE per provider —
        // here, at plan-gate time — and NEVER again during acquisition. A
        // stateful (or hostile) provider that advertises the required kind at
        // preflight and then reports a different kind on a second call therefore
        // cannot move the delivered-kind check's target: the frozen `expected`,
        // not a fresh provider.kind(), is what every delivered component is
        // validated against. This is what makes "the owned set is exactly
        // REQUIRED_IN_ORDER, in order" hold even when a provider's self-reported
        // kind is not stable across calls.
        let mut components: Vec<Box<dyn AcquiredComponent>> = Vec::new();
        for (provider, expected) in providers.into_iter().zip(advertised) {
            match provider.acquire() {
                Ok(component) => {
                    let delivered = component.kind();
                    // Push before any post-acquire check so an offending
                    // component is torn down by the same reverse-order sweep as
                    // its predecessors — no special-case cleanup path to drift.
                    components.push(component);
                    // Delivered-kind check against the FROZEN expected kind: the
                    // plan gate validated the ADVERTISED kinds' order before
                    // acquisition; this verifies the component the provider
                    // actually returned is that same frozen kind, so a provider
                    // cannot pass the ordered-plan gate and then hand back a
                    // different kind (which would diverge the owned set from
                    // REQUIRED_IN_ORDER). A matching shape is not a matching kind.
                    if delivered != expected {
                        release_reverse(&mut components);
                        return Err(EnforcementStartError::Component {
                            failed: expected,
                            // No readiness reading is taken on a kind mismatch.
                            evidence: None,
                            reason: EnforcementError::ComponentKindMismatch {
                                expected: expected.as_str(),
                                actual: delivered.as_str(),
                            },
                        });
                    }
                    // Per-step readiness, TYPED: the first of the two startup checks
                    // memo D1b step 7 names. An unready just-acquired component is
                    // torn down by the same reverse-order sweep as its predecessors,
                    // but WHICH reading it gave decides what happens first.
                    // Safety: the delivered component was pushed onto `components` immediately
                    // above in this same iteration, so the vector is non-empty.
                    let just_acquired = components.last().expect("component just pushed");
                    let readiness = StartupReadiness::of(just_acquired.as_ref());
                    if readiness != StartupReadiness::Ready {
                        // The component's own responder runs BEFORE the unwind, while
                        // it still owns its resources and this process still holds any
                        // host lock. `release_reverse` then runs unconditionally: it is
                        // what releases the host lock the disarm verb needs, so it is
                        // never skipped on this path.
                        respond_to_startup_readiness(just_acquired.as_ref(), readiness);
                        release_reverse(&mut components);
                        return Err(EnforcementStartError::Component {
                            failed: expected,
                            evidence: Some(readiness),
                            reason: EnforcementError::NotReadyAfterAcquire(expected.as_str()),
                        });
                    }
                }
                Err(reason) => {
                    // The failed provider yielded nothing to release; unwind the
                    // predecessors and leave the daemon non-enforcing.
                    release_reverse(&mut components);
                    return Err(EnforcementStartError::Component {
                        failed: expected,
                        // No readiness reading is taken when acquisition itself failed.
                        evidence: None,
                        reason,
                    });
                }
            }
        }
        // Whole-set readiness re-check before any runtime escapes: a component
        // acquired earlier can lose readiness DURING a later provider's
        // acquire() (e.g. binding NFQUEUE clobbers the nftables table the
        // earlier step installed). The per-step check above cannot observe
        // that, so re-poll the ENTIRE set in acquisition order and unwind
        // everything if any member is no longer ready. Iterating in acquisition
        // order and returning the FIRST not-ready component names the earliest
        // casualty. Without this a later acquisition could silently invalidate
        // an earlier component yet start() would return an "enforcing" runtime.
        // The second of the two startup checks, TYPED for the same reason. Iterating in
        // acquisition order and acting on the FIRST non-ready reading names the earliest
        // casualty.
        if let Some((failed, readiness)) = components
            .iter()
            .map(|component| (component, StartupReadiness::of(component.as_ref())))
            .find(|(_, readiness)| *readiness != StartupReadiness::Ready)
            .map(|(component, readiness)| {
                respond_to_startup_readiness(component.as_ref(), readiness);
                (component.kind(), readiness)
            })
        {
            // Never skipped: this is what releases the host lock the disarm verb needs.
            release_reverse(&mut components);
            return Err(EnforcementStartError::Component {
                failed,
                evidence: Some(readiness),
                reason: EnforcementError::NotReadyAfterAcquire(failed.as_str()),
            });
        }
        Ok(Self {
            components,
            shutdown_done: false,
        })
    }

    /// Current kernel-runtime readiness, re-polling each component's live
    /// readiness. Returns `KernelRuntimeReady` ONLY when every required
    /// component is present and ready; a missing component, a lost component, or
    /// a shut-down runtime all read as not-ready. Readiness is a precondition
    /// for enforcing a wrapped agent, never enforcement itself (module docs).
    pub fn status(&self) -> EnforcementStatus {
        self.status_impl(false)
    }

    /// R3 (LINUX-STOP-LOSS-RACE-01, Claude F3): the same projection as
    /// [`status`](Self::status), but every component is read through
    /// [`AcquiredComponent::health_fresh`] instead of `health`, bypassing any
    /// rate-limit cache. The one caller is `stop_final_health_outcome`'s
    /// `S_STOP_FINAL_HEALTH` pass, which must never classify a loss as clean
    /// because it landed inside the nft component's cache window.
    pub fn status_fresh(&self) -> EnforcementStatus {
        self.status_impl(true)
    }

    fn status_impl(&self, force_fresh: bool) -> EnforcementStatus {
        if self.shutdown_done {
            return EnforcementStatus::NotReady {
                reason: NotReadyReason::ShuttingDown,
            };
        }
        for required in ComponentKind::REQUIRED_IN_ORDER {
            match self.components.iter().find(|c| c.kind() == required) {
                // Defense-in-depth: `start` validates the plan against
                // REQUIRED_IN_ORDER before constructing a runtime, so a runtime
                // reached through `start` can never be missing a required kind.
                // This arm still names an absent component rather than falling
                // through to `KernelRuntimeReady`, so a runtime built by any
                // future path that bypasses `start` reads as not-ready.
                None => {
                    return EnforcementStatus::NotReady {
                        reason: NotReadyReason::MissingComponent(required),
                    }
                }
                // Live re-poll: a component that dropped its resource since
                // acquisition invalidates readiness on the spot. An
                // INDETERMINATE reading is reported as `HealthProbeUnavailable`
                // rather than `ComponentLost`, so a supervisor can retry a
                // no-answer instead of restarting the daemon on it, while a
                // status reader still gets no readiness assertion.
                Some(component) => match if force_fresh {
                    component.health_fresh()
                } else {
                    component.health()
                } {
                    ComponentHealth::Ready => {}
                    ComponentHealth::Lost => {
                        return EnforcementStatus::NotReady {
                            reason: NotReadyReason::ComponentLost(required),
                        }
                    }
                    ComponentHealth::ProbeUnavailable => {
                        return EnforcementStatus::NotReady {
                            reason: NotReadyReason::HealthProbeUnavailable,
                        }
                    }
                    ComponentHealth::Indeterminate => {
                        return EnforcementStatus::NotReady {
                            reason: NotReadyReason::HealthProbeIndeterminate,
                        }
                    }
                    // Withhold readiness WITHOUT reporting the loss that a supervisor
                    // exits on: the net is being installed or retried right now.
                    ComponentHealth::Recovering => {
                        return EnforcementStatus::NotReady {
                            reason: NotReadyReason::SafetyNetRecovering(required),
                        }
                    }
                },
            }
        }
        EnforcementStatus::KernelRuntimeReady
    }

    /// Give every component that reports a COMPLETED negative proof one post-READY
    /// recovery attempt, BEFORE the supervisor reaches any exit arm.
    ///
    /// INVARIANT on the ordering: this runs while the process still holds whatever host
    /// lock its components took. Exiting first and recovering later is not available,
    /// because the lock goes with the process and the restart cannot resume an attempt
    /// this process began. Components that report `Ready`, `ProbeUnavailable` or
    /// `Recovering` are not driven here: the first needs nothing, the second is the
    /// absence of evidence, and the third already has an attempt outstanding.
    ///
    /// `shutting_down` is read live by the selected component's own
    /// `attempt_post_ready_recovery`, not copied into a `bool` here (R2). `force_fresh`
    /// (R3) selects `health_fresh` over `health` for the gate check below, matching
    /// whichever the caller used to decide this is the stop-time final pass.
    ///
    /// Return the result of the selected component's call to the supervisor.
    pub fn attempt_post_ready_recovery(
        &self,
        shutting_down: &dyn Fn() -> bool,
        force_fresh: bool,
    ) -> PostReadyRecoveryResult {
        let mut result = PostReadyRecoveryResult::NoInstall;
        for component in &self.components {
            // BOTH readings drive the controller. `Lost` is the entry; `Recovering` is
            // an attempt already outstanding, and it must be re-entered on the retry
            // interval or a failed install would never be retried at all.
            let health = if force_fresh {
                component.health_fresh()
            } else {
                component.health()
            };
            if matches!(health, ComponentHealth::Lost | ComponentHealth::Recovering) {
                let next = component.attempt_post_ready_recovery(shutting_down);
                if next != PostReadyRecoveryResult::NoInstall {
                    result = next;
                }
            }
        }
        result
    }

    /// The supervisor's terminal no-answer transition, before it releases the
    /// runtime. Only a component with an exhausted probe budget runs its hook.
    pub fn hook_post_ready_indeterminate(&self) {
        let mut dispatched = 0usize;
        for component in &self.components {
            if component.health() == ComponentHealth::Indeterminate {
                component.on_post_ready_indeterminate();
                dispatched = dispatched.saturating_add(1);
            }
        }
        let class = match dispatched {
            0 => "no_provider_reached",
            1 => "one_provider_dispatched",
            _ => "multiple_providers_dispatched",
        };
        // SAFETY: stderr is the operator channel for the one terminal dispatch
        // line of this transition. Its cardinality class is the evidence that
        // exactly the components with an exhausted probe budget were reached.
        eprintln!("castle-wall-daemon: terminal_dispatch={class}");
    }

    /// The tagged `safety_net` state to stamp on an audit row or a signed report.
    ///
    /// INVARIANT: a row emitted while an install has FAILED must not attest to a
    /// protection that is not in place, which is why this returns the component's own
    /// recorded outcome rather than deriving one from the fact that a loss occurred.
    /// `NotAttempted` when no component has attempted an install.
    pub fn safety_net_audit_state(&self) -> crate::nftables::SafetyNetAuditState {
        self.components
            .iter()
            .find_map(|component| component.safety_net_audit_state())
            .unwrap_or(crate::nftables::SafetyNetAuditState::NotAttempted)
    }

    /// Convenience: true iff [`status`](Self::status) is `KernelRuntimeReady`.
    /// This is a kernel-runtime readiness predicate, NOT an enforcement one —
    /// see the module docs and [`DaemonHandle::is_enforcing`].
    pub fn is_kernel_runtime_ready(&self) -> bool {
        matches!(self.status(), EnforcementStatus::KernelRuntimeReady)
    }

    /// Release every owned component in reverse acquisition order, joining owned
    /// threads. Idempotent: a second call is a no-op. After this returns,
    /// `is_enforcing()` is false and no resource-owning thread the runtime
    /// spawned is still running.
    pub fn shutdown(&mut self) {
        if self.shutdown_done {
            return;
        }
        release_reverse(&mut self.components);
        self.shutdown_done = true;
    }

    /// The kinds still owned, in acquisition order. Inspection helper for
    /// operators/tests; empty after `shutdown`.
    pub fn owned_kinds(&self) -> Vec<ComponentKind> {
        self.components.iter().map(|c| c.kind()).collect()
    }
}

impl std::fmt::Debug for EnforcementRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait-object components are not Debug; summarize by owned kinds and
        // lifecycle so the runtime is inspectable without exposing internals.
        f.debug_struct("EnforcementRuntime")
            .field("owned_kinds", &self.owned_kinds())
            .field("shutdown_done", &self.shutdown_done)
            .finish()
    }
}

impl Drop for EnforcementRuntime {
    fn drop(&mut self) {
        // Last line of defense for the "no detached thread outlives the owner"
        // invariant: even if the caller never called shutdown(), dropping the
        // runtime joins every owned thread before the components are freed.
        self.shutdown();
    }
}

/// Release the acquired components in REVERSE acquisition order, draining the
/// vector. Last acquired is released first, which is the teardown contract:
/// stop the NFQUEUE verdict thread before removing the nftables table it feeds,
/// never the reverse.
///
/// Each component is contained by TWO nested `catch_unwind`s: one around the
/// explicit `release()` call, and a SECOND around the explicit `drop` of the
/// moved Box, because dropping the component can RE-ENTER `release()` through
/// its `Drop` and an adversarial impl can re-panic there. This sweep runs from
/// three places — an explicit `shutdown()`, the runtime's `Drop` (which may
/// itself be executing during an unwind), and `start`'s fail-before path — so
/// one component that panics during teardown (from either `release()` or its
/// destructor) must not: (a) abort the process by unwinding out of a `Drop`,
/// (b) skip the remaining predecessors and leak or leave them active, or (c) on
/// the `start` path, mask the original startup failure that is about to be
/// returned. A panicking release is therefore treated as a degraded teardown:
/// the panic is caught and swallowed and the sweep continues releasing every
/// predecessor in order. [`AcquiredComponent`] still contracts `release()` as
/// panic-free and idempotent; this containment is defense-in-depth against a
/// buggy impl, never license to panic.
fn release_reverse(components: &mut Vec<Box<dyn AcquiredComponent>>) {
    while let Some(mut component) = components.pop() {
        // Containment #1: the explicit release() call. Its panic cannot abort
        // the sweep (which may run from a Drop during an unwind) or mask a
        // startup error. AssertUnwindSafe: the &mut borrow is not UnwindSafe,
        // but nothing of the component is observed after a panic — it is dropped
        // immediately below and release() is idempotent, so no torn state
        // crosses the boundary. The caught payload is intentionally discarded.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| component.release()));
        // Containment #2: dropping the moved Box can RE-ENTER release() via the
        // component's Drop. A well-behaved impl marks itself released before
        // panicking, so its Drop-invoked release is a no-op; but an ADVERSARIAL
        // (or buggy) impl whose Drop retries and re-panics would otherwise
        // escape containment #1's catch and, on a Drop-driven sweep during an
        // unwind, abort the whole process by double-panicking. Contain the
        // explicit drop of the Box too so destructor re-entry stays inside the
        // sweep. mem::forget is deliberately NOT used: a leaked adversarial fake
        // is a strictly smaller, contained cost than an unsound skipped drop of
        // a real component that owns a thread or kernel handle, and the nested
        // catch already makes a re-panicking Drop safe.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(component)));
    }
}

/// Kernel-runtime readiness for an optional runtime handle. A `None` runtime is
/// the path taken when no runtime could be started and reports
/// `NotReady { NoRuntime }`; a present runtime delegates to its live
/// [`status`](EnforcementRuntime::status). This is the single mapping from "do
/// we hold a runtime" to a status, so the `NoRuntime` reason is emitted here
/// rather than being dead vocabulary.
pub fn enforcement_status(enforcement: Option<&EnforcementRuntime>) -> EnforcementStatus {
    match enforcement {
        None => EnforcementStatus::NotReady {
            reason: NotReadyReason::NoRuntime,
        },
        Some(runtime) => runtime.status(),
    }
}

/// Derive the operator-visible daemon state from the current lifecycle state
/// and the (optional) enforcement runtime.
///
/// `KernelRuntimeReady` is returned ONLY when a runtime is present and every
/// required component reports ready. A `Stopping` or `Degraded` lifecycle takes
/// precedence and is never overridden; a missing runtime, a lost component, or a
/// shutting-down runtime reads as `ControlPlaneOnly`. This is the structural
/// guarantee that authenticated IPC and process liveness (which set
/// `ControlPlaneOnly`) can never be presented as a ready kernel runtime.
///
/// `DaemonRuntimeState::Enforcing` is DELIBERATELY never produced here: it is
/// reserved for the later slice that wraps a real agent and gates its cgroup.
/// Kernel-runtime readiness is a strictly weaker claim than enforcement (module
/// docs), so a ready runtime derives `KernelRuntimeReady`, never `Enforcing`,
/// and `DaemonHandle::is_enforcing()` stays false throughout this slice.
pub fn derive_daemon_state(
    lifecycle: DaemonRuntimeState,
    enforcement: Option<&EnforcementRuntime>,
) -> DaemonRuntimeState {
    match lifecycle {
        // A poisoned-lock caller passes Degraded here; Stopping is set on
        // teardown. Neither is ever promoted.
        DaemonRuntimeState::Stopping | DaemonRuntimeState::Degraded => lifecycle,
        DaemonRuntimeState::ControlPlaneOnly
        | DaemonRuntimeState::KernelRuntimeReady
        | DaemonRuntimeState::Enforcing => match enforcement_status(enforcement) {
            // A fully-ready runtime is KERNEL-RUNTIME-READY, not Enforcing:
            // no agent is wrapped, so nothing is being enforced yet.
            EnforcementStatus::KernelRuntimeReady => DaemonRuntimeState::KernelRuntimeReady,
            // No runtime, or a runtime that is not fully ready, is control
            // plane only.
            EnforcementStatus::NotReady { .. } => DaemonRuntimeState::ControlPlaneOnly,
        },
    }
}

// The production Linux enforcement plan (the concrete providers that acquire the
// real nftables table under the host ownership lock, the bound NFQUEUE + its
// verdict thread, and the manifest watcher thread) lives in
// [`crate::runtime_providers`]. It is kept out of this module so the lifecycle
// CONTRACT here (ordered acquisition, readiness gating, reverse-order teardown)
// stays platform-neutral and testable with fakes, while the kernel-touching
// acquisition bodies are `cfg(target_os = "linux")`-gated over there. `boot()`
// drives that plan through [`EnforcementRuntime::start`].

/// Test-only helpers shared with the daemon integration tests. Gated to
/// `cfg(test)` so no fake ever compiles into the shipped daemon.
#[cfg(test)]
mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A component that is always ready and owns nothing to release.
    struct AlwaysReady(ComponentKind);
    impl AcquiredComponent for AlwaysReady {
        fn kind(&self) -> ComponentKind {
            self.0
        }
        fn is_ready(&self) -> bool {
            true
        }
        fn release(&mut self) {}
    }

    /// A component whose readiness is a shared, flippable atomic. Lets a
    /// supervision test simulate a component dying AFTER the runtime came up
    /// ready (verdict thread death, table clobbered, watcher exit) without a real
    /// kernel, by flipping the returned handle to `false`.
    struct Toggleable {
        kind: ComponentKind,
        ready: Arc<AtomicBool>,
    }
    impl AcquiredComponent for Toggleable {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }
        fn release(&mut self) {}
    }

    /// A component whose three-valued health is scriptable, recording which startup
    /// responder and which recovery attempt it received. This is what makes the
    /// reachability of each entry branch assertable without a kernel.
    struct ScriptedHealth {
        kind: ComponentKind,
        health: Arc<std::sync::Mutex<ComponentHealth>>,
        startup_lost_calls: Arc<AtomicUsize>,
        startup_indeterminate_calls: Arc<AtomicUsize>,
        post_ready_indeterminate_calls: Arc<AtomicUsize>,
        recovery_calls: Arc<AtomicUsize>,
        recovery_saw_shutdown: Arc<AtomicBool>,
    }
    impl AcquiredComponent for ScriptedHealth {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            matches!(self.health(), ComponentHealth::Ready)
        }
        fn health(&self) -> ComponentHealth {
            *self.health.lock().expect("scripted health")
        }
        fn on_startup_lost(&self) {
            self.startup_lost_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn on_startup_indeterminate(&self) {
            self.startup_indeterminate_calls
                .fetch_add(1, Ordering::SeqCst);
        }
        fn on_post_ready_indeterminate(&self) {
            self.post_ready_indeterminate_calls
                .fetch_add(1, Ordering::SeqCst);
        }
        fn attempt_post_ready_recovery(
            &self,
            shutting_down: &dyn Fn() -> bool,
        ) -> PostReadyRecoveryResult {
            // C2a1(a) site 6 (LINUX-STOP-LOSS-RACE-01): a stop never leaves a proven
            // loss without its one net attempt, so the FIRST call installs
            // regardless of `shutting_down`; only a later call under shutdown
            // (a retrying re-probe) returns NoInstall.
            let shutting_down = shutting_down();
            let call_number = self.recovery_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if shutting_down {
                self.recovery_saw_shutdown.store(true, Ordering::SeqCst);
            }
            if shutting_down && call_number > 1 {
                PostReadyRecoveryResult::NoInstall
            } else {
                PostReadyRecoveryResult::InstallSucceeded
            }
        }
        fn release(&mut self) {}
    }

    struct ScriptedProvider {
        kind: ComponentKind,
        health: Arc<std::sync::Mutex<ComponentHealth>>,
        startup_lost_calls: Arc<AtomicUsize>,
        startup_indeterminate_calls: Arc<AtomicUsize>,
        post_ready_indeterminate_calls: Arc<AtomicUsize>,
        recovery_calls: Arc<AtomicUsize>,
        recovery_saw_shutdown: Arc<AtomicBool>,
    }
    impl ComponentProvider for ScriptedProvider {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            Ok(Box::new(ScriptedHealth {
                kind: self.kind,
                health: self.health,
                startup_lost_calls: self.startup_lost_calls,
                startup_indeterminate_calls: self.startup_indeterminate_calls,
                post_ready_indeterminate_calls: self.post_ready_indeterminate_calls,
                recovery_calls: self.recovery_calls,
                recovery_saw_shutdown: self.recovery_saw_shutdown,
            }))
        }
    }

    /// One counter set, shared with the component the provider yields.
    #[derive(Clone, Default)]
    struct ResponderCounters {
        startup_lost: Arc<AtomicUsize>,
        startup_indeterminate: Arc<AtomicUsize>,
        post_ready_indeterminate: Arc<AtomicUsize>,
        recovery: Arc<AtomicUsize>,
        recovery_saw_shutdown: Arc<AtomicBool>,
    }

    fn scripted_plan(
        nft_health: ComponentHealth,
        counters: &ResponderCounters,
    ) -> Vec<Box<dyn ComponentProvider>> {
        vec![
            Box::new(ScriptedProvider {
                kind: ComponentKind::NftablesTable,
                health: Arc::new(std::sync::Mutex::new(nft_health)),
                startup_lost_calls: Arc::clone(&counters.startup_lost),
                startup_indeterminate_calls: Arc::clone(&counters.startup_indeterminate),
                post_ready_indeterminate_calls: Arc::clone(&counters.post_ready_indeterminate),
                recovery_calls: Arc::clone(&counters.recovery),
                recovery_saw_shutdown: Arc::clone(&counters.recovery_saw_shutdown),
            }),
            Box::new(AlwaysReadyProvider(ComponentKind::Nfqueue)),
            Box::new(AlwaysReadyProvider(ComponentKind::ManifestWatcher)),
        ]
    }

    /// ITEM 10, consumer one: the runtime surface that both the WAL row and the signed
    /// report read. A failure-to-retry transition must be visible in it, so a row
    /// emitted after a failed install never claims an installed protection.
    #[test]
    fn the_safety_net_audit_state_follows_the_install_transition() {
        use crate::nftables::SafetyNetAuditState;

        struct StateHolder {
            kind: ComponentKind,
            state: Arc<std::sync::Mutex<Option<SafetyNetAuditState>>>,
        }
        impl AcquiredComponent for StateHolder {
            fn kind(&self) -> ComponentKind {
                self.kind
            }
            fn is_ready(&self) -> bool {
                true
            }
            fn safety_net_audit_state(&self) -> Option<SafetyNetAuditState> {
                self.state.lock().expect("state").clone()
            }
            fn release(&mut self) {}
        }
        struct HolderProvider {
            kind: ComponentKind,
            state: Arc<std::sync::Mutex<Option<SafetyNetAuditState>>>,
        }
        impl ComponentProvider for HolderProvider {
            fn kind(&self) -> ComponentKind {
                self.kind
            }
            fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
                Ok(Box::new(StateHolder {
                    kind: self.kind,
                    state: self.state,
                }))
            }
        }

        let state = Arc::new(std::sync::Mutex::new(None));
        let runtime = EnforcementRuntime::start(vec![
            Box::new(HolderProvider {
                kind: ComponentKind::NftablesTable,
                state: Arc::clone(&state),
            }),
            Box::new(AlwaysReadyProvider(ComponentKind::Nfqueue)),
            Box::new(AlwaysReadyProvider(ComponentKind::ManifestWatcher)),
        ])
        .expect("starts ready");

        // NOTHING ATTEMPTED yet: the surface says so rather than implying an install.
        assert_eq!(
            runtime.safety_net_audit_state(),
            SafetyNetAuditState::NotAttempted
        );

        // An install FAILED: the surface reports the failure, with the scope attempted.
        *state.lock().unwrap() = Some(SafetyNetAuditState::InstallFailed {
            attempted_scope: "v2-confined-identity".to_string(),
            error: "the safety net install failed and will be retried".to_string(),
        });
        let failed = runtime.safety_net_audit_state();
        assert_eq!(failed.tag(), "install_failed");
        assert_eq!(failed.to_json()["state"], "install_failed");
        assert_eq!(failed.to_json()["attempted_scope"], "v2-confined-identity");

        // THE RETRY takes: the surface flips to the installed predicate, with its
        // coverage limit stated on the same row.
        let set = crate::safety_net_uid::ConfinedUidSet::from_validated(vec![
            crate::safety_net_uid::validate_safety_net_uid(
                60123,
                crate::safety_net_uid::HostOverflowUid::from_value(65534),
            )
            .unwrap(),
        ])
        .unwrap();
        *state.lock().unwrap() = Some(SafetyNetAuditState::installed(
            &crate::nftables::SafetyNetScope::Identity(set),
            &crate::nftables::SafetyNetReason::Identity,
            crate::nftables::SafetyNetSources {
                journal: true,
                manifest: true,
                live_table: false,
            },
        ));
        let json = runtime.safety_net_audit_state().to_json();
        assert_eq!(json["state"], "installed");
        assert_eq!(json["shape"], "v2-confined-identity");
        assert_eq!(json["reason"], "identity");
        assert_eq!(json["deny_set_size"], 1);
        assert_eq!(json["deny_set_max"], crate::nftables::DENY_SET_MAX);
        assert_eq!(json["denied_uids"], serde_json::json!([60123]));
        assert_eq!(json["rules"].as_array().unwrap().len(), 3);
        assert_eq!(json["sources"]["journal"], true);
        assert_eq!(json["kernel_nd_accepted"].as_array().unwrap().len(), 3);
        assert_eq!(json["unattestable_packets"], "drop-except-kernel-nd");
        assert!(json["coverage"]
            .as_str()
            .unwrap()
            .contains("packet sockets"));
    }

    #[test]
    fn a_startup_lost_reading_runs_the_loss_responder_then_unwinds_with_typed_evidence() {
        let counters = ResponderCounters::default();
        let err = EnforcementRuntime::start(scripted_plan(ComponentHealth::Lost, &counters))
            .expect_err("a component that is not ready must not yield a runtime");
        // The responder ran exactly once, BEFORE the unwind, and the indeterminate
        // responder did not run at all.
        assert_eq!(counters.startup_lost.load(Ordering::SeqCst), 1);
        assert_eq!(counters.startup_indeterminate.load(Ordering::SeqCst), 0);
        // The error carries the TYPED evidence, so a caller can tell a completed
        // negative proof from a no-answer without parsing the message.
        match err {
            EnforcementStartError::Component {
                failed, evidence, ..
            } => {
                assert_eq!(failed, ComponentKind::NftablesTable);
                assert_eq!(
                    evidence,
                    Some(StartupReadiness::Lost {
                        kind: ComponentKind::NftablesTable
                    })
                );
            }
            other => panic!("expected a component failure, got {other:?}"),
        }
    }

    #[test]
    fn a_startup_indeterminate_reading_runs_only_the_indeterminate_responder() {
        let counters = ResponderCounters::default();
        let err =
            EnforcementRuntime::start(scripted_plan(ComponentHealth::ProbeUnavailable, &counters))
                .expect_err("an indeterminate reading withholds readiness");
        // Nothing may be installed on the absence of evidence, so the LOSS responder
        // must not run here.
        assert_eq!(counters.startup_lost.load(Ordering::SeqCst), 0);
        assert_eq!(counters.startup_indeterminate.load(Ordering::SeqCst), 1);
        match err {
            EnforcementStartError::Component { evidence, .. } => assert_eq!(
                evidence,
                Some(StartupReadiness::Indeterminate {
                    kind: ComponentKind::NftablesTable
                })
            ),
            other => panic!("expected a component failure, got {other:?}"),
        }
    }

    #[test]
    fn a_non_nft_component_loss_runs_no_responder_and_installs_nothing() {
        // Every component but the nftables table leaves the kernel egress gate intact
        // when it fails, so its loss keeps the existing path: unwind, refuse, and let the
        // preserved table be adopted on restart. Installing a net for it would replace a
        // healthy table, and firing the sweep hook would act on a loss that is not about
        // the table at all.
        let counters = ResponderCounters::default();
        let lost_health = Arc::new(std::sync::Mutex::new(ComponentHealth::Lost));
        let err = EnforcementRuntime::start(vec![
            Box::new(AlwaysReadyProvider(ComponentKind::NftablesTable)),
            Box::new(AlwaysReadyProvider(ComponentKind::Nfqueue)),
            Box::new(ScriptedProvider {
                kind: ComponentKind::ManifestWatcher,
                health: Arc::clone(&lost_health),
                startup_lost_calls: Arc::clone(&counters.startup_lost),
                startup_indeterminate_calls: Arc::clone(&counters.startup_indeterminate),
                post_ready_indeterminate_calls: Arc::clone(&counters.post_ready_indeterminate),
                recovery_calls: Arc::clone(&counters.recovery),
                recovery_saw_shutdown: Arc::clone(&counters.recovery_saw_shutdown),
            }),
        ])
        .expect_err("a lost component must not yield a runtime");

        // The failure is attributed to the manifest watcher, and its own responder is the
        // DEFAULT no-op, so nothing was installed and no hook fired.
        match err {
            EnforcementStartError::Component {
                failed, evidence, ..
            } => {
                assert_eq!(failed, ComponentKind::ManifestWatcher);
                assert_eq!(
                    evidence,
                    Some(StartupReadiness::Lost {
                        kind: ComponentKind::ManifestWatcher
                    })
                );
                // The reading is not the nftables component's, so it carries no
                // safety-net action.
                assert_eq!(
                    evidence.and_then(|e| e.nftables_kind()),
                    None,
                    "only the nftables component's reading carries a net action"
                );
            }
            other => panic!("expected a component failure, got {other:?}"),
        }
        // The scripted component counted its own responder calls; the DEFAULT trait
        // methods are what ran, so these stay zero.
        assert_eq!(counters.startup_lost.load(Ordering::SeqCst), 1);
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_ready_startup_runs_no_responder_at_all() {
        let counters = ResponderCounters::default();
        let runtime = EnforcementRuntime::start(scripted_plan(ComponentHealth::Ready, &counters))
            .expect("a fully ready plan yields a runtime");
        assert_eq!(counters.startup_lost.load(Ordering::SeqCst), 0);
        assert_eq!(counters.startup_indeterminate.load(Ordering::SeqCst), 0);
        assert_eq!(
            runtime.status(),
            EnforcementStatus::KernelRuntimeReady,
            "a ready plan reports readiness"
        );
    }

    #[test]
    fn post_ready_recovery_is_driven_for_a_proven_loss_and_observes_the_shutdown_flag() {
        let counters = ResponderCounters::default();
        let health = Arc::new(std::sync::Mutex::new(ComponentHealth::Ready));
        let runtime = EnforcementRuntime::start(vec![
            Box::new(ScriptedProvider {
                kind: ComponentKind::NftablesTable,
                health: Arc::clone(&health),
                startup_lost_calls: Arc::clone(&counters.startup_lost),
                startup_indeterminate_calls: Arc::clone(&counters.startup_indeterminate),
                post_ready_indeterminate_calls: Arc::clone(&counters.post_ready_indeterminate),
                recovery_calls: Arc::clone(&counters.recovery),
                recovery_saw_shutdown: Arc::clone(&counters.recovery_saw_shutdown),
            }),
            Box::new(AlwaysReadyProvider(ComponentKind::Nfqueue)),
            Box::new(AlwaysReadyProvider(ComponentKind::ManifestWatcher)),
        ])
        .expect("starts ready");

        // READY: no recovery is driven, because there is nothing to re-arm.
        assert_eq!(
            runtime.attempt_post_ready_recovery(&|| false, false),
            PostReadyRecoveryResult::NoInstall
        );
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 0);

        // INDETERMINATE: still no recovery. This reading is the absence of evidence,
        // so no kernel action may be taken from it.
        *health.lock().unwrap() = ComponentHealth::ProbeUnavailable;
        assert_eq!(
            runtime.attempt_post_ready_recovery(&|| false, false),
            PostReadyRecoveryResult::NoInstall
        );
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 0);
        runtime.hook_post_ready_indeterminate();
        assert_eq!(counters.post_ready_indeterminate.load(Ordering::SeqCst), 0);

        // The terminal no-answer outcome reaches the hook only when the
        // supervisor explicitly takes its ordered hook-before-exit arm.
        *health.lock().unwrap() = ComponentHealth::Indeterminate;
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::HealthProbeIndeterminate,
            }
        );
        runtime.hook_post_ready_indeterminate();
        assert_eq!(counters.post_ready_indeterminate.load(Ordering::SeqCst), 1);
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 0);

        // LOST, a completed negative proof, encountered WHILE ALREADY SHUTTING
        // DOWN. C2a1(a) (LINUX-STOP-LOSS-RACE-01, inverted contract): a stop
        // never leaves a proven loss without its one net attempt, so the FIRST
        // entry installs even under shutdown. Pre-fix this call returned
        // NoInstall; this assertion is the fail-before witness.
        *health.lock().unwrap() = ComponentHealth::Lost;
        assert_eq!(
            runtime.attempt_post_ready_recovery(&|| true, false),
            PostReadyRecoveryResult::InstallSucceeded,
            "a stop must not leave a proven loss without its one net attempt"
        );
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 1);
        assert!(counters.recovery_saw_shutdown.load(Ordering::SeqCst));

        // A SECOND poll under shutdown, with the loss still outstanding, is the
        // gated retrying re-probe path: no second install, no readiness restore.
        assert_eq!(
            runtime.attempt_post_ready_recovery(&|| true, false),
            PostReadyRecoveryResult::NoInstall
        );
        assert_eq!(counters.recovery.load(Ordering::SeqCst), 2);

        // RECOVERING: an attempt is outstanding, and the controller IS re-entered. This
        // is what makes a failed install retry: the component keeps publishing
        // `Recovering`, and every supervisor tick brings it back here until the
        // resource is repaired or the unit is stopped.
        let before = counters.recovery.load(Ordering::SeqCst);
        *health.lock().unwrap() = ComponentHealth::Recovering;
        assert_eq!(
            runtime.attempt_post_ready_recovery(&|| false, false),
            PostReadyRecoveryResult::InstallSucceeded
        );
        assert_eq!(
            counters.recovery.load(Ordering::SeqCst),
            before + 1,
            "a recovering component must be re-driven so a failed install is retried"
        );

        // And `Recovering` withholds readiness without reporting the loss a
        // supervisor exits on.
        match runtime.status() {
            EnforcementStatus::NotReady {
                reason: NotReadyReason::SafetyNetRecovering(kind),
            } => assert_eq!(kind, ComponentKind::NftablesTable),
            other => panic!("expected the recovering reason, got {other:?}"),
        }

        // A later exhausted no-answer overrides Recovering and reaches the hook
        // consumer. The transient no-answer above never did.
        *health.lock().unwrap() = ComponentHealth::Indeterminate;
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::HealthProbeIndeterminate,
            }
        );
        runtime.hook_post_ready_indeterminate();
        assert_eq!(counters.post_ready_indeterminate.load(Ordering::SeqCst), 2);
    }

    struct AlwaysReadyProvider(ComponentKind);
    impl ComponentProvider for AlwaysReadyProvider {
        fn kind(&self) -> ComponentKind {
            self.0
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            Ok(Box::new(AlwaysReady(self.0)))
        }
    }

    /// A component that runs a one-shot probe closure the first time it is
    /// released. Lets a cross-subsystem test (the daemon drop-order test)
    /// observe daemon state at the instant enforcement tears down.
    struct ProbeOnRelease {
        kind: ComponentKind,
        probe: Option<Box<dyn FnOnce() + Send>>,
    }
    impl AcquiredComponent for ProbeOnRelease {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            true
        }
        fn release(&mut self) {
            // Idempotent: the probe is taken on first release; later calls
            // (including the runtime's Drop after an explicit shutdown) no-op.
            if let Some(probe) = self.probe.take() {
                probe();
            }
        }
    }

    impl EnforcementRuntime {
        /// Build a runtime owning always-ready fakes of every required
        /// component. Lets `daemon.rs` tests drive the `KernelRuntimeReady`
        /// derivation end-to-end without a real kernel.
        pub(crate) fn all_ready_for_test() -> Self {
            let providers: Vec<Box<dyn ComponentProvider>> = ComponentKind::REQUIRED_IN_ORDER
                .into_iter()
                .map(|k| Box::new(AlwaysReadyProvider(k)) as Box<dyn ComponentProvider>)
                .collect();
            EnforcementRuntime::start(providers).expect("all fakes ready")
        }

        /// Build an all-ready runtime whose FIRST-released component (the
        /// last-acquired `ManifestWatcher`) runs `probe` when released. Because
        /// [`shutdown`](Self::shutdown) releases in reverse acquisition order,
        /// the probe fires at the very start of enforcement teardown, so a
        /// daemon test can prove enforcement tears down before the IPC control
        /// surface. The owned set stays exactly `REQUIRED_IN_ORDER`, in order.
        pub(crate) fn all_ready_with_release_probe(probe: Box<dyn FnOnce() + Send>) -> Self {
            let mut components: Vec<Box<dyn AcquiredComponent>> = ComponentKind::REQUIRED_IN_ORDER
                .into_iter()
                .map(|k| Box::new(AlwaysReady(k)) as Box<dyn AcquiredComponent>)
                .collect();
            let last = *ComponentKind::REQUIRED_IN_ORDER
                .last()
                .expect("REQUIRED_IN_ORDER is non-empty");
            *components
                .last_mut()
                .expect("REQUIRED_IN_ORDER is non-empty") = Box::new(ProbeOnRelease {
                kind: last,
                probe: Some(probe),
            });
            Self {
                components,
                shutdown_done: false,
            }
        }

        /// Build an all-ready runtime in which `target`'s readiness is a shared
        /// flippable atomic (all other required components are always-ready).
        /// Returns the runtime plus the toggle handle: flipping it to `false`
        /// simulates that one component dying after the runtime came up ready, so
        /// a supervision test can prove the daemon detects a verdict/table/watcher
        /// death and never keeps reporting a false active service. The owned set
        /// stays exactly `REQUIRED_IN_ORDER`, in order.
        pub(crate) fn all_ready_with_toggleable(target: ComponentKind) -> (Self, Arc<AtomicBool>) {
            let toggle = Arc::new(AtomicBool::new(true));
            let components: Vec<Box<dyn AcquiredComponent>> = ComponentKind::REQUIRED_IN_ORDER
                .into_iter()
                .map(|k| {
                    if k == target {
                        Box::new(Toggleable {
                            kind: k,
                            ready: Arc::clone(&toggle),
                        }) as Box<dyn AcquiredComponent>
                    } else {
                        Box::new(AlwaysReady(k)) as Box<dyn AcquiredComponent>
                    }
                })
                .collect();
            (
                Self {
                    components,
                    shutdown_done: false,
                },
                toggle,
            )
        }

        /// A ready runtime whose nft probe can later exhaust its no-answer
        /// budget, with a counter for the supervisor's ordered hook.
        pub(crate) fn all_ready_with_indeterminate_probe() -> (
            Self,
            Arc<std::sync::Mutex<ComponentHealth>>,
            Arc<AtomicUsize>,
        ) {
            let health = Arc::new(std::sync::Mutex::new(ComponentHealth::Ready));
            let hook_calls = Arc::new(AtomicUsize::new(0));
            let components: Vec<Box<dyn AcquiredComponent>> = ComponentKind::REQUIRED_IN_ORDER
                .into_iter()
                .map(|kind| {
                    if kind == ComponentKind::NftablesTable {
                        Box::new(ScriptedHealth {
                            kind,
                            health: Arc::clone(&health),
                            startup_lost_calls: Arc::new(AtomicUsize::new(0)),
                            startup_indeterminate_calls: Arc::new(AtomicUsize::new(0)),
                            post_ready_indeterminate_calls: Arc::clone(&hook_calls),
                            recovery_calls: Arc::new(AtomicUsize::new(0)),
                            recovery_saw_shutdown: Arc::new(AtomicBool::new(false)),
                        }) as Box<dyn AcquiredComponent>
                    } else {
                        Box::new(AlwaysReady(kind)) as Box<dyn AcquiredComponent>
                    }
                })
                .collect();
            (
                Self {
                    components,
                    shutdown_done: false,
                },
                health,
                hook_calls,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    /// Ordered log of `release()` calls shared across a test's fake components,
    /// so a test can assert reverse-order teardown.
    #[derive(Clone, Default)]
    struct ReleaseLog(Arc<Mutex<Vec<ComponentKind>>>);

    impl ReleaseLog {
        fn record(&self, kind: ComponentKind) {
            self.0.lock().unwrap().push(kind);
        }
        fn order(&self) -> Vec<ComponentKind> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Deterministic fake component. Readiness is a shared atomic so a test can
    /// flip it after acquisition to simulate a lost resource. Optionally owns a
    /// real thread so the join-before-release contract can be asserted.
    struct FakeComponent {
        kind: ComponentKind,
        ready: Arc<AtomicBool>,
        released: bool,
        release_log: Option<ReleaseLog>,
        stop: Option<Arc<AtomicBool>>,
        thread: Option<JoinHandle<()>>,
    }

    impl AcquiredComponent for FakeComponent {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            !self.released && self.ready.load(Ordering::SeqCst)
        }
        fn release(&mut self) {
            if self.released {
                return; // idempotent
            }
            // Join the owned thread BEFORE marking released, mirroring the real
            // contract: no detached resource-owning thread outlives release.
            if let Some(stop) = &self.stop {
                stop.store(true, Ordering::SeqCst);
            }
            if let Some(handle) = self.thread.take() {
                // release() runs from Drop; it must be panic-free, so a failed
                // join is swallowed rather than unwrapped (a panic here during
                // an unwinding Drop would abort the process).
                let _ = handle.join();
            }
            self.released = true;
            if let Some(log) = &self.release_log {
                log.record(self.kind);
            }
        }
    }

    impl Drop for FakeComponent {
        fn drop(&mut self) {
            self.release();
        }
    }

    enum FakeBehavior {
        /// Acquire succeeds and the component is ready.
        Ready,
        /// Acquire itself fails with the given error.
        FailAcquire(EnforcementError),
        /// Acquire succeeds but the component reports not-ready immediately.
        NotReadyAfterAcquire,
        /// Acquire succeeds, ready, and the component owns a live thread that
        /// must be joined on release.
        ReadyWithThread,
        /// Acquire succeeds and returns a READY component whose `kind()` is the
        /// carried value rather than the provider's advertised kind — exercises
        /// the delivered-kind check.
        DeliverWrongKind(ComponentKind),
    }

    struct FakeProvider {
        kind: ComponentKind,
        behavior: FakeBehavior,
        ready: Arc<AtomicBool>,
        release_log: Option<ReleaseLog>,
        thread_alive: Option<Arc<AtomicBool>>,
        /// Bumped once at the top of `acquire()`. A test asserts this stays 0
        /// to prove a rejected plan acquired nothing.
        acquire_count: Option<Arc<AtomicUsize>>,
        /// When set, `acquire()` clears this readiness handle. A test wires it
        /// to an EARLIER component's handle to simulate a later kernel step
        /// clobbering it, which only the whole-set re-check can catch.
        clear_on_acquire: Option<Arc<AtomicBool>>,
    }

    impl FakeProvider {
        fn ready(kind: ComponentKind) -> Self {
            Self {
                kind,
                behavior: FakeBehavior::Ready,
                ready: Arc::new(AtomicBool::new(true)),
                release_log: None,
                thread_alive: None,
                acquire_count: None,
                clear_on_acquire: None,
            }
        }
        fn with_log(mut self, log: ReleaseLog) -> Self {
            self.release_log = Some(log);
            self
        }
        /// Share an acquisition counter so a test can prove `acquire()` was
        /// never reached (a rejected plan must touch no provider).
        fn counting_acquires(mut self, counter: &Arc<AtomicUsize>) -> Self {
            self.acquire_count = Some(Arc::clone(counter));
            self
        }
        /// Wire this provider's `acquire()` to clear `handle` — a test points it
        /// at an earlier component's readiness handle to prove the whole-set
        /// re-check unwinds when a later acquire invalidates an earlier member.
        fn clearing_on_acquire(mut self, handle: &Arc<AtomicBool>) -> Self {
            self.clear_on_acquire = Some(Arc::clone(handle));
            self
        }
        fn failing(kind: ComponentKind, err: EnforcementError) -> Self {
            Self {
                kind,
                behavior: FakeBehavior::FailAcquire(err),
                ready: Arc::new(AtomicBool::new(false)),
                release_log: None,
                thread_alive: None,
                acquire_count: None,
                clear_on_acquire: None,
            }
        }
        fn not_ready(kind: ComponentKind) -> Self {
            Self {
                kind,
                behavior: FakeBehavior::NotReadyAfterAcquire,
                ready: Arc::new(AtomicBool::new(false)),
                release_log: None,
                thread_alive: None,
                acquire_count: None,
                clear_on_acquire: None,
            }
        }
        /// Advertises `advertised` (so the plan gate passes) but `acquire()`
        /// returns a ready component whose `kind()` is `delivered`.
        fn wrong_kind(advertised: ComponentKind, delivered: ComponentKind) -> Self {
            Self {
                kind: advertised,
                behavior: FakeBehavior::DeliverWrongKind(delivered),
                ready: Arc::new(AtomicBool::new(true)),
                release_log: None,
                thread_alive: None,
                acquire_count: None,
                clear_on_acquire: None,
            }
        }
        fn with_thread(kind: ComponentKind) -> Self {
            Self {
                kind,
                behavior: FakeBehavior::ReadyWithThread,
                ready: Arc::new(AtomicBool::new(true)),
                release_log: None,
                thread_alive: Some(Arc::new(AtomicBool::new(false))),
                acquire_count: None,
                clear_on_acquire: None,
            }
        }
        /// Shared readiness handle; a test flips it to simulate resource loss.
        fn ready_handle(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.ready)
        }
        /// Shared liveness flag of the owned thread (only for `with_thread`).
        fn thread_alive_handle(&self) -> Arc<AtomicBool> {
            Arc::clone(self.thread_alive.as_ref().expect("with_thread provider"))
        }
    }

    impl ComponentProvider for FakeProvider {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            let this = *self;
            // Record that acquisition was reached; a plan rejected for shape
            // never gets here, which is exactly what the mismatch tests assert.
            if let Some(counter) = &this.acquire_count {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            // Simulate a later step clobbering an earlier component's resource.
            if let Some(clear) = &this.clear_on_acquire {
                clear.store(false, Ordering::SeqCst);
            }
            match this.behavior {
                FakeBehavior::FailAcquire(err) => Err(err),
                FakeBehavior::Ready => Ok(Box::new(FakeComponent {
                    kind: this.kind,
                    ready: this.ready,
                    released: false,
                    release_log: this.release_log,
                    stop: None,
                    thread: None,
                })),
                FakeBehavior::DeliverWrongKind(delivered) => Ok(Box::new(FakeComponent {
                    // Deliberately NOT this.kind: the component's kind differs
                    // from the advertised kind so the delivered-kind check fires.
                    kind: delivered,
                    ready: this.ready,
                    released: false,
                    release_log: this.release_log,
                    stop: None,
                    thread: None,
                })),
                FakeBehavior::NotReadyAfterAcquire => {
                    this.ready.store(false, Ordering::SeqCst);
                    Ok(Box::new(FakeComponent {
                        kind: this.kind,
                        ready: this.ready,
                        released: false,
                        release_log: this.release_log,
                        stop: None,
                        thread: None,
                    }))
                }
                FakeBehavior::ReadyWithThread => {
                    let stop = Arc::new(AtomicBool::new(false));
                    let alive = this
                        .thread_alive
                        .clone()
                        .expect("with_thread provider carries a liveness flag");
                    let stop_for_thread = Arc::clone(&stop);
                    let alive_for_thread = Arc::clone(&alive);
                    alive.store(true, Ordering::SeqCst);
                    let handle = std::thread::spawn(move || {
                        while !stop_for_thread.load(Ordering::SeqCst) {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        // Thread exits only after being asked to stop; clearing
                        // this AFTER the loop lets the test prove the join
                        // happened, not just that the flag was set.
                        alive_for_thread.store(false, Ordering::SeqCst);
                    });
                    Ok(Box::new(FakeComponent {
                        kind: this.kind,
                        ready: this.ready,
                        released: false,
                        release_log: this.release_log,
                        stop: Some(stop),
                        thread: Some(handle),
                    }))
                }
            }
        }
    }

    fn ready_plan(log: &ReleaseLog) -> Vec<Box<dyn ComponentProvider>> {
        ComponentKind::REQUIRED_IN_ORDER
            .into_iter()
            .map(|k| {
                Box::new(FakeProvider::ready(k).with_log(log.clone())) as Box<dyn ComponentProvider>
            })
            .collect()
    }

    /// Unwrap the `Component` failure variant; the plan-shape mismatch variant
    /// has its own dedicated tests, so a `PlanMismatch` here is a test bug.
    fn expect_component(err: EnforcementStartError) -> (ComponentKind, EnforcementError) {
        match err {
            EnforcementStartError::Component { failed, reason, .. } => (failed, reason),
            other => panic!("expected a component failure, got {other:?}"),
        }
    }

    /// Build a fully-ready fake component directly, bypassing `start`. Used by
    /// the defensive `MissingComponent` test to construct a runtime whose owned
    /// set is deliberately incomplete — a state `start` refuses to produce.
    fn fake_ready_component(kind: ComponentKind) -> Box<dyn AcquiredComponent> {
        Box::new(FakeComponent {
            kind,
            ready: Arc::new(AtomicBool::new(true)),
            released: false,
            release_log: None,
            stop: None,
            thread: None,
        })
    }

    /// As [`fake_ready_component`] but records each release into `log`, so a
    /// direct-construction test can assert reverse-order teardown alongside a
    /// panicking sibling.
    fn fake_ready_component_logging(
        kind: ComponentKind,
        log: &ReleaseLog,
    ) -> Box<dyn AcquiredComponent> {
        Box::new(FakeComponent {
            kind,
            ready: Arc::new(AtomicBool::new(true)),
            released: false,
            release_log: Some(log.clone()),
            stop: None,
            thread: None,
        })
    }

    /// A component whose `release()` panics — but only AFTER recording itself
    /// and marking itself released, so it panics AT MOST ONCE. Its own `Drop`
    /// re-invokes `release()`, which then no-ops on the `released` flag; that is
    /// essential, because `release_reverse` drops each component right after
    /// catching its release panic, and a SECOND panic from that Drop (were it
    /// running while a Drop-driven sweep unwinds) would abort the process — the
    /// exact hazard the containment defends against. Modeling a buggy teardown
    /// while keeping destruction safe is what lets the test exercise the
    /// containment without a spurious abort.
    struct PanicOnRelease {
        kind: ComponentKind,
        release_log: ReleaseLog,
        released: bool,
    }
    impl AcquiredComponent for PanicOnRelease {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            !self.released
        }
        fn release(&mut self) {
            if self.released {
                return; // idempotent: the panic fires at most once
            }
            // Record and mark released BEFORE panicking so the Drop-invoked
            // re-release is a safe no-op (see the type doc).
            self.released = true;
            self.release_log.record(self.kind);
            panic!("simulated teardown panic releasing {}", self.kind);
        }
    }
    impl Drop for PanicOnRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    fn fake_panicking_component(
        kind: ComponentKind,
        log: &ReleaseLog,
    ) -> Box<dyn AcquiredComponent> {
        Box::new(PanicOnRelease {
            kind,
            release_log: log.clone(),
            released: false,
        })
    }

    /// A provider that yields a ready component whose `release()` panics (see
    /// [`PanicOnRelease`]). Used by the startup-unwind test to prove a cleanup
    /// panic during `start`'s fail-before sweep does not mask the original
    /// acquisition failure.
    struct PanicOnReleaseProvider {
        kind: ComponentKind,
        release_log: ReleaseLog,
    }
    impl ComponentProvider for PanicOnReleaseProvider {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            Ok(fake_panicking_component(self.kind, &self.release_log))
        }
    }

    /// An ADVERSARIAL component whose `release()` records its attempt and then
    /// ALWAYS panics WITHOUT marking itself released, and whose `Drop`
    /// re-invokes `release()` — so it panics a SECOND time during destructor
    /// re-entry. Unlike [`PanicOnRelease`] (which guards on a `released` flag and
    /// panics at most once), this models a component that cannot be trusted to
    /// make its own `Drop` safe. `release_reverse`'s SECOND `catch_unwind`
    /// (around the explicit `drop` of the moved Box) is what keeps the
    /// retry-panic from escaping the sweep and aborting the process on a
    /// Drop-driven unwind. It records on EVERY call, so a test can observe TWO
    /// entries (the release panic and the Drop re-panic) and prove both were
    /// contained.
    struct AlwaysPanicOnRelease {
        kind: ComponentKind,
        release_log: ReleaseLog,
    }
    impl AcquiredComponent for AlwaysPanicOnRelease {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn is_ready(&self) -> bool {
            true
        }
        fn release(&mut self) {
            // record() takes and releases the lock BEFORE the panic, so the
            // ReleaseLog mutex is never poisoned; then ALWAYS panic without
            // marking released, so the Drop below re-enters and re-panics.
            self.release_log.record(self.kind);
            panic!("adversarial always-panic release {}", self.kind);
        }
    }
    impl Drop for AlwaysPanicOnRelease {
        fn drop(&mut self) {
            // Retry-and-re-panic with no `released` guard: contained by
            // release_reverse's second catch_unwind, never license to panic.
            self.release();
        }
    }

    struct AlwaysPanicOnReleaseProvider {
        kind: ComponentKind,
        release_log: ReleaseLog,
    }
    impl ComponentProvider for AlwaysPanicOnReleaseProvider {
        fn kind(&self) -> ComponentKind {
            self.kind
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            Ok(Box::new(AlwaysPanicOnRelease {
                kind: self.kind,
                release_log: self.release_log,
            }))
        }
    }

    // ---- successful ordering ------------------------------------------------

    #[test]
    fn start_acquires_all_required_components_in_order() {
        let log = ReleaseLog::default();
        let runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        assert_eq!(
            runtime.owned_kinds(),
            ComponentKind::REQUIRED_IN_ORDER.to_vec()
        );
        assert!(runtime.is_kernel_runtime_ready());
        assert_eq!(runtime.status(), EnforcementStatus::KernelRuntimeReady);
    }

    #[test]
    fn shutdown_releases_in_reverse_acquisition_order() {
        let log = ReleaseLog::default();
        let mut runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        runtime.shutdown();
        let mut expected = ComponentKind::REQUIRED_IN_ORDER.to_vec();
        expected.reverse();
        assert_eq!(log.order(), expected);
        // Post-shutdown the runtime is not enforcing and owns nothing.
        assert!(!runtime.is_kernel_runtime_ready());
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::ShuttingDown
            }
        );
        assert!(runtime.owned_kinds().is_empty());
    }

    #[test]
    fn shutdown_is_idempotent() {
        let log = ReleaseLog::default();
        let mut runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        runtime.shutdown();
        runtime.shutdown();
        runtime.shutdown();
        // Exactly one release per component despite repeated shutdowns.
        assert_eq!(log.order().len(), ComponentKind::REQUIRED_IN_ORDER.len());
    }

    #[test]
    fn drop_without_shutdown_still_releases_every_component() {
        let log = ReleaseLog::default();
        {
            let _runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
            // No explicit shutdown; Drop must still tear everything down.
        }
        let mut expected = ComponentKind::REQUIRED_IN_ORDER.to_vec();
        expected.reverse();
        assert_eq!(log.order(), expected);
    }

    // ---- a panicking release is contained; the sweep still completes --------

    #[test]
    fn shutdown_containing_a_panicking_release_still_releases_all_predecessors_in_reverse() {
        // The last-acquired component (ManifestWatcher, released FIRST) panics
        // during release. Containment must catch that panic and continue, so
        // both predecessors still release, in reverse acquisition order.
        // Without the per-component catch_unwind the panic would unwind out of
        // shutdown() (and, on the Drop path, abort the process), leaking the two
        // predecessors' resources. NOTE: the caught panic prints an expected
        // "simulated teardown panic" line to stderr; the test still passes.
        let log = ReleaseLog::default();
        let mut runtime = EnforcementRuntime {
            components: vec![
                fake_ready_component_logging(ComponentKind::NftablesTable, &log),
                fake_ready_component_logging(ComponentKind::Nfqueue, &log),
                fake_panicking_component(ComponentKind::ManifestWatcher, &log),
            ],
            shutdown_done: false,
        };
        // Returns normally: no panic escapes the contained sweep.
        runtime.shutdown();
        // The panicking component recorded its release before panicking, and
        // both predecessors released after it despite the panic — full reverse
        // order, nothing skipped.
        assert_eq!(
            log.order(),
            vec![
                ComponentKind::ManifestWatcher,
                ComponentKind::Nfqueue,
                ComponentKind::NftablesTable
            ]
        );
        // The set was fully drained and the runtime reads as shut down.
        assert!(runtime.owned_kinds().is_empty());
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::ShuttingDown
            }
        );
    }

    #[test]
    fn cleanup_panic_during_startup_unwind_does_not_mask_the_original_failure() {
        // NftablesTable acquires ready but panics when released; Nfqueue then
        // fails to acquire, triggering start's fail-before reverse sweep that
        // releases NftablesTable — whose release panics. The returned error must
        // still be the ORIGINAL Nfqueue acquisition failure, not the cleanup
        // panic, and the panicking predecessor's release must still have run.
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(PanicOnReleaseProvider {
                kind: ComponentKind::NftablesTable,
                release_log: log.clone(),
            }),
            Box::new(FakeProvider::failing(
                ComponentKind::Nfqueue,
                EnforcementError::NotAvailableOnPlatform(ComponentKind::Nfqueue.as_str()),
            )),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher).with_log(log.clone())),
        ];
        let err = EnforcementRuntime::start(providers)
            .expect_err("Nfqueue acquisition fails; a cleanup panic must not mask it");
        let (failed, reason) = expect_component(err);
        // The original startup failure survives the contained cleanup panic.
        assert_eq!(failed, ComponentKind::Nfqueue);
        assert!(matches!(
            reason,
            EnforcementError::NotAvailableOnPlatform(_)
        ));
        // The panicking predecessor's release was still attempted (and, being
        // the only component acquired before the failure, is the only entry —
        // ManifestWatcher was never reached).
        assert_eq!(log.order(), vec![ComponentKind::NftablesTable]);
    }

    #[test]
    fn adversarial_always_panicking_release_and_drop_is_contained_during_startup_unwind() {
        // NftablesTable acquires ready and logs; Nfqueue is the ADVERSARIAL
        // component (always-panic release + retry-panic Drop, no `released`
        // guard) and acquires ready; ManifestWatcher then FAILS to acquire,
        // triggering start's fail-before reverse sweep over
        // [nftables, nfqueue-adversarial]. The sweep releases the adversarial
        // FIRST: its release() panics (contained by catch #1) and, when the Box
        // is dropped, its Drop re-invokes release() and re-panics (contained by
        // catch #2). Neither escapes, so the process does not abort AND the real
        // predecessor (nftables) STILL releases afterward. The returned error
        // must remain the ORIGINAL ManifestWatcher acquisition failure, not
        // either cleanup panic. Without the SECOND catch_unwind the Drop
        // re-panic would escape and, on a Drop-driven sweep during an unwind,
        // abort the process. NOTE: the two caught panics print expected
        // "adversarial always-panic" lines to stderr; the test still passes.
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone())),
            Box::new(AlwaysPanicOnReleaseProvider {
                kind: ComponentKind::Nfqueue,
                release_log: log.clone(),
            }),
            Box::new(FakeProvider::failing(
                ComponentKind::ManifestWatcher,
                EnforcementError::AcquireFailed {
                    kind: ComponentKind::ManifestWatcher.as_str(),
                    detail: "watch init failed".into(),
                },
            )),
        ];
        let err = EnforcementRuntime::start(providers).expect_err(
            "ManifestWatcher acquisition fails; adversarial cleanup must not mask it or abort",
        );
        let (failed, reason) = expect_component(err);
        // The original startup failure survives BOTH contained cleanup panics.
        assert_eq!(failed, ComponentKind::ManifestWatcher);
        assert!(matches!(reason, EnforcementError::AcquireFailed { .. }));
        // Reverse-order sweep, both containments proven:
        //   - Nfqueue recorded TWICE (the release() panic AND the Drop
        //     re-panic, each caught by its own catch_unwind), and
        //   - NftablesTable released AFTER, so the sweep survived the
        //     adversarial's destructor re-entry to reach the real predecessor
        //     rather than aborting.
        assert_eq!(
            log.order(),
            vec![
                ComponentKind::Nfqueue,
                ComponentKind::Nfqueue,
                ComponentKind::NftablesTable
            ]
        );
    }

    // ---- fail-before per acquisition step -----------------------------------

    #[test]
    fn fail_before_at_first_step_acquires_and_releases_nothing() {
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::failing(
                ComponentKind::NftablesTable,
                EnforcementError::AcquireFailed {
                    kind: ComponentKind::NftablesTable.as_str(),
                    detail: "install failed".into(),
                },
            )),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).with_log(log.clone())),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher).with_log(log.clone())),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("must fail before");
        let (failed, _reason) = expect_component(err);
        assert_eq!(failed, ComponentKind::NftablesTable);
        // Nothing after the failing first step was acquired, so nothing was
        // released.
        assert!(log.order().is_empty());
    }

    #[test]
    fn fail_before_at_middle_step_releases_predecessor_in_reverse() {
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone())),
            Box::new(FakeProvider::failing(
                ComponentKind::Nfqueue,
                EnforcementError::NotAvailableOnPlatform(ComponentKind::Nfqueue.as_str()),
            )),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher).with_log(log.clone())),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("must fail before");
        let (failed, _reason) = expect_component(err);
        assert_eq!(failed, ComponentKind::Nfqueue);
        // Only the predecessor (nftables) was acquired; it is released.
        assert_eq!(log.order(), vec![ComponentKind::NftablesTable]);
    }

    #[test]
    fn fail_before_at_last_step_releases_all_predecessors_in_reverse() {
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone())),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).with_log(log.clone())),
            Box::new(FakeProvider::failing(
                ComponentKind::ManifestWatcher,
                EnforcementError::AcquireFailed {
                    kind: ComponentKind::ManifestWatcher.as_str(),
                    detail: "watch init failed".into(),
                },
            )),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("must fail before");
        let (failed, _reason) = expect_component(err);
        assert_eq!(failed, ComponentKind::ManifestWatcher);
        // Reverse of acquisition: nfqueue released before nftables.
        assert_eq!(
            log.order(),
            vec![ComponentKind::Nfqueue, ComponentKind::NftablesTable]
        );
    }

    #[test]
    fn component_that_acquires_but_is_not_ready_is_a_fail_before() {
        let log = ReleaseLog::default();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone())),
            Box::new(FakeProvider::not_ready(ComponentKind::Nfqueue).with_log(log.clone())),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher).with_log(log.clone())),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("not-ready is fail-before");
        let (failed, reason) = expect_component(err);
        assert_eq!(failed, ComponentKind::Nfqueue);
        assert!(matches!(reason, EnforcementError::NotReadyAfterAcquire(_)));
        // The not-ready component AND its predecessor are both released, in
        // reverse order.
        assert_eq!(
            log.order(),
            vec![ComponentKind::Nfqueue, ComponentKind::NftablesTable]
        );
    }

    // ---- delivered-kind check (advertised kind is not the delivered one) ----

    #[test]
    fn provider_delivering_a_mismatched_kind_is_a_fail_before_and_unwinds() {
        let log = ReleaseLog::default();
        // The middle provider advertises Nfqueue (so the ordered-plan gate
        // passes) but hands back a ManifestWatcher-kind component. The
        // delivered-kind check must reject it, unwind the acquired predecessor
        // in reverse, and never construct a runtime (zero fake-green).
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone())),
            Box::new(
                FakeProvider::wrong_kind(ComponentKind::Nfqueue, ComponentKind::ManifestWatcher)
                    .with_log(log.clone()),
            ),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher).with_log(log.clone())),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("kind mismatch is fail-before");
        let (failed, reason) = expect_component(err);
        // Attributed to the advertised kind the plan expected at this step.
        assert_eq!(failed, ComponentKind::Nfqueue);
        match reason {
            EnforcementError::ComponentKindMismatch { expected, actual } => {
                assert_eq!(expected, ComponentKind::Nfqueue.as_str());
                assert_eq!(actual, ComponentKind::ManifestWatcher.as_str());
            }
            other => panic!("expected ComponentKindMismatch, got {other:?}"),
        }
        // Teardown order: the mismatched component (delivered kind
        // manifest_watcher) is released first, then the acquired predecessor
        // (nftables) — reverse acquisition order.
        assert_eq!(
            log.order(),
            vec![ComponentKind::ManifestWatcher, ComponentKind::NftablesTable]
        );
    }

    /// A provider whose self-reported `kind()` is NOT STABLE across calls:
    /// `preflight_kind` on the first call, `later_kind` on every later call,
    /// counting each call. It delivers a component of `delivered_kind`. If
    /// `start` ever re-read `provider.kind()` during acquisition, it would
    /// validate the delivered component against `later_kind` instead of the
    /// frozen `preflight_kind` — the exact divergence the freeze forecloses.
    struct StatefulKindProvider {
        preflight_kind: ComponentKind,
        later_kind: ComponentKind,
        delivered_kind: ComponentKind,
        kind_calls: Arc<AtomicUsize>,
    }
    impl ComponentProvider for StatefulKindProvider {
        fn kind(&self) -> ComponentKind {
            let n = self.kind_calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                self.preflight_kind
            } else {
                self.later_kind
            }
        }
        fn acquire(self: Box<Self>) -> Result<Box<dyn AcquiredComponent>, EnforcementError> {
            // Delivers a READY component of delivered_kind; the delivered-kind
            // check must reject it against the FROZEN preflight kind.
            Ok(Box::new(FakeComponent {
                kind: self.delivered_kind,
                ready: Arc::new(AtomicBool::new(true)),
                released: false,
                release_log: None,
                stop: None,
                thread: None,
            }))
        }
    }

    #[test]
    fn provider_kind_is_frozen_at_preflight_and_never_re_read_during_acquisition() {
        // The middle provider advertises Nfqueue at preflight (so the ordered
        // plan gate passes: [NftablesTable, Nfqueue, ManifestWatcher]) but would
        // report ManifestWatcher on any SECOND kind() call, and it delivers a
        // ManifestWatcher-kind component. Because the advertised kinds are
        // frozen from the preflight vector, acquisition validates the delivered
        // component against the frozen Nfqueue — catching the mismatch — and
        // never calls provider.kind() again, so the unstable later_kind is never
        // consulted. Under the pre-freeze code a second kind() read would have
        // returned ManifestWatcher, matched the delivered ManifestWatcher, and
        // silently admitted a component that diverges the owned set from
        // REQUIRED_IN_ORDER.
        let kind_calls = Arc::new(AtomicUsize::new(0));
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable)),
            Box::new(StatefulKindProvider {
                preflight_kind: ComponentKind::Nfqueue,
                later_kind: ComponentKind::ManifestWatcher,
                delivered_kind: ComponentKind::ManifestWatcher,
                kind_calls: Arc::clone(&kind_calls),
            }),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher)),
        ];
        let err = EnforcementRuntime::start(providers)
            .expect_err("a delivered component mismatching the frozen kind is rejected");
        let (failed, reason) = expect_component(err);
        // Attributed and validated against the FROZEN preflight kind (Nfqueue),
        // NOT the provider's later self-report (ManifestWatcher).
        assert_eq!(failed, ComponentKind::Nfqueue);
        match reason {
            EnforcementError::ComponentKindMismatch { expected, actual } => {
                assert_eq!(expected, ComponentKind::Nfqueue.as_str());
                assert_eq!(actual, ComponentKind::ManifestWatcher.as_str());
            }
            other => {
                panic!("expected ComponentKindMismatch against the frozen kind, got {other:?}")
            }
        }
        // Decisive assertion: provider.kind() was called EXACTLY ONCE (the
        // preflight read). A second call would have returned later_kind; its
        // absence proves acquisition never re-reads the provider's kind.
        assert_eq!(
            kind_calls.load(Ordering::SeqCst),
            1,
            "provider.kind() must be read exactly once (preflight), never re-read during acquisition"
        );
    }

    // ---- whole-set re-check: an earlier component dies during a later acquire

    #[test]
    fn earlier_component_lost_during_a_later_acquire_unwinds_the_whole_set() {
        let log = ReleaseLog::default();
        // nftables acquires ready; its readiness handle is shared so a later
        // provider can invalidate it. The manifest-watcher provider clears that
        // handle DURING its own acquire(), simulating a later kernel step
        // clobbering the earlier component's resource. Every per-step check
        // passed at the moment it ran, so only the whole-set re-check before Ok
        // can catch this — deterministically, no threads.
        let nftables = FakeProvider::ready(ComponentKind::NftablesTable).with_log(log.clone());
        let nftables_ready = nftables.ready_handle();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(nftables),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).with_log(log.clone())),
            Box::new(
                FakeProvider::ready(ComponentKind::ManifestWatcher)
                    .with_log(log.clone())
                    .clearing_on_acquire(&nftables_ready),
            ),
        ];
        let err = EnforcementRuntime::start(providers)
            .expect_err("an earlier component lost during a later acquire is fail-before");
        let (failed, reason) = expect_component(err);
        // The earliest casualty is named, not the last-acquired component.
        assert_eq!(failed, ComponentKind::NftablesTable);
        assert!(matches!(reason, EnforcementError::NotReadyAfterAcquire(_)));
        // Full reverse-order unwind of the ENTIRE acquired set (zero fake-green:
        // no runtime escaped).
        assert_eq!(
            log.order(),
            vec![
                ComponentKind::ManifestWatcher,
                ComponentKind::Nfqueue,
                ComponentKind::NftablesTable
            ]
        );
    }

    // ---- plan shape is validated before anything is acquired ----------------

    #[test]
    fn start_rejects_a_misordered_plan_and_acquires_nothing() {
        let acquires = Arc::new(AtomicUsize::new(0));
        // REQUIRED order is [NftablesTable, Nfqueue, ManifestWatcher]; hand it
        // the reverse. Acquiring NFQUEUE before its nftables table is exactly
        // the ordering hazard the plan gate exists to reject.
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(
                FakeProvider::ready(ComponentKind::ManifestWatcher).counting_acquires(&acquires),
            ),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).counting_acquires(&acquires)),
            Box::new(
                FakeProvider::ready(ComponentKind::NftablesTable).counting_acquires(&acquires),
            ),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("misordered plan is rejected");
        match err {
            EnforcementStartError::PlanMismatch { expected, actual } => {
                assert_eq!(expected, ComponentKind::REQUIRED_IN_ORDER.to_vec());
                assert_eq!(
                    actual,
                    vec![
                        ComponentKind::ManifestWatcher,
                        ComponentKind::Nfqueue,
                        ComponentKind::NftablesTable
                    ]
                );
            }
            other => panic!("expected PlanMismatch, got {other:?}"),
        }
        assert_eq!(
            acquires.load(Ordering::SeqCst),
            0,
            "a misordered plan must acquire no provider"
        );
    }

    #[test]
    fn start_rejects_an_incomplete_plan_and_acquires_nothing() {
        let acquires = Arc::new(AtomicUsize::new(0));
        // ManifestWatcher missing: an incomplete set could otherwise acquire a
        // partial runtime that then reads as enforcing on the kinds present.
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(
                FakeProvider::ready(ComponentKind::NftablesTable).counting_acquires(&acquires),
            ),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).counting_acquires(&acquires)),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("incomplete plan is rejected");
        match err {
            EnforcementStartError::PlanMismatch { expected, actual } => {
                assert_eq!(expected, ComponentKind::REQUIRED_IN_ORDER.to_vec());
                assert_eq!(
                    actual,
                    vec![ComponentKind::NftablesTable, ComponentKind::Nfqueue]
                );
            }
            other => panic!("expected PlanMismatch, got {other:?}"),
        }
        assert_eq!(
            acquires.load(Ordering::SeqCst),
            0,
            "an incomplete plan must acquire no provider"
        );
    }

    #[test]
    fn start_rejects_a_plan_with_a_duplicate_component_and_acquires_nothing() {
        let acquires = Arc::new(AtomicUsize::new(0));
        // A duplicate NFQUEUE in place of the manifest watcher: right count,
        // wrong set. Exact equality catches it; a "contains all required" check
        // would not.
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(
                FakeProvider::ready(ComponentKind::NftablesTable).counting_acquires(&acquires),
            ),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).counting_acquires(&acquires)),
            Box::new(FakeProvider::ready(ComponentKind::Nfqueue).counting_acquires(&acquires)),
        ];
        let err = EnforcementRuntime::start(providers).expect_err("duplicate plan is rejected");
        assert!(matches!(err, EnforcementStartError::PlanMismatch { .. }));
        assert_eq!(
            acquires.load(Ordering::SeqCst),
            0,
            "a wrong-set plan must acquire no provider"
        );
    }

    // ---- defensive MissingComponent status (start can no longer produce it) --

    #[test]
    fn status_names_a_missing_required_component_when_the_set_is_incomplete() {
        // `start` validates the plan, so a runtime reached through it can never
        // be missing a required kind. Construct an incomplete runtime directly
        // (test-only, same-module field access) to prove the defensive
        // `MissingComponent` arm still reads as not-enforcing rather than
        // falling through to `Enforcing`. This does NOT weaken the exact-plan
        // startup invariant: no production path can build this shape.
        let runtime = EnforcementRuntime {
            components: vec![
                fake_ready_component(ComponentKind::NftablesTable),
                fake_ready_component(ComponentKind::ManifestWatcher),
            ],
            shutdown_done: false,
        };
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::MissingComponent(ComponentKind::Nfqueue)
            }
        );
        assert!(!runtime.is_kernel_runtime_ready());
    }

    // ---- no detached thread outlives the owner ------------------------------

    #[test]
    fn owned_thread_is_joined_before_release_returns() {
        let provider = FakeProvider::with_thread(ComponentKind::Nfqueue);
        let alive = provider.thread_alive_handle();
        let mut component = Box::new(provider).acquire().expect("acquire with thread");
        assert!(alive.load(Ordering::SeqCst), "thread should be running");
        component.release();
        // The thread cleared `alive` only after its loop exited; if release
        // returned before the join, this would still be true.
        assert!(
            !alive.load(Ordering::SeqCst),
            "release must join the owned thread before returning"
        );
    }

    #[test]
    fn runtime_shutdown_joins_component_threads() {
        let provider = FakeProvider::with_thread(ComponentKind::Nfqueue);
        let alive = provider.thread_alive_handle();
        // Build the full required set with a live-thread nfqueue component.
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable)),
            Box::new(provider),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher)),
        ];
        let mut runtime = EnforcementRuntime::start(providers).expect("all ready");
        assert!(alive.load(Ordering::SeqCst));
        runtime.shutdown();
        assert!(
            !alive.load(Ordering::SeqCst),
            "no resource-owning thread may outlive the runtime owner"
        );
    }

    // ---- readiness gating of KernelRuntimeReady -----------------------------

    #[test]
    fn lost_component_drops_out_of_kernel_runtime_ready() {
        // Keep the nfqueue readiness handle so we can flip it after start.
        let nfqueue = FakeProvider::ready(ComponentKind::Nfqueue);
        let nfqueue_ready = nfqueue.ready_handle();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable)),
            Box::new(nfqueue),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher)),
        ];
        let runtime = EnforcementRuntime::start(providers).expect("all ready");
        assert!(runtime.is_kernel_runtime_ready());
        // Simulate the verdict thread dying / table clobbered.
        nfqueue_ready.store(false, Ordering::SeqCst);
        assert_eq!(
            runtime.status(),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::ComponentLost(ComponentKind::Nfqueue)
            }
        );
        assert!(!runtime.is_kernel_runtime_ready());
    }

    // ---- daemon-state derivation --------------------------------------------

    #[test]
    fn derive_state_kernel_runtime_ready_only_when_runtime_fully_ready() {
        let log = ReleaseLog::default();
        let runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        // A fully-ready runtime derives KernelRuntimeReady, NEVER Enforcing:
        // this slice wraps no agent, so nothing is being enforced.
        assert_eq!(
            derive_daemon_state(DaemonRuntimeState::ControlPlaneOnly, Some(&runtime)),
            DaemonRuntimeState::KernelRuntimeReady
        );
        assert_ne!(
            derive_daemon_state(DaemonRuntimeState::ControlPlaneOnly, Some(&runtime)),
            DaemonRuntimeState::Enforcing,
            "kernel-runtime readiness must never be presented as enforcement"
        );
    }

    #[test]
    fn derive_state_no_runtime_is_control_plane_only() {
        assert_eq!(
            derive_daemon_state(DaemonRuntimeState::ControlPlaneOnly, None),
            DaemonRuntimeState::ControlPlaneOnly
        );
    }

    #[test]
    fn enforcement_status_none_reports_no_runtime() {
        // The shipped path in this slice owns no runtime; the status vocabulary
        // must name that explicitly rather than the reason being unreachable.
        assert_eq!(
            enforcement_status(None),
            EnforcementStatus::NotReady {
                reason: NotReadyReason::NoRuntime
            }
        );
    }

    #[test]
    fn enforcement_status_ready_runtime_is_kernel_runtime_ready() {
        let log = ReleaseLog::default();
        let runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        assert_eq!(
            enforcement_status(Some(&runtime)),
            EnforcementStatus::KernelRuntimeReady
        );
    }

    #[test]
    fn derive_state_lost_component_is_control_plane_only_not_enforcing() {
        let nfqueue = FakeProvider::ready(ComponentKind::Nfqueue);
        let nfqueue_ready = nfqueue.ready_handle();
        let providers: Vec<Box<dyn ComponentProvider>> = vec![
            Box::new(FakeProvider::ready(ComponentKind::NftablesTable)),
            Box::new(nfqueue),
            Box::new(FakeProvider::ready(ComponentKind::ManifestWatcher)),
        ];
        let runtime = EnforcementRuntime::start(providers).expect("all ready");
        nfqueue_ready.store(false, Ordering::SeqCst);
        assert_eq!(
            derive_daemon_state(DaemonRuntimeState::ControlPlaneOnly, Some(&runtime)),
            DaemonRuntimeState::ControlPlaneOnly
        );
    }

    #[test]
    fn derive_state_stopping_and_degraded_are_never_promoted_to_enforcing() {
        let log = ReleaseLog::default();
        let runtime = EnforcementRuntime::start(ready_plan(&log)).expect("all ready");
        // Even with a fully-ready runtime, a Stopping/Degraded lifecycle wins.
        assert_eq!(
            derive_daemon_state(DaemonRuntimeState::Stopping, Some(&runtime)),
            DaemonRuntimeState::Stopping
        );
        assert_eq!(
            derive_daemon_state(DaemonRuntimeState::Degraded, Some(&runtime)),
            DaemonRuntimeState::Degraded
        );
    }

    // The production Linux plan and its "fails-before on a host without a
    // drill-verified kernel path" behavior are tested in
    // `crate::runtime_providers` (non-Linux) and the cfg-gated Linux integration
    // test, since the plan now lives there.
}
