//! Bounded, single-flight component health probing.
//!
//! The nftables ownership proof is a `fork`/`exec` of `nft -j list table`. Three
//! properties are required of every caller, and none of them is expressible in a
//! bare `fn is_ready(&self) -> bool` that shells out on every call:
//!
//! 1. **Bounded.** A wedged `nft` (fork/exec or netlink hang) must not delay
//!    shutdown or supervision. The check runs on an isolated worker with a hard
//!    deadline; the calling thread never blocks past that deadline.
//! 2. **Single-flight and rate-limited.** Readiness used to be re-polled by BOTH
//!    the 2-second supervisor tick AND every authenticated `status_request`, with
//!    no cache and no concurrency limit, so a status-polling client could pile up
//!    concurrent `nft` forks, push one past the deadline, and drive a full
//!    enforcement restart with no privilege at all. At most one real check is in
//!    flight at a time, and a check younger than [`ProbeBudget::min_interval`] is
//!    served from the cached reading.
//! 3. **Three-valued.** A completed check that says "not ours" is a PROVEN loss.
//!    A timeout, a failed worker spawn, or a concurrent in-flight check is
//!    INDETERMINATE. Collapsing indeterminate into "lost" is what turned momentary
//!    contention into a false enforcement-loss restart; collapsing it into "ready"
//!    would be the far worse direction. [`ProbeOutcome::Unavailable`] names it, and
//!    every consumer must treat it as not-proven — never as passing.
//!
//! ## Who owns the in-flight slot, and why it is the WORKER
//!
//! Property 2 was previously claimed but not held. The caller cleared the
//! in-flight flag on EVERY exit from `poll`, including the deadline path, while
//! the abandoned worker (and its `nft` child) was still running. A wedged check
//! therefore released the slot after one deadline, and the next supervisor tick
//! forked a SECOND `nft` against the same wedged resource; only the
//! consecutive-indeterminate latch bounded the pile-up. "At most one real check
//! in flight" was false in exactly the wedged-then-recovering schedule the
//! property exists for (AGENTS rule 12: a bound that holds under one
//! instantaneous wave is not a bound under an adversarial fault schedule).
//!
//! Ownership of the slot now belongs to the WORKER, released by a drop guard, so
//! it is released on completion, on panic, and never on a mere deadline overrun.
//! The calling thread still returns within its deadline — it stops waiting, it
//! does not repossess. A blocked worker cannot be cancelled: it is parked in
//! `waitpid` on the `nft` child, and no portable, async-signal-safe way to
//! terminate another thread exists in std. So the bound is structural rather than
//! preemptive:
//!
//! * exactly one `nft` child can exist per probe at a time, wedge or no wedge;
//! * every poll that finds a check running PAST its deadline records an
//!   indeterminate reading, so a permanently wedged worker latches `Lost` on the
//!   same consecutive budget as before and the daemon exits for systemd;
//! * the systemd restart's cgroup kill is what actually reaps the wedged `nft`,
//!   which is the only place a real termination is available.
//!
//! A poll that finds a check running WITHIN its deadline records nothing. That
//! asymmetry is load-bearing: counting healthy concurrent polls would let a burst
//! of callers manufacture the very false loss this module removes, while not
//! counting a proven-late one would delete the fail-closed backstop.
//!
//! Fail-closed is preserved by two latches: a completed `false` withdraws
//! readiness permanently for the process (ownership cannot be proven, so a
//! systemd restart that re-adopts the preserved table is the recovery path), and
//! a bounded run of consecutive indeterminate readings ALSO latches, so an
//! `nft` that never returns can never hold the daemon in "unknown" forever.
//!
//! This module deliberately exposes NO cached-read accessor. Status queries read
//! the supervisor's published observation in [`crate::runtime_health`], which is
//! the single reader-facing surface; a second one here would be a parallel path
//! with no production consumer (AGENTS rule 9).

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A single probe result. Three-valued on purpose: `Unavailable` is the
/// indeterminate reading, and absence of proof is never proof of health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A check completed and proved the resource is still ours.
    Ready,
    /// A check completed and proved the resource is gone/drifted, or the
    /// indeterminate budget was exhausted. Terminal for this process.
    Lost,
    /// No conclusion is available right now: another check is in flight, or this
    /// one exceeded its deadline. NOT a loss and NOT readiness.
    Unavailable,
}

/// Timing/latching parameters for a [`BoundedHealthProbe`]. Derived, not magic:
/// see the field docs for what each bound is measured against.
#[derive(Debug, Clone, Copy)]
pub struct ProbeBudget {
    /// Hard per-check deadline. The calling thread stops waiting after this and
    /// reports `Unavailable`. It does NOT reclaim the in-flight slot; the worker
    /// keeps it until the check actually terminates.
    pub timeout: Duration,
    /// Minimum spacing between REAL checks. A poll inside this window is served
    /// from the cached reading, so N callers per window cost one subprocess.
    /// Must be well under the supervisor's health interval or a genuine loss
    /// would be detected a tick late.
    pub min_interval: Duration,
    /// How many consecutive indeterminate readings may pass before the probe
    /// latches `Lost`. This is the fail-closed backstop for an `nft` that never
    /// returns: worst-case detection is `max_consecutive_unavailable` supervisor
    /// ticks, not unbounded.
    pub max_consecutive_unavailable: u32,
}

#[derive(Debug)]
struct ProbeState {
    /// The last COMPLETED reading and when it completed.
    last: Option<(Instant, bool)>,
    /// When the currently-running check STARTED, or `None` when no check owns
    /// the probe. Written by the poller that wins the slot and cleared ONLY by
    /// that check's drop guard. The start instant (rather than a bare bool) is
    /// what lets a later poller tell a healthy in-flight check from a wedged one.
    in_flight_since: Option<Instant>,
    /// Bumped once per check TERMINATION (completed or panicked). A waiting
    /// poller watches this rather than `in_flight_since`, so it cannot mistake a
    /// third party's freshly-started check for its own having finished.
    completions: u64,
    /// Consecutive indeterminate readings since the last completed one.
    consecutive_unavailable: u32,
    /// Set once readiness is permanently withdrawn for this process.
    latched_lost: bool,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<ProbeState>,
    /// Signalled by a check's drop guard once the slot is released.
    terminated: Condvar,
}

impl Shared {
    /// Lock the state, recovering from poison.
    ///
    /// Recovery is correct here and jamming would not be: the guarded data is
    /// cached readings and counters, no user code ever runs while the lock is
    /// held, and treating a poisoned lock as "cannot conclude" would leave the
    /// in-flight slot permanently occupied — turning one unrelated panic into a
    /// probe that can never run again. Fail-closed still holds through the
    /// latches, which live inside this same state.
    fn lock(&self) -> MutexGuard<'_, ProbeState> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Releases the in-flight slot when the check's worker thread terminates,
/// whichever way it terminates.
///
/// A plain "clear the flag after `check()` returns" would leak the slot forever
/// on a panicking check, which is why this is a `Drop` impl and not a statement.
struct SlotGuard {
    shared: Arc<Shared>,
    max_consecutive_unavailable: u32,
    /// The check's answer, or `None` if it panicked before producing one.
    result: Option<Result<bool, ()>>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.in_flight_since = None;
            state.completions = state.completions.saturating_add(1);
            match self.result {
                Some(Ok(ready)) => {
                    state.last = Some((Instant::now(), ready));
                    state.consecutive_unavailable = 0;
                    if !ready {
                        // A COMPLETED negative proof is terminal: current
                        // ownership cannot be demonstrated, so readiness is
                        // withdrawn for this process and systemd restart is the
                        // recovery path.
                        state.latched_lost = true;
                    }
                }
                Some(Err(())) | None => {
                    // The worker panicked. No answer is not a loss, so the slot
                    // is released without a reading — but it IS an indeterminate
                    // reading, so a check that panics every time still latches
                    // fail-closed instead of retrying forever.
                    note_indeterminate(&mut state, self.max_consecutive_unavailable);
                }
            }
        }
        // Notify OUTSIDE the lock so a woken poller does not immediately block
        // on a lock this thread still holds.
        self.shared.terminated.notify_all();
    }
}

/// Record one indeterminate reading and apply the fail-closed backstop.
/// Shared by every indeterminate route (deadline overrun, spawn failure, panicked
/// worker, proven-wedged in-flight check) so all four latch on the same budget
/// rather than each site re-deriving it.
fn note_indeterminate(state: &mut ProbeState, max_consecutive_unavailable: u32) {
    state.consecutive_unavailable = state.consecutive_unavailable.saturating_add(1);
    if state.consecutive_unavailable >= max_consecutive_unavailable {
        state.latched_lost = true;
    }
}

/// A bounded, single-flight, rate-limited health probe with a fail-closed latch.
#[derive(Debug)]
pub struct BoundedHealthProbe {
    budget: ProbeBudget,
    shared: Arc<Shared>,
}

impl BoundedHealthProbe {
    pub fn new(budget: ProbeBudget) -> Self {
        Self {
            budget,
            shared: Arc::new(Shared {
                state: Mutex::new(ProbeState {
                    last: None,
                    in_flight_since: None,
                    completions: 0,
                    consecutive_unavailable: 0,
                    latched_lost: false,
                }),
                terminated: Condvar::new(),
            }),
        }
    }

    /// Run (or reuse) an authoritative check. Only the supervision loop and the
    /// startup readiness gate call this; it is the ONLY path that may fork.
    ///
    /// `check` is moved to an isolated worker so a wedged `nft` cannot block the
    /// caller past the deadline. The caller returns within
    /// [`ProbeBudget::timeout`] in every case, including the case where the
    /// worker is still running when it returns.
    pub fn poll<F>(&self, check: F) -> ProbeOutcome
    where
        F: FnOnce() -> bool + Send + 'static,
    {
        self.poll_result(move || Ok(check()))
    }

    /// Three-valued variant for probes whose command may fail without proving
    /// resource loss. `Err(())` is indeterminate and consumes the same bounded
    /// retry budget as a timeout or failed spawn; it is never cached as `false`.
    pub fn poll_result<F>(&self, check: F) -> ProbeOutcome
    where
        F: FnOnce() -> Result<bool, ()> + Send + 'static,
    {
        let mut state = self.shared.lock();
        if state.latched_lost {
            return ProbeOutcome::Lost;
        }
        if let Some((at, ready)) = state.last {
            if at.elapsed() < self.budget.min_interval {
                return if ready {
                    ProbeOutcome::Ready
                } else {
                    ProbeOutcome::Lost
                };
            }
        }
        if let Some(since) = state.in_flight_since {
            return self.observe_foreign_check(state, since);
        }

        // Win the slot. It is handed to the worker below and comes back only
        // through `SlotGuard::drop`; nothing on this thread's paths clears it.
        let started_at = Instant::now();
        state.in_flight_since = Some(started_at);
        let generation = state.completions;

        // Spawned while the lock is HELD. That is what makes the wait below
        // race-free: the worker's drop guard cannot take the lock, clear the
        // slot, and signal before this thread reaches `wait_timeout` (which is
        // what releases the lock).
        let shared = Arc::clone(&self.shared);
        let max_consecutive_unavailable = self.budget.max_consecutive_unavailable;
        let spawned = std::thread::Builder::new()
            .name("castle-wall-health-probe".to_string())
            .spawn(move || {
                let mut guard = SlotGuard {
                    shared,
                    max_consecutive_unavailable,
                    result: None,
                };
                // On a panic inside `check`, `guard` is dropped during unwind
                // with `result` still `None`, which releases the slot and counts
                // the attempt as indeterminate.
                guard.result = Some(check());
            });
        if spawned.is_err() {
            // No worker exists, so no drop guard will ever run: this thread is
            // the only one that can release the slot it just took. This is the
            // single exception to worker-owned release, and it is sound
            // precisely because there is nothing in flight to collide with.
            state.in_flight_since = None;
            note_indeterminate(&mut state, self.budget.max_consecutive_unavailable);
            return if state.latched_lost {
                ProbeOutcome::Lost
            } else {
                ProbeOutcome::Unavailable
            };
        }

        // Wait for OUR check to terminate, bounded by the deadline. The
        // generation counter (not `in_flight_since`) is the predicate: between
        // our worker finishing and this thread re-acquiring the lock, another
        // poller may legitimately have started a new check, and waiting on that
        // one would blow the deadline.
        let deadline = started_at + self.budget.timeout;
        while state.completions == generation {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .shared
                .terminated
                .wait_timeout(state, remaining)
                .unwrap_or_else(|err| err.into_inner());
            state = next;
        }

        if state.completions == generation {
            // Deadline overrun. The worker still owns the slot and its `nft`
            // child is still running; we abandon the WAIT, not the check.
            note_indeterminate(&mut state, self.budget.max_consecutive_unavailable);
            return if state.latched_lost {
                ProbeOutcome::Lost
            } else {
                ProbeOutcome::Unavailable
            };
        }
        Self::outcome_after_completion(&state, started_at)
    }

    /// Outcome for a poll whose own check terminated. Reads the state the drop
    /// guard just wrote rather than re-deriving it, so the completed/panicked
    /// distinction lives in exactly one place.
    fn outcome_after_completion(state: &ProbeState, started_at: Instant) -> ProbeOutcome {
        if state.latched_lost {
            return ProbeOutcome::Lost;
        }
        match state.last {
            // `>=` rather than `>`: a check fast enough to complete inside the
            // clock's resolution is still OUR reading.
            Some((at, ready)) if at >= started_at => {
                if ready {
                    ProbeOutcome::Ready
                } else {
                    // Unreachable in practice — a completed `false` latches above
                    // — but stated rather than assumed, so a future change to the
                    // latch cannot silently turn a proven loss into readiness.
                    ProbeOutcome::Lost
                }
            }
            // Terminated without a reading: the worker panicked. Indeterminate,
            // already counted by the drop guard.
            _ => ProbeOutcome::Unavailable,
        }
    }

    /// Outcome for a poll that found ANOTHER check already in flight. Never
    /// starts a second subprocess for the same resource.
    ///
    /// The count/no-count split is the whole point of storing a start instant:
    /// a check still inside its deadline is a healthy concurrent check, and
    /// counting it would let a burst of callers manufacture a loss; a check past
    /// its deadline is proven wedged, and NOT counting it would delete the
    /// fail-closed backstop, because after the first overrun no later poller
    /// ever waits on it again.
    fn observe_foreign_check(
        &self,
        mut state: MutexGuard<'_, ProbeState>,
        since: Instant,
    ) -> ProbeOutcome {
        if since.elapsed() <= self.budget.timeout {
            return ProbeOutcome::Unavailable;
        }
        note_indeterminate(&mut state, self.budget.max_consecutive_unavailable);
        if state.latched_lost {
            ProbeOutcome::Lost
        } else {
            ProbeOutcome::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn budget() -> ProbeBudget {
        ProbeBudget {
            timeout: Duration::from_millis(200),
            min_interval: Duration::from_millis(50),
            max_consecutive_unavailable: 3,
        }
    }

    #[test]
    fn a_completed_positive_check_is_ready_and_is_cached() {
        let probe = BoundedHealthProbe::new(budget());
        let calls = Arc::new(AtomicU32::new(0));
        for _ in 0..10 {
            let calls = Arc::clone(&calls);
            assert_eq!(
                probe.poll(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    true
                }),
                ProbeOutcome::Ready
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "ten polls inside one min_interval must cost exactly one real check; \
             this is the status-poll amplification guard"
        );
    }

    #[test]
    fn a_completed_negative_check_latches_lost_permanently() {
        let probe = BoundedHealthProbe::new(budget());
        assert_eq!(probe.poll(|| false), ProbeOutcome::Lost);
        // Even a later TRUE check cannot un-latch: ownership was provably lost.
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(probe.poll(|| true), ProbeOutcome::Lost);
    }

    /// FAIL-BEFORE for the "one timeout latches health failure permanently"
    /// defect: a single deadline overrun must be INDETERMINATE and must be
    /// recoverable by the next successful check.
    #[test]
    fn a_single_timeout_is_unavailable_and_recovers_on_the_next_check() {
        // A LARGE indeterminate budget on purpose: this test is about recovery,
        // and the fail-closed latch is a separate property with its own test.
        // With the default budget of 3, the polling loop below would exhaust it
        // and latch `Lost` legitimately, testing the wrong thing.
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(200),
            min_interval: Duration::from_millis(50),
            max_consecutive_unavailable: u32::MAX,
        });
        assert_eq!(
            probe.poll(|| {
                std::thread::sleep(Duration::from_millis(400));
                true
            }),
            ProbeOutcome::Unavailable,
            "a deadline overrun is indeterminate, not a proven loss"
        );
        // The abandoned worker still owns the slot, so recovery happens when the
        // wedged check RETURNS, not when a caller gives up. Poll until it does,
        // under a generous overall bound: a fixed sleep here would make the test
        // fail on a loaded machine for a reason that has nothing to do with the
        // property (the worker finishing late), which is a manufactured flake.
        let recovered_at = Instant::now();
        loop {
            match probe.poll(|| true) {
                ProbeOutcome::Ready => break,
                other => {
                    assert_eq!(
                        other,
                        ProbeOutcome::Unavailable,
                        "recovery must never pass through a proven loss"
                    );
                    assert!(
                        recovered_at.elapsed() < Duration::from_secs(5),
                        "a healthy runtime must recover once the wedged check returns"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// The fail-closed backstop for the same seam: indeterminate is bounded, so a
    /// permanently wedged check cannot hold the daemon in "unknown" forever.
    /// Note the SHAPE this now takes: after the first overrun the later polls
    /// never start a check at all, they observe the wedged one.
    #[test]
    fn consecutive_timeouts_exhaust_the_indeterminate_budget_and_latch_lost() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(30),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 3,
        });
        let wedged = || {
            std::thread::sleep(Duration::from_millis(400));
            true
        };
        assert_eq!(probe.poll(wedged), ProbeOutcome::Unavailable);
        // Past the 30ms deadline, so the still-running check reads as wedged.
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(probe.poll(wedged), ProbeOutcome::Unavailable);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            probe.poll(wedged),
            ProbeOutcome::Lost,
            "the third consecutive indeterminate reading must fail closed"
        );
    }

    /// ADVERSARIAL SCHEDULING (AGENTS rule 12): concurrent pollers must not each
    /// fork a check. The in-flight guard is what bounds work per request wave.
    #[test]
    fn concurrent_pollers_run_exactly_one_real_check() {
        let probe = Arc::new(BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_secs(2),
            min_interval: Duration::from_millis(500),
            max_consecutive_unavailable: 3,
        }));
        let calls = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let probe = Arc::clone(&probe);
            let calls = Arc::clone(&calls);
            handles.push(std::thread::spawn(move || {
                probe.poll(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(120));
                    true
                })
            }));
        }
        let outcomes: Vec<ProbeOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "eight concurrent pollers must fork exactly one check (single-flight)"
        );
        assert!(
            outcomes.contains(&ProbeOutcome::Ready),
            "the winning poller must observe the completed check"
        );
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, ProbeOutcome::Ready | ProbeOutcome::Unavailable)),
            "a losing concurrent poller reports indeterminate, never a false loss"
        );
    }

    /// A burst of healthy concurrent pollers must not consume the fail-closed
    /// budget. Before the count/no-count split, every in-flight observation was a
    /// candidate for counting, and 3+ concurrent callers of a perfectly healthy
    /// runtime would have latched `Lost`.
    #[test]
    fn a_burst_of_healthy_concurrent_pollers_never_manufactures_a_loss() {
        let probe = Arc::new(BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_secs(2),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 3,
        }));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let probe = Arc::clone(&probe);
            handles.push(std::thread::spawn(move || {
                probe.poll(|| {
                    std::thread::sleep(Duration::from_millis(150));
                    true
                })
            }));
        }
        let outcomes: Vec<ProbeOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            !outcomes.contains(&ProbeOutcome::Lost),
            "sixteen concurrent polls of a HEALTHY runtime must not exhaust the \
             indeterminate budget; only a check proven past its deadline counts"
        );
        assert_eq!(
            probe.poll(|| true),
            ProbeOutcome::Ready,
            "and the probe must still be usable afterwards"
        );
    }

    #[test]
    fn a_panicking_check_is_indeterminate_not_ready() {
        let probe = BoundedHealthProbe::new(budget());
        // A panicked worker unwinds through the drop guard, which releases the
        // slot with no reading. That must read as "no answer", never as healthy.
        let outcome = probe.poll(|| panic!("probe worker exploded"));
        assert_eq!(outcome, ProbeOutcome::Unavailable);
        assert_ne!(outcome, ProbeOutcome::Ready);
    }

    /// A panicking check must not leak the in-flight slot: if it did, the probe
    /// would be jammed at `Unavailable` for the process lifetime by one panic.
    #[test]
    fn a_panicking_check_releases_the_slot_for_the_next_poll() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(200),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 10,
        });
        assert_eq!(
            probe.poll(|| panic!("probe worker exploded")),
            ProbeOutcome::Unavailable
        );
        assert_eq!(
            probe.poll(|| true),
            ProbeOutcome::Ready,
            "the slot must be released on the unwind path, not only on success"
        );
    }

    /// FAIL-BEFORE for the defect this rewrite removes (AGENTS rule 12,
    /// adversarial fault scheduling). A wedged check followed by later polls must
    /// fork EXACTLY ONE subprocess. The previous implementation cleared the
    /// in-flight flag on its own deadline path while the worker ran on, so each
    /// later poll started another one; this test observed 3 and would fail.
    #[test]
    fn a_wedged_check_is_never_joined_by_a_second_fork() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(40),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 100,
        });
        let forks = Arc::new(AtomicU32::new(0));
        let wedged = {
            let forks = Arc::clone(&forks);
            move || {
                forks.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(600));
                true
            }
        };
        assert_eq!(probe.poll(wedged.clone()), ProbeOutcome::Unavailable);
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(30));
            assert_eq!(probe.poll(wedged.clone()), ProbeOutcome::Unavailable);
        }
        assert_eq!(
            forks.load(Ordering::SeqCst),
            1,
            "a wedged check keeps the in-flight slot until it terminates; six \
             polls against one wedged resource must fork exactly one `nft`"
        );
    }

    /// The recovery half of the same schedule: once the wedged check finally
    /// returns, the probe must be usable again rather than stuck.
    #[test]
    fn a_wedged_check_that_finally_returns_restores_the_probe() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(30),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 100,
        });
        assert_eq!(
            probe.poll(|| {
                std::thread::sleep(Duration::from_millis(200));
                true
            }),
            ProbeOutcome::Unavailable
        );
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            probe.poll(|| true),
            ProbeOutcome::Ready,
            "the slot returns to the pool when the check terminates, not when a \
             caller gives up waiting for it"
        );
    }

    /// The caller's deadline must hold even though the worker keeps the slot:
    /// "bounded" is about the CALLING thread, and shutdown responsiveness
    /// depends on it.
    #[test]
    fn the_caller_returns_within_its_deadline_even_against_a_wedged_worker() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(50),
            min_interval: Duration::ZERO,
            max_consecutive_unavailable: 100,
        });
        let started = Instant::now();
        assert_eq!(
            probe.poll(|| {
                std::thread::sleep(Duration::from_millis(800));
                true
            }),
            ProbeOutcome::Unavailable
        );
        let first = started.elapsed();
        assert!(
            first < Duration::from_millis(500),
            "the first poll blocked {first:?}, past its 50ms deadline"
        );
        // A LATER poll against the same wedged worker must return effectively
        // immediately: it observes the slot rather than waiting on it.
        let second_started = Instant::now();
        assert_eq!(probe.poll(|| true), ProbeOutcome::Unavailable);
        let second = second_started.elapsed();
        assert!(
            second < Duration::from_millis(50),
            "a poll that found a check already in flight blocked {second:?}; it \
             must not wait on someone else's check"
        );
    }

    #[test]
    fn explicit_command_failure_is_indeterminate_not_a_cached_negative() {
        let probe = BoundedHealthProbe::new(ProbeBudget {
            timeout: Duration::from_millis(100),
            min_interval: Duration::from_secs(60),
            max_consecutive_unavailable: 3,
        });
        assert_eq!(probe.poll_result(|| Err(())), ProbeOutcome::Unavailable);
        assert_eq!(
            probe.poll_result(|| Ok(true)),
            ProbeOutcome::Ready,
            "an invocation/I/O failure must not be cached as a proven loss"
        );
    }
}
