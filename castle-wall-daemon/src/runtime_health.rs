//! The published kernel-runtime health view read by authenticated status IPC.
//!
//! ## Why a published view rather than a live probe on the IPC thread
//!
//! Status used to be answered by locking the shared `EnforcementRuntime` mutex
//! from the IPC handler and re-polling component readiness inline. Two defects
//! followed from that, and this module exists to remove both:
//!
//! * **Contention read as loss.** The supervisor holds the runtime mutex while a
//!   bounded `nft` ownership proof runs. A status query landing in that window
//!   got `try_lock() == Err`, which was folded to `false` and reported a healthy
//!   runtime as `degraded`. Contention is INDETERMINATE, not loss; conflating the
//!   two makes the health signal flap in exactly the deployment it was added for.
//! * **Status-poll amplification.** Every status request forked an `nft`
//!   subprocess, so an authenticated poller could drive probe load and push a real
//!   check past its deadline.
//!
//! The supervision loop is now the SOLE writer: it probes on its own cadence and
//! publishes the result here. IPC only reads, and a read is a struct copy under a
//! mutex held for nanoseconds. A reader that still cannot take that lock, or that
//! finds the published observation older than its freshness bound, reports
//! [`RuntimeHealthState::ProbeUnavailable`] — explicitly indeterminate, never
//! promoted to healthy and never reported as a loss.
//!
//! ## Fail-closed direction
//!
//! `ProbeUnavailable` withholds the `kernel_runtime_ready` / `enforcing`
//! assertions (absent reads as not-proven), but does NOT assert `degraded`.
//! `Lost` is the only state that asserts a runtime failure, and it is only ever
//! published from a COMPLETED negative proof or an exhausted indeterminate budget
//! (see [`crate::health_probe`]).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::enforcement::NotReadyReason;

/// Freshness bound a status reader applies to the published observation. Derived
/// from the supervisor cadence: `main.rs` republishes every `HEALTH_INTERVAL`
/// (2s), so anything older than three intervals means the supervisor itself has
/// stopped publishing and the reading is no longer evidence about now.
pub const STATUS_FRESHNESS_WINDOW: Duration = Duration::from_secs(6);

/// What the daemon last positively observed about its kernel runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHealthState {
    /// This daemon holds no kernel runtime at all (control-plane-only host).
    /// Honest absence, not a failure: there is nothing to lose.
    NoRuntime,
    /// Every required component was proven ready at `observed_at`.
    Ready,
    /// A required component was PROVEN lost, with the reason that proved it.
    Lost(NotReadyReason),
    /// No conclusion is available: the probe was in flight, timed out, or the
    /// view could not be read. Indeterminate — never treat as ready or as lost.
    ProbeUnavailable,
}

impl RuntimeHealthState {
    /// Stable wire token for the authenticated status projection. Kept in one
    /// place so the daemon and `server/src/castle-wall/ipc/messages.ts` cannot
    /// drift; must match `RuntimeHealthToken` in that file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRuntime => "no_runtime",
            Self::Ready => "ready",
            Self::Lost(_) => "lost",
            Self::ProbeUnavailable => "probe_unavailable",
        }
    }
}

/// One published observation plus its age, as a reader sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHealthReading {
    pub state: RuntimeHealthState,
    /// How long ago the observation was published. `None` when nothing has been
    /// published yet, or when the view could not be read.
    pub age: Option<Duration>,
}

impl RuntimeHealthReading {
    /// True only for a fresh, positive readiness proof. Deliberately false for
    /// `ProbeUnavailable` and for a stale `Ready`, so the status projection can
    /// never assert kernel readiness it has not currently proven.
    pub fn proves_ready(&self) -> bool {
        matches!(self.state, RuntimeHealthState::Ready)
    }
}

/// Single-writer / many-reader publication point for kernel-runtime health.
#[derive(Debug)]
pub struct RuntimeHealthView {
    inner: Mutex<Option<(Instant, RuntimeHealthState)>>,
}

impl Default for RuntimeHealthView {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeHealthView {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Publish an observation. Called by boot (initial state) and by the
    /// supervision loop on every health tick. The lock is held only for the
    /// duration of a two-word write, so a reader's `try_lock` effectively never
    /// misses; a miss is still handled honestly in [`read`](Self::read).
    pub fn publish(&self, state: RuntimeHealthState) {
        if let Ok(mut slot) = self.inner.lock() {
            *slot = Some((Instant::now(), state));
        }
        // A poisoned view is not silently repaired: the next `read` sees the
        // poison and reports `ProbeUnavailable`, which is the fail-closed
        // direction (no readiness assertion), so there is nothing to recover here.
    }

    /// Read the published observation under a freshness bound. Never blocks and
    /// never probes.
    pub fn read(&self, max_age: Duration) -> RuntimeHealthReading {
        // `try_lock` (not `lock`): the IPC thread must never be able to block on
        // the publisher, because a blocked status handler is itself a liveness
        // defect. A miss is indeterminate, which is why contention no longer
        // manufactures a `degraded` verdict.
        let Ok(slot) = self.inner.try_lock() else {
            return RuntimeHealthReading {
                state: RuntimeHealthState::ProbeUnavailable,
                age: None,
            };
        };
        match *slot {
            None => RuntimeHealthReading {
                state: RuntimeHealthState::ProbeUnavailable,
                age: None,
            },
            Some((at, state)) => {
                let age = at.elapsed();
                // `NoRuntime` is a structural fact about this boot, not an
                // observation that decays: a control-plane-only daemon never
                // acquires a runtime later, so ageing it out would manufacture a
                // spurious "unknown" on an honestly non-enforcing host.
                if state != RuntimeHealthState::NoRuntime && age > max_age {
                    return RuntimeHealthReading {
                        state: RuntimeHealthState::ProbeUnavailable,
                        age: Some(age),
                    };
                }
                RuntimeHealthReading {
                    state,
                    age: Some(age),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::ComponentKind;

    #[test]
    fn an_unpublished_view_is_indeterminate_never_ready() {
        let view = RuntimeHealthView::new();
        let reading = view.read(STATUS_FRESHNESS_WINDOW);
        assert_eq!(reading.state, RuntimeHealthState::ProbeUnavailable);
        assert!(!reading.proves_ready());
    }

    #[test]
    fn a_published_ready_state_reads_ready_and_carries_an_age() {
        let view = RuntimeHealthView::new();
        view.publish(RuntimeHealthState::Ready);
        let reading = view.read(STATUS_FRESHNESS_WINDOW);
        assert_eq!(reading.state, RuntimeHealthState::Ready);
        assert!(reading.proves_ready());
        assert!(reading.age.is_some());
    }

    /// A `Ready` observation is evidence about WHEN it was taken. Past the
    /// freshness bound it must stop asserting readiness rather than being
    /// replayed as current truth.
    #[test]
    fn a_stale_ready_observation_reads_indeterminate_not_ready() {
        let view = RuntimeHealthView::new();
        view.publish(RuntimeHealthState::Ready);
        std::thread::sleep(Duration::from_millis(20));
        let reading = view.read(Duration::from_millis(1));
        assert_eq!(reading.state, RuntimeHealthState::ProbeUnavailable);
        assert!(!reading.proves_ready());
    }

    #[test]
    fn a_control_plane_only_boot_does_not_age_into_unknown() {
        let view = RuntimeHealthView::new();
        view.publish(RuntimeHealthState::NoRuntime);
        std::thread::sleep(Duration::from_millis(20));
        let reading = view.read(Duration::from_millis(1));
        assert_eq!(
            reading.state,
            RuntimeHealthState::NoRuntime,
            "holding no runtime is a fact about this boot, not a decaying observation"
        );
        assert!(!reading.proves_ready());
    }

    #[test]
    fn a_proven_loss_is_reported_as_loss_with_its_reason() {
        let view = RuntimeHealthView::new();
        view.publish(RuntimeHealthState::Lost(NotReadyReason::ComponentLost(
            ComponentKind::NftablesTable,
        )));
        let reading = view.read(STATUS_FRESHNESS_WINDOW);
        assert_eq!(
            reading.state,
            RuntimeHealthState::Lost(NotReadyReason::ComponentLost(ComponentKind::NftablesTable))
        );
        assert_eq!(reading.state.as_str(), "lost");
        assert!(!reading.proves_ready());
    }

    /// The defect this module removes, pinned as a test: an indeterminate probe
    /// must NOT surface as a loss. `probe_unavailable` and `lost` are distinct
    /// wire tokens precisely so a consumer can tell contention from failure.
    #[test]
    fn indeterminate_is_never_collapsed_into_loss() {
        let view = RuntimeHealthView::new();
        view.publish(RuntimeHealthState::ProbeUnavailable);
        let reading = view.read(STATUS_FRESHNESS_WINDOW);
        assert_eq!(reading.state.as_str(), "probe_unavailable");
        assert_ne!(reading.state.as_str(), "lost");
        assert!(!reading.proves_ready());
    }
}
