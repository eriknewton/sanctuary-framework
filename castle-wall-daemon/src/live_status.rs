//! Shared, read-only IPC projection of daemon lifecycle truth.

use std::sync::Mutex;
use std::time::Instant;

use crate::daemon::DaemonRuntimeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    Activating,
    Running,
    Degraded,
    Stopping,
}

impl LifecyclePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activating => "activating",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Stopping => "stopping",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MutableStatus {
    phase: LifecyclePhase,
    runtime_state: DaemonRuntimeState,
}

/// Whether THIS daemon can engage the operator's no-wall emergency bypass.
///
/// It cannot. The Linux daemon has no verb, IPC message, signal, or lifecycle
/// transition that engages no-wall mode; `DaemonConfig::no_wall_max_duration` is
/// carried for parity with the macOS provider and is not consumed here.
///
/// This is a named constant rather than an inline `false` because the previous
/// shape was worse than either: `LiveStatus` carried a mutable
/// `no_wall_engaged` field whose ONLY writer was a `#[cfg(test)]` setter, so the
/// production status always shipped `false` while the consumer carried an
/// invariant comment calling the field "the operator's explicit emergency bypass
/// [that] dominates every readiness claim". That is a live-protection claim over
/// a field no production path can set — a test-only field presented as shipped
/// protection (AGENTS rule 9: the unit of "shipped" is the claim atom).
///
/// The wire field itself stays: `no_wall_engaged` is pre-v2 surface that the
/// macOS provider populates for real, and the consumer's precedence rule is
/// written for that producer. What is removed is any suggestion that the LINUX
/// daemon participates. When a real Linux no-wall transition is built, replace
/// this constant with the state it sets and delete this paragraph.
const LINUX_DAEMON_ENGAGES_NO_WALL: bool = false;

#[derive(Debug, Clone, Copy)]
pub struct LiveStatusSnapshot {
    pub uptime_seconds: u64,
    pub lifecycle_state: &'static str,
    pub runtime_state: &'static str,
    pub kernel_runtime_ready: bool,
    pub enforcing: bool,
    /// Always [`LINUX_DAEMON_ENGAGES_NO_WALL`]. See that constant: this daemon
    /// has no no-wall transition, and the value is a structural fact rather than
    /// an observation.
    pub no_wall_engaged: bool,
}

/// One status source shared by daemon lifecycle and authenticated IPC.
pub struct LiveStatus {
    started_at: Instant,
    mutable: Mutex<MutableStatus>,
}

impl LiveStatus {
    pub fn activating() -> Self {
        Self {
            started_at: Instant::now(),
            mutable: Mutex::new(MutableStatus {
                phase: LifecyclePhase::Activating,
                runtime_state: DaemonRuntimeState::ControlPlaneOnly,
            }),
        }
    }

    pub fn update(&self, phase: LifecyclePhase, runtime_state: DaemonRuntimeState) {
        if let Ok(mut status) = self.mutable.lock() {
            status.phase = phase;
            status.runtime_state = runtime_state;
        }
    }

    pub fn snapshot(&self) -> LiveStatusSnapshot {
        let status = self
            .mutable
            .lock()
            .map(|guard| *guard)
            .unwrap_or(MutableStatus {
                phase: LifecyclePhase::Degraded,
                runtime_state: DaemonRuntimeState::Degraded,
            });
        let running = status.phase == LifecyclePhase::Running;
        LiveStatusSnapshot {
            uptime_seconds: self.started_at.elapsed().as_secs(),
            lifecycle_state: status.phase.as_str(),
            runtime_state: status.runtime_state.as_str(),
            kernel_runtime_ready: running
                && matches!(
                    status.runtime_state,
                    DaemonRuntimeState::KernelRuntimeReady | DaemonRuntimeState::Enforcing
                ),
            enforcing: running && status.runtime_state == DaemonRuntimeState::Enforcing,
            no_wall_engaged: LINUX_DAEMON_ENGAGES_NO_WALL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_control_plane_and_teardown_never_claim_health() {
        let status = LiveStatus::activating();
        let activating = status.snapshot();
        assert_eq!(activating.lifecycle_state, "activating");
        assert!(!activating.kernel_runtime_ready);
        assert!(!activating.enforcing);

        status.update(
            LifecyclePhase::Running,
            DaemonRuntimeState::ControlPlaneOnly,
        );
        let control_only = status.snapshot();
        assert_eq!(control_only.runtime_state, "control_plane_only");
        assert!(!control_only.kernel_runtime_ready);
        assert!(!control_only.enforcing);

        status.update(LifecyclePhase::Stopping, DaemonRuntimeState::Stopping);
        let stopping = status.snapshot();
        assert_eq!(stopping.lifecycle_state, "stopping");
        assert!(!stopping.kernel_runtime_ready);
        assert!(!stopping.enforcing);
    }

    #[test]
    fn kernel_runtime_is_distinct_from_enforcement() {
        let status = LiveStatus::activating();
        status.update(
            LifecyclePhase::Running,
            DaemonRuntimeState::KernelRuntimeReady,
        );
        let runtime = status.snapshot();
        assert!(runtime.kernel_runtime_ready);
        assert!(!runtime.enforcing);
    }

    /// Pins the honesty bound rather than a behavior: this daemon has NO no-wall
    /// transition, so the field is a structural `false` on every reachable
    /// lifecycle state. It replaces a test that used a `#[cfg(test)]` setter to
    /// "prove" no-wall was live — a test that could only ever have passed,
    /// because the setter was the field's only writer in any build.
    ///
    /// If a real Linux no-wall path is ever built, this test FAILS to compile or
    /// to hold, which is the intended prompt to update the claim on both sides.
    #[test]
    fn this_daemon_never_engages_no_wall_on_any_lifecycle_state() {
        // A COMPILE-TIME assertion, so removing the constant or flipping it to
        // `true` without building the transition fails the build rather than one
        // test run. (`assert!` on a constant is also what clippy flags as a
        // runtime assertion that can never vary.)
        const _: () = assert!(!LINUX_DAEMON_ENGAGES_NO_WALL);
        let status = LiveStatus::activating();
        for (phase, runtime_state) in [
            (
                LifecyclePhase::Activating,
                DaemonRuntimeState::ControlPlaneOnly,
            ),
            (
                LifecyclePhase::Running,
                DaemonRuntimeState::KernelRuntimeReady,
            ),
            (LifecyclePhase::Running, DaemonRuntimeState::Enforcing),
            (LifecyclePhase::Degraded, DaemonRuntimeState::Degraded),
            (LifecyclePhase::Stopping, DaemonRuntimeState::Stopping),
        ] {
            status.update(phase, runtime_state);
            assert!(
                !status.snapshot().no_wall_engaged,
                "the Linux daemon has no no-wall transition; reporting `true` \
                 from {phase:?}/{runtime_state:?} would be a fabricated claim"
            );
        }
    }
}
