//! Guard T (the stop guard) and the single process-exit gate.
//!
//! Register ids: `LINUX-STOP-PATH-BUDGET-01` (the stop path is bounded by this
//! guard's deadline, not by a sum of per-step bounds).
//!
//! ## What this module guarantees
//!
//! Once the daemon binary's `main` has called [`enable_process_guard`], every
//! stop REQUEST and every audited supervision decision arms one `alarm(2)`. The
//! process then ends no later than the armed deadline after the EARLIEST request,
//! by exactly one of three claimants, which all pass through one compare-exchange
//! on [`ExitGuard::exit_state`]:
//!
//! * `main` returning normally ([`claim_return`], state `EXIT_RETURNING`);
//! * the NFQUEUE verdict fail-stop ([`terminate_with_decided_code`]);
//! * the `SIGALRM` handler ([`on_stop_guard_alarm`]), which `_exit`s with the
//!   decided code.
//!
//! No thread is spawned: `alarm` cannot fail and is async-signal-safe, so the
//! SIGTERM handler itself can arm it and there is no spawn that could fail.
//!
//! ## Named states
//!
//! `guard_state`: `GUARD_DISABLED` (library and in-process test use; arming is a
//! no-op), `GUARD_IDLE` (the binary enabled the guard, no stop requested yet),
//! `GUARD_ARMED` (an alarm is pending; never re-armed, so the deadline can never
//! be extended).
//!
//! `exit_state`: `EXIT_OPEN`, `EXIT_TERMINATING` (one terminator won and is in
//! `_exit`), `EXIT_RETURNING` (`main` won and is returning through the Rust
//! runtime).
//!
//! In-process tests never arm a real alarm: they drive a local [`ExitGuard`]
//! through the pure methods with a recording [`AlarmBackend`], and only the
//! daemon binary's `main` ever calls [`enable_process_guard`].

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

/// Must match `TimeoutStopSec=` in `systemd/sanctuary-castle-wall.service`
/// (pinned by `tests/systemd_unit.rs::unit_bounds_shutdown_and_kills_wedged_health_children`).
pub const STOP_GUARD_TIMEOUT_STOP_SECS: u32 = 10;

/// Two whole-second allowances between the guard's deadline and systemd's
/// SIGKILL: one for SIGTERM delivery and handler entry on a loaded host (when the
/// guard's clock starts), one for `SIGALRM` delivery, handler entry and
/// `exit_group` (when it ends). So the guard's `_exit` lands before systemd's
/// SIGKILL and `Result=` shows the guard's code, not `signal`.
pub const STOP_GUARD_MARGIN_SECS: u32 = 2;

/// The deadline the production guard arms: 8 = 10 - 2.
pub const STOP_GUARD_DEADLINE_SECS: u32 = STOP_GUARD_TIMEOUT_STOP_SECS - STOP_GUARD_MARGIN_SECS;

/// `EX_TEMPFAIL` from `sysexits.h`, the code this daemon already uses for "stop
/// did not complete". Must match the nonzero arms of
/// `crate::daemon::supervision_exit_status`.
pub const EXIT_CODE_STOP_INCOMPLETE: u8 = 75;

/// `guard_state`: library or in-process test use; `arm` does nothing.
pub const GUARD_DISABLED: u8 = 0;
/// `guard_state`: the daemon binary enabled the guard; no stop requested yet.
pub const GUARD_IDLE: u8 = 1;
/// `guard_state`: an alarm is pending.
pub const GUARD_ARMED: u8 = 2;

/// `exit_state`: no claimant has won.
pub const EXIT_OPEN: u8 = 0;
/// `exit_state`: a terminator (handler or verdict fail-stop) won and is in `_exit`.
pub const EXIT_TERMINATING: u8 = 1;
/// `exit_state`: `main` won and is returning through the Rust runtime.
pub const EXIT_RETURNING: u8 = 2;

/// What the `SIGALRM` handler must do, decided purely from the cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAction {
    /// This handler won the exit gate: `_exit` with this code.
    Terminate(u8),
    /// Another claimant already won; return and let it finish.
    Return,
}

/// Where `arm` sends its deadline. Production uses the real `alarm(2)`; unit
/// tests pass a recording backend so no in-process test ever schedules a
/// process-directed signal.
pub trait AlarmBackend {
    /// Schedule the stop guard's alarm `secs` seconds from now.
    fn schedule(&self, secs: u32);
}

/// The process's cells. One process-global instance ([`PROCESS_EXIT_GUARD`]);
/// unit tests construct local instances so parallel tests never share state.
#[derive(Debug)]
pub struct ExitGuard {
    guard_state: AtomicU8,
    exit_state: AtomicU8,
    /// INVARIANT: the guard fires only because a stop did not complete, so
    /// `stop_succeeded = false` is the only true argument to
    /// `supervision_exit_status` here; every variant maps nonzero (78/75/75/75),
    /// so a guard exit can never read `Result=success`. Stored with `Release`
    /// and loaded with `Acquire` by every terminator, so a terminator that sees
    /// the stored code also sees every write that preceded the decision.
    decided_code: AtomicU8,
    /// `0` until [`ExitGuard::enable`] stores the deadline, which happens BEFORE
    /// `guard_state` moves to IDLE (Release); read by `arm_with` only after it
    /// wins IDLE to ARMED (Acquire).
    deadline_secs: AtomicU32,
}

impl Default for ExitGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitGuard {
    pub const fn new() -> Self {
        Self {
            guard_state: AtomicU8::new(GUARD_DISABLED),
            exit_state: AtomicU8::new(EXIT_OPEN),
            decided_code: AtomicU8::new(EXIT_CODE_STOP_INCOMPLETE),
            deadline_secs: AtomicU32::new(0),
        }
    }

    /// DISABLED to IDLE, with the deadline stored first. Returns whether this
    /// call performed the transition (a second enable is a no-op).
    pub fn enable(&self, deadline_secs: u32) -> bool {
        if self.guard_state.load(Ordering::Acquire) != GUARD_DISABLED {
            return false;
        }
        self.deadline_secs.store(deadline_secs, Ordering::Release);
        self.guard_state
            .compare_exchange(
                GUARD_DISABLED,
                GUARD_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// IDLE to ARMED; only the winner schedules the alarm. A second request never
    /// re-arms, so the deadline is measured from the EARLIEST request and can
    /// never be extended. In DISABLED it does nothing. Async-signal-safe (atomics
    /// plus the backend's `alarm`). Returns whether this call armed.
    pub fn arm_with<B: AlarmBackend + ?Sized>(&self, backend: &B) -> bool {
        if self
            .guard_state
            .compare_exchange(GUARD_IDLE, GUARD_ARMED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        backend.schedule(self.deadline_secs.load(Ordering::Acquire));
        true
    }

    /// Store the code every non-returning terminator will use.
    pub fn decide(&self, code: u8) {
        self.decided_code.store(code, Ordering::Release);
    }

    pub fn decided_code(&self) -> u8 {
        self.decided_code.load(Ordering::Acquire)
    }

    pub fn guard_state(&self) -> u8 {
        self.guard_state.load(Ordering::Acquire)
    }

    pub fn exit_state(&self) -> u8 {
        self.exit_state.load(Ordering::Acquire)
    }

    /// OPEN to TERMINATING, shared by both terminators. Returns the decided code
    /// to the winner and `None` to a loser.
    fn claim_terminate(&self) -> Option<u8> {
        // INVARIANT (single-winner exit gate): every non-returning exit in the
        // daemon crate must win this one compare-exchange; a loser never exits,
        // so the guard, the verdict fail-stop and `main`'s return cannot race.
        self.exit_state
            .compare_exchange(
                EXIT_OPEN,
                EXIT_TERMINATING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| self.decided_code())
    }

    /// The `SIGALRM` handler's pure decision.
    pub fn alarm_action(&self) -> AlarmAction {
        match self.claim_terminate() {
            Some(code) => AlarmAction::Terminate(code),
            None => AlarmAction::Return,
        }
    }

    /// The verdict fail-stop's pure decision: `Some(code)` to the winner.
    pub fn terminate_action(&self) -> Option<u8> {
        self.claim_terminate()
    }

    /// `main`'s pure decision: OPEN to RETURNING; `true` to the winner.
    pub fn claim_return_action(&self) -> bool {
        self.exit_state
            .compare_exchange(
                EXIT_OPEN,
                EXIT_RETURNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// The one process-global guard. DISABLED until the daemon binary's `main` calls
/// [`enable_process_guard`].
pub static PROCESS_EXIT_GUARD: ExitGuard = ExitGuard::new();

/// The real `alarm(2)` backend.
struct SystemAlarm;

impl AlarmBackend for SystemAlarm {
    fn schedule(&self, secs: u32) {
        // TEST-ISOLATION ONLY: a fixed line the T3w subprocess harness timestamps as
        // the arm instant. A raw write(2) is async-signal-safe and allocates nothing,
        // so it is legal inside the SIGTERM handler that may be the arming caller.
        // Compiled out of release builds.
        #[cfg(all(unix, feature = "test-isolation"))]
        {
            const MARKER: &[u8] = b"castle-wall-daemon: stop guard armed\n";
            // SAFETY: fd 2 is the process's stderr; the pointer/length pair names a
            // static byte string. A short or failed write only loses the marker.
            unsafe {
                let _ = libc::write(2, MARKER.as_ptr().cast(), MARKER.len());
            }
        }
        #[cfg(unix)]
        // SAFETY: alarm(2) has no failure return and is async-signal-safe.
        unsafe {
            libc::alarm(secs);
        }
        #[cfg(not(unix))]
        let _ = secs;
    }
}

/// Arm the process guard. Idempotent; a no-op before `enable_process_guard`.
pub fn arm() {
    PROCESS_EXIT_GUARD.arm_with(&SystemAlarm);
}

/// Store `code` as the decided exit code, then arm. Called at every audited
/// supervision decision BEFORE its WAL write, so a hang in that write is inside
/// the deadline.
pub fn decide_and_arm(code: u8) {
    PROCESS_EXIT_GUARD.decide(code);
    arm();
}

/// The ONLY production writer of the daemon stop-request flag: store, then arm.
/// Both steps are async-signal-safe, so the SIGTERM handler calls this directly
/// and the guard's clock starts at the same instant as systemd's `TimeoutStopSec`.
pub fn request_daemon_stop(flag: &AtomicBool) {
    flag.store(true, Ordering::SeqCst);
    arm();
}

/// `SIGALRM` handler: the guard's deadline passed without the process exiting.
extern "C" fn on_stop_guard_alarm(_signum: libc::c_int) {
    // INVARIANT: async-signal-safe only (atomics and _exit, premises P6/P7). A
    // handler that parks or takes a lock could stall the thread it interrupted,
    // which may itself be the exit winner, so a loser RETURNS and lets the winner
    // finish.
    match PROCESS_EXIT_GUARD.alarm_action() {
        // SAFETY: _exit ends every thread (exit_group) without running Drop,
        // unwinding or atexit handlers, which is exactly the point here.
        AlarmAction::Terminate(code) => unsafe { libc::_exit(libc::c_int::from(code)) },
        AlarmAction::Return => {}
    }
}

/// Install the `SIGALRM` handler, unblock `SIGALRM` on the calling thread, and
/// move the process guard DISABLED to IDLE with `deadline_secs`.
///
/// Called ONLY from the daemon binary's `main`, after argv parsing and before
/// `daemon::boot`, i.e. before any daemon thread exists: every thread boot spawns
/// inherits this thread's unblocked mask, so `SIGALRM` can be delivered to any of
/// them (premise P9). A failure here refuses start with 75.
#[cfg(unix)]
pub fn enable_process_guard(deadline_secs: u32) -> Result<(), String> {
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    // SA_RESTART so a syscall interrupted by a LOSER handler (one that returns)
    // restarts; `poll(2)` is not restarted by it and loops on EINTR at its site.
    let action = SigAction::new(
        SigHandler::Handler(on_stop_guard_alarm),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    // SAFETY: the handler is async-signal-safe (atomics and _exit only).
    unsafe { sigaction(Signal::SIGALRM, &action) }
        .map_err(|e| format!("cannot install the stop-guard SIGALRM handler: {e}"))?;
    let mut unblock = SigSet::empty();
    unblock.add(Signal::SIGALRM);
    // INVARIANT (premise P7): this is the ONLY signal-mask change in the crate,
    // and it UNBLOCKS; a block anywhere else could leave SIGALRM pending forever
    // and the guard inert. Pinned by the T15 structural test.
    unblock
        .thread_unblock()
        .map_err(|e| format!("cannot unblock SIGALRM for the stop guard: {e}"))?;
    PROCESS_EXIT_GUARD.enable(deadline_secs);
    Ok(())
}

#[cfg(not(unix))]
pub fn enable_process_guard(deadline_secs: u32) -> Result<(), String> {
    let _ = deadline_secs;
    Err("the stop guard requires a Unix host".to_string())
}

/// The verdict fail-stop's exit: win the gate and `_exit(decided_code)`, or park
/// forever because the winner is already exiting.
pub fn terminate_with_decided_code() -> ! {
    if let Some(code) = PROCESS_EXIT_GUARD.terminate_action() {
        // SAFETY: see `on_stop_guard_alarm`; no Rust cleanup is owed on this path
        // (no atexit in the crate, stderr is unbuffered).
        unsafe { libc::_exit(libc::c_int::from(code)) }
    }
    park_forever()
}

/// `main`'s claim before it returns. The winner cancels a pending alarm with
/// `alarm(0)` and returns; the Rust runtime tail after this (residual R-TAIL) is
/// deliberately not under the guard. A loser parks: a terminator already won.
pub fn claim_return() {
    if PROCESS_EXIT_GUARD.claim_return_action() {
        #[cfg(unix)]
        // SAFETY: alarm(0) cancels any pending alarm; it cannot fail.
        unsafe {
            libc::alarm(0);
        }
        return;
    }
    park_forever()
}

fn park_forever() -> ! {
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every scheduled deadline instead of calling `alarm(2)`.
    #[derive(Default)]
    struct RecordingAlarm {
        scheduled: Mutex<Vec<u32>>,
    }

    impl AlarmBackend for RecordingAlarm {
        fn schedule(&self, secs: u32) {
            self.scheduled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(secs);
        }
    }

    impl RecordingAlarm {
        fn calls(&self) -> Vec<u32> {
            self.scheduled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    /// T2 (LINUX-STOP-PATH-BUDGET-01): the deadline is derived from the unit's
    /// stop timeout minus a margin of at least two whole seconds.
    #[test]
    fn t2_deadline_is_timeout_minus_margin_and_the_margin_is_at_least_two() {
        assert_eq!(
            STOP_GUARD_DEADLINE_SECS,
            STOP_GUARD_TIMEOUT_STOP_SECS - STOP_GUARD_MARGIN_SECS
        );
        const _: () = assert!(STOP_GUARD_MARGIN_SECS >= 2);
        const _: () = assert!(STOP_GUARD_DEADLINE_SECS >= 1);
        let margin = STOP_GUARD_MARGIN_SECS;
        assert!(
            margin >= 2,
            "a margin under two seconds lets systemd's SIGKILL win"
        );
        let deadline = STOP_GUARD_DEADLINE_SECS;
        assert!(deadline >= 1, "a zero deadline would cancel, not arm");
    }

    /// T3 (LINUX-STOP-PATH-BUDGET-01): DISABLED never arms; IDLE arms exactly
    /// once with the injected deadline; a second request never extends it.
    #[test]
    fn t3_arm_is_a_no_op_disabled_and_arms_exactly_once_when_enabled() {
        let guard = ExitGuard::new();
        let backend = RecordingAlarm::default();
        assert_eq!(guard.guard_state(), GUARD_DISABLED);
        assert!(!guard.arm_with(&backend));
        assert!(backend.calls().is_empty(), "DISABLED must never schedule");

        assert!(guard.enable(3));
        assert_eq!(guard.guard_state(), GUARD_IDLE);
        assert!(!guard.enable(9), "a second enable must not replace the deadline");
        assert!(guard.arm_with(&backend));
        assert!(!guard.arm_with(&backend), "a second request must not re-arm");
        assert_eq!(backend.calls(), vec![3]);
        assert_eq!(guard.guard_state(), GUARD_ARMED);
    }

    /// T3: the handler's decision. OPEN terminates with the decided code; after
    /// any claimant has won it returns.
    #[test]
    fn t3_alarm_action_terminates_only_from_open() {
        let open = ExitGuard::new();
        assert_eq!(open.decided_code(), EXIT_CODE_STOP_INCOMPLETE);
        assert_eq!(
            open.alarm_action(),
            AlarmAction::Terminate(EXIT_CODE_STOP_INCOMPLETE)
        );
        assert_eq!(open.exit_state(), EXIT_TERMINATING);
        assert_eq!(open.alarm_action(), AlarmAction::Return);

        let returning = ExitGuard::new();
        assert!(returning.claim_return_action());
        assert_eq!(returning.alarm_action(), AlarmAction::Return);

        let decided = ExitGuard::new();
        decided.decide(78);
        assert_eq!(decided.alarm_action(), AlarmAction::Terminate(78));
    }

    /// T3: the code a guard exit can carry is never 0 for any outcome.
    #[test]
    fn t3_every_outcome_maps_to_a_nonzero_guard_code() {
        use crate::daemon::{supervision_exit_status, SupervisionOutcome};
        use crate::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult};
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let cases = [
            (
                SupervisionOutcome::RepairRequired {
                    reason,
                    install_result: PostReadyRecoveryResult::InstallFailed,
                },
                78,
            ),
            (SupervisionOutcome::ShutdownRequested, 75),
            (SupervisionOutcome::KernelRuntimeLost(reason), 75),
            (SupervisionOutcome::FatalControlPath, 75),
        ];
        for (outcome, want) in cases {
            let guard = ExitGuard::new();
            guard.decide(supervision_exit_status(&outcome, false));
            assert_eq!(guard.decided_code(), want, "{outcome:?}");
            assert_eq!(guard.alarm_action(), AlarmAction::Terminate(want));
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Claimant {
        Handler,
        Verdict,
        MainReturn,
    }

    /// T4b (LINUX-STOP-PATH-BUDGET-01): across every ordering of the three
    /// claimants exactly one wins, and a terminator's code is the decided code
    /// (78 after a RepairRequired store, never a hard-coded 75).
    #[test]
    fn t4b_exactly_one_claimant_wins_in_every_ordering() {
        use Claimant::*;
        let orders = [
            [Handler, Verdict, MainReturn],
            [Handler, MainReturn, Verdict],
            [Verdict, Handler, MainReturn],
            [Verdict, MainReturn, Handler],
            [MainReturn, Handler, Verdict],
            [MainReturn, Verdict, Handler],
        ];
        for decided in [None, Some(78u8)] {
            for order in orders {
                let guard = ExitGuard::new();
                if let Some(code) = decided {
                    guard.decide(code);
                }
                let want = decided.unwrap_or(EXIT_CODE_STOP_INCOMPLETE);
                let mut winners = Vec::new();
                for claimant in order {
                    let won = match claimant {
                        Handler => match guard.alarm_action() {
                            AlarmAction::Terminate(code) => {
                                assert_eq!(code, want, "handler code in {order:?}");
                                true
                            }
                            AlarmAction::Return => false,
                        },
                        Verdict => match guard.terminate_action() {
                            Some(code) => {
                                assert_eq!(code, want, "verdict code in {order:?}");
                                true
                            }
                            None => false,
                        },
                        MainReturn => guard.claim_return_action(),
                    };
                    if won {
                        winners.push(claimant);
                    }
                }
                assert_eq!(winners, vec![order[0]], "one winner, the first, in {order:?}");
            }
        }
    }
}

/// Structural tests over the crate's own source (LINUX-STOP-PATH-BUDGET-01).
/// They pin who may exit the process, who may write the stop-request flag, where
/// the guard is armed, and that nothing can mask `SIGALRM`.
#[cfg(test)]
mod structure {
    use crate::source_scan::{
        cfg_test_module_ranges, daemon_sources, enclosing_fn, in_ranges, line_of, offsets_of,
        production_part, receiver_before, without_comment_lines,
    };
    use std::collections::BTreeSet;

    fn source(path: &str) -> String {
        daemon_sources()
            .into_iter()
            .find(|(p, _)| p == path)
            .map(|(_, text)| text)
            .unwrap_or_else(|| panic!("{path} must exist"))
    }

    /// T1: exactly one exit-code mapping, and it lives in `daemon.rs` beside
    /// `SupervisionOutcome`, where the stop guard's cell is written.
    #[test]
    fn t1_exactly_one_supervision_exit_status_and_it_is_in_daemon_rs() {
        let mut hits = Vec::new();
        for (path, text) in daemon_sources() {
            let code = without_comment_lines(&production_part(&text));
            for at in offsets_of(&code, "fn supervision_exit_status") {
                hits.push(format!("{path}:{}", line_of(&code, at)));
            }
        }
        assert_eq!(hits.len(), 1, "one mapping only: {hits:?}");
        assert!(hits[0].starts_with("src/daemon.rs:"), "{hits:?}");
    }

    /// T4: no raw process exit outside the exit gate. Every non-returning exit
    /// must go through `exit_guard`, or it can race the stop guard and invert a
    /// decided 78 (the unit's RestartPreventExitStatus) into a restarting 75.
    #[test]
    fn t4_no_raw_process_exit_outside_the_exit_gate() {
        let tokens = ["process::exit(", "libc::_exit(", "libc::exit(", "unistd::_exit("];
        let mut hits = Vec::new();
        for (path, text) in daemon_sources() {
            if path == "src/exit_guard.rs" {
                continue;
            }
            let code = without_comment_lines(&text);
            for token in tokens {
                for at in offsets_of(&code, token) {
                    hits.push(format!("{path}:{}: {token}", line_of(&code, at)));
                }
            }
        }
        assert!(hits.is_empty(), "raw exits outside the gate: {hits:?}");
    }

    /// T15: nothing in the crate can block `SIGALRM` or take `ITIMER_REAL` away
    /// from the guard (premise P7). A mask that blocked it on every thread would
    /// leave the guard silently inert.
    #[test]
    fn t15_no_signal_mask_change_or_second_timer_user_outside_the_guard() {
        let tokens = [
            "sigprocmask",
            "pthread_sigmask",
            "thread_block",
            "thread_set_mask",
            "thread_swap_mask",
            "alarm(",
            "setitimer",
        ];
        let mut hits = Vec::new();
        for (path, text) in daemon_sources() {
            if path == "src/exit_guard.rs" {
                continue;
            }
            let code = without_comment_lines(&text);
            for token in tokens {
                for at in offsets_of(&code, token) {
                    hits.push(format!("{path}:{}: {token}", line_of(&code, at)));
                }
            }
        }
        assert!(hits.is_empty(), "signal-mask or timer users: {hits:?}");
    }

    /// Identifiers that name the daemon stop-request flag (or its accept-loop
    /// namesake, which the exemptions below account for).
    const STOP_FLAG_RECEIVERS: [&str; 4] = [
        "shutdown_flag",
        "daemon_shutdown_request",
        "shutdown_requested",
        "flag",
    ];

    /// T14 (writer half): every writer of the stop-request flag is the one helper
    /// that also arms the guard, plus the listed exemptions, by full-set equality.
    #[test]
    fn t14_the_stop_request_flag_has_one_arming_writer_plus_listed_exemptions() {
        const TEST_MODULE: &str = "#[cfg(test)] mod";
        let mut writers = BTreeSet::new();
        for (path, text) in daemon_sources() {
            let code = without_comment_lines(&text);
            let tests = cfg_test_module_ranges(&code);
            for at in offsets_of(&code, ".store(true") {
                let receiver = receiver_before(&code, at);
                if !STOP_FLAG_RECEIVERS.contains(&receiver.as_str()) {
                    continue;
                }
                let site = if in_ranges(&tests, at) {
                    TEST_MODULE.to_string()
                } else {
                    enclosing_fn(&code, at)
                };
                writers.insert((path.clone(), site));
            }
        }
        let expected: BTreeSet<(String, String)> = [
            // The one production writer: store, then arm.
            ("src/exit_guard.rs", "request_daemon_stop"),
            // #[cfg(feature = "test-isolation")] boot-phase seam (A162).
            ("src/daemon.rs", "boot"),
            // #[cfg(test)].
            ("src/daemon.rs", TEST_MODULE),
            // The IPC accept-loop flag, a different flag with the same name.
            ("src/ipc/server.rs", "stop_and_join"),
            ("src/ipc/server.rs", "drop"),
            // #[cfg(all(target_os = "linux", feature = "test-isolation"))] slice-A
            // seam simulating a stop landing after scope resolution; same class as
            // the boot seam above.
            ("src/runtime_providers.rs", "refuse_after_owned_table"),
        ]
        .into_iter()
        .map(|(p, f)| (p.to_string(), f.to_string()))
        .collect();
        assert_eq!(writers, expected);

        let mut callers = BTreeSet::new();
        for (path, text) in daemon_sources() {
            let code = without_comment_lines(&production_part(&text));
            for at in offsets_of(&code, "request_daemon_stop(") {
                if code[..at].ends_with("fn ") {
                    continue;
                }
                callers.insert((path.clone(), enclosing_fn(&code, at)));
            }
        }
        let expected_callers: BTreeSet<(String, String)> = [
            ("src/daemon.rs", "handle_termination_signal"),
            ("src/daemon.rs", "request_stop"),
            ("src/ipc/server.rs", "withdraw_after_activation_audit_failure"),
        ]
        .into_iter()
        .map(|(p, f)| (p.to_string(), f.to_string()))
        .collect();
        assert_eq!(callers, expected_callers);
    }

    /// The body text of `fn <name>(` in `code`, from the signature to its
    /// matching close brace.
    fn fn_body<'a>(code: &'a str, name: &str) -> &'a str {
        let start = code
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} must exist"));
        let open = start + code[start..].find('{').unwrap_or_else(|| panic!("{name} body"));
        let mut depth = 0usize;
        for (i, c) in code[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &code[start..open + i + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("{name} body is unterminated")
    }

    /// The next non-blank line after byte `offset`'s line.
    fn next_code_line(text: &str, offset: usize) -> &str {
        let line_end = text[offset..].find('\n').map(|i| offset + i + 1).unwrap_or(text.len());
        text[line_end..]
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
    }

    /// The previous non-blank line before byte `offset`'s line.
    fn previous_code_line(text: &str, offset: usize) -> &str {
        let line_start = text[..offset].rfind('\n').unwrap_or(0);
        text[..line_start]
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
    }

    /// T14 (arm half) and T16: the ten audited decision sites, and only they, arm
    /// the guard and store their code, each on the line BEFORE its WAL write; the
    /// three RepairRequired arms are the value-changing stores; the wrapper stores
    /// every returned outcome's code.
    #[test]
    fn t14_t16_every_audited_decision_stores_and_arms_before_its_wal_write() {
        let daemon = without_comment_lines(&production_part(&source("src/daemon.rs")));
        let mut sites = Vec::new();
        for at in offsets_of(&daemon, "self.decide_and_arm(") {
            sites.push((enclosing_fn(&daemon, at), next_code_line(&daemon, at).to_string()));
        }
        let per_fn = |name: &str| sites.iter().filter(|(f, _)| f == name).count();
        assert_eq!(sites.len(), 10, "{sites:?}");
        assert_eq!(per_fn("supervise_until_shutdown_body"), 5, "{sites:?}");
        assert_eq!(per_fn("stop_final_health_outcome"), 5, "{sites:?}");
        let recovery = sites
            .iter()
            .filter(|(_, next)| next.starts_with("self.record_recovery_attempt("))
            .count();
        let loss = sites
            .iter()
            .filter(|(_, next)| next.starts_with("self.record_runtime_loss(reason, false)"))
            .count();
        assert_eq!(recovery, 3, "three RepairRequired arms: {sites:?}");
        assert_eq!(loss, 7, "seven KernelRuntimeLost arms: {sites:?}");

        // Every terminal WAL write in the two deciding functions is preceded by the
        // arm, so a new audited decision cannot write before it arms.
        for name in ["supervise_until_shutdown_body", "stop_final_health_outcome"] {
            let body = fn_body(&daemon, name);
            for needle in ["self.record_recovery_attempt(", "self.record_runtime_loss(reason, false)"] {
                for at in offsets_of(body, needle) {
                    assert!(
                        previous_code_line(body, at).starts_with("self.decide_and_arm(&outcome);"),
                        "{name}: `{needle}` at line {} is not armed first",
                        line_of(body, at)
                    );
                }
            }
            // The value that changes the code is RepairRequired: the outcome built
            // just before each recovery-attempt arm names that variant.
            for at in offsets_of(body, "self.record_recovery_attempt(") {
                let head = &body[..at];
                let built = head.rfind("let outcome = SupervisionOutcome::").map(|i| &head[i..]);
                assert!(
                    built.is_some_and(|b| b.starts_with("let outcome = SupervisionOutcome::RepairRequired")),
                    "{name}: a recovery-attempt write must follow a RepairRequired decision"
                );
            }
        }

        let wrapper = fn_body(&daemon, "supervise_until_shutdown");
        assert!(
            wrapper.contains(
                "crate::exit_guard::PROCESS_EXIT_GUARD.decide(supervision_exit_status(&outcome, false));"
            ),
            "the wrapper must store every returned outcome's code"
        );
    }
}
