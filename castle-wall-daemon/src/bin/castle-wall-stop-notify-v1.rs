//! Fixed bounded stop-wave hint. It never waits for extinction.
//!
//! UNREFERENCED IN THIS SLICE: the shipped daemon unit declares no
//! `ExecStopPost`, so nothing invokes this binary on shutdown today.
#[cfg(target_os = "linux")]
fn main() {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let invocation = std::env::var("INVOCATION_ID").unwrap_or_default();
    if boot.trim().is_empty() || invocation.is_empty() {
        std::process::exit(1)
    }
    let req = castle_wall_daemon::protected_agent::owner::Request::StopHint {
        boot_id: boot.trim().to_owned(),
        daemon_invocation: invocation,
    };
    use castle_wall_daemon::protected_agent::owner::OwnerOutcome;
    let outcome = castle_wall_daemon::protected_agent::owner::request(&req)
        .map(|r| r.outcome)
        .unwrap_or(OwnerOutcome::OwnerUnavailable);
    let ok = matches!(
        outcome,
        OwnerOutcome::IntentAccepted | OwnerOutcome::NoOwnedRelease
    );
    // SAFETY: stderr is the operator channel for the shutdown notifier's one
    // outcome line. It runs as an ExecStopPost with no daemon process left to
    // log through, so the journal entry is the whole record of the teardown.
    eprintln!("castle-wall-stop-notify-v1: owner_outcome={outcome:?}");
    if !ok {
        std::process::exit(1)
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(1)
}
