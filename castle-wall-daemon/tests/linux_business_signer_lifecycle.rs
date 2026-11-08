#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::signer_watchdog::*;
#[test]
fn lease_ceiling_is_300_seconds() {
    let mut lease = Lease::default();
    assert!(!lease.begin(0, 301));
    assert!(!lease.begin(0, 0));
    assert!(lease.begin(10, 300));
    assert_eq!(lease.expires(), 10 + 300 * NS_PER_SECOND);
}
#[test]
fn expired_lease_refuses_signing() {
    let mut lease = Lease::default();
    assert!(lease.begin(0, 300));
    assert!(lease.ready(1));
    assert!(lease.can_sign(300 * NS_PER_SECOND - 1));
    assert!(!lease.can_sign(300 * NS_PER_SECOND));
}
#[test]
fn ready_does_not_reset_residency() {
    let mut lease = Lease::default();
    assert!(lease.begin(1, 300));
    assert!(lease.ready(29 * NS_PER_SECOND));
    assert_eq!(lease.expires(), 1 + 300 * NS_PER_SECOND);
    assert!(!lease.ready(30 * NS_PER_SECOND));
}
#[test]
fn unlocking_timeout_precedes_kdf_completion() {
    let mut lease = Lease::default();
    assert!(lease.begin(0, 300));
    assert!(!lease.ready(30 * NS_PER_SECOND));
}
#[test]
fn suspended_or_rolled_clock_cannot_extend_lease() {
    let mut lease = Lease::default();
    assert!(lease.begin(NS_PER_SECOND, 300));
    assert!(!lease.live(0));
    assert!(!lease.live(400 * NS_PER_SECOND));
    assert!(!Lease::default().can_sign(0));
}
#[test]
fn overflow_and_reentry_refuse() {
    let mut lease = Lease::default();
    assert!(!lease.begin(u64::MAX, 300));
    assert!(lease.begin(0, 300));
    assert!(!lease.begin(1, 300));
}
#[test]
fn native_watchdog_reaps_a_spawned_child() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut lease = Lease::default();
    lease.begin(0, 300);
    lease.ready(1);
    kill_and_reap(&mut child, &mut lease).unwrap();
    assert_eq!(lease.state, State::WipeUnconfirmed);
    assert!(!lease.can_sign(2));
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
}
#[test]
fn crashed_worker_is_reaped_and_closed() {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .spawn()
        .unwrap();
    let mut lease = Lease::default();
    lease.begin(0, 300);
    child.wait().unwrap();
    kill_and_reap(&mut child, &mut lease).unwrap();
    assert_eq!(lease.state, State::WipeUnconfirmed);
    assert!(!lease.can_sign(1));
}
#[test]
fn boottime_is_monotonic() {
    let a = boottime_ns().unwrap();
    assert!(boottime_ns().unwrap() >= a);
}
#[test]
fn local_revocation_removes_authority_before_reaping() {
    let mut lease = Lease::default();
    assert!(lease.begin(0, 300));
    assert!(lease.ready(1));
    lease.revoke();
    assert_eq!(lease.state, State::Locking);
    assert!(!lease.can_sign(2));
}

#[test]
fn cleanup_acknowledgement_does_not_renew_kill_deadline() {
    use castle_wall_daemon::business_profile::signer_service::Settlement;
    let mut settlement = Settlement::default();
    let now = NS_PER_SECOND;
    settlement.acknowledge(State::Unlocking, now);
    let deadline = settlement.deadline();
    settlement.lock(State::Locking, now + NS_PER_SECOND);
    assert_eq!(settlement.deadline(), deadline);
}

#[test]
fn child_exit_waits_for_buffered_cleanup_frame() {
    use castle_wall_daemon::business_profile::signer_service::reaped_after_output;
    use std::{
        io::Read,
        os::fd::AsRawFd,
        process::{Command, Stdio},
    };
    let mut child = Command::new("/bin/printf")
        .arg("WIPED")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    assert!(child.wait().unwrap().success());
    assert!(reaped_after_output(&mut child, output.as_raw_fd())
        .unwrap()
        .is_none());
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"WIPED");
    assert!(reaped_after_output(&mut child, output.as_raw_fd())
        .unwrap()
        .unwrap()
        .success());
}

#[test]
fn lifecycle_cap_counts_backlog_while_lock_is_accepted() {
    use castle_wall_daemon::business_profile::{
        signer_contract::LIFECYCLE_CONNECTIONS_MAX, signer_peer,
        signer_service::seal_lifecycle_backlog,
    };
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.sock");
    let listener = signer_peer::listen(&path).unwrap();
    let ceremony = signer_peer::connect(&path).unwrap();
    let accepted = signer_peer::accept(listener.as_raw_fd()).unwrap();
    // Probe empty, then connect before the final accept to exercise the admission race.
    assert!(!castle_wall_daemon::business_profile::signer_service::readable(listener.as_raw_fd()));
    let lock = signer_peer::connect(&path).unwrap();
    assert!(seal_lifecycle_backlog(listener.as_raw_fd(), LIFECYCLE_CONNECTIONS_MAX - 1).unwrap());
    let control = signer_peer::accept(listener.as_raw_fd()).unwrap();
    assert!(signer_peer::connect(&path).is_err());
    drop(control);
    drop(lock);
    std::fs::remove_file(&path).unwrap();
    let reopened = signer_peer::listen(&path).unwrap();
    let next = signer_peer::connect(&path).unwrap();
    let admitted = signer_peer::accept(reopened.as_raw_fd()).unwrap();
    drop((ceremony, accepted, next, admitted));
}

#[test]
fn seeded_worker_settlement_schedules_preserve_custody() {
    use castle_wall_daemon::business_profile::signer_service::Settlement;
    const SEEDS: u64 = 4096;
    const STEPS: usize = 64;
    #[derive(Clone, Copy)]
    enum Event {
        Ready,
        Wiped,
        Lock,
        Fault,
        ExitSuccess,
        Kill,
        Signed,
    }
    const EVENTS: [Event; 9] = [
        Event::Ready,
        Event::Wiped,
        Event::Wiped,
        Event::Lock,
        Event::Lock,
        Event::Fault,
        Event::ExitSuccess,
        Event::Kill,
        Event::Signed,
    ];
    const NS_PER_MS: u64 = NS_PER_SECOND / 1000;
    const TICK_BOUNDARIES: u64 = 3;
    const XORSHIFT_LEFT_FIRST: u32 = 13;
    const XORSHIFT_RIGHT: u32 = 7;
    const XORSHIFT_LEFT_LAST: u32 = 17;
    for seed in 0..SEEDS {
        let mut random = seed + 1;
        let mut lease = Lease::default();
        assert!(lease.begin(0, 300));
        let mut settlement = Settlement::default();
        let mut acks = 0;
        let mut fault = false;
        let mut revoked = false;
        let mut now = 0;
        for _ in 0..STEPS {
            random ^= random << XORSHIFT_LEFT_FIRST;
            random ^= random >> XORSHIFT_RIGHT;
            random ^= random << XORSHIFT_LEFT_LAST;
            now += (random % TICK_BOUNDARIES) * WATCHDOG_TICK_MS as u64 * NS_PER_MS;
            let before = settlement.deadline();
            match EVENTS[random as usize % EVENTS.len()] {
                Event::Ready => {
                    if !lease.ready(now) {
                        settlement.fault(now);
                        fault = true;
                        lease.revoke();
                        revoked = true;
                    }
                }
                Event::Wiped => {
                    acks += 1;
                    fault |= acks != 1 || !matches!(lease.state, State::Unlocking | State::Locking);
                    settlement.acknowledge(lease.state, now);
                    lease.revoke();
                    revoked = true;
                }
                Event::Lock => {
                    settlement.lock(lease.state, now);
                    lease.revoke();
                    revoked = true;
                }
                Event::Fault => {
                    settlement.fault(now);
                    fault = true;
                    lease.revoke();
                    revoked = true;
                }
                Event::Signed => {
                    assert!(!revoked || !lease.can_sign(now), "seed {seed}");
                }
                event @ (Event::ExitSuccess | Event::Kill) => {
                    let success = matches!(event, Event::ExitSuccess);
                    assert_eq!(
                        settlement.cooperative(success),
                        acks == 1 && !fault && success,
                        "seed {seed}"
                    );
                    lease.revoke();
                    revoked = true;
                    lease.reaped(settlement.cooperative(success));
                    if lease.state == State::Wiped {
                        assert!(acks == 1 && !fault && success);
                    }
                }
            }
            if let Some(previous) = before {
                assert!(settlement.deadline().unwrap() <= previous, "seed {seed}");
            }
            if revoked {
                assert!(!lease.can_sign(now), "seed {seed}");
            }
        }
    }
}

#[test]
fn final_slot_seals_even_without_a_readable_probe() {
    use castle_wall_daemon::business_profile::{signer_peer, signer_service};
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.sock");
    let listener = signer_peer::listen(&path).unwrap();
    let first = signer_peer::connect(&path).unwrap();
    let accepted = signer_peer::accept(listener.as_raw_fd()).unwrap();
    assert!(!signer_service::readable(listener.as_raw_fd()));
    assert!(signer_service::seal_lifecycle_backlog(listener.as_raw_fd(), 1).unwrap());
    assert!(signer_peer::connect(&path).is_err());
    drop((first, accepted));
}
