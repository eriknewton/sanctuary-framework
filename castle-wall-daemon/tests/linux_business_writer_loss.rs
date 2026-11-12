// fail-before-exempt: writer recovery and heartbeat states are new.
#![cfg(target_os = "linux")]
mod isolation;
#[path = "support/writer_state.rs"]
mod writer_state;
use castle_wall_daemon::business_profile::writer_service::*;
use castle_wall_daemon::business_profile::{
    signer_contract::SIGNER_IDLE_DEADLINE_MS, writer_protocol::*,
};
use std::sync::atomic::Ordering;
use writer_state::*;
#[test]
fn startup_accepts_only_locked_or_recovery() {
    for state in [
        "LOCKED",
        "WIPE_UNCONFIRMED",
        "RECOVERY_REQUIRED",
        "UNLOCKING",
        "UNLOCKED",
        "LOCKING",
        "WIPED",
    ] {
        let f = Fixture::new();
        f.state(state);
        let result = WriterMachine::isolated(f.signer(), f.reconciler(), "a".repeat(32), f.clock());
        match state {
            "LOCKED" => assert_eq!(result.unwrap().state(), WriterState::ClosedLocked),
            "WIPE_UNCONFIRMED" | "RECOVERY_REQUIRED" => {
                assert_eq!(result.unwrap().state(), WriterState::ClosedRecovery)
            }
            _ => assert!(matches!(result, Err(Error::Start))),
        }
    }
}
#[test]
fn recovery_history_survives_before_wall_and_reconciled() {
    for recovery_before_start in [false, true] {
        let f = Fixture::new();
        if recovery_before_start {
            f.state("RECOVERY_REQUIRED");
        }
        let mut m = f.machine();
        f.state("RECOVERY_REQUIRED");
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::ClosedRecovery);
        f.unlock();
        m.heartbeat().unwrap();
        m.captured_wall_for_test().unwrap();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        assert!(m.status_payload().grant.is_none());
        f.state("LOCKED");
        m.heartbeat().unwrap();
        f.unlock();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        f.now.fetch_add(1, Ordering::SeqCst);
        f.unlock();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::Reconciled);
        f.state("WIPE_UNCONFIRMED");
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        f.unlock();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        f.state("LOCKED");
        m.heartbeat().unwrap();
        f.now.fetch_add(1, Ordering::SeqCst);
        f.unlock();
        m.heartbeat().unwrap();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::Granted);
    }
}
#[test]
fn recovery_can_clear_and_unlock_before_first_wall_connection() {
    let f = Fixture::new();
    f.state("WIPE_UNCONFIRMED");
    let mut m = f.machine();
    f.state("LOCKED");
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::ClosedLocked);
    f.now.fetch_add(1, Ordering::SeqCst);
    f.unlock();
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::ClosedLocked);
    m.captured_wall_for_test().unwrap();
    m.heartbeat().unwrap();
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::Granted);
}
#[test]
fn null_anchors_retain_reconciled_and_changed_observations_return_closed() {
    let f = Fixture::new();
    let mut m = f.machine();
    m.captured_wall_for_test().unwrap();
    f.unlock();
    {
        let mut v = f.view.lock().unwrap();
        v.anchor_digest = None;
        v.anchor_revision = None;
    }
    m.heartbeat().unwrap();
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::Reconciled);
    assert_eq!(f.binds.load(Ordering::SeqCst), 0);
    assert!(m.status_payload().grant.is_none());
    f.view.lock().unwrap().grant.generation += 1;
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::WallBound);
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::Reconciled);
    f.state("LOCKING");
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::WallBound);
    assert!(m.sign(f.header(), &f.body, |_| Ok(())).is_err());
    assert_eq!(f.signs.load(Ordering::SeqCst), 0);
}
#[test]
fn kernel_boot_mismatch_and_reconciliation_refusal_never_grant() {
    let f = Fixture::new();
    let mut m = f.machine();
    m.captured_wall_for_test().unwrap();
    f.unlock();
    f.view.lock().unwrap().boot_id.replace_range(..1, "b");
    m.heartbeat().unwrap();
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::WallBound);
    assert_eq!(f.reconciles.load(Ordering::SeqCst), 0);
    assert!(m.sign(f.header(), &f.body, |_| Ok(())).is_err());
    assert_eq!(f.signs.load(Ordering::SeqCst), 0);
    let f = Fixture::new();
    let mut m = WriterMachine::isolated(
        f.signer(),
        ClosedReconciler::production(),
        "a".repeat(32),
        f.clock(),
    )
    .unwrap();
    m.captured_wall_for_test().unwrap();
    f.unlock();
    m.heartbeat().unwrap();
    m.heartbeat().unwrap();
    assert_eq!(m.state(), WriterState::WallBound);
    assert!(m.sign(f.header(), &f.body, |_| Ok(())).is_err());
}
#[test]
fn bound_view_changes_and_frozen_expiry_settle() {
    for change in 0..5 {
        let f = Fixture::new();
        let mut m = f.machine();
        f.grant(&mut m);
        {
            let mut v = f.view.lock().unwrap();
            match change {
                0 => v.grant.generation += 1,
                1 => v.started_boottime_ns = "2".into(),
                2 => v.expires_boottime_ns = "999999999999".into(),
                3 => v.boot_id = "b".repeat(32),
                _ => v.state = "RECOVERY_REQUIRED".into(),
            }
        }
        assert!(m.heartbeat().is_err());
        assert_eq!(m.state(), WriterState::Settling);
    }
    let f = Fixture::new();
    let mut m = f.machine();
    f.grant(&mut m);
    let expiry = f.view.lock().unwrap().expires_boottime_ns.parse().unwrap();
    f.now.store(expiry, Ordering::SeqCst);
    assert_eq!(m.tick(), Err(Error::Expired));
    assert_eq!(m.state(), WriterState::Settling);
}
#[test]
fn closed_states_keep_heartbeats_and_timeout_waves_do_not_overlap() {
    for _ in 0..HEARTBEAT_WAVES {
        let f = Fixture::new();
        let mut m = f.machine();
        assert!(!m.heartbeat_due().unwrap());
        f.now
            .fetch_add(WRITER_HEARTBEAT_MS * NS_PER_MS, Ordering::SeqCst);
        assert!(m.heartbeat_due().unwrap());
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::ClosedLocked);
        m.captured_wall_for_test().unwrap();
        f.now
            .fetch_add(WRITER_HEARTBEAT_MS * NS_PER_MS, Ordering::SeqCst);
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        f.status_delay.store(
            (SIGNER_IDLE_DEADLINE_MS as u64 + 1) * NS_PER_MS,
            Ordering::SeqCst,
        );
        assert_eq!(m.heartbeat(), Err(Error::Deadline));
        m.settle();
        assert_eq!(m.state(), WriterState::Stopped);
        assert_eq!(f.closes.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn maximum_budget_sign_heartbeats_before_completion_exchange() {
    let f = Fixture::new();
    let mut m = f.machine();
    f.grant(&mut m);
    f.events.lock().unwrap().clear();
    f.delay
        .store(WRITER_SIGN_DEADLINE_MAX_MS * NS_PER_MS, Ordering::SeqCst);
    let events = f.events.clone();
    let now = f.now.clone();
    let body = m
        .sign(f.header(), &f.body, move |end| {
            events.lock().unwrap().push("post-wait".into());
            assert_eq!(
                end,
                now.load(Ordering::SeqCst) + WRITER_HEARTBEAT_MS * NS_PER_MS
            );
            Ok(())
        })
        .unwrap();
    assert!(!body.is_empty());
    assert_eq!(
        *f.events.lock().unwrap(),
        vec!["sign", "status", "post-wait"]
    );
    assert_eq!(m.state(), WriterState::EnvelopeVerified);
    m.verified_sent_for_test();
    assert_eq!(m.state(), WriterState::Granted);
    let mut h = f.header();
    h.deadline_boottime_ns =
        (f.now.load(Ordering::SeqCst) + (WRITER_SIGN_DEADLINE_MAX_MS + 1) * NS_PER_MS).to_string();
    assert_eq!(m.sign(h, &f.body, |_| Ok(())), Err(Error::Deadline));
    assert_eq!(f.signs.load(Ordering::SeqCst), 1);
}

#[test]
fn recovery_without_an_observed_lock_never_forwards_sign() {
    let f = Fixture::new();
    f.state("RECOVERY_REQUIRED");
    let mut m = f.machine();
    assert_eq!(m.state(), WriterState::ClosedRecovery);
    m.captured_wall_for_test().unwrap();
    f.unlock();
    m.heartbeat().unwrap();
    m.heartbeat().unwrap();
    let _ = m.sign(f.header(), &f.body, |_| Ok(()));
    assert_eq!(f.signs.load(Ordering::SeqCst), 0);
}

#[test]
fn sign_deadline_admission_at_clock_and_above_cap() {
    use castle_wall_daemon::business_profile::writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS;
    for offset in [0, (WRITER_SIGN_DEADLINE_MAX_MS + 1) * NS_PER_MS] {
        let f = Fixture::new();
        let mut m = f.machine();
        f.grant(&mut m);
        let mut header = f.header();
        header.deadline_boottime_ns = (f.now.load(Ordering::SeqCst) + offset).to_string();
        assert_eq!(m.sign(header, &f.body, |_| Ok(())), Err(Error::Deadline));
        assert_eq!(f.signs.load(Ordering::SeqCst), 0);
    }
}
