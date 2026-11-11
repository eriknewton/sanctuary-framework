// fail-before-exempt: wall binding and the private bus parser are new.
#![cfg(target_os = "linux")]
mod isolation;
#[path = "support/writer_bus.rs"]
mod writer_bus;
use castle_wall_daemon::business_profile::{
    signer_peer,
    writer_peer::{test_support::*, *},
};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use std::os::fd::AsRawFd;
#[test]
fn production_bus_identity_is_fixed() {
    let (socket, owner, uid, pid, unit) = production_values();
    assert_eq!(socket, std::path::Path::new(SYSTEM_BUS_SOCKET));
    assert_eq!((owner, uid, pid), (0, 0, 1));
    assert_eq!(unit, WALL_UNIT);
}
#[test]
fn cgroup_is_one_unified_absolute_path() {
    assert_eq!(
        normalized_cgroup("0::/user.slice/a\n").unwrap(),
        "/user.slice/a"
    );
    for bad in [
        "0::relative\n",
        "0::/a\n0::/b\n",
        "1:name:/a\n",
        "0::/a\n\n",
        "",
    ] {
        assert_eq!(normalized_cgroup(bad), Err(Error::Group));
    }
}
#[test]
fn authenticated_exchange_and_capture_hold_the_live_main_process() {
    let f = writer_bus::Fixture::new();
    let u = f.target.exchange(deadline_ms(250).unwrap()).unwrap();
    assert_eq!(u, *f.unit.lock().unwrap());
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    signer_peer::passcred(b.as_raw_fd()).unwrap();
    let expected = ListenerExpectations::isolated(
        f.root.path().join("record"),
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
    );
    let binding = WallMainBinding::capture(
        b.as_raw_fd(),
        &f.config,
        &f.target,
        &expected,
        unsafe { libc::geteuid() },
        deadline_ms(250).unwrap(),
    )
    .unwrap();
    assert_eq!(binding.pid, std::process::id() as i32);
    assert!(binding.live());
    assert_eq!(binding.held_artifacts(), 2);
    signer_peer::send(a.as_raw_fd(), b"packet", &[]).unwrap();
    let packet = signer_peer::receive(b.as_raw_fd(), 1024).unwrap();
    binding.packet(&packet).unwrap();
    binding
        .revalidate(&f.target, deadline_ms(250).unwrap())
        .unwrap();
    f.unit.lock().unwrap().invocation[0] ^= 1;
    assert_eq!(
        binding.revalidate(&f.target, deadline_ms(250).unwrap()),
        Err(Error::Identity)
    );
    assert!(binding.live());
}
#[test]
fn each_snapshot_predicate_has_a_valid_control() {
    let f = writer_bus::Fixture::new();
    let original = f.unit.lock().unwrap().clone();
    let validate =
        |u: &UnitSnapshot| validate_snapshot(u, &f.config, original.pid as i32, &original.cgroup);
    assert_eq!(validate(&original), Ok(()));
    let mut cases = vec![];
    let mut u = original.clone();
    u.id.push('x');
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.load = "not-found".into();
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.active = "inactive".into();
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.sub = "dead".into();
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.invocation.pop();
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.fragment = "relative".into();
    cases.push((u, Error::Unit));
    let mut u = original.clone();
    u.pid += 1;
    cases.push((u, Error::Identity));
    let mut u = original.clone();
    u.cgroup.push('x');
    cases.push((u, Error::Identity));
    let mut u = original.clone();
    u.exec.push('x');
    cases.push((u, Error::Exec));
    let mut u = original.clone();
    u.argv.reverse();
    cases.push((u, Error::Exec));
    let mut u = original.clone();
    u.dropins.push("/extra".into());
    cases.push((u, Error::Artifact));
    for (u, error) in cases {
        assert_eq!(validate(&u), Err(error));
    }
    let mut u = original.clone();
    u.active = "activating".into();
    u.sub = "start".into();
    assert_eq!(validate(&u), Ok(()));
}
#[test]
fn capture_refuses_primary_identity_and_artifact_mismatches() {
    let f = writer_bus::Fixture::new();
    let (_a, b) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    let owner = unsafe { libc::geteuid() };
    let expected = ListenerExpectations::isolated(f.root.path().join("record"), owner, unsafe {
        libc::getegid()
    });
    let mut config = f.config.clone();
    config.wall_gid += 1;
    assert!(matches!(
        WallMainBinding::capture(
            b.as_raw_fd(),
            &config,
            &f.target,
            &expected,
            owner,
            deadline_ms(250).unwrap()
        ),
        Err(Error::Peer)
    ));
    let expected_wrong =
        ListenerExpectations::isolated(f.root.path().join("record"), owner + 1, unsafe {
            libc::getegid()
        });
    assert!(matches!(
        WallMainBinding::capture(
            b.as_raw_fd(),
            &f.config,
            &f.target,
            &expected_wrong,
            owner,
            deadline_ms(250).unwrap()
        ),
        Err(Error::Peer)
    ));
    let mut config = f.config.clone();
    config.wall_sha256 = "0".repeat(64);
    assert!(matches!(
        WallMainBinding::capture(
            b.as_raw_fd(),
            &config,
            &f.target,
            &expected,
            owner,
            deadline_ms(250).unwrap()
        ),
        Err(Error::Artifact)
    ));
    assert_eq!(
        check_artifact(&f.config.wall_exec, owner + 1, &f.config.wall_sha256),
        Err(Error::Artifact)
    );
    let link = f.root.path().join("link");
    std::os::unix::fs::symlink(&f.config.wall_exec, &link).unwrap();
    assert!(check_artifact(&link, owner, &f.config.wall_sha256).is_err());
    std::fs::hard_link(&f.config.wall_exec, f.root.path().join("hard")).unwrap();
    assert_eq!(
        check_artifact(&f.config.wall_exec, owner, &f.config.wall_sha256),
        Err(Error::Artifact)
    );
}
#[test]
fn config_is_strict_and_held_identity_is_rechecked() {
    let f = writer_bus::Fixture::new();
    let path = f.config_path();
    let held = HeldConfig::isolated(&path, unsafe { libc::geteuid() }).unwrap();
    assert_eq!(held.recheck(), Ok(()));
    let replacement = f.root.path().join("replacement");
    std::fs::copy(&path, &replacement).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    assert_eq!(held.recheck(), Err(Error::Config));
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["extra"] = serde_json::json!(0);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(
        HeldConfig::isolated(&path, unsafe { libc::geteuid() }),
        Err(Error::Config)
    ));
}
#[test]
fn owner_change_is_terminal_without_rebinding() {
    let f = writer_bus::Fixture::new();
    f.unit.lock().unwrap().owner = ":1.89".into();
    assert_eq!(
        f.target.exchange(deadline_ms(250).unwrap()),
        Err(Error::Sender)
    );
}

#[test]
fn manager_credentials_and_final_ownership_are_pinned() {
    for (pid_offset, uid_offset, change_owner) in [(1, 0, false), (0, 1, false), (0, 0, true)] {
        let f = writer_bus::Fixture::new();
        *f.fault.lock().unwrap() = writer_bus::Fault {
            pid_offset,
            uid_offset,
            change_owner,
            ..Default::default()
        };
        assert_eq!(
            f.target.exchange(deadline_ms(250).unwrap()),
            Err(Error::Owner)
        );
    }
}
#[test]
fn bounded_signals_are_discarded_without_satisfying_a_response() {
    for (signals, invalid, expected) in [
        (BUS_UNSOLICITED_MAX, false, None),
        (BUS_UNSOLICITED_MAX + 1, false, Some(Error::Signals)),
        (1, true, Some(Error::MessageType)),
    ] {
        let f = writer_bus::Fixture::new();
        *f.fault.lock().unwrap() = writer_bus::Fault {
            signals,
            invalid_signal: invalid,
            ..Default::default()
        };
        let result = f.target.exchange(deadline_ms(250).unwrap());
        match expected {
            Some(error) => assert_eq!(result, Err(error)),
            None => assert!(result.is_ok()),
        }
    }
}
#[test]
fn trickled_minimal_reply_cannot_rearm_twenty_fresh_deadlines() {
    const WAVES: usize = 20; // Independent admissions required by the fault schedule.
    for _ in 0..WAVES {
        let f = writer_bus::Fixture::new();
        f.fault.lock().unwrap().trickle = true;
        let start = std::time::Instant::now();
        assert_eq!(
            f.target.exchange(deadline_ms(250).unwrap()),
            Err(Error::Deadline)
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(250 + 100));
    }
}
