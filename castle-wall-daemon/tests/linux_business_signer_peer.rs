#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::signer_peer::*;
use sha2::{Digest, Sha256};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
fn pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        },
        0
    );
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    passcred(a.as_raw_fd()).unwrap();
    passcred(b.as_raw_fd()).unwrap();
    (a, b)
}
fn policy() -> PeerPolicy {
    PeerPolicy {
        uid: unsafe { libc::geteuid() },
        executable_sha256: hex::encode(Sha256::digest(std::fs::read("/proc/self/exe").unwrap())),
        cgroup: std::fs::read_to_string("/proc/self/cgroup")
            .unwrap()
            .trim()
            .into(),
    }
}
#[test]
fn socketpair_kernel_credentials_authenticate_and_wrong_caller_refuses() {
    let (a, b) = pair();
    let peer = Peer::capture(a.as_raw_fd(), &policy()).unwrap();
    send(b.as_raw_fd(), b"hello", &[]).unwrap();
    let packet = receive(a.as_raw_fd(), 32).unwrap();
    assert!(peer.matches(&packet));
    let mut packet = packet;
    packet.cred.uid = peer.uid.wrapping_add(1);
    assert!(!peer.matches(&packet));
    packet.cred.uid = peer.uid;
    assert!(peer.matches(&packet));
    packet.cred.pid += 1;
    assert!(!peer.matches(&packet));
    let mut other = policy();
    other.uid = other.uid.wrapping_add(1);
    assert!(Peer::capture(a.as_raw_fd(), &other).is_err());
}
#[test]
fn wrong_executable_and_cgroup_refuse() {
    let (a, _) = pair();
    let mut p = policy();
    p.executable_sha256 = "0".repeat(64);
    assert!(Peer::capture(a.as_raw_fd(), &p).is_err());
    let mut p = policy();
    p.cgroup = "wrong".into();
    assert!(Peer::capture(a.as_raw_fd(), &p).is_err());
}
#[test]
fn oversized_packet_is_not_truncated_into_valid_work() {
    let (a, b) = pair();
    send(b.as_raw_fd(), &[0; 100], &[]).unwrap();
    assert!(receive(a.as_raw_fd(), 16).is_err());
}
#[test]
fn rights_are_received_cloexec_and_non_tty_refuses() {
    let (a, b) = pair();
    let file = std::fs::File::open("/dev/null").unwrap();
    send(b.as_raw_fd(), b"ceremony", &[file.as_raw_fd()]).unwrap();
    let packet = receive(a.as_raw_fd(), 32).unwrap();
    assert_eq!(packet.rights.len(), 1);
    assert_ne!(
        unsafe { libc::fcntl(packet.rights[0].as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert!(tty_check(packet.rights[0].as_raw_fd(), unsafe { libc::getpid() }).is_err());
}
#[test]
fn extra_rights_are_visible_for_ceremony_refusal() {
    let (a, b) = pair();
    let f = std::fs::File::open("/dev/null").unwrap();
    send(b.as_raw_fd(), b"ceremony", &[f.as_raw_fd(), f.as_raw_fd()]).unwrap();
    assert_eq!(receive(a.as_raw_fd(), 32).unwrap().rights.len(), 2);
}
// Must match signer_peer identity_refusal: receipt must succeed before identity is judged.
const HANDSHAKE_TIMEOUT_MS: i32 = 5000;
const PACKET_BOUND: usize = 32;
const OTHER_UID: u32 = 65534;
fn live_sender_packet(change_uid: bool) -> (Peer, Packet) {
    let (a, b) = pair();
    let peer = Peer::capture(a.as_raw_fd(), &policy()).unwrap();
    send(b.as_raw_fd(), b"control", &[]).unwrap();
    assert!(peer.matches(&receive(a.as_raw_fd(), PACKET_BOUND).unwrap()));
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let input = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let output = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if change_uid && (libc::setgid(OTHER_UID) != 0 || libc::setuid(OTHER_UID) != 0) {
                libc::_exit(2)
            }
        }
        let ok = send(b.as_raw_fd(), b"foreign", &[]).is_ok();
        let mut poll = libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut done = 0u8;
        let acknowledged = unsafe {
            libc::poll(&mut poll, 1, HANDSHAKE_TIMEOUT_MS) == 1
                && libc::read(input.as_raw_fd(), &mut done as *mut u8 as *mut _, 1) == 1
        };
        unsafe { libc::_exit(if ok && acknowledged { 0 } else { 3 }) }
    }
    let mut poll = libc::pollfd {
        fd: a.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let readable = unsafe { libc::poll(&mut poll, 1, HANDSHAKE_TIMEOUT_MS) };
    let packet = receive(a.as_raw_fd(), PACKET_BOUND);
    let result = packet.as_ref().map(|packet| {
        let credentials_match = packet.cred.pid == pid
            && packet.cred.uid == if change_uid { OTHER_UID } else { peer.uid };
        // Must match signer_peer.rs test_identity_refusal: test-only reasons distinguish live identity denial from receive failures.
        #[cfg(feature = "test-isolation")]
        let reason_matches =
            peer.test_identity_refusal(packet) == Some(if change_uid { "UID" } else { "PID" });
        #[cfg(not(feature = "test-isolation"))]
        let reason_matches = true;
        credentials_match && reason_matches && !peer.matches(packet)
    });
    let done = 1u8;
    assert_eq!(
        unsafe { libc::write(output.as_raw_fd(), &done as *const u8 as *const _, 1) },
        1
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert_eq!(readable, 1);
    assert!(result.unwrap());
    (peer, packet.unwrap())
}
#[test]
#[ignore = "needs root host: per-message credentials across real UIDs"]
fn root_real_uid_refuses() {
    kernel_probe().unwrap();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    live_sender_packet(true);
}
#[test]
fn passed_socket_from_another_process_refuses() {
    live_sender_packet(false);
}

#[test]
fn message_pidfd_refuses_forged_credential_identity() {
    let (a, b) = pair();
    let peer = Peer::capture(a.as_raw_fd(), &policy()).unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let ok = send(b.as_raw_fd(), b"foreign", &[]).is_ok();
        let mut poll = libc::pollfd {
            fd: b.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut poll, 1, 5000);
            libc::_exit(if ok { 0 } else { 1 })
        }
    }
    let mut poll = libc::pollfd {
        fd: a.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
    let mut packet = receive(a.as_raw_fd(), 32).unwrap();
    packet.cred.pid = peer.pid;
    packet.cred.uid = peer.uid;
    packet.cred.gid = peer.gid;
    let refused = !peer.matches(&packet);
    send(a.as_raw_fd(), b"done", &[]).unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert!(refused);
}

#[test]
fn bridge_transport_refuses_pipe_and_accepts_unix_socket() {
    let (a, _) = pair();
    assert!(require_unix_socket(a.as_raw_fd()).is_ok());
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let input = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let _output = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    assert!(require_unix_socket(input.as_raw_fd()).is_err());
}
#[test]
fn retained_bounding_capabilities_refuse_peer_admission() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let bnd = status
        .lines()
        .find_map(|s| s.strip_prefix("CapBnd:"))
        .unwrap();
    if u64::from_str_radix(bnd.trim(), 16).unwrap() != 0 {
        assert!(empty_capabilities(unsafe { libc::getpid() }, true).is_err());
    }
}

#[test]
fn service_capability_status_requires_every_empty_set_and_no_new_privileges() {
    // Captured status field layout is parsed by the same function as service accept admission.
    const EMPTY: &str = "Name:\tsigner\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    assert!(validate_capability_status(EMPTY, true).is_ok());
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let fixture = EMPTY.replace(
            &format!("{field}:\t0000000000000000"),
            &format!("{field}:\t0000000000000001"),
        );
        assert!(
            validate_capability_status(&fixture, true).is_err(),
            "{field}"
        );
        let missing = EMPTY.replace(&format!("{field}:\t0000000000000000\n"), "");
        assert!(
            validate_capability_status(&missing, true).is_err(),
            "missing {field}"
        );
        assert_eq!(
            validate_capability_status(&fixture, false).is_ok(),
            field == "CapBnd"
        );
        assert_eq!(
            validate_capability_status(&missing, false).is_ok(),
            field == "CapBnd"
        );
    }
    assert!(validate_capability_status(&EMPTY.replace("NoNewPrivs:\t1\n", ""), true).is_err());
    assert!(
        validate_capability_status(&EMPTY.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), true)
            .is_err()
    );
}
