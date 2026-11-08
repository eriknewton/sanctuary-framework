#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::signer_peer::*;
use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
use sha2::{Digest,Sha256};
fn pair()->(OwnedFd,OwnedFd){let mut fds=[-1;2];assert_eq!(unsafe{libc::socketpair(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC,0,fds.as_mut_ptr())},0);let a=unsafe{OwnedFd::from_raw_fd(fds[0])};let b=unsafe{OwnedFd::from_raw_fd(fds[1])};passcred(a.as_raw_fd()).unwrap();passcred(b.as_raw_fd()).unwrap();(a,b)}
fn policy()->PeerPolicy {PeerPolicy{uid:unsafe{libc::geteuid()},executable_sha256:hex::encode(Sha256::digest(std::fs::read("/proc/self/exe").unwrap())),cgroup:std::fs::read_to_string("/proc/self/cgroup").unwrap().trim().into()}}
#[test]
fn socketpair_kernel_credentials_authenticate_and_wrong_caller_refuses(){let(a,b)=pair();let peer=Peer::capture(a.as_raw_fd(),&policy()).unwrap();send(b.as_raw_fd(),b"hello",&[]).unwrap();let packet=receive(a.as_raw_fd(),32).unwrap();assert!(peer.matches(&packet.cred));let mut wrong=packet.cred;wrong.pid+=1;assert!(!peer.matches(&wrong));let mut other=policy();other.uid=other.uid.wrapping_add(1);assert!(Peer::capture(a.as_raw_fd(),&other).is_err());}
#[test]
fn wrong_executable_and_cgroup_refuse(){let(a,_)=pair();let mut p=policy();p.executable_sha256="0".repeat(64);assert!(Peer::capture(a.as_raw_fd(),&p).is_err());let mut p=policy();p.cgroup="wrong".into();assert!(Peer::capture(a.as_raw_fd(),&p).is_err());}
#[test]
fn oversized_packet_is_not_truncated_into_valid_work(){let(a,b)=pair();send(b.as_raw_fd(),&[0;100],&[]).unwrap();assert!(receive(a.as_raw_fd(),16).is_err());}
#[test]
fn rights_are_received_cloexec_and_non_tty_refuses(){let(a,b)=pair();let file=std::fs::File::open("/dev/null").unwrap();send(b.as_raw_fd(),b"ceremony",&[file.as_raw_fd()]).unwrap();let packet=receive(a.as_raw_fd(),32).unwrap();assert_eq!(packet.rights.len(),1);assert_ne!(unsafe{libc::fcntl(packet.rights[0].as_raw_fd(),libc::F_GETFD)}&libc::FD_CLOEXEC,0);assert!(tty_check(packet.rights[0].as_raw_fd(),unsafe{libc::getpid()}).is_err());}
#[test]
fn extra_rights_are_visible_for_ceremony_refusal(){let(a,b)=pair();let f=std::fs::File::open("/dev/null").unwrap();send(b.as_raw_fd(),b"ceremony",&[f.as_raw_fd(),f.as_raw_fd()]).unwrap();assert_eq!(receive(a.as_raw_fd(),32).unwrap().rights.len(),2);}
#[test]
#[ignore = "needs root host: kernel minimum and SO_PEERPIDFD before system service readiness"]
fn root_kernel_minimum(){assert_eq!(unsafe{libc::geteuid()},0);kernel_probe().unwrap();}
#[test]
#[ignore = "needs root host: per-message credentials across real UIDs"]
fn root_real_uid_refuses(){
    assert_eq!(unsafe{libc::geteuid()},0);let(a,b)=pair();let peer=Peer::capture(a.as_raw_fd(),&policy()).unwrap();
    let pid=unsafe{libc::fork()};assert!(pid>=0);if pid==0{unsafe{if libc::setgid(65534)!=0||libc::setuid(65534)!=0{libc::_exit(2)}};let ok=send(b.as_raw_fd(),b"wrong uid",&[]).is_ok();unsafe{libc::_exit(if ok{0}else{3})}}
    let mut status=0;assert_eq!(unsafe{libc::waitpid(pid,&mut status,0)},pid);assert_eq!(status,0);let packet=receive(a.as_raw_fd(),32).unwrap();assert!(!peer.matches(&packet.cred));
}
#[test]
fn passed_socket_from_another_process_refuses(){
    let(a,b)=pair();let peer=Peer::capture(a.as_raw_fd(),&policy()).unwrap();let pid=unsafe{libc::fork()};assert!(pid>=0);
    if pid==0{let ok=send(b.as_raw_fd(),b"passed socket",&[]).is_ok();unsafe{libc::_exit(if ok{0}else{1})}}
    let mut status=0;assert_eq!(unsafe{libc::waitpid(pid,&mut status,0)},pid);assert_eq!(status,0);
    let packet=receive(a.as_raw_fd(),32).unwrap();assert!(!peer.matches(&packet.cred));
}
