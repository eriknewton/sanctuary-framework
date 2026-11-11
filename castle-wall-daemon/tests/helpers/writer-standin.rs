//! Isolation-only signer and wall actors; the wall uses the production writer codec.
use castle_wall_daemon::business_profile::{
    signer_peer, signer_service,
    writer_protocol::{self, Direction, Operation, StatusPayload},
    writer_service::{Notifier, SystemNotifier},
};
use std::{fs, os::fd::AsRawFd, path::Path, thread, time::Duration};
fn receive(fd: i32) -> Vec<u8> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 3000) }, 1); // Three native request windows.
    writer_protocol::receive(fd, Direction::ToWall)
        .unwrap()
        .bytes
}
fn wall(root: &Path, mode: &str) {
    while !root.join("go").exists() {
        thread::sleep(Duration::from_millis(10));
    }
    if mode == "outside" {
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
    if mode == "child" {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid > 0 {
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
    let fd = signer_peer::connect(&root.join("record.sock")).unwrap();
    signer_peer::passcred(fd.as_raw_fd()).unwrap();
    let bytes = receive(fd.as_raw_fd());
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let header: serde_json::Value = serde_json::from_slice(&bytes[4..4 + n]).unwrap();
    let session = header["session_id"].as_str().unwrap();
    assert!(matches!(
        writer_protocol::decode(&bytes, Direction::ToWall, session)
            .unwrap()
            .operation,
        Operation::Hello
    ));
    signer_peer::send(
        fd.as_raw_fd(),
        &writer_protocol::encode(Direction::ToWriter, session, &Operation::HelloAck, &[]).unwrap(),
        &[],
    )
    .unwrap();
    signer_peer::send(
        fd.as_raw_fd(),
        &writer_protocol::encode(
            Direction::ToWriter,
            session,
            &Operation::Status {
                request_id: "a".repeat(32),
            },
            &[],
        )
        .unwrap(),
        &[],
    )
    .unwrap();
    let bytes = receive(fd.as_raw_fd());
    let frame = writer_protocol::decode(&bytes, Direction::ToWall, session).unwrap();
    assert!(matches!(frame.operation, Operation::StatusReply { .. }));
    assert!(StatusPayload::decode(frame.payload)
        .unwrap()
        .grant
        .is_none());
    if mode == "held" || mode == "sign" {
        let holder = signer_peer::connect(&root.join("holder.sock")).unwrap();
        signer_peer::send(holder.as_raw_fd(), b"hold", &[fd.as_raw_fd()]).unwrap();
    }
    fs::write(root.join("wall-bound"), session).unwrap();
    if mode == "sign" {
        while !root.join("sign-packet").exists() {
            thread::sleep(Duration::from_millis(10));
        }
        let bytes = fs::read(root.join("sign-packet")).unwrap();
        assert!(matches!(
            writer_protocol::decode(&bytes, Direction::ToWriter, session)
                .unwrap()
                .operation,
            Operation::Sign(_)
        ));
        signer_peer::send(fd.as_raw_fd(), &bytes, &[]).unwrap();
        let bytes = receive(fd.as_raw_fd());
        let frame = writer_protocol::decode(&bytes, Direction::ToWall, session).unwrap();
        fs::write(
            root.join("sign-result"),
            if matches!(frame.operation, Operation::Verified { .. }) {
                "verified"
            } else {
                "refused"
            },
        )
        .unwrap();
    }
    loop {
        thread::sleep(Duration::from_millis(10));
    }
}
fn signer(root: &Path, bounded: bool) {
    signer_peer::drop_capabilities().unwrap();
    let listener = signer_peer::listen(&root.join("sign.sock")).unwrap();
    fs::write(root.join("manager"), unsafe { libc::getppid() }.to_string()).unwrap();
    SystemNotifier.notify("READY=1").unwrap();
    let fd = loop {
        if let Ok(fd) = signer_peer::accept(listener.as_raw_fd()) {
            break fd;
        }
        thread::sleep(Duration::from_millis(1));
    };
    let mut replies = 0;
    loop {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 100) } != 1 {
            continue;
        }
        let Ok(packet) = signer_peer::receive(fd.as_raw_fd(), 66564) else {
            break;
        };
        if packet.bytes.is_empty() {
            break;
        }
        assert_eq!(packet.bytes, b"{\"op\":\"STATUS\"}");
        if replies == 0 && root.join("replace-config").exists() {
            fs::copy(root.join("writer.json"), root.join("writer-new.json")).unwrap();
            fs::rename(root.join("writer-new.json"), root.join("writer.json")).unwrap();
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("signer-status.json")).unwrap()).unwrap();
        if signer_peer::send(
            fd.as_raw_fd(),
            &signer_service::encode(&value, &[]).unwrap(),
            &[],
        )
        .is_err()
        {
            break;
        }
        replies += 1;
        if bounded && replies == 3 {
            break;
        } // Bootstrap plus two heartbeats before signer loss.
    }
    drop(fd);
    fs::write(root.join("signer-closed"), b"closed").unwrap();
    loop {
        thread::sleep(Duration::from_millis(10));
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 4);
    let root = Path::new(&args[2]);
    match args[1].as_str() {
        "signer" => signer(root, args[3] == "bounded"),
        "wall" => wall(root, &args[3]),
        _ => panic!("unknown actor"),
    }
}
