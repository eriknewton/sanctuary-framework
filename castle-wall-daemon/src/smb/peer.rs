//! All SMB listeners admit peers through this single credential boundary.
use crate::ipc::auth::peer_uid_for_stream;
use std::{
    io,
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
};

/// A refused connection is consumed; only listener failures terminate the serving loop.
#[derive(Debug)]
pub enum AcceptedPeer {
    Admitted(UnixStream),
    Refused,
}

/// Accept a stream only when its connect-time uid equals the required principal.
pub fn accept_checked(listener: &UnixListener, permitted_uid: u32) -> io::Result<AcceptedPeer> {
    let (stream, _) = listener.accept()?;
    // Credentials bind the connect-time principal; read no byte before this check.
    if peer_uid_for_stream(&stream).map_err(io::Error::other)? != permitted_uid {
        let _ = stream.shutdown(Shutdown::Both);
        // Refusal is connection-local so the next permitted principal can still be served.
        return Ok(AcceptedPeer::Refused);
    }
    Ok(AcceptedPeer::Admitted(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        process::Command,
        time::Duration,
    };

    const PERMITTED_UID: u32 = 1001; // Disposable container account, distinct from root.
    const REFUSED_UID: u32 = PERMITTED_UID + 1;
    const CLIENT_DEADLINE_SECONDS: u64 = 2; // Bound a stalled fixture handshake.
    const CONTAINER_DEADLINE: &str = "30s"; // Bound startup and both child handshakes.
    const FIXTURE_MODE: u32 = 0o777; // Both isolated fixture uids need directory traversal and connect.
    struct ReapedChild(std::process::Child);
    impl Drop for ReapedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires explicit SMB_CONTAINER_PEER_IMAGE and --ignored"]
    fn container_peer() {
        // This test body is the real listener, run only by the container fixture below.
        if std::env::var_os("SMB_PEER_CONTAINER").is_some() {
            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(FIXTURE_MODE))
                .unwrap();
            let path = dir.path().join("peer.sock");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FIXTURE_MODE)).unwrap();
            // Separate processes connect after setpriv; socketpair credentials cannot witness this.
            let exe = std::env::current_exe().unwrap();
            let launch = |uid: u32| {
                ReapedChild(
                    Command::new("setpriv")
                        .args([
                            &format!("--reuid={uid}"),
                            &format!("--regid={uid}"),
                            "--clear-groups",
                        ])
                        .arg(&exe)
                        .args([
                            "smb::peer::tests::peer_client",
                            "--exact",
                            "--nocapture",
                            "--ignored",
                        ])
                        .env("SMB_PEER_PATH", &path)
                        .env_remove("SMB_PEER_CONTAINER")
                        .spawn()
                        .unwrap(),
                )
            };
            let mut refused = launch(REFUSED_UID);
            assert!(matches!(
                accept_checked(&listener, PERMITTED_UID).unwrap(),
                AcceptedPeer::Refused
            ));
            assert!(refused.0.wait().unwrap().success());
            let mut admitted = launch(PERMITTED_UID);
            let AcceptedPeer::Admitted(mut stream) =
                accept_checked(&listener, PERMITTED_UID).unwrap()
            else {
                panic!("permitted peer refused");
            };
            stream.write_all(b"admitted").unwrap();
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"x");
            assert!(admitted.0.wait().unwrap().success());
            println!("permitted uid admitted; other uid closed without payload read");
            return;
        }
        // The host owns only the disposable container; --rm and the outer cleanup reap failures.
        let exe = std::env::current_exe().unwrap();
        let name = format!("smb-peer-{}", std::process::id());
        let image = std::env::var("SMB_CONTAINER_PEER_IMAGE")
            .expect("SMB_CONTAINER_PEER_IMAGE must name the fixture image");
        let output = Command::new("timeout")
            .args([
                CONTAINER_DEADLINE,
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--name",
                &name,
                "-e",
                "SMB_PEER_CONTAINER=1",
                "-v",
            ])
            .arg(format!("{}:/peer-test:ro", exe.display()))
            .arg(image)
            .args([
                "/peer-test",
                "smb::peer::tests::container_peer",
                "--exact",
                "--nocapture",
                "--ignored",
            ])
            .output();
        let _ = Command::new("docker").args(["rm", "-f", &name]).output();
        let output = output.expect("docker/timeout required for peer witness");
        println!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(
            output.status.success(),
            "container peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn peer_refusal_keeps_listener_serving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::getuid() };
        let mut refused = UnixStream::connect(&path).unwrap();
        refused
            .set_read_timeout(Some(Duration::from_secs(CLIENT_DEADLINE_SECONDS)))
            .unwrap();
        // Toggling the low uid bit chooses a distinct principal without integer overflow.
        assert!(matches!(
            accept_checked(&listener, uid ^ 1).unwrap(),
            AcceptedPeer::Refused
        ));
        let mut byte = [0; 1]; // One byte suffices to distinguish EOF from a reply.
        assert_eq!(refused.read(&mut byte).unwrap(), 0);
        let _admitted = UnixStream::connect(&path).unwrap();
        assert!(matches!(
            accept_checked(&listener, uid).unwrap(),
            AcceptedPeer::Admitted(_)
        ));
    }

    #[test]
    #[ignore = "helper invoked only by container_peer"]
    fn peer_client() {
        let path = std::env::var_os("SMB_PEER_PATH").expect("peer_client needs its fixture path");
        let mut stream = UnixStream::connect(path).unwrap();
        // A client sends nothing until admitted: any server read before uid checking stalls the witness.
        stream
            .set_read_timeout(Some(Duration::from_secs(CLIENT_DEADLINE_SECONDS)))
            .unwrap();
        let mut bytes = [0_u8; 8]; // Eight bytes in the literal admission token.
        if unsafe { libc::getuid() } == PERMITTED_UID {
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"admitted");
            stream.write_all(b"x").unwrap();
        } else {
            assert_eq!(stream.read(&mut bytes).unwrap(), 0);
        }
    }
}
