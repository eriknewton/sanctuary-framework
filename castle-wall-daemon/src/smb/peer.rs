//! All SMB listeners admit peers through this single credential boundary.
use crate::ipc::auth::peer_uid_for_stream;
use std::{
    io,
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
};

/// Accept a stream only when its connect-time uid equals the required principal.
pub fn accept_checked(listener: &UnixListener, permitted_uid: u32) -> io::Result<UnixStream> {
    let (stream, _) = listener.accept()?;
    // Credentials bind the connect-time principal; read no byte before this check.
    if peer_uid_for_stream(&stream).map_err(io::Error::other)? != permitted_uid {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SMB peer refused",
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        process::Command,
        time::Duration,
    };

    #[test]
    fn container_peer() {
        // This test body is the real listener, run only by the container fixture below.
        if std::env::var_os("SMB_PEER_CONTAINER").is_some() {
            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
            let path = dir.path().join("peer.sock");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
            // Separate processes connect after setpriv; socketpair credentials cannot witness this.
            let exe = std::env::current_exe().unwrap();
            let launch = |uid: &str| {
                Command::new("setpriv")
                    .args([
                        &format!("--reuid={uid}"),
                        &format!("--regid={uid}"),
                        "--clear-groups",
                    ])
                    .arg(&exe)
                    .args(["smb::peer::tests::peer_client", "--exact", "--nocapture"])
                    .env("SMB_PEER_PATH", &path)
                    .env_remove("SMB_PEER_CONTAINER")
                    .spawn()
                    .unwrap()
            };
            let mut refused = launch("1002");
            assert_eq!(
                accept_checked(&listener, 1001).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(refused.wait().unwrap().success());
            let mut admitted = launch("1001");
            let mut stream = accept_checked(&listener, 1001).unwrap();
            stream.write_all(b"admitted").unwrap();
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"x");
            assert!(admitted.wait().unwrap().success());
            println!("permitted uid admitted; other uid closed without payload read");
            return;
        }
        // The host owns only the disposable container; --rm and the outer cleanup reap failures.
        let exe = std::env::current_exe().unwrap();
        let name = format!("smb-peer-{}", std::process::id());
        let image = std::env::var("SMB_PEER_IMAGE").unwrap_or_else(|_| "n2cap-canary:r4".into());
        let output = Command::new("timeout")
            .args([
                "30s",
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
    fn peer_client() {
        let Some(path) = std::env::var_os("SMB_PEER_PATH") else {
            return;
        };
        let mut stream = UnixStream::connect(path).unwrap();
        // A client sends nothing until admitted: any server read before uid checking stalls the witness.
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0_u8; 8]; // Eight bytes in the literal admission token.
        if unsafe { libc::getuid() } == 1001 {
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"admitted");
            stream.write_all(b"x").unwrap();
        } else {
            assert_eq!(stream.read(&mut bytes).unwrap(), 0);
        }
    }
}
