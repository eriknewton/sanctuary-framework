#[test]
fn bpf_builder_is_well_formed_and_multi_arch() {
    let program = castle_wall_daemon::jail::build_deny_vsock_socket_filter();
    assert!(!program.is_empty());
    assert!(program
        .iter()
        .any(|insn| insn.k == castle_wall_daemon::jail::AUDIT_ARCH_X86_64));
    assert!(program
        .iter()
        .any(|insn| insn.k == castle_wall_daemon::jail::AUDIT_ARCH_AARCH64));
    assert!(program
        .iter()
        .any(|insn| insn.k == castle_wall_daemon::jail::NR_SOCKET_X86_64));
    assert!(program
        .iter()
        .any(|insn| insn.k == castle_wall_daemon::jail::NR_SOCKET_AARCH64));
    assert_eq!(
        program.last().expect("filter has final instruction").k,
        castle_wall_daemon::jail::SECCOMP_RET_ERRNO_EPERM
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    const CHILD_OK: i32 = 0;
    const CHILD_CONFINEMENT_FAILED: i32 = 10;
    const CHILD_VSOCK_NOT_DENIED: i32 = 11;
    const CHILD_UNIX_BLOCKED: i32 = 12;
    const CHILD_INET_BLOCKED: i32 = 13;

    #[test]
    fn in_process_confinement_denies_only_af_vsock_three_times() {
        for _ in 0..3 {
            assert_eq!(run_confined_child(), CHILD_OK);
        }
    }

    #[test]
    fn sanctuary_jail_binary_denies_af_vsock_after_exec() {
        if Command::new("python3").arg("--version").status().is_err() {
            return;
        }

        let jail_bin = std::env::var("CARGO_BIN_EXE_sanctuary-jail")
            .expect("cargo exposes sanctuary-jail binary path to integration tests");
        let script = r#"
import errno
import socket
import sys

af_vsock = getattr(socket, "AF_VSOCK", 40)
try:
    sock = socket.socket(af_vsock, socket.SOCK_STREAM)
except PermissionError as exc:
    sys.exit(0 if exc.errno == errno.EPERM else 21)
except OSError:
    sys.exit(22)
else:
    sock.close()
    sys.exit(23)
"#;

        let status = Command::new(jail_bin)
            .args(["--", "python3", "-c", script])
            .status()
            .expect("run sanctuary-jail smoke probe");
        assert_eq!(status.code(), Some(0));
    }

    fn run_confined_child() -> i32 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let code = confined_child_result();
            unsafe {
                libc::_exit(code);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        }
    }

    fn confined_child_result() -> i32 {
        if castle_wall_daemon::jail::confine_current_process().is_err() {
            return CHILD_CONFINEMENT_FAILED;
        }
        if socket_result(libc::AF_VSOCK) != Err(libc::EPERM) {
            return CHILD_VSOCK_NOT_DENIED;
        }
        if socket_result(libc::AF_UNIX).is_err() {
            return CHILD_UNIX_BLOCKED;
        }
        if socket_result(libc::AF_INET).is_err() {
            return CHILD_INET_BLOCKED;
        }
        CHILD_OK
    }

    fn socket_result(domain: libc::c_int) -> Result<(), i32> {
        let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
        if fd >= 0 {
            let _ = unsafe { libc::close(fd) };
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }
}
