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
    const CHILD_PLUGIN_CONFINEMENT_FAILED: i32 = 20;
    const CHILD_PLUGIN_UNIX_BLOCKED: i32 = 21;
    const CHILD_PLUGIN_INET_NOT_DENIED: i32 = 22;
    const CHILD_PLUGIN_PTRACE_NOT_DENIED: i32 = 23;
    const CHILD_PLUGIN_MOUNT_NOT_DENIED: i32 = 24;
    const CHILD_PLUGIN_UNSHARE_NOT_DENIED: i32 = 25;
    const CHILD_PLUGIN_PROCESS_VM_NOT_DENIED: i32 = 26;
    const CHILD_PLUGIN_FILE_READ_EPERM: i32 = 27;
    const CHILD_PLUGIN_SOCKETPAIR_INET_NOT_DENIED: i32 = 28;
    const CHILD_PLUGIN_CLONE3_NOT_DENIED: i32 = 29;
    const CHILD_PLUGIN_SECCOMP_NOT_DENIED: i32 = 30;
    const CHILD_PLUGIN_PRCTL_NOT_DENIED: i32 = 31;

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

    #[test]
    fn plugin_v1_profile_denies_escape_syscalls_in_kernel() {
        assert_eq!(run_plugin_confined_child(), CHILD_OK);
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

    fn run_plugin_confined_child() -> i32 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let code = plugin_confined_child_result();
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

    fn plugin_confined_child_result() -> i32 {
        if castle_wall_daemon::jail::confine_current_process_with_profile(
            castle_wall_daemon::jail::SeccompProfile::PluginV1,
        )
        .is_err()
        {
            return CHILD_PLUGIN_CONFINEMENT_FAILED;
        }
        if socket_result(libc::AF_UNIX).is_err() {
            return CHILD_PLUGIN_UNIX_BLOCKED;
        }
        if socket_result(libc::AF_INET) != Err(libc::EPERM) {
            return CHILD_PLUGIN_INET_NOT_DENIED;
        }
        if socketpair_result(libc::AF_INET) != Err(libc::EPERM) {
            return CHILD_PLUGIN_SOCKETPAIR_INET_NOT_DENIED;
        }
        if ptrace_traceme_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_PTRACE_NOT_DENIED;
        }
        if mount_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_MOUNT_NOT_DENIED;
        }
        if unshare_result(libc::CLONE_NEWNET) != Err(libc::EPERM) {
            return CHILD_PLUGIN_UNSHARE_NOT_DENIED;
        }
        if process_vm_readv_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_PROCESS_VM_NOT_DENIED;
        }
        if clone3_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_CLONE3_NOT_DENIED;
        }
        if seccomp_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_SECCOMP_NOT_DENIED;
        }
        if prctl_set_dumpable_result() != Err(libc::EPERM) {
            return CHILD_PLUGIN_PRCTL_NOT_DENIED;
        }
        if std::fs::read("/etc/hosts")
            .err()
            .and_then(|err| err.raw_os_error())
            == Some(libc::EPERM)
        {
            return CHILD_PLUGIN_FILE_READ_EPERM;
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

    fn socketpair_result(domain: libc::c_int) -> Result<(), i32> {
        let mut fds = [-1; 2];
        let rc = unsafe { libc::socketpair(domain, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc == 0 {
            let _ = unsafe { libc::close(fds[0]) };
            let _ = unsafe { libc::close(fds[1]) };
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn ptrace_traceme_result() -> Result<(), i32> {
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn mount_result() -> Result<(), i32> {
        let src = std::ffi::CString::new("none").unwrap();
        let target = std::ffi::CString::new("/").unwrap();
        let fstype = std::ffi::CString::new("tmpfs").unwrap();
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null::<libc::c_void>(),
            )
        };
        if rc == 0 {
            let _ = unsafe { libc::umount2(target.as_ptr(), 0) };
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn unshare_result(flags: libc::c_int) -> Result<(), i32> {
        let rc = unsafe { libc::unshare(flags) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn process_vm_readv_result() -> Result<(), i32> {
        let remote_value = 0u8;
        let mut local_value = 0u8;
        let local = libc::iovec {
            iov_base: (&mut local_value as *mut u8).cast(),
            iov_len: 1,
        };
        let remote = libc::iovec {
            iov_base: (&remote_value as *const u8 as *mut u8).cast(),
            iov_len: 1,
        };
        let rc = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        if rc >= 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn clone3_result() -> Result<(), i32> {
        let rc =
            unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0usize) };
        if rc >= 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn seccomp_result() -> Result<(), i32> {
        let rc = unsafe { libc::syscall(libc::SYS_seccomp, u32::MAX, 0usize, 0usize) };
        if rc >= 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn prctl_set_dumpable_result() -> Result<(), i32> {
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }
}
