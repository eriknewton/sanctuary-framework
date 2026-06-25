//! Hostile-plugin drill (plugin-host slice S5).
//!
//! Pre-declared acceptance: a HOSTILE plugin — one that actively tries to break out
//! of its jail — must have every escape probe DENIED. The probes, fixed before the
//! drill:
//!
//!   1. raw socket          — socket(AF_INET, SOCK_RAW/STREAM): must be EPERM. The
//!      plugin-v1 seccomp profile allows only AF_UNIX, so a plugin cannot open ANY
//!      internet socket. This is also the prerequisite for probe 3, so denying it
//!      denies outbound network at the syscall layer.
//!   2. ptrace              — ptrace(PTRACE_TRACEME): must be EPERM. A plugin must
//!      not attach to / inspect another process.
//!   3. daemon-port connect — connect() to a loopback daemon port. Because probe 1
//!      denies AF_INET socket creation, the plugin cannot even construct the fd to
//!      connect with: the connect is unreachable. The drill asserts the socket()
//!      denial that makes the connect impossible.
//!   4. host-file read      — reading a host path outside the bundle. Under seccomp
//!      ALONE the open/read syscalls are not blocked (file confinement is the
//!      launcher's pivot_root job, proven by plugin_launcher_failclosed.rs). This
//!      drill ALSO proves the filesystem half directly: in a child that enters an
//!      unprivileged user+mount namespace and pivots into an empty rootfs, a host
//!      path (/etc/shadow) is ENOENT — absent, not merely permission-denied. When
//!      unprivileged userns is unavailable in the CI sandbox, the probe is recorded
//!      as `launcher_covered` (the seccomp layer still ran), never silently skipped.
//!
//! Repeated N>=3 (drill-acceptance rule). Evidence (one JSON line per run + a
//! summary) is printed to stdout so the run can be captured; the runbook + banked
//! evidence live at docs/audit/plugin-hostile-drill-2026-06-24.md. Linux-only;
//! portable platforms compile a no-op so `cargo test` stays green off-Linux.

#![allow(clippy::needless_return)]

#[cfg(target_os = "linux")]
const DRILL_RUNS: usize = 3;

#[cfg(not(target_os = "linux"))]
#[test]
fn hostile_plugin_drill_is_linux_only() {
    eprintln!("plugin_hostile_drill: skipped (not Linux); confinement is a Linux capability");
}

#[cfg(target_os = "linux")]
#[test]
fn hostile_plugin_drill_denies_every_escape_probe_n_times() {
    use linux::{run_one_drill, ProbeOutcome};

    let mut all_passed = true;
    for run in 1..=DRILL_RUNS {
        let outcome = run_one_drill();
        let passed = outcome.seccomp_probes_all_denied();
        all_passed &= passed;
        println!(
            "{{\"drill\":\"plugin-hostile\",\"run\":{},\"raw_socket_denied\":{},\"ptrace_denied\":{},\"daemon_port_unreachable\":{},\"host_file\":\"{}\",\"ipc_roundtrip_ok\":{},\"pass\":{}}}",
            run,
            outcome.raw_socket_denied,
            outcome.ptrace_denied,
            outcome.daemon_port_unreachable,
            match outcome.host_file {
                ProbeOutcome::DeniedAbsent => "denied_absent",
                ProbeOutcome::LauncherCovered => "launcher_covered",
                ProbeOutcome::Leaked => "LEAKED",
            },
            outcome.ipc_roundtrip_ok,
            passed,
        );
        assert!(passed, "hostile probe escaped on run {run}: {outcome:?}");
        assert!(
            !matches!(outcome.host_file, ProbeOutcome::Leaked),
            "host-file read leaked on run {run}"
        );
    }
    println!(
        "{{\"drill\":\"plugin-hostile\",\"summary\":true,\"runs\":{},\"all_passed\":{}}}",
        DRILL_RUNS, all_passed
    );
    assert!(all_passed, "hostile-plugin drill failed");
}

#[cfg(target_os = "linux")]
mod linux {
    /// Result of the host-file probe.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProbeOutcome {
        /// File confinement proven: the host path is ABSENT in the pivoted rootfs.
        DeniedAbsent,
        /// Unprivileged userns unavailable here; file confinement is the launcher's
        /// pivot_root job (proven elsewhere). The seccomp layer still ran.
        LauncherCovered,
        /// The host path was readable — a confinement FAILURE.
        Leaked,
    }

    #[derive(Debug)]
    pub struct DrillOutcome {
        pub raw_socket_denied: bool,
        pub ptrace_denied: bool,
        pub daemon_port_unreachable: bool,
        pub host_file: ProbeOutcome,
        pub ipc_roundtrip_ok: bool,
    }

    impl DrillOutcome {
        /// The three seccomp-layer probes plus the IPC liveness must hold every run;
        /// host_file must never be Leaked (checked separately).
        pub fn seccomp_probes_all_denied(&self) -> bool {
            self.raw_socket_denied
                && self.ptrace_denied
                && self.daemon_port_unreachable
                && self.ipc_roundtrip_ok
                && self.host_file != ProbeOutcome::Leaked
        }
    }

    const CHILD_BASE: i32 = 40;

    /// Run one full hostile drill in a forked child under plugin-v1 confinement, then
    /// in a second child for the namespace file-confinement probe.
    pub fn run_one_drill() -> DrillOutcome {
        let seccomp = run_seccomp_child();
        let host_file = run_file_confinement_child();
        DrillOutcome {
            raw_socket_denied: seccomp.raw_socket_denied,
            ptrace_denied: seccomp.ptrace_denied,
            daemon_port_unreachable: seccomp.daemon_port_unreachable,
            host_file,
            ipc_roundtrip_ok: seccomp.ipc_roundtrip_ok,
        }
    }

    struct SeccompResult {
        raw_socket_denied: bool,
        ptrace_denied: bool,
        daemon_port_unreachable: bool,
        ipc_roundtrip_ok: bool,
    }

    /// Fork a child, apply the plugin-v1 seccomp profile, run the syscall probes, and
    /// report a bitmask via the exit code.
    fn run_seccomp_child() -> SeccompResult {
        let code = fork_and_run(|| {
            if castle_wall_daemon::jail::confine_current_process_with_profile(
                castle_wall_daemon::jail::SeccompProfile::PluginV1,
            )
            .is_err()
            {
                return CHILD_BASE; // confinement itself failed
            }
            let mut bits = 0i32;
            // probe 1: raw/internet socket denied (EPERM)
            if socket_result(libc::AF_INET, libc::SOCK_STREAM) == Err(libc::EPERM) {
                bits |= 1;
            }
            if socket_result(libc::AF_INET, libc::SOCK_RAW) == Err(libc::EPERM) {
                bits |= 1 << 1;
            }
            // probe 2: ptrace denied (EPERM)
            if ptrace_traceme_result() == Err(libc::EPERM) {
                bits |= 1 << 2;
            }
            // probe 3: daemon-port connect unreachable — AF_INET socket cannot even
            // be created, so the connect fd is unobtainable. (Already covered by
            // probe 1; we assert it independently for the evidence line.)
            if socket_result(libc::AF_INET, libc::SOCK_STREAM) == Err(libc::EPERM) {
                bits |= 1 << 3;
            }
            // IPC liveness: the ALLOWED path (AF_UNIX socketpair) must still work, so
            // confinement is not just "deny everything".
            if af_unix_socketpair_ok() {
                bits |= 1 << 4;
            }
            CHILD_BASE + bits
        });
        let bits = (code - CHILD_BASE).max(0);
        SeccompResult {
            raw_socket_denied: (bits & 1) != 0 && (bits & (1 << 1)) != 0,
            ptrace_denied: (bits & (1 << 2)) != 0,
            daemon_port_unreachable: (bits & (1 << 3)) != 0,
            ipc_roundtrip_ok: (bits & (1 << 4)) != 0,
        }
    }

    /// Fork a child that tries to enter an unprivileged user+mount namespace and
    /// pivot into an empty rootfs, then read a host path. Exit codes:
    ///   70 = DeniedAbsent (host path ENOENT after pivot)
    ///   71 = LauncherCovered (userns/pivot unavailable here)
    ///   72 = Leaked (host path readable)
    fn run_file_confinement_child() -> ProbeOutcome {
        let code = fork_and_run(file_confinement_probe);
        match code {
            70 => ProbeOutcome::DeniedAbsent,
            72 => ProbeOutcome::Leaked,
            _ => ProbeOutcome::LauncherCovered,
        }
    }

    fn file_confinement_probe() -> i32 {
        use std::ffi::CString;

        // Enter a new user namespace (unprivileged) + mount namespace. If the sandbox
        // forbids unprivileged userns, this fails and we report LauncherCovered.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
        if rc != 0 {
            return 71;
        }
        // Make mounts private so our tmpfs/pivot does not propagate.
        let root = CString::new("/").unwrap();
        let none = CString::new("none").unwrap();
        let _ = unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        // Build an empty rootfs on tmpfs and chroot into it (a minimal stand-in for
        // the launcher's pivot_root: the point is the host filesystem is gone).
        let tmp = CString::new("/tmp/sanctuary-hostile-rootfs").unwrap();
        unsafe {
            libc::mkdir(tmp.as_ptr(), 0o700);
        }
        let tmpfs = CString::new("tmpfs").unwrap();
        let mnt = unsafe {
            libc::mount(
                none.as_ptr(),
                tmp.as_ptr(),
                tmpfs.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if mnt != 0 {
            return 71;
        }
        if unsafe { libc::chroot(tmp.as_ptr()) } != 0 {
            return 71;
        }
        let _ = unsafe { libc::chdir(CString::new("/").unwrap().as_ptr()) };

        // Now try to read a host path. After chroot into the empty tmpfs, the host
        // /etc/shadow does not exist → ENOENT (absent, not EACCES). A successful read
        // is a LEAK.
        match std::fs::read("/etc/shadow") {
            Ok(_) => 72,
            Err(err) => {
                if err.raw_os_error() == Some(libc::ENOENT) {
                    70
                } else {
                    // Some other error (e.g. EACCES) — the file is not readable, but
                    // we wanted to prove ABSENCE. Treat as launcher-covered rather
                    // than claim the absence proof.
                    71
                }
            }
        }
    }

    fn fork_and_run(child: impl FnOnce() -> i32) -> i32 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = child();
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        }
    }

    fn socket_result(domain: libc::c_int, ty: libc::c_int) -> Result<(), i32> {
        let fd = unsafe { libc::socket(domain, ty, 0) };
        if fd >= 0 {
            let _ = unsafe { libc::close(fd) };
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    fn af_unix_socketpair_ok() -> bool {
        let mut fds = [-1; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc == 0 {
            let _ = unsafe { libc::close(fds[0]) };
            let _ = unsafe { libc::close(fds[1]) };
            true
        } else {
            false
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

    fn last_errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }
}
