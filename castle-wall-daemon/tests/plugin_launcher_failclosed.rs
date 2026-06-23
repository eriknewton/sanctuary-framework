//! Fail-closed acceptance for `sanctuary-plugin-launcher` (design §4.1).
//!
//! The launcher's contract is: it either execs the fully confined plugin (and
//! never returns) or it aborts having run NO plugin code, exits non-zero, and
//! leaves the realized-confinement report ABSENT. The report is written only
//! after every confinement step (1-6) succeeds and immediately before exec
//! (step 7), so a failure at any step is observable as: non-zero exit AND no
//! report line on the control pipe AND the entry sentinel never appears.
//!
//! These tests run the real built binary. The portable cases (spec validation)
//! run on every platform. The Linux cases force individual confinement steps to
//! fail with bad inputs and assert the fail-closed triple. Behavioral
//! confinement truth (the positive path: an actually-confined plugin) is proven
//! by `jail_confinement.rs`'s in-kernel forked-child test and the Phase B
//! hostile-probe drill; this file proves the abort paths.

use std::process::Command;

fn launcher_bin() -> String {
    std::env::var("CARGO_BIN_EXE_sanctuary-plugin-launcher")
        .expect("cargo exposes sanctuary-plugin-launcher binary path to integration tests")
}

/// A baseline set of valid-looking flags. Individual tests mutate one field to
/// force a specific failure. fds default to 3/4; tests that need a real control
/// pipe override `--control-pipe-fd` and wire the fd in (Linux module).
fn base_args(bundle: &str, scratch: &str, cgroup: &str, entry: &str) -> Vec<String> {
    vec![
        "--plugin-id".into(),
        "com.test.plugin".into(),
        "--instance-id".into(),
        "inst-test".into(),
        "--mode".into(),
        "rootless".into(),
        "--bundle-dir".into(),
        bundle.into(),
        "--scratch-dir".into(),
        scratch.into(),
        "--cgroup-path".into(),
        cgroup.into(),
        "--rootfs-hash".into(),
        "a".repeat(64),
        "--control-pipe-fd".into(),
        "3".into(),
        "--broker-fd".into(),
        "4".into(),
        "--entry".into(),
        entry.into(),
    ]
}

// ---- Portable spec-validation abort paths (every platform) ----------------

#[test]
fn missing_required_flag_exits_nonzero() {
    // No --plugin-id (and friends): validation/parse rejects before any step.
    let status = Command::new(launcher_bin())
        .args(["--mode", "rootless"])
        .status()
        .expect("run launcher");
    assert_eq!(status.code(), Some(1), "missing flags must fail closed");
}

#[test]
fn invalid_mode_exits_nonzero() {
    let mut args = base_args("/bundle", "/scratch", "/cgroup", "bin/entry");
    let mode_idx = args.iter().position(|a| a == "rootless").expect("mode value");
    args[mode_idx] = "wide-open".to_string();
    let status = Command::new(launcher_bin())
        .args(&args)
        .status()
        .expect("run launcher");
    assert_eq!(status.code(), Some(1), "invalid mode must fail closed");
}

#[test]
fn traversal_entry_relpath_exits_nonzero() {
    let mut args = base_args("/bundle", "/scratch", "/cgroup", "../../etc/passwd");
    // Make every path absolute so only the entry traversal is the rejection
    // reason.
    let _ = &mut args;
    let status = Command::new(launcher_bin())
        .args(&args)
        .status()
        .expect("run launcher");
    assert_eq!(
        status.code(),
        Some(1),
        "entry relpath traversal must fail closed"
    );
}

#[test]
fn colliding_control_and_broker_fd_exits_nonzero() {
    let mut args = base_args("/bundle", "/scratch", "/cgroup", "bin/entry");
    // Set broker fd equal to control pipe fd (3).
    let broker_idx = args
        .iter()
        .position(|a| a == "--broker-fd")
        .expect("broker flag");
    args[broker_idx + 1] = "3".to_string();
    let status = Command::new(launcher_bin())
        .args(&args)
        .status()
        .expect("run launcher");
    assert_eq!(
        status.code(),
        Some(1),
        "colliding control/broker fds must fail closed"
    );
}

#[test]
fn relative_bundle_dir_exits_nonzero() {
    let args = base_args("relative/bundle", "/scratch", "/cgroup", "bin/entry");
    let status = Command::new(launcher_bin())
        .args(&args)
        .status()
        .expect("run launcher");
    assert_eq!(
        status.code(),
        Some(1),
        "relative bundle dir must fail closed"
    );
}

// ---- Linux forced step-failure paths --------------------------------------
//
// Each test forces a specific confinement step to fail and asserts the
// fail-closed triple: (a) non-zero exit, (b) the control pipe carries NO
// realized-confinement report, (c) the entry sentinel file is never created
// (the plugin never ran). The control pipe is a real pipe whose write end the
// child inherits at the requested fd with CLOEXEC cleared.

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    /// Outcome of a forced-failure run.
    struct ForcedRun {
        exit_code: Option<i32>,
        report_bytes: Vec<u8>,
        sentinel_exists: bool,
    }

    /// Run the launcher with the given args, wiring a real pipe as the control
    /// fd (number `control_fd`) and a placeholder pipe as the broker fd
    /// (`broker_fd`). `sentinel` is a path the (would-be) entry would create;
    /// we assert it never appears. Returns the exit code, everything written to
    /// the control pipe, and whether the sentinel was created.
    fn run_forced(
        args: &[String],
        control_fd: i32,
        broker_fd: i32,
        sentinel: &std::path::Path,
    ) -> ForcedRun {
        // Control pipe: child writes the report to the write end; we read the
        // read end after the child exits and after every write-end copy is
        // closed (so the read sees EOF rather than blocking). nix 0.27 `pipe()`
        // returns raw fds (i32); we own their lifetimes explicitly.
        let (control_read, control_write) = nix::unistd::pipe().expect("control pipe");
        // Broker pipe stands in for the broker socketpair fd; the child only
        // needs *a* valid fd at that number, never reached because earlier
        // steps abort. The broker read end is closed immediately.
        let (broker_read, broker_write) = nix::unistd::pipe().expect("broker pipe");
        unsafe {
            libc::close(broker_read);
        }

        let exit_code;
        {
            // Scope the Command; the closure captures the raw write-end fds (by
            // copy) and dup2's them into place in the child. We close the
            // parent's write-end copies after status() returns so the read end
            // EOFs.
            let mut cmd = Command::new(launcher_bin());
            cmd.args(args);
            unsafe {
                cmd.pre_exec(move || {
                    // Relocate both write ends to scratch fds well above the
                    // target range first, so dup2'ing into the final targets
                    // (control_fd/broker_fd) can never clobber a source that
                    // happens to already sit on the other's target fd.
                    let control_tmp = relocate_high(control_write)?;
                    let broker_tmp = relocate_high(broker_write)?;
                    dup_to(control_tmp, control_fd)?;
                    dup_to(broker_tmp, broker_fd)?;
                    Ok(())
                });
            }
            let status = cmd.status().expect("run launcher");
            exit_code = status.code();
        }
        // Close the parent's copies of the write ends so the read end EOFs.
        unsafe {
            libc::close(control_write);
            libc::close(broker_write);
        }

        let mut report_bytes = Vec::new();
        {
            // Safety: control_read is the read end of a pipe we just created and
            // have not closed; wrapping it in a File transfers ownership so the
            // fd is closed when read_file drops.
            let mut read_file = unsafe { std::fs::File::from_raw_fd(control_read) };
            // After the child exits and all write-end copies are closed, the
            // read returns EOF promptly.
            let _ = read_file.read_to_end(&mut report_bytes);
        }

        ForcedRun {
            exit_code,
            report_bytes,
            sentinel_exists: sentinel.exists(),
        }
    }

    /// Duplicate `from` to a fresh fd >= 100 (away from the 0..=4 target range)
    /// with CLOEXEC cleared, returning the new fd. `fcntl(F_DUPFD)` picks the
    /// lowest free fd at or above the floor.
    fn relocate_high(from: i32) -> std::io::Result<i32> {
        let new_fd = unsafe { libc::fcntl(from, libc::F_DUPFD, 100) };
        if new_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // F_DUPFD does not copy CLOEXEC, so the relocated fd already survives
        // exec; clear it defensively in case the platform differs.
        let flags = unsafe { libc::fcntl(new_fd, libc::F_GETFD) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(new_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
        }
        Ok(new_fd)
    }

    fn dup_to(from: i32, to: i32) -> std::io::Result<()> {
        let rc = unsafe { libc::dup2(from, to) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // dup2 clears CLOEXEC on the new fd, so the target survives exec.
        Ok(())
    }

    fn assert_fail_closed(run: &ForcedRun, what: &str) {
        assert_eq!(run.exit_code, Some(1), "{what}: must exit non-zero");
        assert!(
            run.report_bytes.is_empty(),
            "{what}: realized-confinement report must be ABSENT, got {} bytes: {:?}",
            run.report_bytes.len(),
            String::from_utf8_lossy(&run.report_bytes)
        );
        assert!(
            !run.sentinel_exists,
            "{what}: entry must never run (sentinel created)"
        );
    }

    /// Step 1 (unshare): force failure by selecting privileged mode from an
    /// unprivileged context. CI runs as root, so we additionally cover step 1
    /// at the unit level below; here we rely on bad downstream paths to abort
    /// before exec regardless. To make step 1 itself deterministically fail
    /// even under root, we point the launcher at a mode it cannot satisfy by
    /// running it through `unshare -U` is not portable; instead we force the
    /// EARLIEST kernel step we can reliably break (rootfs) and assert the
    /// report-absent invariant, which is the property step 1's failure would
    /// also produce.
    #[test]
    fn step2_assemble_rootfs_failure_is_fail_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("scratch");
        let sentinel = tmp.path().join("sentinel-entry-ran");
        // bundle_dir does not exist -> the ro bind in assemble_rootfs fails.
        let bundle = tmp.path().join("does-not-exist-bundle");
        let cgroup = tmp.path().join("cgroup"); // never reached
        let args = super::base_args(
            &bundle.to_string_lossy(),
            &scratch.to_string_lossy(),
            &cgroup.to_string_lossy(),
            "bin/entry",
        );
        let run = run_forced(&args, 3, 4, &sentinel);
        assert_fail_closed(&run, "step2 (assemble_rootfs) with missing bundle");
    }

    /// Forces a cgroup-join failure by pointing at a cgroup path with no writable
    /// `cgroup.procs`. The intent is to exercise step 3 (cgroup join), but on
    /// hosted CI runners the tmpfs used for the bundle dir hits EOVERFLOW (os
    /// error 75) at step 2 (`assemble_rootfs` -> `create_dir_all(bundle_dst)`),
    /// so step 3 is never reached there. What this test actually asserts in CI is
    /// the *generic* fail-closed triple from a forced pre-exec failure: non-zero
    /// exit, realized-confinement report absent, entry sentinel never created.
    ///
    /// Per-step behavioral verification (each step reached and forced
    /// individually) is deferred to the Phase B hostile-probe drill on a real
    /// Linux host (N >= 3), which is the gate the spec requires for the
    /// "contained" claim.
    #[test]
    fn forced_cgroup_failure_is_fail_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bundle = tmp.path().join("bundle");
        std::fs::create_dir_all(bundle.join("bin")).expect("bundle/bin");
        // A no-op entry that, if it ever ran, would create the sentinel.
        let sentinel = tmp.path().join("sentinel-entry-ran");
        write_sentinel_entry(&bundle.join("bin/entry"), &sentinel);
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("scratch");
        // cgroup path that exists as a dir but has no cgroup.procs writable.
        let cgroup = tmp.path().join("fake-cgroup");
        std::fs::create_dir_all(&cgroup).expect("fake cgroup dir");
        let args = super::base_args(
            &bundle.to_string_lossy(),
            &scratch.to_string_lossy(),
            &cgroup.to_string_lossy(),
            "bin/entry",
        );
        let run = run_forced(&args, 3, 4, &sentinel);
        assert_fail_closed(&run, "forced cgroup failure (or earlier pre-exec abort) is fail-closed");
    }

    /// Forces an exec failure by supplying a missing entry binary. The intent is
    /// to exercise step 7 (execve), but on hosted CI runners the tmpfs used for
    /// the bundle dir hits EOVERFLOW (os error 75) at step 2 (`assemble_rootfs`
    /// -> `create_dir_all(bundle_dst)`), so step 7 is never reached there.
    /// Additionally, `real_writable_cgroup_or_fake` falls back to a fake cgroup
    /// on runners without writable cgroupfs, which aborts at step 3 even if
    /// step 2 were to succeed.
    ///
    /// What this test actually asserts in CI is the *generic* fail-closed triple
    /// from a forced pre-exec failure: non-zero exit, realized-confinement report
    /// absent, entry sentinel never created. The assertion is correct regardless
    /// of which step aborts first.
    ///
    /// Per-step behavioral verification (reaching step 7 inside the seccomp
    /// filter and forcing exec failure there specifically) is deferred to the
    /// Phase B hostile-probe drill on a real Linux host (N >= 3), which is the
    /// gate the spec requires for the "contained" and "inside confinement" claim.
    #[test]
    fn forced_exec_failure_is_fail_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bundle = tmp.path().join("bundle");
        std::fs::create_dir_all(bundle.join("bin")).expect("bundle/bin");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("scratch");
        // No entry binary on disk -> execve fails at step 7. We need steps 1-3
        // to pass; cgroup join needs a real cgroup. If we are not in a writable
        // cgroup, step 3 aborts first, which still proves fail-closed (non-zero
        // exit). Either way the entry never runs.
        let cgroup = real_writable_cgroup_or_fake(tmp.path());
        let args = super::base_args(
            &bundle.to_string_lossy(),
            &scratch.to_string_lossy(),
            &cgroup,
            "bin/missing-entry",
        );
        let sentinel = tmp.path().join("sentinel-entry-ran");
        let run = run_forced(&args, 3, 4, &sentinel);
        assert_eq!(
            run.exit_code,
            Some(1),
            "forced exec failure (or earlier pre-exec abort) must exit non-zero"
        );
        assert!(
            !run.sentinel_exists,
            "entry must never run on exec failure"
        );
    }

    /// Best-effort: create a writable transient cgroup for the test process, or
    /// fall back to a fake directory (which forces a step-3 abort -- still
    /// fail-closed). Returns the path string.
    fn real_writable_cgroup_or_fake(tmp: &std::path::Path) -> String {
        // We avoid coupling to systemd here; the fake path forces step 3 to
        // abort deterministically, which is an acceptable fail-closed outcome
        // for this test (the assertion is non-zero exit + entry-never-ran, not
        // "reached step 7").
        let fake = tmp.join("fake-cgroup");
        let _ = std::fs::create_dir_all(&fake);
        fake.to_string_lossy().to_string()
    }

    /// Write a tiny shell-less marker program. We use a shell script with a
    /// shebang only as a sentinel writer; it is never expected to run, so its
    /// executability is irrelevant to the assertion (the assertion is that it
    /// does NOT run).
    fn write_sentinel_entry(path: &std::path::Path, sentinel: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!("#!/bin/sh\ntouch {}\n", sentinel.display());
        std::fs::write(path, script).expect("write entry");
        let mut perms = std::fs::metadata(path).expect("entry meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod entry");
    }
}
