//! Bounded provisioning files and helpers preserve custody and recoverable state.
#![cfg(target_os = "linux")]
use castle_wall_daemon::linux_install::transaction::{run_bounded, Root};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    time::{Duration, Instant},
};

#[test]
fn custody_refuses_links_writable_files_and_growth_quota() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    root.mkdir("state", 0o700).unwrap();
    root.write("state/data", b"good", 0o600).unwrap();
    assert_eq!(root.read("state/data", 4).unwrap(), b"good");
    assert!(root.read("state/data", 3).is_err());
    fs::hard_link(tmp.path().join("state/data"), tmp.path().join("state/hard")).unwrap();
    assert!(root.read("state/data", 4).is_err());
    fs::remove_file(tmp.path().join("state/hard")).unwrap();
    symlink("data", tmp.path().join("state/link")).unwrap();
    assert!(root.read("state/link", 4).is_err());
    fs::write(tmp.path().join("state/writable"), b"x").unwrap();
    fs::set_permissions(
        tmp.path().join("state/writable"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(root.read("state/writable", 4).is_err());
    assert!(root.read("state/../state/writable", 4).is_err());
    assert!(root.write("state/link", b"bad", 0o600).is_err());
}

#[test]
fn helpers_bound_output_timeout_and_reap_descendants() {
    let started = Instant::now();
    assert!(run_bounded(
        "/bin/sh",
        &["-c", "sleep 30 & wait"],
        Duration::from_millis(100),
        64
    )
    .is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    let overflow =
        run_bounded("/bin/sh", &["-c", "yes x"], Duration::from_secs(1), 64).unwrap_err();
    assert!(overflow.to_string().contains("output quota"));
    let result = run_bounded(
        "/usr/bin/printf",
        &["literal;$HOME"],
        Duration::from_secs(1),
        64,
    )
    .unwrap();
    assert_eq!(result.stdout, b"literal;$HOME");
}

#[test]
fn lock_contention_never_removes_existing_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    let guard = root.lock("mutation.lock").unwrap();
    assert!(root.lock("mutation.lock").is_err());
    drop(guard);
    assert!(root.lock("mutation.lock").is_ok());
}

#[test]
fn malformed_transaction_cannot_resume_account_or_policy_mutation() {
    use castle_wall_daemon::linux_install::{
        account::AccountStep,
        transaction::{State, Transaction},
    };
    let good = Transaction {
        version: 1,
        request_sha256: "a".repeat(64),
        state: State::Absent,
        agent_uid: 60123,
        service_uid: 60124,
        operator_uid: 0,
        fortress_id: "0123456789abcdef".into(),
        sanctuary_gid: None,
        account_step: AccountStep::Fresh,
        policy_generation: 0,
        policy_request_sha256: None,
        policy_complete: false,
    };
    assert!(good.validate().is_ok());
    let mut bad = good.clone();
    bad.version = 2;
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.request_sha256 = "A".repeat(64);
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.service_uid = bad.agent_uid;
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.account_step = AccountStep::SanctuaryIntent;
    assert!(bad.validate().is_err());
    let mut bad = good;
    bad.policy_complete = true;
    assert!(bad.validate().is_err());
}

#[test]
fn special_files_ancestors_and_foreign_owners_are_refused() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    root.mkdir("real", 0o700).unwrap();
    root.write("real/data", b"ok", 0o600).unwrap();
    symlink("real", tmp.path().join("alias")).unwrap();
    assert!(root.read("alias/data", 16).is_err());
    let fifo = CString::new(tmp.path().join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(root.file("fifo").is_err());
    let started = Instant::now();
    assert!(root.read("fifo", 16).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    if unsafe { libc::geteuid() } == 0 {
        let path = CString::new(tmp.path().join("real/data").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 60125, 60125) }, 0);
        assert!(root.read("real/data", 16).is_err());
    }
}

#[test]
fn workload_requires_native_elf_without_privileged_modes() {
    use castle_wall_daemon::linux_install::command::verify_elf;
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    let mut header = vec![0; 64];
    header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    header[16] = 2;
    header[18] = 62;
    root.write("program", &header, 0o755).unwrap();
    assert!(verify_elf(&root, "/program").is_ok());
    for (offset, value) in [(0, b'#'), (4, 1), (5, 2), (16, 1), (18, 3)] {
        let mut bad = header.clone();
        bad[offset] = value;
        root.write("program", &bad, 0o755).unwrap();
        assert!(verify_elf(&root, "/program").is_err());
    }
    for mode in [0o644, 0o4755, 0o2755] {
        root.write("program", &header, mode).unwrap();
        assert!(verify_elf(&root, "/program").is_err());
    }
}

#[test]
fn helper_exec_retains_the_mutation_lease() {
    use std::os::fd::AsRawFd;
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    let lease = root.lock("mutation.lock").unwrap();
    let descriptor = format!("/proc/self/fd/{}", lease.as_raw_fd());
    let out = run_bounded(
        "/usr/bin/readlink",
        &[&descriptor],
        Duration::from_secs(1),
        1024,
    )
    .unwrap();
    assert_eq!(out.code, Some(0));
    assert_eq!(
        std::str::from_utf8(&out.stdout).unwrap().trim(),
        tmp.path().join("mutation.lock").to_str().unwrap()
    );
}

#[test]
fn helper_parent_fixture() {
    let Ok(path) = std::env::var("P2_HELPER_PARENT_FIXTURE") else {
        return;
    };
    let root = Root::open(std::path::Path::new(&path)).unwrap();
    let _lease = root.lock("mutation.lock").unwrap();
    let pid = std::path::Path::new(&path).join("helper.pid");
    let _ = run_bounded(
        "/bin/sh",
        &[
            "-c",
            "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 30",
            "fixture",
            pid.to_str().unwrap(),
        ],
        Duration::from_secs(60),
        1024,
    );
}

#[test]
fn helper_dies_when_its_coordinator_is_killed() {
    use std::process::{Command, Stdio};
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "helper_parent_fixture", "--nocapture"])
        .env("P2_HELPER_PARENT_FIXTURE", tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pidfile = tmp.path().join("helper.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(&pidfile) {
            if let Ok(pid) = text.parse::<i32>() {
                break pid;
            }
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("helper did not publish pid");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    child.kill().unwrap();
    child.wait().unwrap();
    let alive = || {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .is_some_and(|s| {
                s.rsplit_once(')')
                    .is_some_and(|(_, tail)| !tail.starts_with(" Z "))
            })
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let survived = alive();
    // Cleanup also runs for a guard-removal witness; no thirty-second sleeper may outlive the test.
    if survived {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    assert!(!survived, "helper outlived its coordinator");
    assert!(Root::open(tmp.path())
        .unwrap()
        .lock("mutation.lock")
        .is_ok());
}

#[test]
fn explicit_operator_inputs_and_exports_do_not_relax_installed_custody() {
    use std::{ffi::CString, os::unix::fs::MetadataExt};
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    root.mkdir("operator", 0o700).unwrap();
    root.write("operator/input", b"{}", 0o600).unwrap();
    let operator = if unsafe { libc::geteuid() } == 0 {
        1000
    } else {
        unsafe { libc::geteuid() }
    };
    if unsafe { libc::geteuid() } == 0 {
        for name in ["operator", "operator/input"] {
            let p = CString::new(tmp.path().join(name).to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::chown(p.as_ptr(), operator, operator) }, 0);
        }
    }
    assert_eq!(root.input("operator/input", 2, operator).unwrap(), b"{}");
    assert!(root.input("operator/input", 1, operator).is_err());
    if unsafe { libc::geteuid() } == 0 {
        assert!(root.read("operator/input", 2).is_err());
        assert!(root.input("operator/input", 2, 2000).is_err());
    }
    symlink("input", tmp.path().join("operator/link")).unwrap();
    assert!(root.input("operator/link", 2, operator).is_err());
    fs::hard_link(
        tmp.path().join("operator/input"),
        tmp.path().join("operator/hard"),
    )
    .unwrap();
    assert!(root.input("operator/input", 2, operator).is_err());
    fs::remove_file(tmp.path().join("operator/hard")).unwrap();
    let output = root.output("operator/evidence/boot-0", operator).unwrap();
    output.write("public.json", b"{}", 0o600).unwrap();
    assert_eq!(
        fs::metadata(tmp.path().join("operator/evidence/boot-0"))
            .unwrap()
            .uid(),
        unsafe { libc::geteuid() }
    );
    assert!(root.output("operator/evidence/boot-0", operator).is_err());
    fs::set_permissions(
        tmp.path().join("operator"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(root.input("operator/input", 2, operator).is_err());
    assert!(root.output("operator/refused", operator).is_err());
}

#[test]
#[ignore = "requires an explicitly assigned disposable root VM"]
fn real_account_helper_avoids_home_mail_and_subordinate_allocations() {
    use castle_wall_daemon::linux_install::{
        account::{agent_name, useradd_arguments},
        transaction::checked,
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        fs::read_to_string("/root/.sanctuary-host-role")
            .unwrap()
            .lines()
            .next(),
        Some("disposable")
    );
    const UID: u32 = 20123; // Within Ubuntu's ordinary-user allocation range, so this witnesses the system-account distinction.
    let name = agent_name(UID);
    for database in ["passwd", "group"] {
        for key in [&name, &UID.to_string()] {
            let result = run_bounded(
                "/usr/bin/getent",
                &[database, key],
                Duration::from_secs(5),
                4096,
            )
            .unwrap();
            assert_eq!(result.code, Some(2));
            assert!(result.stdout.is_empty());
        }
    }
    checked("/usr/sbin/groupadd", &["--gid", &UID.to_string(), &name]).unwrap();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = checked("/usr/sbin/userdel", &[&self.0]);
            let _ = checked("/usr/sbin/groupdel", &[&self.0]);
        }
    }
    let _cleanup = Cleanup(name.clone());
    let args = useradd_arguments(UID);
    checked(
        "/usr/sbin/useradd",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .unwrap();
    for path in ["/etc/subuid", "/etc/subgid"] {
        assert!(
            !fs::read_to_string(path)
                .unwrap()
                .lines()
                .any(|line| line.starts_with(&format!("{name}:"))),
            "unexpected subordinate-id allocation"
        );
    }
    assert!(!std::path::Path::new(&format!("/var/mail/{name}")).exists());
    assert!(!std::path::Path::new(&format!("/home/{name}")).exists());
    let passwd = checked("/usr/bin/getent", &["passwd", &name]).unwrap();
    assert!(std::str::from_utf8(&passwd)
        .unwrap()
        .ends_with(":/nonexistent:/usr/sbin/nologin\n"));
}
