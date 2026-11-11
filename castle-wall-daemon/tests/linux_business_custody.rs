#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::custody::*;
use std::{os::unix::fs::PermissionsExt, process::Stdio};
#[test]
fn environment_drops_unlisted_variables() {
    let cmd = worker_command(
        std::path::Path::new("/bin/echo"),
        std::path::Path::new("/fixture"),
    );
    let env: Vec<_> = cmd
        .get_envs()
        .filter_map(|(k, v)| {
            v.map(|v| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
        })
        .collect();
    assert_eq!(
        env,
        vec![
            ("LANG".into(), "C.UTF-8".into()),
            ("TZ".into(), "UTC".into())
        ]
    );
    assert!(cmd.get_args().any(|a| a == "--disable-sigusr1"));
}
// CI installs Node outside /usr/bin, so the child is the node on PATH; the closed environment is what this test proves, not the install location.
fn node_on_path() -> std::path::PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join("node"))
                .find(|candidate| candidate.is_file())
        })
        .expect("node must be on PATH for the closed-environment witness")
}
#[test]
fn closed_environment_applies_to_child() {
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("environment.cjs");
    std::fs::write(&script, "process.stdout.write(JSON.stringify(process.env))").unwrap();
    std::env::set_var("K1_UNLISTED_SENTINEL", "should-not-inherit");
    let output = worker_command(&node_on_path(), &script)
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    std::env::remove_var("K1_UNLISTED_SENTINEL");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value.get("K1_UNLISTED_SENTINEL").is_none());
    assert!(value.get("HOME").is_none());
    assert_eq!(value.as_object().unwrap().len(), 2);
}
#[test]
fn custody_file_owner_mode_size_and_symlink_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("file");
    std::fs::write(&path, b"public ciphertext").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
    let uid = unsafe { libc::geteuid() };
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(b"public ciphertext"));
    assert!(artifact(&path, &digest, uid).is_ok());
    assert!(artifact(&path, &"0".repeat(64), uid).is_err());
    assert!(read_pinned(&path, uid, CONFIG_MAX_BYTES, PRIVATE_MODE).is_ok());
    assert!(read_pinned(&path, uid, 1, PRIVATE_MODE).is_err());
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_pinned(&link, uid, CONFIG_MAX_BYTES, PRIVATE_MODE).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_pinned(&path, uid, CONFIG_MAX_BYTES, PRIVATE_MODE).is_err());
}
#[test]
#[ignore = "needs root host: root-owned socket UID and mode under protected control parent"]
fn root_socket_ownership() {
    use castle_wall_daemon::business_profile::signer_peer::{
        accept, connect, listen, receive, send,
    };
    use std::os::fd::AsRawFd;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
    let socket = root.path().join("sign.sock");
    let listener = listen(&socket).unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        const UNPRIVILEGED_UID: u32 = 65534;
        if unsafe { libc::setgid(UNPRIVILEGED_UID) } != 0
            || unsafe { libc::setuid(UNPRIVILEGED_UID) } != 0
        {
            unsafe { libc::_exit(2) }
        }
        let denied = connect(&socket).is_err();
        unsafe { libc::_exit(if denied { 0 } else { 1 }) }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    let control = connect(&socket).unwrap();
    let accepted = accept(listener.as_raw_fd()).unwrap();
    send(control.as_raw_fd(), b"STATUS", &[]).unwrap();
    assert_eq!(receive(accepted.as_raw_fd(), 32).unwrap().bytes, b"STATUS");
}

#[test]
#[ignore = "needs root host: system manager filesystem confinement is enforced"]
fn root_reconstructed_unit_directives_deny_filesystem_write() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let root = tempfile::tempdir().unwrap();
    let forbidden = root.path().join("forbidden");
    let allowed = root.path().join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let unit = include_str!("../systemd/sanctuary-business-signer.service");
    let mut command = std::process::Command::new("systemd-run");
    command.args(["--system", "--wait", "--collect", "--quiet"]);
    for name in [
        "ProtectSystem",
        "ProtectHome",
        "PrivateDevices",
        "NoNewPrivileges",
        "CapabilityBoundingSet",
        "RestrictAddressFamilies",
    ] {
        let prefix = format!("{name}=");
        let directive = unit.lines().find(|line| line.starts_with(&prefix)).unwrap();
        command.arg("-p").arg(directive);
    }
    let status = command
        .arg("-p")
        .arg(format!("ReadWritePaths={}", allowed.display()))
        .args([
            "/bin/sh",
            "-c",
            "touch \"$1/positive\" && ! touch \"$2\"",
            "k1-confinement",
        ])
        .arg(&allowed)
        .arg(&forbidden)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(allowed.join("positive").exists());
    assert!(!forbidden.exists());
}
#[test]
fn production_store_is_pinned_beneath_role_root() {
    let mut config: Config = serde_json::from_value(serde_json::json!({
        "controller":{"uid":unsafe {libc::geteuid()},"gid":unsafe {libc::getegid()},"executable_sha256":"0".repeat(64),"cgroup":"fixture"},
        "launcher":{"uid":unsafe {libc::geteuid()},"gid":unsafe {libc::getegid()},"executable_sha256":"0".repeat(64),"cgroup":"fixture"},
        "node_sha256":"0".repeat(64),"worker_sha256":"0".repeat(64),
        "grant":{"role":"extension:linux-business-producer-v0"},"fortress_id":"fixture-fortress",
        "roster_digest":"public","binding_high_water":0,"runtime":[]
    }))
    .unwrap();
    assert_eq!(
        production_custody_path(&config).unwrap(),
        std::path::Path::new(CUSTODY_ROOT)
            .join("fixture-fortress")
            .join(PRODUCER_ROLE_SLOT)
    );
    config.fortress_id = "../other".into();
    assert!(production_custody_path(&config).is_err());
    config.fortress_id = "fixture-fortress".into();
    config.grant["role"] = serde_json::json!("evidence-pack:manifest-v0");
    assert!(production_custody_path(&config).is_err());
}

#[test]
fn same_length_artifact_replacement_refuses() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("worker");
    let replacement = root.path().join("replacement");
    std::fs::write(&path, b"first").unwrap();
    let held = std::fs::File::open(&path).unwrap();
    assert!(verify_artifact_identity(&path, &held).is_ok());
    std::fs::write(&replacement, b"other").unwrap();
    std::fs::rename(replacement, &path).unwrap();
    assert!(verify_artifact_identity(&path, &held).is_err());
}
#[test]
fn durable_unclean_marker_is_exclusive_and_survives_reopen() {
    let root = tempfile::tempdir().unwrap();
    mark_unclean(root.path()).unwrap();
    assert!(root.path().join(UNCLEAN_MARKER).exists());
    assert!(mark_unclean(root.path()).is_err());
}

#[test]
fn exec_failure_remains_visible_after_descriptor_closure() {
    use std::os::unix::process::CommandExt;
    let root = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(root.path().join("missing-executable"));
    unsafe {
        cmd.pre_exec(close_worker_descriptors);
    }
    assert!(cmd.spawn().is_err());
}

#[test]
#[ignore = "needs root system manager, no host swap or hibernation, and built native and worker artifacts"]
fn root_shipped_unit_ceremony_and_sign() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    verify_host_memory_policy().unwrap();
    let status = std::process::Command::new("npx")
        .current_dir("../server")
        .env("SANCTUARY_K1_ROOT_UNIT_DRILL", "1")
        .args([
            "vitest",
            "run",
            "test/signing/attendance.test.ts",
            "-t",
            "root shipped unit",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
