//! Capability: the installed launcher and manager enforce literal exec,
//! bounded workspace, confinement and wall-dependent lifecycle. P3.
#![cfg(target_os = "linux")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::linux_install::contract::*;
use castle_wall_daemon::manifest::{canonical_json::canonicalize_to_bytes, verify::*};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const UID: u32 = 60123; // Dedicated disposable fixture principal, never an operator.
const SERVICE_UID: u32 = 60124; // Reserved non-account control identity.
const FORTRESS: &str = "0123456789abcdef";
const WALL: &str = "sanctuary-castle-wall.service";
const AGENT: &str = "sanctuary-agent@60123.service";
const PROBE: &str = "/usr/local/libexec/sanctuary/p3-launch-probe";
const WAIT: Duration = Duration::from_secs(30); // Manager observation deadline.

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .expect("execute fixture command")
}
fn ok(program: &str, args: &[&str]) -> Output {
    let output = run(program, args);
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn property(unit: &str, name: &str) -> String {
    String::from_utf8(ok("systemctl", &["show", unit, "--value", "--property", name]).stdout)
        .unwrap()
        .trim()
        .into()
}
fn mono(unit: &str, name: &str) -> u64 {
    property(unit, name).parse().unwrap()
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "manager observation timed out");
        thread::sleep(Duration::from_millis(50));
    }
}
fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>, mode: u32) {
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Fixture {
    _lock: fs::File,
    source: PathBuf,
    evidence: PathBuf,
    created_group: bool,
    created_user: bool,
    created_sanctuary: bool,
}
impl Fixture {
    fn new() -> Self {
        // Ignored tests still require explicit intent, disposable role and an
        // empty product footprint; no ambient root session authorizes mutation.
        assert_eq!(
            std::env::var("SANCTUARY_P3_MANAGER_TEST").as_deref(),
            Ok("1")
        );
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            fs::read_to_string("/root/.sanctuary-host-role")
                .unwrap()
                .trim(),
            "disposable"
        );
        assert_eq!(
            fs::read_to_string("/proc/1/comm").unwrap().trim(),
            "systemd"
        );
        assert!(String::from_utf8(ok("systemctl", &["--version"]).stdout)
            .unwrap()
            .starts_with("systemd 255"));
        use std::os::fd::AsRawFd;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open("/root/build/p3-manager-tests.lock")
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "run manager fixtures serially (--test-threads=1)"
        );
        for path in [
            "/etc/sanctuary",
            "/var/lib/sanctuary",
            "/usr/local/libexec/sanctuary",
        ] {
            assert!(
                !Path::new(path).exists(),
                "pre-existing product path {path}"
            );
        }
        let tables = String::from_utf8(ok("nft", &["list", "tables"]).stdout).unwrap();
        assert!(
            !tables.contains("sanctuary-castle"),
            "pre-existing product table"
        );
        assert!(!run("getent", &["passwd", &SERVICE_UID.to_string()])
            .status
            .success());
        let evidence = PathBuf::from(
            std::env::var("SANCTUARY_P3_EVIDENCE_DIR").expect("bounded evidence destination"),
        );
        assert!(evidence.starts_with("/root/build/"));
        fs::create_dir_all(&evidence).unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut f = Self {
            _lock: lock,
            source,
            evidence,
            created_group: false,
            created_user: false,
            created_sanctuary: false,
        };
        // Only the fixture's prior sandbox principal is accepted for this test.
        if run("getent", &["passwd", &UID.to_string()])
            .status
            .success()
        {
            let got =
                String::from_utf8(ok("getent", &["passwd", &UID.to_string()]).stdout).unwrap();
            assert!(got.starts_with("p3-agent:"));
        } else {
            ok("groupadd", &["--gid", &UID.to_string(), "p3-agent"]);
            f.created_group = true;
            ok(
                "useradd",
                &[
                    "--uid",
                    &UID.to_string(),
                    "--gid",
                    &UID.to_string(),
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "p3-agent",
                ],
            );
            f.created_user = true;
        }
        if !run("getent", &["group", "sanctuary"]).status.success() {
            ok("groupadd", &["--system", "sanctuary"]);
            f.created_sanctuary = true;
        }
        for dir in [
            "/etc/sanctuary/agent",
            "/usr/local/libexec/sanctuary",
            "/var/lib/sanctuary-agent-workspace",
        ] {
            fs::create_dir_all(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let paths = PolicyPaths::for_fortress(FORTRESS).unwrap();
        fs::create_dir_all(&paths.rules).unwrap();
        for (source, dest) in [
            (env!("CARGO_BIN_EXE_castle-wall-daemon"), DAEMON_PATH),
            (env!("CARGO_BIN_EXE_protected-agent-v1"), LAUNCHER_PATH),
            (env!("CARGO_BIN_EXE_network-agent-standin"), STANDIN_PATH),
        ] {
            fs::copy(source, dest).unwrap();
            fs::set_permissions(dest, fs::Permissions::from_mode(0o755)).unwrap();
        }
        for unit in [WALL, "sanctuary-agent@.service", WORKSPACE_MOUNT_UNIT] {
            let dest = Path::new("/run/systemd/system").join(unit);
            assert!(!dest.exists());
            fs::copy(f.source.join("systemd").join(unit), dest).unwrap();
        }
        write(
            ENV_PATH,
            format!(
                "SANCTUARY_FORTRESS_ID={FORTRESS}\nSANCTUARY_TRUSTED_SERVICE_UID={SERVICE_UID}\n"
            ),
            0o600,
        );
        f.stage_policy();
        let c = f.source.join("tests/linux_agent_launch_probe.c");
        ok(
            "cc",
            &["-Wall", "-Wextra", "-O2", c.to_str().unwrap(), "-o", PROBE],
        );
        f.stage_command(
            PROBE,
            vec![
                "".into(),
                "a b".into(),
                "$HOME".into(),
                "; touch /tmp/p3-shell-escaped".into(),
                "$(echo no)".into(),
            ],
        );
        ok("systemctl", &["daemon-reload"]);
        // The watchdog only stops these test-owned processes. The RAII owner
        // performs authenticated disarm; no unrelated nft table is ever flushed.
        ok(
            "systemd-run",
            &[
                "--unit=p3-manager-watchdog",
                "--on-active=10min",
                "/usr/bin/systemctl",
                "stop",
                AGENT,
                WALL,
            ],
        );
        f
    }
    fn stage_policy(&self) {
        let paths = PolicyPaths::for_fortress(FORTRESS).unwrap();
        let key = SigningKey::from_bytes(&[21; 32]); // Test-only authority, never owner custody.
        write(&paths.pin, key.verifying_key().to_bytes(), 0o644);
        let allow=serde_json::to_vec(&json!({"id":"p3-allow","schema_version":1,"created_at":"2026-10-01T00:00:00Z","match":{"ip":["127.0.0.1","::1"],"port":[41003],"protocol":"tcp"},"disposition":"allow"})).unwrap();
        let habeas = castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
        let mut rules = Vec::new();
        for (id, bytes) in [
            ("p3-allow", allow.as_slice()),
            ("reserved_habeas_distress_local", habeas),
        ] {
            let file = format!("{id}.json");
            write(paths.rules.join(&file), bytes, 0o644);
            rules.push(ManifestRuleEntry {
                rule_id: id.into(),
                file,
                sha256: sha(bytes),
            });
        }
        let manifest = AllowlistManifest {
            schema_version: 1,
            fortress_id: FORTRESS.into(),
            issued_at: "2026-10-01T00:00:00Z".into(),
            generation: 1,
            agent_origin: Some(AgentOrigin {
                mode: "uid".into(),
                egress_helper_signing_id: None,
                egress_helper_team_id: None,
                agent_runtime_port_range: None,
                agent_uid: Some(UID),
                gate_uid: None,
                system_uid_allow_ceiling: 1000,
            }),
            operator_baseline: None,
            rules,
        };
        let canonical = canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let signed = SignedManifest {
            manifest,
            signature: ManifestSignature {
                signature_scheme: "ed25519-v1".into(),
                signing_key_id: castle_wall_daemon::crypto::castle_wall_signing_key_id(
                    key.verifying_key().as_bytes(),
                )
                .unwrap(),
                signature_b64url: URL_SAFE_NO_PAD.encode(key.sign(&canonical).to_bytes()),
            },
        };
        write(paths.manifest, serde_json::to_vec(&signed).unwrap(), 0o644);
        let response_key = SigningKey::from_bytes(&[22; 32]);
        let endpoints:Vec<_>=ENDPOINT_ORDER.iter().map(|(family,role,protocol)|json!({"family":family,"role":role,"protocol":protocol,"ip":if *family==Family::Ipv4{"127.0.0.1"}else{"::1"},
            "port":if *role==Role::Allow{41003}else if *protocol==Protocol::Tcp{41001}else{41002},"attempts":ATTEMPTS_PER_ENDPOINT,"response_public_key_hex":if *role==Role::Allow{Some(hex::encode(response_key.verifying_key().as_bytes()))}else{None}})).collect();
        write(ENDPOINTS_PATH,serde_json::to_vec(&json!({"version":1,"initial_delay_ms":INITIAL_DELAY_MS,"attempt_timeout_ms":ATTEMPT_TIMEOUT_MS,"max_response_bytes":MAX_RESPONSE_BYTES,"endpoints":endpoints})).unwrap(),0o644);
    }
    fn stage_command(&self, exe: &str, args: Vec<String>) {
        let command=serde_json::to_vec(&json!({"version":1,"agent_uid":UID,"fortress_id":FORTRESS,"executable":exe,"argv":args,"env":{"LANG":"C","TZ":"UTC"},"resource_profile":RESOURCE_PROFILE})).unwrap();
        write(COMMAND_PATH, &command, 0o644);
        let paths = PolicyPaths::for_fortress(FORTRESS).unwrap();
        let policy = fs::read(paths.manifest).unwrap();
        let signed: SignedManifest = serde_json::from_slice(&policy).unwrap();
        let marker = ConfiguredV1 {
            version: 1,
            agent_uid: UID,
            fortress_id: FORTRESS.into(),
            command_sha256: sha(&command),
            endpoints_sha256: sha(&fs::read(ENDPOINTS_PATH).unwrap()),
            public_pin_sha256: sha(&fs::read(paths.pin).unwrap()),
            policy_generation: 1,
            policy_signature_b64url: signed.signature.signature_b64url,
            policy_sha256: sha(&policy),
        };
        write(CONFIGURED_PATH, serde_json::to_vec(&marker).unwrap(), 0o644);
    }
    fn snapshot(&self, name: &str) {
        use std::io::Read;
        let wal = PathBuf::from(format!("/var/lib/sanctuary/{FORTRESS}/filter-events.wal"));
        let mut bytes = Vec::new();
        fs::File::open(wal)
            .unwrap()
            .take(PLANNED_WAL_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= PLANNED_WAL_MAX_BYTES);
        assert!(bytes.ends_with(b"\n"));
        let max_row = bytes
            .split(|b| *b == b'\n')
            .map(|row| row.len())
            .max()
            .unwrap_or(0);
        assert!(
            max_row <= EMAX,
            "encoded row exceeds the frozen proof ceiling"
        );
        fs::write(self.evidence.join(format!("{name}-wal.jsonl")), &bytes).unwrap();
        let stats = json!({"bytes":bytes.len(),"max_encoded_row_bytes":max_row,"sha256":sha(&bytes),"planned_wal_max_bytes":PLANNED_WAL_MAX_BYTES});
        fs::write(
            self.evidence.join(format!("{name}-wal-budget.json")),
            serde_json::to_vec(&stats).unwrap(),
        )
        .unwrap();
        for (suffix, output) in [
            ("agent", ok("systemctl", &["show", AGENT])),
            ("wall", ok("systemctl", &["show", WALL])),
            (
                "nft",
                ok(
                    "nft",
                    &["-j", "-a", "list", "table", "inet", "sanctuary-castle"],
                ),
            ),
        ] {
            fs::write(
                self.evidence.join(format!("{name}-{suffix}.txt")),
                output.stdout,
            )
            .unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = run(
            "systemctl",
            &[
                "stop",
                AGENT,
                WALL,
                "p3-manager-watchdog.timer",
                "p3-manager-watchdog.service",
            ],
        );
        let journal = run("journalctl", &["--no-pager", "-u", AGENT, "-u", WALL]);
        let _ = fs::write(self.evidence.join("manager-journal.txt"), journal.stdout);
        let disarm = run(DAEMON_PATH, &["--disarm"]);
        let _ = fs::write(
            self.evidence.join("disarm.txt"),
            [disarm.stdout, disarm.stderr].concat(),
        );
        let _ = run("systemctl", &["stop", WORKSPACE_MOUNT_UNIT]);
        for unit in [WALL, "sanctuary-agent@.service", WORKSPACE_MOUNT_UNIT] {
            let _ = fs::remove_file(Path::new("/run/systemd/system").join(unit));
        }
        let _ = run("systemctl", &["daemon-reload"]);
        // These paths were absent before this fixture; do not remove a retained
        // enforcement record unless the daemon confirmed its authenticated disarm.
        if disarm.status.success() {
            for path in [
                "/etc/sanctuary",
                "/var/lib/sanctuary",
                "/usr/local/libexec/sanctuary",
            ] {
                let _ = fs::remove_dir_all(path);
            }
        }
        if self.created_user {
            let _ = run("userdel", &["p3-agent"]);
        }
        if self.created_group {
            let _ = run("groupdel", &["p3-agent"]);
        }
        if self.created_sanctuary {
            let _ = run("groupdel", &["sanctuary"]);
        }
    }
}

#[test]
#[ignore = "requires an explicitly authorized empty disposable systemd-255 host"]
fn installed_launcher_and_real_manager_lifecycle() {
    let f = Fixture::new();
    ok("systemctl", &["start", AGENT]);
    wait(|| {
        fs::read_link(format!("/proc/{}/exe", property(AGENT, "MainPID")))
            .ok()
            .as_deref()
            == Some(Path::new(PROBE))
    });
    let pid = property(AGENT, "MainPID");
    let invocation = property(AGENT, "InvocationID");
    let start = mono(AGENT, "ExecMainStartTimestampMonotonic");
    assert!(start > mono(WALL, "ActiveEnterTimestampMonotonic"));
    let argv = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert_eq!(
        argv,
        [
            PROBE,
            "",
            "a b",
            "$HOME",
            "; touch /tmp/p3-shell-escaped",
            "$(echo no)"
        ]
        .join("\0")
        .into_bytes()
        .into_iter()
        .chain([0])
        .collect::<Vec<_>>()
    );
    let env = fs::read(format!("/proc/{pid}/environ")).unwrap();
    assert_eq!(
        env,
        format!("HOME={WORKSPACE_PATH}\0LANG=C\0TZ=UTC\0").as_bytes()
    );
    assert!(!Path::new("/tmp/p3-shell-escaped").exists());
    wait(|| Path::new(WORKSPACE_PATH).join("p3-sandbox.txt").exists());
    let probe = fs::read_to_string(Path::new(WORKSPACE_PATH).join("p3-sandbox.txt")).unwrap();
    fs::write(f.evidence.join("sandbox.txt"), &probe).unwrap();
    for family in [1, 16, 17] {
        assert!(
            probe.contains(&format!("family {family} fd -1 errno 97")),
            "{probe}"
        );
    }
    assert!(
        probe.contains("alternate_abi status 159 signal 31"),
        "{probe}"
    );
    assert!(
        !probe
            .lines()
            .filter(|l| l.starts_with("namespace "))
            .any(|l| !l.contains("result -1 errno 1")),
        "{probe}"
    );
    assert!(
        !probe
            .lines()
            .filter(|l| l.starts_with("write "))
            .any(|l| !l.contains("fd -1")),
        "{probe}"
    );
    assert!(probe.contains("setuid0 result -1 errno 1"), "{probe}");
    assert!(
        probe.contains("device /dev/null written 12 errno 0"),
        "{probe}"
    );
    assert!(
        probe.contains("device /dev/zero written 12 errno 0"),
        "{probe}"
    );
    assert!(
        probe.contains("device /dev/full written -1 errno 28"),
        "{probe}"
    );
    assert!(
        probe
            .lines()
            .filter(|l| l.starts_with("api_write "))
            .all(|l| l.contains("fd -1")),
        "{probe}"
    );

    assert!(probe.contains("inherited_fds 0"), "{probe}");
    assert!(probe.contains("x32_abi signal 31"), "{probe}");
    assert!(probe.contains("setns result -1 errno 1"), "{probe}");
    assert!(
        probe
            .lines()
            .filter(|l| l.starts_with("clone_namespace "))
            .all(|l| l.contains("result -1 errno 1")),
        "{probe}"
    );
    let field = |prefix: &str, index: usize| -> u64 {
        probe
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap()
            .split_whitespace()
            .nth(index)
            .unwrap()
            .parse()
            .unwrap()
    };
    assert!(field("byte_flood", 2) <= WORKSPACE_MAX_BYTES as u64);
    assert_eq!(field("byte_flood", 4), libc::ENOSPC as u64);
    assert!(field("inode_flood", 2) < WORKSPACE_MAX_INODES as u64);
    assert_eq!(field("inode_flood", 4), libc::ENOSPC as u64);
    assert!(field("fork_flood", 2) < TASKS_MAX as u64);
    assert_eq!(field("fork_flood", 4), libc::EAGAIN as u64);
    assert_eq!(property(AGENT, "MemoryMax"), MEMORY_MAX_BYTES.to_string());

    f.snapshot("before-restart");
    ok("systemctl", &["restart", WALL]);
    wait(|| {
        property(AGENT, "ActiveState") == "active"
            && mono(AGENT, "ExecMainStartTimestampMonotonic") > start
    });
    wait(|| {
        fs::read_link(format!("/proc/{}/exe", property(AGENT, "MainPID")))
            .ok()
            .as_deref()
            == Some(Path::new(PROBE))
    });
    assert_ne!(property(AGENT, "InvocationID"), invocation);
    assert!(
        mono(AGENT, "InactiveEnterTimestampMonotonic")
            <= mono(WALL, "ActiveExitTimestampMonotonic")
    );
    assert!(
        mono(AGENT, "ExecMainStartTimestampMonotonic")
            > mono(WALL, "ActiveEnterTimestampMonotonic")
    );
    assert_eq!(property(AGENT, "NRestarts"), "0");
    f.snapshot("after-propagated-restart");
    ok("systemctl", &["stop", WALL]);
    assert_eq!(property(AGENT, "ActiveState"), "inactive");
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    f.snapshot("after-stop");
    // The shipped stand-in owns all 18 slots across its three processes.
    let sentinels = Sentinels::start();
    f.stage_command(
        STANDIN_PATH,
        vec!["--endpoints".into(), ENDPOINTS_PATH.into()],
    );
    ok("systemctl", &["start", AGENT]);
    let first = finite_activation(&f, &sentinels, "finite-first", 0);
    let first_invocation = property(AGENT, "InvocationID");
    let first_start = mono(AGENT, "ExecMainStartTimestampMonotonic");
    let before_restart = Instant::now();
    ok("systemctl", &["restart", WALL]);
    assert!(before_restart.elapsed() < Duration::from_secs(25)); // Agent 10s + wall 10s + scheduling slack.
    for pid in first {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "descendant survived {pid}"
        );
    }
    wait(|| {
        property(AGENT, "ActiveState") == "active"
            && mono(AGENT, "ExecMainStartTimestampMonotonic") > first_start
    });
    wait(|| {
        fs::read_link(format!("/proc/{}/exe", property(AGENT, "MainPID")))
            .ok()
            .as_deref()
            == Some(Path::new(STANDIN_PATH))
    });
    assert_ne!(property(AGENT, "InvocationID"), first_invocation);
    assert!(
        mono(AGENT, "InactiveEnterTimestampMonotonic")
            <= mono(WALL, "ActiveExitTimestampMonotonic")
    );
    assert!(
        mono(AGENT, "ExecMainStartTimestampMonotonic")
            > mono(WALL, "ActiveEnterTimestampMonotonic")
    );
    let second = finite_activation(&f, &sentinels, "finite-propagated", 6);
    ok("systemctl", &["stop", WALL]);
    for pid in second {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "descendant survived {pid}"
        );
    }
    assert_eq!(property(AGENT, "NRestarts"), "0");
}

#[test]
fn shipped_binaries_refuse_path_overrides_and_extra_arguments() {
    for bin in [
        env!("CARGO_BIN_EXE_protected-agent-v1"),
        env!("CARGO_BIN_EXE_network-agent-standin"),
    ] {
        for argv in [
            ["--test-isolation-root", "/tmp"],
            ["--endpoints", "/tmp/endpoints.json"],
        ] {
            assert!(!run(bin, &argv).status.success());
        }
    }
}

#[test]
fn shipped_operator_control_is_finite_and_needs_no_installed_records() {
    let sentinels = Sentinels::start();
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let key = hex::encode(SigningKey::from_bytes(&[22; 32]).verifying_key().as_bytes());
    let endpoints: Vec<_> = ENDPOINT_ORDER.iter().map(|(family, role, protocol)| json!({
        "family": family, "role": role, "protocol": protocol,
        "ip": if *family == Family::Ipv4 { "127.0.0.1" } else { "::1" },
        "port": if *role == Role::Allow {41003} else if *protocol == Protocol::Tcp {41001} else {41002},
        "attempts": ATTEMPTS_PER_ENDPOINT,
        "response_public_key_hex": if *role == Role::Allow {Some(&key)} else {None}
    })).collect();
    let path = dir.path().join("endpoints.json");
    write(
        &path,
        serde_json::to_vec(&json!({"version":VERSION,
        "initial_delay_ms":INITIAL_DELAY_MS,"attempt_timeout_ms":ATTEMPT_TIMEOUT_MS,
        "max_response_bytes":MAX_RESPONSE_BYTES,"endpoints":endpoints}))
        .unwrap(),
        0o644,
    );
    let bin = env!("CARGO_BIN_EXE_network-agent-standin");
    // Six three-second attempts plus seven seconds of scheduling headroom; a
    // product idle loop must never hang the ordinary operator control command.
    let mut cmd = Command::new("timeout");
    cmd.arg("25");
    if unsafe { libc::geteuid() } == 0 {
        cmd.args([
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]);
    }
    let output = cmd
        .arg(bin)
        .args(["--control", "--endpoints"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= OBSERVATION_MAX_BYTES);
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["phase"], "control-complete");
    assert_eq!(record["attempt_count"], ENDPOINT_COUNT);
    let rows = record["attempts"].as_array().unwrap();
    assert_eq!(rows.len(), ENDPOINT_COUNT);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["index"], index);
        assert_eq!(row["sent_bytes"], 32);
        assert_eq!(row["phase"], "control");
        if row["endpoint"]["role"] == "allow" {
            assert_eq!(row["authenticated"], true);
        }
    }
    assert_eq!(sentinels.receipts.lock().unwrap().len(), ENDPOINT_COUNT);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(sentinels.receipts.lock().unwrap().len(), ENDPOINT_COUNT);

    // The fault instrument cannot consume a normal or multi-attempt schedule.
    let invoke = || {
        run(
            "timeout",
            &[
                "8",
                bin,
                "--fault-probe",
                "--endpoints",
                path.to_str().unwrap(),
            ],
        )
    };
    assert!(!invoke().status.success());
    let mut fault: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (index, endpoint) in fault["endpoints"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        endpoint["attempts"] = json!(u8::from(index == 0));
    }
    write(&path, serde_json::to_vec(&fault).unwrap(), 0o644);
    let output = invoke();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= OBSERVATION_MAX_BYTES);
    let fault_record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fault_record["phase"], "fault-probe-complete");
    assert_eq!(fault_record["attempt_count"], 1);
    assert_eq!(fault_record["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(fault_record["attempts"][0]["phase"], "fault-probe");
    assert_eq!(fault_record["attempts"][0]["index"], 0);
    assert_eq!(fault_record["attempts"][0]["sent_bytes"], 32);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(sentinels.receipts.lock().unwrap().len(), ENDPOINT_COUNT + 1);
    for index in 0..ENDPOINT_COUNT {
        fault["endpoints"][0]["attempts"] = json!(0);
        fault["endpoints"][index]["attempts"] = json!(if index == 0 { 2 } else { 1 });
        write(&path, serde_json::to_vec(&fault).unwrap(), 0o644);
        assert!(
            !invoke().status.success(),
            "invalid fault schedule index {index}"
        );
        fault["endpoints"][index]["attempts"] = json!(0);
    }
    assert_eq!(sentinels.receipts.lock().unwrap().len(), ENDPOINT_COUNT + 1);
}

struct Sentinels {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    receipts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}
impl Sentinels {
    fn start() -> Self {
        use std::io::{Read, Write};
        use std::net::{TcpListener, UdpSocket};
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for ip in ["127.0.0.1", "::1"] {
            for port in [41001, 41003] {
                let listener = TcpListener::bind((ip, port)).unwrap();
                listener.set_nonblocking(true).unwrap();
                let stop = stop.clone();
                let receipts = receipts.clone();
                handles.push(thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(300); // Two finite 114-second activations plus stop headroom.
                    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                        if let Ok((mut stream, peer)) = listener.accept() {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let mut nonce = [0; 32];
                            let result = stream.read_exact(&mut nonce);
                            receipts.lock().unwrap().push(format!(
                                "tcp {ip}:{port} peer={peer} nonce={} read={}",
                                hex::encode(nonce),
                                result.is_ok()
                            ));
                            if port == 41003 && result.is_ok() {
                                let key = SigningKey::from_bytes(&[22; 32]);
                                let mut response = nonce.to_vec();
                                response.extend_from_slice(&key.sign(&nonce).to_bytes());
                                let _ = stream.write_all(&response);
                            }
                        } else {
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                }));
            }
            let socket = UdpSocket::bind((ip, 41002)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let stop = stop.clone();
            let receipts = receipts.clone();
            handles.push(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(300);
                let mut buf = [0; 256];
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                        receipts
                            .lock()
                            .unwrap()
                            .push(format!("udp {ip}:41002 peer={peer} bytes={n}"));
                    } else {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }));
        }
        Self {
            stop,
            handles,
            receipts,
        }
    }
}
impl Drop for Sentinels {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for handle in self.handles.drain(..) {
            handle.join().unwrap();
        }
    }
}

fn finite_activation(
    f: &Fixture,
    sentinels: &Sentinels,
    label: &str,
    prior_count: usize,
) -> Vec<u32> {
    let record_path = Path::new(WORKSPACE_PATH).join("observations.json");
    let pid: u32 = property(AGENT, "MainPID").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(125); // 60-second delay + 18*3-second slots + bounded collection.
    let mut prior = prior_count;
    let value: Value = loop {
        if let Ok(bytes) = fs::read(&record_path) {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            if value["invocation"]["leader_pid"] == pid {
                assert!(bytes.len() <= OBSERVATION_MAX_BYTES);
                fs::write(f.evidence.join(format!("{label}-observations.json")), bytes).unwrap();
                break value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "finite stand-in record unavailable"
        );
        let count = sentinels.receipts.lock().unwrap().len();
        assert!(count >= prior);
        prior = count;
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(value["phase"], "idle");
    assert_eq!(value["attempt_count"], 18);
    let attempts = value["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 18);
    let mut pids = std::collections::BTreeSet::new();
    let mut authenticated = 0;
    for (index, row) in attempts.iter().enumerate() {
        assert_eq!(row["index"], index);
        assert_eq!(row["worker"], index % 3);
        assert_eq!(row["socket_errno"], 0);
        assert!(row["local_tuple"].as_str().is_some());
        assert!(
            row["start_ns"].as_u64().unwrap()
                >= value["invocation"]["start_monotonic_ns"].as_u64().unwrap()
                    + u64::from(INITIAL_DELAY_MS) * 1_000_000
        );
        pids.insert(row["pid"].as_u64().unwrap() as u32);
        if row["endpoint"]["role"] == "allow" {
            assert_eq!(row["authenticated"], true, "{row}");
            authenticated += 1;
        } else if row["endpoint"]["protocol"] == "tcp" {
            assert_ne!(row["connect_errno"], 0, "{row}");
        }
    }
    assert_eq!(authenticated, 6);
    assert_eq!(pids.len(), 3);
    assert!(pids.contains(&pid));
    let after = sentinels.receipts.lock().unwrap().clone();
    assert_eq!(after.len() - prior_count, 6, "{after:?}");
    assert!(after
        .iter()
        .all(|r| r.starts_with("tcp ") && r.contains(":41003 ")));
    thread::sleep(Duration::from_secs(4)); // Beyond the per-attempt deadline; idle has no sends.
    assert_eq!(sentinels.receipts.lock().unwrap().len(), after.len());
    fs::write(
        f.evidence.join(format!("{label}-receipts.txt")),
        after.join("\n"),
    )
    .unwrap();
    f.snapshot(label);
    pids.into_iter().collect()
}

#[test]
#[ignore = "requires an explicitly authorized empty disposable systemd-255 host"]
fn installed_launcher_negative_records_and_inherited_socket() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let f = Fixture::new();
    ok("systemctl", &["start", WORKSPACE_MOUNT_UNIT]);
    let source = f.source.join("tests/linux_agent_launch_fd_probe.c");
    ok(
        "cc",
        &[
            "-Wall",
            "-Wextra",
            "-O2",
            source.to_str().unwrap(),
            "-o",
            PROBE,
        ],
    );
    f.stage_command(PROBE, vec![]);
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = socket.as_raw_fd();
    let spawn = |path: &str, chain: bool| {
        let mut command = Command::new("setpriv");
        command.args([
            "--reuid=60123",
            "--regid=60123",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            path,
        ]);
        if chain {
            command.arg("--chain");
        }
        command.stderr(std::process::Stdio::piped());
        command
            .env_clear()
            .env("SANCTUARY_FORTRESS_ID", FORTRESS)
            .env("SANCTUARY_TRUSTED_SERVICE_UID", SERVICE_UID.to_string());
        // The deliberate high non-CLOEXEC socket witnesses closure beyond the
        // conventional small fd range; no shell carries it to the trampoline.
        unsafe {
            command.pre_exec(move || {
                let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
                if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut limit = limit.assume_init();
                limit.rlim_cur = limit.rlim_cur.max(5001); // Admit the deliberately inherited fd 5000.
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(fd, 5000) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    };
    let record = Path::new(WORKSPACE_PATH).join("fd-probe.txt");
    let mut control = spawn(PROBE, false);
    assert!(control.wait().unwrap().success());
    let before = fs::read_to_string(&record).unwrap();
    assert!(before.contains("fds=1\n"), "{before}");
    fs::remove_file(&record).unwrap();
    let mut child = spawn(LAUNCHER_PATH, false);
    let pid = child.id();
    assert!(child.wait().unwrap().success());
    let after = fs::read_to_string(&record).unwrap();
    assert!(
        after.contains(&format!("pid={pid}\nfds=0\ncwd={WORKSPACE_PATH}\n")),
        "{after}"
    );
    for fd in 0..=2 {
        assert!(after.contains(&format!("stdio{fd}=/dev/null\n")), "{after}");
    }
    fs::write(f.evidence.join("fd-before.txt"), before).unwrap();
    fs::write(f.evidence.join("fd-after.txt"), after).unwrap();
    let mut chain = spawn(PROBE, true);
    let chain_pid = chain.id();
    assert!(chain.wait().unwrap().success());
    let before = fs::read_to_string(Path::new(WORKSPACE_PATH).join("fd-probe-before.txt")).unwrap();
    let after = fs::read_to_string(&record).unwrap();
    for key in ["pid=", "start_ticks="] {
        let first = before.lines().find(|l| l.starts_with(key)).unwrap();
        let second = after.lines().find(|l| l.starts_with(key)).unwrap();
        assert_eq!(first, second);
    }
    assert!(after.contains(&format!("pid={chain_pid}\n")));
    assert!(after.contains("fds=0\n"));
    fs::write(f.evidence.join("second-exec-before.txt"), before).unwrap();
    fs::write(f.evidence.join("second-exec-after.txt"), after).unwrap();

    let command = fs::read(COMMAND_PATH).unwrap();
    let marker = fs::read(CONFIGURED_PATH).unwrap();
    let endpoints = fs::read(ENDPOINTS_PATH).unwrap();
    let negative = |label: &str| {
        let child = spawn(LAUNCHER_PATH, false);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "guard admitted {label}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        let expected = match label {
            "configured-identity" => "Configured identity differs",
            "command-digest" | "endpoint-digest" => "Configured digest differs",
            "record-size" | "record-mode" | "record-links" => "record custody or size",
            "record-symlink" => "Too many levels of symbolic links",
            "writable-parent" => "parent custody",
            "setuid-executable" => "executable custody",
            "file-capability" => "file capabilities",
            "non-elf" => "native amd64 ELF required",
            "workspace-byte-ceiling"
            | "workspace-inode-ceiling"
            | "workspace-noexec"
            | "workspace-nosuid"
            | "workspace-nodev" => "mandatory workspace limits",
            "missing-mount" => "workspace custody",
            _ => "No such file or directory",
        };
        // A later exec failure is not evidence that the intended admission guard
        // ran. Retain the exact refusal before the trampoline nulls its streams.
        assert!(
            stderr.contains(expected),
            "{label}: wrong refusal: {stderr}"
        );
        fs::write(f.evidence.join(format!("refused-{label}.txt")), stderr).unwrap();
    };
    fs::remove_file(CONFIGURED_PATH).unwrap();
    negative("absent-configured");
    write(CONFIGURED_PATH, &marker, 0o644);
    let mut wrong: Value = serde_json::from_slice(&marker).unwrap();
    wrong["agent_uid"] = json!(UID + 1);
    write(CONFIGURED_PATH, serde_json::to_vec(&wrong).unwrap(), 0o644);
    negative("configured-identity");
    write(CONFIGURED_PATH, &marker, 0o644);
    write(COMMAND_PATH, [command.as_slice(), b" "].concat(), 0o644);
    negative("command-digest");
    write(COMMAND_PATH, &command, 0o644);
    write(ENDPOINTS_PATH, [endpoints.as_slice(), b" "].concat(), 0o644);
    negative("endpoint-digest");
    write(ENDPOINTS_PATH, &endpoints, 0o644);
    write(COMMAND_PATH, vec![b' '; COMMAND_MAX_BYTES + 1], 0o644);
    negative("record-size");
    write(COMMAND_PATH, &command, 0o644);
    fs::set_permissions(COMMAND_PATH, fs::Permissions::from_mode(0o666)).unwrap();
    negative("record-mode");
    fs::set_permissions(COMMAND_PATH, fs::Permissions::from_mode(0o644)).unwrap();
    let alias = Path::new(COMMAND_PATH).with_extension("alias");
    fs::hard_link(COMMAND_PATH, &alias).unwrap();
    negative("record-links");
    fs::remove_file(alias).unwrap();
    fs::rename(COMMAND_PATH, format!("{COMMAND_PATH}.real")).unwrap();
    std::os::unix::fs::symlink(format!("{COMMAND_PATH}.real"), COMMAND_PATH).unwrap();
    negative("record-symlink");
    fs::remove_file(COMMAND_PATH).unwrap();
    fs::rename(format!("{COMMAND_PATH}.real"), COMMAND_PATH).unwrap();
    fs::set_permissions("/etc/sanctuary/agent", fs::Permissions::from_mode(0o777)).unwrap();
    negative("writable-parent");
    fs::set_permissions("/etc/sanctuary/agent", fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(PROBE, fs::Permissions::from_mode(0o4755)).unwrap();
    negative("setuid-executable");
    fs::set_permissions(PROBE, fs::Permissions::from_mode(0o755)).unwrap();
    ok("setcap", &["cap_net_raw=ep", PROBE]);
    negative("file-capability");
    ok("setcap", &["-r", PROBE]);
    let original = fs::read(PROBE).unwrap();
    write(
        PROBE,
        b"#!/bin/sh\nexit 0\n# padding makes this at least one complete ELF header long\n",
        0o755,
    );
    negative("non-elf");
    write(PROBE, &original, 0o755);
    ok("mount", &["-o", "remount,size=65M", WORKSPACE_PATH]);
    negative("workspace-byte-ceiling");
    ok(
        "mount",
        &["-o", "remount,size=64M,nr_inodes=4097", WORKSPACE_PATH],
    );
    negative("workspace-inode-ceiling");
    ok(
        "mount",
        &["-o", "remount,nr_inodes=4096,exec", WORKSPACE_PATH],
    );
    negative("workspace-noexec");
    ok("mount", &["-o", "remount,noexec,suid", WORKSPACE_PATH]);
    negative("workspace-nosuid");
    ok("mount", &["-o", "remount,nosuid,dev", WORKSPACE_PATH]);
    negative("workspace-nodev");
    ok("mount", &["-o", "remount,nodev", WORKSPACE_PATH]);
    ok("systemctl", &["stop", WORKSPACE_MOUNT_UNIT]);
    negative("missing-mount");
    // Root itself is never a supported fallback, even with every record present.
    assert!(!run(LAUNCHER_PATH, &[]).status.success());
}
