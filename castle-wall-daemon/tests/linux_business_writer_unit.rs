// fail-before-exempt: writer closure and reconciliation are new.
#![cfg(target_os = "linux")]
mod isolation;
#[path = "support/writer_bus.rs"]
mod writer_bus;
#[path = "support/writer_state.rs"]
mod writer_state;
use castle_wall_daemon::business_profile::{
    writer_peer::HeldConfig,
    writer_service::{test_support::*, *},
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
const CAPS:&str="CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
struct ClosureFixture {
    f: writer_bus::Fixture,
    status: PathBuf,
    maps: PathBuf,
    boot: PathBuf,
    config: PathBuf,
}
impl ClosureFixture {
    fn new() -> Self {
        let mut f = writer_bus::Fixture::new();
        f.config.writer_sha256 = f.config.wall_sha256.clone();
        let status = f.root.path().join("status");
        let maps = f.root.path().join("maps");
        let boot = f.root.path().join("boot");
        fs::write(&status, CAPS).unwrap();
        fs::write(&boot, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n").unwrap();
        fs::write(&maps, Self::mapping(&f.config.wall_exec, "r-xp")).unwrap();
        let config = f.config_path();
        Self {
            f,
            status,
            maps,
            boot,
            config,
        }
    }
    fn mapping(path: &std::path::Path, perms: &str) -> String {
        let m = fs::metadata(path).unwrap();
        format!(
            "1000-2000 {perms} 00000000 {:02x}:{:02x} {} {}\n",
            libc::major(m.dev()),
            libc::minor(m.dev()),
            m.ino(),
            path.display()
        )
    }
    fn paths(&self) -> ClosurePaths {
        ClosurePaths::isolated(
            self.f.config.wall_exec.clone(),
            self.status.clone(),
            self.maps.clone(),
            self.f.config.wall_exec.clone(),
            self.boot.clone(),
            unsafe { libc::geteuid() },
        )
    }
    fn held(&self) -> HeldConfig {
        HeldConfig::isolated(&self.config, unsafe { libc::geteuid() }).unwrap()
    }
}
#[test]
fn each_capability_and_no_new_privileges_are_checked() {
    let f = ClosureFixture::new();
    assert!(closure_check(&f.paths(), &f.held(), &[]).is_ok());
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        fs::write(
            &f.status,
            CAPS.replace(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000000001"),
            ),
        )
        .unwrap();
        assert_eq!(
            closure_check(&f.paths(), &f.held(), &[]),
            Err(Error::Closure),
            "{field}"
        );
    }
    fs::write(&f.status, CAPS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).unwrap();
    assert_eq!(
        closure_check(&f.paths(), &f.held(), &[]),
        Err(Error::Closure)
    );
}
#[test]
fn image_pin_identity_permissions_and_link_count_close_readiness() {
    for fault in ["digest", "identity", "permissions", "links", "owner"] {
        let f = ClosureFixture::new();
        assert!(closure_check(&f.paths(), &f.held(), &[]).is_ok());
        let mut paths = f.paths();
        match fault {
            "digest" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
                value["writer_sha256"] = serde_json::json!("0".repeat(64));
                fs::write(&f.config, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "identity" => {
                let other = f.f.root.path().join("other-image");
                fs::copy(&f.f.config.wall_exec, &other).unwrap();
                paths = ClosurePaths::isolated(
                    f.f.config.wall_exec.clone(),
                    f.status.clone(),
                    f.maps.clone(),
                    other,
                    f.boot.clone(),
                    unsafe { libc::geteuid() },
                );
            }
            "permissions" => {
                fs::set_permissions(&f.f.config.wall_exec, fs::Permissions::from_mode(0o666))
                    .unwrap()
            }
            "links" => {
                fs::hard_link(&f.f.config.wall_exec, f.f.root.path().join("another-link")).unwrap()
            }
            _ => {
                paths = ClosurePaths::isolated(
                    f.f.config.wall_exec.clone(),
                    f.status.clone(),
                    f.maps.clone(),
                    f.f.config.wall_exec.clone(),
                    f.boot.clone(),
                    unsafe { libc::geteuid() } + 1,
                )
            }
        }
        assert!(closure_check(&paths, &f.held(), &[]).is_err(), "{fault}");
    }
}
#[test]
fn maps_and_environment_are_bounded_and_held() {
    for fault in [
        "writable-executable",
        "deleted",
        "library-writable",
        "too-many",
        "too-large",
        "ld-variable",
    ] {
        let f = ClosureFixture::new();
        let mut environment = vec![];
        let mut maps = ClosureFixture::mapping(&f.f.config.wall_exec, "r-xp");
        match fault {
            "writable-executable" => maps = ClosureFixture::mapping(&f.f.config.wall_exec, "rwxp"),
            "deleted" => maps = maps.replace('\n', " (deleted)\n"),
            "library-writable" => {
                let library = f.f.root.path().join("library");
                fs::write(&library, b"library").unwrap();
                fs::set_permissions(&library, fs::Permissions::from_mode(0o666)).unwrap();
                maps.push_str(&ClosureFixture::mapping(&library, "r-xp"));
            }
            "too-many" => {
                for index in 0..WRITER_MAPPINGS_MAX {
                    let library = f.f.root.path().join(format!("lib-{index}"));
                    fs::write(&library, b"library").unwrap();
                    maps.push_str(&ClosureFixture::mapping(&library, "r-xp"));
                }
            }
            "too-large" => maps = "x".repeat(65536 + 1),
            _ => environment.push("LD_SANCTUARY_PROBE".into()),
        }
        fs::write(&f.maps, maps).unwrap();
        assert!(
            closure_check(&f.paths(), &f.held(), &environment).is_err(),
            "{fault}"
        );
    }
}
#[test]
fn config_replacement_after_validation_refuses_closure() {
    let f = ClosureFixture::new();
    let held = f.held();
    let other = f.f.root.path().join("new-config");
    fs::copy(&f.config, &other).unwrap();
    fs::rename(&other, &f.config).unwrap();
    assert!(closure_check(&f.paths(), &held, &[]).is_err());
}
#[test]
fn production_reconciliation_has_no_grant_edge() {
    let f = writer_state::Fixture::new();
    f.unlock();
    let observation = f.view.lock().unwrap().clone();
    let mut reconciler = ClosedReconciler::production();
    assert!(matches!(
        reconciler.reconcile(ReconcileEvidence {
            observation: &observation,
            fortress_id: "fixture",
            enrollment_revision: 1
        }),
        Reconciliation::NotReconciled
    ));
}

#[test]
fn mapping_owner_uses_the_same_predicate_as_the_inventory() {
    let f = ClosureFixture::new();
    assert_eq!(
        mapping_owner(&f.f.config.wall_exec, unsafe { libc::geteuid() }),
        Ok(())
    );
    assert_eq!(
        mapping_owner(&f.f.config.wall_exec, unsafe { libc::geteuid() } + 1),
        Err(Error::Closure)
    );
}

fn directives(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut result = std::collections::BTreeMap::new();
    let mut section = "";
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let (key, value) = line.split_once('=').expect("directive");
        assert!(
            result
                .insert(format!("{section}.{key}"), value.into())
                .is_none(),
            "duplicate {key}"
        );
    }
    result
}
#[test]
fn complete_production_units_and_hardening_are_pinned() {
    use castle_wall_daemon::business_profile::writer_peer::{
        RECORD_FD_NAME, RECORD_MODE, RECORD_SOCKET, WALL_UNIT, WRITER_EXEC,
    };
    let service = directives(include_str!("../systemd/sanctuary-business-writer.service"));
    let socket = directives(include_str!("../systemd/sanctuary-business-writer.socket"));
    let expected_service = directives(
        r#"[Unit]
Description=Sanctuary closed business writer
Requires=sanctuary-business-barrier.service sanctuary-business-signer.service sanctuary-business-writer.socket dbus.socket
After=sanctuary-business-barrier.service sanctuary-business-signer.service sanctuary-business-writer.socket dbus.socket
BindsTo=sanctuary-business-signer.service sanctuary-castle-wall.service
PartOf=sanctuary-castle-wall.service
Before=sanctuary-castle-wall.service

[Service]
Type=notify
NotifyAccess=main
User=root
Group=sanctuary
SupplementaryGroups=
Slice=system.slice
Delegate=no
# Must match WRITER_EXEC and WALL_UNIT in writer_peer.rs.
ExecStart=/usr/libexec/sanctuary-business-writer
Restart=no
TimeoutStartSec=30
TimeoutStopSec=5
KillMode=control-group
SendSIGKILL=yes
# the socket unit owns this directory; a service RuntimeDirectory= here would re-own the socket's group on start.
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
PrivateIPC=yes
PrivateTmp=yes
PrivateUsers=no
ProtectProc=default
ProcSubset=all
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
LimitCORE=0
MemorySwapMax=0
MemoryMax=64M
TasksMax=16
StandardInput=null
StandardOutput=journal
StandardError=journal
# ProtectSystem=strict and no writable path exceptions leave no persistent writable writer state.
"#,
    );
    let expected_socket = directives(
        r#"[Unit]
Description=Sanctuary business record socket
Requires=sanctuary-business-barrier.service
After=sanctuary-business-barrier.service
BindsTo=sanctuary-business-writer.service
Before=sanctuary-business-writer.service sanctuary-castle-wall.service

[Socket]
# Must match RECORD_SOCKET, RECORD_FD_NAME and RECORD_MODE in writer_peer.rs.
ListenSequentialPacket=/run/sanctuary-business-writer/record.sock
Service=sanctuary-business-writer.service
Accept=no
SocketUser=root
SocketGroup=sanctuary-business-writer
SocketMode=0660
DirectoryMode=0755
Backlog=1
PassCredentials=yes
FlushPending=yes
RemoveOnStop=yes
FileDescriptorName=records
"#,
    );
    assert_eq!(service, expected_service);
    assert_eq!(socket, expected_socket);
    assert_eq!(service["[Service].ExecStart"], WRITER_EXEC);
    assert_eq!(service["[Unit].PartOf"], WALL_UNIT);
    assert_eq!(socket["[Socket].ListenSequentialPacket"], RECORD_SOCKET);
    assert_eq!(socket["[Socket].FileDescriptorName"], RECORD_FD_NAME);
    assert_eq!(
        u32::from_str_radix(&socket["[Socket].SocketMode"], 8).unwrap(),
        RECORD_MODE
    );
    for key in [
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "StateDirectory",
        "LogsDirectory",
        "ReadWritePaths",
    ] {
        assert!(!service.contains_key(&format!("[Service].{key}")));
    }
    assert!(service
        .keys()
        .chain(socket.keys())
        .all(|k| !k.starts_with("[Install]")));
}

#[path = "support/writer_run.rs"]
mod writer_run;
#[test]
fn composed_startup_and_recovery_notifications() {
    for case in [
        "start-recovery",
        "start-wipe",
        "start-refuse-UNLOCKING",
        "start-refuse-UNLOCKED",
        "start-refuse-LOCKING",
        "start-refuse-WIPED",
        "activation-two",
    ] {
        writer_run::child_case("composed_startup_and_recovery_notifications", case, || {
            writer_run::scenario(case)
        });
    }
}
#[test]
fn composed_native_client_populated_and_null_anchors() {
    for case in ["native-populated", "native-null"] {
        writer_run::child_case(
            "composed_native_client_populated_and_null_anchors",
            case,
            || writer_run::scenario(case),
        );
    }
}
#[test]
fn composed_closed_reconciler_and_envelope_admission() {
    for case in [
        "inert",
        "noncanonical",
        "oversized-canonical",
        "wrong-signature",
        "positive",
        "second-accept",
        "maximum-sign",
        "postwait-mainpid",
        "postwait-invocation",
        "postwait-cgroup",
        "postwait-owner",
    ] {
        writer_run::child_case(
            "composed_closed_reconciler_and_envelope_admission",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn binary_notifications_and_start_closure() {
    use sha2::{Digest, Sha256};
    use std::{
        process::{Command, Stdio},
        thread,
        time::Duration,
    };
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let executable = env!("CARGO_BIN_EXE_writer-standin");
    let policy = serde_json::json!({"uid":unsafe{libc::geteuid()},"gid":unsafe{libc::getegid()},"executable_sha256":hex::encode(Sha256::digest(fs::read(executable).unwrap())),"cgroup":fs::read_to_string("/proc/self/cgroup").unwrap().trim()});
    for fault in [
        "none",
        "recovery",
        "wipe",
        "active",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "digest",
        "owner",
        "mode",
        "links",
        "identity",
        "wx",
        "deleted",
        "map-size",
        "library-owner",
        "library-mode",
        "mapping-count",
        "config-replace",
        "environment",
        "unknown",
        "two-fds",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sign.sock");
        let f = writer_state::Fixture::new();
        if fault == "recovery" {
            f.state("RECOVERY_REQUIRED");
        }
        if fault == "wipe" {
            f.state("WIPE_UNCONFIRMED");
        }
        if fault == "active" {
            f.unlock();
        }
        fs::write(
            root.path().join("signer-status.json"),
            serde_json::to_vec(&f.view.lock().unwrap().clone()).unwrap(),
        )
        .unwrap();
        let mut server = Child(
            Command::new(executable)
                .arg("signer")
                .arg(root.path())
                .arg("bounded")
                .env_clear()
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        for _ in 0..300 {
            if path.exists() {
                break;
            }
            assert!(server.0.try_wait().unwrap().is_none());
            thread::sleep(Duration::from_millis(10));
        }
        assert!(path.exists());
        let output = Command::new("python3")
            .args(["-I", "../server/test/fixtures/k1-writer-controller.py"])
            .arg(root.path())
            .arg(
                std::path::Path::new(
                    &std::env::var("SANCTUARY_K1_TEST_BINARIES")
                        .expect("dedicated writer harness required"),
                )
                .join("debug/sanctuary-business-writer"),
            )
            .arg(&path)
            .arg(policy.to_string())
            .arg(fault)
            .output()
            .unwrap();
        drop(server);
        assert!(
            output.status.success(),
            "{fault}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let messages: Vec<_> = events.iter().filter_map(|v| v["notify"].as_str()).collect();
        if matches!(fault, "none" | "recovery" | "wipe") {
            assert_eq!(
                messages,
                vec![
                    if fault == "none" {
                        "READY=1\nSTATUS=writer closed"
                    } else {
                        "READY=1\nSTATUS=writer closed for recovery"
                    },
                    STOP_STATUS,
                    "STOPPING=1"
                ],
                "{fault}"
            );
        } else {
            assert_eq!(messages, vec!["STATUS=writer refused at start"], "{fault}");
        }
        assert_eq!(events.last().unwrap()["exit"], 1);
        assert_eq!(output.stderr, b"K1_REFUSED\n", "{fault}");
    }
}

#[test]
fn composed_bus_malformed_fields_close_the_runtime() {
    for case in [
        "bus-duplicate-serial",
        "bus-duplicate-destination",
        "bus-duplicate-sender",
        "bus-duplicate-signature",
        "bus-unknown-header",
        "bus-signature",
    ] {
        writer_run::child_case(
            "composed_bus_malformed_fields_close_the_runtime",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn composed_capture_predicates_close_after_ready() {
    for case in [
        "capture-mainpid",
        "capture-cgroup",
        "capture-unit-id",
        "capture-invocation",
        "capture-argv",
        "capture-dropins",
        "capture-owner",
        "capture-wall-hash",
        "capture-fragment-hash",
    ] {
        writer_run::child_case(
            "composed_capture_predicates_close_after_ready",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn composed_heartbeat_timeout_waves_and_bound_loss() {
    for wave in 0..writer_state::HEARTBEAT_WAVES {
        let case = format!("heartbeat-timeout-{wave}");
        writer_run::child_case(
            "composed_heartbeat_timeout_waves_and_bound_loss",
            &case,
            || writer_run::scenario(&case),
        );
    }
    for case in [
        "frozen-expiry",
        "bound-change-grant",
        "bound-change-start",
        "bound-change-expiry",
        "bound-change-boot",
    ] {
        writer_run::child_case(
            "composed_heartbeat_timeout_waves_and_bound_loss",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn composed_recovery_needs_a_new_lock_and_later_unlock() {
    for case in [
        "recovery-no-lock",
        "recovery-stale",
        "recovery-fresh",
        "boot-mismatch",
    ] {
        writer_run::child_case(
            "composed_recovery_needs_a_new_lock_and_later_unlock",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn composed_ack_packets_and_frozen_grant_admission() {
    for case in [
        "ack-foreign",
        "packet-mainpid",
        "packet-session",
        "packet-rights",
        "admission-activation",
        "admission-lease",
        "admission-generation",
        "admission-epoch",
        "admission-deadline",
        "admission-expired",
        "admission-text",
    ] {
        writer_run::child_case(
            "composed_ack_packets_and_frozen_grant_admission",
            case,
            || writer_run::scenario(case),
        );
    }
}

#[test]
fn composed_wall_death_during_sign_emits_no_verified() {
    writer_run::child_case(
        "composed_wall_death_during_sign_emits_no_verified",
        "death-during-sign",
        || writer_run::scenario("death-during-sign"),
    );
}

#[test]
fn closure_work_precedes_the_signer_idle_window() {
    for case in ["slow-closure", "closure-refusal"] {
        writer_run::child_case("closure_work_precedes_the_signer_idle_window", case, || {
            writer_run::scenario(case)
        });
    }
}
