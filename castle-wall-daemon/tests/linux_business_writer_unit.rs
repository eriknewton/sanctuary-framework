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
