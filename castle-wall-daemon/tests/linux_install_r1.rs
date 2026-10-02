//! Capability: retirement, full unit inventory and current-principal exclusion. LINUX-INSTALL-R1.
#![cfg(target_os = "linux")]
use castle_wall_daemon::linux_install::{
    command::{admitted_package_status, inspect_unit_tree},
    transaction::Root,
};
#[test]
fn retirement_survives_refused_dpkg_selection_without_admitting_activation() {
    for status in [
        b"install ok installed".as_slice(),
        b"deinstall ok installed",
        b"purge ok installed",
        b"hold ok installed",
        b"unknown ok installed",
    ] {
        assert!(admitted_package_status(status, true));
        assert_eq!(
            admitted_package_status(status, false),
            status == b"install ok installed"
        );
    }
    for status in [
        b"install reinstreq installed".as_slice(),
        b"install ok unpacked",
        b"deinstall ok half-installed",
    ] {
        assert!(!admitted_package_status(status, true));
    }
}
#[test]
fn every_dependency_suffix_is_inventoried() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::open(dir.path()).unwrap();
    for suffix in ["wants", "requires", "upholds", "other/nested"] {
        let parent = format!("etc/systemd/system/other.target.{suffix}");
        std::fs::create_dir_all(dir.path().join(&parent)).unwrap();
        let path = dir.path().join(parent).join("helper.service");
        assert!(inspect_unit_tree(&root, "etc/systemd/system", &[], true).is_ok());
        std::os::unix::fs::symlink("/etc/systemd/system/sanctuary-agent@.service", &path).unwrap();
        assert!(inspect_unit_tree(&root, "etc/systemd/system", &[], true).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

fn transaction() -> castle_wall_daemon::linux_install::transaction::Transaction {
    use castle_wall_daemon::linux_install::{
        account::AccountStep,
        transaction::{State, Transaction},
    };
    Transaction {
        version: 1,
        request_sha256: "a".repeat(64),
        state: State::Absent,
        agent_uid: 60123,
        service_uid: 60124,
        operator_uid: 1000,
        fortress_id: "0123456789abcdef".into(),
        sanctuary_gid: None,
        account_step: AccountStep::Fresh,
        policy_generation: 0,
        policy_request_sha256: None,
        policy_complete: false,
    }
}
#[test]
fn a_resuming_operator_cannot_become_either_installation_principal() {
    use castle_wall_daemon::linux_install::account::validate_current_operator;
    let t = transaction();
    assert!(validate_current_operator(&t, 1001).is_ok());
    for uid in [t.agent_uid, t.service_uid, u32::MAX] {
        assert!(validate_current_operator(&t, uid).is_err());
    }
}
#[test]
fn partial_accounts_refuse_policy_before_reading_or_writing_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::open(dir.path()).unwrap();
    let result =
        castle_wall_daemon::linux_install::policy::install(&root, &mut transaction(), b"{}", "");
    assert_eq!(
        result.unwrap_err().to_string(),
        "provision accounts incomplete"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
