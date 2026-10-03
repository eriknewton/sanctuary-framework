//! The real CLI exposes only the install command grammar and no isolation switches.
#![cfg(target_os = "linux")]
use castle_wall_daemon::linux_install::command::parse_options;
use std::process::Command;
#[test]
fn packaged_binary_has_help_and_refuses_test_isolation_and_cut_verbs() {
    let binary = env!("CARGO_BIN_EXE_sanctuary-linux");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    for verb in [
        "provision",
        "policy-install",
        "enable",
        "disable",
        "stop",
        "status",
        "evidence",
    ] {
        assert!(text.contains(verb));
    }
    for bad in [
        "--test-root",
        "--runtime-dir",
        "--test-isolation",
        "command-create",
        "install-probe-endpoints",
        "remove",
    ] {
        assert!(!Command::new(binary).arg(bad).status().unwrap().success());
    }
}
#[test]
fn options_refuse_duplicates_unknown_and_missing_values() {
    let names = ["--one", "--two"];
    let convert = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(parse_options(&convert(&["--one", "a", "--two", "b"]), &names).is_ok());
    for bad in [
        vec!["--one", "a", "--one", "b"],
        vec!["--one", "a", "--other", "b"],
        vec!["--one", "a"],
        vec!["--one", "a", "--two"],
    ] {
        assert!(parse_options(&convert(&bad), &names).is_err());
    }
}

#[test]
fn manager_singleton_names_accept_exact_mount_escaping_and_refuse_aliases() {
    use castle_wall_daemon::linux_install::{
        command::verify_unit_observation, contract::WORKSPACE_MOUNT_UNIT,
    };
    use std::collections::BTreeMap;
    for unit in [
        "sanctuary-castle-wall.service",
        "sanctuary-agent@60123.service",
        WORKSPACE_MOUNT_UNIT,
    ] {
        let fragment = if unit.starts_with("sanctuary-agent@") {
            "sanctuary-agent@.service"
        } else {
            unit
        };
        let path = format!("/etc/systemd/system/{fragment}");
        let names = if unit == WORKSPACE_MOUNT_UNIT {
            format!("\"{}\"", unit.replace('\\', "\\\\"))
        } else {
            unit.into()
        };
        let valid: BTreeMap<String, String> = [
            ("Id", unit),
            ("Names", names.as_str()),
            ("FragmentPath", path.as_str()),
            ("LoadState", "loaded"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("UnitFileState", "disabled"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert!(verify_unit_observation(&valid, unit, &path).is_ok());
        for (field, value) in [
            ("Id", "alias.service"),
            ("Names", "alias.service"),
            ("FragmentPath", "/run/systemd/system/foreign.service"),
            ("LoadState", "not-found"),
            ("DropInPaths", "/etc/systemd/system/override.conf"),
            ("NeedDaemonReload", "yes"),
            ("UnitFileState", "masked"),
        ] {
            let mut changed = valid.clone();
            changed.insert(field.into(), value.into());
            assert!(verify_unit_observation(&changed, unit, &path).is_err());
            changed = valid.clone();
            changed.remove(field);
            assert!(verify_unit_observation(&changed, unit, &path).is_err());
        }
        let mut alias = valid.clone();
        alias.insert("Names".into(), format!("{names} extra.service"));
        assert!(verify_unit_observation(&alias, unit, &path).is_err());
    }
}
