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
