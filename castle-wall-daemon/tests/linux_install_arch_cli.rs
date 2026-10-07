//! Unpinned Arch CLI fails closed before privilege checks while help stays stable. ARCH-CLI-PINS-01.
#![cfg(all(target_os = "linux", feature = "arch-install"))]

use std::process::Command;

const UNPINNED_REASON: &str = "Arch CLI built without package pins";
const ROOT_REASON: &str = "root required";

fn arch_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sanctuary-linux-arch")
}

fn ubuntu_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sanctuary-linux")
}

#[test]
fn help_is_byte_identical_to_ubuntu_cli_contract() {
    let ubuntu = Command::new(ubuntu_bin()).arg("--help").output().unwrap();
    let arch = Command::new(arch_bin()).arg("--help").output().unwrap();
    assert!(ubuntu.status.success());
    assert!(arch.status.success());
    assert_eq!(arch.stdout, ubuntu.stdout);
}

#[test]
fn unpinned_build_refuses_ubuntu_cut_words_and_every_verb_before_root() {
    for args in [
        vec!["--test-root"],
        vec!["--runtime-dir"],
        vec!["--test-isolation"],
        vec!["command-create"],
        vec!["install-probe-endpoints"],
        vec!["remove"],
        vec!["provision"],
        vec!["policy-install"],
        vec!["enable"],
        vec!["start"],
        vec!["status", "--json"],
        vec!["evidence", "--output", "/tmp/sanctuary-evidence"],
        vec!["disable"],
        vec!["stop"],
    ] {
        let output = Command::new(arch_bin()).args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains(UNPINNED_REASON),
            "args {args:?} stderr {stderr:?}"
        );
        assert!(
            !stderr.contains(ROOT_REASON),
            "args {args:?} stderr {stderr:?}"
        );
    }
}
