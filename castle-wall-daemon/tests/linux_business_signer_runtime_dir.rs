#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::custody::CONTROL_ROOT;
#[test]
fn signer_owns_its_runtime_directory_and_unit_policy() {
    // Check the changed path first so historical failure identifies runtime separation.
    assert_eq!(CONTROL_ROOT, "/run/sanctuary-business-signer");
    let unit = include_str!("../systemd/sanctuary-business-signer.service");
    let directive = |name: &str| {
        unit.lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
    };
    assert_eq!(
        CONTROL_ROOT,
        format!("/run/{}", directive("RuntimeDirectory="))
    );
    assert!(directive("ReadWritePaths=")
        .split_whitespace()
        .any(|path| path == CONTROL_ROOT));
    assert_eq!(directive("RuntimeDirectoryMode="), "0700");
    assert_eq!(directive("Group="), "sanctuary");
    assert_eq!(directive("SupplementaryGroups="), "");
    assert!(!CONTROL_ROOT.starts_with("/run/sanctuary/"));
    for path in directive("ReadWritePaths=").split_whitespace() {
        assert!(!path.starts_with("/run/sanctuary/"));
    }
    for (key, expected) in [
        ("Slice=", "system.slice"),
        ("Delegate=", "no"),
        ("NotifyAccess=", "main"),
        ("TimeoutStartSec=", "30"),
        ("SendSIGKILL=", "yes"),
    ] {
        assert_eq!(directive(key), expected);
    }
}
