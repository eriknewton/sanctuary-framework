// fail-before-exempt: rendered writer activation and lifetime actors are new.
#![cfg(target_os = "linux")]
mod isolation;
fn witness(mode: &str) {
    let output = std::process::Command::new("python3")
        .args([
            "-I",
            "tests/helpers/writer-user-manager.py",
            &std::env::var("WRITER_TEST_HELPER").expect("optimized isolation actor required"),
            &format!(
                "{}/debug/sanctuary-business-writer",
                std::env::var("SANCTUARY_K1_TEST_BINARIES")
                    .expect("dedicated writer harness required")
            ),
            mode,
        ])
        // Must match writer-user-manager.py's final argument: one shared signer idle window.
        .arg(
            castle_wall_daemon::business_profile::signer_contract::SIGNER_IDLE_DEADLINE_MS
                .to_string(),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn mainpid_activation_and_ownership() {
    witness("main");
}
#[test]
fn same_cgroup_child_is_not_mainpid() {
    witness("child");
}
#[test]
fn outside_unit_is_not_mainpid() {
    witness("outside");
}
#[test]
fn ordinary_wall_death_stops_writer() {
    witness("death");
}
#[test]
fn held_record_fd_does_not_hide_pidfd_death() {
    witness("held");
}
#[test]
fn wall_stop_propagates_lifetime_edges() {
    witness("edges");
}
#[test]
fn stream_activation_refuses() {
    witness("stream");
}
#[test]
fn two_descriptor_activation_refuses() {
    witness("two");
}
