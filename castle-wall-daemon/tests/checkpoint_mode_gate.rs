// fail-before-exempt: feature-off checkpoint composition is checked against native source and the Rust compiler.
// W-CHECKPOINT
use std::{fs, path::PathBuf, process::Command};
fn source() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/business_profile/writer_service.rs"),
    )
    .unwrap()
}
#[test]
fn acceptance_variant_requires_the_isolation_feature() {
    let source = source();
    let start = source.find("pub(crate) enum CheckpointMode {").unwrap();
    let end = start + source[start..].find('}').unwrap() + 1;
    let declaration = &source[start..end];
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mode.rs");
    for (variant, feature, expected) in [
        ("Refuse", false, true),
        ("Accept", true, true),
        ("Accept", false, false),
    ] {
        fs::write(
            &path,
            format!("{declaration}\nfn main() {{ let _ = CheckpointMode::{variant}; }}"),
        )
        .unwrap();
        let mut compiler = Command::new("rustc");
        compiler
            .arg("--edition=2021")
            .arg(&path)
            .arg("-o")
            .arg(root.path().join("mode"));
        if feature {
            compiler.args(["--cfg", "feature=\"test-isolation\""]);
        }
        let output = compiler.output().unwrap();
        assert_eq!(
            output.status.success(),
            expected,
            "{variant}, feature={feature}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !expected {
            assert!(String::from_utf8_lossy(&output.stderr).contains("E0599"));
        }
    }
}
#[test]
fn required_mode_has_no_wildcard_or_default() {
    let source = source();
    let start = source.find("match mode {").unwrap();
    let tail = &source[start..];
    let end = tail.find("if machine.checkpoint.transfer").unwrap();
    let block = &tail[..end];
    assert!(block.contains("CheckpointMode::Refuse => return Err(Error::State)"));
    assert!(block.contains("CheckpointMode::Accept =>"));
    assert!(
        !block.contains("_ =>"),
        "checkpoint mode must remain exhaustive"
    );
    assert!(!source.contains("impl Default for CheckpointMode"));
    assert!(source.contains("&deps.clock,\n        CheckpointMode::Refuse,"));
}
