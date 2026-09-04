//! Structural guard: every integration target that can reach a HOST-GLOBAL
//! object must be gated behind `required-features = ["test-isolation"]`.
//!
//! AGENTS.md, "the operator's machine is not a fixture", plus the rule-5
//! lesson that a convention held in prose drifts. The gate was applied by hand to
//! four suites and a fifth (`integration_manifest_and_drain`) was missed for
//! exactly the reason hand-mirrored sets are always missed: its assertions are
//! platform-portable, so it did not LOOK like a kernel suite, while its
//! `daemon::boot` call installed the production `sanctuary-castle` table on any
//! privileged Linux host that ran `cargo test`.
//!
//! This target is deliberately NOT gated, so a plain `cargo test` runs it. It
//! reads files and spawns nothing, so it is safe on every host.
//!
//! Failure mode this catches, stated as the operator sees it: none. A missing
//! gate is silent on macOS and destroys an operator's live enforcement table on
//! Linux, with no error attributable to the test that did it. There is no
//! after-the-fact symptom to look for, which is why the check must be structural.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Source substrings that prove a target can reach a host-global object: the
/// nftables table (shared kernel object), or `daemon::boot`, whose Linux path
/// calls `activate_kernel_runtime` and installs that table, takes the host
/// ownership lock, and writes the authenticated ownership journal plus its
/// root-owned MAC key.
///
/// Assembled from fragments rather than written as whole literals so that THIS
/// file does not match its own rule. A `file!()`-based self-exclusion would work
/// too, but it would also silently excuse a future edit that really did add a
/// boot call here.
fn host_global_markers() -> Vec<String> {
    vec![
        format!("{}::{}", "castle_wall_daemon", "nftables"),
        format!("{}::{}", "nftables", "install_castle_table"),
        format!("{}::{}(", "daemon", "boot"),
        format!("{} {}", "use castle_wall_daemon::daemon::", "boot;"),
    ]
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Test targets Cargo.toml declares with `required-features = ["test-isolation"]`.
///
/// Parsed from the manifest rather than hard-coded: a hard-coded expected list is
/// the same hand-mirrored shape this test exists to prohibit, and it would pass
/// while the manifest said something else.
fn gated_targets() -> BTreeSet<String> {
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("read Cargo.toml");
    let mut gated = BTreeSet::new();
    let mut name: Option<String> = None;
    let mut in_test_target = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // A new table ends the previous one; an ungated `[[test]]` block
            // therefore drops its name without recording it.
            in_test_target = line == "[[test]]";
            name = None;
            continue;
        }
        if !in_test_target {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name") {
            if let Some(value) = rest.split('=').nth(1) {
                name = Some(value.trim().trim_matches('"').to_string());
            }
        }
        if line.starts_with("required-features") && line.contains("test-isolation") {
            if let Some(n) = name.clone() {
                gated.insert(n);
            }
        }
    }
    gated
}

/// Every `tests/*.rs` file, which is exactly the set cargo auto-discovers as
/// integration targets. Files under `tests/<dir>/` (such as `tests/isolation/`)
/// are shared modules, not targets, and are excluded the same way cargo excludes
/// them.
fn integration_target_files() -> Vec<(String, PathBuf)> {
    let dir = crate_root().join("tests");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read tests dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("utf-8 test file name")
            .to_string();
        out.push((stem, path));
    }
    out.sort();
    out
}

/// Source of a target plus every non-target module it pulls in with `mod x;`,
/// so a suite that hides its `nftables` use behind a shared helper still counts.
fn effective_source(path: &Path) -> String {
    let mut source = std::fs::read_to_string(path).expect("read test source");
    let dir = path.parent().expect("tests dir");
    for line in source.clone().lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("mod ") else {
            continue;
        };
        let Some(module) = rest.strip_suffix(';') else {
            continue;
        };
        let module_path = dir.join(module.trim()).join("mod.rs");
        if let Ok(extra) = std::fs::read_to_string(module_path) {
            source.push_str(&extra);
        }
    }
    source
}

#[test]
fn every_target_that_can_reach_host_global_state_is_gated_on_test_isolation() {
    let gated = gated_targets();
    let markers = host_global_markers();
    let mut ungated_but_reaching = Vec::new();
    for (name, path) in integration_target_files() {
        let source = effective_source(&path);
        let reaches = markers.iter().any(|m| source.contains(m.as_str()));
        if reaches && !gated.contains(&name) {
            ungated_but_reaching.push(name);
        }
    }
    assert!(
        ungated_but_reaching.is_empty(),
        "these integration targets can reach the nftables table, the host ownership \
         lock, the ownership journal or its MAC key, but Cargo.toml does not declare \
         `required-features = [\"test-isolation\"]` for them, so a plain `cargo test` \
         on a Linux host runs them against the operator's LIVE enforcement state: {:?}. \
         Add a `[[test]]` block with the gate, add `mod isolation;`, and take \
         `isolation::guard()` before anything that can resolve a host-global name.",
        ungated_but_reaching
    );
}

/// The converse half. A gate in Cargo.toml is only half the protection: a gated
/// suite that never installs the isolated table still resolves `castle_table()`
/// to `sanctuary-castle` on its first nftables call. The shared module is the one
/// place that installs it, so every gated target must include it.
#[test]
fn every_gated_target_installs_the_shared_isolation_module() {
    let gated = gated_targets();
    let mut missing_module = Vec::new();
    for (name, path) in integration_target_files() {
        if !gated.contains(&name) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read test source");
        if !source.contains("mod isolation;") {
            missing_module.push(name);
        }
    }
    assert!(
        missing_module.is_empty(),
        "these targets are gated on `test-isolation` but never pull in \
         `tests/isolation/mod.rs`, which is the only code that installs the \
         isolated nftables table and asserts the production table was never \
         resolved. Being unable to BUILD without the feature does not redirect \
         anything by itself: {:?}",
        missing_module
    );
}

/// Names the gate list in one assertion so a target that is REMOVED from it shows
/// up as a diff here rather than as a silent loss of protection. This is the one
/// place an explicit list is correct: it is the assertion's subject, not a mirror
/// of a fact stored elsewhere.
#[test]
fn the_gated_set_is_exactly_the_five_known_host_touching_targets() {
    let expected: BTreeSet<String> = [
        "integration_dns_bypass",
        "integration_failure_modes",
        "integration_kernel_binding",
        "integration_linux_runtime_activation",
        "integration_manifest_and_drain",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        gated_targets(),
        expected,
        "the set of isolation-gated test targets changed. Adding one is fine \
         (update this list). REMOVING one means a suite that touches the host \
         nftables table, ownership lock or journal is now reachable from a plain \
         `cargo test`."
    );
}
