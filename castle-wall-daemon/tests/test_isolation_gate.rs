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
//! The same file also owns the Linux CI witness-loop parity check, so the CI
//! step that witnesses the feature-gated binaries cannot silently lose one from
//! its list.
//!
//! Failure mode this catches, stated as the operator sees it: none. A missing
//! gate is silent on macOS and destroys an operator's live enforcement table on
//! Linux, with no error attributable to the test that did it. There is no
//! after-the-fact symptom to look for, which is why the check must be structural.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// Marker strings must match the suite-list-begin/end comments in the repo-root
// path .github/workflows/castle-wall-linux.yml.
const WORKFLOW_SUITE_LIST_BEGIN: &str = "# suite-list-begin:";
const WORKFLOW_SUITE_LIST_END: &str = "# suite-list-end:";
const WORKFLOW_LIST_EXTRA_TARGET: &str = "test_isolation_gate";
// Must match the grep/echo/exit/brace lines immediately below suite-list-end in
// .github/workflows/castle-wall-linux.yml; this array is the single body pin.
const WORKFLOW_SUITE_RAN_LOOP_BODY: &[&str] = &[
    r#"grep -q "Running tests/$suite.rs" cargo-test.plain.log || {"#,
    r#"echo "FAIL: $suite did not run; the test-isolation feature is required for it""#,
    "exit 1",
    "}",
];

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

fn repo_root() -> PathBuf {
    crate_root()
        .parent()
        .expect("crate root has repository parent")
        .to_path_buf()
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

/// The Linux CI "did it run" loop names every gated target plus this guard
/// target. Parsed from anchored comments so the workflow and Cargo.toml lists
/// cannot drift independently. Remaining bound: this pins workflow TEXT between
/// the markers, not which YAML node runs it. Commands before the begin marker,
/// wrappers around the whole loop (`if false`, a subshell `|| true`, an
/// uncalled function), step-level `if:` or `continue-on-error:`, and relocating
/// the marked block into another scalar are out of reach, as is YAML-parse
/// validity (separate workflow work).
fn workflow_suite_targets() -> BTreeSet<String> {
    let workflow_path = repo_root().join(".github/workflows/castle-wall-linux.yml");
    let workflow = std::fs::read_to_string(workflow_path).expect("read Linux workflow");
    workflow_suite_targets_from_str(&workflow)
}

fn workflow_suite_targets_from_str(workflow: &str) -> BTreeSet<String> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum WorkflowSuiteLoopState {
        Outside,
        InList,
        InBody,
    }

    fn parse_suite_list_lines(lines: &[String]) -> BTreeSet<String> {
        assert!(
            !lines.is_empty(),
            "Linux workflow suite list marker block contains no suite names"
        );
        assert!(
            lines
                .first()
                .expect("suite list lines already known non-empty")
                .starts_with("for suite in"),
            "Linux workflow suite list must start with `for suite in`"
        );

        let mut suites = BTreeSet::new();
        let Some((last_line, earlier_lines)) = lines.split_last() else {
            unreachable!("empty suite list was rejected before split_last")
        };

        for line in earlier_lines {
            assert!(
                !line.contains('#'),
                "Linux workflow suite list must not contain comments"
            );
            assert!(
                line.ends_with('\\'),
                "every non-final Linux workflow suite list line must end with a backslash"
            );
        }
        assert!(
            !last_line.contains('#'),
            "Linux workflow suite list must not contain comments"
        );
        assert!(
            last_line.ends_with("; do"),
            "final Linux workflow suite list line must end with `; do`"
        );

        for (index, line) in lines.iter().enumerate() {
            let mut command_part = line.as_str();
            if index == 0 {
                command_part = command_part
                    .strip_prefix("for suite in")
                    .expect("first suite list line was checked above");
            }
            if index + 1 == lines.len() {
                command_part = command_part
                    .strip_suffix("; do")
                    .expect("final suite list line was checked above");
            } else {
                command_part = command_part
                    .strip_suffix('\\')
                    .expect("non-final suite list line was checked above");
            }
            for token in command_part.split_whitespace() {
                suites.insert(token.to_string());
            }
        }
        suites
    }

    let mut suites = BTreeSet::new();
    let mut suite_list_lines = Vec::new();
    let mut state = WorkflowSuiteLoopState::Outside;
    let mut saw_begin = false;
    let mut saw_end = false;
    let mut body_line_index = 0usize;
    let mut saw_loop_done = false;

    for raw_line in workflow.lines() {
        let line = raw_line.trim();
        // A marker counts only when the trimmed line starts with it: after trim, a line
        // starting with `#` is all comment to bash, so no command can ride on a marker line.
        if line.starts_with(WORKFLOW_SUITE_LIST_BEGIN) {
            assert!(
                !saw_begin,
                "more than one Linux workflow suite-list-begin marker"
            );
            assert!(
                state == WorkflowSuiteLoopState::Outside,
                "Linux workflow suite-list-begin marker must start a loop list"
            );
            state = WorkflowSuiteLoopState::InList;
            saw_begin = true;
            continue;
        }
        if line.starts_with(WORKFLOW_SUITE_LIST_END) {
            assert!(
                !saw_end,
                "more than one Linux workflow suite-list-end marker"
            );
            assert!(
                state == WorkflowSuiteLoopState::InList,
                "Linux workflow suite-list-end marker without a begin marker"
            );
            suites = parse_suite_list_lines(&suite_list_lines);
            state = WorkflowSuiteLoopState::InBody;
            body_line_index = 0usize;
            saw_end = true;
            continue;
        }

        match state {
            WorkflowSuiteLoopState::Outside => continue,
            WorkflowSuiteLoopState::InList => {
                suite_list_lines.push(line.to_string());
            }
            WorkflowSuiteLoopState::InBody => {
                if body_line_index < WORKFLOW_SUITE_RAN_LOOP_BODY.len() {
                    assert!(
                        line == WORKFLOW_SUITE_RAN_LOOP_BODY[body_line_index],
                        "Linux workflow suite-ran loop body must match the pinned fail-closed body"
                    );
                    body_line_index += 1;
                    continue;
                }
                assert!(
                    line == "done",
                    "Linux workflow suite-ran loop body must be followed immediately by `done`"
                );
                saw_loop_done = true;
                state = WorkflowSuiteLoopState::Outside;
                continue;
            }
        }
    }

    assert!(
        saw_begin,
        "Linux workflow suite-list-begin marker is missing"
    );
    assert!(saw_end, "Linux workflow suite-list-end marker is missing");
    assert!(
        state != WorkflowSuiteLoopState::InList,
        "Linux workflow suite list marker block is unterminated"
    );
    assert!(
        saw_loop_done,
        "Linux workflow suite-ran loop must close after the marker block"
    );
    assert!(
        !suites.is_empty(),
        "Linux workflow suite list marker block contains no suite names"
    );
    suites
}

#[test]
fn workflow_suite_loop_shape_rejects_neutral_negative_fixtures() {
    let cases = [
        (
            "second marker pair",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              echo "FAIL: $suite did not run; the test-isolation feature is required for it"
              exit 1
            }
          done
          # suite-list-begin:
          for suite in integration_kernel_binding; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              echo "FAIL: $suite did not run; the test-isolation feature is required for it"
              exit 1
            }
          done
"#,
            "more than one Linux workflow suite-list-begin marker",
        ),
        (
            "header separated from body check",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation integration_kernel_binding; do
          # suite-list-end:
            true
          done
          for suite in integration_linux_runtime_activation; do
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              exit 1
            }
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "body without witness check",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            true
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "comment inside suite list",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation \
          # integration_kernel_binding
                       integration_dns_bypass; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              exit 1
            }
          done
"#,
            "Linux workflow suite list must not contain comments",
        ),
        (
            "missing continuation backslash",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation
                       integration_kernel_binding; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              exit 1
            }
          done
"#,
            "every non-final Linux workflow suite list line must end with a backslash",
        ),
        (
            "continue before witness check",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            continue
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              exit 1
            }
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "neutralized witness check",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || true || {
              exit 1
            }
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "inner suite shadow loop",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation integration_kernel_binding; do
          # suite-list-end:
            for suite in test_isolation_gate; do
              grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
                exit 1
              }
            done
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "early successful exit after witness group",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              echo "FAIL: $suite did not run; the test-isolation feature is required for it"
              exit 1
            }
            exit 0
          done
"#,
            "Linux workflow suite-ran loop body must be followed immediately by `done`",
        ),
        (
            "witness check reads inline text",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          # suite-list-end:
            grep -q "Running tests/$suite.rs" <<< "Running tests/$suite.rs" || {
              exit 1
            }
          done
"#,
            "Linux workflow suite-ran loop body must match the pinned fail-closed body",
        ),
        (
            "command on the end marker line",
            r#"
          # suite-list-begin:
          for suite in integration_linux_runtime_activation; do
          continue # suite-list-end:
            grep -q "Running tests/$suite.rs" cargo-test.plain.log || {
              echo "FAIL: $suite did not run; the test-isolation feature is required for it"
              exit 1
            }
          done
"#,
            "Linux workflow suite-list-end marker is missing",
        ),
    ];

    let mut accepted = Vec::new();
    let mut wrong_panic = Vec::new();
    for (name, workflow, expected_message) in cases {
        match std::panic::catch_unwind(|| workflow_suite_targets_from_str(workflow)) {
            Ok(_) => {
                accepted.push(name);
            }
            Err(payload) => {
                let message = panic_message(payload);
                if !message.contains(expected_message) {
                    wrong_panic.push(format!("{name}: {message:?}"));
                }
            }
        }
    }
    assert!(
        wrong_panic.is_empty(),
        "workflow suite-loop parser rejected invalid fixture shapes for the wrong reason: {:?}",
        wrong_panic
    );
    assert!(
        accepted.is_empty(),
        "workflow suite-loop parser accepted invalid fixture shapes: {:?}",
        accepted
    );
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else {
        "<non-string panic>".to_string()
    }
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
fn the_gated_set_is_exactly_the_known_host_touching_targets() {
    // Deliberately no count in the test name: a name that carries the cardinality
    // ("...the_five_known...") goes stale the first time a target is added and
    // then reads as a lie in the CI output while the assertion itself is correct.
    let expected: BTreeSet<String> = [
        "confined_agent_id",
        "integration_dns_bypass",
        "integration_failure_modes",
        "integration_gf1_recovery",
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

/// The workflow loop is the CI-side witness that every gated test binary
/// actually appeared in the `cargo test --features test-isolation` run. It must
/// stay equal to Cargo.toml's gated set, plus this ungated self-check target.
#[test]
fn linux_workflow_suite_ran_loop_matches_the_gated_target_set() {
    let mut expected = gated_targets();
    assert!(
        expected.insert(WORKFLOW_LIST_EXTRA_TARGET.to_string()),
        "the workflow's one documented extra target must not also be gated"
    );
    assert_eq!(
        workflow_suite_targets(),
        expected,
        "the Linux workflow suite-ran loop must equal the Cargo.toml \
         `test-isolation` gated target set, plus `test_isolation_gate` as the \
         one documented extra self-check target"
    );
}
