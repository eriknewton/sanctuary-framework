//! HABEAS PORT conflict-gate cross-language parity (Linux daemon side).
//!
//! Loads the SAME shared fixture the TS suite consumes
//! (`server/test/castle-wall/fixtures/habeas-conflict-parity.json`) and
//! asserts the Rust `find_habeas_conflicts` reaches the same conflict/clean
//! verdict on every case. This is the W5-style cross-language fixture: one
//! file, two languages, identical decision — so the TS and Linux gates reject
//! the same rule sets.

use std::path::PathBuf;

use castle_wall_daemon::habeas::{
    find_habeas_conflicts, find_habeas_conflicts_in_composed, HabeasWebhookTarget,
};
use castle_wall_daemon::policy::AllowlistRule;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WebhookTarget {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct ParityCase {
    name: String,
    webhook: Option<WebhookTarget>,
    rules: Vec<AllowlistRule>,
    expect_conflict: bool,
}

#[derive(Debug, Deserialize)]
struct ComposedParityCase {
    name: String,
    rules: Vec<AllowlistRule>,
    expect_conflict: bool,
}

#[derive(Debug, Deserialize)]
struct ParityFixture {
    cases: Vec<ParityCase>,
    composed_cases: Vec<ComposedParityCase>,
}

fn fixture_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/castle-wall-daemon
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("server")
        .join("test")
        .join("castle-wall")
        .join("fixtures")
        .join("habeas-conflict-parity.json")
}

#[test]
fn rust_gate_agrees_with_shared_parity_fixture() {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let fixture: ParityFixture =
        serde_json::from_str(&raw).expect("parse habeas-conflict-parity.json");

    assert!(!fixture.cases.is_empty(), "fixture has no cases");

    for case in &fixture.cases {
        let webhook = case
            .webhook
            .as_ref()
            .map(|w| HabeasWebhookTarget {
                host: w.host.clone(),
                port: w.port,
            });
        let issues = find_habeas_conflicts(&case.rules, webhook.as_ref());
        let conflicted = !issues.is_empty();
        assert_eq!(
            conflicted, case.expect_conflict,
            "case \"{}\": rust verdict {} != expected {} (issues: {:?})",
            case.name, conflicted, case.expect_conflict, issues
        );
    }
}

#[test]
fn rust_composed_gate_agrees_with_shared_parity_fixture() {
    // Composed-manifest gate parity (codex round-4 finding 4): duplicate
    // reserved ids and the always-on-local-lane requirement must produce the
    // same accept/reject verdict in both languages.
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let fixture: ParityFixture =
        serde_json::from_str(&raw).expect("parse habeas-conflict-parity.json");

    assert!(
        !fixture.composed_cases.is_empty(),
        "fixture has no composed_cases"
    );

    for case in &fixture.composed_cases {
        let issues = find_habeas_conflicts_in_composed(&case.rules);
        let conflicted = !issues.is_empty();
        assert_eq!(
            conflicted, case.expect_conflict,
            "composed case \"{}\": rust verdict {} != expected {} (issues: {:?})",
            case.name, conflicted, case.expect_conflict, issues
        );
    }
}
