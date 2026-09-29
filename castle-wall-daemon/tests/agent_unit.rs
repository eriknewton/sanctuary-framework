//! Structural checks on the SHIPPED agent template unit,
//! `systemd/sanctuary-agent@.service` (slice B; register id
//! `defect.linux-no-agent-launcher-assigns-or-drops-to-the-agent-uid`).
//!
//! Capability: an agent started by this unit runs only after the Castle Wall
//! unit is ready, only as the uid named by the instance, only when a
//! credential self-check and a root kernel gate both exit 0, and it is stopped
//! and never restarted when the wall stops or its process ends. These tests
//! prove the unit CARRIES exactly the directives that sentence depends on; the
//! real-manager behaviour is proven by TB0a, TB0b (tests/systemd_unit.rs) and
//! TB10 (tests/integration_linux_runtime_activation.rs).
//!
//! Every directive read runs only after the canonical-form check over the SAME
//! bytes the digest hashes, because a lenient parser passes decoys (a comment
//! naming a section header, a spaced key, a continuation) while systemd reads
//! the real directive.
//!
//! Reads files and spawns nothing, so it is safe on every host and needs no
//! `test-isolation` gate.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The audited agent unit digest. Pinned only after TB0a and TB0b passed on a
/// systemd 255 PID 1 host; any byte change, including a comment, needs a fresh
/// review of the effective unit before this value moves.
const AGENT_UNIT_SHA256: &str = "859d6e3cd65e0025aad423b4b74513628d26f80a61d2fe3667bb43c4f1180e34";

/// The installed daemon path both `ExecStartPre=` lines execute.
/// Must match `DAEMON_PATH` in packaging/ubuntu/lifecycle-guard.py.
const DAEMON_PATH: &str = "/usr/local/libexec/sanctuary/castle-wall-daemon";

/// The complete directive set of section 5.1 of the slice B design, as
/// (section, key, value) triples in file order. TB1b compares the unit's
/// multiset against exactly this, so any extra directive (a supplementary
/// group, an ambient capability, a second dependency edge, an
/// `UnsetEnvironment=`) fails by construction rather than by an absence list.
const EXPECTED_DIRECTIVES: &[(&str, &str, &str)] = &[
    ("Unit", "Description", "Sanctuary confined agent (uid %i)"),
    ("Unit", "BindsTo", "sanctuary-castle-wall.service"),
    ("Unit", "After", "sanctuary-castle-wall.service"),
    ("Service", "Type", "exec"),
    ("Service", "User", "%i"),
    ("Service", "Group", "%i"),
    ("Service", "EnvironmentFile", "/etc/sanctuary/castle-wall.env"),
    (
        "Service",
        "ExecStartPre",
        "/usr/local/libexec/sanctuary/castle-wall-daemon --agent-credential-check %i",
    ),
    (
        "Service",
        "ExecStartPre",
        "+/usr/local/libexec/sanctuary/castle-wall-daemon --agent-start-gate %i --fortress-id ${SANCTUARY_FORTRESS_ID} --trusted-service-uid ${SANCTUARY_TRUSTED_SERVICE_UID}",
    ),
    (
        "Service",
        "ExecStart",
        "/usr/local/libexec/sanctuary/protected-agent-v1",
    ),
    ("Service", "Restart", "no"),
    ("Service", "TimeoutStartSec", "30"),
    ("Service", "TimeoutStopSec", "10"),
    ("Service", "KillMode", "control-group"),
    ("Service", "SendSIGKILL", "yes"),
    ("Service", "NoNewPrivileges", "yes"),
    ("Service", "CapabilityBoundingSet", ""),
    ("Service", "StateDirectory", "sanctuary-agent-%i"),
    ("Service", "StateDirectoryMode", "0700"),
    ("Service", "RuntimeDirectory", "sanctuary-agent-%i"),
    ("Service", "RuntimeDirectoryMode", "0700"),
    ("Service", "WorkingDirectory", "%S/sanctuary-agent-%i"),
    ("Service", "Environment", "HOME=%S/sanctuary-agent-%i"),
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn agent_unit_text() -> String {
    let path = crate_root()
        .join("systemd")
        .join("sanctuary-agent@.service");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("shipped agent unit must be readable at {path:?}: {e}"))
}

/// Every canonical-form violation in `text` (empty means canonical).
///
/// The form: exactly one `[Unit]` then one `[Service]` and no other section;
/// comments start at column 0 with `#` and never contain `[`; every other
/// non-blank line is `Key=value` with an ASCII-letter key and no whitespace
/// before `=`; no line has leading whitespace, a carriage return or a trailing
/// backslash (a continuation); no key repeats except `ExecStartPre`, which
/// appears exactly twice.
fn canonical_form_violations(text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let mut sections: Vec<&str> = Vec::new();
    let mut key_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, line) in text.split('\n').enumerate() {
        let n = index + 1;
        if line.is_empty() {
            continue;
        }
        if line.contains('\r') {
            violations.push(format!("line {n}: carriage return"));
        }
        if line.starts_with(char::is_whitespace) {
            violations.push(format!("line {n}: leading whitespace"));
        }
        if line.ends_with('\\') {
            violations.push(format!("line {n}: trailing backslash continuation"));
        }
        if let Some(comment) = line.strip_prefix('#') {
            if comment.contains('[') {
                violations.push(format!("line {n}: comment contains '['"));
            }
            continue;
        }
        if line.starts_with('[') {
            match line {
                "[Unit]" | "[Service]" => sections.push(line),
                other => violations.push(format!("line {n}: section {other} not allowed")),
            }
            continue;
        }
        if sections.is_empty() {
            violations.push(format!("line {n}: directive before any section"));
        }
        match line.split_once('=') {
            Some((key, _)) if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphabetic()) => {
                *key_counts.entry(key).or_default() += 1;
            }
            _ => violations.push(format!("line {n}: not Key=value: {line:?}")),
        }
    }
    if sections != ["[Unit]", "[Service]"] {
        violations.push(format!(
            "sections must be exactly [Unit] then [Service], got {sections:?}"
        ));
    }
    for (key, count) in &key_counts {
        let allowed = if *key == "ExecStartPre" { 2 } else { 1 };
        if *count != allowed {
            violations.push(format!(
                "key {key} appears {count} times, expected {allowed}"
            ));
        }
    }
    violations
}

/// The (section, key, value) triples of canonical-form bytes, in file order.
/// Panics on non-canonical input: a directive read is valid only after the
/// canonical check passed over the same bytes.
fn directives(text: &str) -> Vec<(String, String, String)> {
    let violations = canonical_form_violations(text);
    assert!(
        violations.is_empty(),
        "directives are read only from canonical-form bytes: {violations:?}"
    );
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let (key, value) = line.split_once('=').expect("canonical lines are Key=value");
        out.push((section.clone(), key.to_string(), value.to_string()));
    }
    out
}

/// Differences between the unit's directive multiset and the expected listing.
fn directive_set_differences(text: &str) -> Vec<String> {
    let mut actual: BTreeMap<(String, String, String), i64> = BTreeMap::new();
    for triple in directives(text) {
        *actual.entry(triple).or_default() += 1;
    }
    for (section, key, value) in EXPECTED_DIRECTIVES {
        *actual
            .entry((section.to_string(), key.to_string(), value.to_string()))
            .or_default() -= 1;
    }
    actual
        .into_iter()
        .filter(|(_, count)| *count != 0)
        .map(|(triple, count)| {
            if count > 0 {
                format!("unexpected {triple:?} (x{count})")
            } else {
                format!("missing {triple:?} (x{})", -count)
            }
        })
        .collect()
}

/// The exec-start-pre problems of a unit, as named failures (TB1c).
fn exec_start_pre_problems(text: &str) -> Vec<String> {
    let lines: Vec<String> = directives(text)
        .into_iter()
        .filter(|(section, key, _)| section == "Service" && key == "ExecStartPre")
        .map(|(_, _, value)| value)
        .collect();
    let mut problems = Vec::new();
    if lines.len() != 2 {
        return vec![format!("expected exactly two ExecStartPre=, got {lines:?}")];
    }
    // The first line runs under the agent's own credentials: any systemd
    // command prefix (`+`, `!`, `!!`, `-`, `@`, `:`) would change what it proves.
    let check = &lines[0];
    if !check.starts_with('/') {
        problems.push(format!(
            "the credential check must carry no prefix: {check:?}"
        ));
    }
    let check_argv: Vec<&str> = check.split(' ').collect();
    if check_argv != [DAEMON_PATH, "--agent-credential-check", "%i"] {
        problems.push(format!("credential check argv drifted: {check_argv:?}"));
    }
    // The second line must be root (`+`, exactly one) to read the nft table.
    let gate = &lines[1];
    match gate.strip_prefix('+') {
        Some(rest) if rest.starts_with('/') => {
            let gate_argv: Vec<&str> = rest.split(' ').collect();
            let expected = [
                DAEMON_PATH,
                "--agent-start-gate",
                "%i",
                "--fortress-id",
                "${SANCTUARY_FORTRESS_ID}",
                "--trusted-service-uid",
                "${SANCTUARY_TRUSTED_SERVICE_UID}",
            ];
            if gate_argv != expected {
                problems.push(format!("kernel gate argv drifted: {gate_argv:?}"));
            }
        }
        _ => problems.push(format!(
            "the kernel gate must carry exactly one leading '+': {gate:?}"
        )),
    }
    problems
}

#[test]
fn tb1_the_agent_unit_bytes_are_pinned() {
    assert_eq!(
        format!("{:x}", Sha256::digest(agent_unit_text().as_bytes())),
        AGENT_UNIT_SHA256,
        "the audited agent unit bytes changed; re-review the effective unit before moving the pin"
    );
}

#[test]
fn tb1a_the_agent_unit_is_in_canonical_form() {
    let violations = canonical_form_violations(&agent_unit_text());
    assert!(violations.is_empty(), "canonical form: {violations:?}");
}

#[test]
fn tb1a_decoys_are_refused_by_the_canonical_form() {
    let shipped = agent_unit_text();
    let decoys = [
        (
            "a comment naming a section header, then decoy keys",
            shipped.replace("[Service]\n", "[Service]\n# [Service]\nUser=root\n"),
        ),
        (
            "a spaced key",
            shipped.replace("Group=%i\n", "Group = root\n"),
        ),
        (
            "a continuation",
            shipped.replace("Restart=no\n", "Restart=no \\\n"),
        ),
        (
            "leading whitespace",
            shipped.replace("Restart=no\n", "  Restart=no\n"),
        ),
        (
            "an Install section",
            format!("{shipped}\n[Install]\nWantedBy=multi-user.target\n"),
        ),
        (
            "a repeated section",
            format!("{shipped}\n[Service]\nRestart=no\n"),
        ),
    ];
    for (name, decoy) in decoys {
        assert_ne!(decoy, shipped, "the decoy {name} must change the bytes");
        assert!(
            !canonical_form_violations(&decoy).is_empty(),
            "the canonical form must refuse {name}"
        );
    }
}

#[test]
fn tb1b_the_agent_unit_directive_set_equals_the_design_listing() {
    let differences = directive_set_differences(&agent_unit_text());
    assert!(differences.is_empty(), "directive set: {differences:?}");
}

#[test]
fn tb1b_each_security_relevant_mutation_changes_the_directive_set() {
    let shipped = agent_unit_text();
    let mutants = [
        (
            "dropped BindsTo= (the agent would survive a wall stop)",
            shipped.replace("BindsTo=sanctuary-castle-wall.service\n", ""),
        ),
        (
            "Type=simple (a missing executable would read as started)",
            shipped.replace("Type=exec\n", "Type=simple\n"),
        ),
        (
            "Restart=on-failure (the agent would return behind a failed wall)",
            shipped.replace("Restart=no\n", "Restart=on-failure\n"),
        ),
        (
            "KillMode=process",
            shipped.replace("KillMode=control-group\n", "KillMode=process\n"),
        ),
        (
            "SendSIGKILL=no (an unbounded stop)",
            shipped.replace("SendSIGKILL=yes\n", "SendSIGKILL=no\n"),
        ),
        (
            "an added SupplementaryGroups=sanctuary",
            shipped.replace("Group=%i\n", "Group=%i\nSupplementaryGroups=sanctuary\n"),
        ),
        (
            "UnsetEnvironment= re-added (the trusted uid would stop arriving)",
            shipped.replace(
                "EnvironmentFile=/etc/sanctuary/castle-wall.env\n",
                "EnvironmentFile=/etc/sanctuary/castle-wall.env\n\
                 UnsetEnvironment=SANCTUARY_TRUSTED_SERVICE_UID\n",
            ),
        ),
    ];
    for (name, mutant) in mutants {
        assert_ne!(mutant, shipped, "the mutant {name} must change the bytes");
        assert!(
            !directive_set_differences(&mutant).is_empty(),
            "the directive-set equality must refuse {name}"
        );
    }
}

#[test]
fn tb1c_the_two_exec_start_pre_lines_are_ordered_prefixed_and_exact() {
    let problems = exec_start_pre_problems(&agent_unit_text());
    assert!(problems.is_empty(), "ExecStartPre: {problems:?}");
}

#[test]
fn tb1c_prefix_order_and_argv_mutations_are_refused() {
    let shipped = agent_unit_text();
    let gate_line =
        "ExecStartPre=+/usr/local/libexec/sanctuary/castle-wall-daemon --agent-start-gate";
    let check_line =
        "ExecStartPre=/usr/local/libexec/sanctuary/castle-wall-daemon --agent-credential-check";
    let mutants = [
        (
            "the gate without '+' (cannot read nft; always refuses)",
            shipped.replace(
                gate_line,
                "ExecStartPre=/usr/local/libexec/sanctuary/castle-wall-daemon --agent-start-gate",
            ),
        ),
        (
            "the gate with a doubled '+'",
            shipped.replace(
                gate_line,
                "ExecStartPre=++/usr/local/libexec/sanctuary/castle-wall-daemon --agent-start-gate",
            ),
        ),
        (
            "the check with '+' (runs as root, proves nothing)",
            shipped.replace(
                check_line,
                "ExecStartPre=+/usr/local/libexec/sanctuary/castle-wall-daemon --agent-credential-check",
            ),
        ),
        (
            "the trusted-uid argument dropped",
            shipped.replace(
                " --trusted-service-uid ${SANCTUARY_TRUSTED_SERVICE_UID}",
                "",
            ),
        ),
        (
            "the two lines swapped",
            {
                let lines: Vec<&str> = shipped.split('\n').collect();
                let a = lines.iter().position(|l| l.starts_with(check_line)).unwrap();
                let b = lines.iter().position(|l| l.starts_with(gate_line)).unwrap();
                let mut swapped: Vec<&str> = lines.clone();
                swapped.swap(a, b);
                swapped.join("\n")
            },
        ),
    ];
    for (name, mutant) in mutants {
        assert_ne!(mutant, shipped, "the mutant {name} must change the bytes");
        assert!(
            !exec_start_pre_problems(&mutant).is_empty(),
            "the ExecStartPre= check must refuse {name}"
        );
    }
}

/// Paths excluded from TB2's instance-name scan, BY EXACT PATH relative to the
/// crate root: test fixtures may name a concrete instance, shipped artifacts
/// may not. Two of the three live under `packaging/`, which is why the rule is
/// a path list and not a directory convention.
const INSTANCE_NAME_EXCLUSIONS: &[&str] = &[
    "tests/",
    "packaging/ubuntu/test-lifecycle-guard.py",
    "packaging/ubuntu/ci-lifecycle.sh",
];

fn files_under(root: &Path, relative: &str, out: &mut Vec<(String, PathBuf)>) {
    let dir = root.join(relative);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .expect("under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            files_under(root, &rel, out);
        } else {
            out.push((rel, path));
        }
    }
}

/// Byte offsets of `sanctuary-agent@` followed by an ASCII digit.
fn hard_coded_instances(text: &str) -> Vec<usize> {
    let needle = "sanctuary-agent@";
    text.match_indices(needle)
        .filter(|(at, _)| {
            text[at + needle.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn tb2_the_agent_uid_is_derived_from_the_instance_and_never_hard_coded() {
    let triples = directives(&agent_unit_text());
    let value = |key: &str| -> Vec<String> {
        triples
            .iter()
            .filter(|(section, k, _)| section == "Service" && k == key)
            .map(|(_, _, v)| v.clone())
            .collect()
    };
    assert_eq!(value("User"), vec!["%i"], "User= must be the instance");
    assert_eq!(value("Group"), vec!["%i"], "Group= must be the instance");

    let root = crate_root();
    // No shipped unit carries an all-digit User= or Group=: a literal uid
    // bypasses the instance the kernel gate compares against.
    let mut units = Vec::new();
    files_under(&root, "systemd", &mut units);
    for (rel, path) in &units {
        let text = std::fs::read_to_string(path).expect("read unit");
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            for key in ["User=", "Group="] {
                if let Some(v) = line.trim().strip_prefix(key) {
                    assert!(
                        v.is_empty() || !v.chars().all(|c| c.is_ascii_digit()),
                        "{rel}: {key}{v} is an all-digit literal"
                    );
                }
            }
        }
    }

    let mut scanned = Vec::new();
    for dir in ["systemd", "packaging", "src"] {
        files_under(&root, dir, &mut scanned);
    }
    for (rel, path) in scanned {
        if INSTANCE_NAME_EXCLUSIONS
            .iter()
            .any(|ex| rel == *ex || (ex.ends_with('/') && rel.starts_with(ex)))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        assert!(
            hard_coded_instances(&text).is_empty(),
            "{rel} hard-codes an agent unit instance; instances are chosen by the operator"
        );
    }
}

#[test]
fn tb2_literal_identities_and_instance_names_are_refused() {
    let shipped = agent_unit_text();
    for (name, mutant) in [
        ("User=1500", shipped.replace("User=%i\n", "User=1500\n")),
        ("User=root", shipped.replace("User=%i\n", "User=root\n")),
        (
            "Group=sanctuary",
            shipped.replace("Group=%i\n", "Group=sanctuary\n"),
        ),
    ] {
        assert!(
            !directive_set_differences(&mutant).is_empty(),
            "the directive set must refuse {name}"
        );
    }
    assert!(!hard_coded_instances("x sanctuary-agent@1500.service").is_empty());
    assert!(hard_coded_instances("sanctuary-agent@.service sanctuary-agent@<uid>").is_empty());
}
