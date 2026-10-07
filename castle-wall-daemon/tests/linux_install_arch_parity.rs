//! Arch CLI forks stay byte-identical to Ubuntu text after counted seams. ARCH-CLI-PARITY-01.
use std::{fs, path::Path};

#[derive(Clone, Copy)]
struct Seam {
    name: &'static str,
    ubuntu: &'static str,
    arch: &'static str,
    count: usize,
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap()
}

fn apply(mut text: String, seams: &[Seam]) -> Result<String, String> {
    for seam in seams {
        let observed = text.matches(seam.ubuntu).count();
        if observed != seam.count {
            return Err(format!(
                "{} fired {observed} time(s), expected {}",
                seam.name, seam.count
            ));
        }
        text = text.replacen(seam.ubuntu, seam.arch, seam.count);
    }
    Ok(text)
}

fn assert_order(seams: &[Seam], expected: &[&str]) -> Result<(), String> {
    let names: Vec<_> = seams.iter().map(|seam| seam.name).collect();
    if names == expected {
        Ok(())
    } else {
        Err(format!("seam order changed: {names:?}"))
    }
}

fn first_item(text: &str, byte: usize) -> &str {
    let mut current = "file header";
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start_matches("#[");
        if line.starts_with("fn ")
            || line.starts_with("pub fn ")
            || line.starts_with("const ")
            || line.starts_with("pub const ")
            || line.starts_with("static ")
            || line.starts_with("pub static ")
            || line.starts_with("struct ")
            || line.starts_with("pub struct ")
            || line.starts_with("enum ")
            || line.starts_with("pub enum ")
            || line.starts_with("impl ")
            || line.starts_with("use ")
            || line.starts_with("pub use ")
            || line.starts_with("mod ")
            || line.starts_with("type ")
            || trimmed != line
        {
            current = line.trim();
        }
        offset += line.len();
        if offset > byte {
            return current;
        }
    }
    current
}

fn check_order(name: &str, seams: &[Seam]) -> Result<(), String> {
    match name {
        "command" => assert_order(
            seams,
            &[
                "C0", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12",
            ],
        ),
        "account" => assert_order(seams, &["A0a", "A0b", "A1", "A2", "A3", "A4"]),
        "evidence" => assert_order(seams, &["E1"]),
        _ => unreachable!(),
    }
}

fn compare_text(name: &str, ubuntu: String, arch: &str, seams: &[Seam]) -> Result<(), String> {
    check_order(name, seams)?;
    let rendered = apply(ubuntu, seams)?;
    compare_rendered(name, &rendered, arch)
}

fn compare_rendered(name: &str, rendered: &str, arch: &str) -> Result<(), String> {
    if rendered != arch {
        let index = rendered
            .bytes()
            .zip(arch.bytes())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| rendered.len().min(arch.len()));
        return Err(format!("{name} drift near {}", first_item(arch, index)));
    }
    Ok(())
}

fn compare_files(
    name: &str,
    ubuntu_path: &str,
    arch_path: &str,
    seams: &[Seam],
) -> Result<(), String> {
    compare_text(name, read(ubuntu_path), &read(arch_path), seams)
}

fn assert_parity(name: &str, ubuntu_path: &str, arch_path: &str, seams: &[Seam]) {
    compare_files(name, ubuntu_path, arch_path, seams).unwrap_or_else(|error| panic!("{error}"));
}

fn command_seams() -> Vec<Seam> {
    vec![
        Seam {
            name: "C0",
            ubuntu: "pub fn run(args: &[String]) -> Result<Value> {\n    if unsafe { libc::geteuid() } != 0\n",
            arch: "pub fn run(args: &[String]) -> Result<Value> {\n    super::pacman::require_pins()?;\n    if unsafe { libc::geteuid() } != 0\n",
            count: 1,
        },
        Seam {
            name: "C2",
            ubuntu: "/// dpkg selection may record a refused removal while the configured payload remains installed.\npub fn admitted_package_status(status: &[u8], retiring: bool) -> bool {\n    // Retirement remains available after a refused removal; activation still requires install intent.\n    status == b\"install ok installed\"\n        || (retiring\n            && matches!(\n                status,\n                b\"deinstall ok installed\"\n                    | b\"purge ok installed\"\n                    | b\"hold ok installed\"\n                    | b\"unknown ok installed\"\n            ))\n}\n",
            arch: "",
            count: 1,
        },
        Seam {
            name: "C3",
            ubuntu: "fn package(root: &Root) -> Result<()> {\n    package_for(root, false)\n}\n",
            arch: "fn package(root: &Root) -> Result<()> {\n    package_for(root)\n}\n",
            count: 1,
        },
        Seam {
            name: "C4",
            ubuntu: "fn package_for(root: &Root, retiring: bool) -> Result<()> {\n    let installed = checked(\n        \"/usr/bin/dpkg-query\",\n        &[\"--show\", \"--showformat=${Status}\", PACKAGE],\n    )?;\n    if !admitted_package_status(&installed, retiring) {\n        return Err(\"install package is not configured\".into());\n    }\n    let verification = checked(\"/usr/bin/dpkg\", &[\"--verify\", PACKAGE])?;\n    if !verification.is_empty() {\n        return Err(\"package payload differs from installed identity\".into());\n    }\n",
            arch: "fn package_for(root: &Root) -> Result<()> {\n    let mut snapshot = super::pacman::installed(root, PACKAGE)?;\n",
            count: 1,
        },
        Seam {
            name: "C5",
            ubuntu: "    let identity = root.read(BUILD_IDENTITY, RECORD_MAX_BYTES)?;\n    // Must match packaging/ubuntu/build-install-deb.py's install identity, not the internal text manifest.\n    let value: Value = serde_json::from_slice(&identity)?;\n    if value[\"artifact_kind\"] != \"ubuntu-install-deb-v1\"\n        || value[\"install_ready\"] != true\n        || value[\"package\"] != PACKAGE\n        || value[\"target\"] != \"x86_64-unknown-linux-gnu\"\n        || value[\"features\"] != json!([])\n    {\n        return Err(\"install build identity mismatch\".into());\n    }\n",
            arch: "    // Must match packaging/arch/build-arch-package.py's install identity; the compiled pins bind it to this build.\n    let value = super::pacman::verified_identity(root, &mut snapshot)?;\n",
            count: 1,
        },
        Seam {
            name: "C6",
            ubuntu: "        CLI_PATH.to_owned(),\n",
            arch: "        super::pacman::ARCH_CLI_PATH.to_owned(),\n",
            count: 1,
        },
        Seam {
            name: "C7",
            ubuntu: "    for path in [DAEMON_PATH, CLI_PATH, LAUNCHER_PATH, STANDIN_PATH] {\n        verify_elf(root, path)?;\n    }\n    Ok(())\n}\n",
            arch: "    for path in [\n        DAEMON_PATH,\n        super::pacman::ARCH_CLI_PATH,\n        LAUNCHER_PATH,\n        STANDIN_PATH,\n    ] {\n        verify_elf(root, path)?;\n    }\n    super::pacman::recheck(root, &snapshot)\n}\n",
            count: 1,
        },
        Seam {
            name: "C8",
            ubuntu: "fn units(root: &Root, t: &Transaction, retiring: bool) -> Result<()> {\n    package_for(root, retiring)?;\n",
            arch: "fn units(root: &Root, t: &Transaction, _retiring: bool) -> Result<()> {\n    package_for(root)?;\n",
            count: 1,
        },
        Seam {
            name: "C9",
            ubuntu: "        .read(BUILD_IDENTITY, RECORD_MAX_BYTES)\n",
            arch: "        .read(super::pacman::ARCH_BUILD_IDENTITY, RECORD_MAX_BYTES)\n",
            count: 1,
        },
        Seam {
            name: "C10",
            ubuntu: "    let group = account::sanctuary_group_observation();\n",
            arch: "    let group = account::sanctuary_group_observation();\n    let ranges = super::login_defs::read(root).ok();\n",
            count: 1,
        },
        Seam {
            name: "C11",
            ubuntu: "\"enforcement_claim\":\"unproven\"}),\n",
            arch: "\"enforcement_claim\":\"unproven\",\"package_manager\":\"pacman\",\"system_id_ranges\":ranges,\"package_pins\":super::pacman::pins_for_status()}),\n",
            count: 1,
        },
        Seam {
            name: "C12",
            ubuntu: "    account::verify(root, t)?;\n    if !t.policy_complete {\n",
            arch: "    account::verify(root, t)?;\n    account::require_system_gid(root, t)?;\n    if !t.policy_complete {\n",
            count: 1,
        },
    ]
}

fn account_seams() -> Vec<Seam> {
    vec![
        Seam {
            name: "A0a",
            ubuntu: "use serde::{Deserialize, Serialize};\n",
            arch: "",
            count: 1,
        },
        Seam {
            name: "A0b",
            ubuntu: "#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]\npub enum AccountStep {\n    Fresh,\n    SanctuaryIntent,\n    SanctuaryCreated,\n    AgentGroupIntent,\n    AgentGroupCreated,\n    AgentUserIntent,\n    Complete,\n}\n",
            arch: "pub use crate::linux_install::account::AccountStep;\n",
            count: 1,
        },
        Seam {
            name: "A1",
            ubuntu: "const SYSTEM_GID_FIRST: u32 = 100; // Ubuntu's dynamically allocated system group range.\nconst SYSTEM_GID_LAST: u32 = 999;\n",
            arch: "",
            count: 1,
        },
        Seam {
            name: "A2",
            ubuntu: "                let gid = (SYSTEM_GID_FIRST..=SYSTEM_GID_LAST)\n",
            arch: "                let ranges = super::login_defs::read(root)?;\n                let gid = (ranges.sys_gid_min..=ranges.sys_gid_max)\n",
            count: 1,
        },
        Seam {
            name: "A3",
            ubuntu: "                Nss::read()?.exact(root, \"group\", &group(\"sanctuary\", gid))?;\n",
            arch: "                Nss::read()?.exact(root, \"group\", &group(\"sanctuary\", gid))?;\n                require_system_gid(root, t)?;\n",
            count: 1,
        },
        Seam {
            name: "A4",
            ubuntu: "/// An observed group, distinct from whether the complete configured identity still agrees.\n",
            arch: "/// The sanctuary gid, created or recorded, must sit inside the system range login.defs states.\npub fn require_system_gid(root: &Root, t: &Transaction) -> Result<()> {\n    let ranges = super::login_defs::read(root)?;\n    let gid = t.sanctuary_gid.ok_or(\"missing sanctuary gid\")?;\n    // groupadd honors an explicit --gid outside SYS_GID_MIN..=SYS_GID_MAX; the range is enforced here, not assumed from the search.\n    if !(ranges.sys_gid_min..=ranges.sys_gid_max).contains(&gid) {\n        return Err(\"sanctuary gid outside the system range\".into());\n    }\n    Ok(())\n}\n\n/// An observed group, distinct from whether the complete configured identity still agrees.\n",
            count: 1,
        },
    ]
}

fn evidence_seams() -> Vec<Seam> {
    vec![Seam {
        name: "E1",
        ubuntu: "        (command::BUILD_IDENTITY.into(), \"build-identity\"),\n",
        arch: "        (super::pacman::ARCH_BUILD_IDENTITY.into(), \"build-identity\"),\n",
        count: 1,
    }]
}

#[test]
fn forks_match_ubuntu_after_nineteen_counted_seams() {
    assert_parity(
        "command",
        "src/linux_install/command.rs",
        "src/linux_install/arch/command.rs",
        &command_seams(),
    );
    assert_parity(
        "account",
        "src/linux_install/account.rs",
        "src/linux_install/arch/account.rs",
        &account_seams(),
    );
    assert_parity(
        "evidence",
        "src/linux_install/evidence.rs",
        "src/linux_install/arch/evidence.rs",
        &evidence_seams(),
    );
}

#[test]
fn parity_negative_controls_fail_on_drift_removed_seam_and_reorder() {
    let command = read("src/linux_install/command.rs");
    let seams = command_seams();
    let rendered = apply(command.clone(), &seams).unwrap();
    let drift = rendered.replacen("pub fn run", "pub fn run_drift", 1);
    let drift_error = compare_text("command", command.clone(), &drift, &seams).unwrap_err();
    assert!(drift_error.contains("command drift near pub fn run_drift"));
    let without = &seams[..seams.len() - 1];
    let removed = apply(command.clone(), without).unwrap();
    let removed_error = compare_rendered(
        "command",
        &removed,
        &read("src/linux_install/arch/command.rs"),
    )
    .unwrap_err();
    assert!(removed_error.contains("command drift near"));
    let order_sensitive = [
        Seam {
            name: "R1",
            ubuntu: "aa",
            arch: "a",
            count: 1,
        },
        Seam {
            name: "R2",
            ubuntu: "a",
            arch: "b",
            count: 1,
        },
    ];
    assert_eq!(apply("aa".to_owned(), &order_sensitive).unwrap(), "b");
    let reordered = [order_sensitive[1], order_sensitive[0]];
    assert!(apply("aa".to_owned(), &reordered)
        .unwrap_err()
        .contains("R2 fired 2 time(s), expected 1"));
    assert!(apply(
        "once".to_owned(),
        &[Seam {
            name: "COUNT",
            ubuntu: "once",
            arch: "twice",
            count: 2,
        }]
    )
    .unwrap_err()
    .contains("COUNT fired 1 time(s), expected 2"));
    assert_eq!(apply(command, &seams).unwrap(), rendered);
}
