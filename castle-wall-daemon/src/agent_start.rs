//! The agent template unit's start-time checks (slice B).
//!
//! `systemd/sanctuary-agent@.service` starts one agent per uid; its instance
//! name is the uid. Before `ExecStart=` it runs two read-only verbs of this
//! daemon binary, in this order:
//!
//! 1. `--agent-credential-check <uid>`, as the instance uid: the process's own
//!    kernel credentials must be exactly the instance's.
//! 2. `--agent-start-gate <uid> --fortress-id <id> --trusted-service-uid <uid>`,
//!    as root: the live owned table must bind exactly that uid, and the uid
//!    must not be the wall's trusted control uid.
//!
//! Register id: `defect.linux-no-agent-launcher-assigns-or-drops-to-the-agent-uid`.

/// The kernel gate's verb flag. Must match the second `ExecStartPre=` of
/// `systemd/sanctuary-agent@.service` and `value_options` in `src/main.rs`.
pub const AGENT_START_GATE_FLAG: &str = "--agent-start-gate";
/// The credential self-check's verb flag. Must match the first
/// `ExecStartPre=` of `systemd/sanctuary-agent@.service` and `value_options`
/// in `src/main.rs`.
pub const AGENT_CREDENTIAL_CHECK_FLAG: &str = "--agent-credential-check";
/// Both verb flags take a value (the instance uid). `value_options` in
/// `src/main.rs` must contain both, or a later structural scan could read a
/// uid as a flag; TB6 pins that parity over the whole set.
pub const AGENT_VERB_VALUE_FLAGS: [&str; 2] = [AGENT_START_GATE_FLAG, AGENT_CREDENTIAL_CHECK_FLAG];

/// Exit status for `Admit` / `Match`.
pub const EXIT_ADMIT: u8 = 0;
/// Exit status for every named refusal.
pub const EXIT_REFUSED: u8 = 1;
/// Exit status for an argv that is not exactly one verb shape: `EX_USAGE`
/// (64) from sysexits.h, so a usage error can never read as a refusal.
pub const EXIT_USAGE: u8 = 64;

/// The largest uid an instance may name: `u32::MAX` is `(uid_t)-1`, which the
/// kernel's credential calls treat as "leave unchanged", so it is never a uid.
const MAX_INSTANCE_UID: u32 = u32::MAX - 1;
/// Digits in `MAX_INSTANCE_UID` (4294967294): the canonical grammar
/// `^[1-9][0-9]{0,9}$` allows at most ten.
const MAX_INSTANCE_UID_DIGITS: usize = 10;

/// Whether `args` names either agent verb ANYWHERE. When it does the process
/// is in verb mode and never reaches the daemon's other structural scans
/// (`--preflight-manifest`, `--disarm`), the run-config parser or the stop
/// guard: a smuggled `--disarm` beside a verb must never delete the owned
/// table.
pub fn argv_names_an_agent_verb(args: &[String]) -> bool {
    args.iter()
        .any(|arg| AGENT_VERB_VALUE_FLAGS.contains(&arg.as_str()))
}

/// The two exact argv shapes, positionally matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentVerbArgv<'a> {
    /// `--agent-start-gate <uid> --fortress-id <id> --trusted-service-uid <uid>`.
    StartGate {
        uid: &'a str,
        fortress_id: &'a str,
        trusted_service_uid: &'a str,
    },
    /// `--agent-credential-check <uid>`.
    CredentialCheck { uid: &'a str },
}

/// Match `args` against exactly one verb shape. Anything else (either flag
/// twice, both verbs, a missing value, any extra token such as `--disarm`) is
/// a usage error, exit 64, and nothing is touched.
pub fn parse_agent_verb_argv(args: &[String]) -> Result<AgentVerbArgv<'_>, String> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match argv.as_slice() {
        [AGENT_START_GATE_FLAG, uid, "--fortress-id", fortress_id, "--trusted-service-uid", trusted_service_uid] => {
            Ok(AgentVerbArgv::StartGate {
                uid,
                fortress_id,
                trusted_service_uid,
            })
        }
        [AGENT_CREDENTIAL_CHECK_FLAG, uid] => Ok(AgentVerbArgv::CredentialCheck { uid }),
        _ => Err(format!(
            "expected exactly `{AGENT_START_GATE_FLAG} <uid> --fortress-id <id> \
             --trusted-service-uid <uid>` or `{AGENT_CREDENTIAL_CHECK_FLAG} <uid>`, got {} \
             argument(s)",
            argv.len()
        )),
    }
}

/// The instance uid, canonical decimal only: `^[1-9][0-9]{0,9}$` with a value
/// in `1..=u32::MAX - 1`. No sign, no leading zero, no whitespace, no
/// non-ASCII digit, so one uid has exactly one accepted spelling and the value
/// the gate compares is the value systemd applied as `User=`.
pub fn parse_instance_uid(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    let canonical = !bytes.is_empty()
        && bytes.len() <= MAX_INSTANCE_UID_DIGITS
        && bytes[0] != b'0'
        && bytes.iter().all(u8::is_ascii_digit);
    if !canonical {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| (1..=u64::from(MAX_INSTANCE_UID)).contains(value))
        .and_then(|value| u32::try_from(value).ok())
}

/// The kernel gate's named verdicts. `token()` is the stderr contract the
/// integration tests and host legs read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStartVerdict {
    Admit,
    RefuseArgv(String),
    RefuseTrustedUidCollision,
    RefuseTableUnreadable(String),
    RefuseNotOwnedShape(String),
    RefuseBindingSet(String),
}

impl AgentStartVerdict {
    pub fn token(&self) -> &'static str {
        match self {
            Self::Admit => "Admit",
            Self::RefuseArgv(_) => "RefuseArgv",
            Self::RefuseTrustedUidCollision => "RefuseTrustedUidCollision",
            Self::RefuseTableUnreadable(_) => "RefuseTableUnreadable",
            Self::RefuseNotOwnedShape(_) => "RefuseNotOwnedShape",
            Self::RefuseBindingSet(_) => "RefuseBindingSet",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Admit => "",
            Self::RefuseTrustedUidCollision => "the instance uid is the wall's trusted service uid",
            Self::RefuseArgv(d)
            | Self::RefuseTableUnreadable(d)
            | Self::RefuseNotOwnedShape(d)
            | Self::RefuseBindingSet(d) => d,
        }
    }
}

/// The kernel gate over injected inputs: argv values plus one listing call.
/// Named states, in order: `ARGV` (both uids canonical, fortress id in the
/// wall's grammar), `COLLISION` (before any listing), `TABLE_READ` (exactly
/// one call to `list_owned_table`), `SET_RULE`.
///
/// `list_owned_table` is called at most once and never on an argv or collision
/// refusal; TB5 pins that with a recording stub.
#[cfg(any(target_os = "linux", test))]
pub fn start_gate_verdict_with(
    uid_arg: &str,
    fortress_id: &str,
    trusted_service_uid_arg: &str,
    list_owned_table: &mut dyn FnMut() -> Result<String, String>,
) -> AgentStartVerdict {
    // state ARGV
    let Some(uid) = parse_instance_uid(uid_arg) else {
        return AgentStartVerdict::RefuseArgv(format!("instance uid {uid_arg:?} is not canonical"));
    };
    let Some(trusted_service_uid) = parse_instance_uid(trusted_service_uid_arg) else {
        return AgentStartVerdict::RefuseArgv(format!(
            "trusted service uid {trusted_service_uid_arg:?} is not canonical"
        ));
    };
    if let Err(err) = crate::config::validate_fortress_id(fortress_id) {
        return AgentStartVerdict::RefuseArgv(err);
    }
    // state COLLISION. The wall's IPC treats this kernel uid as its sole
    // control principal (see the peer-uid check in `src/ipc/server.rs`); an
    // agent must never run as it, whatever the manifest admitted. Checked
    // before the listing, so the refusal needs no kernel read.
    if uid == trusted_service_uid {
        return AgentStartVerdict::RefuseTrustedUidCollision;
    }
    // state TABLE_READ: one bounded call; an absent table is unreadable.
    let json = match list_owned_table() {
        Ok(json) => json,
        Err(err) => return AgentStartVerdict::RefuseTableUnreadable(err),
    };
    // state SET_RULE
    match crate::nftables::agent_start_gate_verdict(&json, fortress_id, uid) {
        crate::nftables::AgentStartTableVerdict::Admit => AgentStartVerdict::Admit,
        crate::nftables::AgentStartTableVerdict::RefuseNotOwnedShape(d) => {
            AgentStartVerdict::RefuseNotOwnedShape(d)
        }
        crate::nftables::AgentStartTableVerdict::RefuseBindingSet(d) => {
            AgentStartVerdict::RefuseBindingSet(d)
        }
    }
}

/// The kernel gate against the live owned table.
///
/// DEBT(LINUX-AGENT-OFF-UNIT-LAUNCH-01): this gate runs only for starts of the
/// agent unit. A process of the agent uid launched any other way is confined by
/// the kernel binding while the owned table exists, but is never start-gated
/// and is not stopped with the wall.
fn start_gate_verdict(
    uid: &str,
    fortress_id: &str,
    trusted_service_uid: &str,
) -> AgentStartVerdict {
    #[cfg(target_os = "linux")]
    {
        start_gate_verdict_with(uid, fortress_id, trusted_service_uid, &mut || {
            crate::nftables::list_owned_castle_table_json_for_binding_set()
                .map_err(|err| err.to_string())
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fail closed: there is no owned table to read on this platform.
        let _ = (uid, fortress_id, trusted_service_uid);
        AgentStartVerdict::RefuseTableUnreadable("not available on this platform".to_string())
    }
}

/// The credential self-check's named verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVerdict {
    Match,
    RefuseArgv(String),
    RefuseUid,
    RefuseGid,
    RefuseGroups,
    RefuseCapabilities,
    RefuseNoNewPrivs,
    RefuseStatusUnreadable(String),
}

impl CredentialVerdict {
    pub fn token(&self) -> &'static str {
        match self {
            Self::Match => "Match",
            Self::RefuseArgv(_) => "RefuseArgv",
            Self::RefuseUid => "RefuseUid",
            Self::RefuseGid => "RefuseGid",
            Self::RefuseGroups => "RefuseGroups",
            Self::RefuseCapabilities => "RefuseCapabilities",
            Self::RefuseNoNewPrivs => "RefuseNoNewPrivs",
            Self::RefuseStatusUnreadable(_) => "RefuseStatusUnreadable",
        }
    }
}

/// The capability and no-new-privileges fields of `/proc/self/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCredentials {
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_amb: u64,
    pub cap_bnd: u64,
    pub no_new_privs: u8,
}

/// What the kernel says this process is: real, effective and saved uid and
/// gid, the supplementary groups, and the parsed status fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSnapshot {
    pub uids: [u32; 3],
    pub gids: [u32; 3],
    pub groups: Vec<u32>,
    pub status: Result<StatusCredentials, String>,
}

/// Hex digits in a 64-bit capability mask as `/proc/<pid>/status` prints it.
const CAP_MASK_HEX_DIGITS: usize = 16;

/// Parse the five fields the self-check needs. Each must appear exactly once;
/// a duplicate, a missing field or a malformed value refuses, because a
/// status the parser cannot read completely proves nothing.
pub fn parse_status_credentials(text: &str) -> Result<StatusCredentials, String> {
    let mut fields: [Option<u64>; 5] = [None; 5];
    const NAMES: [&str; 5] = ["CapPrm", "CapEff", "CapAmb", "CapBnd", "NoNewPrivs"];
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(index) = NAMES.iter().position(|name| *name == key) else {
            continue;
        };
        if fields[index].is_some() {
            return Err(format!("duplicate {key} field"));
        }
        let value = value.trim();
        let parsed = if key == "NoNewPrivs" {
            match value {
                "0" => Some(0),
                "1" => Some(1),
                _ => None,
            }
        } else if !value.is_empty()
            && value.len() <= CAP_MASK_HEX_DIGITS
            && value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            u64::from_str_radix(value, 16).ok()
        } else {
            None
        };
        fields[index] = Some(parsed.ok_or_else(|| format!("malformed {key} value {value:?}"))?);
    }
    let get = |index: usize| fields[index].ok_or_else(|| format!("missing {} field", NAMES[index]));
    Ok(StatusCredentials {
        cap_prm: get(0)?,
        cap_eff: get(1)?,
        cap_amb: get(2)?,
        cap_bnd: get(3)?,
        no_new_privs: u8::try_from(get(4)?).map_err(|_| "NoNewPrivs out of range".to_string())?,
    })
}

/// The credential verdict for instance `uid`, first failing atom named.
///
/// These are the credentials the kernel will apply to the agent's sockets; a
/// drop-in that changes the unit's identity without deleting this check cannot
/// reach `ExecStart`. `uid` and `gid` equal to the instance imply both nonzero,
/// because `parse_instance_uid` refuses 0.
pub fn credential_verdict(uid: u32, snapshot: &CredentialSnapshot) -> CredentialVerdict {
    // Saved ids are checked too: a process whose saved uid differs can switch
    // back to it without any privilege.
    if snapshot.uids != [uid; 3] {
        return CredentialVerdict::RefuseUid;
    }
    if snapshot.gids != [uid; 3] {
        return CredentialVerdict::RefuseGid;
    }
    // A subset of {uid}: an extra group (for example `sanctuary`, which reaches
    // the wall's control socket directory) refuses.
    if snapshot.groups.iter().any(|group| *group != uid) {
        return CredentialVerdict::RefuseGroups;
    }
    let status = match &snapshot.status {
        Ok(status) => status,
        Err(err) => return CredentialVerdict::RefuseStatusUnreadable(err.clone()),
    };
    // All four sets, including ambient and bounding: an ambient capability
    // survives execve, and a nonempty bounding set is what a later setuid
    // binary could draw from.
    if status.cap_prm != 0 || status.cap_eff != 0 || status.cap_amb != 0 || status.cap_bnd != 0 {
        return CredentialVerdict::RefuseCapabilities;
    }
    if status.no_new_privs != 1 {
        return CredentialVerdict::RefuseNoNewPrivs;
    }
    CredentialVerdict::Match
}

/// Upper bound on the bytes read from `/proc/self/status`: a Linux 6.x status
/// file is under 2 KiB, so 16 KiB (1024 * 16) is eight times that; anything
/// larger is refused as malformed rather than read without bound.
#[cfg(target_os = "linux")]
const MAX_PROC_STATUS_BYTES: u64 = 16 * 1024;

#[cfg(target_os = "linux")]
fn read_snapshot() -> CredentialSnapshot {
    use std::io::Read;
    let res_uid = nix::unistd::getresuid();
    let res_gid = nix::unistd::getresgid();
    let groups = nix::unistd::getgroups();
    let status = std::fs::File::open("/proc/self/status")
        .map_err(|e| format!("open /proc/self/status: {e}"))
        .and_then(|file| {
            let mut text = String::new();
            file.take(MAX_PROC_STATUS_BYTES + 1)
                .read_to_string(&mut text)
                .map_err(|e| format!("read /proc/self/status: {e}"))?;
            if text.len() as u64 > MAX_PROC_STATUS_BYTES {
                return Err("/proc/self/status exceeds its bound".to_string());
            }
            parse_status_credentials(&text)
        });
    // A failed id or group read leaves an impossible snapshot (u32::MAX is
    // never an instance uid), so it refuses at the first atom.
    let unreadable = [u32::MAX; 3];
    CredentialSnapshot {
        uids: res_uid
            .map(|r| [r.real.as_raw(), r.effective.as_raw(), r.saved.as_raw()])
            .unwrap_or(unreadable),
        gids: res_gid
            .map(|r| [r.real.as_raw(), r.effective.as_raw(), r.saved.as_raw()])
            .unwrap_or(unreadable),
        groups: groups
            .map(|g| g.into_iter().map(|gid| gid.as_raw()).collect())
            .unwrap_or_else(|_| vec![u32::MAX]),
        status,
    }
}

fn credential_check(uid_arg: &str) -> CredentialVerdict {
    let Some(uid) = parse_instance_uid(uid_arg) else {
        return CredentialVerdict::RefuseArgv(format!("instance uid {uid_arg:?} is not canonical"));
    };
    #[cfg(target_os = "linux")]
    {
        credential_verdict(uid, &read_snapshot())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = uid;
        CredentialVerdict::RefuseStatusUnreadable("not available on this platform".to_string())
    }
}

/// Run whichever agent verb `args` names and return the process exit status.
/// Every path returns here; nothing else in `main` runs in verb mode.
pub fn run_agent_verb(args: &[String]) -> u8 {
    match parse_agent_verb_argv(args) {
        Err(usage) => {
            // SAFETY: stderr is the CLI usage-error contract of the agent verbs;
            // exit 64 beside it keeps a usage error distinct from a refusal.
            eprintln!("castle-wall-daemon: agent verb usage error: {usage}");
            EXIT_USAGE
        }
        Ok(AgentVerbArgv::StartGate {
            uid,
            fortress_id,
            trusted_service_uid,
        }) => match start_gate_verdict(uid, fortress_id, trusted_service_uid) {
            AgentStartVerdict::Admit => {
                // SAFETY: stdout is the agent start gate's admit contract: this
                // exact line lands in the agent unit's journal and the host legs
                // read it. `uid` is canonical decimal here (the gate admitted it).
                println!("castle-wall-daemon: agent_start_gate=admit uid={uid}");
                EXIT_ADMIT
            }
            refusal => {
                // SAFETY: stderr is the agent start gate's refusal contract: one
                // line naming the verdict token, beside exit 1.
                eprintln!(
                    "castle-wall-daemon: agent_start_gate=refuse verdict={} uid={uid:?} detail={}",
                    refusal.token(),
                    refusal.detail()
                );
                EXIT_REFUSED
            }
        },
        Ok(AgentVerbArgv::CredentialCheck { uid }) => match credential_check(uid) {
            CredentialVerdict::Match => {
                // SAFETY: stdout is the credential self-check's match contract;
                // `uid` is canonical decimal here (it matched).
                println!("castle-wall-daemon: agent_credential_check=match uid={uid}");
                EXIT_ADMIT
            }
            refusal => {
                // SAFETY: stderr is the credential self-check's refusal contract:
                // one line naming the first failing atom, beside exit 1.
                eprintln!(
                    "castle-wall-daemon: agent_credential_check=refuse verdict={} uid={uid:?} \
                     detail={refusal:?}",
                    refusal.token()
                );
                EXIT_REFUSED
            }
        },
    }
}

#[cfg(test)]
mod tests {
    //! Capability under test: the agent unit's two start-time checks refuse
    //! every start except the instance uid the wall bound, under exactly that
    //! uid's credentials. Register ids:
    //! `defect.linux-no-agent-launcher-assigns-or-drops-to-the-agent-uid`,
    //! `LINUX-AGENT-TRUSTED-UID-COLLISION-01`.
    use super::*;
    use crate::source_scan::{
        daemon_sources, enclosing_fn, fn_body, offsets_of, production_part, without_comment_lines,
    };

    /// A canonical instance uid used by the argv and credential fixtures.
    const U: u32 = 60123;
    /// A fixture fortress id in the wall's grammar (8 lowercase hex).
    const FORTRESS: &str = "deadbeef";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn production_source(rel: &str) -> String {
        let (_, text) = crate::source_scan::rust_files_under("src")
            .into_iter()
            .find(|(path, _)| path == rel)
            .unwrap_or_else(|| panic!("{rel} must exist"));
        without_comment_lines(&production_part(&text))
    }

    // ---- TB5: the collision refusal precedes the table read ---------------

    #[test]
    fn tb5_a_trusted_uid_collision_or_bad_argv_refuses_before_any_table_read() {
        for (uid, fortress, trusted, token) in [
            ("60123", FORTRESS, "60123", "RefuseTrustedUidCollision"),
            ("0", FORTRESS, "60124", "RefuseArgv"),
            ("60123", FORTRESS, "01", "RefuseArgv"),
            ("60123", "DEADBEEF", "60124", "RefuseArgv"),
            ("60123", "short", "60124", "RefuseArgv"),
        ] {
            let mut calls = 0;
            let verdict = start_gate_verdict_with(uid, fortress, trusted, &mut || {
                calls += 1;
                Ok(String::new())
            });
            assert_eq!(verdict.token(), token, "{uid}/{fortress}/{trusted}");
            assert_eq!(calls, 0, "{token} must be decided before the nft read");
        }
    }

    #[test]
    fn tb5_the_gate_reads_the_table_once_and_maps_an_unreadable_table() {
        let mut calls = 0;
        let verdict = start_gate_verdict_with("60123", FORTRESS, "60124", &mut || {
            calls += 1;
            Err("no such table".to_string())
        });
        assert_eq!(verdict.token(), "RefuseTableUnreadable");
        assert_eq!(calls, 1);
    }

    // ---- TB6: argv shapes and the canonical uid grammar -------------------

    #[test]
    fn tb6_parse_instance_uid_accepts_only_canonical_decimal_in_range() {
        assert_eq!(parse_instance_uid("1"), Some(1));
        assert_eq!(parse_instance_uid("60123"), Some(60123));
        assert_eq!(parse_instance_uid("4294967294"), Some(u32::MAX - 1));
        for bad in [
            "0",
            "01500",
            "+1500",
            "-1500",
            "1500 ",
            " 1500",
            "",
            "4294967295",
            "4294967296",
            "99999999999",
            "\u{0661}\u{0665}",
            "15\u{0660}0",
            "0x10",
        ] {
            assert_eq!(parse_instance_uid(bad), None, "{bad:?} must refuse");
        }
    }

    #[test]
    fn tb6_only_the_two_exact_argv_shapes_parse_and_every_smuggle_is_usage() {
        assert_eq!(
            parse_agent_verb_argv(&args(&[
                "--agent-start-gate",
                "60123",
                "--fortress-id",
                FORTRESS,
                "--trusted-service-uid",
                "60124"
            ])),
            Ok(AgentVerbArgv::StartGate {
                uid: "60123",
                fortress_id: FORTRESS,
                trusted_service_uid: "60124"
            })
        );
        assert_eq!(
            parse_agent_verb_argv(&args(&["--agent-credential-check", "60123"])),
            Ok(AgentVerbArgv::CredentialCheck { uid: "60123" })
        );
        for smuggle in [
            vec!["--agent-start-gate", "1500", "--disarm"],
            vec!["--disarm", "--agent-credential-check", "1500"],
            vec!["--agent-credential-check", "1500", "--disarm"],
            vec![
                "--agent-credential-check",
                "1500",
                "--agent-start-gate",
                "1500",
            ],
            vec![
                "--agent-credential-check",
                "1500",
                "--agent-credential-check",
                "1500",
            ],
            vec!["--agent-credential-check"],
            vec![
                "--agent-start-gate",
                "1500",
                "--fortress-id",
                FORTRESS,
                "--trusted-service-uid",
                "60124",
                "--disarm",
            ],
            vec![
                "--agent-start-gate",
                "1500",
                "--trusted-service-uid",
                "60124",
                "--fortress-id",
                FORTRESS,
            ],
            vec![
                "--fortress-id",
                FORTRESS,
                "--agent-credential-check",
                "1500",
            ],
        ] {
            let argv = args(&smuggle);
            assert!(argv_names_an_agent_verb(&argv), "{smuggle:?} is verb mode");
            assert!(
                parse_agent_verb_argv(&argv).is_err(),
                "{smuggle:?} must be usage"
            );
            assert_eq!(
                run_agent_verb(&argv),
                EXIT_USAGE,
                "{smuggle:?} must exit 64"
            );
        }
    }

    // ---- TB7: the credential verdict and the status parser ----------------

    fn matching_snapshot() -> CredentialSnapshot {
        CredentialSnapshot {
            uids: [U; 3],
            gids: [U; 3],
            groups: vec![U],
            status: Ok(StatusCredentials {
                cap_prm: 0,
                cap_eff: 0,
                cap_amb: 0,
                cap_bnd: 0,
                no_new_privs: 1,
            }),
        }
    }

    #[test]
    fn tb7_the_credential_verdict_matches_only_the_exact_instance_credentials() {
        assert_eq!(
            credential_verdict(U, &matching_snapshot()),
            CredentialVerdict::Match
        );
        let mut empty_groups = matching_snapshot();
        empty_groups.groups.clear();
        assert_eq!(
            credential_verdict(U, &empty_groups),
            CredentialVerdict::Match
        );

        let with = |edit: &dyn Fn(&mut CredentialSnapshot)| {
            let mut snapshot = matching_snapshot();
            edit(&mut snapshot);
            credential_verdict(U, &snapshot).token()
        };
        let status = |edit: &dyn Fn(&mut StatusCredentials)| {
            with(&|s: &mut CredentialSnapshot| {
                let mut st = s.status.clone().unwrap();
                edit(&mut st);
                s.status = Ok(st);
            })
        };
        // Kills a geteuid-only check.
        assert_eq!(with(&|s| s.uids[2] = U + 1), "RefuseUid");
        assert_eq!(with(&|s| s.uids[0] = U + 1), "RefuseUid");
        assert_eq!(with(&|s| s.gids[1] = U + 1), "RefuseGid");
        assert_eq!(with(&|s| s.gids[2] = U + 1), "RefuseGid");
        // Kills groups-as-superset.
        assert_eq!(with(&|s| s.groups.push(U + 1)), "RefuseGroups");
        // Kills ignoring CapAmb or CapBnd.
        assert_eq!(status(&|st| st.cap_amb = 1 << 12), "RefuseCapabilities");
        assert_eq!(status(&|st| st.cap_bnd = 1), "RefuseCapabilities");
        assert_eq!(status(&|st| st.cap_eff = 1), "RefuseCapabilities");
        assert_eq!(status(&|st| st.cap_prm = 1), "RefuseCapabilities");
        assert_eq!(status(&|st| st.no_new_privs = 0), "RefuseNoNewPrivs");
        assert_eq!(
            with(&|s| s.status = Err("x".to_string())),
            "RefuseStatusUnreadable"
        );
        // Root (the `+` mutant of the check) is never the instance.
        assert_eq!(
            credential_verdict(
                U,
                &CredentialSnapshot {
                    uids: [0; 3],
                    ..matching_snapshot()
                }
            ),
            CredentialVerdict::RefuseUid
        );
    }

    const STATUS_OK: &str = "Name:\tcastle-wall-daem\nUid:\t60123\t60123\t60123\t60123\n\
        CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
        CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n";

    #[test]
    fn tb7_the_status_parser_reads_each_field_exactly_once() {
        assert_eq!(
            parse_status_credentials(STATUS_OK),
            Ok(StatusCredentials {
                cap_prm: 0,
                cap_eff: 0,
                cap_amb: 0,
                cap_bnd: 0,
                no_new_privs: 1
            })
        );
        let root = STATUS_OK.replace("CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff");
        assert_eq!(
            parse_status_credentials(&root).unwrap().cap_bnd,
            0x1ff_ffff_ffff
        );
        for (name, bad) in [
            (
                "duplicate CapEff",
                format!("{STATUS_OK}CapEff:\t0000000000000000\n"),
            ),
            (
                "duplicate NoNewPrivs",
                format!("{STATUS_OK}NoNewPrivs:\t1\n"),
            ),
            (
                "missing CapAmb",
                STATUS_OK.replace("CapAmb:\t0000000000000000\n", ""),
            ),
            (
                "non-hex CapPrm",
                STATUS_OK.replace("CapPrm:\t0000000000000000", "CapPrm:\tzz"),
            ),
            (
                "overlong CapEff",
                STATUS_OK.replace("CapEff:\t0000000000000000", "CapEff:\t00000000000000000"),
            ),
            (
                "empty CapBnd",
                STATUS_OK.replace("CapBnd:\t0000000000000000", "CapBnd:\t"),
            ),
            (
                "NoNewPrivs 2",
                STATUS_OK.replace("NoNewPrivs:\t1", "NoNewPrivs:\t2"),
            ),
        ] {
            assert!(
                parse_status_credentials(&bad).is_err(),
                "{name} must refuse"
            );
        }
    }

    // ---- TB5s: one set rule, one argv-fed Confined site -------------------

    #[test]
    fn tb5s_the_set_rule_has_one_implementation_and_confined_has_two_provenances() {
        let nft = production_source("src/nftables.rs");
        let calls: Vec<String> = offsets_of(&nft, "binding_set_rule(")
            .into_iter()
            .filter(|at| !nft[..*at].ends_with("fn "))
            .map(|at| enclosing_fn(&nft, at))
            .collect();
        let mut calls_sorted = calls.clone();
        calls_sorted.sort();
        assert_eq!(
            calls_sorted,
            vec![
                "agent_start_gate_verdict",
                "owned_table_binding_set_from_json"
            ],
            "binding_set_rule must be called from exactly the wall's set rule and the gate"
        );
        assert_eq!(offsets_of(&nft, "fn binding_set_rule(").len(), 1);
        for consumer in [
            "owned_table_binding_set_from_json",
            "agent_start_gate_verdict",
        ] {
            assert!(
                !fn_body(&nft, consumer).contains("confined_agent_id("),
                "{consumer} must not carry its own expected-set equality"
            );
        }
        assert!(
            !production_source("src/agent_start.rs").contains("run_nft("),
            "the gate verb must make no nft call of its own"
        );

        // Every production CONSTRUCTION (a braced body with a field
        // initializer) of the trusted expectation, by enclosing function.
        let mut sites = Vec::new();
        for (path, text) in daemon_sources() {
            let code = without_comment_lines(&production_part(&text));
            for needle in ["ExpectedAgentBinding::Confined {", "Self::Confined {"] {
                if needle.starts_with("Self") && path != "src/nftables.rs" {
                    continue;
                }
                for at in offsets_of(&code, needle) {
                    let open = at + needle.len() - 1;
                    let close = open + code[open..].find('}').expect("closed");
                    let fields = code[open + 1..close].replace("::", "");
                    if fields.contains(':') {
                        sites.push(format!("{path}::{}", enclosing_fn(&code, at)));
                    }
                }
            }
        }
        sites.sort();
        assert_eq!(
            sites,
            vec![
                "src/nftables.rs::agent_start_gate_verdict".to_string(),
                "src/runtime_providers.rs::current_expected_agent_binding".to_string(),
            ],
            "Confined is built only from the frozen armed identity and, from argv, only \
             in the gate"
        );

        let raw = crate::source_scan::rust_files_under("src")
            .into_iter()
            .find(|(p, _)| p == "src/nftables.rs")
            .unwrap()
            .1;
        assert!(raw.contains("(b) the agent unit's instance uid, for the agent start gate ONLY"));
        assert!(raw.contains(
            "the frozen\n/// manifest uid in the daemon, the unit instance in the agent start gate"
        ));
    }

    // ---- TB7s: imports, ordering, pins and the single fortress grammar ----

    #[test]
    fn tb7s_the_verbs_import_no_stateful_module_and_route_before_every_other_scan() {
        let verbs = production_source("src/agent_start.rs");
        for module in [
            "runtime_lock",
            "ownership_journal",
            "audit",
            "protected_agent",
            "manifest",
            "ipc",
            "decision",
        ] {
            for prefix in ["crate::", "super::", "castle_wall_daemon::"] {
                assert!(
                    !verbs.contains(&format!("{prefix}{module}")),
                    "the agent verbs must not reach {module} (a lock or a journal write would \
                     contend with the live wall)"
                );
            }
        }

        let main = production_source("src/main.rs");
        let route = fn_body(&main, "pre_parser_route");
        let verb = route.find("argv_names_an_agent_verb").expect("verb test");
        let preflight = route
            .find("\"--preflight-manifest\"")
            .expect("preflight scan");
        let disarm = route.find("\"--disarm\"").expect("disarm scan");
        assert!(
            verb < preflight && preflight < disarm,
            "verb mode must be routed first"
        );
        let body = fn_body(&main, "run_daemon_main");
        let strip = body
            .find("\"--isolated-castle-table-tag\"")
            .expect("isolation strip");
        let routed = body.find("run_pre_parser_route(").expect("route call");
        let parser = body
            .find("DaemonConfig::from_argv")
            .expect("run-config parser");
        // Built with concat! so this test is not itself a call site of the
        // guard (exit_guard's structure test counts call syntax).
        let guard = body
            .find(concat!("enable_process", "_guard("))
            .expect("stop guard");
        assert!(strip < routed && routed < parser && routed < guard);
        assert!(
            body.contains("if let Some(code) = run_pre_parser_route("),
            "a routed verb must return from run_daemon_main"
        );
        let run = fn_body(&main, "run_pre_parser_route");
        assert!(run.contains("PreParserRoute::AgentVerb => Some("));
    }

    #[test]
    fn tb7s_the_executable_and_environment_pins_hold_on_both_sides() {
        let unit = include_str!("../systemd/sanctuary-agent@.service");
        let wall = include_str!("../systemd/sanctuary-castle-wall.service");
        assert!(unit.contains("Must match EXECUTABLE_PATH in src/protected_agent/profile.rs"));
        let profile = include_str!("protected_agent/profile.rs");
        assert!(
            profile.contains("Must match `ExecStart=` in\n/// `systemd/sanctuary-agent@.service`")
        );
        let env = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|l| l.starts_with("EnvironmentFile="))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(
            env(unit),
            env(wall),
            "the agent unit reads the wall's env file"
        );
        assert_eq!(env(unit).len(), 1);
    }

    #[test]
    fn tb7s_validate_fortress_id_is_the_single_fortress_id_grammar() {
        let definitions: usize = daemon_sources()
            .iter()
            .map(|(_, text)| offsets_of(&production_part(text), "fn validate_fortress_id(").len())
            .sum();
        assert_eq!(definitions, 1, "exactly one fortress-id grammar");
        let config = production_source("src/config.rs");
        let grammar = fn_body(&config, "validate_fortress_id");
        // The lowercase-hex test is the grammar's signature; outside the one
        // function it would be a second grammar.
        assert_eq!(
            offsets_of(&config, "is_ascii_uppercase").len(),
            offsets_of(grammar, "is_ascii_uppercase").len()
        );
        assert!(fn_body(&config, "validate_server_profile").contains("validate_fortress_id("));
        let verbs = production_source("src/agent_start.rs");
        assert!(verbs.contains("crate::config::validate_fortress_id("));
        assert!(!verbs.contains("is_ascii_uppercase"));
    }

    // ---- TB8: stdout discipline on the pinned admit line ------------------

    #[test]
    fn tb8_the_pinned_admit_line_carries_its_safety_annotation() {
        let text = include_str!("agent_start.rs");
        let needle = concat!("castle-wall-daemon: agent_start_gate", "=admit uid={uid}");
        let at = text.find(needle).expect("the pinned admit line");
        let before: Vec<&str> = text[..at].lines().rev().skip(1).collect();
        let annotated = before
            .iter()
            .take_while(|l| l.trim_start().starts_with("//"))
            .any(|l| l.contains("SAFETY:"));
        assert!(
            annotated,
            "the admit println! must carry a // SAFETY: annotation"
        );
        assert_eq!(text.matches(needle).count(), 1, "one pinned admit line");
    }

    #[cfg(target_os = "linux")]
    mod tb4_unit_bounds {
        //! TB4: the agent unit's bounds against the one `nft` call the gate makes.

        /// The shipped agent unit. Must match `systemd/sanctuary-agent@.service`.
        const AGENT_UNIT: &str = include_str!("../systemd/sanctuary-agent@.service");
        /// The shipped wall unit. Must match `systemd/sanctuary-castle-wall.service`.
        const WALL_UNIT: &str = include_str!("../systemd/sanctuary-castle-wall.service");

        /// The single non-comment value of `key` in a unit (the agent unit's
        /// canonical form is enforced by `tests/agent_unit.rs`).
        fn value<'a>(unit: &'a str, key: &str) -> &'a str {
            let values: Vec<&str> = unit
                .lines()
                .filter(|line| !line.starts_with('#'))
                .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .collect();
            assert_eq!(values.len(), 1, "exactly one {key}= expected");
            values[0]
        }

        #[test]
        fn tb4_the_start_timeout_exceeds_one_nft_call_and_the_stop_timeout_matches_the_wall() {
            let start: u64 = value(AGENT_UNIT, "TimeoutStartSec")
                .parse()
                .expect("TimeoutStartSec is whole seconds");
            // The gate makes exactly one bounded nft call; a start timeout at or
            // below its worst case would kill a healthy gate mid-read.
            assert!(
                std::time::Duration::from_secs(start) > crate::nftables::NFT_CALL_WORST_CASE,
                "agent TimeoutStartSec {start}s must exceed NFT_CALL_WORST_CASE {:?}",
                crate::nftables::NFT_CALL_WORST_CASE
            );
            assert_eq!(
                value(AGENT_UNIT, "TimeoutStopSec"),
                value(WALL_UNIT, "TimeoutStopSec"),
                "the agent's TimeoutStopSec must equal the wall's"
            );
            assert_eq!(
                value(AGENT_UNIT, "ExecStart"),
                crate::protected_agent::profile::EXECUTABLE_PATH,
                "ExecStart= must match profile::EXECUTABLE_PATH"
            );
        }
    }
}
