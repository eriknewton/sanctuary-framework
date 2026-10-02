//! NSS and local account agreement for the single no-broker installation.
use super::{
    transaction::{
        checked, run_bounded, Root, State, Transaction, HELPER_MAX_BYTES, HELPER_TIMEOUT,
    },
    Result,
};
use serde::{Deserialize, Serialize};

const SYSTEM_GID_FIRST: u32 = 100; // Ubuntu's dynamically allocated system group range.
const SYSTEM_GID_LAST: u32 = 999;
const MAX_NSS_ROWS: usize = 4096; // Fixed enumeration ceiling; larger directories require an explicit future profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountStep {
    Fresh,
    SanctuaryIntent,
    SanctuaryCreated,
    AgentGroupIntent,
    AgentGroupCreated,
    AgentUserIntent,
    Complete,
}
pub fn agent_name(uid: u32) -> String {
    format!("sanctuary-agent-{uid}")
}

#[derive(Debug)]
struct Nss {
    passwd: Vec<Vec<String>>,
    groups: Vec<Vec<String>>,
}
fn rows(bytes: &[u8], width: usize) -> Result<Vec<Vec<String>>> {
    let text = std::str::from_utf8(bytes)?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("incomplete NSS observation".into());
    }
    let rows: Vec<Vec<String>> = text
        .lines()
        .map(|l| l.split(':').map(str::to_owned).collect())
        .collect();
    if rows.len() > MAX_NSS_ROWS || rows.iter().any(|r| r.len() != width) {
        return Err("NSS shape or quota".into());
    }
    Ok(rows)
}
impl Nss {
    fn read() -> Result<Self> {
        Ok(Self {
            passwd: rows(&checked("/usr/bin/getent", &["passwd"])?, 7)?,
            groups: rows(&checked("/usr/bin/getent", &["group"])?, 4)?,
        })
    }
    fn absent(&self, database: &str, name: &str, number: u32) -> Result<()> {
        let entries = if database == "passwd" {
            &self.passwd
        } else {
            &self.groups
        };
        if entries
            .iter()
            .any(|r| r[0] == name || r[2] == number.to_string())
        {
            return Err("account collision".into());
        }
        // Successful bounded enumeration AND both keyed reads are required; lookup failure alone is not absence.
        for key in [name.to_owned(), number.to_string()] {
            let result = run_bounded(
                "/usr/bin/getent",
                &[database, &key],
                HELPER_TIMEOUT,
                HELPER_MAX_BYTES,
            )?;
            if result.code != Some(2) || !result.stdout.is_empty() || !result.stderr.is_empty() {
                return Err("NSS absence not established".into());
            }
        }
        Ok(())
    }
    fn exact(&self, root: &Root, database: &str, expected: &[String]) -> Result<()> {
        let entries = if database == "passwd" {
            &self.passwd
        } else {
            &self.groups
        };
        let selected: Vec<_> = entries
            .iter()
            .filter(|r| r[0] == expected[0] || r[2] == expected[2])
            .collect();
        if selected.len() != 1 || selected[0] != expected {
            return Err("NSS identity drift".into());
        }
        for key in [&expected[0], &expected[2]] {
            let actual = rows(
                &checked("/usr/bin/getent", &[database, key])?,
                expected.len(),
            )?;
            if actual != vec![expected.to_vec()] {
                return Err("keyed NSS identity drift".into());
            }
        }
        let local = rows(
            &root.read(&format!("etc/{database}"), HELPER_MAX_BYTES)?,
            expected.len(),
        )?;
        let matched: Vec<_> = local
            .iter()
            .filter(|r| r[0] == expected[0] || r[2] == expected[2])
            .collect();
        if matched.len() != 1 || matched[0] != expected {
            return Err("local account identity drift".into());
        }
        Ok(())
    }
}
fn group(name: &str, gid: u32) -> Vec<String> {
    vec![name.into(), "x".into(), gid.to_string(), String::new()]
}
fn user(uid: u32) -> Vec<String> {
    vec![
        agent_name(uid),
        "x".into(),
        uid.to_string(),
        uid.to_string(),
        String::new(),
        "/nonexistent".into(),
        "/usr/sbin/nologin".into(),
    ]
}
pub fn overflow_uid() -> Result<u32> {
    // procfs exposes a kernel scalar rather than a regular custodied file.
    let bytes = checked("/usr/bin/cat", &["/proc/sys/kernel/overflowuid"])?;
    Ok(std::str::from_utf8(&bytes)?.trim().parse()?)
}
pub fn operator_uid() -> Result<u32> {
    let raw = checked("/usr/bin/cat", &["/proc/self/loginuid"])?;
    let login: u32 = std::str::from_utf8(&raw)?.trim().parse()?;
    // An unset loginuid cannot prove which operator must remain excluded.
    if login == u32::MAX {
        return Err("operator loginuid unavailable".into());
    }
    Ok(login)
}
pub fn validate_ids(t: &Transaction, overflow: u32) -> Result<()> {
    for uid in [t.agent_uid, t.service_uid] {
        if [0, u32::MAX, t.operator_uid, overflow].contains(&uid) {
            return Err("excluded uid".into());
        }
    }
    if t.agent_uid == t.service_uid {
        return Err("service and agent uid collide".into());
    }
    Ok(())
}
fn reserve_service(nss: &Nss, t: &Transaction) -> Result<()> {
    nss.absent(
        "passwd",
        &format!("sanctuary-service-{}", t.service_uid),
        t.service_uid,
    )
}
pub fn verify(root: &Root, t: &Transaction) -> Result<()> {
    validate_ids(t, overflow_uid()?)?;
    let nss = Nss::read()?;
    reserve_service(&nss, t)?;
    nss.exact(
        root,
        "group",
        &group("sanctuary", t.sanctuary_gid.ok_or("missing sanctuary gid")?),
    )?;
    nss.exact(root, "group", &group(&agent_name(t.agent_uid), t.agent_uid))?;
    nss.exact(root, "passwd", &user(t.agent_uid))?;
    if nss
        .groups
        .iter()
        .any(|r| r[3].split(',').any(|n| n == agent_name(t.agent_uid)))
    {
        return Err("supplementary group membership".into());
    }
    let groups = checked("/usr/bin/id", &["-G", &agent_name(t.agent_uid)])?;
    if std::str::from_utf8(&groups)?.trim() != t.agent_uid.to_string() {
        return Err("effective supplementary groups".into());
    }
    let shadow = rows(&root.read("etc/shadow", HELPER_MAX_BYTES)?, 9)?;
    let entries: Vec<_> = shadow
        .iter()
        .filter(|r| r[0] == agent_name(t.agent_uid))
        .collect();
    // Never emit shadow bytes; this account is locked and has no credential enrollment path.
    if entries.len() != 1 || !matches!(entries[0][1].as_str(), "!" | "*") {
        return Err("agent password is not locked".into());
    }
    Ok(())
}
/// The single fixed account-creation invocation shared with the disposable-host helper test.
pub fn useradd_arguments(uid: u32) -> Vec<String> {
    // System accounts avoid ordinary-user subordinate-ID allocation and personal-account bookkeeping.
    vec![
        "--system".into(),
        "--uid".into(),
        uid.to_string(),
        "--gid".into(),
        uid.to_string(),
        "--no-create-home".into(),
        "--no-user-group".into(),
        "--no-log-init".into(),
        "--home-dir".into(),
        "/nonexistent".into(),
        "--shell".into(),
        "/usr/sbin/nologin".into(),
        "--password".into(),
        "!".into(),
        agent_name(uid),
    ]
}
/// Each account helper is preceded by a durable intent; only that exact intent may resume.
pub fn provision(root: &Root, t: &mut Transaction) -> Result<()> {
    validate_ids(t, overflow_uid()?)?;
    let name = agent_name(t.agent_uid);
    loop {
        let nss = Nss::read()?;
        reserve_service(&nss, t)?;
        match t.account_step {
            AccountStep::Fresh => {
                nss.absent("passwd", &name, t.agent_uid)?;
                nss.absent("group", &name, t.agent_uid)?;
                if nss.groups.iter().any(|r| r[0] == "sanctuary") {
                    return Err("refusing sanctuary group adoption".into());
                }
                let gid = (SYSTEM_GID_FIRST..=SYSTEM_GID_LAST)
                    .rev()
                    .find(|gid| {
                        *gid != t.agent_uid && !nss.groups.iter().any(|r| r[2] == gid.to_string())
                    })
                    .ok_or("no system gid available")?;
                nss.absent("group", "sanctuary", gid)?;
                t.sanctuary_gid = Some(gid);
                t.account_step = AccountStep::SanctuaryIntent;
                t.save(root)?;
            }
            AccountStep::SanctuaryIntent => {
                let gid = t.sanctuary_gid.ok_or("missing gid intent")?;
                if !nss
                    .groups
                    .iter()
                    .any(|r| r[0] == "sanctuary" || r[2] == gid.to_string())
                {
                    nss.absent("group", "sanctuary", gid)?;
                    checked(
                        "/usr/sbin/groupadd",
                        &["--system", "--gid", &gid.to_string(), "sanctuary"],
                    )?;
                }
                Nss::read()?.exact(root, "group", &group("sanctuary", gid))?;
                t.account_step = AccountStep::SanctuaryCreated;
                t.save(root)?;
            }
            AccountStep::SanctuaryCreated => {
                nss.absent("group", &name, t.agent_uid)?;
                t.account_step = AccountStep::AgentGroupIntent;
                t.save(root)?;
            }
            AccountStep::AgentGroupIntent => {
                if !nss
                    .groups
                    .iter()
                    .any(|r| r[0] == name || r[2] == t.agent_uid.to_string())
                {
                    nss.absent("group", &name, t.agent_uid)?;
                    checked(
                        "/usr/sbin/groupadd",
                        &["--gid", &t.agent_uid.to_string(), &name],
                    )?;
                }
                Nss::read()?.exact(root, "group", &group(&name, t.agent_uid))?;
                t.account_step = AccountStep::AgentGroupCreated;
                t.save(root)?;
            }
            AccountStep::AgentGroupCreated => {
                nss.absent("passwd", &name, t.agent_uid)?;
                t.account_step = AccountStep::AgentUserIntent;
                t.save(root)?;
            }
            AccountStep::AgentUserIntent => {
                if !nss
                    .passwd
                    .iter()
                    .any(|r| r[0] == name || r[2] == t.agent_uid.to_string())
                {
                    nss.absent("passwd", &name, t.agent_uid)?;
                    checked(
                        "/usr/sbin/useradd",
                        &useradd_arguments(t.agent_uid)
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                    )?;
                }
                verify(root, t)?;
                t.account_step = AccountStep::Complete;
                t.state = State::AccountsCreated;
                t.save(root)?;
            }
            AccountStep::Complete => return verify(root, t),
        }
    }
}

/// An observed group, distinct from whether the complete configured identity still agrees.
pub fn sanctuary_group_observation() -> Result<Option<u32>> {
    let nss = Nss::read()?;
    let groups: Vec<_> = nss.groups.iter().filter(|g| g[0] == "sanctuary").collect();
    match groups.as_slice() {
        [] => Ok(None),
        [entry] => Ok(Some(entry[2].parse()?)),
        _ => Err("ambiguous sanctuary group observation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nss_requires_complete_bounded_rows_and_exact_width() {
        assert!(rows(b"root:x:0:0:root:/root:/bin/sh\n", 7).is_ok());
        assert!(rows(b"root:x:0:0:root:/root:/bin/sh", 7).is_err());
        assert!(rows(b"root:x:0\n", 7).is_err());
        assert!(rows(b"\xff\n", 7).is_err());
        assert!(rows(
            "a:x:1:1::/:/bin/false\n"
                .repeat(MAX_NSS_ROWS + 1)
                .as_bytes(),
            7
        )
        .is_err());
    }
    #[test]
    fn agent_and_reserved_service_exclude_operator_overflow_and_each_other() {
        let good = Transaction {
            version: 1,
            request_sha256: "a".repeat(64),
            state: State::Absent,
            agent_uid: 60123,
            service_uid: 60124,
            operator_uid: 1000,
            fortress_id: "0123456789abcdef".into(),
            sanctuary_gid: None,
            account_step: AccountStep::Fresh,
            policy_generation: 0,
            policy_request_sha256: None,
            policy_complete: false,
        };
        assert!(validate_ids(&good, 65534).is_ok());
        for uid in [0, u32::MAX, 1000, 65534, 60124] {
            let mut bad = good.clone();
            bad.agent_uid = uid;
            assert!(validate_ids(&bad, 65534).is_err());
        }
        for uid in [0, u32::MAX, 1000, 65534, 60123] {
            let mut bad = good.clone();
            bad.service_uid = uid;
            assert!(validate_ids(&bad, 65534).is_err());
        }
    }
}
