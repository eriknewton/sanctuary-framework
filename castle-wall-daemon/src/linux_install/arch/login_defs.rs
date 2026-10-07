//! Arch login.defs range reader for system account allocation.
use super::{transaction::Root, Result};
use serde::Serialize;
use std::collections::BTreeMap;

const LOGIN_DEFS: &str = "etc/login.defs";
const LOGIN_DEFS_MAX_BYTES: usize = 64 * 1024; // Shadow's login.defs is a small key-value file; this caps root-edited input at 64 KiB.
const REQUIRED_KEYS: [&str; 8] = [
    "SYS_GID_MIN",
    "SYS_GID_MAX",
    "SYS_UID_MIN",
    "SYS_UID_MAX",
    "UID_MIN",
    "UID_MAX",
    "GID_MIN",
    "GID_MAX",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Ranges {
    pub sys_gid_min: u32,
    pub sys_gid_max: u32,
    pub sys_uid_min: u32,
    pub sys_uid_max: u32,
    pub uid_min: u32,
    pub uid_max: u32,
    pub gid_min: u32,
    pub gid_max: u32,
}

pub fn read(root: &Root) -> Result<Ranges> {
    parse(&root.read(LOGIN_DEFS, LOGIN_DEFS_MAX_BYTES)?)
}

pub fn parse(bytes: &[u8]) -> Result<Ranges> {
    let text = std::str::from_utf8(bytes)?;
    let mut values = BTreeMap::new();
    for raw in text.lines() {
        // shadow's getdef splits on ASCII isspace; Unicode whitespace would let this reader see a key shadow never reads.
        let line = raw.trim_matches(|c: char| c.is_ascii_whitespace());
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next().ok_or("malformed login.defs line")?;
        let required = REQUIRED_KEYS.contains(&key);
        let case_only_required = REQUIRED_KEYS
            .iter()
            .any(|required| key != *required && key.eq_ignore_ascii_case(required));
        if !required {
            if case_only_required {
                return Err("login.defs key case mismatch".into());
            }
            // shadow owns every other key, including valueless ones (the stock Arch file's bare MOTD_FILE line) and
            // multi-word values. Skipping them cannot hide a range key: any line shadow reads as one of REQUIRED_KEYS
            // has that exact key as its first ASCII-whitespace token here too, and is parsed strictly below.
            continue;
        }
        let value = fields.next().ok_or("malformed login.defs line")?;
        if fields.next().is_some() {
            return Err("malformed login.defs line".into());
        }
        if values.contains_key(key) {
            return Err("duplicate login.defs key".into());
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("non-decimal login.defs value".into());
        }
        values.insert(key, value.parse::<u32>()?);
    }
    for key in REQUIRED_KEYS {
        if !values.contains_key(key) {
            return Err("login.defs does not state the system id ranges".into());
        }
    }
    let ranges = Ranges {
        sys_gid_min: values["SYS_GID_MIN"],
        sys_gid_max: values["SYS_GID_MAX"],
        sys_uid_min: values["SYS_UID_MIN"],
        sys_uid_max: values["SYS_UID_MAX"],
        uid_min: values["UID_MIN"],
        uid_max: values["UID_MAX"],
        gid_min: values["GID_MIN"],
        gid_max: values["GID_MAX"],
    };
    if ranges.sys_gid_min == 0
        || ranges.sys_uid_min == 0
        || ranges.sys_gid_min > ranges.sys_gid_max
        || ranges.sys_gid_max >= ranges.gid_min
        || ranges.gid_min > ranges.gid_max
        || ranges.sys_uid_min > ranges.sys_uid_max
        || ranges.sys_uid_max >= ranges.uid_min
        || ranges.uid_min > ranges.uid_max
    {
        return Err("login.defs system id range order".into());
    }
    Ok(ranges)
}
