//! Arch login.defs range reader for system account allocation.
use super::{transaction::Root, Result};
use serde::Serialize;
use std::collections::BTreeMap;

const LOGIN_DEFS: &str = "etc/login.defs";
const LOGIN_DEFS_MAX_BYTES: usize = 64 * 1024; // Shadow's login.defs is a small key-value file; this caps root-edited input at 64 KiB.
const SHADOW_FGETS_BUFFER_BYTES: usize = 1024;
// 1023 = shadow 4.20.0's 1024-byte fgets buffer minus the trailing NUL. The check below counts a line with its LF, so
// it refuses content of 1022 bytes or more; shadow reads a second record only from content of 1024 bytes or more.
const MAX_SHADOW_PHYSICAL_LINE_BYTES: usize = SHADOW_FGETS_BUFFER_BYTES - 1;
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
    let mut values = BTreeMap::new();
    // The shadow separator evidence is not stable across reviewers; bytes outside space, tab and newline are refused rather than guessed.
    if bytes
        .iter()
        .any(|byte| matches!(*byte, 0x00..=0x08 | 0x0b..=0x1f | 0x7f))
    {
        return Err("ambiguous login.defs control byte".into());
    }
    for raw in bytes.split_inclusive(|byte| *byte == b'\n') {
        if raw.len() >= MAX_SHADOW_PHYSICAL_LINE_BYTES {
            return Err("login.defs physical line too long".into());
        }
        let mut line = raw.strip_suffix(b"\n").unwrap_or(raw);
        line = trim_space_tab(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut fields = line
            .split(|byte| *byte == b' ' || *byte == b'\t')
            .filter(|field| !field.is_empty());
        let key = fields.next().ok_or("malformed login.defs line")?;
        // A token that begins with a range key but is not exactly it may be a range record under a separator model we do not trust.
        if REQUIRED_KEYS
            .iter()
            .any(|required| key.starts_with(required.as_bytes()) && key != required.as_bytes())
        {
            return Err("ambiguous login.defs range key".into());
        }
        let required = REQUIRED_KEYS
            .iter()
            .any(|required| key == required.as_bytes());
        let case_only_required = REQUIRED_KEYS.iter().any(|required| {
            key != required.as_bytes() && key.eq_ignore_ascii_case(required.as_bytes())
        });
        if !required {
            if case_only_required {
                return Err("login.defs key case mismatch".into());
            }
            // Shadow owns unrelated keys; this reader refuses ambiguous range-key prefixes instead of claiming to model every separator shadow might accept.
            continue;
        }
        let value = fields.next().ok_or("malformed login.defs line")?;
        if fields.next().is_some() {
            return Err("malformed login.defs line".into());
        }
        let key = std::str::from_utf8(key)?;
        if values.contains_key(key) {
            return Err("duplicate login.defs key".into());
        }
        if !value.iter().all(|byte| byte.is_ascii_digit()) {
            return Err("non-decimal login.defs value".into());
        }
        // shadow 4.20.0 parses values with strtoumax base 0, so a multi-digit value with a leading zero is octal there
        // (01750 is 1000); this reader is decimal, so it refuses that shape rather than disagree. A lone 0 reads the same
        // in every base and falls through to the order checks, which refuse it.
        if value.len() > 1 && value[0] == b'0' {
            return Err("leading-zero login.defs value".into());
        }
        values.insert(key, std::str::from_utf8(value)?.parse::<u32>()?);
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

fn trim_space_tab(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
