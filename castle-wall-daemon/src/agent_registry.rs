//! The operator's agent registry: WHICH local account the wall is expected to
//! confine, read once at activation.
//!
//! This is the READ side only. Nothing here provisions an account, writes the
//! file, or launches anything; those are later slices. The one question this
//! module answers is: "does the account the operator registered still resolve to
//! the uid the signed manifest admits?" A `false` answer must stop the daemon
//! before `READY=1`, because readiness is what a supervisor starts the agent on.
//!
//! WHY THE FILE IS NOT TRUSTED THE WAY A SIGNED MANIFEST IS: the manifest is
//! signed and the registry is not, so the registry can only ever NARROW what the
//! manifest already admits. It can refuse a boot; it can never widen the binding,
//! name a second uid, or change which uid is bound. Every check below exists to
//! keep that direction: custody proves only root wrote it, and the admitted-uid
//! comparison (in `runtime_providers`) is what makes the file non-authoritative.

use std::path::Path;

/// The shipped registry path. Must match the `agent_registry_path` default in
/// `LinuxRuntimePaths::production` (`src/config.rs`); the constant lives here so
/// the module that parses the file also owns where it lives.
pub const DEFAULT_AGENT_REGISTRY_PATH: &str = "/etc/sanctuary/agents/registry-v1.json";

/// The only schema this daemon reads. A future schema is refused rather than
/// best-effort parsed: a registry it cannot fully understand is a registry whose
/// refusals it cannot honour.
const AGENT_REGISTRY_SCHEMA_V1: u32 = 1;

/// The only agent profile this daemon reads, for the same reason as the schema.
const AGENT_PROFILE_V1: u32 = 1;

/// The account-name prefix the operator's provisioning uses. The registry names
/// the SUFFIX (`drill`), never a full account name, so a registry edit cannot
/// point the lookup at an arbitrary system account such as `root` or `nobody`.
/// Must match the account-name form in the Linux runbook and the drill harness.
pub const AGENT_ACCOUNT_PREFIX: &str = "sanctuary-agent-";

/// Cap on the registry file this daemon will read into memory.
///
/// DERIVATION: a schema-1 registry holds exactly one entry of three small scalar
/// fields, so a well-formed file is a few hundred bytes; 64 KiB is three orders
/// of magnitude of headroom and still bounds the read of a file that a
/// root-owned-but-wrong process could have grown. Reading is bounded work even
/// though the file is root-owned, because "root wrote it" is custody, not size.
const MAX_REGISTRY_BYTES: u64 = 64 * 1024;

/// Group- and other-write bits. A registry any non-root principal can write is
/// not a statement by the operator, whatever its owner says.
///
/// DERIVATION: 0o022 = S_IWGRP (0o020) | S_IWOTH (0o002).
const NON_OWNER_WRITE_BITS: u32 = 0o022;

/// One registered agent, exactly as schema 1 declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredAgent {
    /// The account-name SUFFIX. The resolved account is
    /// `AGENT_ACCOUNT_PREFIX` + this.
    pub name: String,
    /// The uid the operator registered for that account.
    pub uid: u32,
}

impl RegisteredAgent {
    /// The full local account name this entry names.
    pub fn account_name(&self) -> String {
        format!("{AGENT_ACCOUNT_PREFIX}{}", self.name)
    }
}

/// Every way the registry can refuse an activation. Each variant is a distinct
/// operator repair, which is why they are not one string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AgentRegistryError {
    #[error("the agent registry at {path} could not be opened safely: {detail}")]
    Unreadable { path: String, detail: String },
    #[error("the agent registry at {path} is not a plain root-owned file: {detail}")]
    Custody { path: String, detail: String },
    #[error("the agent registry at {path} is malformed: {detail}")]
    Malformed { path: String, detail: String },
    #[error(
        "the agent registry names account {account} at uid {registered}, but that account \
         resolves to {resolved:?} on this host"
    )]
    AccountMismatch {
        account: String,
        registered: u32,
        resolved: Option<u32>,
    },
    #[error("the account {account} named by the agent registry could not be resolved: {detail}")]
    AccountUnresolvable { account: String, detail: String },
}

/// How an account name becomes a uid.
///
/// Injected rather than called directly so every refusal above is testable on a
/// host that has no such account. The production implementation is
/// [`SystemAccountLookup`], which uses the REENTRANT `getpwnam_r`: the daemon
/// resolves accounts from more than one thread, and `getpwnam` returns a pointer
/// into a shared static buffer that a concurrent call overwrites.
pub trait AccountLookup {
    /// `Ok(Some(uid))` when the account exists, `Ok(None)` when it provably does
    /// not, `Err` when the answer is indeterminate (an NSS backend error).
    ///
    /// FAILURE MODE worth stating for the runbook: a remote NSS backend (LDAP,
    /// SSSD) can block here for as long as its own timeout, and this call sits on
    /// the activation path before `READY=1`. The bound is the unit's
    /// `TimeoutStartSec`: a hung directory service reads as a failed start, not
    /// as a wall that came up unconfined.
    fn uid_for_account(&self, account: &str) -> Result<Option<u32>, String>;
}

/// The production account lookup.
pub struct SystemAccountLookup;

impl AccountLookup for SystemAccountLookup {
    #[cfg(unix)]
    fn uid_for_account(&self, account: &str) -> Result<Option<u32>, String> {
        use std::ffi::CString;
        let c_account = CString::new(account)
            .map_err(|_| "the account name contains an interior NUL byte".to_string())?;
        // DERIVATION of the ceiling: a `passwd` record is five short strings and
        // two integers; 16 KiB is three orders of magnitude above any real one,
        // so a record that does not fit is a pathological or hostile NSS answer
        // and is treated as indeterminate rather than absent.
        const MAX_PASSWD_BUFFER_BYTES: usize = 16 * 1024;
        // DERIVATION of the fallback: `sysconf` may answer -1 ("no definite
        // limit"), and glibc's own documented starting point for that case is
        // 1 KiB, which holds an ordinary local record in one pass.
        const DEFAULT_PASSWD_BUFFER_BYTES: usize = 1024;
        // DERIVATION of the starting size: `sysconf(_SC_GETPW_R_SIZE_MAX)` is the
        // platform's own answer and is the value glibc documents for this call.
        // It is advisory (it may be -1, and a large NSS record can still exceed
        // it), so an ERANGE answer grows the buffer rather than being read as
        // "no such account".
        //
        // INVARIANT at this line: the suggestion is CLAMPED to the ceiling before
        // it is ever allocated. Without the clamp the ceiling is a claim the code
        // does not keep: a platform (or a hostile `sysconf` shim) answering a
        // huge value would have this allocate it in one shot, which is exactly
        // the unbounded allocation the ceiling exists to prevent.
        let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let mut size: usize = if suggested > 0 {
            (suggested as usize).min(MAX_PASSWD_BUFFER_BYTES)
        } else {
            DEFAULT_PASSWD_BUFFER_BYTES
        };
        loop {
            let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let mut buffer = vec![0 as libc::c_char; size];
            // Safety: `getpwnam_r` writes only into `passwd` and `buffer`, both
            // owned here and live for the call; `result` is set to either
            // `&mut passwd` or NULL. The reentrant form is required because the
            // daemon resolves accounts off more than one thread.
            let code = unsafe {
                libc::getpwnam_r(
                    c_account.as_ptr(),
                    &mut passwd,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut result,
                )
            };
            if code == 0 {
                if result.is_null() {
                    // A zero return with a NULL result is the POSIX spelling of
                    // "no such account", which is a definite answer.
                    return Ok(None);
                }
                return Ok(Some(passwd.pw_uid));
            }
            if code == libc::ERANGE && size < MAX_PASSWD_BUFFER_BYTES {
                size = (size * 2).min(MAX_PASSWD_BUFFER_BYTES);
                continue;
            }
            return Err(format!("getpwnam_r failed with errno {code}"));
        }
    }

    #[cfg(not(unix))]
    fn uid_for_account(&self, _account: &str) -> Result<Option<u32>, String> {
        Err("account resolution is not available on this platform".to_string())
    }
}

/// Read the registry and resolve the account it names.
///
/// `Ok(None)` means NO agent is registered, which is the shipped default: the
/// file is absent, or it is present with an empty `entries` array. In that state
/// the binding follows the signed manifest alone and this module imposes nothing.
///
/// Every other reading is a refusal. The registry can only narrow.
pub fn read_registered_agent(
    path: &Path,
    lookup: &dyn AccountLookup,
) -> Result<Option<RegisteredAgent>, AgentRegistryError> {
    let Some(bytes) = read_registry_file(path)? else {
        return Ok(None);
    };
    let Some(entry) = parse_registry(path, &bytes)? else {
        return Ok(None);
    };
    let account = entry.account_name();
    match lookup.uid_for_account(&account) {
        Ok(Some(resolved)) if resolved == entry.uid => Ok(Some(entry)),
        Ok(resolved) => Err(AgentRegistryError::AccountMismatch {
            account,
            registered: entry.uid,
            resolved,
        }),
        Err(detail) => Err(AgentRegistryError::AccountUnresolvable { account, detail }),
    }
}

/// Open the registry with `O_NOFOLLOW` and prove its custody before reading it.
///
/// FAILURE MODE the flag closes: a symlink at the registry path reads perfectly
/// well through an ordinary open, and the custody checks below would then
/// describe the TARGET's owner, not the link's. `O_NOFOLLOW` makes the final
/// component a hard failure instead, which is the only reading that is honest.
/// The check order matters too: custody is proven on the OPEN DESCRIPTOR, so a
/// swap between a `stat` and a read cannot change what was checked.
#[cfg(unix)]
fn read_registry_file(path: &Path) -> Result<Option<Vec<u8>>, AgentRegistryError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        // An absent registry is the shipped default, not a failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(AgentRegistryError::Unreadable {
                path: path.display().to_string(),
                detail: err.to_string(),
            })
        }
    };
    let metadata = file
        .metadata()
        .map_err(|err| AgentRegistryError::Unreadable {
            path: path.display().to_string(),
            detail: err.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(AgentRegistryError::Custody {
            path: path.display().to_string(),
            detail: "the registry path is not a regular file".to_string(),
        });
    }
    if metadata.uid() != 0 {
        return Err(AgentRegistryError::Custody {
            path: path.display().to_string(),
            detail: format!(
                "the registry is owned by uid {} rather than root; only root may declare \
                 which account this wall confines",
                metadata.uid()
            ),
        });
    }
    if metadata.mode() & NON_OWNER_WRITE_BITS != 0 {
        return Err(AgentRegistryError::Custody {
            path: path.display().to_string(),
            detail: format!(
                "the registry is writable by a non-owner (mode {:o}); a principal other than \
                 root could then choose which account the wall refuses to start without",
                metadata.mode() & 0o7777
            ),
        });
    }
    if metadata.len() > MAX_REGISTRY_BYTES {
        return Err(AgentRegistryError::Custody {
            path: path.display().to_string(),
            detail: format!(
                "the registry is {} bytes, above the {MAX_REGISTRY_BYTES}-byte cap",
                metadata.len()
            ),
        });
    }
    let mut bytes = Vec::new();
    // The read is capped independently of the size check above: the file could
    // grow between the two, and an unbounded read on the activation path is
    // unbounded work however small the file looked a moment ago.
    file.take(MAX_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| AgentRegistryError::Unreadable {
            path: path.display().to_string(),
            detail: err.to_string(),
        })?;
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(AgentRegistryError::Custody {
            path: path.display().to_string(),
            detail: format!("the registry exceeds the {MAX_REGISTRY_BYTES}-byte cap while reading"),
        });
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_registry_file(path: &Path) -> Result<Option<Vec<u8>>, AgentRegistryError> {
    Err(AgentRegistryError::Unreadable {
        path: path.display().to_string(),
        detail: "the agent registry is only readable on a unix host".to_string(),
    })
}

/// Parse a schema-1 registry body. Pure over the bytes, so every malformed shape
/// is testable without a filesystem.
fn parse_registry(
    path: &Path,
    bytes: &[u8],
) -> Result<Option<RegisteredAgent>, AgentRegistryError> {
    let malformed = |detail: String| AgentRegistryError::Malformed {
        path: path.display().to_string(),
        detail,
    };
    let doc: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|err| malformed(format!("the registry is not JSON: {err}")))?;
    let schema = doc
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed("the registry declares no schema_version".to_string()))?;
    if schema != u64::from(AGENT_REGISTRY_SCHEMA_V1) {
        return Err(malformed(format!(
            "the registry declares schema_version {schema}; this daemon reads only \
             {AGENT_REGISTRY_SCHEMA_V1}"
        )));
    }
    let entries = doc
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| malformed("the registry has no `entries` array".to_string()))?;
    // An EMPTY registry is the same statement as an absent one: no agent is
    // registered. Any other cardinality is refused rather than truncated,
    // because this slice binds exactly one agent and a second entry would be a
    // registration this daemon silently ignored.
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() != 1 {
        return Err(malformed(format!(
            "the registry declares {} entries; this daemon binds exactly one agent",
            entries.len()
        )));
    }
    let entry = entries[0]
        .as_object()
        .ok_or_else(|| malformed("the registry entry is not an object".to_string()))?;
    for key in entry.keys() {
        if !matches!(key.as_str(), "name" | "uid" | "profile") {
            return Err(malformed(format!(
                "the registry entry carries the unknown field {key:?}"
            )));
        }
    }
    let profile = entry
        .get("profile")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed("the registry entry declares no profile".to_string()))?;
    if profile != u64::from(AGENT_PROFILE_V1) {
        return Err(malformed(format!(
            "the registry entry declares profile {profile}; this daemon reads only \
             {AGENT_PROFILE_V1}"
        )));
    }
    let name = entry
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("the registry entry declares no name".to_string()))?;
    // The name becomes half of a local account name, so it is constrained to the
    // characters an account name may carry. A name with a slash, a NUL or a space
    // could otherwise name something other than the account the operator meant.
    if name.is_empty()
        || name.len() > MAX_AGENT_NAME_LEN
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(malformed(format!(
            "the registry entry's name {name:?} is not a lowercase, digit and hyphen account \
             suffix of at most {MAX_AGENT_NAME_LEN} characters"
        )));
    }
    let uid = entry
        .get("uid")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed("the registry entry declares no uid".to_string()))?;
    let uid = u32::try_from(uid)
        .map_err(|_| malformed(format!("the registry entry's uid {uid} is not a uid")))?;
    if uid == 0 {
        return Err(malformed(
            "the registry entry names uid 0; root is never the confined agent".to_string(),
        ));
    }
    Ok(Some(RegisteredAgent {
        name: name.to_string(),
        uid,
    }))
}

/// DERIVATION: a Linux account name is bounded by `sysconf(_SC_LOGIN_NAME_MAX)`,
/// conventionally 32 including the terminator, and this value is only the SUFFIX
/// after `AGENT_ACCOUNT_PREFIX` (16 characters), so 15 keeps the composed name
/// inside the conventional bound.
const MAX_AGENT_NAME_LEN: usize = 15;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FixedLookup(Result<Option<u32>, String>);

    impl AccountLookup for FixedLookup {
        fn uid_for_account(&self, _account: &str) -> Result<Option<u32>, String> {
            self.0.clone()
        }
    }

    fn path() -> PathBuf {
        PathBuf::from("/etc/sanctuary/agents/registry-v1.json")
    }

    fn parse(body: &str) -> Result<Option<RegisteredAgent>, AgentRegistryError> {
        parse_registry(&path(), body.as_bytes())
    }

    #[test]
    fn an_empty_entries_array_reads_as_no_registered_agent() {
        assert_eq!(
            parse(r#"{"schema_version":1,"entries":[]}"#).unwrap(),
            None,
            "an empty registry is the same statement as an absent one"
        );
    }

    #[test]
    fn one_well_formed_entry_parses() {
        let entry =
            parse(r#"{"schema_version":1,"entries":[{"name":"drill","uid":60123,"profile":1}]}"#)
                .unwrap()
                .unwrap();
        assert_eq!(entry.uid, 60123);
        assert_eq!(entry.account_name(), "sanctuary-agent-drill");
    }

    #[test]
    fn a_second_entry_is_refused_rather_than_truncated() {
        let err = parse(
            r#"{"schema_version":1,"entries":[{"name":"a","uid":60123,"profile":1},{"name":"b","uid":60124,"profile":1}]}"#,
        )
        .unwrap_err();
        assert!(matches!(err, AgentRegistryError::Malformed { .. }));
    }

    #[test]
    fn an_unknown_schema_or_profile_is_refused() {
        assert!(matches!(
            parse(r#"{"schema_version":2,"entries":[]}"#).unwrap_err(),
            AgentRegistryError::Malformed { .. }
        ));
        assert!(matches!(
            parse(r#"{"schema_version":1,"entries":[{"name":"a","uid":60123,"profile":2}]}"#)
                .unwrap_err(),
            AgentRegistryError::Malformed { .. }
        ));
    }

    #[test]
    fn a_name_that_is_not_an_account_suffix_is_refused() {
        for name in ["", "../root", "Drill", "a b", &"x".repeat(64)] {
            let body = format!(
                r#"{{"schema_version":1,"entries":[{{"name":"{name}","uid":60123,"profile":1}}]}}"#
            );
            assert!(
                matches!(
                    parse(&body).unwrap_err(),
                    AgentRegistryError::Malformed { .. }
                ),
                "name {name:?} must not compose an account name"
            );
        }
    }

    #[test]
    fn uid_zero_and_unknown_fields_are_refused() {
        assert!(matches!(
            parse(r#"{"schema_version":1,"entries":[{"name":"a","uid":0,"profile":1}]}"#)
                .unwrap_err(),
            AgentRegistryError::Malformed { .. }
        ));
        assert!(matches!(
            parse(r#"{"schema_version":1,"entries":[{"name":"a","uid":1,"profile":1,"x":1}]}"#)
                .unwrap_err(),
            AgentRegistryError::Malformed { .. }
        ));
    }

    #[test]
    fn an_account_resolving_to_another_uid_is_a_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry = dir.path().join("registry-v1.json");
        std::fs::write(
            &registry,
            r#"{"schema_version":1,"entries":[{"name":"drill","uid":60123,"profile":1}]}"#,
        )
        .unwrap();
        // The custody gate refuses a non-root-owned file before the lookup runs,
        // which is exactly what a test running as a normal user proves.
        let err = read_registered_agent(&registry, &FixedLookup(Ok(Some(60124)))).unwrap_err();
        assert!(
            matches!(err, AgentRegistryError::Custody { .. })
                || matches!(err, AgentRegistryError::AccountMismatch { .. }),
            "a registry this process's own uid could rewrite must not be honoured: {err}"
        );
    }

    #[test]
    fn an_absent_registry_reads_as_no_registered_agent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            read_registered_agent(&dir.path().join("absent.json"), &FixedLookup(Ok(None))).unwrap(),
            None
        );
    }

    #[test]
    fn a_symlinked_registry_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("real.json");
        std::fs::write(&target, r#"{"schema_version":1,"entries":[]}"#).unwrap();
        let link = dir.path().join("registry-v1.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = read_registered_agent(&link, &FixedLookup(Ok(None))).unwrap_err();
        assert!(
            matches!(err, AgentRegistryError::Unreadable { .. }),
            "O_NOFOLLOW must make a symlinked registry a hard failure, got {err}"
        );
    }
}
