//! cgroup v2 transient scope creation via systemd-run.
//!
//! Per scope-lock section 1: each wrapped agent runs in its own systemd
//! transient scope. The daemon resolves the cgroup ID from the scope path
//! for use in nftables `socket cgroupv2` matches. The cgroup-id renumbering
//! gotcha (nftables resolves cgroup paths to numeric inode IDs at rule-load
//! time) is handled by re-installing rules when a scope is re-created.
//!
//! All kernel-touching functions are `#[cfg(target_os = "linux")]`-gated.

use std::path::{Path, PathBuf};

/// Errors emitted by the cgroup module.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("cgroup operation not available on this platform")]
    NotAvailableOnPlatform,
    #[error("systemd-run binary missing: {0}")]
    BinaryMissing(String),
    #[error("systemd-run invocation failed: {0}")]
    InvocationFailed(String),
    #[error("cgroup path not found: {0}")]
    PathNotFound(String),
    #[error("cgroup id resolution failed: {0}")]
    IdResolutionFailed(String),
    #[error("systemd not PID 1 (F-8 per scope-lock section 7)")]
    SystemdNotPid1,
}

/// A live cgroup identifier from systemd transient scope creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeHandle {
    pub agent_id: String,
    pub scope_unit: String,
    pub cgroup_path: PathBuf,
    pub cgroup_id: u64,
}

/// Derive the systemd scope unit name from an agent id.
pub fn scope_unit_name(agent_id: &str) -> String {
    // Sanitize: systemd unit names allow alphanumeric, hyphen, underscore,
    // period, backslash, colon. Replace anything else with underscore.
    let sanitized: String = agent_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("sanctuary-agent-{sanitized}.scope")
}

/// Resolve the cgroup v2 path for a systemd scope unit.
pub fn cgroup_path_for_scope(scope_unit: &str) -> PathBuf {
    // systemd places transient scopes under /sys/fs/cgroup/system.slice/
    // (system scopes) or /sys/fs/cgroup/user.slice/user-<UID>.slice/
    // (user scopes). For the daemon (running as root), system scope is
    // canonical.
    PathBuf::from(format!("/sys/fs/cgroup/system.slice/{scope_unit}"))
}

// ---- Linux implementations ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::process::Command;

    /// Verify systemd is PID 1. Per scope-lock section 7 F-8: refuse to start
    /// in non-systemd environments (rootless containers, WSL2 without
    /// systemd, etc.).
    pub fn verify_systemd_pid1() -> Result<(), CgroupError> {
        match fs::read_link("/proc/1/exe") {
            Ok(path) => {
                let path_str = path.to_string_lossy();
                if path_str.contains("systemd") {
                    Ok(())
                } else {
                    Err(CgroupError::SystemdNotPid1)
                }
            }
            Err(_) => {
                // Fallback: check if systemctl is available and reports active
                let status = Command::new("systemctl")
                    .arg("is-system-running")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .status();
                match status {
                    Ok(s) if s.success() => Ok(()),
                    _ => Err(CgroupError::SystemdNotPid1),
                }
            }
        }
    }

    /// Create a transient systemd scope for an agent. Uses `systemd-run`
    /// in scope mode. The scope is a pure cgroup container; no process
    /// is launched inside it yet. The caller (nfqueue verdict loop)
    /// classifies processes into this cgroup.
    pub fn create_agent_scope_impl(agent_id: &str) -> Result<ScopeHandle, CgroupError> {
        let unit = scope_unit_name(agent_id);
        let output = Command::new("systemd-run")
            .args([
                "--scope",
                "--unit",
                &unit,
                "--property=Delegate=yes",
                "--remain-after-exit",
                "/bin/true",
            ])
            .output()
            .map_err(|e| CgroupError::InvocationFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CgroupError::InvocationFailed(format!(
                "systemd-run exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        let cgroup_path = cgroup_path_for_scope(&unit);
        let cgroup_id = resolve_cgroup_id(&cgroup_path)?;

        Ok(ScopeHandle {
            agent_id: agent_id.to_string(),
            scope_unit: unit,
            cgroup_path,
            cgroup_id,
        })
    }

    /// Resolve the cgroup inode ID for an nftables `socket cgroupv2` match.
    /// This is the cgroup-id-renumbering gotcha from scope-lock section 1:
    /// nftables resolves paths to inode IDs at rule-load time, so we must
    /// re-resolve and re-install rules when a scope is destroyed and
    /// recreated.
    pub fn resolve_cgroup_id(cgroup_path: &Path) -> Result<u64, CgroupError> {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(cgroup_path).map_err(|e| {
            CgroupError::IdResolutionFailed(format!(
                "{}: {}",
                cgroup_path.display(),
                e
            ))
        })?;
        Ok(meta.ino())
    }

    /// Tear down a transient scope on agent shutdown / unwrap.
    pub fn destroy_agent_scope_impl(handle: &ScopeHandle) -> Result<(), CgroupError> {
        let output = Command::new("systemctl")
            .args(["stop", &handle.scope_unit])
            .output()
            .map_err(|e| CgroupError::InvocationFailed(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Scope may already be gone; treat as success.
            if !stderr.contains("not loaded") && !stderr.contains("not found") {
                return Err(CgroupError::InvocationFailed(format!(
                    "systemctl stop {} exited {}: {}",
                    handle.scope_unit,
                    output.status,
                    stderr.trim()
                )));
            }
        }
        Ok(())
    }

    /// Move a process into a cgroup scope by writing its PID to the
    /// cgroup.procs file. Used by the verdict loop to classify wrapped
    /// agent processes into their assigned cgroup.
    pub fn classify_pid(cgroup_path: &Path, pid: u32) -> Result<(), CgroupError> {
        let procs_path = cgroup_path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string()).map_err(|e| {
            CgroupError::InvocationFailed(format!(
                "failed to write PID {} to {}: {}",
                pid,
                procs_path.display(),
                e
            ))
        })
    }
}

// ---- Public API (platform-dispatching) ------------------------------------

/// Verify systemd is PID 1. Per scope-lock section 7 F-8.
#[cfg(target_os = "linux")]
pub fn verify_systemd_pid1() -> Result<(), CgroupError> {
    linux::verify_systemd_pid1()
}

#[cfg(not(target_os = "linux"))]
pub fn verify_systemd_pid1() -> Result<(), CgroupError> {
    Err(CgroupError::NotAvailableOnPlatform)
}

/// Create a transient scope for an agent and resolve its cgroup id.
#[cfg(target_os = "linux")]
pub fn create_agent_scope(agent_id: &str) -> Result<ScopeHandle, CgroupError> {
    linux::create_agent_scope_impl(agent_id)
}

#[cfg(not(target_os = "linux"))]
pub fn create_agent_scope(_agent_id: &str) -> Result<ScopeHandle, CgroupError> {
    Err(CgroupError::NotAvailableOnPlatform)
}

/// Tear down a transient scope on agent shutdown / unwrap.
#[cfg(target_os = "linux")]
pub fn destroy_agent_scope(handle: &ScopeHandle) -> Result<(), CgroupError> {
    linux::destroy_agent_scope_impl(handle)
}

#[cfg(not(target_os = "linux"))]
pub fn destroy_agent_scope(_handle: &ScopeHandle) -> Result<(), CgroupError> {
    Err(CgroupError::NotAvailableOnPlatform)
}

/// Resolve a cgroup path to its inode ID for nftables matching.
#[cfg(target_os = "linux")]
pub fn resolve_cgroup_id(cgroup_path: &Path) -> Result<u64, CgroupError> {
    linux::resolve_cgroup_id(cgroup_path)
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_cgroup_id(_cgroup_path: &Path) -> Result<u64, CgroupError> {
    Err(CgroupError::NotAvailableOnPlatform)
}

/// Move a process into a cgroup scope.
#[cfg(target_os = "linux")]
pub fn classify_pid(cgroup_path: &Path, pid: u32) -> Result<(), CgroupError> {
    linux::classify_pid(cgroup_path, pid)
}

#[cfg(not(target_os = "linux"))]
pub fn classify_pid(_cgroup_path: &Path, _pid: u32) -> Result<(), CgroupError> {
    Err(CgroupError::NotAvailableOnPlatform)
}

/// Register a journal listener that re-installs nftables rules if the
/// agent's transient scope is destroyed and recreated under a new cgroup
/// id (the cgroup-id renumbering gotcha).
///
/// Note: this is a stub that returns Ok. The full journal listener
/// (subscribing to systemd unit start/stop events via sd-journal) is
/// deferred to Checkpoint 4 alongside the failure-mode F-3/F-4/F-6
/// coverage. The re-install logic is structurally simple (resolve new
/// cgroup id, call load_agent_ruleset with the new id), but the journal
/// subscription machinery needs the daemon's event loop which is wired
/// in the next checkpoint.
pub fn register_scope_journal_listener() -> Result<(), CgroupError> {
    // Stub: journal listener deferred to Checkpoint 4.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_unit_name_sanitizes() {
        assert_eq!(
            scope_unit_name("my-agent"),
            "sanctuary-agent-my-agent.scope"
        );
        assert_eq!(
            scope_unit_name("agent/with spaces"),
            "sanctuary-agent-agent_with_spaces.scope"
        );
    }

    #[test]
    fn cgroup_path_for_scope_is_under_system_slice() {
        let path = cgroup_path_for_scope("sanctuary-agent-test.scope");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/system.slice/sanctuary-agent-test.scope")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_cgroup_id_works_on_root_cgroup() {
        // /sys/fs/cgroup always exists on cgroup v2 systems.
        let path = PathBuf::from("/sys/fs/cgroup");
        if path.exists() {
            let id = resolve_cgroup_id(&path);
            assert!(id.is_ok());
            assert!(id.unwrap() > 0);
        }
    }
}
