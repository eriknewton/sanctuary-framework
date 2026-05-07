//! cgroup v2 transient unit creation via systemd-run.
//!
//! Per scope-lock section 1: each wrapped agent runs in its own systemd
//! transient unit. The daemon resolves the cgroup ID from the unit path
//! for use in nftables `socket cgroupv2` matches. The cgroup-id renumbering
//! gotcha (nftables resolves cgroup paths to numeric inode IDs at rule-load
//! time) is handled by re-installing rules when a unit is re-created.
//!
//! Implementation note: we use systemd transient `.service` units with a
//! `sleep infinity` placeholder to anchor the cgroup lifetime. The earlier
//! `--scope --remain-after-exit /bin/true` shape was rejected on systemd
//! 255 (Ubuntu 24.04 and later) because `--remain-after-exit` is not
//! supported in `--scope` mode. The `--service` shape is the correct
//! unit type for "create a cgroup that outlives systemd-run": services
//! manage their own lifetime, accept `Delegate=yes`, and return promptly
//! when invoked with `--no-block`.
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
    /// Depth of the cgroup in the cgroup-v2 hierarchy, counting from the
    /// root (`/sys/fs/cgroup`) as depth 0. The agent's cgroup is depth 2
    /// in canonical deployments (`/system.slice/sanctuary-agent-foo.service`)
    /// but can be 3+ in nested environments (CI runners, Docker-in-Docker)
    /// where the daemon process itself is already inside a deeper cgroup.
    /// Used by nftables `socket cgroupv2 level <N> "<path>"` rule emission
    /// so the level matches where systemd actually placed the unit.
    pub cgroup_level: u32,
}

/// Derive the systemd transient unit name from an agent id.
///
/// Returns a `.service` unit name. The earlier `.scope` shape was changed
/// to `.service` when the production code switched to `systemd-run --service`
/// to work around systemd 255 rejecting `--remain-after-exit` in `--scope`
/// mode.
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
    format!("sanctuary-agent-{sanitized}.service")
}

/// Resolve the cgroup v2 path for a systemd transient unit.
pub fn cgroup_path_for_scope(scope_unit: &str) -> PathBuf {
    // systemd places transient system units under /sys/fs/cgroup/system.slice/
    // (system-level) or /sys/fs/cgroup/user.slice/user-<UID>.slice/
    // (user-level). The daemon runs as root, so system.slice is canonical.
    PathBuf::from(format!("/sys/fs/cgroup/system.slice/{scope_unit}"))
}

/// Compute the cgroup-v2 relative path string from a `ScopeHandle`.
///
/// nftables `socket cgroupv2 level <N> "<path>"` rules expect the cgroup
/// path with the `/sys/fs/cgroup/` prefix stripped, no leading slash, no
/// trailing slash (e.g. `system.slice/sanctuary-agent-foo.service`). The
/// kernel walks `/sys/fs/cgroup/<path>` at rule-load time at depth N.
///
/// Returns `CgroupError::PathNotFound` if the absolute path does not start
/// with `/sys/fs/cgroup/`, which would indicate the daemon resolved the
/// scope from somewhere unexpected (a non-canonical mount or a user-slice
/// hierarchy on a non-root invocation).
pub fn cgroup_relative_path(handle: &ScopeHandle) -> Result<String, CgroupError> {
    const ROOT: &str = "/sys/fs/cgroup/";
    let abs = handle.cgroup_path.to_string_lossy();
    match abs.strip_prefix(ROOT) {
        Some(rel) => {
            let trimmed = rel.trim_end_matches('/');
            if trimmed.is_empty() {
                Err(CgroupError::PathNotFound(format!(
                    "cgroup path {abs} is the root; expected a per-agent subpath"
                )))
            } else {
                Ok(trimmed.to_string())
            }
        }
        None => Err(CgroupError::PathNotFound(format!(
            "cgroup path {abs} does not start with {ROOT}"
        ))),
    }
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

    /// Create a transient systemd unit for an agent. Uses `systemd-run`
    /// in service mode with a `sleep infinity` placeholder to anchor the
    /// cgroup lifetime. `--no-block` ensures `systemd-run` returns promptly
    /// once the unit is queued; the caller (nfqueue verdict loop) then
    /// classifies real agent processes into the cgroup.
    ///
    /// systemd 255 rejects `--remain-after-exit` in `--scope` mode, so the
    /// older `--scope --remain-after-exit /bin/true` shape no longer works.
    /// Service units are the correct unit type for "create an empty cgroup
    /// that survives the create call."
    ///
    /// The `cgroup_path` returned is queried from systemd via
    /// `systemctl show --property=ControlGroup` (the canonical source of
    /// truth) rather than synthesized from the unit name. This avoids
    /// drift between the daemon's path assumption and where systemd 255
    /// actually places the cgroup, and it lets nft's
    /// `socket cgroupv2 level 2 "<path>"` rule lookup find the cgroup at
    /// rule-load time. Waits for the unit to reach `active` state before
    /// resolving so the cgroup inode is stable.
    pub fn create_agent_scope_impl(agent_id: &str) -> Result<ScopeHandle, CgroupError> {
        let unit = scope_unit_name(agent_id);
        let output = Command::new("systemd-run")
            .args([
                "--no-block",
                "--unit",
                &unit,
                "--property=Delegate=yes",
                "/usr/bin/sleep",
                "infinity",
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

        // Wait for the unit to reach `active` state so the placeholder
        // process is running and the cgroup is fully materialized. Up to
        // ~2s with 50ms polling. Without this, `--no-block` can return
        // while the unit is still in `activating`, the cgroup directory
        // is empty (cgroup.procs has no PID yet), and downstream
        // `nft -f -` rule loads can race the directory's full setup.
        let mut active = false;
        for _ in 0..40 {
            let status = Command::new("systemctl")
                .args(["is-active", "--quiet", &unit])
                .status();
            if matches!(status, Ok(s) if s.success()) {
                active = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !active {
            return Err(CgroupError::InvocationFailed(format!(
                "unit {unit} did not reach active state within 2s"
            )));
        }

        // Query systemd for the canonical ControlGroup path. The earlier
        // synthesized path (`/sys/fs/cgroup/system.slice/<unit>`) was a
        // best guess; systemd 255's actual placement under cgroup-v2 is
        // authoritative. The systemctl --value form returns just the
        // path, e.g. `/system.slice/sanctuary-agent-foo.service`.
        let show = Command::new("systemctl")
            .args(["show", &unit, "--property=ControlGroup", "--value"])
            .output()
            .map_err(|e| {
                CgroupError::InvocationFailed(format!("systemctl show ControlGroup: {e}"))
            })?;
        let control_group = String::from_utf8_lossy(&show.stdout).trim().to_string();
        if control_group.is_empty() {
            return Err(CgroupError::PathNotFound(format!(
                "unit {unit} has no ControlGroup"
            )));
        }
        let cgroup_path = PathBuf::from(format!("/sys/fs/cgroup{control_group}"));
        let cgroup_id = resolve_cgroup_id(&cgroup_path)?;
        // Depth in the cgroup-v2 hierarchy, counted from root. `control_group`
        // looks like `/system.slice/foo.service` (depth 2) or
        // `/system.slice/parent.service/foo.service` (depth 3) in nested
        // environments. Counting non-empty path components after the leading
        // slash gives the right number for nftables `level N` matching.
        let cgroup_level: u32 = control_group
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .count() as u32;

        Ok(ScopeHandle {
            agent_id: agent_id.to_string(),
            scope_unit: unit,
            cgroup_path,
            cgroup_id,
            cgroup_level,
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
        // Suffix is `.service` (not `.scope`): production switched to
        // `systemd-run --service` after systemd 255 rejected
        // `--remain-after-exit` in `--scope` mode.
        assert_eq!(
            scope_unit_name("my-agent"),
            "sanctuary-agent-my-agent.service"
        );
        assert_eq!(
            scope_unit_name("agent/with spaces"),
            "sanctuary-agent-agent_with_spaces.service"
        );
    }

    #[test]
    fn cgroup_path_for_scope_is_under_system_slice() {
        let path = cgroup_path_for_scope("sanctuary-agent-test.service");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/system.slice/sanctuary-agent-test.service")
        );
    }

    fn make_scope_handle(abs_path: &str, level: u32) -> ScopeHandle {
        ScopeHandle {
            agent_id: "x".to_string(),
            scope_unit: "sanctuary-agent-x.service".to_string(),
            cgroup_path: PathBuf::from(abs_path),
            cgroup_id: 0,
            cgroup_level: level,
        }
    }

    #[test]
    fn cgroup_relative_path_strips_canonical_prefix() {
        let h = make_scope_handle(
            "/sys/fs/cgroup/system.slice/sanctuary-agent-foo.service",
            2,
        );
        let rel = cgroup_relative_path(&h).expect("relative path");
        assert_eq!(rel, "system.slice/sanctuary-agent-foo.service");
    }

    #[test]
    fn cgroup_relative_path_handles_nested_depth() {
        let h = make_scope_handle(
            "/sys/fs/cgroup/system.slice/parent.service/sanctuary-agent-nested.service",
            3,
        );
        let rel = cgroup_relative_path(&h).expect("relative path");
        assert_eq!(
            rel,
            "system.slice/parent.service/sanctuary-agent-nested.service"
        );
    }

    #[test]
    fn cgroup_relative_path_rejects_non_canonical_prefix() {
        let h = make_scope_handle("/var/lib/docker/cgroups/foo", 2);
        assert!(matches!(
            cgroup_relative_path(&h),
            Err(CgroupError::PathNotFound(_))
        ));
    }

    #[test]
    fn cgroup_relative_path_trims_trailing_slash() {
        let h = make_scope_handle(
            "/sys/fs/cgroup/system.slice/sanctuary-agent-trim.service/",
            2,
        );
        let rel = cgroup_relative_path(&h).expect("relative path");
        assert_eq!(rel, "system.slice/sanctuary-agent-trim.service");
    }

    #[test]
    fn cgroup_relative_path_rejects_root() {
        let h = make_scope_handle("/sys/fs/cgroup/", 0);
        assert!(matches!(
            cgroup_relative_path(&h),
            Err(CgroupError::PathNotFound(_))
        ));
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
