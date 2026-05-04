//! cgroup v2 transient scope creation via systemd-run.
//!
//! PR 2a stub: declares the public surface that PR 2b will implement.
//! Per scope-lock §1: each wrapped agent runs in its own systemd transient
//! scope (`systemd-run --scope --user`); the daemon resolves the cgroup ID
//! via the systemd journal listener pattern from
//! systemd-cgroup-nftables-policy-manager (mk-fg).

use std::path::PathBuf;

/// Errors emitted by the cgroup module.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("cgroup operation not implemented in PR 2a (kernel enforcement lands in PR 2b)")]
    NotImplementedInPhase2a,
    #[error("systemd-run binary missing: {0}")]
    BinaryMissing(String),
    #[error("systemd-run invocation failed: {0}")]
    InvocationFailed(String),
}

/// A live cgroup identifier from systemd transient scope creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeHandle {
    pub agent_id: String,
    pub scope_unit: String,
    pub cgroup_path: PathBuf,
    pub cgroup_id: u64,
}

/// PR 2b: create a transient scope for an agent and resolve its cgroup id.
pub fn create_agent_scope(_agent_id: &str) -> Result<ScopeHandle, CgroupError> {
    Err(CgroupError::NotImplementedInPhase2a)
}

/// PR 2b: tear down a transient scope on agent shutdown / unwrap.
pub fn destroy_agent_scope(_handle: &ScopeHandle) -> Result<(), CgroupError> {
    Err(CgroupError::NotImplementedInPhase2a)
}

/// PR 2b: register a journal listener that re-installs nftables rules if
/// the agent's transient scope is destroyed and recreated under a new
/// cgroup id (the cgroup-id-renumbering gotcha).
pub fn register_scope_journal_listener() -> Result<(), CgroupError> {
    Err(CgroupError::NotImplementedInPhase2a)
}
