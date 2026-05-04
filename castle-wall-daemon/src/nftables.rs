//! nftables CLI shell-out wrappers.
//!
//! PR 2a stub: declares the public surface that PR 2b will implement.
//! Per scope-lock §1 Option A: the daemon shells out to the `nft` binary
//! with atomic ruleset replacement, installs rules in a dedicated
//! `sanctuary-castle` table (E7.2 namespace separation), binds rules to
//! cgroup IDs via `socket cgroupv2 level N "<scope-path>"` matches.

use std::path::PathBuf;

/// Errors emitted by the nftables module.
#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables operation not implemented in PR 2a (kernel enforcement lands in PR 2b)")]
    NotImplementedInPhase2a,
    #[error("nft binary missing: {0}")]
    BinaryMissing(String),
    #[error("nft invocation failed: {0}")]
    InvocationFailed(String),
}

/// Identifier for a wrapped agent's cgroup-bound ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRulesetId {
    pub agent_id: String,
    pub cgroup_path: PathBuf,
}

/// PR 2b: install the dedicated `sanctuary-castle` table if absent.
pub fn install_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotImplementedInPhase2a)
}

/// PR 2b: load a ruleset for one agent's cgroup. Atomic replace on the
/// per-agent named table; existing connections preserved per nftables
/// atomic-replace semantics.
pub fn load_agent_ruleset(_id: &AgentRulesetId, _ruleset: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotImplementedInPhase2a)
}

/// PR 2b: remove an agent's ruleset (called on agent shutdown / unwrap).
pub fn remove_agent_ruleset(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotImplementedInPhase2a)
}

/// PR 2b: list current agent rulesets in `sanctuary-castle`.
pub fn list_agent_rulesets() -> Result<Vec<AgentRulesetId>, NftablesError> {
    Err(NftablesError::NotImplementedInPhase2a)
}
