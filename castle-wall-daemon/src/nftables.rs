//! nftables CLI shell-out wrappers.
//!
//! Per scope-lock section 1 Option A: the daemon shells out to the `nft` binary
//! with atomic ruleset replacement, installs rules in a dedicated
//! `sanctuary-castle` table (E7.2 namespace separation), binds rules to
//! cgroup IDs via `socket cgroupv2 level N "<scope-path>"` matches.
//!
//! All kernel-touching functions are `#[cfg(target_os = "linux")]`-gated;
//! on macOS (the dev sandbox) the stubs return structured errors so
//! `cargo check` passes cross-platform.

use std::path::PathBuf;

/// Errors emitted by the nftables module.
#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables not available on this platform")]
    NotAvailableOnPlatform,
    #[error("nft binary missing: {0}")]
    BinaryMissing(String),
    #[error("nft invocation failed: {0}")]
    InvocationFailed(String),
    #[error("failed to parse nft output: {0}")]
    ParseFailed(String),
}

/// Identifier for a wrapped agent's cgroup-bound ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRulesetId {
    pub agent_id: String,
    pub cgroup_path: PathBuf,
}

/// The dedicated nftables table name. Per scope-lock section 7 E7.2, the daemon
/// installs into its own table so it never conflicts with ufw / firewalld /
/// operator rules.
pub const CASTLE_TABLE: &str = "sanctuary-castle";

/// The nftables table family. `inet` covers both IPv4 and IPv6.
pub const CASTLE_FAMILY: &str = "inet";
const NFT_CHAIN_MAX_LEN: usize = 256;
const AGENT_CHAIN_PREFIX: &str = "agent_";

/// A single nftables rule fragment generated from a PolicySnapshot rule.
#[derive(Debug, Clone)]
pub struct NftRuleFragment {
    /// The allowlist rule id this fragment was generated from.
    pub rule_id: String,
    /// nft rule expression (e.g., `ip daddr 1.2.3.4 tcp dport 443 accept`).
    pub nft_expr: String,
}

/// Translate a PolicySnapshot into nftables rule fragments for one agent.
/// The fragments are installed inside a per-agent chain within the
/// `sanctuary-castle` table. The chain ends with a `queue num 0` verdict
/// for any unmatched traffic (NFQUEUE with FAIL_OPEN explicitly off).
///
/// `cgroup_relative_path` is the cgroup-v2 path with the `/sys/fs/cgroup/`
/// prefix stripped, e.g. `system.slice/sanctuary-agent-foo.service`. nft
/// expects a quoted path string at rule-load time and walks
/// `/sys/fs/cgroup/<path>` at depth `cgroup_level` to validate the cgroup
/// exists. Earlier production code emitted the cgroup inode integer
/// instead, which nft 1.x rejects: the integer is the post-resolution
/// internal form (what `nft list rules` displays back), not the documented
/// input form. Compute the relative path via `cgroup::cgroup_relative_path`
/// from a `ScopeHandle.cgroup_path`.
///
/// `cgroup_level` is the depth at which the agent's cgroup lives in the
/// cgroup-v2 hierarchy (counted from `/sys/fs/cgroup` as depth 0). It comes
/// from `cgroup::ScopeHandle::cgroup_level`, which is derived from
/// systemd's reported ControlGroup. If the level is wrong (because the
/// deployment is nested), nft rejects with "cgroupv2 path fails: No such
/// file or directory". Threading the actual level through avoids that.
pub fn build_agent_ruleset(
    agent_id: &str,
    cgroup_relative_path: &str,
    cgroup_level: u32,
    rules: &[NftRuleFragment],
) -> String {
    let chain_name = agent_chain_name(agent_id);
    let agent_mark = crate::nfqueue::register_agent_mark(agent_id);
    let mut script = String::new();
    // Atomic replace: flush the chain then re-add all rules.
    script.push_str(&format!(
        "flush chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n"
    ));
    // cgroup match: only packets from this agent's cgroup enter this chain.
    // The cgroup match is installed as a jump rule in the base output chain.
    for frag in rules {
        // Each rule fragment is a complete nft rule expression.
        script.push_str(&format!(
            "add rule {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name} {}\n",
            frag.nft_expr
        ));
    }
    // Default: send unmatched traffic to NFQUEUE 0 for userspace verdict.
    // Per scope-lock section 1: `queue num 0` without `bypass` flag.
    script.push_str(&format!(
        "add rule {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name} \
         socket cgroupv2 level {cgroup_level} \"{cgroup_relative_path}\" \
         meta mark set 0x{agent_mark:08x} queue num 0\n"
    ));
    script
}

/// Build the jump rule that routes packets from an agent's cgroup-v2
/// directory into its per-agent chain in the `sanctuary-castle` output
/// chain. Pure helper: emits the nft rule string only; callers shell out
/// to apply it.
///
/// The base `output` chain created by [`install_castle_table`] is hooked
/// into netfilter (`type filter hook output priority 0`) but has no rules
/// of its own. Per-agent chains are non-base chains and stay dead until
/// something jumps to them. This helper produces the `goto agent_<id>`
/// rule that gates entry into the per-agent chain on the cgroup-v2
/// `socket cgroupv2 level <N> "<path>"` match: only packets owned by a
/// socket inside the agent's cgroup transit the per-agent rules. Every
/// other packet in the operator's host (browser, OS daemons, the
/// operator's other apps) flows past the jump and is allowed by the base
/// chain's `policy accept`.
///
/// The path is quoted at emission time (the same correctness invariant
/// pinned for [`build_agent_ruleset`] in PR #130). `cgroup_level` mirrors
/// the same dynamic-depth shape: depth 2 in canonical
/// `system.slice/<unit>` placement, deeper for nested deployments.
pub fn build_agent_jump_rule(
    agent_id: &str,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> String {
    let chain_name = agent_chain_name(agent_id);
    format!(
        "add rule {CASTLE_FAMILY} {CASTLE_TABLE} output \
         socket cgroupv2 level {cgroup_level} \"{cgroup_relative_path}\" goto {chain_name}"
    )
}

/// Build a fail-closed per-agent chain body for a refreshed cgroup.
///
/// During systemd scope recreation there is a short interval where the old
/// base-chain jump points at an obsolete cgroup identity and the new cgroup
/// identity is not yet wired. This ruleset is the first stage of refresh:
/// replace the per-agent chain with a single drop verdict, then wire the
/// refreshed cgroup jump to it before the normal policy rules are restored.
pub fn build_agent_fail_closed_ruleset(agent_id: &str) -> String {
    let chain_name = agent_chain_name(agent_id);
    format!(
        "flush chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n\
         add rule {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name} drop\n"
    )
}

/// Derive a sanitized chain name from an agent id.
pub(crate) fn agent_chain_name(agent_id: &str) -> String {
    let max_component_len = NFT_CHAIN_MAX_LEN - AGENT_CHAIN_PREFIX.len();
    let encoded = crate::identity::encode_agent_component(agent_id, max_component_len);
    format!("{AGENT_CHAIN_PREFIX}{encoded}")
}

// ---- Linux implementations ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;

    /// Locate the `nft` binary.
    fn nft_path() -> Result<&'static str, NftablesError> {
        // Common locations; prefer the one in PATH.
        for candidate in &["/usr/sbin/nft", "/sbin/nft", "nft"] {
            let status = Command::new("which")
                .arg(candidate)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if let Ok(s) = status {
                if s.success() {
                    // Leak a &'static str for the path. In practice we call
                    // this at most once per daemon lifetime.
                    return Ok(match *candidate {
                        "/usr/sbin/nft" => "/usr/sbin/nft",
                        "/sbin/nft" => "/sbin/nft",
                        _ => "nft",
                    });
                }
            }
        }
        Err(NftablesError::BinaryMissing(
            "nft binary not found in /usr/sbin, /sbin, or PATH".to_string(),
        ))
    }

    fn run_nft(args: &[&str]) -> Result<String, NftablesError> {
        let nft = nft_path()?;
        let output = Command::new(nft)
            .args(args)
            .output()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft {} exited {}: {}",
                args.join(" "),
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_nft_stdin(script: &str) -> Result<(), NftablesError> {
        let nft = nft_path()?;
        let mut child = Command::new(nft)
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft -f - exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    pub fn install_castle_table_impl() -> Result<(), NftablesError> {
        // Create the table if it does not exist. nft add is idempotent.
        run_nft(&["add", "table", CASTLE_FAMILY, CASTLE_TABLE])?;
        // Create a base output chain that hooks into the output path.
        // type filter hook output priority 0 ensures we see all egress.
        let chain_script = format!(
            "add chain {CASTLE_FAMILY} {CASTLE_TABLE} output \
             {{ type filter hook output priority 0 ; policy accept ; }}\n"
        );
        // Ignore error if chain already exists (idempotent).
        let _ = run_nft_stdin(&chain_script);
        Ok(())
    }

    fn replace_agent_chain_and_jump_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // Ensure the per-agent chain exists.
        let create = format!("add chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n");
        let _ = run_nft_stdin(&create);

        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, CASTLE_TABLE, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                String::new()
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);

        let mut script = String::new();
        script.push_str(ruleset_script);
        for handle in handles {
            script.push_str(&format!(
                "delete rule {CASTLE_FAMILY} {CASTLE_TABLE} output handle {handle}\n"
            ));
        }
        let rule = build_agent_jump_rule(&id.agent_id, cgroup_level, cgroup_relative_path);
        script.push_str(&format!("{rule}\n"));
        run_nft_stdin(&script)
    }

    pub fn load_agent_ruleset_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        // Atomically replace the per-agent chain body and the base output
        // jump that reaches it. This keeps policy reloads and cgroup refresh
        // from leaking a stale jump to an old cgroup identity.
        replace_agent_chain_and_jump_impl(id, ruleset_script, cgroup_level, cgroup_relative_path)
    }

    pub fn load_agent_fail_closed_ruleset_impl(
        id: &AgentRulesetId,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        let ruleset_script = build_agent_fail_closed_ruleset(&id.agent_id);
        replace_agent_chain_and_jump_impl(id, &ruleset_script, cgroup_level, cgroup_relative_path)
    }

    pub fn remove_agent_ruleset_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // Remove the base-chain jump rule first so it does not dangle
        // pointing at a deleted chain. Idempotent: missing rule is fine.
        let _ = remove_agent_jump_rule_impl(id);
        // Flush rules first, then delete the chain.
        let script = format!(
            "flush chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n\
             delete chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n"
        );
        run_nft_stdin(&script)
    }

    /// Install the jump rule from the base `output` chain into this agent's
    /// per-agent chain, gated on the cgroup-v2 socket match. Idempotent:
    /// any prior jump rule pointing at the same agent's chain is removed
    /// (handle-based delete) before the new rule is added. This lets the
    /// function double as both the fresh-install and policy-reload path
    /// without leaking stale jumps.
    pub fn install_agent_jump_rule_impl(
        id: &AgentRulesetId,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        // Drop any existing jump rule for this agent before adding a new
        // one. Failures during the lookup are not fatal here: a missing
        // base chain (table just created, nothing in output yet) returns
        // an error from `nft -a list chain`; the upcoming add will fail
        // with a clearer message if the table is genuinely absent.
        let _ = remove_agent_jump_rule_impl(id);
        let rule = build_agent_jump_rule(&id.agent_id, cgroup_level, cgroup_relative_path);
        let script = format!("{rule}\n");
        run_nft_stdin(&script)
    }

    /// Remove the jump rule from the base `output` chain that targets this
    /// agent's per-agent chain. Idempotent: zero matching rules returns
    /// `Ok(())` rather than an error so policy-reload code paths can call
    /// it unconditionally.
    pub fn remove_agent_jump_rule_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // `-a` annotates each rule with `# handle <N>`; we parse those
        // handles for any rule whose verdict targets our chain.
        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, CASTLE_TABLE, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                // Base chain absent (table was deleted or never installed).
                // Treat as zero matching rules.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);
        for handle in handles {
            run_nft(&[
                "delete",
                "rule",
                CASTLE_FAMILY,
                CASTLE_TABLE,
                "output",
                "handle",
                &handle.to_string(),
            ])?;
        }
        Ok(())
    }

    /// Parse `nft -a list chain ... output` output, returning the handle
    /// integer for every rule whose verdict is `goto <chain_name>`. The
    /// match is token-precise (no substring match) so chain names that
    /// share a prefix (`agent_foo`, `agent_foo_bar`) do not collide.
    pub(super) fn parse_jump_rule_handles(listing: &str, chain_name: &str) -> Vec<u64> {
        let mut handles = Vec::new();
        for line in listing.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Find a `goto <chain_name>` token pair. nft also emits `jump`
            // for non-terminating verdicts; we only emit `goto` so we
            // restrict the match to that.
            let has_goto = tokens
                .iter()
                .enumerate()
                .any(|(i, tok)| *tok == "goto" && tokens.get(i + 1) == Some(&chain_name));
            if !has_goto {
                continue;
            }
            // Extract handle from "# handle <N>". `nft -a` always emits
            // both tokens together at the end of the rule line.
            if let Some(handle_idx) = tokens.iter().position(|t| *t == "handle") {
                if handle_idx > 0 && tokens[handle_idx - 1] == "#" {
                    if let Some(handle_tok) = tokens.get(handle_idx + 1) {
                        if let Ok(h) = handle_tok.parse::<u64>() {
                            handles.push(h);
                        }
                    }
                }
            }
        }
        handles
    }

    pub fn list_agent_rulesets_impl() -> Result<Vec<AgentRulesetId>, NftablesError> {
        let output = run_nft(&["list", "chains", CASTLE_FAMILY])?;
        let mut results = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("chain agent_") {
                // Extract chain name between "chain " and the next space or '{'
                if let Some(name) = trimmed
                    .strip_prefix("chain ")
                    .and_then(|s| s.split_whitespace().next())
                {
                    if let Some(agent_id) = name.strip_prefix("agent_") {
                        results.push(AgentRulesetId {
                            agent_id: agent_id.to_string(),
                            cgroup_path: PathBuf::new(),
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    pub fn remove_castle_table_impl() -> Result<(), NftablesError> {
        run_nft(&["delete", "table", CASTLE_FAMILY, CASTLE_TABLE]).map(|_| ())
    }

    pub fn table_exists_impl() -> Result<bool, NftablesError> {
        match run_nft(&["list", "table", CASTLE_FAMILY, CASTLE_TABLE]) {
            Ok(_) => Ok(true),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}

// ---- Public API (platform-dispatching) ------------------------------------

/// Install the dedicated `sanctuary-castle` table if absent.
/// Per scope-lock section 7 E7.2: namespace separation from the operator's
/// existing firewall (ufw, firewalld, etc.).
#[cfg(target_os = "linux")]
pub fn install_castle_table() -> Result<(), NftablesError> {
    linux::install_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn install_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Load a ruleset for one agent's cgroup. Atomic replace on the per-agent
/// chain; existing connections preserved per nftables atomic-replace
/// semantics. Also installs (or refreshes) the jump rule in the base
/// `output` chain that gates entry into the per-agent chain on the
/// cgroup-v2 socket match. Without that jump rule the per-agent chain is
/// a dead chain and the kernel never consults it.
///
/// `cgroup_level` is the depth of the agent's cgroup in the cgroup-v2
/// hierarchy (matches `ScopeHandle::cgroup_level`). `cgroup_relative_path`
/// is the path with the `/sys/fs/cgroup/` prefix stripped (matches
/// [`crate::cgroup::cgroup_relative_path`]).
#[cfg(target_os = "linux")]
pub fn load_agent_ruleset(
    id: &AgentRulesetId,
    ruleset: &str,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    linux::load_agent_ruleset_impl(id, ruleset, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_ruleset(
    _id: &AgentRulesetId,
    _ruleset: &str,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Replace an agent ruleset with a fail-closed drop chain and atomically wire
/// the refreshed cgroup jump to that chain. Used during scope recreation
/// before the normal policy ruleset is restored.
#[cfg(target_os = "linux")]
pub fn load_agent_fail_closed_ruleset(
    id: &AgentRulesetId,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    linux::load_agent_fail_closed_ruleset_impl(id, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_fail_closed_ruleset(
    _id: &AgentRulesetId,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove an agent's ruleset (called on agent shutdown / unwrap). Removes
/// the base-chain jump rule first so it does not dangle pointing at a
/// deleted chain, then flushes and deletes the per-agent chain.
#[cfg(target_os = "linux")]
pub fn remove_agent_ruleset(id: &AgentRulesetId) -> Result<(), NftablesError> {
    linux::remove_agent_ruleset_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_ruleset(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Install the jump rule from the base `output` chain into the per-agent
/// chain, gated on the cgroup-v2 socket match. Idempotent: a prior jump
/// rule for the same agent is removed (handle-based delete) before the
/// new one is added.
///
/// Most callers should use [`load_agent_ruleset`], which combines the
/// per-agent chain rules with the jump-rule wiring in one call. This
/// granular surface is exposed for binding code that needs to refresh
/// the jump rule independently (e.g., on a cgroup-id renumbering event
/// where the chain rules have not changed).
#[cfg(target_os = "linux")]
pub fn install_agent_jump_rule(
    id: &AgentRulesetId,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    linux::install_agent_jump_rule_impl(id, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn install_agent_jump_rule(
    _id: &AgentRulesetId,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the jump rule from the base `output` chain that targets this
/// agent's per-agent chain. Idempotent: zero matching rules returns
/// `Ok(())`.
#[cfg(target_os = "linux")]
pub fn remove_agent_jump_rule(id: &AgentRulesetId) -> Result<(), NftablesError> {
    linux::remove_agent_jump_rule_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_jump_rule(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// List current agent rulesets in `sanctuary-castle`.
#[cfg(target_os = "linux")]
pub fn list_agent_rulesets() -> Result<Vec<AgentRulesetId>, NftablesError> {
    linux::list_agent_rulesets_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn list_agent_rulesets() -> Result<Vec<AgentRulesetId>, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the entire `sanctuary-castle` table. Used during daemon shutdown
/// cleanup or in tests.
#[cfg(target_os = "linux")]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    linux::remove_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Check whether the sanctuary-castle table exists.
#[cfg(target_os = "linux")]
pub fn table_exists() -> Result<bool, NftablesError> {
    linux::table_exists_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn table_exists() -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Translate a single AllowlistRule into nft rule expression fragments.
///
/// Destination-constrained rules deliberately do not emit static nft
/// accept/drop verdicts: those decisions must stay on the NFQUEUE verdict path
/// where the daemon evaluates the full match clause against the signed policy.
/// `host` / `host_pattern` rules stay on that path because nft cannot verify
/// resolved-hostname context. `ip` / `cidr` rules stay on it too: lowering a
/// rule that carries an ip/cidr axis to a bare `proto dport N <verdict>` would
/// DROP the address constraint and widen the rule to every destination on that
/// port. The reserved loopback distress rule (`ip:[127.0.0.1,::1] port:8741`)
/// would otherwise become `tcp dport 8741 accept` for any host, breaking the
/// loopback-only invariant (codex round-3). Until the lowering emits `ip
/// daddr` / `ip6 daddr` matchers, such rules stay on the evaluator path where
/// the new ip/cidr matching ([`crate::policy::RuleMatch::matches`]) enforces
/// them. Only rules with NO destination axis (port/protocol only, or fully
/// open) are safe to lower directly into nftables.
pub fn rule_to_nft_expr(rule: &crate::policy::AllowlistRule) -> Vec<NftRuleFragment> {
    let mut frags = Vec::new();
    let disposition_expr = match rule.disposition {
        crate::policy::RuleDisposition::Allow => "accept",
        crate::policy::RuleDisposition::Deny => "drop",
        // Prompt rules are handled by the NFQUEUE verdict loop; they do NOT
        // produce static nftables rules. The NFQUEUE catch-all at the end of
        // the chain handles them.
        crate::policy::RuleDisposition::Prompt => return frags,
    };

    let port_expr = if let Some(ports) = rule.match_clause.port.as_ref() {
        if ports.len() == 1 {
            format!("dport {}", ports[0])
        } else {
            let set: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            format!("dport {{ {} }}", set.join(", "))
        }
    } else {
        String::new()
    };

    let proto = rule
        .match_clause
        .protocol
        .as_deref()
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    if rule.match_clause.host.is_some()
        || rule.match_clause.host_pattern.is_some()
        || rule.match_clause.ip.is_some()
        || rule.match_clause.cidr.is_some()
    {
        return frags;
    }

    let mut expr = proto.to_string();
    if !port_expr.is_empty() {
        expr.push_str(&format!(" {port_expr}"));
    }
    expr.push_str(&format!(" {disposition_expr}"));
    frags.push(NftRuleFragment {
        rule_id: rule.id.clone(),
        nft_expr: expr,
    });

    frags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowlistRule, RuleDisposition, RuleMatch, RuleScope};

    fn make_rule(
        id: &str,
        host: Option<Vec<&str>>,
        port: Option<Vec<u16>>,
        proto: Option<&str>,
        disposition: RuleDisposition,
    ) -> AllowlistRule {
        AllowlistRule {
            id: id.to_string(),
            schema_version: 1,
            created_at: "2026-05-05T00:00:00Z".to_string(),
            description: None,
            match_clause: RuleMatch {
                host: host.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
                host_pattern: None,
                ip: None,
                cidr: None,
                port,
                protocol: proto.map(|s| s.to_string()),
            },
            scope: RuleScope::default(),
            disposition,
            time_window: None,
            derived: None,
        }
    }

    #[test]
    fn agent_chain_name_sanitizes() {
        assert_eq!(agent_chain_name("my-agent"), "agent_my-agent");
        assert_eq!(
            agent_chain_name("agent/with spaces"),
            "agent_agent_x2f_with_x20_spaces"
        );
    }

    #[test]
    fn agent_chain_name_does_not_collapse_colliding_agent_ids() {
        let slash_agent = agent_chain_name("agent/a");
        let underscore_agent = agent_chain_name("agent_a");
        assert_ne!(slash_agent, underscore_agent);
        assert_eq!(slash_agent, "agent_agent_x2f_a");
        assert_eq!(underscore_agent, "agent_agent_a");
    }

    #[test]
    fn agent_chain_name_stays_within_nft_budget() {
        let chain = agent_chain_name(&format!("agent/{}", "x".repeat(400)));
        assert!(chain.len() <= NFT_CHAIN_MAX_LEN);
        assert!(chain.starts_with(AGENT_CHAIN_PREFIX));
    }

    #[test]
    fn build_agent_ruleset_includes_cgroup_queue() {
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "test-agent",
            "system.slice/sanctuary-agent-test.service",
            2,
            &frags,
        );
        assert!(script.contains("flush chain"));
        assert!(script.contains("tcp dport 443 accept"));
        assert!(script.contains("queue num 0"));
        assert!(script.contains("meta mark set"));
        // Path is quoted, comes after the level, no leading slash. Level 2
        // is the canonical depth for `/system.slice/<unit>`; nested
        // deployments pass higher values, hence the rule encoding the level.
        assert!(
            script.contains("level 2 \"system.slice/sanctuary-agent-test.service\""),
            "rule must emit quoted cgroup-relative path after level: {script}"
        );
    }

    #[test]
    fn build_agent_ruleset_threads_dynamic_level() {
        // In nested environments (CI runners, Docker-in-Docker) the agent's
        // cgroup may be at depth 3 or 4; the rule must reflect that or nft
        // rejects with "cgroupv2 path fails" at load time.
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "nested",
            "system.slice/parent.service/sanctuary-agent-nested.service",
            3,
            &frags,
        );
        assert!(script
            .contains("level 3 \"system.slice/parent.service/sanctuary-agent-nested.service\""));
        assert!(!script.contains("level 2"));
    }

    #[test]
    fn build_agent_ruleset_registers_mark_for_nfqueue_attribution() {
        let script = build_agent_ruleset(
            "attributed-agent",
            "system.slice/sanctuary-agent-attributed-agent.service",
            2,
            &[],
        );
        let mark = crate::nfqueue::agent_mark("attributed-agent");
        assert!(
            script.contains(&format!("meta mark set 0x{mark:08x} queue num 0")),
            "catchall must set a per-agent mark before NFQUEUE: {script}"
        );
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            Some("attributed-agent".to_string())
        );
    }

    #[test]
    fn build_agent_ruleset_emits_quoted_path_not_inode_integer() {
        // Regression guard: earlier production code emitted the post-resolution
        // inode integer where nft expects a quoted cgroup-relative path string.
        // nft 1.x rejects integer input at rule-load time. This test pins the
        // emission to the documented input form.
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "regression",
            "system.slice/sanctuary-agent-regression.service",
            2,
            &frags,
        );
        // Path must be quoted.
        assert!(
            script.contains("\"system.slice/sanctuary-agent-regression.service\""),
            "cgroup path must be quoted: {script}"
        );
        // Must not emit a bare integer where the path goes (i.e. no
        // `level 2 <digit>` pattern without a quote).
        let lines: Vec<&str> = script.lines().filter(|l| l.contains("cgroupv2")).collect();
        assert_eq!(lines.len(), 1, "exactly one cgroupv2 rule expected");
        let cgroupv2_line = lines[0];
        let post_level = cgroupv2_line
            .split("level 2 ")
            .nth(1)
            .expect("expected 'level 2 ' marker");
        assert!(
            post_level.starts_with('"'),
            "after 'level 2 ' nft requires a quoted path, got: {post_level}"
        );
    }

    #[test]
    fn rule_to_nft_expr_allow_with_host_and_port_stays_on_nfqueue() {
        let r = make_rule(
            "r1",
            Some(vec!["api.anthropic.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host allow rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_deny_no_host() {
        let r = make_rule(
            "r2",
            None,
            Some(vec![80, 8080]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        let frags = rule_to_nft_expr(&r);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].nft_expr.contains("drop"));
        assert!(frags[0].nft_expr.contains("dport { 80, 8080 }"));
    }

    #[test]
    fn rule_to_nft_expr_prompt_produces_no_fragments() {
        let r = make_rule(
            "r3",
            Some(vec!["example.com"]),
            None,
            None,
            RuleDisposition::Prompt,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(frags.is_empty());
    }

    #[test]
    fn rule_to_nft_expr_multiple_hosts_stays_on_nfqueue() {
        let r = make_rule(
            "r4",
            Some(vec!["a.com", "b.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "multi-host rules must not emit comment-only static verdicts"
        );
    }

    #[test]
    fn rule_to_nft_expr_host_pattern_stays_on_nfqueue() {
        let mut r = make_rule(
            "r5",
            None,
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        r.match_clause.host_pattern = Some(".example.com".to_string());
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host-pattern rules must not become static port-wide nft drops"
        );
    }

    #[test]
    fn rule_to_nft_expr_ip_axis_stays_on_nfqueue() {
        // An ip-pinned rule (the genuine reserved local distress shape) must
        // NOT lower to a bare `tcp dport 8741 accept` that would grant the port
        // to ANY destination — the loopback constraint would be lost in the
        // kernel (codex round-3). It stays on the evaluator path.
        let mut r = make_rule("r-ip", None, Some(vec![8741]), Some("tcp"), RuleDisposition::Allow);
        r.match_clause.ip = Some(vec!["127.0.0.1".to_string(), "::1".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "ip-pinned rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_cidr_axis_stays_on_nfqueue() {
        let mut r = make_rule("r-cidr", None, Some(vec![8741]), Some("tcp"), RuleDisposition::Deny);
        r.match_clause.cidr = Some(vec!["10.0.0.0/8".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "cidr rules must not become static port-wide nft drops"
        );
    }

    // ---- build_agent_jump_rule pure-helper tests --------------------------

    #[test]
    fn build_agent_jump_rule_emits_canonical_shape() {
        // Pin the exact rule string for the canonical case: depth-2 cgroup
        // under system.slice, single-segment agent id. This is what the
        // base output chain needs to route packets from the agent's cgroup
        // into the per-agent chain.
        let rule = build_agent_jump_rule("alpha", 2, "system.slice/sanctuary-agent-alpha.service");
        assert_eq!(
            rule,
            "add rule inet sanctuary-castle output \
             socket cgroupv2 level 2 \"system.slice/sanctuary-agent-alpha.service\" \
             goto agent_alpha"
        );
    }

    #[test]
    fn build_agent_jump_rule_quotes_cgroup_path() {
        // Defense against the integer-bug recurrence pattern PR #130 fixed
        // for build_agent_ruleset: nft 1.x rejects unquoted path strings
        // and unquoted integer-only inputs at rule-load time. The jump
        // rule must always emit a quoted path.
        let rule = build_agent_jump_rule(
            "regression",
            2,
            "system.slice/sanctuary-agent-regression.service",
        );
        assert!(
            rule.contains("\"system.slice/sanctuary-agent-regression.service\""),
            "cgroup path must be quoted: {rule}"
        );
        // No bare integer where the path goes.
        let post_level = rule
            .split("level 2 ")
            .nth(1)
            .expect("expected 'level 2 ' marker");
        assert!(
            post_level.starts_with('"'),
            "after 'level 2 ' nft requires a quoted path, got: {post_level}"
        );
    }

    #[test]
    fn build_agent_jump_rule_threads_dynamic_level() {
        // Mirror the build_agent_ruleset dynamic-depth shape: nested
        // deployments place the agent's cgroup deeper than depth 2, and
        // the jump rule must reflect the actual depth or nft rejects with
        // "cgroupv2 path fails".
        let rule = build_agent_jump_rule(
            "nested",
            3,
            "system.slice/parent.service/sanctuary-agent-nested.service",
        );
        assert!(
            rule.contains("level 3 \"system.slice/parent.service/sanctuary-agent-nested.service\"")
        );
        assert!(!rule.contains("level 2"));
    }

    #[test]
    fn build_agent_jump_rule_chain_name_matches_agent_chain_name() {
        // The goto target must match agent_chain_name(agent_id) exactly so
        // the per-agent chain created by load_agent_ruleset_impl is the
        // chain reached by this jump.
        for agent_id in &["alpha", "my-agent", "team_a.svc1", "weird/id"] {
            let rule = build_agent_jump_rule(agent_id, 2, "system.slice/x.service");
            let chain = agent_chain_name(agent_id);
            assert!(
                rule.ends_with(&format!("goto {chain}")),
                "jump rule must end with goto <chain_name> matching agent_chain_name; \
                 agent={agent_id} chain={chain} rule={rule}"
            );
        }
    }

    #[test]
    fn build_agent_fail_closed_ruleset_drops_everything_in_chain() {
        let script = build_agent_fail_closed_ruleset("refresh-agent");
        assert!(script.contains("flush chain inet sanctuary-castle agent_refresh-agent"));
        assert!(script.contains("add rule inet sanctuary-castle agent_refresh-agent drop"));
        assert!(
            !script.contains("queue"),
            "refresh fail-closed stage must drop rather than queue: {script}"
        );
    }

    // ---- parse_jump_rule_handles tests ------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_matches_target_chain_only() {
        // Synthetic `nft -a list chain` output with three rules: one
        // jumping to our chain, one jumping to a different chain, one
        // doing something else entirely.
        let listing = "\
table inet sanctuary-castle {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tsocket cgroupv2 level 2 \"system.slice/sanctuary-agent-alpha.service\" goto agent_alpha # handle 5
\t\tsocket cgroupv2 level 2 \"system.slice/sanctuary-agent-beta.service\" goto agent_beta # handle 7
\t\tudp dport 53 accept # handle 9
\t}
}";
        let handles = linux::parse_jump_rule_handles(listing, "agent_alpha");
        assert_eq!(handles, vec![5]);
        let handles_beta = linux::parse_jump_rule_handles(listing, "agent_beta");
        assert_eq!(handles_beta, vec![7]);
        let handles_missing = linux::parse_jump_rule_handles(listing, "agent_gamma");
        assert!(handles_missing.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_does_not_substring_match() {
        // Critical correctness invariant: chain names that share a prefix
        // (`agent_foo` and `agent_foo_bar`) must not collide. A naive
        // substring match for `agent_foo` would wrongly hit the line
        // ending in `goto agent_foo_bar`.
        let listing = "\
\t\tsocket cgroupv2 level 2 \"system.slice/foo.service\" goto agent_foo # handle 11
\t\tsocket cgroupv2 level 2 \"system.slice/foo_bar.service\" goto agent_foo_bar # handle 13
";
        let handles_foo = linux::parse_jump_rule_handles(listing, "agent_foo");
        assert_eq!(handles_foo, vec![11], "must not match agent_foo_bar");
        let handles_foo_bar = linux::parse_jump_rule_handles(listing, "agent_foo_bar");
        assert_eq!(handles_foo_bar, vec![13]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_collects_all_duplicates() {
        // If a prior install-and-no-remove path leaked stale jumps for the
        // same agent (the bug shape `install_agent_jump_rule_impl`'s
        // delete-then-add prevents going forward), the parser must surface
        // every handle so a remove call cleans them all out.
        let listing = "\
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 21
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 22
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 23
";
        let handles = linux::parse_jump_rule_handles(listing, "agent_dup");
        assert_eq!(handles, vec![21, 22, 23]);
    }
}
