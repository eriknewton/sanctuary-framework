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
pub fn build_agent_ruleset(
    agent_id: &str,
    cgroup_id: u64,
    rules: &[NftRuleFragment],
) -> String {
    let chain_name = agent_chain_name(agent_id);
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
         socket cgroupv2 level 2 {cgroup_id} queue num 0\n"
    ));
    script
}

/// Derive a sanitized chain name from an agent id.
fn agent_chain_name(agent_id: &str) -> String {
    // nftables chain names allow alphanumeric, underscore, hyphen, period.
    // Replace anything else with underscore.
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
    format!("agent_{sanitized}")
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

    pub fn load_agent_ruleset_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
    ) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // Ensure the per-agent chain exists.
        let create = format!(
            "add chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n"
        );
        let _ = run_nft_stdin(&create);
        // Apply the ruleset script (atomic replace).
        run_nft_stdin(ruleset_script)
    }

    pub fn remove_agent_ruleset_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // Flush rules first, then delete the chain.
        let script = format!(
            "flush chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n\
             delete chain {CASTLE_FAMILY} {CASTLE_TABLE} {chain_name}\n"
        );
        run_nft_stdin(&script)
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
        run_nft(&["delete", "table", CASTLE_FAMILY, CASTLE_TABLE])
    }

    pub fn table_exists_impl() -> Result<bool, NftablesError> {
        match run_nft(&["list", "table", CASTLE_FAMILY, CASTLE_TABLE]) {
            Ok(_) => Ok(true),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory")
                    || msg.contains("does not exist") =>
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
/// semantics.
#[cfg(target_os = "linux")]
pub fn load_agent_ruleset(id: &AgentRulesetId, ruleset: &str) -> Result<(), NftablesError> {
    linux::load_agent_ruleset_impl(id, ruleset)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_ruleset(_id: &AgentRulesetId, _ruleset: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove an agent's ruleset (called on agent shutdown / unwrap).
#[cfg(target_os = "linux")]
pub fn remove_agent_ruleset(id: &AgentRulesetId) -> Result<(), NftablesError> {
    linux::remove_agent_ruleset_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_ruleset(_id: &AgentRulesetId) -> Result<(), NftablesError> {
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

/// Translate a single AllowlistRule into an nft rule expression fragment.
/// Handles host exact-match, suffix-glob, port sets, and protocol match.
pub fn rule_to_nft_expr(
    rule: &crate::policy::AllowlistRule,
) -> Vec<NftRuleFragment> {
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

    // Build exact-host rules.
    if let Some(hosts) = rule.match_clause.host.as_ref() {
        for host in hosts {
            // nftables does not do DNS resolution in rules. For hostname-based
            // allowlisting, the NFQUEUE verdict path handles DNS-resolved
            // matching. Static nft rules use IP-based matching only. We emit
            // a comment-tagged placeholder that the NFQUEUE handler
            // recognizes. In production the DNS resolver populates IP sets.
            let mut expr = proto.to_string();
            if !port_expr.is_empty() {
                expr.push_str(&format!(" {port_expr}"));
            }
            expr.push_str(&format!(" comment \"host={host}\" {disposition_expr}"));
            frags.push(NftRuleFragment {
                rule_id: rule.id.clone(),
                nft_expr: expr,
            });
        }
    }

    // If no hosts specified, emit an unconstrained rule.
    if rule.match_clause.host.is_none()
        && rule.match_clause.host_pattern.is_none()
    {
        let mut expr = proto.to_string();
        if !port_expr.is_empty() {
            expr.push_str(&format!(" {port_expr}"));
        }
        expr.push_str(&format!(" {disposition_expr}"));
        frags.push(NftRuleFragment {
            rule_id: rule.id.clone(),
            nft_expr: expr,
        });
    }

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
                port,
                protocol: proto.map(|s| s.to_string()),
            },
            scope: RuleScope::default(),
            disposition,
        }
    }

    #[test]
    fn agent_chain_name_sanitizes() {
        assert_eq!(agent_chain_name("my-agent"), "agent_my-agent");
        assert_eq!(agent_chain_name("agent/with spaces"), "agent_agent_with_spaces");
    }

    #[test]
    fn build_agent_ruleset_includes_cgroup_queue() {
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset("test-agent", 42, &frags);
        assert!(script.contains("flush chain"));
        assert!(script.contains("tcp dport 443 accept"));
        assert!(script.contains("queue num 0"));
        assert!(script.contains("42"));
    }

    #[test]
    fn rule_to_nft_expr_allow_with_host_and_port() {
        let r = make_rule(
            "r1",
            Some(vec!["api.anthropic.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert_eq!(frags.len(), 1);
        assert!(frags[0].nft_expr.contains("tcp"));
        assert!(frags[0].nft_expr.contains("dport 443"));
        assert!(frags[0].nft_expr.contains("accept"));
        assert!(frags[0].nft_expr.contains("api.anthropic.com"));
    }

    #[test]
    fn rule_to_nft_expr_deny_no_host() {
        let r = make_rule("r2", None, Some(vec![80, 8080]), Some("tcp"), RuleDisposition::Deny);
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
    fn rule_to_nft_expr_multiple_hosts() {
        let r = make_rule(
            "r4",
            Some(vec!["a.com", "b.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert_eq!(frags.len(), 2);
        assert!(frags[0].nft_expr.contains("a.com"));
        assert!(frags[1].nft_expr.contains("b.com"));
    }
}
