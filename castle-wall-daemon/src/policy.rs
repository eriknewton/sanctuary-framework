//! In-memory policy state and rule evaluation.
//!
//! PR 2a ships the data shape that PR 2b's evaluator consumes. The
//! evaluator runs on the hot path; PR 2b adds the actual hostname / port
//! / protocol matching with the cgroup-bound agent scope filter.

use serde::{Deserialize, Serialize};

/// Disposition applied when a rule matches an outbound flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDisposition {
    Allow,
    Prompt,
    Deny,
}

/// Match conditions for a rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Scope describes which wrapped agents the rule applies to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub template_ids: Vec<String>,
}

/// A single allowlist rule loaded from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistRule {
    pub id: String,
    pub schema_version: u32,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "match")]
    pub match_clause: RuleMatch,
    #[serde(default)]
    pub scope: RuleScope,
    pub disposition: RuleDisposition,
}

/// Snapshot of the loaded policy. PR 2b's evaluator runs against an
/// instance of this; the daemon swaps the snapshot atomically on each
/// successful manifest reload.
#[derive(Debug, Clone, Default)]
pub struct PolicySnapshot {
    pub rules: Vec<AllowlistRule>,
    pub manifest_signature_b64url: Option<String>,
    pub fortress_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rule_round_trips_through_json() {
        let rule = AllowlistRule {
            id: "uuid-1".to_string(),
            schema_version: 1,
            created_at: "2026-05-04T00:00:00Z".to_string(),
            description: Some("anthropic api".to_string()),
            match_clause: RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                host_pattern: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            scope: RuleScope::default(),
            disposition: RuleDisposition::Allow,
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["disposition"], json!("allow"));
        let back: AllowlistRule = serde_json::from_value(json).unwrap();
        assert_eq!(back, rule);
    }
}
