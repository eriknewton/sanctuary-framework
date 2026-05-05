//! In-memory policy state and rule evaluation.
//!
//! PR 2a shipped the data shape (`AllowlistRule`, `RuleMatch`, `RuleScope`,
//! `RuleDisposition`, `PolicySnapshot`) that PR 2b's evaluator consumes.
//! Checkpoint 3 fills in the evaluation core: the F-1 deny-by-default
//! invariant, allow-list matching against a verified ManifestStore snapshot,
//! and the canonical-JSON audit shape per scope-lock §8 that Sanctuary main
//! signs into the existing L1 audit log on drain.
//!
//! The evaluator is a pure function of (snapshot, request); it does not
//! touch the kernel, the filesystem, or the IPC surface. Kernel binding
//! (nftables atomic-replace, cgroup v2 transient scopes, NFQUEUE verdict
//! loop) is the next-checkpoint scope; this module is the in-process
//! decision engine those bindings drive.

use serde::{Deserialize, Serialize};

use crate::constants::{AUDIT_LAYER, SCHEMA_VERSION_V1};
use crate::manifest::canonical_json::{canonicalize, CanonicalJsonError};
use crate::manifest::store::LoadedManifest;

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

impl RuleMatch {
    /// True iff this match-clause covers the given attempt.
    ///
    /// Semantics:
    /// - `host`: case-insensitive exact match against any entry. Absent =
    ///   "any host" (in concert with `host_pattern`).
    /// - `host_pattern`: leading-dot suffix glob. `".example.com"` matches
    ///   `"api.example.com"` and `"foo.bar.example.com"` but not the bare
    ///   apex `"example.com"`. Absent = "no pattern."
    /// - When both `host` and `host_pattern` are present, the attempt
    ///   matches if EITHER hits. When both are absent the host axis is
    ///   not constraining (any host satisfies it, including the no-host
    ///   case where dest is a raw IP).
    /// - `port`: exact match against any entry. Absent = "any port."
    /// - `protocol`: case-insensitive exact match. Absent = "any protocol."
    pub fn matches(
        &self,
        dest_host: Option<&str>,
        dest_port: u16,
        dest_protocol: &str,
    ) -> bool {
        if !self.matches_host(dest_host) {
            return false;
        }
        if let Some(ports) = self.port.as_ref() {
            if !ports.contains(&dest_port) {
                return false;
            }
        }
        if let Some(protocol) = self.protocol.as_ref() {
            if !protocol.eq_ignore_ascii_case(dest_protocol) {
                return false;
            }
        }
        true
    }

    fn matches_host(&self, dest_host: Option<&str>) -> bool {
        let exact_present = self.host.as_ref().map(|h| !h.is_empty()).unwrap_or(false);
        let pattern_present = self
            .host_pattern
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false);

        // No host-axis constraints means the rule matches regardless of dest_host.
        if !exact_present && !pattern_present {
            return true;
        }

        let host = match dest_host {
            Some(h) if !h.is_empty() => h,
            // The rule constrains by host but the attempt has no host
            // (raw-IP destination); cannot match.
            _ => return false,
        };
        let host_lower = host.to_ascii_lowercase();

        if exact_present {
            if let Some(hosts) = self.host.as_ref() {
                if hosts
                    .iter()
                    .any(|h| h.to_ascii_lowercase() == host_lower)
                {
                    return true;
                }
            }
        }
        if pattern_present {
            if let Some(pattern) = self.host_pattern.as_ref() {
                if matches_suffix_pattern(pattern, &host_lower) {
                    return true;
                }
            }
        }
        false
    }
}

fn matches_suffix_pattern(pattern: &str, host_lower: &str) -> bool {
    // Suffix pattern semantics: pattern must start with '.'; host matches
    // when it ends with the pattern (i.e., the pattern is a true subdomain
    // suffix). The bare apex of the suffix (without the leading dot) does
    // NOT match. Operators who want to allow the apex must list it
    // explicitly under `host`.
    let pattern_lower = pattern.to_ascii_lowercase();
    if !pattern_lower.starts_with('.') {
        // Defensive: malformed pattern. Treat as non-match so manifest
        // typos cannot accidentally allow traffic.
        return false;
    }
    host_lower.ends_with(&pattern_lower) && host_lower.len() > pattern_lower.len()
}

/// Scope describes which wrapped agents the rule applies to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuleScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub template_ids: Vec<String>,
}

impl RuleScope {
    /// True iff this scope applies to the given agent. Empty scope (no
    /// agent_ids and no template_ids) applies to every wrapped agent.
    pub fn applies_to(&self, agent_id: &str, agent_template: &str) -> bool {
        let scoped_by_agent = !self.agent_ids.is_empty();
        let scoped_by_template = !self.template_ids.is_empty();
        if !scoped_by_agent && !scoped_by_template {
            return true;
        }
        if scoped_by_agent && self.agent_ids.iter().any(|id| id == agent_id) {
            return true;
        }
        if scoped_by_template
            && self
                .template_ids
                .iter()
                .any(|tpl| tpl == agent_template)
        {
            return true;
        }
        false
    }
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

/// One agent's outbound attempt as presented to the evaluator.
///
/// `dest_host` is the resolved hostname when known (DNS-resolved or
/// SNI-derived). `dest_ip` is the wire-level destination address; one of
/// them must be present for the request to be evaluable. `opaque` mirrors
/// the IPC `IpcDestination.opaque` flag from scope-lock §6 confidence
/// labels: true when the destination is a raw IP with no resolved
/// hostname, which drives the `low_raw_ip` confidence label on emitted
/// prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRequest {
    pub agent_id: String,
    pub agent_template: String,
    pub dest_host: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_port: u16,
    pub dest_protocol: String,
    pub opaque: bool,
}

/// Final decision returned by [`PolicySnapshot::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The attempt matched a rule with `Allow` disposition.
    Allow { rule_id: String },
    /// The attempt matched a rule with `Prompt` disposition; the daemon
    /// must prompt the operator before delivering a terminal verdict.
    PromptRequired { rule_id: String },
    /// The attempt was denied. Carries the reason so the audit-event
    /// builder can stamp the right `decision_provenance`.
    Deny { reason: DeniedReason },
}

/// Why a verdict resolved to deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedReason {
    /// No rule matched. F-1 deny-by-default invariant.
    DefaultDeny,
    /// A rule matched and explicitly denied. Carries the rule id so the
    /// operator dashboard can show "blocked by rule X."
    ExplicitRule { rule_id: String },
}

/// Snapshot of the loaded policy. Built from a verified [`LoadedManifest`]
/// via [`PolicySnapshot::from_loaded_manifest`]; the daemon swaps the
/// snapshot atomically on each successful manifest reload.
#[derive(Debug, Clone, Default)]
pub struct PolicySnapshot {
    pub rules: Vec<AllowlistRule>,
    pub manifest_signature_b64url: Option<String>,
    pub fortress_id: String,
}

/// Errors produced when constructing a [`PolicySnapshot`] from a
/// [`LoadedManifest`].
#[derive(Debug, thiserror::Error, Clone)]
pub enum PolicySnapshotError {
    #[error("rule file {file} not present in loaded manifest's rule_files")]
    RuleFileMissing { file: String },
    #[error("rule file {file} could not be parsed as JSON: {source_message}")]
    RuleParse { file: String, source_message: String },
    #[error(
        "rule file {file} declares rule_id {file_rule_id} but the manifest entry binds it to {manifest_rule_id}"
    )]
    RuleIdMismatch {
        file: String,
        file_rule_id: String,
        manifest_rule_id: String,
    },
    #[error("rule {rule_id} schema_version {found} is not supported (expected {expected})")]
    UnsupportedSchemaVersion {
        rule_id: String,
        found: u32,
        expected: u32,
    },
}

impl PolicySnapshot {
    /// Build a snapshot from a verified [`LoadedManifest`]. The manifest's
    /// signature has already been checked by the manifest store; here we
    /// only parse each per-rule JSON document, validate that the rule's
    /// declared `id` matches the manifest entry's `rule_id`, and collect
    /// them in manifest order.
    pub fn from_loaded_manifest(loaded: &LoadedManifest) -> Result<Self, PolicySnapshotError> {
        let mut rules = Vec::with_capacity(loaded.signed.manifest.rules.len());
        for entry in &loaded.signed.manifest.rules {
            let bytes = loaded
                .rule_files
                .get(&entry.file)
                .ok_or_else(|| PolicySnapshotError::RuleFileMissing {
                    file: entry.file.clone(),
                })?;
            let rule: AllowlistRule =
                serde_json::from_slice(bytes).map_err(|err| PolicySnapshotError::RuleParse {
                    file: entry.file.clone(),
                    source_message: err.to_string(),
                })?;
            if rule.id != entry.rule_id {
                return Err(PolicySnapshotError::RuleIdMismatch {
                    file: entry.file.clone(),
                    file_rule_id: rule.id,
                    manifest_rule_id: entry.rule_id.clone(),
                });
            }
            if rule.schema_version != SCHEMA_VERSION_V1 {
                return Err(PolicySnapshotError::UnsupportedSchemaVersion {
                    rule_id: rule.id,
                    found: rule.schema_version,
                    expected: SCHEMA_VERSION_V1,
                });
            }
            rules.push(rule);
        }
        Ok(Self {
            rules,
            manifest_signature_b64url: Some(loaded.manifest_signature_b64url.clone()),
            fortress_id: loaded.signed.manifest.fortress_id.clone(),
        })
    }

    /// Evaluate a request against the snapshot. F-1 deny-by-default: an
    /// empty snapshot or a snapshot with no matching rule yields
    /// [`Verdict::Deny { reason: DeniedReason::DefaultDeny }`]. First-match-
    /// wins among rules whose scope applies and whose match-clause covers
    /// the attempt.
    pub fn evaluate(&self, request: &EvaluationRequest) -> Verdict {
        for rule in &self.rules {
            if !rule
                .scope
                .applies_to(&request.agent_id, &request.agent_template)
            {
                continue;
            }
            if !rule.match_clause.matches(
                request.dest_host.as_deref(),
                request.dest_port,
                &request.dest_protocol,
            ) {
                continue;
            }
            return match rule.disposition {
                RuleDisposition::Allow => Verdict::Allow {
                    rule_id: rule.id.clone(),
                },
                RuleDisposition::Prompt => Verdict::PromptRequired {
                    rule_id: rule.id.clone(),
                },
                RuleDisposition::Deny => Verdict::Deny {
                    reason: DeniedReason::ExplicitRule {
                        rule_id: rule.id.clone(),
                    },
                },
            };
        }
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        }
    }
}

/// Operation tag that maps to the existing Sanctuary `AuditEntry.operation`
/// enum per scope-lock §8.
fn operation_for_verdict(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow { .. } => "egress_approved",
        Verdict::PromptRequired { .. } => "egress_pending",
        Verdict::Deny { .. } => "egress_blocked",
    }
}

/// `decision_provenance` field per scope-lock §8 critical-event shape.
fn decision_provenance(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow { .. } | Verdict::PromptRequired { .. } => "static_rule",
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        } => "default_deny",
        Verdict::Deny {
            reason: DeniedReason::ExplicitRule { .. },
        } => "static_rule",
    }
}

/// `result` field per scope-lock §8 (mirrors existing AuditEntry shape).
fn result_for_verdict(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow { .. } => "success",
        // Prompts have no terminal decision yet; the request itself was
        // accepted into the prompt queue, so result=success matches the
        // shape of "the gate did its job and routed correctly."
        Verdict::PromptRequired { .. } => "success",
        Verdict::Deny { .. } => "failure",
    }
}

/// Pull the rule_id (if any) that drove the verdict, for the audit entry's
/// `details.rule_id_matched` field. None on default-deny.
fn matched_rule_id(verdict: &Verdict) -> Option<&str> {
    match verdict {
        Verdict::Allow { rule_id } => Some(rule_id.as_str()),
        Verdict::PromptRequired { rule_id } => Some(rule_id.as_str()),
        Verdict::Deny {
            reason: DeniedReason::ExplicitRule { rule_id },
        } => Some(rule_id.as_str()),
        Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        } => None,
    }
}

/// Build the canonical-JSON `AuditEntry` body for a verdict + request.
/// Shape matches scope-lock §8 critical-event recommendation: `layer:
/// "l1"`, `operation` from [`operation_for_verdict`], `identity_id` =
/// agent fortress identity, `result` from [`result_for_verdict`], and a
/// `details` object carrying destination metadata + rule provenance.
///
/// The body is canonicalized so the bytes Sanctuary main signs on drain
/// match what the daemon hashed into the WAL chain. `timestamp_iso8601`
/// is supplied by the caller (the daemon stamps it at evaluation time).
pub fn build_audit_event_canonical_json(
    verdict: &Verdict,
    request: &EvaluationRequest,
    timestamp_iso8601: &str,
) -> Result<String, CanonicalJsonError> {
    let mut details = serde_json::Map::new();
    details.insert(
        "agent_id".to_string(),
        serde_json::Value::String(request.agent_id.clone()),
    );
    details.insert(
        "agent_template".to_string(),
        serde_json::Value::String(request.agent_template.clone()),
    );
    if let Some(host) = request.dest_host.as_ref() {
        details.insert(
            "dest_host".to_string(),
            serde_json::Value::String(host.clone()),
        );
    }
    if let Some(ip) = request.dest_ip.as_ref() {
        details.insert(
            "dest_ip".to_string(),
            serde_json::Value::String(ip.clone()),
        );
    }
    details.insert(
        "dest_port".to_string(),
        serde_json::Value::Number(serde_json::Number::from(request.dest_port)),
    );
    details.insert(
        "dest_protocol".to_string(),
        serde_json::Value::String(request.dest_protocol.clone()),
    );
    details.insert(
        "opaque".to_string(),
        serde_json::Value::Bool(request.opaque),
    );
    details.insert(
        "decision_provenance".to_string(),
        serde_json::Value::String(decision_provenance(verdict).to_string()),
    );
    if let Some(rule_id) = matched_rule_id(verdict) {
        details.insert(
            "rule_id_matched".to_string(),
            serde_json::Value::String(rule_id.to_string()),
        );
    }

    let mut entry = serde_json::Map::new();
    entry.insert(
        "timestamp".to_string(),
        serde_json::Value::String(timestamp_iso8601.to_string()),
    );
    entry.insert(
        "layer".to_string(),
        serde_json::Value::String(AUDIT_LAYER.to_string()),
    );
    entry.insert(
        "operation".to_string(),
        serde_json::Value::String(operation_for_verdict(verdict).to_string()),
    );
    entry.insert(
        "identity_id".to_string(),
        serde_json::Value::String(request.agent_id.clone()),
    );
    entry.insert(
        "result".to_string(),
        serde_json::Value::String(result_for_verdict(verdict).to_string()),
    );
    entry.insert(
        "details".to_string(),
        serde_json::Value::Object(details),
    );

    canonicalize(&serde_json::Value::Object(entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::canonical_json::canonicalize_to_bytes;
    use crate::manifest::verify::{
        AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    fn rule(
        id: &str,
        match_clause: RuleMatch,
        scope: RuleScope,
        disposition: RuleDisposition,
    ) -> AllowlistRule {
        AllowlistRule {
            id: id.to_string(),
            schema_version: SCHEMA_VERSION_V1,
            created_at: "2026-05-05T00:00:00Z".to_string(),
            description: None,
            match_clause,
            scope,
            disposition,
        }
    }

    fn snapshot(rules: Vec<AllowlistRule>) -> PolicySnapshot {
        PolicySnapshot {
            rules,
            manifest_signature_b64url: Some("test-sig".to_string()),
            fortress_id: "deadbeef".to_string(),
        }
    }

    fn req(host: Option<&str>, port: u16, proto: &str) -> EvaluationRequest {
        EvaluationRequest {
            agent_id: "agent-1".to_string(),
            agent_template: "claude-code".to_string(),
            dest_host: host.map(|h| h.to_string()),
            dest_ip: Some("203.0.113.10".to_string()),
            dest_port: port,
            dest_protocol: proto.to_string(),
            opaque: host.is_none(),
        }
    }

    #[test]
    fn rule_round_trips_through_json() {
        let r = AllowlistRule {
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
        let body = serde_json::to_value(&r).unwrap();
        assert_eq!(body["disposition"], json!("allow"));
        let back: AllowlistRule = serde_json::from_value(body).unwrap();
        assert_eq!(back, r);
    }

    // ---- RuleMatch ---------------------------------------------------------

    #[test]
    fn match_host_exact_case_insensitive() {
        let m = RuleMatch {
            host: Some(vec!["API.example.COM".to_string()]),
            host_pattern: None,
            port: None,
            protocol: None,
        };
        assert!(m.matches(Some("api.example.com"), 443, "tcp"));
        assert!(m.matches(Some("API.EXAMPLE.COM"), 443, "tcp"));
        assert!(!m.matches(Some("other.example.com"), 443, "tcp"));
    }

    #[test]
    fn match_host_pattern_suffix_glob() {
        let m = RuleMatch {
            host: None,
            host_pattern: Some(".example.com".to_string()),
            port: None,
            protocol: None,
        };
        assert!(m.matches(Some("api.example.com"), 443, "tcp"));
        assert!(m.matches(Some("a.b.c.example.com"), 443, "tcp"));
        // Apex does NOT match the leading-dot suffix glob.
        assert!(!m.matches(Some("example.com"), 443, "tcp"));
        // Different domain.
        assert!(!m.matches(Some("api.evil.com"), 443, "tcp"));
    }

    #[test]
    fn match_host_pattern_without_leading_dot_does_not_match() {
        // Defensive: pattern without leading dot is malformed and should
        // not match anything, so manifest typos can't accidentally allow.
        let m = RuleMatch {
            host: None,
            host_pattern: Some("example.com".to_string()),
            port: None,
            protocol: None,
        };
        assert!(!m.matches(Some("api.example.com"), 443, "tcp"));
        assert!(!m.matches(Some("example.com"), 443, "tcp"));
    }

    #[test]
    fn match_host_axis_absent_is_unconstrained() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            port: Some(vec![443]),
            protocol: Some("tcp".to_string()),
        };
        assert!(m.matches(Some("anything.example.com"), 443, "tcp"));
        assert!(m.matches(None, 443, "tcp"));
    }

    #[test]
    fn match_host_constraint_with_no_dest_host_misses() {
        // Rule asks for a specific host but the attempt is raw-IP.
        let m = RuleMatch {
            host: Some(vec!["api.example.com".to_string()]),
            host_pattern: None,
            port: None,
            protocol: None,
        };
        assert!(!m.matches(None, 443, "tcp"));
    }

    #[test]
    fn match_port_must_be_in_set() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            port: Some(vec![443, 8443]),
            protocol: None,
        };
        assert!(m.matches(Some("x"), 443, "tcp"));
        assert!(m.matches(Some("x"), 8443, "tcp"));
        assert!(!m.matches(Some("x"), 80, "tcp"));
    }

    #[test]
    fn match_protocol_case_insensitive() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            port: None,
            protocol: Some("TCP".to_string()),
        };
        assert!(m.matches(Some("x"), 443, "tcp"));
        assert!(m.matches(Some("x"), 443, "TCP"));
        assert!(!m.matches(Some("x"), 443, "udp"));
    }

    // ---- RuleScope ---------------------------------------------------------

    #[test]
    fn scope_empty_applies_to_everyone() {
        let s = RuleScope::default();
        assert!(s.applies_to("any-agent", "any-template"));
    }

    #[test]
    fn scope_agent_id_constrains() {
        let s = RuleScope {
            agent_ids: vec!["agent-1".to_string()],
            template_ids: Vec::new(),
        };
        assert!(s.applies_to("agent-1", "any-template"));
        assert!(!s.applies_to("agent-2", "any-template"));
    }

    #[test]
    fn scope_template_id_constrains() {
        let s = RuleScope {
            agent_ids: Vec::new(),
            template_ids: vec!["claude-code".to_string()],
        };
        assert!(s.applies_to("any-agent", "claude-code"));
        assert!(!s.applies_to("any-agent", "other-template"));
    }

    #[test]
    fn scope_either_axis_satisfies_when_both_present() {
        let s = RuleScope {
            agent_ids: vec!["agent-1".to_string()],
            template_ids: vec!["claude-code".to_string()],
        };
        // agent_id hit
        assert!(s.applies_to("agent-1", "other"));
        // template hit
        assert!(s.applies_to("agent-other", "claude-code"));
        // neither
        assert!(!s.applies_to("agent-other", "other-template"));
    }

    // ---- PolicySnapshot::evaluate -----------------------------------------

    #[test]
    fn empty_snapshot_default_denies() {
        let snap = snapshot(Vec::new());
        let v = snap.evaluate(&req(Some("api.anthropic.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::Deny {
                reason: DeniedReason::DefaultDeny
            }
        );
    }

    #[test]
    fn unmatched_request_default_denies() {
        let snap = snapshot(vec![rule(
            "r1",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                host_pattern: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        )]);
        let v = snap.evaluate(&req(Some("api.unknown-host.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::Deny {
                reason: DeniedReason::DefaultDeny
            }
        );
    }

    #[test]
    fn matched_allow_rule_returns_allow_with_rule_id() {
        let snap = snapshot(vec![rule(
            "r-allow",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                host_pattern: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        )]);
        let v = snap.evaluate(&req(Some("api.anthropic.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::Allow {
                rule_id: "r-allow".to_string()
            }
        );
    }

    #[test]
    fn matched_deny_rule_returns_explicit_rule() {
        let snap = snapshot(vec![rule(
            "r-deny",
            RuleMatch {
                host: Some(vec!["pastebin.com".to_string()]),
                host_pattern: None,
                port: None,
                protocol: None,
            },
            RuleScope::default(),
            RuleDisposition::Deny,
        )]);
        let v = snap.evaluate(&req(Some("pastebin.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::Deny {
                reason: DeniedReason::ExplicitRule {
                    rule_id: "r-deny".to_string()
                }
            }
        );
    }

    #[test]
    fn matched_prompt_rule_returns_prompt_required() {
        let snap = snapshot(vec![rule(
            "r-prompt",
            RuleMatch {
                host_pattern: Some(".example.com".to_string()),
                host: None,
                port: None,
                protocol: None,
            },
            RuleScope::default(),
            RuleDisposition::Prompt,
        )]);
        let v = snap.evaluate(&req(Some("api.example.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::PromptRequired {
                rule_id: "r-prompt".to_string()
            }
        );
    }

    #[test]
    fn first_match_wins_in_rule_order() {
        let snap = snapshot(vec![
            rule(
                "r-deny-first",
                RuleMatch {
                    host: Some(vec!["api.anthropic.com".to_string()]),
                    host_pattern: None,
                    port: None,
                    protocol: None,
                },
                RuleScope::default(),
                RuleDisposition::Deny,
            ),
            rule(
                "r-allow-second",
                RuleMatch {
                    host: Some(vec!["api.anthropic.com".to_string()]),
                    host_pattern: None,
                    port: Some(vec![443]),
                    protocol: Some("tcp".to_string()),
                },
                RuleScope::default(),
                RuleDisposition::Allow,
            ),
        ]);
        let v = snap.evaluate(&req(Some("api.anthropic.com"), 443, "tcp"));
        assert_eq!(
            v,
            Verdict::Deny {
                reason: DeniedReason::ExplicitRule {
                    rule_id: "r-deny-first".to_string()
                }
            }
        );
    }

    #[test]
    fn scope_filter_skips_non_applicable_rules() {
        let snap = snapshot(vec![rule(
            "r-other-agent",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                host_pattern: None,
                port: None,
                protocol: None,
            },
            RuleScope {
                agent_ids: vec!["agent-other".to_string()],
                template_ids: Vec::new(),
            },
            RuleDisposition::Allow,
        )]);
        let v = snap.evaluate(&req(Some("api.anthropic.com"), 443, "tcp"));
        // Rule scoped to a different agent; this attempt sees default-deny.
        assert_eq!(
            v,
            Verdict::Deny {
                reason: DeniedReason::DefaultDeny
            }
        );
    }

    // ---- PolicySnapshot::from_loaded_manifest ------------------------------

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut s = String::with_capacity(out.len() * 2);
        for b in out.iter() {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    fn synthetic_loaded(rules_for_files: Vec<(String, AllowlistRule)>) -> LoadedManifest {
        let entries: Vec<ManifestRuleEntry> = rules_for_files
            .iter()
            .map(|(file, rule)| {
                let bytes = serde_json::to_vec(rule).unwrap();
                ManifestRuleEntry {
                    rule_id: rule.id.clone(),
                    file: file.clone(),
                    sha256: sha256_hex(&bytes),
                }
            })
            .collect();
        let manifest = AllowlistManifest {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            rules: entries,
        };
        let mut rule_files: HashMap<String, Vec<u8>> = HashMap::new();
        for (file, rule) in rules_for_files {
            let bytes = serde_json::to_vec(&rule).unwrap();
            rule_files.insert(file, bytes);
        }
        LoadedManifest {
            signed: SignedManifest {
                manifest,
                signature: ManifestSignature {
                    signature_scheme: "ed25519-v1".to_string(),
                    signing_key_id: "test".to_string(),
                    signature_b64url: "AAAA".to_string(),
                },
            },
            rule_files,
            manifest_signature_b64url: "AAAA".to_string(),
            rule_count: 0,
        }
    }

    #[test]
    fn snapshot_from_loaded_manifest_happy_path() {
        let r1 = rule(
            "uuid-1",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                host_pattern: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        let loaded = synthetic_loaded(vec![("rule-0.json".to_string(), r1.clone())]);
        let snap = PolicySnapshot::from_loaded_manifest(&loaded).expect("snapshot");
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.rules[0], r1);
        assert_eq!(snap.fortress_id, "deadbeef");
    }

    #[test]
    fn snapshot_rejects_rule_id_mismatch() {
        let r = rule(
            "uuid-real",
            RuleMatch {
                host: None,
                host_pattern: None,
                port: None,
                protocol: None,
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        // Build a LoadedManifest where the manifest entry's rule_id does
        // NOT match the rule body's id.
        let bytes = serde_json::to_vec(&r).unwrap();
        let entry = ManifestRuleEntry {
            rule_id: "uuid-claimed".to_string(),
            file: "rule-0.json".to_string(),
            sha256: sha256_hex(&bytes),
        };
        let manifest = AllowlistManifest {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            rules: vec![entry],
        };
        let mut rule_files = HashMap::new();
        rule_files.insert("rule-0.json".to_string(), bytes);
        let loaded = LoadedManifest {
            signed: SignedManifest {
                manifest,
                signature: ManifestSignature {
                    signature_scheme: "ed25519-v1".to_string(),
                    signing_key_id: "test".to_string(),
                    signature_b64url: "AAAA".to_string(),
                },
            },
            rule_files,
            manifest_signature_b64url: "AAAA".to_string(),
            rule_count: 0,
        };
        let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
        assert!(matches!(err, PolicySnapshotError::RuleIdMismatch { .. }));
    }

    #[test]
    fn snapshot_rejects_unsupported_schema_version() {
        let mut r = rule(
            "uuid-1",
            RuleMatch {
                host: None,
                host_pattern: None,
                port: None,
                protocol: None,
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        r.schema_version = 99;
        let loaded = synthetic_loaded(vec![("rule-0.json".to_string(), r)]);
        let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
        assert!(matches!(
            err,
            PolicySnapshotError::UnsupportedSchemaVersion { .. }
        ));
    }

    #[test]
    fn snapshot_rejects_unparseable_rule_file() {
        let r = rule(
            "uuid-1",
            RuleMatch {
                host: None,
                host_pattern: None,
                port: None,
                protocol: None,
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        // Corrupt the rule_files entry so JSON parse fails.
        let entry = ManifestRuleEntry {
            rule_id: "uuid-1".to_string(),
            file: "rule-0.json".to_string(),
            sha256: sha256_hex(&serde_json::to_vec(&r).unwrap()),
        };
        let manifest = AllowlistManifest {
            schema_version: SCHEMA_VERSION_V1,
            fortress_id: "deadbeef".to_string(),
            issued_at: "2026-05-05T00:00:00Z".to_string(),
            rules: vec![entry],
        };
        let mut rule_files = HashMap::new();
        rule_files.insert("rule-0.json".to_string(), b"not-valid-json".to_vec());
        let loaded = LoadedManifest {
            signed: SignedManifest {
                manifest,
                signature: ManifestSignature {
                    signature_scheme: "ed25519-v1".to_string(),
                    signing_key_id: "test".to_string(),
                    signature_b64url: "AAAA".to_string(),
                },
            },
            rule_files,
            manifest_signature_b64url: "AAAA".to_string(),
            rule_count: 0,
        };
        let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
        assert!(matches!(err, PolicySnapshotError::RuleParse { .. }));
    }

    // ---- build_audit_event_canonical_json ---------------------------------

    fn parse_canonical(body: &str) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(body).expect("parse canonical")
    }

    #[test]
    fn audit_for_allow_emits_egress_approved() {
        let v = Verdict::Allow {
            rule_id: "r1".to_string(),
        };
        let request = req(Some("api.anthropic.com"), 443, "tcp");
        let body =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["layer"], json!("l1"));
        assert_eq!(parsed["operation"], json!("egress_approved"));
        assert_eq!(parsed["identity_id"], json!("agent-1"));
        assert_eq!(parsed["result"], json!("success"));
        assert_eq!(parsed["timestamp"], json!("2026-05-05T01:02:03Z"));
        assert_eq!(parsed["details"]["dest_host"], json!("api.anthropic.com"));
        assert_eq!(parsed["details"]["dest_port"], json!(443));
        assert_eq!(parsed["details"]["dest_protocol"], json!("tcp"));
        assert_eq!(parsed["details"]["agent_id"], json!("agent-1"));
        assert_eq!(parsed["details"]["agent_template"], json!("claude-code"));
        assert_eq!(parsed["details"]["rule_id_matched"], json!("r1"));
        assert_eq!(parsed["details"]["decision_provenance"], json!("static_rule"));
        assert_eq!(parsed["details"]["opaque"], json!(false));
    }

    #[test]
    fn audit_for_default_deny_emits_egress_blocked_with_default_deny_provenance() {
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let request = req(Some("api.evil.com"), 443, "tcp");
        let body =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["operation"], json!("egress_blocked"));
        assert_eq!(parsed["result"], json!("failure"));
        assert_eq!(parsed["details"]["decision_provenance"], json!("default_deny"));
        assert_eq!(parsed["details"]["rule_id_matched"], serde_json::Value::Null);
    }

    #[test]
    fn audit_for_explicit_deny_emits_static_rule_provenance() {
        let v = Verdict::Deny {
            reason: DeniedReason::ExplicitRule {
                rule_id: "r-deny".to_string(),
            },
        };
        let request = req(Some("pastebin.com"), 443, "tcp");
        let body =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["operation"], json!("egress_blocked"));
        assert_eq!(parsed["details"]["decision_provenance"], json!("static_rule"));
        assert_eq!(parsed["details"]["rule_id_matched"], json!("r-deny"));
    }

    #[test]
    fn audit_for_prompt_emits_egress_pending() {
        let v = Verdict::PromptRequired {
            rule_id: "r-prompt".to_string(),
        };
        let request = req(Some("api.example.com"), 443, "tcp");
        let body =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["operation"], json!("egress_pending"));
        assert_eq!(parsed["result"], json!("success"));
        assert_eq!(parsed["details"]["rule_id_matched"], json!("r-prompt"));
    }

    #[test]
    fn audit_for_raw_ip_attempt_omits_dest_host_and_marks_opaque() {
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let request = EvaluationRequest {
            agent_id: "agent-2".to_string(),
            agent_template: "tmpl".to_string(),
            dest_host: None,
            dest_ip: Some("203.0.113.10".to_string()),
            dest_port: 8443,
            dest_protocol: "tcp".to_string(),
            opaque: true,
        };
        let body =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let parsed = parse_canonical(&body);
        assert!(parsed["details"].get("dest_host").is_none());
        assert_eq!(parsed["details"]["dest_ip"], json!("203.0.113.10"));
        assert_eq!(parsed["details"]["opaque"], json!(true));
    }

    #[test]
    fn audit_canonical_form_is_byte_stable() {
        // Canonical-JSON sorts object keys; building the same audit twice
        // yields byte-identical output regardless of HashMap iteration
        // order on the details object.
        let v = Verdict::Allow {
            rule_id: "r1".to_string(),
        };
        let request = req(Some("api.anthropic.com"), 443, "tcp");
        let a =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        let b =
            build_audit_event_canonical_json(&v, &request, "2026-05-05T01:02:03Z").unwrap();
        assert_eq!(a, b);
        // Same shape under canonical-JSON byte serialization.
        let bytes_a = canonicalize_to_bytes(&serde_json::from_str(&a).unwrap()).unwrap();
        assert_eq!(a.as_bytes(), bytes_a.as_slice());
    }
}
