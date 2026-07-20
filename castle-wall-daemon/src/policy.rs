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

use std::collections::{HashMap, HashSet};

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
///
/// `ip` / `cidr` mirror the TS schema's destination-IP axes (#380): a rule may
/// pin a flow to a concrete address set or subnet. The evaluator
/// ([`RuleMatch::matches`]) enforces them against the raw destination IP, and
/// the HABEAS PORT conflict gate (`crate::habeas`) reasons over them — so the
/// genuine local distress rule's loopback `ip` pin is honoured end-to-end (it
/// is NOT silently flattened to "any host", and a cidr/ip-only deny is scoped
/// to its addresses rather than shadowing every host on the port).
///
/// `deny_unknown_fields` (codex round-4 MEDIUM): every field inside `match`
/// is a constraint axis with enforcement semantics. The TS composer's match
/// surface (host / host_pattern / ip / cidr / port / protocol) is fully
/// modeled here, so an unknown match field can only mean a NEWER axis this
/// daemon does not know how to enforce — silently ignoring it would enforce
/// a broader rule than the operator signed. Fail closed: the rule file fails
/// to parse, snapshot construction aborts, and the daemon keeps the prior
/// good policy (loud `RuleParse` error on the reload response).
/// Scalar-or-array deserialization shim (codex round-5 MEDIUM): the TS schema
/// types every list axis as `T | T[]` (`host?: string | string[]`, etc.), and
/// the TS validator + composer sign scalar-form operator rules AS-IS. The
/// daemon must therefore parse the scalar spelling too — a TS-valid signed
/// manifest must never be refused over an equivalent JSON shape. A scalar
/// normalizes to a one-element vec, which is semantics-identical everywhere
/// (evaluator, habeas gates, validators).
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

fn de_one_or_many<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<OneOrMany<T>>::deserialize(deserializer)?.map(|v| match v {
        OneOrMany::One(one) => vec![one],
        OneOrMany::Many(many) => many,
    }))
}

/// Port axis deserializer (codex round-7): JSON has ONE number type, so the
/// tokens `443`, `443.0`, and `4.43e2` all denote the number 443 — and the TS
/// side (`JSON.parse` + validateRule's `Number.isInteger`) accepts all three
/// spellings in a signed rule file. A plain `u16` field would refuse the
/// float-token spellings, leaving a TS-valid signed manifest Linux-refused.
/// Accept any JSON number with an exactly-integral value in [1, 65535];
/// reject everything else (range parity with the TS validator).
fn de_one_or_many_port<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<OneOrMany<f64>>::deserialize(deserializer)?;
    raw.map(|v| {
        let nums = match v {
            OneOrMany::One(one) => vec![one],
            OneOrMany::Many(many) => many,
        };
        nums.into_iter()
            .map(|n| {
                if n.is_finite() && n.fract() == 0.0 && (1.0..=65535.0).contains(&n) {
                    Ok(n as u16)
                } else {
                    Err(serde::de::Error::custom(format!(
                        "port {n} must be an integer in [1, 65535]"
                    )))
                }
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .transpose()
}

/// `schema_version` deserializer: same JSON-number-token parity as ports
/// (`1.0` denotes 1; the TS `===` check passes it, so serde must too).
fn de_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let n = f64::deserialize(deserializer)?;
    if n.is_finite() && n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&n) {
        Ok(n as u32)
    } else {
        Err(serde::de::Error::custom(format!(
            "schema_version {n} must be a non-negative integer"
        )))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    #[serde(
        default,
        deserialize_with = "de_one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub host: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_pattern: Option<String>,
    /// Exact destination-IP literals (IPv4 or IPv6). Mirrors TS `match.ip`.
    #[serde(
        default,
        deserialize_with = "de_one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub ip: Option<Vec<String>>,
    /// Destination CIDR blocks (`addr/prefix`). Mirrors TS `match.cidr`.
    #[serde(
        default,
        deserialize_with = "de_one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub cidr: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "de_one_or_many_port",
        skip_serializing_if = "Option::is_none"
    )]
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
    /// - `ip` / `cidr`: family-aware exact / subnet match against the raw
    ///   destination IP (`dest_ip`). Match a DNS/raw-IP flow that has no
    ///   hostname. Absent = not constraining.
    /// - `port`: exact match against any entry. Absent = "any port."
    /// - `protocol`: case-insensitive exact match. Absent = "any protocol."
    ///
    /// Destination axes (host / host_pattern / ip / cidr) compose as an OR
    /// (parity with the TS egress-proxy and Swift evaluators): when NONE is
    /// specified the destination is "match any"; when any is specified, at
    /// least one must match. This is why the habeas conflict gate
    /// (`crate::habeas`) can reason over ip/cidr — the evaluator honours them.
    pub fn matches(
        &self,
        dest_host: Option<&str>,
        dest_ip: Option<&str>,
        dest_port: u16,
        dest_protocol: &str,
    ) -> bool {
        if !self.matches_destination(dest_host, dest_ip) {
            return false;
        }
        if let Some(ports) = self.port.as_ref() {
            if !ports.contains(&dest_port) {
                return false;
            }
        }
        if let Some(protocol) = self.protocol.as_ref() {
            // TS schema parity: `tcp+udp` (the protocol the composer stamps
            // on the derived DNS rule, dns-derivation.ts) matches EITHER
            // transport. Exact-matching it would silently never fire — an
            // allow that does nothing and, worse, a deny that never blocks.
            let matches_protocol = if protocol.eq_ignore_ascii_case("tcp+udp") {
                dest_protocol.eq_ignore_ascii_case("tcp")
                    || dest_protocol.eq_ignore_ascii_case("udp")
            } else {
                protocol.eq_ignore_ascii_case(dest_protocol)
            };
            if !matches_protocol {
                return false;
            }
        }
        true
    }

    fn matches_destination(&self, dest_host: Option<&str>, dest_ip: Option<&str>) -> bool {
        let exact_present = self.host.as_ref().map(|h| !h.is_empty()).unwrap_or(false);
        let pattern_present = self
            .host_pattern
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false);
        let ip_present = self.ip.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
        let cidr_present = self.cidr.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

        // No destination-axis constraints means the rule matches any destination.
        if !exact_present && !pattern_present && !ip_present && !cidr_present {
            return true;
        }

        // Host / host_pattern axes (need a hostname destination).
        if let Some(host) = dest_host.filter(|h| !h.is_empty()) {
            let host_lower = host.to_ascii_lowercase();
            if exact_present {
                if let Some(hosts) = self.host.as_ref() {
                    if hosts.iter().any(|h| h.to_ascii_lowercase() == host_lower) {
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
        }

        // ip / cidr axes (need a raw-IP destination; the host literal itself may
        // be an IP, so fall back to dest_host when dest_ip is absent).
        let ip_literal = dest_ip
            .filter(|s| !s.is_empty())
            .or(dest_host)
            .and_then(|s| s.parse::<std::net::IpAddr>().ok());
        if let Some(addr) = ip_literal {
            if ip_present && ip_axis_matches(self.ip.as_ref(), &addr) {
                return true;
            }
            if cidr_present && cidr_axis_matches(self.cidr.as_ref(), &addr) {
                return true;
            }
        }
        false
    }
}

/// Family-aware exact match of `addr` against an `ip` axis.
fn ip_axis_matches(spec: Option<&Vec<String>>, addr: &std::net::IpAddr) -> bool {
    let Some(ips) = spec else { return false };
    ips.iter().any(|candidate| {
        candidate
            .parse::<std::net::IpAddr>()
            .map(|c| &c == addr)
            .unwrap_or(false)
    })
}

/// Family-aware subnet containment of `addr` against a `cidr` axis.
fn cidr_axis_matches(spec: Option<&Vec<String>>, addr: &std::net::IpAddr) -> bool {
    let Some(cidrs) = spec else { return false };
    cidrs.iter().any(|cidr| cidr_contains(cidr, addr))
}

/// True iff `cidr` (`addr/prefix`) contains `target`, family-aware. Malformed
/// input returns false.
fn cidr_contains(cidr: &str, target: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let Some((base_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    let Ok(base) = base_str.parse::<IpAddr>() else {
        return false;
    };
    match (base, target) {
        (IpAddr::V4(base), IpAddr::V4(target)) => {
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(base) & mask) == (u32::from(*target) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(target)) => {
            if prefix > 128 {
                return false;
            }
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(base) & mask) == (u128::from(*target) & mask)
        }
        _ => false,
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
///
/// `deny_unknown_fields`: scope fields carry enforcement semantics too — an
/// ignored (unmodeled) scope axis would apply a rule to MORE agents than the
/// operator intended. The TS scope surface (agent_ids / template_ids) is
/// fully modeled, so unknown fields are rejected (fail closed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
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
        if scoped_by_template && self.template_ids.iter().any(|tpl| tpl == agent_template) {
            return true;
        }
        false
    }
}

/// Time-of-day window where a rule is active (HH:MM, fortress-local).
/// Mirrors the TS `RuleTimeWindow`. The Linux daemon does NOT implement
/// time-window enforcement; a rule carrying this axis is REJECTED at
/// snapshot-build time (see [`PolicySnapshot::from_loaded_manifest`]) rather
/// than silently enforced without its time bound — an allow rule the
/// operator scoped to working hours must not become a 24/7 allow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleTimeWindow {
    pub start: String,
    pub end: String,
}

/// A single allowlist rule loaded from the manifest.
///
/// `deny_unknown_fields` (codex round-4 MEDIUM, deliberate choice): the TS
/// rule surface (id / schema_version / created_at / description / match /
/// scope / disposition / time_window / derived) is fully modeled here, so an
/// unknown rule-level field can only come from a NEWER server schema. The
/// daemon and server ship together; the W-series lesson is that silently
/// accepting partially-understood policy produces cross-language enforcement
/// drift. Refusing the manifest is loud (reload responds `ok: false` with a
/// `RuleParse` reason and keeps the prior good policy), mis-enforcing it is
/// silent — so we fail closed on unknown fields at every level of the rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowlistRule {
    pub id: String,
    #[serde(deserialize_with = "de_schema_version")]
    pub schema_version: u32,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "match")]
    pub match_clause: RuleMatch,
    #[serde(default)]
    pub scope: RuleScope,
    pub disposition: RuleDisposition,
    /// Time-of-day activation window (TS parity field). MODELED so it parses,
    /// but UNENFORCEABLE on this daemon — snapshot construction rejects any
    /// rule that carries it (fail closed; see `RuleTimeWindow`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<RuleTimeWindow>,
    /// True when the rule was auto-derived by the composer (habeas lane, DNS
    /// derivation). Informational metadata only: the habeas gate verifies
    /// derived-rule genuineness by exact SHAPE (`crate::habeas`), never by
    /// trusting this flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived: Option<bool>,
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
    /// Daemon-side WAL append failed. Per scope-lock section 7 the
    /// `RuntimeAuditWalAppendFailed` failure mode dispatches to FailClosed
    /// regardless of the original allow/deny verdict; without a durable
    /// audit chain the egress decision cannot be reconstructed, so the
    /// safe default is to drop the packet. Mapped to the `egress_blocked`
    /// audit operation with `decision_provenance = "audit_wal_append_failed"`.
    AuditWalAppendFailed,
}

/// Snapshot of the loaded policy. Built from a verified [`LoadedManifest`]
/// via [`PolicySnapshot::from_loaded_manifest`]; the daemon swaps the
/// snapshot atomically on each successful manifest reload.
#[derive(Debug, Clone, Default)]
pub struct PolicySnapshot {
    pub rules: Vec<AllowlistRule>,
    pub manifest_signature_b64url: Option<String>,
    pub fortress_id: String,
    pub confined_agent_uid: Option<u32>,
}

/// Errors produced when constructing a [`PolicySnapshot`] from a
/// [`LoadedManifest`].
#[derive(Debug, thiserror::Error, Clone)]
pub enum PolicySnapshotError {
    #[error("rule file {file} not present in loaded manifest's rule_files")]
    RuleFileMissing { file: String },
    #[error("rule file {file} could not be parsed as JSON: {source_message}")]
    RuleParse {
        file: String,
        source_message: String,
    },
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
    /// A rule's `match.ip` / `match.cidr` axis contains a malformed entry.
    /// Fail closed (codex round-4 HIGH): a malformed entry would silently
    /// become a non-match at evaluation time, which flips a deny/prompt rule
    /// into "never fires" — so the manifest is rejected at snapshot-build
    /// time instead, mirroring the TS build-time `isValidIp`/`isValidCidr`
    /// gate (`ip-cidr.ts`).
    #[error("rule {rule_id} has a malformed {axis} entry {value:?}: {message}")]
    InvalidMatchAxis {
        rule_id: String,
        axis: &'static str,
        value: String,
        message: &'static str,
    },
    /// The rule carries an axis this daemon cannot enforce (`time_window`).
    /// Fail closed: enforcing the rule WITHOUT its time bound would make an
    /// allow broader than the operator signed, so the manifest is refused
    /// (loud reload error, prior good policy kept) until the daemon grows
    /// time-window enforcement.
    #[error(
        "rule {rule_id} carries the {axis} axis, which this daemon cannot \
         enforce; refusing the manifest rather than enforcing the rule \
         without its {axis} bound"
    )]
    UnenforceableRuleAxis {
        rule_id: String,
        axis: &'static str,
    },
    #[error(
        "agent ids {left_agent_id} and {right_agent_id} collide for {resource_kind} identity {resource_name}"
    )]
    AgentIdentityCollision {
        resource_kind: &'static str,
        resource_name: String,
        left_agent_id: String,
        right_agent_id: String,
    },
    /// The manifest would silence the reserved habeas distress lane (an
    /// operator rule claims a reserved id, or a deny/prompt rule could shadow
    /// the loopback lane or the configured webhook target). Fail closed:
    /// snapshot construction aborts so the daemon keeps the prior good policy
    /// rather than putting a distress-silencing wall into force. Parity with
    /// the TS `HabeasConflictError` (`habeas-port.ts`).
    #[error(
        "manifest rejected: it would silence the reserved habeas distress lane ({}). \
         The habeas lane is the guaranteed distress channel and cannot be removed or \
         shadowed by policy.",
        issues.join("; ")
    )]
    HabeasConflict { issues: Vec<String> },
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
            let bytes = loaded.rule_files.get(&entry.file).ok_or_else(|| {
                PolicySnapshotError::RuleFileMissing {
                    file: entry.file.clone(),
                }
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
            validate_rule_axes(&rule)?;
            rules.push(rule);
        }
        validate_agent_identity_collisions(&rules)?;
        // HABEAS PORT conflict gate (parity with TS findHabeasConflicts): refuse
        // to put a policy into force that would silence the reserved distress
        // lane. Runs over the composed manifest, exempting the genuine derived
        // reserved rules. Fail closed: a conflict aborts snapshot construction
        // and the caller (reload) keeps the prior good policy.
        let habeas_issues = crate::habeas::find_habeas_conflicts_in_composed(&rules);
        if !habeas_issues.is_empty() {
            return Err(PolicySnapshotError::HabeasConflict {
                issues: habeas_issues,
            });
        }
        Ok(Self {
            rules,
            manifest_signature_b64url: Some(loaded.manifest_signature_b64url.clone()),
            fortress_id: loaded.signed.manifest.fortress_id.clone(),
            confined_agent_uid: confined_agent_uid_from_loaded_manifest(loaded),
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
                request.dest_ip.as_deref(),
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

fn confined_agent_uid_from_loaded_manifest(loaded: &LoadedManifest) -> Option<u32> {
    let origin = loaded.signed.manifest.agent_origin.as_ref()?;
    if origin.mode != "uid" {
        return None;
    }

    let agent_uid = origin.agent_uid?;
    if agent_uid < 1 || agent_uid < origin.system_uid_allow_ceiling {
        return None;
    }

    if let Some(gate_uid) = origin.gate_uid {
        if gate_uid < 1
            || gate_uid < origin.system_uid_allow_ceiling
            || gate_uid == agent_uid
        {
            return None;
        }
    }

    Some(agent_uid)
}

/// Validate a parsed rule's match axes at snapshot-build time (codex round-4
/// HIGH + MEDIUM). Mirrors the TS build-time gate (`ip-cidr.ts` `isValidIp` /
/// `parseCidr`):
///
///   - every `match.ip` entry must be a syntactically valid IPv4/IPv6 literal;
///   - every `match.cidr` entry must be `addr/prefix` with a valid IP base, an
///     all-digits prefix, and the prefix within the family's legal range
///     ([0,32] v4, [0,128] v6);
///   - `time_window` must be absent (the daemon cannot enforce it — see
///     [`PolicySnapshotError::UnenforceableRuleAxis`]).
///
/// REJECTING the manifest (rather than letting malformed entries silently
/// never-match at evaluation time) is the fail-closed disposition: a deny rule
/// with a typo'd CIDR must not quietly stop firing.
fn validate_rule_axes(rule: &AllowlistRule) -> Result<(), PolicySnapshotError> {
    if rule.time_window.is_some() {
        return Err(PolicySnapshotError::UnenforceableRuleAxis {
            rule_id: rule.id.clone(),
            axis: "time_window",
        });
    }
    if let Some(ips) = rule.match_clause.ip.as_ref() {
        for entry in ips {
            if entry.parse::<std::net::IpAddr>().is_err() {
                return Err(PolicySnapshotError::InvalidMatchAxis {
                    rule_id: rule.id.clone(),
                    axis: "match.ip",
                    value: entry.clone(),
                    message: "not a valid IPv4/IPv6 literal",
                });
            }
        }
    }
    if let Some(cidrs) = rule.match_clause.cidr.as_ref() {
        for entry in cidrs {
            validate_cidr_literal(entry).map_err(|message| {
                PolicySnapshotError::InvalidMatchAxis {
                    rule_id: rule.id.clone(),
                    axis: "match.cidr",
                    value: entry.clone(),
                    message,
                }
            })?;
        }
    }
    Ok(())
}

/// Syntactic CIDR validation, parity with TS `parseCidr`: `addr/prefix`,
/// valid IP base, all-digits prefix, prefix within the family's legal range.
fn validate_cidr_literal(cidr: &str) -> Result<(), &'static str> {
    use std::net::IpAddr;
    let Some((base_str, prefix_str)) = cidr.split_once('/') else {
        return Err("missing '/prefix'");
    };
    let Ok(base) = base_str.parse::<IpAddr>() else {
        return Err("base address is not a valid IPv4/IPv6 literal");
    };
    if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err("prefix is not a non-negative integer");
    }
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return Err("prefix is not a non-negative integer");
    };
    let max = match base {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err("prefix exceeds the address family's maximum");
    }
    Ok(())
}

fn validate_agent_identity_collisions(rules: &[AllowlistRule]) -> Result<(), PolicySnapshotError> {
    let mut agent_ids = HashSet::new();
    for rule in rules {
        for agent_id in &rule.scope.agent_ids {
            agent_ids.insert(agent_id.as_str());
        }
    }

    let mut systemd_units: HashMap<String, &str> = HashMap::new();
    let mut nft_chains: HashMap<String, &str> = HashMap::new();
    for agent_id in agent_ids {
        reject_identity_collision(
            &mut systemd_units,
            "systemd unit",
            crate::cgroup::scope_unit_name(agent_id),
            agent_id,
        )?;
        reject_identity_collision(
            &mut nft_chains,
            "nft chain",
            crate::nftables::agent_chain_name(agent_id),
            agent_id,
        )?;
    }
    Ok(())
}

fn reject_identity_collision<'a>(
    seen: &mut HashMap<String, &'a str>,
    resource_kind: &'static str,
    resource_name: String,
    agent_id: &'a str,
) -> Result<(), PolicySnapshotError> {
    if let Some(existing) = seen.insert(resource_name.clone(), agent_id) {
        if existing != agent_id {
            return Err(PolicySnapshotError::AgentIdentityCollision {
                resource_kind,
                resource_name,
                left_agent_id: existing.to_string(),
                right_agent_id: agent_id.to_string(),
            });
        }
    }
    Ok(())
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
        Verdict::Deny {
            reason: DeniedReason::AuditWalAppendFailed,
        } => "audit_wal_append_failed",
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
/// `details.rule_id_matched` field. None on default-deny and on the
/// audit-WAL-append-failed dispatch (where the original verdict was
/// discarded in favor of fail-closed).
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
        Verdict::Deny {
            reason: DeniedReason::AuditWalAppendFailed,
        } => None,
    }
}

/// Build the canonical-JSON `AuditEntry` body for a verdict + request.
/// Shape matches scope-lock §8 critical-event recommendation: `layer:
/// "l1"`, `operation` from [`operation_for_verdict`], `identity_id` =
/// the canonical Sanctuary protection subject (`fortress_id/uid-N`) when the
/// signed manifest binds Linux uid-mode origin, `result` from
/// [`result_for_verdict`], and a `details` object carrying destination metadata
/// + rule provenance.
///
/// The body is canonicalized so the bytes Sanctuary main signs on drain
/// match what the daemon hashed into the WAL chain. `timestamp_iso8601`
/// is supplied by the caller (the daemon stamps it at evaluation time).
pub fn build_audit_event_canonical_json(
    verdict: &Verdict,
    request: &EvaluationRequest,
    fortress_id: &str,
    confined_agent_uid: Option<u32>,
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
        details.insert("dest_ip".to_string(), serde_json::Value::String(ip.clone()));
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
        serde_json::Value::String(
            protection_subject_for_uid(fortress_id, confined_agent_uid)
                .unwrap_or_else(|| request.agent_id.clone()),
        ),
    );
    entry.insert(
        "fortress_id".to_string(),
        serde_json::Value::String(fortress_id.to_string()),
    );
    entry.insert(
        "result".to_string(),
        serde_json::Value::String(result_for_verdict(verdict).to_string()),
    );
    entry.insert("details".to_string(), serde_json::Value::Object(details));

    canonicalize(&serde_json::Value::Object(entry))
}

fn protection_subject_for_uid(fortress_id: &str, uid: Option<u32>) -> Option<String> {
    let uid = uid.filter(|candidate| *candidate > 0)?;
    if fortress_id.is_empty() {
        return None;
    }
    Some(format!("{fortress_id}/uid-{uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::canonical_json::canonicalize_to_bytes;
    use crate::manifest::verify::{
        AgentOrigin, AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
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
            time_window: None,
            derived: None,
        }
    }

    fn snapshot(rules: Vec<AllowlistRule>) -> PolicySnapshot {
        PolicySnapshot {
            rules,
            manifest_signature_b64url: Some("test-sig".to_string()),
            fortress_id: "deadbeef".to_string(),
            confined_agent_uid: Some(503),
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
                ip: None,
                cidr: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            scope: RuleScope::default(),
            disposition: RuleDisposition::Allow,
            time_window: None,
            derived: None,
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
            ip: None,
            cidr: None,
            port: None,
            protocol: None,
        };
        assert!(m.matches(Some("api.example.com"), None, 443, "tcp"));
        assert!(m.matches(Some("API.EXAMPLE.COM"), None, 443, "tcp"));
        assert!(!m.matches(Some("other.example.com"), None, 443, "tcp"));
    }

    #[test]
    fn match_host_pattern_suffix_glob() {
        let m = RuleMatch {
            host: None,
            host_pattern: Some(".example.com".to_string()),
            ip: None,
            cidr: None,
            port: None,
            protocol: None,
        };
        assert!(m.matches(Some("api.example.com"), None, 443, "tcp"));
        assert!(m.matches(Some("a.b.c.example.com"), None, 443, "tcp"));
        // Apex does NOT match the leading-dot suffix glob.
        assert!(!m.matches(Some("example.com"), None, 443, "tcp"));
        // Different domain.
        assert!(!m.matches(Some("api.evil.com"), None, 443, "tcp"));
    }

    #[test]
    fn match_host_pattern_without_leading_dot_does_not_match() {
        // Defensive: pattern without leading dot is malformed and should
        // not match anything, so manifest typos can't accidentally allow.
        let m = RuleMatch {
            host: None,
            host_pattern: Some("example.com".to_string()),
            ip: None,
            cidr: None,
            port: None,
            protocol: None,
        };
        assert!(!m.matches(Some("api.example.com"), None, 443, "tcp"));
        assert!(!m.matches(Some("example.com"), None, 443, "tcp"));
    }

    #[test]
    fn match_host_axis_absent_is_unconstrained() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            ip: None,
            cidr: None,
            port: Some(vec![443]),
            protocol: Some("tcp".to_string()),
        };
        assert!(m.matches(Some("anything.example.com"), None, 443, "tcp"));
        assert!(m.matches(None, None, 443, "tcp"));
    }

    #[test]
    fn match_host_constraint_with_no_dest_host_misses() {
        // Rule asks for a specific host but the attempt is raw-IP.
        let m = RuleMatch {
            host: Some(vec!["api.example.com".to_string()]),
            host_pattern: None,
            ip: None,
            cidr: None,
            port: None,
            protocol: None,
        };
        assert!(!m.matches(None, None, 443, "tcp"));
    }

    #[test]
    fn match_port_must_be_in_set() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            ip: None,
            cidr: None,
            port: Some(vec![443, 8443]),
            protocol: None,
        };
        assert!(m.matches(Some("x"), None, 443, "tcp"));
        assert!(m.matches(Some("x"), None, 8443, "tcp"));
        assert!(!m.matches(Some("x"), None, 80, "tcp"));
    }

    #[test]
    fn match_protocol_case_insensitive() {
        let m = RuleMatch {
            host: None,
            host_pattern: None,
            ip: None,
            cidr: None,
            port: None,
            protocol: Some("TCP".to_string()),
        };
        assert!(m.matches(Some("x"), None, 443, "tcp"));
        assert!(m.matches(Some("x"), None, 443, "TCP"));
        assert!(!m.matches(Some("x"), None, 443, "udp"));
    }

    #[test]
    fn match_protocol_tcp_plus_udp_matches_either_transport() {
        // TS schema parity: the composer's derived DNS rule uses
        // protocol "tcp+udp"; it must match both transports (and nothing
        // else), never silently fail to fire.
        let m = RuleMatch {
            protocol: Some("tcp+udp".to_string()),
            ..Default::default()
        };
        assert!(m.matches(Some("x"), None, 53, "tcp"));
        assert!(m.matches(Some("x"), None, 53, "udp"));
        assert!(m.matches(Some("x"), None, 53, "UDP"));
        assert!(!m.matches(Some("x"), None, 53, "icmp"));
    }

    #[test]
    fn match_ip_axis_family_aware_exact() {
        let m = RuleMatch {
            ip: Some(vec!["127.0.0.1".to_string(), "::1".to_string()]),
            port: Some(vec![8741]),
            protocol: Some("tcp".to_string()),
            ..Default::default()
        };
        // dest_ip path.
        assert!(m.matches(None, Some("127.0.0.1"), 8741, "tcp"));
        assert!(m.matches(None, Some("0:0:0:0:0:0:0:1"), 8741, "tcp")); // ::1 normalized
        // dest_host carrying an IP literal also matches the ip axis.
        assert!(m.matches(Some("127.0.0.1"), None, 8741, "tcp"));
        // A non-loopback IP does NOT match (the key regression fix: an ip-only
        // rule is no longer "any host").
        assert!(!m.matches(None, Some("8.8.8.8"), 8741, "tcp"));
        // A hostname destination cannot satisfy an ip-only rule.
        assert!(!m.matches(Some("api.example.com"), None, 8741, "tcp"));
        // Wrong port misses.
        assert!(!m.matches(None, Some("127.0.0.1"), 80, "tcp"));
    }

    #[test]
    fn match_cidr_axis_family_aware_containment() {
        let m = RuleMatch {
            cidr: Some(vec!["10.0.0.0/8".to_string(), "::1/128".to_string()]),
            ..Default::default()
        };
        assert!(m.matches(None, Some("10.1.2.3"), 443, "tcp"));
        assert!(m.matches(None, Some("::1"), 443, "tcp"));
        // In-range v4 matches.
        assert!(m.matches(None, Some("10.0.0.1"), 443, "tcp"));
        // Outside the subnet.
        assert!(!m.matches(None, Some("11.0.0.1"), 443, "tcp"));
        // Family mismatch / outside v6 prefix never matches.
        assert!(!m.matches(None, Some("2001:db8::1"), 443, "tcp"));
    }

    #[test]
    fn match_destination_axes_compose_as_or() {
        // host OR ip: a flow matching EITHER axis matches.
        let m = RuleMatch {
            host: Some(vec!["api.example.com".to_string()]),
            ip: Some(vec!["203.0.113.7".to_string()]),
            ..Default::default()
        };
        assert!(m.matches(Some("api.example.com"), None, 443, "tcp"));
        assert!(m.matches(None, Some("203.0.113.7"), 443, "tcp"));
        assert!(!m.matches(Some("other.example.com"), Some("203.0.113.8"), 443, "tcp"));
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
                ip: None,
                cidr: None,
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
                ip: None,
                cidr: None,
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
                ip: None,
                cidr: None,
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
                ip: None,
                cidr: None,
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
                    ip: None,
                    cidr: None,
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
                    ip: None,
                    cidr: None,
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
                ip: None,
                cidr: None,
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

    /// The genuine derived habeas local rule. Every composed manifest must
    /// carry exactly one (the always-on-lane gate), so happy-path snapshot
    /// fixtures include it.
    fn habeas_local_rule() -> AllowlistRule {
        rule(
            crate::habeas::HABEAS_LOCAL_RULE_ID,
            RuleMatch {
                ip: Some(vec!["127.0.0.1".to_string(), "::1".to_string()]),
                port: Some(vec![crate::habeas::HABEAS_DISTRESS_PORT]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
            RuleScope {
                agent_ids: vec!["sanctuary:habeas-distress-emitter".to_string()],
                template_ids: Vec::new(),
            },
            RuleDisposition::Allow,
        )
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
            agent_origin: None,
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
                ip: None,
                cidr: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        let loaded = synthetic_loaded(vec![
            ("rule-0.json".to_string(), r1.clone()),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ]);
        let snap = PolicySnapshot::from_loaded_manifest(&loaded).expect("snapshot");
        assert_eq!(snap.rules.len(), 2);
        assert_eq!(snap.rules[0], r1);
        assert_eq!(snap.fortress_id, "deadbeef");
        assert_eq!(snap.confined_agent_uid, None);
    }

    #[test]
    fn snapshot_records_uid_mode_agent_origin_for_linux_audit_subjects() {
        let r1 = rule(
            "uuid-1",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        let mut loaded = synthetic_loaded(vec![
            ("rule-0.json".to_string(), r1),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ]);
        loaded.signed.manifest.agent_origin = Some(AgentOrigin {
            mode: "uid".to_string(),
            egress_helper_signing_id: None,
            egress_helper_team_id: None,
            agent_runtime_port_range: None,
            agent_uid: Some(503),
            gate_uid: Some(504),
            system_uid_allow_ceiling: 500,
        });

        let snap = PolicySnapshot::from_loaded_manifest(&loaded).expect("snapshot");

        assert_eq!(snap.confined_agent_uid, Some(503));
    }

    #[test]
    fn snapshot_refuses_uid_mode_agent_origin_below_system_uid_ceiling() {
        let r1 = rule(
            "uuid-1",
            RuleMatch {
                host: Some(vec!["api.anthropic.com".to_string()]),
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        let mut loaded = synthetic_loaded(vec![
            ("rule-0.json".to_string(), r1),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ]);
        loaded.signed.manifest.agent_origin = Some(AgentOrigin {
            mode: "uid".to_string(),
            egress_helper_signing_id: None,
            egress_helper_team_id: None,
            agent_runtime_port_range: None,
            agent_uid: Some(65),
            gate_uid: None,
            system_uid_allow_ceiling: 500,
        });

        let snap = PolicySnapshot::from_loaded_manifest(&loaded).expect("snapshot");

        assert_eq!(snap.confined_agent_uid, None);

        let body = build_audit_event_canonical_json(
            &Verdict::Deny {
                reason: DeniedReason::DefaultDeny,
            },
            &req(Some("evil.example"), 443, "tcp"),
            "fortress:test",
            snap.confined_agent_uid,
            "2026-05-05T01:02:03Z",
        )
        .unwrap();
        let parsed = parse_canonical(&body);
        assert_ne!(parsed["identity_id"], json!("fortress:test/uid-65"));
        assert_eq!(parsed["identity_id"], json!("agent-1"));
    }

    #[test]
    fn snapshot_accepts_agent_ids_that_used_to_sanitize_collide() {
        let r1 = rule(
            "uuid-slash",
            RuleMatch {
                host: None,
                host_pattern: None,
                ip: None,
                cidr: None,
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope {
                agent_ids: vec!["agent/a".to_string()],
                template_ids: Vec::new(),
            },
            RuleDisposition::Allow,
        );
        let r2 = rule(
            "uuid-underscore",
            RuleMatch {
                host: None,
                host_pattern: None,
                ip: None,
                cidr: None,
                port: Some(vec![8443]),
                protocol: Some("tcp".to_string()),
            },
            RuleScope {
                agent_ids: vec!["agent_a".to_string()],
                template_ids: Vec::new(),
            },
            RuleDisposition::Deny,
        );
        let loaded = synthetic_loaded(vec![
            ("rule-0.json".to_string(), r1.clone()),
            ("rule-1.json".to_string(), r2.clone()),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ]);

        let snap = PolicySnapshot::from_loaded_manifest(&loaded).expect("snapshot");

        assert_eq!(snap.rules, vec![r1, r2, habeas_local_rule()]);
    }

    #[test]
    fn snapshot_rejects_rule_id_mismatch() {
        let r = rule(
            "uuid-real",
            RuleMatch {
                host: None,
                host_pattern: None,
                ip: None,
                cidr: None,
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
            agent_origin: None,
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
                ip: None,
                cidr: None,
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
                ip: None,
                cidr: None,
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
            agent_origin: None,
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

    // ---- codex round-4 HIGH: malformed ip/cidr fail closed -----------------

    fn loaded_with_single_match(match_clause: RuleMatch) -> LoadedManifest {
        synthetic_loaded(vec![
            (
                "rule-0.json".to_string(),
                // Allow disposition: these tests target axis validation, which
                // runs BEFORE the habeas conflict gate; an allow rule cannot
                // trip the gate's deny/prompt loopback-shadow scan.
                rule("uuid-1", match_clause, RuleScope::default(), RuleDisposition::Allow),
            ),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ])
    }

    #[test]
    fn snapshot_rejects_malformed_ip_entries() {
        for bad in ["999.0.0.1", "not-an-ip", "::g", "127.0.0.1/8", ""] {
            let loaded = loaded_with_single_match(RuleMatch {
                ip: Some(vec![bad.to_string()]),
                ..Default::default()
            });
            let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
            assert!(
                matches!(
                    err,
                    PolicySnapshotError::InvalidMatchAxis { axis: "match.ip", .. }
                ),
                "ip entry {bad:?} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn snapshot_rejects_malformed_cidr_entries() {
        for bad in [
            "10.0.0.0",      // missing prefix
            "10.0.0.0/33",   // v4 prefix out of range
            "::1/129",       // v6 prefix out of range
            "10.0.0.0/abc",  // non-numeric prefix
            "10.0.0.0/-1",   // negative prefix
            "10.0.0.0/",     // empty prefix
            "999.0.0.0/8",   // malformed base
            "evil.com/8",    // hostname base
        ] {
            let loaded = loaded_with_single_match(RuleMatch {
                cidr: Some(vec![bad.to_string()]),
                ..Default::default()
            });
            let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
            assert!(
                matches!(
                    err,
                    PolicySnapshotError::InvalidMatchAxis { axis: "match.cidr", .. }
                ),
                "cidr entry {bad:?} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn snapshot_accepts_wellformed_ip_and_cidr() {
        let loaded = loaded_with_single_match(RuleMatch {
            ip: Some(vec!["192.0.2.1".to_string(), "2001:db8::1".to_string()]),
            cidr: Some(vec!["10.0.0.0/8".to_string(), "::1/128".to_string()]),
            ..Default::default()
        });
        PolicySnapshot::from_loaded_manifest(&loaded).expect("well-formed axes accepted");
    }

    // ---- codex round-4 MEDIUM: unmodeled / unenforceable axes fail closed --

    #[test]
    fn snapshot_rejects_rule_with_time_window() {
        // The daemon cannot enforce time windows; a rule carrying one must be
        // refused rather than enforced without its time bound.
        let mut r = rule(
            "uuid-1",
            RuleMatch {
                host: Some(vec!["api.example.com".to_string()]),
                ..Default::default()
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        r.time_window = Some(RuleTimeWindow {
            start: "09:00".to_string(),
            end: "17:00".to_string(),
        });
        let loaded = synthetic_loaded(vec![
            ("rule-0.json".to_string(), r),
            ("rule-habeas.json".to_string(), habeas_local_rule()),
        ]);
        let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
        assert!(matches!(
            err,
            PolicySnapshotError::UnenforceableRuleAxis { axis: "time_window", .. }
        ));
    }

    #[test]
    fn scalar_axis_forms_parse_as_one_element_vecs() {
        // codex round-5 MEDIUM: the TS schema types list axes as `T | T[]`
        // and signs scalar-form rules as-is; the daemon must accept them.
        let raw = r#"{ "id": "uuid-1", "schema_version": 1, "created_at": "2026-05-05T00:00:00Z", "match": { "host": "api.example.com", "ip": "203.0.113.7", "cidr": "10.0.0.0/8", "port": 443 }, "scope": {}, "disposition": "allow" }"#;
        let parsed = serde_json::from_str::<AllowlistRule>(raw).expect("scalar forms parse");
        assert_eq!(parsed.match_clause.host.as_deref(), Some(&["api.example.com".to_string()][..]));
        assert_eq!(parsed.match_clause.ip.as_deref(), Some(&["203.0.113.7".to_string()][..]));
        assert_eq!(parsed.match_clause.cidr.as_deref(), Some(&["10.0.0.0/8".to_string()][..]));
        assert_eq!(parsed.match_clause.port.as_deref(), Some(&[443u16][..]));
        // Array forms still parse identically.
        let raw_arrays = raw
            .replace("\"api.example.com\"", "[\"api.example.com\"]")
            .replace("\"203.0.113.7\"", "[\"203.0.113.7\"]")
            .replace("\"10.0.0.0/8\"", "[\"10.0.0.0/8\"]")
            .replace(": 443", ": [443]");
        let parsed_arrays =
            serde_json::from_str::<AllowlistRule>(&raw_arrays).expect("array forms parse");
        assert_eq!(parsed, parsed_arrays);
    }

    #[test]
    fn json_number_token_spellings_parse_for_port_and_schema_version() {
        // codex round-7: JSON has one number type — `443.0` and `4.43e2`
        // denote 443, and the TS parser/validator accepts those spellings in
        // a signed rule file. serde must agree.
        let raw = r#"{ "id": "uuid-1", "schema_version": 1.0, "created_at": "2026-05-05T00:00:00Z", "match": { "host": ["api.example.com"], "port": [443.0, 4.43e2, 80] }, "scope": {}, "disposition": "allow" }"#;
        let parsed = serde_json::from_str::<AllowlistRule>(raw).expect("number tokens parse");
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.match_clause.port.as_deref(), Some(&[443u16, 443, 80][..]));
    }

    #[test]
    fn non_integral_or_out_of_range_ports_fail_to_parse() {
        for bad in ["443.5", "0", "70000", "-1", "1e9"] {
            let raw = format!(
                "{{\"id\":\"uuid-1\",\"schema_version\":1,\
                 \"created_at\":\"2026-05-05T00:00:00Z\",\
                 \"match\":{{\"port\":[{bad}]}},\"scope\":{{}},\
                 \"disposition\":\"allow\"}}"
            );
            assert!(
                serde_json::from_str::<AllowlistRule>(&raw).is_err(),
                "port token {bad} must be rejected"
            );
        }
    }

    #[test]
    fn rule_with_unknown_match_axis_fails_to_parse() {
        // deny_unknown_fields on RuleMatch: an unmodeled match axis (a newer
        // constraint this daemon cannot enforce) must reject the rule, not be
        // silently ignored.
        let raw = r#"{ "id": "uuid-1", "schema_version": 1, "created_at": "2026-05-05T00:00:00Z", "match": { "host": ["api.example.com"], "future_axis": ["x"] }, "scope": {}, "disposition": "deny" }"#;
        let parsed = serde_json::from_str::<AllowlistRule>(raw);
        assert!(parsed.is_err(), "unknown match axis must fail deserialization");
        assert!(parsed.unwrap_err().to_string().contains("future_axis"));
    }

    #[test]
    fn rule_with_unknown_top_level_field_fails_to_parse() {
        let raw = r#"{ "id": "uuid-1", "schema_version": 1, "created_at": "2026-05-05T00:00:00Z", "match": { "host": ["api.example.com"] }, "scope": {}, "disposition": "deny", "novel_field": true }"#;
        assert!(serde_json::from_str::<AllowlistRule>(raw).is_err());
    }

    // ---- S5-0 (2026-07-14 two-confined-uid extension, macOS Castle Wall) ----
    //
    // The macOS sysext + TS producer gained an optional `scope.uids` axis so
    // an endpoint rule can bind to a SECOND confined uid (a `sanctuary-gate`
    // account) without matching the wrapped agent's uid. This daemon (Linux,
    // cgroup/nftables-based) has NO per-flow raw-uid attribution concept --
    // its `RuleScope::applies_to` reasons over `(agent_id, agent_template)`
    // strings resolved from a cgroup-tagged process, never a uid. `uids` is
    // therefore out of this daemon's wire vocabulary by design, not omission.
    //
    // The existing `deny_unknown_fields` on `RuleScope` (see its doc comment
    // above: "an ignored (unmodeled) scope axis would apply a rule to MORE
    // agents than the operator intended") is the CORRECT, deliberate response
    // to a `uids`-bearing rule: refuse the rule file outright (fail closed,
    // "RuleParse" error, keep the prior good policy) rather than silently
    // drop the axis and risk enforcing a rule wider than what was signed.
    // This test proves that safety net actually holds for the new field --
    // no Rust source change was needed or made for S5-0; this only pins the
    // existing behavior so a future serde/schema refactor cannot silently
    // regress it into an ignored-field accept.
    #[test]
    fn rule_with_macos_gate_uid_scope_axis_fails_to_parse_not_silently_ignored() {
        let raw = r#"{ "id": "uuid-1", "schema_version": 1, "created_at": "2026-05-05T00:00:00Z", "match": { "host": ["gate-endpoint.example.com"] }, "scope": { "uids": [601] }, "disposition": "allow" }"#;
        let parsed = serde_json::from_str::<AllowlistRule>(raw);
        assert!(
            parsed.is_err(),
            "a macOS-only scope.uids axis must fail deserialization here, not silently apply to every agent"
        );
        assert!(parsed.unwrap_err().to_string().contains("uids"));
    }

    #[test]
    fn rule_with_derived_flag_and_time_window_field_parses() {
        // The full TS rule surface is modeled: `derived` and `time_window`
        // parse (time_window is then rejected by the snapshot gate, not the
        // parser).
        let raw = r#"{ "id": "uuid-1", "schema_version": 1, "created_at": "2026-05-05T00:00:00Z", "match": { "host": ["api.example.com"] }, "scope": {}, "disposition": "allow", "derived": true, "time_window": { "start": "09:00", "end": "17:00" } }"#;
        let parsed = serde_json::from_str::<AllowlistRule>(raw).expect("modeled fields parse");
        assert_eq!(parsed.derived, Some(true));
        assert!(parsed.time_window.is_some());
    }

    // ---- codex round-4 HIGH: always-on lane required in every manifest -----

    #[test]
    fn snapshot_rejects_manifest_without_habeas_local_lane() {
        let r1 = rule(
            "uuid-1",
            RuleMatch {
                host: Some(vec!["api.example.com".to_string()]),
                port: Some(vec![443]),
                ..Default::default()
            },
            RuleScope::default(),
            RuleDisposition::Allow,
        );
        let loaded = synthetic_loaded(vec![("rule-0.json".to_string(), r1)]);
        let err = PolicySnapshot::from_loaded_manifest(&loaded).unwrap_err();
        match err {
            PolicySnapshotError::HabeasConflict { issues } => {
                assert!(issues.iter().any(|i| i.contains("exactly one")));
            }
            other => panic!("expected HabeasConflict, got: {other}"),
        }
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
        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["layer"], json!("l1"));
        assert_eq!(parsed["operation"], json!("egress_approved"));
        assert_eq!(parsed["fortress_id"], json!("deadbeef"));
        assert_eq!(parsed["identity_id"], json!("deadbeef/uid-503"));
        assert_eq!(parsed["result"], json!("success"));
        assert_eq!(parsed["timestamp"], json!("2026-05-05T01:02:03Z"));
        assert_eq!(parsed["details"]["dest_host"], json!("api.anthropic.com"));
        assert_eq!(parsed["details"]["dest_port"], json!(443));
        assert_eq!(parsed["details"]["dest_protocol"], json!("tcp"));
        assert_eq!(parsed["details"]["agent_id"], json!("agent-1"));
        assert_eq!(parsed["details"]["agent_template"], json!("claude-code"));
        assert_eq!(parsed["details"]["rule_id_matched"], json!("r1"));
        assert_eq!(
            parsed["details"]["decision_provenance"],
            json!("static_rule")
        );
        assert_eq!(parsed["details"]["opaque"], json!(false));
    }

    #[test]
    fn audit_preserves_raw_agent_id_for_kernel_encoded_names() {
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let mut request = req(Some("api.example.com"), 443, "tcp");
        request.agent_id = "agent/a".to_string();

        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let parsed = parse_canonical(&body);

        assert_eq!(parsed["identity_id"], json!("deadbeef/uid-503"));
        assert_eq!(parsed["details"]["agent_id"], json!("agent/a"));
    }

    #[test]
    fn audit_without_uid_origin_keeps_legacy_agent_name_subject_unbound_shape() {
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let request = req(Some("api.example.com"), 443, "tcp");

        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            None,
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let parsed = parse_canonical(&body);

        assert_eq!(parsed["fortress_id"], json!("deadbeef"));
        assert_eq!(parsed["identity_id"], json!("agent-1"));
        assert_eq!(parsed["details"]["agent_id"], json!("agent-1"));
    }

    #[test]
    fn linux_audit_fixture_vectors_are_emitted_by_the_audit_builder() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../server/test/castle-wall/fixtures/linux-daemon-canonical-subject-audit-vectors.json"
        )).unwrap();
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let request = req(Some("evil.example"), 443, "tcp");
        let uid_503 = build_audit_event_canonical_json(
            &v,
            &request,
            "fortress:test",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let uid_504 = build_audit_event_canonical_json(
            &v,
            &request,
            "fortress:test",
            Some(504),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let old_agent_name = build_audit_event_canonical_json(
            &v,
            &request,
            "fortress:test",
            None,
            "2026-05-05T01:02:03Z",
        ).unwrap();

        assert_eq!(uid_503, fixture["uid_503"].as_str().unwrap());
        assert_eq!(uid_504, fixture["uid_504"].as_str().unwrap());
        assert_eq!(
            old_agent_name,
            fixture["old_agent_name"].as_str().unwrap()
        );

        if std::env::var("SANCTUARY_CAPTURE_LINUX_AUDIT_FIXTURES").as_deref() == Ok("1") {
            println!("uid_503={uid_503}");
            println!("uid_504={uid_504}");
            println!("old_agent_name={old_agent_name}");
        }
    }

    #[test]
    fn audit_for_default_deny_emits_egress_blocked_with_default_deny_provenance() {
        let v = Verdict::Deny {
            reason: DeniedReason::DefaultDeny,
        };
        let request = req(Some("api.evil.com"), 443, "tcp");
        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["operation"], json!("egress_blocked"));
        assert_eq!(parsed["result"], json!("failure"));
        assert_eq!(
            parsed["details"]["decision_provenance"],
            json!("default_deny")
        );
        assert_eq!(
            parsed["details"]["rule_id_matched"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn audit_for_explicit_deny_emits_static_rule_provenance() {
        let v = Verdict::Deny {
            reason: DeniedReason::ExplicitRule {
                rule_id: "r-deny".to_string(),
            },
        };
        let request = req(Some("pastebin.com"), 443, "tcp");
        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let parsed = parse_canonical(&body);
        assert_eq!(parsed["operation"], json!("egress_blocked"));
        assert_eq!(
            parsed["details"]["decision_provenance"],
            json!("static_rule")
        );
        assert_eq!(parsed["details"]["rule_id_matched"], json!("r-deny"));
    }

    #[test]
    fn audit_for_prompt_emits_egress_pending() {
        let v = Verdict::PromptRequired {
            rule_id: "r-prompt".to_string(),
        };
        let request = req(Some("api.example.com"), 443, "tcp");
        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
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
        let body = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(504),
            "2026-05-05T01:02:03Z",
        ).unwrap();
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
        let a = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        let b = build_audit_event_canonical_json(
            &v,
            &request,
            "deadbeef",
            Some(503),
            "2026-05-05T01:02:03Z",
        ).unwrap();
        assert_eq!(a, b);
        // Same shape under canonical-JSON byte serialization.
        let bytes_a = canonicalize_to_bytes(&serde_json::from_str(&a).unwrap()).unwrap();
        assert_eq!(a.as_bytes(), bytes_a.as_slice());
    }
}
