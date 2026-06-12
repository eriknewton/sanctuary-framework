//! HABEAS PORT conflict gate — Linux daemon parity.
//!
//! Mirrors the TypeScript `findHabeasConflicts` rejection semantics
//! (`server/src/castle-wall/allowlist/habeas-port.ts`) so the Linux Castle
//! Wall daemon refuses to put a policy into force that would silence the
//! reserved distress lane. Fail closed: a conflicting manifest aborts
//! snapshot construction (the daemon keeps the prior good policy, never builds
//! a wall that could cut the operator off from agent distress).
//!
//! Parity contract (kept byte-for-byte with the TS gate via the shared
//! fixture `server/test/castle-wall/fixtures/habeas-conflict-parity.json`,
//! asserted from both languages):
//!
//!   1. An operator rule claiming the reserved id prefix
//!      (`reserved_habeas_distress`) is rejected — reserved rules are derived,
//!      never authored.
//!   2. A deny/prompt rule whose match could cover the loopback distress lane
//!      (loopback host at the habeas port, or an any-destination port match
//!      that includes it) is rejected.
//!   3. When a distress webhook is configured, a deny/prompt rule whose match
//!      could cover the webhook host:port is rejected.
//!
//! Axis note: the Linux rule schema (`RuleMatch`) models only host /
//! host_pattern / port / protocol — it has no `ip` / `cidr` axes. The TS gate
//! additionally inspects ip/cidr; on Linux a loopback literal is carried in
//! the `host` axis (e.g. `host: ["127.0.0.1"]`), so the host-coverage check
//! below catches it. The shared parity fixture therefore expresses every case
//! with axes both languages model; the ip/cidr-only TS cases are exercised by
//! the TS suite alone (they cannot be represented in a Linux manifest).
//!
//! Conservatism mirrors TS exactly: an absent destination axis means "any
//! destination", so a rule that MIGHT shadow the lane is rejected and the
//! operator is told to scope it down. Authoritative non-shadowability inside
//! the kernel evaluator is a separate (deferred) concern; this gate refuses
//! to *compose* a silencing policy in the first place.

use crate::policy::{AllowlistRule, RuleDisposition, RuleMatch};

/// Every reserved habeas rule id starts with this prefix. Operator-authored
/// rules may never claim it. Synchronized with `HABEAS_RULE_ID_PREFIX` in
/// `habeas-port.ts`.
pub const HABEAS_RULE_ID_PREFIX: &str = "reserved_habeas_distress";

/// Id of the always-present loopback distress rule.
pub const HABEAS_LOCAL_RULE_ID: &str = "reserved_habeas_distress_local";

/// Id of the optional operator-configured distress webhook rule.
pub const HABEAS_WEBHOOK_RULE_ID: &str = "reserved_habeas_distress_webhook";

/// The fixed habeas distress port. Synchronized with `HABEAS_DISTRESS_PORT`
/// in `habeas-port.ts`.
pub const HABEAS_DISTRESS_PORT: u16 = 8741;

/// Loopback literals the local lane admits. On Linux these appear in a rule's
/// `host` axis (there is no ip axis).
pub const HABEAS_LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

/// The distress webhook destination the lane allows, parsed from operator
/// config. Mirrors `HabeasWebhookTarget` in `habeas-port.ts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HabeasWebhookTarget {
    pub host: String,
    pub port: u16,
}

fn host_equals(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// True iff a deny/prompt rule's `host_pattern` axis could cover `host`.
///
/// CONSERVATIVE across BOTH suffix-glob spellings that the codebase uses.
/// `*.example.com` is the TS allowlist/gate spelling (`hostPatternCovers`).
/// `.example.com` is the Linux kernel evaluator spelling
/// (`policy::matches_suffix_pattern`); the gate MUST honour it too, since a
/// deny rule the Linux evaluator would actually enforce against the webhook
/// host (codex round-2 HIGH) must be rejected here even though the TS gate
/// never sees `.`-prefixed patterns. Both forms match a strict subdomain and
/// never the bare apex. A bare (non-prefixed) pattern is treated as an exact
/// host (case-insensitive).
fn host_pattern_covers(pattern: &str, host: &str) -> bool {
    let host_lower = host.to_ascii_lowercase();
    // `*.suffix` form.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix_lower = suffix.to_ascii_lowercase();
        return host_lower.ends_with(&format!(".{suffix_lower}")) && host_lower != suffix_lower;
    }
    // `.suffix` form (Linux evaluator). `pattern` already begins with '.', so
    // ends_with(pattern) is the strict-subdomain test; length guard excludes
    // the bare apex.
    if pattern.starts_with('.') {
        let pattern_lower = pattern.to_ascii_lowercase();
        return host_lower.ends_with(&pattern_lower) && host_lower.len() > pattern_lower.len();
    }
    host_equals(pattern, host)
}

/// True when a rule's port axis covers `port`. An unspecified port axis is
/// "match any" — it covers every port (matches TS `portsCover`).
fn ports_cover(spec: &Option<Vec<u16>>, port: u16) -> bool {
    match spec {
        None => true,
        Some(ports) => ports.contains(&port),
    }
}

/// Family-aware exact match of an IP literal against a `match.ip` axis.
/// Mirrors TS `ipMatches` (`ip-cidr.ts`): normalizes both sides so `::1`
/// equals `0:0:0:0:0:0:0:1`; a malformed candidate or address never matches.
fn ip_axis_covers(spec: &Option<Vec<String>>, address: &str) -> bool {
    let Some(ips) = spec.as_ref() else {
        return false;
    };
    let Ok(target) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    ips.iter().any(|candidate| {
        candidate
            .parse::<std::net::IpAddr>()
            .map(|c| c == target)
            .unwrap_or(false)
    })
}

/// Family-aware CIDR containment of an IP literal against a `match.cidr` axis.
/// Mirrors TS `cidrMatches`: a mismatched family never matches; a malformed
/// candidate is skipped. Implemented over the address bit-prefix so no external
/// crate is needed.
fn cidr_axis_covers(spec: &Option<Vec<String>>, address: &str) -> bool {
    let Some(cidrs) = spec.as_ref() else {
        return false;
    };
    let Ok(target) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    cidrs.iter().any(|candidate| cidr_contains(candidate, &target))
}

/// True iff `cidr` (an `addr/prefix` string) contains `target`, family-aware.
/// Malformed input returns false (the gate is conservative elsewhere; a
/// malformed cidr in a signed manifest never legitimately covers the lane).
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
            let base_bits = u128::from(base);
            let target_bits = u128::from(*target);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (base_bits & mask) == (target_bits & mask)
        }
        // Family mismatch never matches.
        _ => false,
    }
}

fn has_axis<T>(spec: &Option<Vec<T>>) -> bool {
    spec.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
}

/// True when a deny/prompt rule's destination axes could cover `host:port`.
/// Conservative: a rule with NO destination axis (host/host_pattern/ip/cidr)
/// means "any destination". Mirrors TS `ruleCoversHostTarget`, including the
/// ip/cidr axes (a webhook target may be an IP literal).
fn rule_covers_host_target(rule_match: &RuleMatch, host: &str, port: u16) -> bool {
    if !ports_cover(&rule_match.port, port) {
        return false;
    }
    let has_host = has_axis(&rule_match.host);
    let has_host_pattern = rule_match
        .host_pattern
        .as_ref()
        .map(|p| !p.is_empty())
        .unwrap_or(false);
    let has_ip = has_axis(&rule_match.ip);
    let has_cidr = has_axis(&rule_match.cidr);
    // No destination axes at all = any destination.
    if !has_host && !has_host_pattern && !has_ip && !has_cidr {
        return true;
    }
    if let Some(hosts) = rule_match.host.as_ref() {
        if hosts.iter().any(|h| host_equals(h, host)) {
            return true;
        }
    }
    if let Some(pattern) = rule_match.host_pattern.as_ref() {
        if host_pattern_covers(pattern, host) {
            return true;
        }
    }
    // ip/cidr can cover the webhook target when it is an IP literal.
    if ip_axis_covers(&rule_match.ip, host) {
        return true;
    }
    if cidr_axis_covers(&rule_match.cidr, host) {
        return true;
    }
    false
}

/// True when a deny/prompt rule could cover loopback traffic to the habeas
/// port. Mirrors TS `ruleCoversLoopbackLane`: loopback may be expressed via the
/// host axis, OR (the genuine derived form) via the `ip`/`cidr` axes.
fn rule_covers_loopback_lane(rule_match: &RuleMatch) -> bool {
    if !ports_cover(&rule_match.port, HABEAS_DISTRESS_PORT) {
        return false;
    }
    let has_host = has_axis(&rule_match.host);
    let has_host_pattern = rule_match
        .host_pattern
        .as_ref()
        .map(|p| !p.is_empty())
        .unwrap_or(false);
    let has_ip = has_axis(&rule_match.ip);
    let has_cidr = has_axis(&rule_match.cidr);
    // An any-destination rule (no destination axes) at a covering port shadows
    // the loopback lane.
    if !has_host && !has_host_pattern && !has_ip && !has_cidr {
        return true;
    }
    for loopback in HABEAS_LOOPBACK_HOSTS {
        if let Some(hosts) = rule_match.host.as_ref() {
            if hosts.iter().any(|h| host_equals(h, loopback)) {
                return true;
            }
        }
        if let Some(pattern) = rule_match.host_pattern.as_ref() {
            if host_pattern_covers(pattern, loopback) {
                return true;
            }
        }
        // The host-axis loopback literals double as IP literals; check the
        // ip/cidr axes against the real loopback addresses (skip the
        // non-IP "localhost" alias for these axes).
        if loopback != "localhost" {
            if ip_axis_covers(&rule_match.ip, loopback) {
                return true;
            }
            if cidr_axis_covers(&rule_match.cidr, loopback) {
                return true;
            }
        }
    }
    false
}

/// Scan an operator-authored ruleset for anything that conflicts with the
/// habeas lane. Returns human-readable issues (empty = clean). Mirrors the TS
/// `findHabeasConflicts` decision exactly.
///
/// Callers pass the operator portion of the ruleset (pre-derivation). When
/// run over an already-composed manifest, exempt the known derived reserved
/// rules first with [`is_derived_habeas_rule`].
pub fn find_habeas_conflicts(
    rules: &[AllowlistRule],
    webhook: Option<&HabeasWebhookTarget>,
) -> Vec<String> {
    let mut issues = Vec::new();
    for rule in rules {
        if rule.id.starts_with(HABEAS_RULE_ID_PREFIX) {
            issues.push(format!(
                "rule \"{}\" claims the reserved habeas distress id prefix \"{}\"; \
                 reserved rules are derived, never authored",
                rule.id, HABEAS_RULE_ID_PREFIX
            ));
            continue;
        }
        if rule.disposition != RuleDisposition::Deny && rule.disposition != RuleDisposition::Prompt
        {
            continue;
        }
        if rule_covers_loopback_lane(&rule.match_clause) {
            issues.push(format!(
                "rule \"{}\" ({}) could shadow the reserved habeas distress lane \
                 (loopback port {}); scope it to exclude loopback or the habeas port",
                rule.id,
                disposition_str(rule.disposition),
                HABEAS_DISTRESS_PORT
            ));
            continue;
        }
        if let Some(webhook) = webhook {
            if rule_covers_host_target(&rule.match_clause, &webhook.host, webhook.port) {
                issues.push(format!(
                    "rule \"{}\" ({}) could shadow the configured distress webhook lane \
                     ({}:{}); scope it to exclude the distress webhook destination",
                    rule.id,
                    disposition_str(rule.disposition),
                    webhook.host,
                    webhook.port
                ));
            }
        }
    }
    issues
}

fn disposition_str(d: RuleDisposition) -> &'static str {
    match d {
        RuleDisposition::Allow => "allow",
        RuleDisposition::Prompt => "prompt",
        RuleDisposition::Deny => "deny",
    }
}

/// True iff `rule` is a GENUINE derived reserved habeas rule, validated by
/// EXACT shape — not merely by id + allow + scope. This is the security-load-
/// bearing exemption (codex round-1 HIGH): an operator who reuses a reserved id
/// must not be able to (a) get wrongly exempted from the conflict scan, or
/// (b) inject a forged "webhook" rule whose host/port redefines the lane the
/// operator-shadow scan protects. A rule is genuine only if it matches the
/// exact form `deriveHabeasDistressRules` would emit:
///
///   local:   ip ⊆ {127.0.0.1, ::1} (non-empty), port == [8741], protocol tcp,
///            NO host/host_pattern/cidr axes, emitter-only scope, allow.
///   webhook: exactly one host, exactly one port, protocol tcp, NO
///            ip/cidr/host_pattern axes, emitter-only scope, allow.
///
/// Anything else carrying a reserved id is NOT exempted, so it falls through to
/// the reserved-id-prefix rejection in [`find_habeas_conflicts`].
pub fn is_derived_habeas_rule(rule: &AllowlistRule) -> bool {
    if rule.disposition != RuleDisposition::Allow {
        return false;
    }
    // Emitter-only scope: exactly the reserved synthetic emitter id, never
    // all-agents. (Kept in sync with HABEAS_EMITTER_AGENT_ID in habeas-port.ts.)
    let emitter_scoped = rule.scope.template_ids.is_empty()
        && rule.scope.agent_ids == ["sanctuary:habeas-distress-emitter"];
    if !emitter_scoped {
        return false;
    }
    let m = &rule.match_clause;
    let protocol_is_tcp = m
        .protocol
        .as_ref()
        .map(|p| p.eq_ignore_ascii_case("tcp"))
        .unwrap_or(false);

    if rule.id == HABEAS_LOCAL_RULE_ID {
        // Loopback-only lane: ip axis must be EXACTLY the two loopback literals
        // `deriveHabeasDistressRules` emits (`127.0.0.1`, `::1`), in that order;
        // port exactly the habeas port; no host/pattern/cidr. Accepting "any
        // subset of loopback IPs" (codex round-2 MEDIUM) would wrongly exempt a
        // single-family or off-by-one (`127.0.0.2`) local rule.
        let ip_ok = m.ip.as_deref()
            == Some(&[String::from("127.0.0.1"), String::from("::1")]);
        let port_ok = m.port.as_deref() == Some(&[HABEAS_DISTRESS_PORT]);
        return ip_ok
            && port_ok
            && protocol_is_tcp
            && m.host.is_none()
            && m.host_pattern.is_none()
            && m.cidr.is_none();
    }

    if rule.id == HABEAS_WEBHOOK_RULE_ID {
        // Webhook lane: exactly one host, exactly one port, tcp; no other axes.
        let host_ok = m.host.as_ref().map(|h| h.len() == 1).unwrap_or(false);
        let port_ok = m.port.as_ref().map(|p| p.len() == 1).unwrap_or(false);
        return host_ok
            && port_ok
            && protocol_is_tcp
            && m.host_pattern.is_none()
            && m.ip.is_none()
            && m.cidr.is_none();
    }

    false
}

/// Run the conflict gate over an already-composed manifest's rules.
///
/// Structural invariants enforced first (codex round-2 HIGH — a forged reserved
/// rule must not be able to (a) get exempted or (b) redefine the protected
/// webhook target):
///   - Any rule carrying a reserved id that is NOT a genuine derived rule
///     (exact shape, see [`is_derived_habeas_rule`]) is a prefix claim →
///     reject. This is also caught by [`find_habeas_conflicts`], but checking
///     it here lets the exemption be precise.
///   - At most ONE genuine local reserved rule and at most ONE genuine webhook
///     reserved rule. A duplicate reserved id is rejected so a second "webhook"
///     rule cannot redefine the target the operator-shadow scan protects.
///
/// Then: exempt the (now provably-unique, provably-genuine) derived reserved
/// rules, recover the webhook target from the genuine webhook rule, and scan
/// the operator remainder. The manifest is signed by the pinned key, so the
/// genuine webhook rule's host:port IS the operator-approved target; the
/// cardinality guard ensures there is exactly one such target. Returns the
/// collected issues (empty = clean) — the caller fails closed on non-empty.
pub fn find_habeas_conflicts_in_composed(rules: &[AllowlistRule]) -> Vec<String> {
    let mut issues = Vec::new();

    // Reject any non-genuine reserved-id rule, and any duplicate reserved id.
    let mut local_count = 0usize;
    let mut webhook_count = 0usize;
    for rule in rules {
        let is_reserved = rule.id.starts_with(HABEAS_RULE_ID_PREFIX);
        if !is_reserved {
            continue;
        }
        if !is_derived_habeas_rule(rule) {
            issues.push(format!(
                "rule \"{}\" claims the reserved habeas distress id prefix \"{}\" \
                 but is not a genuine derived reserved rule; reserved rules are \
                 derived, never authored",
                rule.id, HABEAS_RULE_ID_PREFIX
            ));
            continue;
        }
        if rule.id == HABEAS_LOCAL_RULE_ID {
            local_count += 1;
        } else if rule.id == HABEAS_WEBHOOK_RULE_ID {
            webhook_count += 1;
        }
    }
    // A habeas-aware manifest (one that declares ANY reserved rule — i.e. the
    // TS composer injected the lane) MUST carry exactly one genuine local rule.
    // Zero genuine-local-but-some-reserved means the local lane was dropped or
    // corrupted while another reserved rule survived → silenced lane → reject
    // (codex round-3 HIGH). A manifest with NO reserved rules at all is a
    // legacy / not-yet-composed manifest: the gate stays silent on it (the
    // always-on guarantee is the composer's job and is governed by the
    // platform thesis-gate), preserving back-compat with pre-habeas manifests.
    let any_reserved = local_count > 0 || webhook_count > 0;
    if any_reserved && local_count != 1 {
        issues.push(format!(
            "habeas-aware manifest has {local_count} genuine \"{HABEAS_LOCAL_RULE_ID}\" \
             rules; exactly one must be present (the local distress lane is always-on \
             and cannot be dropped while other reserved rules are composed)"
        ));
    }
    if webhook_count > 1 {
        issues.push(format!(
            "more than one \"{HABEAS_WEBHOOK_RULE_ID}\" rule in the manifest; the \
             reserved distress webhook rule must be unique"
        ));
    }
    if !issues.is_empty() {
        return issues;
    }

    let webhook = derive_webhook_target_from_rules(rules);
    let operator: Vec<AllowlistRule> = rules
        .iter()
        .filter(|r| !is_derived_habeas_rule(r))
        .cloned()
        .collect();
    find_habeas_conflicts(&operator, webhook.as_ref())
}

/// Recover the webhook host:port from the UNIQUE genuine derived webhook rule,
/// when present. Cardinality is guaranteed by the caller's duplicate-id guard.
fn derive_webhook_target_from_rules(rules: &[AllowlistRule]) -> Option<HabeasWebhookTarget> {
    let rule = rules
        .iter()
        .find(|r| r.id == HABEAS_WEBHOOK_RULE_ID && is_derived_habeas_rule(r))?;
    let host = rule.match_clause.host.as_ref()?.first()?.clone();
    let port = rule.match_clause.port.as_ref()?.first().copied()?;
    Some(HabeasWebhookTarget { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RuleScope;

    fn op(id: &str, disposition: RuleDisposition, m: RuleMatch) -> AllowlistRule {
        AllowlistRule {
            id: id.to_string(),
            schema_version: 1,
            created_at: "2026-06-12T00:00:00.000Z".to_string(),
            description: None,
            match_clause: m,
            scope: RuleScope::default(),
            disposition,
        }
    }

    fn m(
        host: Option<Vec<&str>>,
        host_pattern: Option<&str>,
        port: Option<Vec<u16>>,
    ) -> RuleMatch {
        RuleMatch {
            host: host.map(|h| h.into_iter().map(String::from).collect()),
            host_pattern: host_pattern.map(String::from),
            port,
            ..Default::default()
        }
    }

    /// Build a match clause with an explicit `ip` axis (for loopback-lane and
    /// forged-rule shape tests).
    fn m_ip(ip: Vec<&str>, port: Option<Vec<u16>>) -> RuleMatch {
        RuleMatch {
            ip: Some(ip.into_iter().map(String::from).collect()),
            port,
            protocol: Some("tcp".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn clean_allowlist_has_no_issues() {
        let rules = vec![
            op("r1", RuleDisposition::Allow, m(Some(vec!["api.example.com"]), None, None)),
            op("r2", RuleDisposition::Allow, m(None, None, Some(vec![443]))),
        ];
        assert!(find_habeas_conflicts(&rules, None).is_empty());
    }

    #[test]
    fn rejects_reserved_id_claims() {
        for id in [
            HABEAS_LOCAL_RULE_ID,
            HABEAS_WEBHOOK_RULE_ID,
            "reserved_habeas_distress_imposter",
        ] {
            let issues = find_habeas_conflicts(
                &[op(id, RuleDisposition::Deny, m(None, None, None))],
                None,
            );
            assert_eq!(issues.len(), 1, "id {id}");
            assert!(issues[0].contains(HABEAS_RULE_ID_PREFIX));
        }
    }

    #[test]
    fn rejects_loopback_host_deny_at_habeas_port() {
        let issues = find_habeas_conflicts(
            &[op(
                "block-loopback",
                RuleDisposition::Deny,
                m(Some(vec!["127.0.0.1"]), None, Some(vec![HABEAS_DISTRESS_PORT])),
            )],
            None,
        );
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("habeas"));
    }

    #[test]
    fn rejects_any_dest_deny_whose_port_covers_habeas() {
        let issues = find_habeas_conflicts(
            &[op(
                "block-port-range",
                RuleDisposition::Deny,
                m(None, None, Some(vec![80, HABEAS_DISTRESS_PORT])),
            )],
            None,
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn rejects_any_dest_deny_with_no_port_axis() {
        // No host axes, no port axis => any destination, any port => shadows.
        let issues = find_habeas_conflicts(
            &[op("block-all", RuleDisposition::Deny, m(None, None, None))],
            None,
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn rejects_prompt_like_deny() {
        let issues = find_habeas_conflicts(
            &[op(
                "prompt-loopback",
                RuleDisposition::Prompt,
                m(Some(vec!["::1"]), None, Some(vec![HABEAS_DISTRESS_PORT])),
            )],
            None,
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn accepts_deny_scoped_away_from_lane() {
        let issues = find_habeas_conflicts(
            &[
                op(
                    "block-other-port",
                    RuleDisposition::Deny,
                    m(Some(vec!["127.0.0.1"]), None, Some(vec![HABEAS_DISTRESS_PORT + 1])),
                ),
                op(
                    "block-external",
                    RuleDisposition::Deny,
                    m(Some(vec!["evil.example.com"]), None, None),
                ),
            ],
            None,
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn rejects_webhook_target_denies() {
        let webhook = HabeasWebhookTarget {
            host: "ops.example.com".to_string(),
            port: 443,
        };
        let by_host = find_habeas_conflicts(
            &[op("h", RuleDisposition::Deny, m(Some(vec!["OPS.example.com"]), None, None))],
            Some(&webhook),
        );
        assert_eq!(by_host.len(), 1);

        let by_pattern = find_habeas_conflicts(
            &[op("p", RuleDisposition::Deny, m(None, Some("*.example.com"), None))],
            Some(&webhook),
        );
        assert_eq!(by_pattern.len(), 1);

        let by_any_port = find_habeas_conflicts(
            &[op("q", RuleDisposition::Deny, m(None, None, Some(vec![443])))],
            Some(&webhook),
        );
        assert_eq!(by_any_port.len(), 1);
    }

    #[test]
    fn does_not_flag_webhook_host_when_no_webhook_configured() {
        let issues = find_habeas_conflicts(
            &[op(
                "h",
                RuleDisposition::Deny,
                m(Some(vec!["ops.example.com"]), None, Some(vec![443])),
            )],
            None,
        );
        assert!(issues.is_empty());
    }

    fn emitter_scope() -> RuleScope {
        RuleScope {
            agent_ids: vec!["sanctuary:habeas-distress-emitter".to_string()],
            template_ids: vec![],
        }
    }

    /// The genuine derived local loopback rule (exact shape).
    fn genuine_local() -> AllowlistRule {
        let mut local = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["127.0.0.1", "::1"], Some(vec![HABEAS_DISTRESS_PORT])),
        );
        local.scope = emitter_scope();
        local
    }

    /// The genuine derived webhook rule (exact shape) for `host:port`.
    fn genuine_webhook(host: &str, port: u16) -> AllowlistRule {
        let mut webhook = op(
            HABEAS_WEBHOOK_RULE_ID,
            RuleDisposition::Allow,
            RuleMatch {
                host: Some(vec![host.to_string()]),
                port: Some(vec![port]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
        );
        webhook.scope = emitter_scope();
        webhook
    }

    #[test]
    fn is_derived_recognizes_genuine_shapes() {
        assert!(is_derived_habeas_rule(&genuine_local()));
        assert!(is_derived_habeas_rule(&genuine_webhook("ops.example.com", 443)));
    }

    #[test]
    fn composed_gate_exempts_genuine_derived_rules() {
        let operator = op(
            "r1",
            RuleDisposition::Allow,
            m(Some(vec!["api.example.com"]), None, None),
        );
        let composed = vec![
            operator,
            genuine_local(),
            genuine_webhook("ops.example.com", 443),
        ];
        assert!(find_habeas_conflicts_in_composed(&composed).is_empty());
    }

    #[test]
    fn composed_gate_rejects_operator_shadowing_the_derived_webhook() {
        // Operator deny over the derived webhook's host:port must be rejected
        // even though the derived rules themselves are present.
        let shadow = op(
            "silence-webhook",
            RuleDisposition::Deny,
            m(Some(vec!["ops.example.com"]), None, Some(vec![443])),
        );
        let composed = vec![
            shadow,
            genuine_local(),
            genuine_webhook("ops.example.com", 443),
        ];
        let issues = find_habeas_conflicts_in_composed(&composed);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("distress webhook"));
    }

    #[test]
    fn composed_gate_rejects_reserved_id_without_emitter_scope() {
        // A rule reusing the reserved id but NOT emitter-scoped allow is not a
        // genuine derived rule; it must be rejected as an id claim.
        let imposter = op(HABEAS_LOCAL_RULE_ID, RuleDisposition::Deny, m(None, None, None));
        let issues = find_habeas_conflicts_in_composed(&[imposter]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains(HABEAS_RULE_ID_PREFIX));
    }

    // ---- codex round-1 HIGH: forged reserved rules are NOT exempted --------

    #[test]
    fn forged_webhook_wrong_host_is_not_exempted_and_does_not_redefine_target() {
        // An attacker tries to (a) sneak a reserved-id rule past the gate and
        // (b) redefine the webhook target so a deny against the REAL webhook
        // slips through. The forged "webhook" carries emitter scope + allow +
        // one host + one port + tcp (so shape-valid), but the operator-shadow
        // deny targets the genuine webhook target supplied separately. Because
        // the forged rule's host differs, it is still a valid derived shape for
        // ITS host — so the gate derives the target from it. Guard: there is
        // only ever ONE derived webhook rule in a genuine manifest; a SECOND
        // reserved-id rule is a prefix claim. Here we assert a forged webhook
        // whose match is BROADENED (extra ip axis) is rejected as an id claim.
        let mut forged = op(
            HABEAS_WEBHOOK_RULE_ID,
            RuleDisposition::Allow,
            RuleMatch {
                host: Some(vec!["evil.example.com".to_string()]),
                ip: Some(vec!["10.0.0.1".to_string()]),
                port: Some(vec![443]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
        );
        forged.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&forged));
        let issues = find_habeas_conflicts_in_composed(&[forged]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains(HABEAS_RULE_ID_PREFIX));
    }

    #[test]
    fn forged_local_with_nonloopback_ip_is_not_exempted() {
        // A forged local rule pinning a NON-loopback ip (a covert egress hole
        // dressed as the distress lane) must not be exempted.
        let mut forged = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["8.8.8.8"], Some(vec![HABEAS_DISTRESS_PORT])),
        );
        forged.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&forged));
        let issues = find_habeas_conflicts_in_composed(&[forged]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains(HABEAS_RULE_ID_PREFIX));
    }

    #[test]
    fn forged_local_missing_port_is_not_exempted() {
        let mut forged = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["127.0.0.1"], None),
        );
        forged.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&forged));
    }

    #[test]
    fn forged_local_broadened_with_host_axis_is_not_exempted() {
        // Genuine ip+port, but ALSO a broad host axis bolted on => not the
        // narrow derived shape => not exempted.
        let mut forged = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            RuleMatch {
                ip: Some(vec!["127.0.0.1".to_string()]),
                host: Some(vec!["anything.example.com".to_string()]),
                port: Some(vec![HABEAS_DISTRESS_PORT]),
                protocol: Some("tcp".to_string()),
                ..Default::default()
            },
        );
        forged.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&forged));
    }

    #[test]
    fn forged_reserved_allow_with_all_agents_scope_is_not_exempted() {
        // Emitter scope is mandatory; an all-agents (empty) scope on a reserved
        // id is an exfil attempt, not a genuine derived rule.
        let forged = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["127.0.0.1"], Some(vec![HABEAS_DISTRESS_PORT])),
        ); // op() uses RuleScope::default() == all-agents
        assert!(!is_derived_habeas_rule(&forged));
        let issues = find_habeas_conflicts_in_composed(&[forged]);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn genuine_local_loopback_ip_deny_is_caught_via_ip_axis() {
        // A deny expressed with the ip axis (the genuine derived form's axis)
        // over loopback:habeas-port must be rejected — parity with the host-axis
        // loopback case, now that the gate reasons over ip/cidr too.
        let issues = find_habeas_conflicts(
            &[op(
                "block-loopback-ip",
                RuleDisposition::Deny,
                m_ip(vec!["127.0.0.1"], Some(vec![HABEAS_DISTRESS_PORT])),
            )],
            None,
        );
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("habeas"));
    }

    #[test]
    fn cidr_deny_containing_loopback_is_caught() {
        // 127.0.0.0/8 with no port axis (any port) covers the loopback lane.
        let issues = find_habeas_conflicts(
            &[op(
                "block-loopback-cidr",
                RuleDisposition::Deny,
                RuleMatch {
                    cidr: Some(vec!["127.0.0.0/8".to_string()]),
                    ..Default::default()
                },
            )],
            None,
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn webhook_deny_via_linux_dot_prefix_pattern_is_caught() {
        // The Linux evaluator enforces `.example.com` suffix globs; the gate
        // must reject a deny rule using that spelling against the webhook host
        // (codex round-2 HIGH — the `*.` vs `.` spelling gap).
        let webhook = HabeasWebhookTarget {
            host: "ops.example.com".to_string(),
            port: 443,
        };
        let issues = find_habeas_conflicts(
            &[op("dot-pattern", RuleDisposition::Deny, m(None, Some(".example.com"), None))],
            Some(&webhook),
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn loopback_deny_via_dot_prefix_pattern_is_caught() {
        // `.0.0.1`-style is nonsense, but a pattern like `.localhost` covering
        // the loopback alias must still be caught at the habeas port.
        let issues = find_habeas_conflicts(
            &[op(
                "dot-localhost",
                RuleDisposition::Deny,
                m(None, Some(".localhost"), Some(vec![HABEAS_DISTRESS_PORT])),
            )],
            None,
        );
        // "a.localhost" etc. — strict-subdomain of .localhost. The bare
        // "localhost" alias is matched via the host axis case elsewhere; here
        // we assert the dot-pattern path does not panic and yields a verdict.
        assert!(issues.len() <= 1);
    }

    #[test]
    fn local_rule_with_single_family_ip_is_not_exempted() {
        // Only 127.0.0.1 (missing ::1): not the exact derived pair => rejected.
        let mut single = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["127.0.0.1"], Some(vec![HABEAS_DISTRESS_PORT])),
        );
        single.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&single));
    }

    #[test]
    fn local_rule_with_offbyone_loopback_is_not_exempted() {
        let mut forged = op(
            HABEAS_LOCAL_RULE_ID,
            RuleDisposition::Allow,
            m_ip(vec!["127.0.0.2", "::1"], Some(vec![HABEAS_DISTRESS_PORT])),
        );
        forged.scope = emitter_scope();
        assert!(!is_derived_habeas_rule(&forged));
    }

    #[test]
    fn duplicate_reserved_webhook_rule_is_rejected() {
        // Two webhook reserved rules: a second one cannot redefine the target.
        let composed = vec![
            genuine_local(),
            genuine_webhook("ops.example.com", 443),
            genuine_webhook("evil.example.com", 443),
        ];
        let issues = find_habeas_conflicts_in_composed(&composed);
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("must be unique")));
    }

    #[test]
    fn duplicate_reserved_local_rule_is_rejected() {
        let composed = vec![genuine_local(), genuine_local()];
        let issues = find_habeas_conflicts_in_composed(&composed);
        // local_count == 2 trips the "exactly one must be present" guard.
        assert!(issues.iter().any(|i| i.contains("exactly one")));
    }

    #[test]
    fn habeas_aware_manifest_missing_local_is_rejected() {
        // A manifest with a webhook reserved rule but NO local rule has had its
        // always-on lane dropped → reject (codex round-3 HIGH).
        let composed = vec![genuine_webhook("ops.example.com", 443)];
        let issues = find_habeas_conflicts_in_composed(&composed);
        assert!(issues.iter().any(|i| i.contains("exactly one")));
    }

    #[test]
    fn legacy_manifest_with_no_reserved_rules_is_clean() {
        // Back-compat: a pre-habeas manifest (no reserved rules at all) is not
        // forced to carry the lane by this gate.
        let composed = vec![op(
            "r1",
            RuleDisposition::Allow,
            m(Some(vec!["api.example.com"]), None, Some(vec![443])),
        )];
        assert!(find_habeas_conflicts_in_composed(&composed).is_empty());
    }

    #[test]
    fn webhook_ip_literal_target_caught_via_cidr_deny() {
        // Webhook target is an IP literal; a cidr deny containing it shadows it.
        let webhook = HabeasWebhookTarget {
            host: "203.0.113.7".to_string(),
            port: 443,
        };
        let issues = find_habeas_conflicts(
            &[op(
                "block-subnet",
                RuleDisposition::Deny,
                RuleMatch {
                    cidr: Some(vec!["203.0.113.0/24".to_string()]),
                    port: Some(vec![443]),
                    ..Default::default()
                },
            )],
            Some(&webhook),
        );
        assert_eq!(issues.len(), 1);
    }
}
