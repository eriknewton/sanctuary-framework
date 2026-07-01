/**
 * Sanctuary Tunability UX: plain-English rendering of the current
 * Principal Policy.
 *
 * The north-star hard requirement is that fine-grained policy be
 * trivially legible so nobody disables the wall ("never make me disable
 * you"). The dashboard Policy surface renders the LIVE Principal Policy
 * in plain English ("every send-email routes to you for approval") rather
 * than raw manifest YAML. This module is that renderer.
 *
 * It is PURE and OPERATOR-FACING. It is consumed only behind the
 * operator-bearer chokepoint on the dashboard (GET /api/policy/current).
 * It never emits an agent-readable surface: the routes layer gates every
 * call to it, and this module itself has no I/O and no outbound surface.
 *
 * AGENTS.md hard rule 7 (agent must not read or infer the Principal
 * Policy) is upheld structurally by the caller: the ONLY caller is the
 * bearer-gated GET /api/policy/current route. This module does not widen
 * that boundary; it is a formatter, not a data source.
 */

import type {
  PrincipalPolicy,
  Tier2Config,
} from "../principal-policy/types.js";

/** A single operator-facing plain-English policy line. */
export interface PolicyPlainEnglishLine {
  /** Grouping key so the UI can section the view. */
  section: "approval" | "auto_allow" | "anomaly" | "channel";
  /** The plain-English sentence the operator reads. */
  text: string;
}

/** The full plain-English rendering of a Principal Policy. */
export interface PolicyPlainEnglishView {
  policy_version: number;
  lines: PolicyPlainEnglishLine[];
}

/**
 * Turn a snake_case operation/field token into a readable phrase.
 * "state_export" -> "state export"; "operator_cloud_provision" ->
 * "operator cloud provision". Unknown tokens degrade gracefully to
 * their de-underscored form so the view never shows raw identifiers
 * without at least basic humanization, and never throws on a token it
 * has not seen.
 */
function humanizeToken(token: string): string {
  return token.replace(/_/g, " ").trim();
}

/**
 * A small curated map of the operations Sanctuary ships so the common
 * cases read as natural sentences. Anything not in the map falls back to
 * the humanized token, so a newly-added operation is still legible.
 */
const OPERATION_PHRASES: Record<string, string> = {
  state_export: "export your saved state off the machine",
  state_import: "import state into your fortress",
  identity_sign: "sign arbitrary data with your identity key",
  key_rotate: "rotate your identity keys",
  identity_delete: "delete an identity",
  reputation_import: "import a reputation bundle",
  operator_cloud_provision: "provision operator cloud custody",
  state_read: "read your saved state",
  state_list: "list your saved state",
};

function operationPhrase(op: string): string {
  return OPERATION_PHRASES[op] ?? humanizeToken(op);
}

/** Human-readable phrasing for a Tier-2 anomaly action. */
function anomalyActionPhrase(action: string): string {
  switch (action) {
    case "approve":
      return "route it to you for approval";
    case "log":
      return "allow it but record it in the audit log";
    case "allow":
      return "allow it silently";
    default:
      return humanizeToken(action);
  }
}

/**
 * Render the Tier-2 anomaly configuration in plain English. Each field
 * gets one operator-facing sentence.
 */
function renderTier2Lines(tier2: Tier2Config): PolicyPlainEnglishLine[] {
  const lines: PolicyPlainEnglishLine[] = [];
  lines.push({
    section: "anomaly",
    text:
      "When an agent touches a namespace it has never used before, " +
      anomalyActionPhrase(tier2.new_namespace_access) + ".",
  });
  lines.push({
    section: "anomaly",
    text:
      "When an agent talks to an unknown counterparty for the first time, " +
      anomalyActionPhrase(tier2.new_counterparty) + ".",
  });
  lines.push({
    section: "anomaly",
    text:
      "On an agent's first session before a baseline exists, " +
      anomalyActionPhrase(tier2.first_session_policy) + ".",
  });
  lines.push({
    section: "anomaly",
    text:
      "Flag a tool-call frequency spike when it exceeds " +
      String(tier2.frequency_spike_multiplier) + "x the normal rate.",
  });
  lines.push({
    section: "anomaly",
    text:
      "Flag more than " +
      String(tier2.max_signs_per_minute) +
      " signing operations in a single minute.",
  });
  lines.push({
    section: "anomaly",
    text:
      "Flag reading more than " +
      String(tier2.bulk_read_threshold) +
      " keys from one namespace within a minute.",
  });
  return lines;
}

/**
 * Render the live Principal Policy as an ordered list of plain-English
 * lines. Pure function; no I/O. The order is: what always needs your
 * approval, what agents may do freely, the anomaly rules, then how
 * approvals reach you.
 */
export function renderPolicyPlainEnglish(
  policy: PrincipalPolicy,
): PolicyPlainEnglishView {
  const lines: PolicyPlainEnglishLine[] = [];

  if (policy.tier1_always_approve.length === 0) {
    lines.push({
      section: "approval",
      text: "No operations are currently pinned to always require your approval.",
    });
  } else {
    for (const op of [...policy.tier1_always_approve].sort()) {
      lines.push({
        section: "approval",
        text: "Every attempt to " + operationPhrase(op) + " routes to you for approval.",
      });
    }
  }

  if (policy.tier3_always_allow.length === 0) {
    lines.push({
      section: "auto_allow",
      text: "No operations are on the always-allow list; everything else is evaluated per action.",
    });
  } else {
    for (const op of [...policy.tier3_always_allow].sort()) {
      lines.push({
        section: "auto_allow",
        text: "Agents may " + operationPhrase(op) + " without asking you (audited only).",
      });
    }
  }

  for (const line of renderTier2Lines(policy.tier2_anomaly)) {
    lines.push(line);
  }

  const channel = policy.approval_channel;
  lines.push({
    section: "channel",
    text:
      "Approval requests reach you over the " +
      humanizeToken(channel.type) +
      " channel; if you do not respond within " +
      String(channel.timeout_seconds) +
      " seconds the request is denied.",
  });

  return { policy_version: policy.version, lines };
}
